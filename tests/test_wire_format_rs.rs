//! test_wire_format_rs.rs — SAACP Wire Format layout tests
//!
//! Ports tests from Python tests/test_vectors.py
//!
//! Verifies that the Rust implementation's wire format exactly matches
//! the normative byte layout documented in README §4.1 and §4.1b.

use saacp::{
    MEASC_MAGIC, MEASC_HEADER_SIZE, MEASC_AUTH_TAG_SIZE,
    MEASC_CONTEXT_REF_ID_OFFSET, MEASC_CONTEXT_REF_ID_SIZE,
    MEASCFrame, SessionEpochManager,
    MEASC_DEFAULT_EPOCH_TIME_SECONDS, MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
    EasiEncryptor,
};

// ─── MEASC Header: 128-byte layout (README §4.1) ─────────────────────────────
//
//   Offset | Size | Field
//   -------|------|------
//        0 |    4 | Magic "SACP"
//        4 |    2 | schema_id (u16 big-endian)
//        6 |    1 | status_code
//        7 |    1 | flags
//        8 |    1 | action_class
//        9 |    3 | reserved
//       12 |    4 | payload_length (u32 big-endian)
//       16 |   16 | session_id
//       32 |    4 | epoch_id (u32 big-endian)
//       36 |    8 | PSN (u64 big-endian)
//       44 |   32 | Context Ref ID (EASI-encrypted)   ← M-2 fix
//       76 |    4 | context_version (u32 big-endian)
//       80 |   24 | traceparent
//      104 |   24 | reserved (zeros)
//  ─────── total: 128 bytes ───────────────────────────────────────────────────

#[test]
fn test_measc_header_is_128_bytes() {
    assert_eq!(MEASC_HEADER_SIZE, 128,
        "MEASC header must be exactly 128 bytes (README §4.1)");
}

#[test]
fn test_magic_bytes_are_sacp() {
    assert_eq!(MEASC_MAGIC, b"SACP",
        "MEASC magic must be exactly b\"SACP\"");
}

#[test]
fn test_auth_tag_is_16_bytes() {
    // AES-256-GCM authentication tag: always 16 bytes
    assert_eq!(MEASC_AUTH_TAG_SIZE, 16,
        "AES-GCM auth tag must be exactly 16 bytes");
}

#[test]
fn test_context_ref_id_at_offset_44() {
    // M-2 fix: Context Ref ID occupies bytes [44..76] in the header
    assert_eq!(MEASC_CONTEXT_REF_ID_OFFSET, 44,
        "Context Ref ID must start at byte offset 44");
    assert_eq!(MEASC_CONTEXT_REF_ID_SIZE, 32,
        "Context Ref ID must be 32 bytes");
    assert_eq!(
        MEASC_CONTEXT_REF_ID_OFFSET + MEASC_CONTEXT_REF_ID_SIZE, 76,
        "Context Ref ID must end at offset 76"
    );
}

#[test]
fn test_frame_minimum_size_is_header_plus_tag() {
    // A frame with 0-byte payload must still be header + auth-tag = 144 bytes
    let min = MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE;
    assert_eq!(min, 144, "Minimum MEASC frame size must be 144 bytes");
}

// ─── Live frame byte layout verification ─────────────────────────────────────

fn make_test_frame(payload: &[u8]) -> Vec<u8> {
    let sid = [0xABu8; 16];
    let mgr = SessionEpochManager::new();
    mgr.create_session(
        sid, [0x42u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    ).unwrap();
    let ctx_ref = [0u8; 32];
    let traceparent = [0u8; 24];
    mgr.with_epoch_mut(&sid, 0, |epoch| {
        MEASCFrame::build_frame(
            epoch, 0x01, 0x00, 0x00, 0x00,
            payload, &ctx_ref, &traceparent, 0,
        )
    }).unwrap().unwrap().0
}

#[test]
fn test_frame_starts_with_magic() {
    let frame = make_test_frame(b"hello");
    assert_eq!(&frame[..4], b"SACP",
        "Frame must start with magic b\"SACP\"");
}

#[test]
fn test_frame_magic_at_offset_0() {
    let frame = make_test_frame(b"test payload");
    let magic = u32::from_be_bytes(frame[0..4].try_into().unwrap());
    // "SACP" as big-endian u32 = 0x53414350
    assert_eq!(magic, 0x5341_4350, "Magic bytes must be 0x53414350");
}

#[test]
fn test_frame_context_ref_id_offset() {
    let frame = make_test_frame(b"ctx test");
    // Context Ref ID occupies header bytes [44..76] (MEASC_CONTEXT_REF_ID_OFFSET = 44).
    // GAP-9 / M-2 fix: the field is now EASI-encrypted on the wire.
    // Even when the plaintext context_ref_id is all-zeros, the wire bytes are
    // the EASI keystream (non-zero when the HKDF pad is non-zero), confirming
    // the encryption wrapper is applied.
    let ctx = &frame[44..76];
    assert_eq!(ctx.len(), 32,
        "Context Ref ID field must be exactly 32 bytes at [44..76]");
    // The EASI pad derived from (traffic_key, epoch_id=0, psn=1) is non-zero,
    // so the encrypted form of [0u8; 32] is non-zero.
    let is_non_zero = ctx.iter().any(|&b| b != 0);
    assert!(is_non_zero,
        "EASI-encrypted Context Ref ID at [44..76] must not be all-zero \
         (M-2 fix: encryption pad must be applied)");
}

#[test]
fn test_frame_session_id_at_offset_16() {
    let frame = make_test_frame(b"sid test");
    // session_id is at bytes [16..32] in the header
    let sid_in_frame: [u8; 16] = frame[16..32].try_into().unwrap();
    assert_eq!(sid_in_frame, [0xABu8; 16],
        "session_id at [16..32] must match supplied session ID");
}

#[test]
fn test_frame_payload_length_at_offset_12() {
    let payload = b"length test payload";
    let frame = make_test_frame(payload);
    let len_field = u32::from_be_bytes(frame[12..16].try_into().unwrap());
    assert_eq!(len_field as usize, payload.len(),
        "Payload length at [12..16] must match actual payload length");
}

#[test]
fn test_frame_epoch_id_at_offset_32() {
    let frame = make_test_frame(b"epoch test");
    // epoch_id at bytes [32..36], starting at epoch 0
    let epoch_id = u32::from_be_bytes(frame[32..36].try_into().unwrap());
    assert_eq!(epoch_id, 0, "epoch_id at [32..36] must be 0 for first epoch");
}

#[test]
fn test_frame_psn_at_offset_36() {
    let frame = make_test_frame(b"psn test");
    // PSN at bytes [36..44] — first packet in session, so PSN = 1
    let psn = u64::from_be_bytes(frame[36..44].try_into().unwrap());
    assert_eq!(psn, 1, "PSN at [36..44] must be 1 for first packet");
}

#[test]
fn test_frame_has_auth_tag_after_header() {
    let frame = make_test_frame(b"tag test");
    // Auth tag is 16 bytes immediately after header
    assert!(frame.len() >= MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE,
        "Frame must contain at least header + auth tag");
}

#[test]
fn test_larger_payload_produces_larger_frame() {
    let frame_short = make_test_frame(b"hi");
    let frame_long = make_test_frame(&vec![0x42u8; 1024]);
    assert!(frame_long.len() > frame_short.len(),
        "Larger payload must produce larger frame");
}

// ─── EASI encryption on wire ─────────────────────────────────────────────────

/// Verify that different context_ref_ids encrypt to different wire bytes,
/// and that the roundtrip (build → parse) recovers the original context_ref_id.
#[test]
fn test_easi_different_ctx_refs_produce_different_wire_bytes() {
    let sid = [0xABu8; 16];

    let make_frame_with_ctx = |ctx: [u8; 32]| -> Vec<u8> {
        let mgr = SessionEpochManager::new();
        mgr.create_session(
            sid, [0x42u8; 32],
            MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
            None,
        ).unwrap();
        mgr.with_epoch_mut(&sid, 0, |epoch| {
            MEASCFrame::build_frame(epoch, 0x01, 0x00, 0x00, 0x00, b"payload", &ctx, &[0u8; 24], 0)
        }).unwrap().unwrap().0
    };

    let frame_a = make_frame_with_ctx([0xAAu8; 32]);
    let frame_b = make_frame_with_ctx([0xBBu8; 32]);

    let wire_ctx_a = &frame_a[44..76];
    let wire_ctx_b = &frame_b[44..76];

    assert_ne!(wire_ctx_a, wire_ctx_b,
        "Different plaintext context_ref_ids must produce different EASI-encrypted wire bytes");
}

/// Verify EASI roundtrip: a non-zero context_ref_id is correctly recovered after
/// build_frame (encrypt) → parse_frame (decrypt).
#[test]
fn test_easi_roundtrip_context_ref_id_recovered() {
    let sid = [0xCCu8; 16];
    let ctx_ref_plaintext = [0x55u8; 32];

    let mgr = SessionEpochManager::new();
    mgr.create_session(
        sid, [0x42u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    ).unwrap();

    let frame = mgr.with_epoch_mut(&sid, 0, |epoch| {
        MEASCFrame::build_frame(
            epoch, 0x01, 0x00, 0x00, 0x00,
            b"easi roundtrip", &ctx_ref_plaintext, &[0u8; 24], 0,
        )
    }).unwrap().unwrap().0;

    // Wire bytes at [44..76] must NOT be the plaintext (they are EASI-encrypted)
    assert_ne!(&frame[44..76], &ctx_ref_plaintext,
        "Wire context_ref_id must be EASI-encrypted (not plaintext)");

    // Parse recovers the plaintext context_ref_id
    let mgr2 = SessionEpochManager::new();
    mgr2.create_session(
        sid, [0x42u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    ).unwrap();
    let parsed = MEASCFrame::parse_frame(&frame, &mgr2, true)
        .expect("parse_frame must succeed");

    assert_eq!(parsed.context_ref_id, ctx_ref_plaintext,
        "parse_frame must recover the original plaintext context_ref_id via EASI decrypt");
}

/// Verify EasiEncryptor standalone: encrypt then decrypt recovers plaintext.
#[test]
fn test_easi_encryptor_roundtrip() {
    let key = [0x77u8; 32];
    let ctx = [0x42u8; 32];
    let enc = EasiEncryptor::encrypt(&ctx, &key, 5, 100);
    let dec = EasiEncryptor::decrypt(&enc, &key, 5, 100);
    assert_eq!(dec, ctx, "EasiEncryptor roundtrip must recover plaintext");
}

// ─── Round-trip parse verification ───────────────────────────────────────────

#[test]
fn test_frame_roundtrip_preserves_payload() {
    let payload = b"round-trip payload test";
    let frame = make_test_frame(payload);

    let sid = [0xABu8; 16];
    let mgr = SessionEpochManager::new();
    mgr.create_session(
        sid, [0x42u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    ).unwrap();
    // rebuild so we can parse (need a fresh epoch with PSN 0 for the check)
    // Use skip_schema_validation=true for simplicity
    let parsed = MEASCFrame::parse_frame(&frame, &mgr, true)
        .expect("parse_frame must succeed on valid frame");
    assert_eq!(parsed.payload, payload,
        "Parsed payload must match original");
    assert_eq!(parsed.session_id, sid,
        "Parsed session_id must match original");
}
