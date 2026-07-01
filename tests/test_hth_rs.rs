//! test_hth_rs.rs — Handshake Transcript Hash (HTH) tests
//!
//! Ports Python: tests/test_hth.py
//! HandshakeTranscript, TranscriptElementType, bind_capability, TranscriptRegistry.

use saacp::{
    HandshakeTranscript, TranscriptElementType,
    bind_capability, verify_capability_binding,
    TranscriptRegistry, TranscriptSession,
};

fn make_session_id() -> Vec<u8> {
    vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
         0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10]
}

// ─── HandshakeTranscript::new ─────────────────────────────────────────────────

#[test]
fn test_new_with_16_bytes_ok() {
    let sid = make_session_id();
    let ht = HandshakeTranscript::new(&sid);
    assert!(ht.is_ok(), "16-byte session_id must succeed");
}

#[test]
fn test_new_with_15_bytes_fails() {
    let sid = vec![0u8; 15];
    assert!(HandshakeTranscript::new(&sid).is_err(), "15-byte session_id must fail");
}

#[test]
fn test_new_with_17_bytes_fails() {
    let sid = vec![0u8; 17];
    assert!(HandshakeTranscript::new(&sid).is_err(), "17-byte session_id must fail");
}

#[test]
fn test_new_with_empty_fails() {
    assert!(HandshakeTranscript::new(&[]).is_err(), "Empty session_id must fail");
}

// ─── Element count ────────────────────────────────────────────────────────────

#[test]
fn test_element_count_zero_initially() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    assert_eq!(ht.element_count(), 0);
}

#[test]
fn test_element_count_increments_on_append() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.append(TranscriptElementType::ClientHello, b"hello").unwrap();
    assert_eq!(ht.element_count(), 1);
    ht.append(TranscriptElementType::ServerHello, b"world").unwrap();
    assert_eq!(ht.element_count(), 2);
}

// ─── append / finalize ────────────────────────────────────────────────────────

#[test]
fn test_append_all_element_types() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.append(TranscriptElementType::ClientHello, b"ch").unwrap();
    ht.append(TranscriptElementType::ServerHello, b"sh").unwrap();
    ht.append(TranscriptElementType::IdentityProof, b"ip").unwrap();
    ht.append(TranscriptElementType::KeyExchangeShare, b"ks").unwrap();
    ht.append(TranscriptElementType::EpochInit, b"ei").unwrap();
    ht.append(TranscriptElementType::PolicyCommitment, b"pc").unwrap();
    ht.append(TranscriptElementType::CapabilityBinding, b"cb").unwrap();
    ht.append(TranscriptElementType::SessionParams, b"sp").unwrap();
    assert_eq!(ht.element_count(), 8);
}

#[test]
fn test_finalize_produces_32_bytes() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.append(TranscriptElementType::ClientHello, b"client_data").unwrap();
    let hth = ht.finalize().unwrap();
    assert_eq!(hth.len(), 32, "HTH must be 32 bytes (SHA-256)");
}

#[test]
fn test_finalize_marks_finalized() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.finalize().unwrap();
    assert!(ht.is_finalized());
}

#[test]
fn test_hth_accessible_after_finalize() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.append(TranscriptElementType::EpochInit, b"epoch").unwrap();
    ht.finalize().unwrap();
    assert!(ht.hth().is_some());
    assert!(ht.hth_hex().is_some());
}

#[test]
fn test_hth_hex_is_64_chars() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.append(TranscriptElementType::ClientHello, b"x").unwrap();
    ht.finalize().unwrap();
    let hex = ht.hth_hex().unwrap();
    assert_eq!(hex.len(), 64);
}

// ─── Determinism ─────────────────────────────────────────────────────────────

#[test]
fn test_finalize_deterministic_same_data() {
    let sid = make_session_id();
    let ht1 = HandshakeTranscript::new(&sid).unwrap();
    ht1.append(TranscriptElementType::ClientHello, b"data").unwrap();
    let hth1 = ht1.finalize().unwrap();

    let ht2 = HandshakeTranscript::new(&sid).unwrap();
    ht2.append(TranscriptElementType::ClientHello, b"data").unwrap();
    let hth2 = ht2.finalize().unwrap();

    assert_eq!(hth1, hth2, "Same inputs must produce same HTH");
}

#[test]
fn test_different_data_yields_different_hth() {
    let sid = make_session_id();
    let ht1 = HandshakeTranscript::new(&sid).unwrap();
    ht1.append(TranscriptElementType::ClientHello, b"data_A").unwrap();
    let hth1 = ht1.finalize().unwrap();

    let ht2 = HandshakeTranscript::new(&sid).unwrap();
    ht2.append(TranscriptElementType::ClientHello, b"data_B").unwrap();
    let hth2 = ht2.finalize().unwrap();

    assert_ne!(hth1, hth2, "Different data must yield different HTH");
}

#[test]
fn test_different_session_id_yields_different_hth() {
    let ht1 = HandshakeTranscript::new(&[0x01u8; 16]).unwrap();
    ht1.append(TranscriptElementType::ClientHello, b"same").unwrap();
    let hth1 = ht1.finalize().unwrap();

    let ht2 = HandshakeTranscript::new(&[0x02u8; 16]).unwrap();
    ht2.append(TranscriptElementType::ClientHello, b"same").unwrap();
    let hth2 = ht2.finalize().unwrap();

    assert_ne!(hth1, hth2, "Different session_id must produce different HTH");
}

// ─── Error paths ──────────────────────────────────────────────────────────────

#[test]
fn test_append_after_finalize_fails() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.finalize().unwrap();
    let res = ht.append(TranscriptElementType::ClientHello, b"late");
    assert!(res.is_err(), "Append after finalize must fail");
}

#[test]
fn test_finalize_twice_fails() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    ht.finalize().unwrap();
    let res = ht.finalize();
    assert!(res.is_err(), "Double finalize must fail");
}

#[test]
fn test_hth_none_before_finalize() {
    let ht = HandshakeTranscript::new(&make_session_id()).unwrap();
    assert!(ht.hth().is_none());
}

// ─── TranscriptSession ────────────────────────────────────────────────────────

#[test]
fn test_transcript_session_create_ok() {
    let sid = make_session_id();
    let ht = HandshakeTranscript::new(&sid).unwrap();
    ht.append(TranscriptElementType::SessionParams, b"params").unwrap();
    let session = TranscriptSession::create(&sid, 1, "cid-001", ht).unwrap();
    assert_eq!(session.hth.len(), 32);
    assert_eq!(session.epoch_id, 1);
    assert_eq!(session.conversation_id, "cid-001");
}

#[test]
fn test_transcript_session_already_finalized_ok() {
    let sid = make_session_id();
    let ht = HandshakeTranscript::new(&sid).unwrap();
    ht.append(TranscriptElementType::EpochInit, b"epoch").unwrap();
    ht.finalize().unwrap();
    let session = TranscriptSession::create(&sid, 2, "cid-002", ht).unwrap();
    assert_eq!(session.hth.len(), 32);
}

// ─── bind_capability / verify_capability_binding ──────────────────────────────

#[test]
fn test_bind_capability_produces_32_bytes() {
    let hth = vec![0xABu8; 32];
    let token = b"capability_token_bytes";
    let secret = b"hmac_secret_key";
    let mac = bind_capability(&hth, token, secret).unwrap();
    assert_eq!(mac.len(), 32);
}

#[test]
fn test_bind_capability_deterministic() {
    let hth = vec![0xCDu8; 32];
    let token = b"token_data";
    let secret = b"secret";
    let mac1 = bind_capability(&hth, token, secret).unwrap();
    let mac2 = bind_capability(&hth, token, secret).unwrap();
    assert_eq!(mac1, mac2);
}

#[test]
fn test_bind_capability_wrong_hth_length_fails() {
    let hth = vec![0xABu8; 31];
    let res = bind_capability(&hth, b"token", b"secret");
    assert!(res.is_err(), "31-byte HTH must fail");
}

#[test]
fn test_verify_capability_binding_valid_ok() {
    let hth = vec![0xABu8; 32];
    let token = b"cap_token";
    let secret = b"shared_secret";
    let mac = bind_capability(&hth, token, secret).unwrap();
    assert!(verify_capability_binding(&hth, token, secret, &mac).unwrap());
}

#[test]
fn test_verify_capability_binding_bad_mac_fails() {
    let hth = vec![0xABu8; 32];
    let token = b"cap_token";
    let secret = b"shared_secret";
    let mac = bind_capability(&hth, token, secret).unwrap();
    let mut bad_mac = mac.clone();
    bad_mac[0] ^= 0xFF;
    assert!(!verify_capability_binding(&hth, token, secret, &bad_mac).unwrap());
}

#[test]
fn test_verify_capability_binding_wrong_secret_fails() {
    let hth = vec![0xABu8; 32];
    let token = b"cap_token";
    let mac = bind_capability(&hth, token, b"secret1").unwrap();
    assert!(!verify_capability_binding(&hth, token, b"secret2", &mac).unwrap());
}

#[test]
fn test_verify_capability_binding_different_token_fails() {
    let hth = vec![0xABu8; 32];
    let secret = b"secret";
    let mac = bind_capability(&hth, b"token_A", secret).unwrap();
    assert!(!verify_capability_binding(&hth, b"token_B", secret, &mac).unwrap());
}

#[test]
fn test_bind_different_hth_yields_different_mac() {
    let hth1 = vec![0x11u8; 32];
    let hth2 = vec![0x22u8; 32];
    let token = b"same_token";
    let secret = b"same_secret";
    let mac1 = bind_capability(&hth1, token, secret).unwrap();
    let mac2 = bind_capability(&hth2, token, secret).unwrap();
    assert_ne!(mac1, mac2);
}

// ─── TranscriptRegistry ───────────────────────────────────────────────────────

#[test]
fn test_registry_count_zero_initially() {
    let reg = TranscriptRegistry::new();
    assert_eq!(reg.count(), 0);
}

#[test]
fn test_registry_register_and_contains() {
    let sid = make_session_id();
    let ht = HandshakeTranscript::new(&sid).unwrap();
    ht.append(TranscriptElementType::ClientHello, b"hello").unwrap();
    let session = TranscriptSession::create(&sid, 1, "cid", ht).unwrap();

    let reg = TranscriptRegistry::new();
    reg.register(session);
    assert!(reg.contains(&sid));
    assert_eq!(reg.count(), 1);
}

#[test]
fn test_registry_get_session_hth() {
    let sid = make_session_id();
    let ht = HandshakeTranscript::new(&sid).unwrap();
    ht.append(TranscriptElementType::KeyExchangeShare, b"key").unwrap();
    let session = TranscriptSession::create(&sid, 5, "cid-5", ht).unwrap();
    let hth_val = session.hth.clone();

    let reg = TranscriptRegistry::new();
    reg.register(session);

    let found = reg.get(&sid, |s| s.hth.clone());
    assert_eq!(found, Some(hth_val));
}

#[test]
fn test_registry_remove_session() {
    let sid = make_session_id();
    let ht = HandshakeTranscript::new(&sid).unwrap();
    ht.append(TranscriptElementType::ClientHello, b"x").unwrap();
    let session = TranscriptSession::create(&sid, 1, "c", ht).unwrap();

    let reg = TranscriptRegistry::new();
    reg.register(session);
    reg.remove(&sid);
    assert!(!reg.contains(&sid));
    assert_eq!(reg.count(), 0);
}

#[test]
fn test_registry_remove_nonexistent_no_panic() {
    let reg = TranscriptRegistry::new();
    reg.remove(&[0u8; 16]);
}

#[test]
fn test_registry_get_nonexistent_returns_none() {
    let reg = TranscriptRegistry::new();
    let result = reg.get(&[0u8; 16], |s| s.epoch_id);
    assert!(result.is_none());
}
