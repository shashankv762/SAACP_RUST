//! test_measc_v2_packet_chaining.rs
//!
//! Integration tests for MEASC v2 packet-chaining: prev_packet_hash computation,
//! v2 extension build/parse, PacketChainVerifier state machine, and genesis/chain-break
//! rejection cases.

use saacp::{
    compute_prev_packet_hash, build_v2_extension, parse_v2_extension,
    PacketChainVerifier,
    MEASC_V2_HEADER_SIZE, MEASC_V2_PREV_HASH_SIZE, MEASC_V2_CHAIN_GENESIS,
    MEASC_FORMAT_VERSION_V2, MEASC_FORMAT_VERSION_V1,
    MEASC_V2_PREV_HASH_OFFSET, MEASC_V2_EPOCH_BEACON_OFFSET,
};

// ─── Packet hash tests ────────────────────────────────────────────────────────

#[test]
fn test_compute_prev_packet_hash_deterministic() {
    // SHA-3-256 over a fixed input is deterministic.
    let header = [0u8; 128];
    let h1 = compute_prev_packet_hash(&header);
    let h2 = compute_prev_packet_hash(&header);
    assert_eq!(h1, h2, "hash of same input must be identical");
    // All-zero 128-byte input must NOT produce the all-zero genesis hash.
    assert_ne!(h1, MEASC_V2_CHAIN_GENESIS, "SHA-3-256 of zero input must not be zero");
}

#[test]
fn test_compute_prev_packet_hash_different_inputs() {
    let h1 = [0u8; 128];
    let mut h2 = [0u8; 128];
    h2[0] = 1; // differ by one bit
    let hash1 = compute_prev_packet_hash(&h1);
    let hash2 = compute_prev_packet_hash(&h2);
    assert_ne!(hash1, hash2, "different inputs must produce different hashes");
}

#[test]
fn test_compute_prev_packet_hash_length() {
    let header = [0xABu8; 128];
    let hash = compute_prev_packet_hash(&header);
    assert_eq!(hash.len(), MEASC_V2_PREV_HASH_SIZE, "hash must be exactly 24 bytes");
}

// ─── v2 extension build/parse round-trip ─────────────────────────────────────

#[test]
fn test_build_parse_v2_extension_roundtrip() {
    let prev_hash = [0x42u8; MEASC_V2_PREV_HASH_SIZE];
    let epoch_beacon: u64 = 0xDEAD_BEEF_CAFE_1234;
    let ext = build_v2_extension(&prev_hash, epoch_beacon);
    assert_eq!(ext.len(), 32);

    // Build a fake 160-byte buffer with the extension at offset 128.
    let mut buf = [0u8; MEASC_V2_HEADER_SIZE];
    buf[MEASC_V2_PREV_HASH_OFFSET..MEASC_V2_PREV_HASH_OFFSET + 32]
        .copy_from_slice(&ext);

    let (parsed_hash, parsed_beacon) = parse_v2_extension(&buf).unwrap();
    assert_eq!(parsed_hash, prev_hash, "prev_hash round-trip failed");
    assert_eq!(parsed_beacon, epoch_beacon, "epoch_beacon round-trip failed");
}

#[test]
fn test_parse_v2_extension_too_short() {
    let short_buf = [0u8; 150]; // < 160 bytes
    let result = parse_v2_extension(&short_buf);
    assert!(result.is_err(), "must fail for buffer shorter than MEASC_V2_HEADER_SIZE");
}

#[test]
fn test_parse_v2_extension_genesis_beacon() {
    // Build with genesis hash (all zeros) and epoch_beacon = 0.
    let buf = [0u8; MEASC_V2_HEADER_SIZE];
    // genesis hash at offset 128 is already zero — no action needed.
    // epoch_beacon at offset 152 is already zero.
    let (hash, beacon) = parse_v2_extension(&buf).unwrap();
    assert_eq!(hash, MEASC_V2_CHAIN_GENESIS);
    assert_eq!(beacon, 0);
}

// ─── PacketChainVerifier state machine ───────────────────────────────────────

#[test]
fn test_chain_verifier_initial_state() {
    let v = PacketChainVerifier::new();
    let stats = v.stats();
    assert!(!stats.initialized, "new verifier must be uninitialized");
    assert_eq!(stats.packets_verified, 0);
    assert_eq!(stats.chain_breaks_detected, 0);
}

#[test]
fn test_chain_verifier_accepts_genesis_first_packet() {
    let v = PacketChainVerifier::new();
    // Genesis claim on first packet: always accepted.
    let result = v.verify(&MEASC_V2_CHAIN_GENESIS);
    assert!(result.is_ok(), "genesis claim on first packet must be Ok");
    assert!(result.unwrap(), "genesis claim on first packet must return true");
}

#[test]
fn test_chain_verifier_accepts_any_hash_first_packet() {
    let v = PacketChainVerifier::new();
    // Non-genesis hash on first packet: also accepted (we don't know the prior hash yet).
    let hash = [0xABu8; MEASC_V2_PREV_HASH_SIZE];
    let result = v.verify(&hash);
    assert!(result.is_ok() && result.unwrap());
}

#[test]
fn test_chain_verifier_accept_then_verify_correct_chain() {
    let mut v = PacketChainVerifier::new();

    // Simulate first packet with a known header.
    let header1 = [0x01u8; 128];
    let expected_hash = compute_prev_packet_hash(&header1);

    // Accept first packet.
    v.accept(&header1);
    assert!(v.stats().initialized, "after first accept, must be initialized");
    assert_eq!(v.stats().packets_verified, 1);

    // Second packet claims prev_hash = hash of first packet: must pass.
    let result = v.verify(&expected_hash);
    assert!(result.is_ok() && result.unwrap(), "correct chain hash must verify");
}

#[test]
fn test_chain_verifier_detects_chain_break() {
    let mut v = PacketChainVerifier::new();
    let header1 = [0x01u8; 128];
    v.accept(&header1);

    // Provide a WRONG prev_hash for the second packet.
    let wrong_hash = [0xFFu8; MEASC_V2_PREV_HASH_SIZE];
    let result = v.verify(&wrong_hash);
    assert!(result.is_ok(), "chain break must return Ok(false), not Err");
    assert!(!result.unwrap(), "wrong chain hash must return false");
}

#[test]
fn test_chain_verifier_records_chain_break() {
    let mut v = PacketChainVerifier::new();
    let header1 = [0x01u8; 128];
    v.accept(&header1);

    // Wrong hash — chain break.
    let wrong_hash = [0xFFu8; MEASC_V2_PREV_HASH_SIZE];
    v.verify(&wrong_hash).unwrap(); // ignore the bool
    v.record_chain_break();

    assert_eq!(v.stats().chain_breaks_detected, 1, "chain break must be recorded");
    // State must NOT advance after a chain break — the known hash stays at header1's hash.
    let correct_hash = compute_prev_packet_hash(&header1);
    let result = v.verify(&correct_hash);
    assert!(result.is_ok() && result.unwrap(), "correct hash must still work after recorded break");
}

#[test]
fn test_chain_verifier_genesis_after_established_session_is_error() {
    let mut v = PacketChainVerifier::new();
    let header1 = [0x01u8; 128];
    v.accept(&header1);

    // After session established, genesis claim is a hard error (replay/rewind attack).
    let result = v.verify(&MEASC_V2_CHAIN_GENESIS);
    assert!(result.is_err(), "genesis after established session must be Err");
}

#[test]
fn test_chain_verifier_reset_restores_genesis_state() {
    let mut v = PacketChainVerifier::new();
    let header1 = [0x01u8; 128];
    v.accept(&header1);
    assert!(v.stats().initialized);

    v.reset();
    assert!(!v.stats().initialized, "reset must restore genesis state");
    // After reset, genesis claim must be accepted again.
    let result = v.verify(&MEASC_V2_CHAIN_GENESIS);
    assert!(result.is_ok() && result.unwrap());
}

#[test]
fn test_chain_verifier_multi_packet_chain() {
    let mut v = PacketChainVerifier::new();

    // Simulate a sequence of 5 packets.
    let headers: Vec<[u8; 128]> = (0u8..5).map(|i| [i; 128]).collect();

    // First packet: accept genesis.
    v.accept(&headers[0]);

    // Subsequent packets: verify then accept.
    for i in 1..5 {
        let expected_hash = compute_prev_packet_hash(&headers[i - 1]);
        let result = v.verify(&expected_hash).expect("chain verify should not error");
        assert!(result, "packet {} chain verify must pass", i);
        v.accept(&headers[i]);
    }

    assert_eq!(v.stats().packets_verified, 5);
    assert_eq!(v.stats().chain_breaks_detected, 0);
}

// ─── Wire format constant invariants ─────────────────────────────────────────

#[test]
fn test_v2_header_size_is_160() {
    assert_eq!(MEASC_V2_HEADER_SIZE, 160, "v2 header must be exactly 160 bytes");
}

#[test]
fn test_v2_field_offsets_non_overlapping() {
    // prev_hash: 128..152 (24 bytes)
    // epoch_beacon: 152..160 (8 bytes)
    assert_eq!(MEASC_V2_PREV_HASH_OFFSET, 128);
    assert_eq!(MEASC_V2_PREV_HASH_OFFSET + MEASC_V2_PREV_HASH_SIZE, MEASC_V2_EPOCH_BEACON_OFFSET,
        "prev_hash and epoch_beacon fields must be contiguous");
    assert_eq!(MEASC_V2_EPOCH_BEACON_OFFSET + 8, MEASC_V2_HEADER_SIZE,
        "epoch_beacon must end exactly at v2 header boundary");
}

#[test]
fn test_format_version_discriminator_values() {
    assert_eq!(MEASC_FORMAT_VERSION_V1, 0x00, "v1 discriminator must be 0x00");
    assert_eq!(MEASC_FORMAT_VERSION_V2, 0x02, "v2 discriminator must be 0x02");
    assert_ne!(MEASC_FORMAT_VERSION_V1, MEASC_FORMAT_VERSION_V2,
        "v1 and v2 discriminators must be distinct");
}
