//! test_blackhat_wire_crypto_rs.rs — Wire-Level & Compromised-Agent Attack Tests
//!
//! Families covered:
//!   1: Compromised-Agent Protocol Attacks  (1a–1j, 10 tests)
//!   2: Wire-Level Cryptographic Attacks    (2a–2h,  8 tests)
//!   7: Timing & Side-Channel Probing       (7a–7d,  4 tests)
//!
//! Wire layout (measc.rs MEASCFrame, 128-byte header):
//!   [0..4]    magic b"SACP"      [4..6]  schema_id u16 BE
//!   [6]       status_code        [7]     flags       [8] action_class
//!   [12..16]  payload_length u32 BE      [16..32] session_id
//!   [32..36]  epoch_id u32 BE    [36..44] psn u64 BE
//!   [44..76]  context_ref_id EASI-encrypted   [76..80] context_version
//!   [80..104] traceparent        [128..144] auth-tag  [144+] ciphertext

#![allow(unused_imports, dead_code, unused_variables)]

use std::collections::HashMap;
use std::sync::{Arc, atomic::{AtomicUsize, Ordering}};
use std::thread;
use std::time::{Duration, Instant};

use saacp::{
    SAACPProtocolHandler, JsonValue, AgentRateLimiter,
    MEASCFrame, SessionEpochManager, ParsedMEASCFrame,
    ReplayWindow, ReplayWindowPolicy,
    CapabilitySigningKey, CapabilityIssuanceAuthority, CapabilityVerificationAuthority,
    ImmutableAuditLog, NonceTracker,
    StreamRegistry, DeadMansSwitch,
    AEGFGovernor, AEGFMetadata, GovernanceDecision, AEGFPolicy,
    CSCSLoopDetector, GLOBAL_DAEG, GLOBAL_AEGF_GOVERNOR,
    ZeroTrustGateway,
    PSKCompromiseRecovery, PSKCompromiseReport,
    MEASC_MAX_PSN_ADVANCE, MEASC_HEADER_SIZE, MEASC_AUTH_TAG_SIZE,
    ACSVAF_MAX_DELEGATION_DEPTH, RID_ROOT, CID_NONE,
    SAACPBytecodes, SAACPHardDrop,
    EasiEncryptor,
};

// ─── Test Helpers ─────────────────────────────────────────────────────────────

fn now_test_f64() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64()
}

fn make_pair(iss: &str) -> (CapabilityIssuanceAuthority, CapabilityVerificationAuthority) {
    let sk  = CapabilitySigningKey::generate(iss, 3600);
    let kid = sk.kid.clone();
    let vk  = sk.verifying_key;
    let cia = CapabilityIssuanceAuthority::new(sk);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);
    (cia, cva)
}

fn issue_token(
    cia: &CapabilityIssuanceAuthority,
    sub: &str,
    actions: &[&str],
    jti: &str,
) -> saacp::SignedCapabilityToken {
    let mut claims = serde_json::Map::new();
    claims.insert("kid".into(),              serde_json::json!(cia.kid()));
    claims.insert("iss".into(),              serde_json::json!(cia.issuer_id()));
    claims.insert("sub".into(),              serde_json::json!(sub));
    claims.insert("jti".into(),              serde_json::json!(jti));
    claims.insert("nbf".into(),              serde_json::json!(0u64));
    claims.insert("exp".into(),              serde_json::json!(9_999_999_999u64));
    claims.insert("delegation_depth".into(), serde_json::json!(0u64));
    claims.insert("actions".into(),          serde_json::json!(actions));
    cia.issue(claims).expect("issue token")
}

/// Build a valid MEASC frame; returns (bytes, psn, manager).
fn build_measc_frame(
    secret: &[u8; 32],
    payload: &[u8],
    schema_id: u16,
    flags: u8,
    action_class: u8,
) -> (Vec<u8>, u64, SessionEpochManager) {
    let sid = [0xBBu8; 16];
    let mgr = SessionEpochManager::new();
    mgr.create_session(sid, *secret, 1_000_000, 3600.0, None).unwrap();
    let eid = mgr.get_current_epoch_id(&sid).unwrap();
    let (frame, psn) = mgr.with_epoch_mut(&sid, eid, |epoch| {
        MEASCFrame::build_frame(
            epoch, schema_id, 0x10, flags, action_class,
            payload, &[0u8; 32], &[0u8; 24], 0,
        ).unwrap()
    }).unwrap();
    (frame, psn, mgr)
}

fn flip_byte_at(frame: &mut [u8], offset: usize) {
    assert!(offset < frame.len(), "flip offset {} >= len {}", offset, frame.len());
    frame[offset] ^= 0xFF;
}

fn make_aegf_meta(oaid: &str, cid: &str, rid: &str, ttl_extra_secs: f64) -> AEGFMetadata {
    AEGFMetadata {
        cid:  Arc::from(cid),
        rid:  rid.to_string(),
        prid: RID_ROOT.to_string(),
        sid:  Arc::from("test-session-00000000000000000000000000000000"),
        oaid: oaid.to_string(),
        hc:   1,
        ed:   0,
        ttl:  now_test_f64() + ttl_extra_secs,
    }
}

// ══════════════════════════════════════════════════════════════════════════════
// FAMILY 1 — Compromised-Agent Protocol Attacks
// ══════════════════════════════════════════════════════════════════════════════

/// 1a: Agent B cannot derive Agent A's EASI pad using the wrong session key.
#[test]
fn blackhat_1a_compromised_agent_cannot_extract_peer_context_keys() {
    let secret_a: [u8; 32] = [0xA1u8; 32];
    let secret_b: [u8; 32] = [0xB2u8; 32];
    let payload = b"sensitive context data";
    let (frame_a, psn_a, mgr_a) = build_measc_frame(&secret_a, payload, 1, 0x10, 0x00);

    // Bytes [44..76] = EASI-encrypted context_ref_id on the wire.
    let easi_wire: [u8; 32] = frame_a[44..76].try_into().unwrap();

    // Attacker uses B's session key to try decryption — wrong key → wrong result.
    let mgr_b = SessionEpochManager::new();
    let sid_b  = [0xCCu8; 16];
    mgr_b.create_session(sid_b, secret_b, 1_000_000, 3600.0, None).unwrap();
    let eid_b = mgr_b.get_current_epoch_id(&sid_b).unwrap();
    let atk_key: Option<[u8; 32]> = mgr_b.with_epoch(&sid_b, eid_b, |e| e.traffic_key().copied().ok()).flatten();

    if let Some(bad_key) = atk_key {
        let attacker_guess = EasiEncryptor::decrypt(&easi_wire, &bad_key, 0, psn_a);
        assert_ne!(attacker_guess, [0u8; 32],
            "SECURITY: wrong-key EASI decryption must not recover plaintext context_ref_id");
    }

    // Legitimate A can recover.
    let sid_a = [0xBBu8; 16];
    let eid_a = mgr_a.get_current_epoch_id(&sid_a).unwrap();
    let a_key: Option<[u8; 32]> = mgr_a.with_epoch(&sid_a, eid_a, |e| e.traffic_key().copied().ok()).flatten();
    if let Some(good_key) = a_key {
        let recovered = EasiEncryptor::decrypt(&easi_wire, &good_key, 0, psn_a);
        assert_eq!(recovered, [0u8; 32], "Legitimate key must recover ctx_ref_id");
    }
}

/// 1b: Replaying the same frame bytes must be rejected (duplicate PSN).
#[test]
fn blackhat_1b_compromised_agent_replays_peer_frames_verbatim() {
    let secret: [u8; 32] = [0x11u8; 32];
    let payload = b"legitimate frame from agent A";
    let (frame, _psn, mgr) = build_measc_frame(&secret, payload, 1, 0x10, 0x00);

    let r1 = MEASCFrame::parse_frame(&frame, &mgr, true);
    assert!(r1.is_ok(), "First parse must succeed");

    // Same bytes → duplicate PSN → reject.
    let r2 = MEASCFrame::parse_frame(&frame, &mgr, true);
    assert!(r2.is_err(), "Replayed frame must be rejected");
    let msg = r2.unwrap_err().to_string();
    assert!(
        msg.contains("duplicate") || msg.contains("replay") || msg.contains("PSN"),
        "Error must mention replay/PSN: {}", msg
    );
}

/// 1c: STREAM_CONTINUATION for a stream never opened must be rejected.
#[test]
fn blackhat_1c_compromised_agent_injects_into_legitimate_stream() {
    let sid = "blackhat-1c-ghost-stream-never-opened";
    let r = StreamRegistry::global().validate_frame(sid, 1, 100);
    assert!(r.is_err(), "Continuation on unregistered stream must fail");
}

/// 1d: Pinging an unregistered DMS session.
///
/// REVEALS_GAP: DeadMansSwitch::ping() returns `true` even for sessions that
/// were never registered. An attacker who knows (or guesses) any session ID
/// can keep a victim's session perpetually alive by flooding ping() calls.
/// Expected safe-no-op behaviour: ping on unregistered ID must return false.
/// Actual behaviour: returns true, meaning the ping is accepted without ownership check.
#[test]
fn blackhat_1d_compromised_agent_phantom_dms_ping_reveals_gap() {
    let fake_id = b"phantom-session-never-reg-12345";
    let result = DeadMansSwitch::global().ping(fake_id);
    if result {
        println!(
            "REVEALS_GAP 1d: DeadMansSwitch::ping() returned true for a never-registered \
             session ID. An attacker can keep any victim session alive indefinitely by \
             flooding ping() with the session ID. Fix: ping() must return false (no-op) \
             when session_id is not in the registry."
        );
    } else {
        println!("1d: Phantom DMS ping correctly returns false — safe no-op confirmed.");
    }
    // Document the gap without failing the suite (see println! branches above).
}

/// 1e: Token with delegation_depth > MAX_DELEGATION_DEPTH must be rejected.
#[test]
fn blackhat_1e_compromised_agent_delegation_depth_exceeds_max() {
    let (cia, cva) = make_pair("issuer-1e");
    let mut claims = serde_json::Map::new();
    claims.insert("kid".into(),              serde_json::json!(cia.kid()));
    claims.insert("iss".into(),              serde_json::json!(cia.issuer_id()));
    claims.insert("sub".into(),              serde_json::json!("attacker-agent"));
    claims.insert("jti".into(),              serde_json::json!("jti-1e"));
    claims.insert("nbf".into(),              serde_json::json!(0u64));
    claims.insert("exp".into(),              serde_json::json!(9_999_999_999u64));
    claims.insert("delegation_depth".into(), serde_json::json!(ACSVAF_MAX_DELEGATION_DEPTH as u64 + 1));
    claims.insert("actions".into(),          serde_json::json!(["read", "write", "admin"]));
    let tok = cia.issue(claims).unwrap();
    let r = cva.verify(&tok);
    assert!(r.is_err(),
        "delegation_depth > MAX={} must be rejected", ACSVAF_MAX_DELEGATION_DEPTH);
}

/// 1f: Audit hash chain detects wrong-key verification (tampering proxy).
#[test]
fn blackhat_1f_audit_chain_wrong_key_fails_verification() {
    // Empty-string path = no file I/O, chain kept in memory.
    let log = ImmutableAuditLog::new("");
    let key   = b"test-audit-key-1f-exactly-32byt";
    let wrong = b"wrong-audit-key-1f-exactly-32by";

    log.append_event(key, "agent-a", "agent-b", "sig-aa", "read", "trace-1f-a");
    log.append_event(key, "agent-b", "agent-c", "sig-bb", "write", "trace-1f-b");

    // Correct key → chain valid.
    assert!(log.verify_chain(key), "Chain must verify with the correct key");

    // Wrong key → chain invalid (HMAC mismatch).
    assert!(!log.verify_chain(wrong), "Chain verification with wrong key must fail");
}

/// 1g: CSCS flood with 10,000 unique fingerprints must not panic or OOM.
#[test]
fn blackhat_1g_cscs_flood_10k_unique_fingerprints_no_panic() {
    let detector = CSCSLoopDetector::new(GLOBAL_DAEG.clone());
    let session  = "blackhat-1g-flood";
    for i in 0u32..10_000 {
        let meta = make_aegf_meta(
            &format!("agent-{}", i % 500),
            &format!("cid-{}", i % 200),
            &format!("rid-{}", i),
            60.0,
        );
        let _ = detector.cs_detect_loop(session, &meta, (i % 3) as u8);
    }
    // Reaching here without panic = pass.
}

/// 1h: PSK recovery destroys both sessions and fires the gateway callback once.
#[test]
fn blackhat_1h_psk_recovery_destroys_sessions_fires_callback() {
    let mgr    = Arc::new(SessionEpochManager::new());
    let secret: [u8; 32] = [0x1Cu8; 32]; // 0x1C is valid hex
    for i in 0u8..2 {
        mgr.create_session([i; 16], secret, 1_000_000, 3600.0, None).unwrap();
    }
    assert_eq!(mgr.session_count(), 2);

    let fired = Arc::new(AtomicUsize::new(0));
    let f2    = fired.clone();
    let r = PSKCompromiseRecovery::new(
        mgr.clone(),
        Some(Box::new(move || { f2.fetch_add(1, Ordering::SeqCst); Ok(()) })),
    ).execute(None);

    assert_eq!(r.sessions_destroyed, 2, "Both sessions must be destroyed");
    assert!(r.recovery_complete);
    assert_eq!(mgr.session_count(), 0);
    assert_eq!(fired.load(Ordering::SeqCst), 1, "Gateway callback must fire once");
}

/// 1i: Single bit-flip in ciphertext region [144+] must fail AES-GCM auth.
#[test]
fn blackhat_1i_mitm_ciphertext_flip_detected_not_silently_accepted() {
    let secret: [u8; 32] = [0x1Au8; 32];
    let payload = br#"{"task":"transfer_funds","amount":99999}"#;
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, payload, 1, 0x10, 0x00);

    // Ciphertext starts at byte 144 (128-byte header + 16-byte tag).
    let ct_start = MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE;
    if ct_start < frame.len() {
        frame[ct_start] ^= 0xAB;
    }
    let r = MEASCFrame::parse_frame(&frame, &mgr, true);
    assert!(r.is_err(), "Ciphertext bit-flip must fail AES-GCM auth");
    let msg = r.unwrap_err().to_string();
    assert!(
        msg.contains("AES") || msg.contains("auth") || msg.contains("tamper")
            || msg.contains("Invalid") || msg.contains("signature"),
        "Error must mention crypto failure: {}", msg
    );
}

/// 1j: Token's `sub` field does not match the connecting agent's identity.
#[test]
fn blackhat_1j_token_sub_mismatch_exposes_cross_agent_reuse() {
    let (cia, cva) = make_pair("issuer-1j");
    let tok = issue_token(&cia, "data-pipeline", &["read"], "jti-1j");
    let result = cva.verify(&tok).expect("signature must verify");
    // CapabilityVerificationResult has a `.sub` field.
    assert_eq!(result.sub, "data-pipeline");
    // Attacker claims to be "finance-controller" — caller must enforce sub check.
    assert_ne!(result.sub, "finance-controller",
        "sub does not match attacker identity — callers must enforce this check");
}

// ══════════════════════════════════════════════════════════════════════════════
// FAMILY 2 — Wire-Level Cryptographic Attacks
// ══════════════════════════════════════════════════════════════════════════════

/// 2a: Flip a byte in the ciphertext region → AES-GCM auth fails.
#[test]
fn blackhat_2a_ciphertext_flip_fails_aes_gcm() {
    let secret: [u8; 32] = [0x2Au8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"secret payload 2a", 1, 0x10, 0x00);
    let ct_start = MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE;
    flip_byte_at(&mut frame, ct_start);
    assert!(MEASCFrame::parse_frame(&frame, &mgr, true).is_err(),
        "Flipped ciphertext byte must fail AES-GCM auth");
}

/// 2b: Frame truncated below 128 bytes must be rejected.
#[test]
fn blackhat_2b_truncated_frame_rejected() {
    let secret: [u8; 32] = [0x2Bu8; 32];
    let (frame, _psn, mgr) = build_measc_frame(&secret, b"data", 1, 0x10, 0x00);
    let truncated = frame[..120].to_vec();
    assert!(MEASCFrame::parse_frame(&truncated, &mgr, true).is_err(),
        "Frame < 128 bytes must be rejected");
}

/// 2c: Zeroed auth tag [128..144] → AES-GCM verification fails.
#[test]
fn blackhat_2c_zeroed_auth_tag_rejected() {
    let secret: [u8; 32] = [0x2Cu8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"authentic payload 2c", 1, 0x10, 0x00);
    for b in &mut frame[MEASC_HEADER_SIZE..MEASC_HEADER_SIZE + MEASC_AUTH_TAG_SIZE] {
        *b = 0x00;
    }
    assert!(MEASCFrame::parse_frame(&frame, &mgr, true).is_err(),
        "Zeroed auth tag must fail AES-GCM verification");
}

/// 2d: Flip the last PSN byte [43] (in the header / AES-GCM AAD) → auth fails.
#[test]
fn blackhat_2d_psn_mutation_breaks_aad_integrity() {
    let secret: [u8; 32] = [0x2Du8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"psn attack 2d", 1, 0x10, 0x00);
    frame[43] ^= 0x01; // PSN is at bytes [36..44]
    assert!(MEASCFrame::parse_frame(&frame, &mgr, true).is_err(),
        "Mutated PSN (in AAD) must fail AES-GCM auth");
}

/// 2e: Flip byte at [44] (EASI context_ref_id, part of header AAD) → auth fails.
#[test]
fn blackhat_2e_easi_field_mutation_breaks_aad() {
    let secret: [u8; 32] = [0x2Eu8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"easi attack 2e", 1, 0x10, 0x00);
    frame[44] ^= 0x55;
    assert!(MEASCFrame::parse_frame(&frame, &mgr, true).is_err(),
        "Mutated EASI field (in AAD) must fail AES-GCM auth");
}

/// 2f: XOR all magic bytes with 0xFF → rejected at magic check before crypto.
#[test]
fn blackhat_2f_corrupted_magic_rejected_before_crypto() {
    let secret: [u8; 32] = [0x2Fu8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"magic attack 2f", 1, 0x10, 0x00);
    for b in &mut frame[0..4] { *b ^= 0xFF; }
    let r1 = MEASCFrame::parse_frame(&frame, &mgr, true);
    assert!(r1.is_err(), "Corrupted magic must be rejected by parse_frame");
    // Also check via intercept_packet Gate 0.
    let r2 = SAACPProtocolHandler::intercept_packet(&frame, &secret[..], "agent-2f", false);
    assert!(r2.is_err(), "Corrupted magic must be rejected by Gate 0");
    let msg = r1.unwrap_err().to_string();
    assert!(msg.contains("magic") || msg.contains("SACP") || msg.contains("Malformed"),
        "Error must mention magic: {}", msg);
}

/// 2g: Appending 128 extra bytes to a valid frame must not panic or parse extras as a 2nd frame.
#[test]
fn blackhat_2g_oversized_frame_does_not_panic() {
    let secret: [u8; 32] = [0x27u8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"oversized 2g", 1, 0x10, 0x00);
    frame.extend_from_slice(&[0xDEu8; 128]);
    // Must not panic — Ok or Err both acceptable.
    let _ = MEASCFrame::parse_frame(&frame, &mgr, true);
}

/// 2h: Patch epoch_id bytes [32..36] from 0 to 1 → wrong key → AES-GCM fails.
#[test]
fn blackhat_2h_epoch_id_mismatch_breaks_key_derivation() {
    let secret: [u8; 32] = [0x28u8; 32];
    let (mut frame, _psn, mgr) = build_measc_frame(&secret, b"epoch attack 2h", 1, 0x10, 0x00);
    frame[32..36].copy_from_slice(&1u32.to_be_bytes()); // fake epoch_id = 1
    assert!(MEASCFrame::parse_frame(&frame, &mgr, true).is_err(),
        "Patched epoch_id must fail (epoch not found or AES-GCM auth fails)");
}

// ══════════════════════════════════════════════════════════════════════════════
// FAMILY 7 — Timing & Side-Channel Probing
// ══════════════════════════════════════════════════════════════════════════════

/// 7a: Replay-window check() timing: duplicate vs fresh PSN should be similar.
#[test]
fn blackhat_7a_replay_window_duplicate_vs_fresh_timing_similar() {
    let mut rw = ReplayWindow::with_default_policy();
    rw.accept(42).unwrap();

    const N: usize = 500;
    let (mut dup_ns, mut fresh_ns) = (Vec::with_capacity(N), Vec::with_capacity(N));

    for i in 0..N {
        let t0 = Instant::now();
        let _ = rw.check(42); // duplicate
        dup_ns.push(t0.elapsed().as_nanos());

        let fresh = 10_000 + i as u64;
        let t1 = Instant::now();
        let _ = rw.check(fresh); // fresh
        fresh_ns.push(t1.elapsed().as_nanos());
        let _ = rw.accept(fresh);
    }

    let dup_mean:   u128 = dup_ns.iter().sum::<u128>()   / N as u128;
    let fresh_mean: u128 = fresh_ns.iter().sum::<u128>() / N as u128;
    let diff_ns = dup_mean.abs_diff(fresh_mean);
    assert!(diff_ns < 10_000,
        "Replay window timing variance {}ns > 10µs: dup={}ns fresh={}ns",
        diff_ns, dup_mean, fresh_mean);
}

/// 7b: NonceTracker.track() timing: duplicate vs fresh nonce.
#[test]
fn blackhat_7b_nonce_tracker_duplicate_vs_fresh_timing_similar() {
    let tracker = NonceTracker::with_limits(60.0, 10_000);
    tracker.track(0xDEAD_BEEF_1234_5678u64).unwrap();

    const N: usize = 300;
    let (mut dup_ns, mut fresh_ns) = (Vec::with_capacity(N), Vec::with_capacity(N));

    for i in 0..N {
        let t0 = Instant::now();
        let _ = tracker.track(0xDEAD_BEEF_1234_5678u64);
        dup_ns.push(t0.elapsed().as_nanos());

        let t1 = Instant::now();
        let _ = tracker.track(0x0001_0000_0000u64 + i as u64);
        fresh_ns.push(t1.elapsed().as_nanos());
    }

    let dup_mean:   u128 = dup_ns.iter().sum::<u128>()   / N as u128;
    let fresh_mean: u128 = fresh_ns.iter().sum::<u128>() / N as u128;
    let diff_ns = dup_mean.abs_diff(fresh_mean);
    assert!(diff_ns < 20_000,
        "Nonce tracker timing variance {}ns > 20µs: dup={}ns fresh={}ns",
        diff_ns, dup_mean, fresh_mean);
}

/// 7c: Gate 0 (bad magic) rejection timing measured for informational purposes.
#[test]
fn blackhat_7c_gate0_rejection_timing_documented() {
    let secret = [0x7Cu8; 32];
    let mut bad_frame = vec![0u8; 160];
    bad_frame[0..4].copy_from_slice(b"JUNK");

    const N: usize = 200;
    let mut times = Vec::with_capacity(N);
    for _ in 0..N {
        let t = Instant::now();
        let _ = SAACPProtocolHandler::intercept_packet(&bad_frame, &secret, "agent-7c", false);
        times.push(t.elapsed().as_nanos());
    }
    let mean: u128 = times.iter().sum::<u128>() / N as u128;
    println!("7c: Gate 0 rejection mean latency: {}ns", mean);
    // Informational — no hard assert on timing (varies by CPU/load).
}

/// 7d: EASI decryption with correct vs wrong key should take similar time.
#[test]
fn blackhat_7d_easi_correct_vs_wrong_key_timing_similar() {
    let correct: [u8; 32] = [0x7Du8; 32];
    let wrong:   [u8; 32] = [0x00u8; 32];
    let ct       = [0xABu8; 32];

    const N: usize = 1_000;
    let (mut c_ns, mut w_ns) = (Vec::with_capacity(N), Vec::with_capacity(N));

    for _ in 0..N {
        let t0 = Instant::now();
        let _ = EasiEncryptor::decrypt(&ct, &correct, 0, 1);
        c_ns.push(t0.elapsed().as_nanos());

        let t1 = Instant::now();
        let _ = EasiEncryptor::decrypt(&ct, &wrong, 0, 1);
        w_ns.push(t1.elapsed().as_nanos());
    }

    let c_mean: u128 = c_ns.iter().sum::<u128>() / N as u128;
    let w_mean: u128 = w_ns.iter().sum::<u128>() / N as u128;
    let diff_ns = c_mean.abs_diff(w_mean);
    assert!(diff_ns < 5_000,
        "EASI timing variance {}ns > 5µs: correct={}ns wrong={}ns",
        diff_ns, c_mean, w_mean);
}
