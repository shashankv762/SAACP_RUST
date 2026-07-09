//! Integration tests for saacp-rs — Phase 7 completion
//!
//! Covers all remaining Phase 7 tasks:
//!   1. PSKCompromiseRecovery - epoch destruction + callback
//!   2. ThresholdAuthorityIssuer - 2-of-3 M-of-N signing flow
//!   3. CryptoTransparencyLedger - hash chain integrity
//!   4. KLMS - key lifecycle (register, rotate, revoke)
//!   5. CRYPTO_SUITES - registry governance (register_suite)
//!   6. CapabilityTransparencyLog - append + verify_chain_integrity
//!   7. ACSVAF - delegation depth constant + issue/verify round-trip
//!   8. PRODUCTION_POLICY singleton sanity
//!   9. Handler Gate 0 - garbage packet rejection

use std::sync::Arc;
use serde_json::{Map, Value};

use saacp::{
    SessionEpochManager, PSKCompromiseRecovery,
    ThresholdAuthorityIssuer,
    CapabilityIssuanceAuthority, CapabilitySigningKey, CapabilityVerificationAuthority,
    ACSVAF_MAX_DELEGATION_DEPTH,
    CapabilityTransparencyLog,
    CryptoTransparencyLedger, CryptoLedgerEntry, PRODUCTION_POLICY,
    KeyRegistry, KeyLifecycleManager, KeyAlgorithm, KeyCategory,
    make_kid, make_descriptor,
    CRYPTO_SUITES, register_suite,
    SAACPProtocolHandler,
};

// ─────────────────────────────────────────────────────────────
// 1. PSKCompromiseRecovery
// ─────────────────────────────────────────────────────────────

#[test]
fn psk_recovery_destroys_all_sessions() {
    let manager = Arc::new(SessionEpochManager::new());
    // create_session(session_id: [u8;16], secret: [u8;32], packet_threshold, time_threshold, transcript_hash)
    manager.create_session([0x01u8; 16], [0xAAu8; 32], 10_000, 600.0, None).unwrap();
    manager.create_session([0x02u8; 16], [0xBBu8; 32], 10_000, 600.0, None).unwrap();
    assert_eq!(manager.session_count(), 2);

    let recovery = PSKCompromiseRecovery::new(manager.clone(), None);
    let report = recovery.execute(Some(99));

    assert_eq!(report.sessions_destroyed, 2);
    assert_eq!(report.revocation_epoch, 99);
    assert!(report.recovery_complete);
    assert_eq!(manager.session_count(), 0);
}

#[test]
fn psk_recovery_empty_is_safe() {
    let manager = Arc::new(SessionEpochManager::new());
    let report = PSKCompromiseRecovery::new(manager, None).execute(None);
    assert_eq!(report.sessions_destroyed, 0);
    assert!(report.recovery_complete);
}

#[test]
fn psk_recovery_callback_fires() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let manager = Arc::new(SessionEpochManager::new());
    manager.create_session([0xFFu8; 16], [0xCCu8; 32], 1000, 60.0, None).unwrap();

    let fired = Arc::new(AtomicBool::new(false));
    let clone = fired.clone();
    let recovery = PSKCompromiseRecovery::new(
        manager,
        Some(Box::new(move || { clone.store(true, Ordering::SeqCst); Ok(()) })),
    );
    recovery.execute(Some(1));
    assert!(fired.load(Ordering::SeqCst), "gateway callback must fire on recovery");
}

// ─────────────────────────────────────────────────────────────
// 2. ThresholdAuthorityIssuer
// ─────────────────────────────────────────────────────────────

fn make_token_for(issuer_id: &str) -> saacp::SignedCapabilityToken {
    let sk = CapabilitySigningKey::generate(issuer_id, 3600);
    let cia = CapabilityIssuanceAuthority::new(sk);
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(issuer_id.into()));
    claims.insert("sub".into(), Value::String("threshold-sub".into()));
    claims.insert("jti".into(), Value::String(format!("jti-{}", issuer_id)));
    cia.issue(claims).expect("issue token")
}

#[test]
fn threshold_2_of_3_happy_path() {
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({"budget": 1000}));
    assert_eq!(issuer.pending_request_count(), 1);

    let state_a = issuer.submit_partial_approval(&req, "A", &make_token_for("A")).unwrap();
    assert_eq!(state_a.approvals_received, 1);
    assert!(!state_a.is_ready);

    let state_b = issuer.submit_partial_approval(&req, "B", &make_token_for("B")).unwrap();
    assert_eq!(state_b.approvals_received, 2);
    assert!(state_b.is_ready);

    let tt = issuer.assemble_threshold_token(&req).unwrap();
    assert_eq!(tt.threshold_m, 2);
    assert_eq!(tt.signatures.len(), 2);
    assert!(tt.participating_authorities.contains(&"A".to_string()));
    assert!(tt.participating_authorities.contains(&"B".to_string()));
}

#[test]
fn threshold_duplicate_rejected() {
    let issuer = ThresholdAuthorityIssuer::new(2, vec!["A".to_string(), "B".to_string()], 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({}));
    issuer.submit_partial_approval(&req, "A", &make_token_for("A")).unwrap();
    assert!(issuer.submit_partial_approval(&req, "A", &make_token_for("A")).is_err());
}

#[test]
fn threshold_rogue_authority_rejected() {
    let issuer = ThresholdAuthorityIssuer::new(1, vec!["legit".to_string()], 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({}));
    assert!(issuer.submit_partial_approval(&req, "rogue", &make_token_for("rogue")).is_err());
}

#[test]
fn threshold_assemble_fails_below_m() {
    let issuer = ThresholdAuthorityIssuer::new(3,
        vec!["a".to_string(), "b".to_string(), "c".to_string()], 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({}));
    issuer.submit_partial_approval(&req, "a", &make_token_for("a")).unwrap();
    issuer.submit_partial_approval(&req, "b", &make_token_for("b")).unwrap();
    let r = issuer.assemble_threshold_token(&req);
    assert!(r.is_err());
    assert!(r.unwrap_err().contains("2/3"));
}

#[test]
fn threshold_purge_expired() {
    let issuer = ThresholdAuthorityIssuer::new(1, vec!["a".to_string()], 0.001).unwrap();
    issuer.create_request(serde_json::json!({}));
    std::thread::sleep(std::time::Duration::from_millis(5));
    assert_eq!(issuer.purge_expired_requests(), 1);
    assert_eq!(issuer.pending_request_count(), 0);
}

// ─────────────────────────────────────────────────────────────
// 3. CryptoTransparencyLedger
// ─────────────────────────────────────────────────────────────

fn make_entry(i: u32) -> CryptoLedgerEntry {
    CryptoLedgerEntry {
        timestamp: 1_000_000.0 + i as f64,
        event_type: "TEST".into(),
        suite_name: "ed25519".into(),
        session_id: format!("s-{}", i),
        outcome: "APPROVED".into(),
        transcript_hash: format!("th-{}", i),
        details: format!("entry {}", i),
        entry_hash: String::new(),
    }
}

#[test]
fn crypto_ledger_chain_holds() {
    let ledger = CryptoTransparencyLedger::new();
    for i in 0..5 { ledger.append(make_entry(i)); }
    // CryptoTransparencyLedger::entries() returns Vec<CryptoLedgerEntry>
    assert_eq!(ledger.entries().len(), 5);
    assert!(ledger.verify_chain());
}

#[test]
fn crypto_ledger_reset_clears() {
    let ledger = CryptoTransparencyLedger::new();
    ledger.append(make_entry(0));
    ledger.reset();
    assert_eq!(ledger.entries().len(), 0);
    assert!(ledger.verify_chain());
}

// ─────────────────────────────────────────────────────────────
// 4. KLMS key lifecycle
// ─────────────────────────────────────────────────────────────

#[test]
fn klms_register_and_get() {
    let registry = KeyRegistry::new();
    let kid = make_kid();
    let desc = make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::TokenSigning,
        vec![0xAAu8; 32], None, None, None).unwrap();
    registry.register(desc).unwrap();
    let active = registry.get_active(&kid).unwrap();
    assert_eq!(active.kid, kid);
    assert!(registry.list_active_kids().contains(&kid));
}

#[test]
fn klms_rotate_and_revoke() {
    let registry = KeyRegistry::new();
    let kid = make_kid();
    let desc = make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::TokenSigning,
        vec![0x11u8; 32], None, None, None).unwrap();
    registry.register(desc).unwrap();

    let mgr = KeyLifecycleManager::new(registry, None);
    let rotated = mgr.rotate_key(&kid, vec![0x22u8; 32], KeyAlgorithm::Ed25519).unwrap();
    assert_eq!(rotated.version, 2);

    let record = mgr.revoke_key(&kid, "end-of-life").unwrap();
    assert_eq!(record.kid, kid);
    assert!(!mgr.get_revocation_log().is_empty());
}

// ─────────────────────────────────────────────────────────────
// 5. CRYPTO_SUITES registry governance
// ─────────────────────────────────────────────────────────────

#[test]
fn crypto_suites_has_ed25519() {
    assert!(CRYPTO_SUITES.lock().unwrap().contains(&"ed25519".to_string()));
}

#[test]
fn register_suite_needs_allow_override() {
    let l = CryptoTransparencyLedger::new();
    assert!(register_suite("xalg", "LAB", false, &l).is_err());
}

#[test]
fn register_suite_blocked_in_production() {
    let l = CryptoTransparencyLedger::new();
    assert!(register_suite("xalg", "PRODUCTION", true, &l).is_err());
}

#[test]
fn register_suite_ok_in_lab() {
    let l = CryptoTransparencyLedger::new();
    assert!(register_suite("test-suite-it-100", "LAB", true, &l).is_ok());
    assert!(CRYPTO_SUITES.lock().unwrap().contains(&"test-suite-it-100".to_string()));
}

// ─────────────────────────────────────────────────────────────
// 6. CapabilityTransparencyLog
// ─────────────────────────────────────────────────────────────

#[test]
fn cap_log_chain_and_jti_lookup() {
    let log = CapabilityTransparencyLog::new();
    // append(event, issuer, jti, kid, sub, aud: &[&str], actions: &[&str], depth, parent_jti, signing_key)
    log.append("ISSUED", "iss-1", Some("jti-A"), Some("kid-1"),
        "sub-1", &["agent-X"], &["read"], 0, None, None);
    log.append("DELEGATED", "iss-1", Some("jti-A"), Some("kid-1"),
        "sub-2", &["agent-Y"], &["read"], 1, Some("jti-A"), None);
    log.append("ISSUED", "iss-2", Some("jti-B"), Some("kid-2"),
        "sub-3", &["agent-Z"], &["write"], 0, None, None);

    assert_eq!(log.count(), 3);
    assert!(log.verify_chain_integrity());
    assert_eq!(log.get_entries_by_jti("jti-A").len(), 2);
    assert_eq!(log.get_entries_by_jti("jti-B").len(), 1);
}

// ─────────────────────────────────────────────────────────────
// 7. ACSVAF
// ─────────────────────────────────────────────────────────────

#[test]
fn acsvaf_depth_constant_is_3() {
    // Spec §5.7: MAX_DELEGATION_DEPTH = 3
    assert_eq!(ACSVAF_MAX_DELEGATION_DEPTH, 3);
}

#[test]
fn acsvaf_issue_verify_roundtrip() {
    let sk = CapabilitySigningKey::generate("issuer-X", 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;

    let cia = CapabilityIssuanceAuthority::new(sk);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);

    let mut claims = Map::new();
    claims.insert("kid".into(), Value::String(kid.clone()));
    claims.insert("sub".into(), Value::String("agent-bob".into()));
    claims.insert("iss".into(), Value::String("issuer-X".into()));
    claims.insert("jti".into(), Value::String("jti-roundtrip".into()));
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    claims.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("actions".into(), Value::Array(vec![
        Value::String("read".into()), Value::String("write".into()),
    ]));

    let token = cia.issue(claims).expect("issue token");
    let result = cva.verify(&token);
    assert!(result.is_ok(), "verify must succeed: {:?}", result);
    let v = result.unwrap();
    assert_eq!(v.sub, "agent-bob");
    assert!(v.actions.contains(&"read".to_string()));
    assert!(v.actions.contains(&"write".to_string()));
}

// ─────────────────────────────────────────────────────────────
// 8. PRODUCTION_POLICY
// ─────────────────────────────────────────────────────────────

#[test]
fn production_policy_approves_ed25519() {
    assert!(PRODUCTION_POLICY.is_approved("ed25519"));
    assert!(!PRODUCTION_POLICY.allow_experimental);
}

// ─────────────────────────────────────────────────────────────
// 9. Handler Gate 0 smoke test
// ─────────────────────────────────────────────────────────────

#[test]
fn handler_rejects_garbage() {
    assert!(SAACPProtocolHandler::intercept_packet(&[0xAAu8; 200], &[0x42u8; 32], "a", false).is_err());
}

#[test]
fn handler_rejects_wrong_magic() {
    let mut bad = vec![0u8; 120];
    bad[0] = b'X'; bad[1] = b'X'; bad[2] = b'X'; bad[3] = b'X';
    assert!(SAACPProtocolHandler::intercept_packet(&bad, &[0u8; 32], "a", false).is_err());
}
