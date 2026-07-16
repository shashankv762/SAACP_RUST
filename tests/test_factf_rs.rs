//! test_factf_rs.rs — FACTF Federated Authorization and Cryptographic Trust Framework tests
//!
//! Ports Python: tests/test_factf.py
//! DelegationChainValidator, ThresholdAuthorityIssuer, CapabilityTransparencyLog,
//! RiskAwareAuthorizationEvaluator, PostCompromiseRecovery.

use serde_json::{Map, Value};
use saacp::{
    CapabilitySigningKey, CapabilityIssuanceAuthority, CapabilityVerificationAuthority,
    DelegationChainValidator,
    ThresholdAuthorityIssuer, ThresholdCapabilityToken, ThresholdSignatureEntry,
    CapabilityTransparencyLog,
    RiskAwareAuthorizationEvaluator, AuthorizationContext,
    PostCompromiseRecovery, CompromiseRecoveryReport,
    FilesystemBackend, TransparencyLogBackend,
};

/// Unique scratch file path under the OS temp dir for `FilesystemBackend` tests —
/// avoids collisions between parallel test threads without adding a `tempfile` dev-dependency.
fn scratch_path(tag: &str) -> String {
    let dir = std::env::temp_dir();
    let pid = std::process::id();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.join(format!("saacp_test_tlog_{tag}_{pid}_{nonce}.jsonl"))
        .to_string_lossy()
        .into_owned()
}

fn make_ca_pair(iss: &str) -> (CapabilityIssuanceAuthority, CapabilityVerificationAuthority) {
    let sk = CapabilitySigningKey::generate(iss, 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;
    let cia = CapabilityIssuanceAuthority::new(sk);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);
    (cia, cva)
}

fn simple_token(cia: &CapabilityIssuanceAuthority, sub: &str, jti: &str) -> saacp::SignedCapabilityToken {
    let mut claims = Map::new();
    claims.insert("kid".into(), Value::String(cia.kid().to_string()));
    claims.insert("iss".into(), Value::String(cia.issuer_id().to_string()));
    claims.insert("sub".into(), Value::String(sub.to_string()));
    claims.insert("jti".into(), Value::String(jti.to_string()));
    claims.insert("nbf".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    claims.insert("actions".into(), Value::Array(vec![Value::String("read".to_string())]));
    claims.insert("sid".into(), Value::String("sid-common".to_string()));
    claims.insert("max_action_class".into(), Value::Number(serde_json::Number::from(1u64)));
    claims.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(0u64)));
    cia.issue(claims).expect("issue token")
}

fn make_token_for(issuer_id: &str) -> saacp::SignedCapabilityToken {
    let sk = CapabilitySigningKey::generate(issuer_id, 3600);
    let cia = CapabilityIssuanceAuthority::new(sk);
    let mut claims = Map::new();
    claims.insert("iss".into(), Value::String(issuer_id.into()));
    claims.insert("sub".into(), Value::String("threshold-sub".into()));
    claims.insert("jti".into(), Value::String(format!("jti-{}", issuer_id)));
    claims.insert("nbf".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    claims.insert("actions".into(), Value::Array(vec![]));
    cia.issue(claims).expect("issue token")
}

// ─── DelegationChainValidator ────────────────────────────────────────────────

#[test]
fn test_validate_chain_empty_fails() {
    let (_, cva) = make_ca_pair("iss-del-1");
    let result = DelegationChainValidator::validate_chain(&[], &cva);
    assert!(!result.valid, "Empty chain must not be valid");
    assert!(!result.violations.is_empty());
}

#[test]
fn test_validate_chain_single_token_ok() {
    let (cia, cva) = make_ca_pair("iss-del-2");
    let tok = simple_token(&cia, "sub-1", "jti-single");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    assert!(result.valid, "Single valid token chain must validate: {:?}", result.violations);
}

#[test]
fn test_validate_chain_tampered_signature_fails() {
    let (cia, cva) = make_ca_pair("iss-del-3");
    let mut tok = simple_token(&cia, "sub-1", "jti-badsig");
    tok.signature = [0u8; 64];
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    assert!(!result.valid, "Tampered token must not validate");
    assert!(!result.violations.is_empty());
}

#[test]
fn test_validate_chain_has_root_jti() {
    let (cia, cva) = make_ca_pair("iss-del-4");
    let tok = simple_token(&cia, "sub-1", "jti-root");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    assert_eq!(result.root_jti, "jti-root");
}

#[test]
fn test_validate_chain_depth_zero_for_single_token() {
    let (cia, cva) = make_ca_pair("iss-del-5");
    let tok = simple_token(&cia, "sub-1", "jti-d0");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    if result.valid {
        assert_eq!(result.depth, 0);
    }
}

#[test]
fn test_validate_chain_unknown_kid_violation() {
    let (cia, _) = make_ca_pair("iss-del-6");
    let cva_empty = CapabilityVerificationAuthority::new();
    let tok = simple_token(&cia, "sub-1", "jti-unkid");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva_empty);
    assert!(!result.valid);
    assert!(!result.violations.is_empty(), "Unknown kid must produce violation");
}

#[test]
fn test_validate_chain_final_jti_set() {
    let (cia, cva) = make_ca_pair("iss-del-7");
    let tok = simple_token(&cia, "sub-final", "jti-final");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    assert_eq!(result.final_jti, "jti-final");
}

#[test]
fn test_validate_chain_violations_empty_when_valid() {
    let (cia, cva) = make_ca_pair("iss-del-8");
    let tok = simple_token(&cia, "sub-clean", "jti-clean");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    assert!(result.violations.is_empty(), "Valid chain must have no violations");
}

// ─── ThresholdAuthorityIssuer ─────────────────────────────────────────────────

#[test]
fn test_threshold_2_of_3_constructs() {
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    assert!(ThresholdAuthorityIssuer::new(2, auths, 300.0).is_ok());
}

#[test]
fn test_threshold_m_greater_than_n_fails() {
    let auths = vec!["A".to_string(), "B".to_string()];
    assert!(ThresholdAuthorityIssuer::new(5, auths, 300.0).is_err());
}

#[test]
fn test_threshold_m_zero_fails() {
    let auths = vec!["A".to_string()];
    assert!(ThresholdAuthorityIssuer::new(0, auths, 300.0).is_err());
}

#[test]
fn test_threshold_happy_path_2_of_3() {
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({"budget": 1000}));
    assert_eq!(issuer.pending_request_count(), 1);

    let s1 = issuer.submit_partial_approval(&req, "A", &make_token_for("A")).unwrap();
    assert_eq!(s1.approvals_received, 1);
    assert!(!s1.is_ready);

    let s2 = issuer.submit_partial_approval(&req, "B", &make_token_for("B")).unwrap();
    assert_eq!(s2.approvals_received, 2);
    assert!(s2.is_ready, "2 approvals must reach threshold");
}

#[test]
fn test_threshold_unknown_authority_fails() {
    let auths = vec!["A".to_string(), "B".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({"x": 1}));
    assert!(issuer.submit_partial_approval(&req, "UNKNOWN", &make_token_for("UNKNOWN")).is_err());
}

#[test]
fn test_threshold_duplicate_authority_rejected() {
    let auths = vec!["A".to_string(), "B".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({"x": 1}));
    issuer.submit_partial_approval(&req, "A", &make_token_for("A")).unwrap();
    assert!(
        issuer.submit_partial_approval(&req, "A", &make_token_for("A")).is_err(),
        "Duplicate authority must be rejected"
    );
}

#[test]
fn test_threshold_1_of_1_ready_immediately() {
    let auths = vec!["Solo".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(1, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({}));
    let s = issuer.submit_partial_approval(&req, "Solo", &make_token_for("Solo")).unwrap();
    assert!(s.is_ready);
}

#[test]
fn test_threshold_assemble_token_after_threshold() {
    let auths = vec!["X".to_string(), "Y".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(1, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({"op": "transfer"}));
    issuer.submit_partial_approval(&req, "X", &make_token_for("X")).unwrap();
    let tok = issuer.assemble_threshold_token(&req).unwrap();
    assert_eq!(tok.request_id, req);
    assert_eq!(tok.threshold_m, 1);
    assert_eq!(tok.signatures.len(), 1);
}

#[test]
fn test_threshold_assemble_fails_below_threshold() {
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 300.0).unwrap();
    let req = issuer.create_request(serde_json::json!({}));
    // Only 1 approval submitted, threshold is 2
    issuer.submit_partial_approval(&req, "A", &make_token_for("A")).unwrap();
    assert!(issuer.assemble_threshold_token(&req).is_err());
}

// ─── CRIT-3 / CRIT-4: verify_threshold_token hardening ───────────────────────
//
// CRIT-3: verify_threshold_token must compare valid_count against the
// issuer's own configured threshold (self.m), never the token's
// self-declared threshold_m field.
//
// CRIT-4: every signature in a ThresholdCapabilityToken must be verified
// against the token's shared base_claims — never against a per-entry
// claims payload — so M signatures over M different payloads can never be
// packaged as one valid M-of-N consensus.

/// Generate a fresh keypair for `issuer_id`, register the verifying key with
/// `cva`, sign `claims_for_signature`, and return a ThresholdSignatureEntry
/// ready to be packaged into a ThresholdCapabilityToken.
fn make_verified_entry(
    cva: &CapabilityVerificationAuthority,
    issuer_id: &str,
    claims_for_signature: &[u8],
) -> ThresholdSignatureEntry {
    let sk = CapabilitySigningKey::generate(issuer_id, 3600);
    let kid = sk.kid.clone();
    cva.register_key(&kid, sk.verifying_key);
    let sig = sk.sign(claims_for_signature);
    ThresholdSignatureEntry {
        kid,
        issuer_id: issuer_id.to_string(),
        signature_hex: hex::encode(sig.to_bytes()),
        claims_bytes_hex: hex::encode(claims_for_signature),
    }
}

#[test]
fn test_crit3_verify_rejects_self_declared_low_threshold() {
    // Issuer requires M=3, but the attacker forges a token declaring
    // threshold_m=1 while attaching only one genuinely valid signature.
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(3, auths, 300.0).unwrap();
    let cva = CapabilityVerificationAuthority::new();

    let base_claims = serde_json::json!({"action": "wire_transfer", "amount": 100000});
    let claims_bytes = serde_json::to_vec(&base_claims).unwrap();
    let entry = make_verified_entry(&cva, "A", &claims_bytes);

    let forged = ThresholdCapabilityToken {
        request_id: "forged-req-crit3".to_string(),
        base_claims,
        signatures: vec![entry],
        threshold_m: 1, // attacker-controlled field — must be ignored entirely
        participating_authorities: vec!["A".to_string()],
    };

    assert!(
        !issuer.verify_threshold_token(&forged, &cva),
        "CRIT-3: a token with only 1 valid signature must be rejected when the \
         issuer requires M=3, regardless of the token's self-declared threshold_m=1"
    );
}

#[test]
fn test_crit4_verify_rejects_signatures_over_different_claims() {
    // Three authorities each sign a DIFFERENT (individually benign) payload.
    // Packaging all three under one arbitrary base_claims must NOT satisfy
    // consensus, even though each signature is individually valid.
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(3, auths, 300.0).unwrap();
    let cva = CapabilityVerificationAuthority::new();

    let entry_a = make_verified_entry(&cva, "A", br#"{"benign":"request-a"}"#);
    let entry_b = make_verified_entry(&cva, "B", br#"{"benign":"request-b"}"#);
    let entry_c = make_verified_entry(&cva, "C", br#"{"benign":"request-c"}"#);

    let forged = ThresholdCapabilityToken {
        request_id: "forged-req-crit4".to_string(),
        base_claims: serde_json::json!({"action": "delete_production_database"}),
        signatures: vec![entry_a, entry_b, entry_c],
        threshold_m: 3,
        participating_authorities: vec!["A".to_string(), "B".to_string(), "C".to_string()],
    };

    assert!(
        !issuer.verify_threshold_token(&forged, &cva),
        "CRIT-4: signatures made over claims other than base_claims must never \
         count towards the threshold, even if each is individually valid"
    );
}

#[test]
fn test_threshold_verify_accepts_genuine_consensus_over_base_claims() {
    // Positive path: 3 authorities genuinely sign the exact base_claims bytes.
    // Must be ACCEPTED — proves the CRIT-3/CRIT-4 fix does not break
    // legitimate M-of-N consensus.
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(3, auths, 300.0).unwrap();
    let cva = CapabilityVerificationAuthority::new();

    let base_claims = serde_json::json!({"action": "approve_release", "version": "2.0"});
    let claims_bytes = serde_json::to_vec(&base_claims).unwrap();

    let entry_a = make_verified_entry(&cva, "A", &claims_bytes);
    let entry_b = make_verified_entry(&cva, "B", &claims_bytes);
    let entry_c = make_verified_entry(&cva, "C", &claims_bytes);

    let token = ThresholdCapabilityToken {
        request_id: "genuine-req".to_string(),
        base_claims,
        signatures: vec![entry_a, entry_b, entry_c],
        threshold_m: 3,
        participating_authorities: vec!["A".to_string(), "B".to_string(), "C".to_string()],
    };

    assert!(
        issuer.verify_threshold_token(&token, &cva),
        "3 genuine signatures over the exact base_claims bytes with issuer m=3 \
         must be accepted"
    );
}

#[test]
fn test_crit3_verify_rejects_when_below_real_threshold_even_if_token_claims_enough() {
    // Attacker sets threshold_m equal to the real M, but only supplies fewer
    // genuinely valid signatures than required — must still be rejected on
    // signature count, independent of the CRIT-3 field-trust bug.
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(3, auths, 300.0).unwrap();
    let cva = CapabilityVerificationAuthority::new();

    let base_claims = serde_json::json!({"action": "approve_release"});
    let claims_bytes = serde_json::to_vec(&base_claims).unwrap();
    let entry_a = make_verified_entry(&cva, "A", &claims_bytes);
    let entry_b = make_verified_entry(&cva, "B", &claims_bytes);

    let token = ThresholdCapabilityToken {
        request_id: "under-threshold-req".to_string(),
        base_claims,
        signatures: vec![entry_a, entry_b],
        threshold_m: 3,
        participating_authorities: vec!["A".to_string(), "B".to_string()],
    };

    assert!(
        !issuer.verify_threshold_token(&token, &cva),
        "2 valid signatures must not satisfy an issuer requiring M=3"
    );
}

// ─── submit_partial_approval: opt-in cryptographic verification ──────────────
//
// When a CapabilityVerificationAuthority is registered on the issuer,
// submit_partial_approval must reject any approval whose signature is not a
// valid Ed25519 signature over the proposal's base_claims — closing the hole
// where the only prior check was "signature is not all-zero".

/// Build a `SignedCapabilityToken` carrying `kid` in its claims and a signature
/// (by `sk`) over `sign_over` — decoupled from the token's own claims so a test
/// can produce a signature over the proposal base_claims OR over unrelated bytes.
fn threshold_approval_token(
    sk: &CapabilitySigningKey,
    kid: &str,
    sign_over: &[u8],
) -> saacp::SignedCapabilityToken {
    let mut claims = Map::new();
    claims.insert("kid".into(), Value::String(kid.into()));
    let sig = sk.sign(sign_over);
    saacp::SignedCapabilityToken { claims, signature: sig.to_bytes() }
}

#[test]
fn test_submit_rejects_forged_approval_when_cva_registered() {
    let auths = vec!["A".to_string(), "B".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 300.0).unwrap();
    let cva = std::sync::Arc::new(CapabilityVerificationAuthority::new());
    issuer.register_verification_authority(std::sync::Arc::clone(&cva));

    let base_claims = serde_json::json!({"action": "wire_transfer", "amount": 100000});
    let req = issuer.create_request(base_claims.clone());
    let base_bytes = serde_json::to_vec(&base_claims).unwrap();

    // Authority A registers its key but signs SOMETHING ELSE (not base_claims).
    let sk = CapabilitySigningKey::generate("A", 3600);
    let kid = sk.kid.clone();
    cva.register_key(&kid, sk.verifying_key);
    let forged = threshold_approval_token(&sk, &kid, br#"{"unrelated":"payload"}"#);

    assert!(
        issuer.submit_partial_approval(&req, "A", &forged).is_err(),
        "a non-zero but wrong-payload signature must be rejected once a CVA is registered"
    );

    // And a signature over the correct base_claims is accepted.
    let genuine = threshold_approval_token(&sk, &kid, &base_bytes);
    assert!(
        issuer.submit_partial_approval(&req, "A", &genuine).is_ok(),
        "a valid signature over base_claims must be accepted"
    );
}

#[test]
fn test_submit_rejects_unknown_kid_when_cva_registered() {
    let auths = vec!["A".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(1, auths, 300.0).unwrap();
    let cva = std::sync::Arc::new(CapabilityVerificationAuthority::new());
    issuer.register_verification_authority(std::sync::Arc::clone(&cva));

    let base_claims = serde_json::json!({"op": "release"});
    let req = issuer.create_request(base_claims.clone());
    let base_bytes = serde_json::to_vec(&base_claims).unwrap();

    // Key is NEVER registered with the CVA — fail closed.
    let sk = CapabilitySigningKey::generate("A", 3600);
    let kid = sk.kid.clone();
    let token = threshold_approval_token(&sk, &kid, &base_bytes);

    assert!(
        issuer.submit_partial_approval(&req, "A", &token).is_err(),
        "an approval whose kid has no registered verification key must be rejected"
    );
}

// ─── CapabilityTransparencyLog ───────────────────────────────────────────────
#[test]
fn test_transparency_log_new_empty_integrity() {
    let log = CapabilityTransparencyLog::new();
    assert!(log.verify_chain_integrity());
    assert_eq!(log.count(), 0);
}

#[test]
fn test_transparency_log_append_count() {
    let log = CapabilityTransparencyLog::new();
    log.append("ISSUED", "iss-1", Some("jti-1"), None, "sub-1", &[], &["read"], 0, None, None);
    assert_eq!(log.count(), 1);
}

#[test]
fn test_transparency_log_chain_integrity_after_appends() {
    let log = CapabilityTransparencyLog::new();
    for i in 0..5u32 {
        let jti = format!("jti-{}", i);
        log.append(
            "ISSUED", "iss-tl", Some(jti.as_str()), None,
            "sub", &[], &["read"], 0, None, None,
        );
    }
    assert_eq!(log.count(), 5);
    assert!(log.verify_chain_integrity(), "Chain must be intact after sequential appends");
}

/// M-30 regression: `verify_chain_integrity` caches its result, invalidated
/// only by `append()`. Calling it repeatedly WITHOUT an intervening append
/// must keep returning the correct (unchanged) answer (exercising the
/// cache-hit path), and calling it again immediately AFTER each append must
/// correctly reflect the newly-appended entry (exercising cache
/// invalidation) — interleaved across many appends, not just checked once
/// at the end, so a caching bug that only shows up on the Nth cache
/// hit/invalidation cycle would be caught.
#[test]
fn m30_verify_chain_integrity_cache_tracks_current_state_across_interleaved_calls() {
    let log = CapabilityTransparencyLog::new();

    // Empty log: first call computes and caches; second call (no append in
    // between) must hit the cache and still return the same correct answer.
    assert!(log.verify_chain_integrity());
    assert!(log.verify_chain_integrity(), "repeated call with no append must stay consistent");

    for i in 0..20u32 {
        let jti = format!("jti-interleaved-{}", i);
        log.append(
            "ISSUED", "iss-tl-interleaved", Some(jti.as_str()), None,
            "sub", &[], &["read"], 0, None, None,
        );
        // Immediately after append: cache must be invalidated by the
        // generation bump and recomputed against the new entry.
        assert!(
            log.verify_chain_integrity(),
            "must reflect the just-appended entry (iteration {i}), not a stale cached result"
        );
        // A second call right after, with no further append: must hit the
        // now-fresh cache and return the same correct answer again.
        assert!(
            log.verify_chain_integrity(),
            "repeated call immediately after append must stay consistent (iteration {i})"
        );
    }
    assert_eq!(log.count(), 20);
}

/// M-30: the cache must also invalidate correctly across the H-26
/// capacity-eviction path (which mutates `chain_floor_hash`, not just
/// `last_hash`/backend content) — every append while at capacity still
/// goes through the same single `generation` bump, so this must behave
/// identically to the below-capacity case above.
#[test]
fn m30_verify_chain_integrity_cache_correct_across_capacity_eviction() {
    let log = CapabilityTransparencyLog::with_capacity(5);
    for i in 0..15u32 {
        let jti = format!("jti-cap-{}", i);
        log.append(
            "ISSUED", "iss-tl-cap", Some(jti.as_str()), None,
            "sub", &[], &["read"], 0, None, None,
        );
        assert!(
            log.verify_chain_integrity(),
            "must verify correctly immediately after append {i}, including once eviction begins"
        );
    }
    assert_eq!(log.count(), 5, "must stay at capacity throughout");
    assert_eq!(log.pruned_count(), 10);
    // Final steady-state check with no intervening append (cache-hit path).
    assert!(log.verify_chain_integrity());
}

/// H-26: the backend must be capacity-bounded (not grow forever), must evict
/// oldest-first, and must keep the hash chain verifiable over the retained
/// window after eviction — rolling the log over must never look like
/// tampering.
#[test]
fn h26_transparency_log_bounded_with_verifiable_chain_after_eviction() {
    let log = CapabilityTransparencyLog::with_capacity(10);
    for i in 0..25u32 {
        let jti = format!("jti-{}", i);
        log.append(
            "ISSUED", "iss-tl", Some(jti.as_str()), None,
            "sub", &[], &["read"], 0, None, None,
        );
    }
    // Bounded: never exceeds the configured cap despite 25 appends.
    assert_eq!(log.count(), 10);
    // Honest about what rolled off.
    assert_eq!(log.pruned_count(), 15);
    // Oldest-first: the first 15 jtis must be gone, the last 10 retained.
    assert!(log.get_entries_by_jti("jti-0").is_empty());
    assert!(log.get_entries_by_jti("jti-14").is_empty());
    assert!(!log.get_entries_by_jti("jti-15").is_empty());
    assert!(!log.get_entries_by_jti("jti-24").is_empty());
    // Re-anchored chain floor: verification over the retained window must
    // still succeed, not fail closed just because the genesis entry aged out.
    assert!(
        log.verify_chain_integrity(),
        "chain must verify over the retained window after oldest-first eviction"
    );
}

#[test]
fn test_transparency_log_get_entries_by_jti() {
    let log = CapabilityTransparencyLog::new();
    log.append("ISSUED", "iss-q", Some("jti-target"), None, "sub-q", &[], &["write"], 0, None, None);
    log.append("ISSUED", "iss-q", Some("jti-other"), None, "sub-q", &[], &["read"], 0, None, None);
    let entries = log.get_entries_by_jti("jti-target");
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].jti.as_deref(), Some("jti-target"));
}

#[test]
fn test_transparency_log_get_entries_by_jti_empty_for_unknown() {
    let log = CapabilityTransparencyLog::new();
    log.append("ISSUED", "iss", Some("jti-x"), None, "sub", &[], &[], 0, None, None);
    assert!(log.get_entries_by_jti("nonexistent-jti").is_empty());
}

#[test]
fn test_transparency_log_append_returns_chain_hash() {
    let log = CapabilityTransparencyLog::new();
    let hash = log.append("ISSUED", "iss", Some("jti-h"), None, "sub", &[], &[], 0, None, None);
    assert_eq!(hash.len(), 64, "chain_hash must be 64-char hex (SHA-256)");
}

#[test]
fn test_transparency_log_chain_hashes_are_different() {
    let log = CapabilityTransparencyLog::new();
    let h1 = log.append("ISSUED", "iss", Some("j1"), None, "s", &[], &[], 0, None, None);
    let h2 = log.append("ISSUED", "iss", Some("j2"), None, "s", &[], &[], 0, None, None);
    assert_ne!(h1, h2, "Sequential chain hashes must differ");
}

#[test]
fn test_transparency_log_delegation_depth_recorded() {
    let log = CapabilityTransparencyLog::new();
    log.append("DELEGATED", "iss", Some("jti-del"), None, "sub", &[], &["read"], 2, Some("parent-jti"), None);
    let entries = log.get_entries_by_jti("jti-del");
    assert_eq!(entries[0].delegation_depth, 2);
    assert!(entries[0].parent_jti_hash.is_some());
}

#[test]
fn test_transparency_log_export_audit_bundle_valid() {
    let log = CapabilityTransparencyLog::new();
    log.append("ISSUED", "iss-ab", Some("jti-ab"), None, "sub-ab", &[], &["read"], 0, None, None);
    let bundle = log.export_audit_bundle(None);
    assert_eq!(bundle["entry_count"].as_u64().unwrap(), 1);
    assert!(bundle["chain_valid"].as_bool().unwrap());
}

// ─── RiskAwareAuthorizationEvaluator ─────────────────────────────────────────

fn low_risk_ctx() -> AuthorizationContext {
    AuthorizationContext {
        requesting_agent: "agent-safe".to_string(),
        target_agent: "agent-target".to_string(),
        session_trust_level: "full".to_string(),
        requested_action_class: 0,
        delegation_depth: 1,
        issuer_reputation_score: 0.95,
        capability_age_seconds: 30.0,
        behavioral_anomaly_flag: false,
        prior_violation_count: 0,
        is_high_risk_operation: false,
    }
}

fn high_risk_ctx() -> AuthorizationContext {
    AuthorizationContext {
        requesting_agent: "agent-risky".to_string(),
        target_agent: "agent-target".to_string(),
        session_trust_level: "minimal".to_string(),
        requested_action_class: 2,
        delegation_depth: 8,
        issuer_reputation_score: 0.1,
        capability_age_seconds: 300.0,
        behavioral_anomaly_flag: true,
        prior_violation_count: 5,
        is_high_risk_operation: true,
    }
}

#[test]
fn test_risk_evaluator_default_new() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let result = eval.evaluate(&low_risk_ctx());
    assert_eq!(result.decision, "APPROVE");
    assert!(result.risk_score < 0.30);
}

#[test]
fn test_risk_evaluator_low_risk_approves() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let result = eval.evaluate(&low_risk_ctx());
    assert_eq!(result.decision, "APPROVE");
}

#[test]
fn test_risk_evaluator_high_risk_rejects() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let result = eval.evaluate(&high_risk_ctx());
    assert_ne!(result.decision, "APPROVE", "High-risk context must not be approved");
}

#[test]
fn test_risk_evaluator_behavioral_anomaly_increases_score() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let mut ctx = low_risk_ctx();
    ctx.behavioral_anomaly_flag = true;
    let r1 = eval.evaluate(&low_risk_ctx());
    let r2 = eval.evaluate(&ctx);
    assert!(r2.risk_score > r1.risk_score);
}

#[test]
fn test_risk_evaluator_prior_violations_increase_score() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let mut ctx = low_risk_ctx();
    ctx.prior_violation_count = 5;
    let r_clean = eval.evaluate(&low_risk_ctx());
    let r_violations = eval.evaluate(&ctx);
    assert!(r_violations.risk_score > r_clean.risk_score);
}

#[test]
fn test_risk_evaluator_deep_delegation_increases_score() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let mut ctx = low_risk_ctx();
    ctx.delegation_depth = 7;
    let r_shallow = eval.evaluate(&low_risk_ctx());
    let r_deep = eval.evaluate(&ctx);
    assert!(r_deep.risk_score > r_shallow.risk_score);
}

#[test]
fn test_risk_evaluator_risk_score_0_to_1() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let r = eval.evaluate(&high_risk_ctx());
    assert!(r.risk_score >= 0.0 && r.risk_score <= 1.0);
}

#[test]
fn test_risk_evaluator_factors_not_empty_for_high_risk() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let r = eval.evaluate(&high_risk_ctx());
    assert!(!r.factors.is_empty(), "High risk context must produce at least one factor");
}

#[test]
fn test_risk_evaluator_with_policy_thresholds() {
    let eval = RiskAwareAuthorizationEvaluator::with_policy(0.10, 0.20);
    let result = eval.evaluate(&low_risk_ctx());
    // With very tight thresholds, even low risk may not approve
    assert!(!result.decision.is_empty());
}

#[test]
fn test_risk_evaluator_irreversible_action_class_increases_score() {
    let eval = RiskAwareAuthorizationEvaluator::new();
    let mut ctx = low_risk_ctx();
    ctx.requested_action_class = 2;
    let r_safe = eval.evaluate(&low_risk_ctx());
    let r_irrev = eval.evaluate(&ctx);
    assert!(r_irrev.risk_score > r_safe.risk_score);
}

// ─── PostCompromiseRecovery ───────────────────────────────────────────────────

#[test]
fn test_post_compromise_get_affected_tokens_empty_log() {
    let log = CapabilityTransparencyLog::new();
    let affected = PostCompromiseRecovery::get_affected_tokens("kid-x", &log);
    assert!(affected.is_empty());
}

#[test]
fn test_post_compromise_get_affected_tokens_finds_matching() {
    let log = CapabilityTransparencyLog::new();
    log.append("ISSUED", "iss", Some("jti-match"), Some("kid-compromised"), "sub", &[], &["read"], 0, None, None);
    log.append("ISSUED", "iss", Some("jti-other"), Some("kid-safe"), "sub", &[], &["read"], 0, None, None);
    let affected = PostCompromiseRecovery::get_affected_tokens("kid-compromised", &log);
    assert_eq!(affected.len(), 1);
    assert_eq!(affected[0], "jti-match");
}

#[test]
fn test_post_compromise_validate_recovery_complete_true() {
    let report = CompromiseRecoveryReport {
        compromised_kid: "old-kid".to_string(),
        replacement_kid: "new-kid".to_string(),
        affected_token_count: 0,
        revoked_jti_list: vec![],
        recovery_timestamp: 0.0,
        recovery_complete: true,
    };
    assert!(PostCompromiseRecovery::validate_recovery_complete(&report));
}

#[test]
fn test_post_compromise_validate_recovery_same_kid_fails() {
    let report = CompromiseRecoveryReport {
        compromised_kid: "same-kid".to_string(),
        replacement_kid: "same-kid".to_string(),
        affected_token_count: 0,
        revoked_jti_list: vec![],
        recovery_timestamp: 0.0,
        recovery_complete: true,
    };
    assert!(!PostCompromiseRecovery::validate_recovery_complete(&report),
        "Recovery with same kid must not be valid");
}

#[test]
fn test_post_compromise_validate_recovery_incomplete_false() {
    let report = CompromiseRecoveryReport {
        compromised_kid: "old-k".to_string(),
        replacement_kid: "new-k".to_string(),
        affected_token_count: 0,
        revoked_jti_list: vec![],
        recovery_timestamp: 0.0,
        recovery_complete: false,
    };
    assert!(!PostCompromiseRecovery::validate_recovery_complete(&report));
}

#[test]
fn test_post_compromise_declare_key_compromise_logs_events() {
    let (cia, cva) = make_ca_pair("iss-pcr");
    let log = CapabilityTransparencyLog::new();

    // Log some tokens for the compromised key
    log.append("ISSUED", "iss-pcr", Some("jti-tok1"), Some(cia.kid()), "sub", &[], &["read"], 0, None, None);
    log.append("ISSUED", "iss-pcr", Some("jti-tok2"), Some(cia.kid()), "sub", &[], &["read"], 0, None, None);

    let report = PostCompromiseRecovery::declare_key_compromise(
        cia.kid(), "new-kid-replacement", "iss-pcr", &cva, &log,
    );

    assert!(report.recovery_complete);
    assert_eq!(report.compromised_kid, cia.kid());
    assert_eq!(report.replacement_kid, "new-kid-replacement");
    assert_eq!(report.affected_token_count, 2);
    assert_eq!(report.revoked_jti_list.len(), 2);
    assert!(PostCompromiseRecovery::validate_recovery_complete(&report));
    // log must have: 2 ISSUED + 1 KEY_COMPROMISED + 1 KEY_ROTATED = 4
    assert_eq!(log.count(), 4);
}

#[test]
fn test_post_compromise_revokes_key_in_cva() {
    let (cia, cva) = make_ca_pair("iss-rev");
    let log = CapabilityTransparencyLog::new();
    let tok = simple_token(&cia, "sub", "jti-rev");
    assert!(cva.verify(&tok).is_ok());

    PostCompromiseRecovery::declare_key_compromise(cia.kid(), "new-kid", "iss-rev", &cva, &log);
    assert!(cva.verify(&tok).is_err(), "Token must be invalid after key compromise declared");
}

// ─── FilesystemBackend persistence (Phase 5, item 2) ───────────────────────────

#[test]
fn test_filesystem_backend_round_trip_write_reopen_verify() {
    let path = scratch_path("roundtrip");
    let _ = std::fs::remove_file(&path);

    {
        let log = CapabilityTransparencyLog::with_backend(Box::new(
            FilesystemBackend::open(&path).unwrap(),
        ));
        log.append("ISSUED", "iss-fs", Some("jti-1"), Some("kid-1"), "sub", &[], &["read"], 0, None, None);
        log.append("DELEGATED", "iss-fs", Some("jti-2"), Some("kid-1"), "sub", &[], &["write"], 1, Some("jti-1"), None);
        log.append("REVOKED", "iss-fs", Some("jti-2"), Some("kid-1"), "sub", &[], &[], 1, None, None);
        assert!(log.verify_chain_integrity());
        assert_eq!(log.count(), 3);
    } // log (and its FilesystemBackend's file handle) dropped here

    // Reopen against the same path — must replay all 3 entries and verify the chain.
    let reopened_backend = FilesystemBackend::open(&path).unwrap();
    assert_eq!(reopened_backend.count(), 3);
    let log2 = CapabilityTransparencyLog::with_backend(Box::new(reopened_backend));
    assert_eq!(log2.count(), 3);
    assert!(log2.verify_chain_integrity());
    assert_eq!(log2.get_entries_by_jti("jti-1").len(), 1);
    assert_eq!(log2.get_entries_by_jti("jti-2").len(), 2);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_filesystem_backend_truncated_file_rejected() {
    let path = scratch_path("truncated");
    let _ = std::fs::remove_file(&path);

    {
        let log = CapabilityTransparencyLog::with_backend(Box::new(
            FilesystemBackend::open(&path).unwrap(),
        ));
        log.append("ISSUED", "iss-trunc", Some("jti-a"), Some("kid-a"), "sub", &[], &["read"], 0, None, None);
        log.append("ISSUED", "iss-trunc", Some("jti-b"), Some("kid-a"), "sub", &[], &["read"], 0, None, None);
    }

    // Corrupt the file: flip a byte inside the JSON so it still parses as a
    // line but the hash-chain no longer recomputes correctly.
    let contents = std::fs::read_to_string(&path).unwrap();
    let corrupted = contents.replacen("jti-a", "jti-X", 1);
    std::fs::write(&path, corrupted).unwrap();

    let result = FilesystemBackend::open(&path);
    assert!(result.is_err(), "Tampered transparency log file must fail to open, not silently reset to empty");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_filesystem_backend_truncated_last_line_rejected() {
    let path = scratch_path("truncated_line");
    let _ = std::fs::remove_file(&path);

    {
        let log = CapabilityTransparencyLog::with_backend(Box::new(
            FilesystemBackend::open(&path).unwrap(),
        ));
        log.append("ISSUED", "iss-tl", Some("jti-c"), Some("kid-c"), "sub", &[], &["read"], 0, None, None);
        log.append("ISSUED", "iss-tl", Some("jti-d"), Some("kid-c"), "sub", &[], &["read"], 0, None, None);
    }

    // Truncate mid-way through the last line so it's no longer valid JSON.
    let contents = std::fs::read_to_string(&path).unwrap();
    let cut = contents.len() - 5;
    std::fs::write(&path, &contents[..cut]).unwrap();

    let result = FilesystemBackend::open(&path);
    assert!(result.is_err(), "A truncated final line must fail to open, not silently drop the partial entry");

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_filesystem_backend_fresh_file_starts_empty_and_verifies() {
    let path = scratch_path("fresh");
    let _ = std::fs::remove_file(&path);

    let backend = FilesystemBackend::open(&path).unwrap();
    assert_eq!(backend.count(), 0);
    assert_eq!(backend.path(), path);

    let log = CapabilityTransparencyLog::with_backend(Box::new(backend));
    assert!(log.verify_chain_integrity());
    assert_eq!(log.count(), 0);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_filesystem_backend_persists_across_multiple_reopens() {
    let path = scratch_path("multi_reopen");
    let _ = std::fs::remove_file(&path);

    for i in 0..5 {
        let backend = FilesystemBackend::open(&path).unwrap();
        let log = CapabilityTransparencyLog::with_backend(Box::new(backend));
        assert_eq!(log.count(), i);
        log.append("ISSUED", "iss-multi", Some(&format!("jti-{i}")), Some("kid-multi"), "sub", &[], &["read"], 0, None, None);
        assert!(log.verify_chain_integrity());
    }

    let final_backend = FilesystemBackend::open(&path).unwrap();
    assert_eq!(final_backend.count(), 5);

    let _ = std::fs::remove_file(&path);
}

#[test]
fn test_filesystem_backend_rotation_produces_bak_file() {
    let path = scratch_path("rotation");
    let _ = std::fs::remove_file(&path);

    // A tiny threshold (256 bytes) forces rotation after just a couple of entries.
    let backend = FilesystemBackend::open_with_max_file_size(&path, 256).unwrap();
    let log = CapabilityTransparencyLog::with_backend(Box::new(backend));
    for i in 0..20 {
        log.append("ISSUED", "iss-rot", Some(&format!("jti-rot-{i}")), Some("kid-rot"), "sub", &[], &["read"], 0, None, None);
    }
    assert_eq!(log.count(), 20, "in-memory mirror must retain all entries regardless of on-disk rotation");
    assert!(log.verify_chain_integrity());

    // At least one rotated `.bak` file must have been produced given the tiny threshold
    // (same rotation contract as `security::WalWriter` — rotated-out entries live in the
    // `.bak` sibling, not the active file; only the active file is replayed on reopen).
    let dir = std::path::Path::new(&path).parent().unwrap();
    let file_name = std::path::Path::new(&path).file_name().unwrap().to_string_lossy().into_owned();
    let bak_files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            name.starts_with(&file_name) && name.ends_with(".bak")
        })
        .collect();
    assert!(!bak_files.is_empty(), "expected at least one rotated .bak file given a 256-byte threshold and 20 entries");

    // Clean up the primary file, its .floor sidecar, and any .bak siblings it produced.
    for e in bak_files {
        let _ = std::fs::remove_file(e.path());
    }
    let _ = std::fs::remove_file(format!("{path}.floor"));
    let _ = std::fs::remove_file(&path);
}
