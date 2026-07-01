//! test_factf_rs.rs — FACTF Federated Authorization and Cryptographic Trust Framework tests
//!
//! Ports Python: tests/test_factf.py
//! DelegationChainValidator, ThresholdAuthorityIssuer, CapabilityTransparencyLog,
//! RiskAwareAuthorizationEvaluator, PostCompromiseRecovery.

use serde_json::{Map, Value};
use saacp::{
    CapabilitySigningKey, CapabilityIssuanceAuthority, CapabilityVerificationAuthority,
    DelegationChainValidator,
    ThresholdAuthorityIssuer,
    CapabilityTransparencyLog,
    RiskAwareAuthorizationEvaluator, AuthorizationContext,
    PostCompromiseRecovery, CompromiseRecoveryReport,
};

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
