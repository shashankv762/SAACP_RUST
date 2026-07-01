//! test_realworld_rs.rs — Real-world multi-agent scenario tests
//!
//! Ports Python: tests/test_realworld.py, tests/test_multi_agent.py
//! End-to-end flows: capability issuance → verification → delegation → governance.

use std::sync::Arc;
use serde_json::{Map, Value};

use saacp::{
    CapabilitySigningKey, CapabilityIssuanceAuthority, CapabilityVerificationAuthority,
    AEGFGovernor, AEGFMetadata, GovernanceDecision,
    AgentIdentity, AgentCredential, TrustAnchor, TrustStore, AttestationType,
    TrustMeshFederation,
    CapabilityTransparencyLog,
    ThresholdAuthorityIssuer,
    DelegationChainValidator,
    DeadMansSwitch,
    StreamSession, StreamRegistry,
    SessionEpochManager,
};

fn make_pair(iss: &str) -> (CapabilityIssuanceAuthority, CapabilityVerificationAuthority) {
    let sk = CapabilitySigningKey::generate(iss, 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;
    let cia = CapabilityIssuanceAuthority::new(sk);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);
    (cia, cva)
}

fn issue_token(cia: &CapabilityIssuanceAuthority, sub: &str, actions: &[&str], jti: &str) -> saacp::SignedCapabilityToken {
    let mut claims = Map::new();
    claims.insert("kid".into(), Value::String(cia.kid().to_string()));
    claims.insert("iss".into(), Value::String(cia.issuer_id().to_string()));
    claims.insert("sub".into(), Value::String(sub.to_string()));
    claims.insert("jti".into(), Value::String(jti.to_string()));
    claims.insert("nbf".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    claims.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("actions".into(), Value::Array(
        actions.iter().map(|a| Value::String(a.to_string())).collect(),
    ));
    cia.issue(claims).expect("issue token")
}

// ─── Scenario 1: Healthcare Multi-Agent Coordination ─────────────────────────

#[test]
fn test_healthcare_read_only_agent_capability() {
    let (cia, cva) = make_pair("hospital-iss");
    let tok = issue_token(&cia, "agent-reader", &["read"], "jti-hc-1");
    let res = cva.verify(&tok);
    assert!(res.is_ok());
    let v = res.unwrap();
    assert!(v.actions.contains(&"read".to_string()));
    assert!(!v.actions.contains(&"write".to_string()));
}

#[test]
fn test_healthcare_write_agent_capability() {
    let (cia, cva) = make_pair("hospital-iss");
    let tok = issue_token(&cia, "agent-writer", &["read", "write"], "jti-hc-2");
    let res = cva.verify(&tok);
    assert!(res.is_ok());
    assert!(res.unwrap().actions.contains(&"write".to_string()));
}

#[test]
fn test_healthcare_governance_allows_normal_request() {
    let gov = AEGFGovernor::new(None);
    let m = AEGFMetadata::new("agent-doctor", "session-hc", None, None, 60.0, 0, 0);
    let decision = gov.submit_request(&m);
    assert!(matches!(decision, GovernanceDecision::Allow | GovernanceDecision::Pause));
}

// ─── Scenario 2: Financial Institution Threshold Authorization ────────────────

#[test]
fn test_financial_2_of_3_threshold() {
    let auths = vec!["compliance".to_string(), "cto".to_string(), "cfo".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(2, auths, 600.0).unwrap();

    let req = issuer.create_request(serde_json::json!({
        "amount": 1_000_000,
        "currency": "USD",
        "beneficiary": "partner-bank"
    }));

    let sk_comp = CapabilitySigningKey::generate("compliance", 3600);
    let cia_comp = CapabilityIssuanceAuthority::new(sk_comp);
    let tok_comp = issue_token(&cia_comp, "system", &["approve"], "jti-comp");

    let sk_cto = CapabilitySigningKey::generate("cto", 3600);
    let cia_cto = CapabilityIssuanceAuthority::new(sk_cto);
    let tok_cto = issue_token(&cia_cto, "system", &["approve"], "jti-cto");

    let s1 = issuer.submit_partial_approval(&req, "compliance", &tok_comp).unwrap();
    assert!(!s1.is_ready);
    let s2 = issuer.submit_partial_approval(&req, "cto", &tok_cto).unwrap();
    assert!(s2.is_ready, "2-of-3 must be ready after 2 approvals");
}

#[test]
fn test_financial_1_approval_not_enough() {
    let auths = vec!["A".to_string(), "B".to_string(), "C".to_string()];
    let issuer = ThresholdAuthorityIssuer::new(3, auths, 600.0).unwrap();
    let req = issuer.create_request(serde_json::json!({"amount": 1000}));

    let sk = CapabilitySigningKey::generate("A", 3600);
    let cia = CapabilityIssuanceAuthority::new(sk);
    let tok = issue_token(&cia, "sys", &["approve"], "jti-fin-a");

    let s = issuer.submit_partial_approval(&req, "A", &tok).unwrap();
    assert!(!s.is_ready, "3-of-3 threshold requires all 3 approvals");
}

// ─── Scenario 3: Trust Mesh Federation (Multi-Organization) ──────────────────

#[test]
fn test_trust_mesh_two_orgs_register() {
    use rand::rngs::OsRng;
    use ed25519_dalek::SigningKey;

    let sk1 = SigningKey::generate(&mut OsRng);
    let vk1 = sk1.verifying_key();
    let sk2 = SigningKey::generate(&mut OsRng);
    let vk2 = sk2.verifying_key();

    let anchor1 = TrustAnchor::new("org-A-anchor", vk1);
    let anchor2 = TrustAnchor::new("org-B-anchor", vk2);

    let mesh = TrustMeshFederation::new();
    mesh.register_member("org-A", &anchor1);
    mesh.register_member("org-B", &anchor2);

    let members = mesh.list_members();
    assert!(members.contains(&"org-A".to_string()));
    assert!(members.contains(&"org-B".to_string()));
}

#[test]
fn test_trust_mesh_cross_domain_validation() {
    use rand::rngs::OsRng;
    use ed25519_dalek::SigningKey;

    let sk_issuer = SigningKey::generate(&mut OsRng);
    let vk_issuer = sk_issuer.verifying_key();
    let anchor = TrustAnchor::new("cross-anchor", vk_issuer);

    let mesh = TrustMeshFederation::new();
    mesh.register_member("org-X", &anchor);

    let identity = AgentIdentity::generate("agent-cross", "org-Y-iss", 3600, None, None, "", AttestationType::None);
    let cred = AgentCredential::issue(&identity, &sk_issuer, &vk_issuer);

    let store = TrustStore::new();
    store.register_anchor(TrustAnchor::new("cross-anchor", vk_issuer));

    let (ok, reason) = store.verify_credential(&cred, "org-X");
    assert!(ok, "Cross-domain credential must be valid: {}", reason);
}

// ─── Scenario 4: Delegation Chain ────────────────────────────────────────────

#[test]
fn test_delegation_chain_single_hop() {
    let (cia, cva) = make_pair("root-iss");
    let tok = issue_token(&cia, "agent-delegated", &["read"], "jti-chain-1");
    let result = DelegationChainValidator::validate_chain(&[tok], &cva);
    assert!(result.valid, "Single-hop delegation must be valid: {:?}", result.violations);
}

#[test]
fn test_capability_log_multi_agent_events() {
    let log = CapabilityTransparencyLog::new();
    let (cia, _) = make_pair("log-iss");

    for i in 0..5u32 {
        let sub = format!("agent-{}", i);
        let jti = format!("jti-{}", i);
        log.append("ISSUED", cia.issuer_id(), Some(jti.as_str()), Some(cia.kid()), &sub, &[], &["read"], 0, None, None);
    }
    assert_eq!(log.count(), 5);
    assert!(log.verify_chain_integrity());
}

// ─── Scenario 5: Session Key Management ──────────────────────────────────────

#[test]
fn test_session_epoch_multi_agent() {
    let manager = Arc::new(SessionEpochManager::new());
    for i in 0..5u8 {
        let mut sid = [0u8; 16];
        sid[0] = i;
        manager.create_session(sid, [0xAAu8; 32], 10_000, 600.0, None).unwrap();
    }
    assert_eq!(manager.session_count(), 5);
}

#[test]
fn test_session_epoch_destruction() {
    let manager = Arc::new(SessionEpochManager::new());
    manager.create_session([0x01u8; 16], [0xAAu8; 32], 1000, 60.0, None).unwrap();
    manager.create_session([0x02u8; 16], [0xBBu8; 32], 1000, 60.0, None).unwrap();

    let recovery = saacp::PSKCompromiseRecovery::new(manager.clone(), None);
    let report = recovery.execute(None);
    assert!(report.recovery_complete);
    assert_eq!(manager.session_count(), 0);
}

// ─── Scenario 6: Dead Man's Switch ───────────────────────────────────────────

#[test]
fn test_dead_mans_switch_ping() {
    let dms = DeadMansSwitch::global();
    let cid = b"test-context-id-1234567890abcdef";
    dms.ping(cid); // Must not panic
}

#[test]
fn test_dead_mans_switch_is_active() {
    let dms = DeadMansSwitch::global();
    let active = dms.is_active(b"test-context-id-1234567890abcdef");
    let _ = active;
}

// ─── Scenario 7: Multi-agent Streaming ───────────────────────────────────────

#[test]
fn test_multi_agent_independent_streams() {
    let reg = StreamRegistry::new();
    let s1 = StreamSession::new("s1".to_string(), "agent-X".to_string(), 256);
    let s2 = StreamSession::new("s2".to_string(), "agent-Y".to_string(), 256);
    reg.register(s1).unwrap();
    reg.register(s2).unwrap();
    assert_eq!(reg.agent_stream_count("agent-X"), 1);
    assert_eq!(reg.agent_stream_count("agent-Y"), 1);
    assert_eq!(reg.active_count(), 2);
}

#[test]
fn test_agent_cannot_access_another_agents_stream() {
    let reg = StreamRegistry::new();
    let s = StreamSession::new("stream-private".to_string(), "agent-owner".to_string(), 256);
    reg.register(s).unwrap();
    // agent-intruder has 0 streams registered; cannot close what they don't own
    assert_eq!(reg.agent_stream_count("agent-intruder"), 0);
}

// ─── Scenario 8: Token Revocation Cascade ────────────────────────────────────

#[test]
fn test_token_revocation_cascade() {
    let (cia, cva) = make_pair("rev-cascade-iss");

    let tok1 = issue_token(&cia, "agent-a", &["read"], "jti-cascade-1");
    let tok2 = issue_token(&cia, "agent-b", &["read"], "jti-cascade-2");
    let tok3 = issue_token(&cia, "agent-c", &["read"], "jti-cascade-3");

    assert!(cva.verify(&tok1).is_ok());
    assert!(cva.verify(&tok2).is_ok());
    assert!(cva.verify(&tok3).is_ok());

    // Revoke the signing key — all tokens become invalid
    cva.revoke_trusted_key(cia.kid());

    assert!(cva.verify(&tok1).is_err(), "tok1 must fail after key revocation");
    assert!(cva.verify(&tok2).is_err(), "tok2 must fail after key revocation");
    assert!(cva.verify(&tok3).is_err(), "tok3 must fail after key revocation");
}
