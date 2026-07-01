//! test_acsvaf_rs.rs — ACSVAF capability token tests
//!
//! Ports Python: tests/test_acsvaf.py, tests/test_acsvaf_tokens.py
//! Ed25519 key gen, issuance, verification, expiry, revocation, delegation.

use serde_json::{Map, Value};
use saacp::{
    CapabilitySigningKey, CapabilityIssuanceAuthority, CapabilityVerificationAuthority,
    ACSVAF_MAX_DELEGATION_DEPTH,
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

fn make_pair(issuer_id: &str) -> (CapabilityIssuanceAuthority, CapabilityVerificationAuthority) {
    let sk = CapabilitySigningKey::generate(issuer_id, 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;
    let cia = CapabilityIssuanceAuthority::new(sk);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);
    (cia, cva)
}

fn make_claims(cia: &CapabilityIssuanceAuthority, sub: &str, actions: &[&str], exp: u64) -> Map<String, Value> {
    let mut claims = Map::new();
    claims.insert("kid".into(), Value::String(cia.kid().to_string()));
    claims.insert("iss".into(), Value::String(cia.issuer_id().to_string()));
    claims.insert("sub".into(), Value::String(sub.to_string()));
    claims.insert("jti".into(), Value::String(uuid::Uuid::new_v4().to_string()));
    claims.insert("nbf".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(exp)));
    claims.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(0u64)));
    claims.insert("actions".into(), Value::Array(
        actions.iter().map(|a| Value::String(a.to_string())).collect(),
    ));
    claims.insert("audience".into(), Value::Array(vec![Value::String("agent-*".to_string())]));
    claims
}

// ─── Key Generation ────────────────────────────────────────────────────────────

#[test]
fn test_generate_key_has_kid() {
    let sk = CapabilitySigningKey::generate("issuer-a", 3600);
    assert!(!sk.kid.is_empty());
    assert!(sk.kid.starts_with("ed25519-v1-"));
}

#[test]
fn test_generate_key_issuer_id_stored() {
    let sk = CapabilitySigningKey::generate("issuer-b", 7200);
    assert_eq!(sk.issuer_id, "issuer-b");
}

#[test]
fn test_two_keys_different_kids() {
    let sk1 = CapabilitySigningKey::generate("iss", 3600);
    let sk2 = CapabilitySigningKey::generate("iss", 3600);
    assert_ne!(sk1.kid, sk2.kid);
}

#[test]
fn test_key_public_bytes_len() {
    let sk = CapabilitySigningKey::generate("iss", 3600);
    assert_eq!(sk.public_key_bytes().len(), 32);
}

#[test]
fn test_delegation_depth_constant() {
    // Spec §5.7: MAX_DELEGATION_DEPTH = 3
    assert_eq!(ACSVAF_MAX_DELEGATION_DEPTH, 3);
}

// ─── Issuance ─────────────────────────────────────────────────────────────────

#[test]
fn test_issue_returns_token() {
    let (cia, _) = make_pair("iss-1");
    let claims = make_claims(&cia, "agent-a", &["read"], 9_999_999_999);
    let tok = cia.issue(claims);
    assert!(tok.is_ok());
}

#[test]
fn test_issued_token_has_signature() {
    let (cia, _) = make_pair("iss-2");
    let claims = make_claims(&cia, "agent-b", &["write"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    assert_ne!(tok.signature, [0u8; 64]);
}

#[test]
fn test_issued_token_claims_preserved() {
    let (cia, _) = make_pair("iss-3");
    let claims = make_claims(&cia, "agent-c", &["read", "write"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    assert_eq!(tok.claims["sub"].as_str().unwrap(), "agent-c");
}

#[test]
fn test_to_wire_not_empty() {
    let (cia, _) = make_pair("iss-4");
    let claims = make_claims(&cia, "agent-d", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let wire = tok.to_wire();
    assert!(!wire.is_empty());
}

// ─── Verification ─────────────────────────────────────────────────────────────

#[test]
fn test_verify_roundtrip_ok() {
    let (cia, cva) = make_pair("iss-5");
    let claims = make_claims(&cia, "agent-e", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let res = cva.verify(&tok);
    assert!(res.is_ok(), "verify must succeed: {:?}", res);
}

#[test]
fn test_verify_result_sub() {
    let (cia, cva) = make_pair("iss-6");
    let claims = make_claims(&cia, "agent-f", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let v = cva.verify(&tok).unwrap();
    assert_eq!(v.sub, "agent-f");
}

#[test]
fn test_verify_result_actions() {
    let (cia, cva) = make_pair("iss-7");
    let claims = make_claims(&cia, "agent-g", &["read", "write", "delete"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let v = cva.verify(&tok).unwrap();
    assert!(v.actions.contains(&"read".to_string()));
    assert!(v.actions.contains(&"write".to_string()));
    assert!(v.actions.contains(&"delete".to_string()));
}

#[test]
fn test_verify_result_issuer_id() {
    let (cia, cva) = make_pair("iss-8");
    let claims = make_claims(&cia, "agent-h", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let v = cva.verify(&tok).unwrap();
    assert_eq!(v.issuer_id, "iss-8");
}

// ─── Expiry ───────────────────────────────────────────────────────────────────

#[test]
fn test_expired_token_rejected() {
    let (cia, cva) = make_pair("iss-9");
    let claims = make_claims(&cia, "agent-i", &["read"], 1); // exp = epoch 1 = past
    let tok = cia.issue(claims).unwrap();
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Expired token must be rejected");
}

#[test]
fn test_valid_exp_future_accepted() {
    let (cia, cva) = make_pair("iss-10");
    let claims = make_claims(&cia, "agent-j", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    assert!(cva.verify(&tok).is_ok());
}

#[test]
fn test_nbf_in_future_rejected() {
    let (cia, cva) = make_pair("iss-11");
    let mut claims = make_claims(&cia, "agent-k", &["read"], 9_999_999_999);
    // nbf far in the future
    claims.insert("nbf".into(), Value::Number(serde_json::Number::from(9_999_999_000u64)));
    let tok = cia.issue(claims).unwrap();
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Token with future nbf must be rejected");
}

// ─── Revocation ───────────────────────────────────────────────────────────────

#[test]
fn test_revoked_jti_rejected() {
    let (cia, cva) = make_pair("iss-12");
    let jti = "jti-revoke-test".to_string();
    let mut claims = make_claims(&cia, "agent-l", &["read"], 9_999_999_999);
    claims.insert("jti".into(), Value::String(jti.clone()));
    let tok = cia.issue(claims).unwrap();
    assert!(cva.verify(&tok).is_ok(), "token valid before revocation");
    cva.revoke_token(&jti);
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Revoked token must be rejected");
}

#[test]
fn test_revoke_trusted_key_blocks_verify() {
    let (cia, cva) = make_pair("iss-13");
    let claims = make_claims(&cia, "agent-m", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    assert!(cva.verify(&tok).is_ok());
    cva.revoke_trusted_key(cia.kid());
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Token from revoked key must be rejected");
}

#[test]
fn test_clear_replay_registry_returns_count() {
    let (_cia, cva) = make_pair("iss-14");
    cva.revoke_token("jti-a");
    cva.revoke_token("jti-b");
    cva.revoke_token("jti-c");
    let n = cva.clear_replay_registry();
    assert_eq!(n, 3);
    assert_eq!(cva.clear_replay_registry(), 0);
}

#[test]
fn test_different_token_same_key_works_after_one_revoked() {
    let (cia, cva) = make_pair("iss-15");

    let jti1 = "jti-one".to_string();
    let mut c1 = make_claims(&cia, "agent-n", &["read"], 9_999_999_999);
    c1.insert("jti".into(), Value::String(jti1.clone()));
    let tok1 = cia.issue(c1).unwrap();

    let jti2 = "jti-two".to_string();
    let mut c2 = make_claims(&cia, "agent-o", &["read"], 9_999_999_999);
    c2.insert("jti".into(), Value::String(jti2.clone()));
    let tok2 = cia.issue(c2).unwrap();

    cva.revoke_token(&jti1);
    assert!(cva.verify(&tok1).is_err(), "tok1 revoked");
    assert!(cva.verify(&tok2).is_ok(), "tok2 still valid");
}

// ─── Key Manifest / Registry ───────────────────────────────────────────────────

#[test]
fn test_list_kids_contains_registered() {
    let cva = CapabilityVerificationAuthority::new();
    let sk = CapabilitySigningKey::generate("iss-kl", 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;
    cva.register_key(&kid, vk);
    assert!(cva.list_kids().contains(&kid));
}

#[test]
fn test_list_kids_empty_initially() {
    let cva = CapabilityVerificationAuthority::new();
    assert!(cva.list_kids().is_empty());
}

#[test]
fn test_register_multiple_keys() {
    let cva = CapabilityVerificationAuthority::new();
    for i in 0..5 {
        let sk = CapabilitySigningKey::generate(&format!("iss-{}", i), 3600);
        let kid = sk.kid.clone();
        let vk = sk.verifying_key;
        cva.register_key(&kid, vk);
    }
    assert_eq!(cva.list_kids().len(), 5);
}

// ─── Unknown Key ──────────────────────────────────────────────────────────────

#[test]
fn test_unknown_key_id_rejected() {
    let cva = CapabilityVerificationAuthority::new();
    // No key registered — issue with one cia but verify with empty cva
    let sk = CapabilitySigningKey::generate("iss-unk", 3600);
    let cia = CapabilityIssuanceAuthority::new(sk);
    let claims = make_claims(&cia, "agent-x", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Unknown key must be rejected");
}

// ─── Multi-issuer ─────────────────────────────────────────────────────────────

#[test]
fn test_wrong_issuers_key_rejected() {
    let (cia1, _cva1) = make_pair("iss-a");
    let (_cia2, cva2) = make_pair("iss-b");

    // Issue with cia1 but verify with cva2 (which only has cia2's key)
    let claims = make_claims(&cia1, "agent-p", &["read"], 9_999_999_999);
    let tok = cia1.issue(claims).unwrap();
    let res = cva2.verify(&tok);
    assert!(res.is_err(), "Token from different issuer must be rejected");
}

#[test]
fn test_two_issuers_both_registered_works() {
    let sk1 = CapabilitySigningKey::generate("iss-X", 3600);
    let kid1 = sk1.kid.clone();
    let vk1 = sk1.verifying_key;

    let sk2 = CapabilitySigningKey::generate("iss-Y", 3600);
    let kid2 = sk2.kid.clone();
    let vk2 = sk2.verifying_key;

    let cia1 = CapabilityIssuanceAuthority::new(sk1);
    let cia2 = CapabilityIssuanceAuthority::new(sk2);

    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid1, vk1);
    cva.register_key(&kid2, vk2);

    let c1 = make_claims(&cia1, "a1", &["read"], 9_999_999_999);
    let c2 = make_claims(&cia2, "a2", &["write"], 9_999_999_999);

    assert!(cva.verify(&cia1.issue(c1).unwrap()).is_ok());
    assert!(cva.verify(&cia2.issue(c2).unwrap()).is_ok());
}

// ─── Delegation depth ────────────────────────────────────────────────────────

#[test]
fn test_delegation_depth_at_max_allowed() {
    // delegation_depth = 3 is the max allowed per spec §5.7
    let (cia, cva) = make_pair("iss-del-1");
    let mut claims = make_claims(&cia, "agent-del", &["read"], 9_999_999_999);
    claims.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(ACSVAF_MAX_DELEGATION_DEPTH)));
    let tok = cia.issue(claims).unwrap();
    // depth = 3 (max) must be accepted
    assert!(cva.verify(&tok).is_ok());
}

#[test]
fn test_delegation_depth_above_max_rejected() {
    // delegation_depth = 4 > MAX (3) must be rejected per spec §5.7
    let (cia, cva) = make_pair("iss-del-2");
    let mut claims = make_claims(&cia, "agent-del2", &["read"], 9_999_999_999);
    claims.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(ACSVAF_MAX_DELEGATION_DEPTH + 1)));
    let tok = cia.issue(claims).unwrap();
    // depth = 4 exceeds max (3), verify must reject
    assert!(cva.verify(&tok).is_err());
}

#[test]
fn test_get_verification_key_returns_key() {
    let sk = CapabilitySigningKey::generate("iss-vk", 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);
    let found = cva.get_verification_key(&kid);
    assert!(found.is_some());
}

#[test]
fn test_get_verification_key_missing_returns_none() {
    let cva = CapabilityVerificationAuthority::new();
    assert!(cva.get_verification_key("nonexistent-kid").is_none());
}

// ─── Wire format ─────────────────────────────────────────────────────────────

#[test]
fn test_to_wire_is_base64() {
    let (cia, _) = make_pair("iss-wire");
    let claims = make_claims(&cia, "agent-w", &["read"], 9_999_999_999);
    let tok = cia.issue(claims).unwrap();
    let wire = tok.to_wire();
    // Base64 alphabet — should decode without error
    let s = String::from_utf8(wire).unwrap();
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD, &s
    );
    assert!(decoded.is_ok());
}

#[test]
fn test_issuer_id_accessor() {
    let sk = CapabilitySigningKey::generate("my-issuer", 3600);
    let cia = CapabilityIssuanceAuthority::new(sk);
    assert_eq!(cia.issuer_id(), "my-issuer");
}

#[test]
fn test_kid_accessor() {
    let sk = CapabilitySigningKey::generate("any-issuer", 3600);
    let kid = sk.kid.clone();
    let cia = CapabilityIssuanceAuthority::new(sk);
    assert_eq!(cia.kid(), kid);
}
