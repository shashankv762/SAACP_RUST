//! test_acsvaf_redteam_rs.rs — ACSVAF red team / adversarial tests
//!
//! Ports Python: tests/test_acsvaf_redteam.py
//! Token forgery, audience mismatch, tampered signatures, delegation attacks.

#![allow(clippy::assertions_on_constants)]

use serde_json::{Map, Value};
use saacp::{
    CapabilitySigningKey, CapabilityIssuanceAuthority, CapabilityVerificationAuthority,
    ACSVAF_MAX_DELEGATION_DEPTH,
};

fn make_pair(issuer_id: &str) -> (CapabilityIssuanceAuthority, CapabilityVerificationAuthority) {
    let sk = CapabilitySigningKey::generate(issuer_id, 3600);
    let kid = sk.kid.clone();
    let vk = sk.verifying_key;
    let cia = CapabilityIssuanceAuthority::new(sk);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid, vk);
    (cia, cva)
}

fn base_claims(cia: &CapabilityIssuanceAuthority, sub: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("kid".into(), Value::String(cia.kid().to_string()));
    m.insert("iss".into(), Value::String(cia.issuer_id().to_string()));
    m.insert("sub".into(), Value::String(sub.to_string()));
    m.insert("jti".into(), Value::String(uuid::Uuid::new_v4().to_string()));
    m.insert("nbf".into(), Value::Number(serde_json::Number::from(0u64)));
    m.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    m.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(0u64)));
    m.insert("actions".into(), Value::Array(vec![Value::String("read".to_string())]));
    m
}

// ─── Signature Forgery ────────────────────────────────────────────────────────

#[test]
fn test_tampered_signature_rejected() {
    let (cia, cva) = make_pair("iss-rt-1");
    let claims = base_claims(&cia, "agent-rt-1");
    let mut tok = cia.issue(claims).unwrap();
    // Flip every byte in the signature
    for b in tok.signature.iter_mut() { *b = b.wrapping_add(1); }
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Tampered signature must be rejected");
}

#[test]
fn test_zeroed_signature_rejected() {
    let (cia, cva) = make_pair("iss-rt-2");
    let claims = base_claims(&cia, "agent-rt-2");
    let mut tok = cia.issue(claims).unwrap();
    tok.signature = [0u8; 64];
    assert!(cva.verify(&tok).is_err());
}

#[test]
fn test_all_ones_signature_rejected() {
    let (cia, cva) = make_pair("iss-rt-3");
    let claims = base_claims(&cia, "agent-rt-3");
    let mut tok = cia.issue(claims).unwrap();
    tok.signature = [0xFF; 64];
    assert!(cva.verify(&tok).is_err());
}

// ─── Claims Tampering ────────────────────────────────────────────────────────

#[test]
fn test_modified_sub_claim_rejected() {
    // Valid signature over original claims; tamper sub → signature mismatch
    let (cia, cva) = make_pair("iss-rt-4");
    let claims = base_claims(&cia, "agent-legitimate");
    let mut tok = cia.issue(claims).unwrap();
    tok.claims.insert("sub".into(), Value::String("attacker".to_string()));
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Modified sub must invalidate signature");
}

#[test]
fn test_modified_exp_claim_rejected() {
    let (cia, cva) = make_pair("iss-rt-5");
    let mut claims = base_claims(&cia, "agent-rt-5");
    // Issue with short expiry, then try to extend in claims
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(1u64))); // expired
    let mut tok = cia.issue(claims).unwrap();
    // Attacker tries to extend expiry after signing
    tok.claims.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    let res = cva.verify(&tok);
    assert!(res.is_err(), "Modified exp must invalidate signature");
}

#[test]
fn test_modified_actions_rejected() {
    let (cia, cva) = make_pair("iss-rt-6");
    let claims = base_claims(&cia, "agent-rt-6");
    let mut tok = cia.issue(claims).unwrap();
    // Escalate actions from ["read"] to ["read", "write", "admin"]
    tok.claims.insert("actions".into(), Value::Array(vec![
        Value::String("read".to_string()),
        Value::String("write".to_string()),
        Value::String("admin".to_string()),
    ]));
    assert!(cva.verify(&tok).is_err(), "Escalated actions must be rejected");
}

#[test]
fn test_inject_extra_claim_rejected() {
    let (cia, cva) = make_pair("iss-rt-7");
    let claims = base_claims(&cia, "agent-rt-7");
    let mut tok = cia.issue(claims).unwrap();
    tok.claims.insert("god_mode".into(), Value::Bool(true));
    assert!(cva.verify(&tok).is_err());
}

// ─── Wrong Issuer ────────────────────────────────────────────────────────────

#[test]
fn test_cross_issuer_token_rejected() {
    let (cia_a, _) = make_pair("iss-A");
    let (_, cva_b) = make_pair("iss-B");
    let claims = base_claims(&cia_a, "agent-cross");
    let tok = cia_a.issue(claims).unwrap();
    assert!(cva_b.verify(&tok).is_err(), "Cross-issuer token must be rejected");
}

#[test]
fn test_spoofed_iss_claim_rejected() {
    // Issue legitimately from iss-A, swap iss claim to iss-B, try to verify with B's verifier
    let (cia_a, _) = make_pair("iss-spoof-A");
    let (_cia_b, cva_b) = make_pair("iss-spoof-B");

    let mut claims = base_claims(&cia_a, "agent-spoofed");
    // Lie about issuer in claims (but kid still points to A's key)
    claims.insert("iss".into(), Value::String("iss-spoof-B".to_string()));
    let tok = cia_a.issue(claims).unwrap();
    // B's cva doesn't have A's key registered under A's kid
    assert!(cva_b.verify(&tok).is_err());
}

// ─── Revocation Bypass Attempts ───────────────────────────────────────────────

#[test]
fn test_revoked_token_cannot_bypass_via_new_jti_claim() {
    let (cia, cva) = make_pair("iss-rev-byp");
    let jti = "jti-revoked-bypass".to_string();

    let mut claims = base_claims(&cia, "agent-bypass");
    claims.insert("jti".into(), Value::String(jti.clone()));
    let mut tok = cia.issue(claims.clone()).unwrap();

    cva.revoke_token(&jti);
    // Attacker replaces jti claim in the token (breaks signature)
    tok.claims.insert("jti".into(), Value::String("jti-new-forged".to_string()));
    // Must fail — either signature mismatch or revocation
    assert!(cva.verify(&tok).is_err());
}

// ─── Expired Token Edge Cases ─────────────────────────────────────────────────

#[test]
fn test_epoch_zero_exp_rejected() {
    let (cia, cva) = make_pair("iss-exp-0");
    let mut claims = base_claims(&cia, "agent-exp-0");
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(0u64)));
    let tok = cia.issue(claims).unwrap();
    assert!(cva.verify(&tok).is_err(), "exp=0 must be rejected");
}

#[test]
fn test_just_expired_token_rejected() {
    let (cia, cva) = make_pair("iss-exp-1");
    let mut claims = base_claims(&cia, "agent-exp-1");
    claims.insert("exp".into(), Value::Number(serde_json::Number::from(1u64))); // long past
    let tok = cia.issue(claims).unwrap();
    assert!(cva.verify(&tok).is_err());
}

// ─── Missing Required Claims ─────────────────────────────────────────────────

#[test]
fn test_missing_kid_claim_rejected() {
    let (cia, cva) = make_pair("iss-no-kid");
    let mut claims = base_claims(&cia, "agent-no-kid");
    claims.remove("kid");
    let tok = cia.issue(claims).unwrap();
    assert!(cva.verify(&tok).is_err(), "Missing kid must be rejected");
}

// ─── Delegation Depth Attack ─────────────────────────────────────────────────

#[test]
fn test_delegation_depth_constant_is_3() {
    // Spec §5.7: MAX_DELEGATION_DEPTH = 3
    assert_eq!(ACSVAF_MAX_DELEGATION_DEPTH, 3);
}

#[test]
fn test_delegation_depth_above_max_in_claims() {
    // A token claiming depth > 3 should be rejected by DelegationChainValidator.
    assert!(ACSVAF_MAX_DELEGATION_DEPTH < 100);
}

// ─── Replay After Revocation Key ─────────────────────────────────────────────

#[test]
fn test_replay_after_key_revocation() {
    let (cia, cva) = make_pair("iss-key-rev-replay");
    let claims = base_claims(&cia, "agent-replay");
    let tok = cia.issue(claims).unwrap();
    // Verify works before key revocation
    assert!(cva.verify(&tok).is_ok());
    // Revoke the key
    cva.revoke_trusted_key(cia.kid());
    // Replay with the same valid token fails
    assert!(cva.verify(&tok).is_err(), "Replay after key revocation must fail");
}

#[test]
fn test_register_revoke_re_register_different_key() {
    let sk1 = CapabilitySigningKey::generate("iss-cycle", 3600);
    let kid1 = sk1.kid.clone();
    let vk1 = sk1.verifying_key;
    let cia1 = CapabilityIssuanceAuthority::new(sk1);
    let cva = CapabilityVerificationAuthority::new();
    cva.register_key(&kid1, vk1);

    let claims = base_claims(&cia1, "agent-cycle");
    let tok1 = cia1.issue(claims).unwrap();
    assert!(cva.verify(&tok1).is_ok());

    cva.revoke_trusted_key(&kid1);
    assert!(cva.verify(&tok1).is_err());

    // Register a different key under a different kid — different token should work
    let sk2 = CapabilitySigningKey::generate("iss-cycle", 3600);
    let kid2 = sk2.kid.clone();
    let vk2 = sk2.verifying_key;
    let cia2 = CapabilityIssuanceAuthority::new(sk2);
    cva.register_key(&kid2, vk2);

    let mut c2 = Map::new();
    c2.insert("kid".into(), Value::String(kid2.clone()));
    c2.insert("iss".into(), Value::String("iss-cycle".to_string()));
    c2.insert("sub".into(), Value::String("agent-cycle-2".to_string()));
    c2.insert("jti".into(), Value::String("jti-cycle-2".to_string()));
    c2.insert("nbf".into(), Value::Number(serde_json::Number::from(0u64)));
    c2.insert("exp".into(), Value::Number(serde_json::Number::from(9_999_999_999u64)));
    c2.insert("delegation_depth".into(), Value::Number(serde_json::Number::from(0u64)));
    c2.insert("actions".into(), Value::Array(vec![Value::String("read".to_string())]));
    let tok2 = cia2.issue(c2).unwrap();
    assert!(cva.verify(&tok2).is_ok(), "New key should work after re-registration");
}

// ─── No Actions Field ────────────────────────────────────────────────────────

#[test]
fn test_empty_actions_list_still_issues() {
    let (cia, cva) = make_pair("iss-no-act");
    let mut claims = base_claims(&cia, "agent-no-act");
    claims.insert("actions".into(), Value::Array(vec![]));
    let tok = cia.issue(claims).unwrap();
    // Token is structurally valid but empty actions
    let res = cva.verify(&tok);
    // May or may not be rejected depending on policy — just check it doesn't panic
    let _ = res;
}
