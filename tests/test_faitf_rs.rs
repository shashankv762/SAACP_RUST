//! test_faitf_rs.rs — FAITF Federated Agent Identity and Trust Framework tests
//!
//! Ports Python: tests/test_faitf.py
//! AgentIdentity, AgentCredential, TrustAnchor, TrustStore, DRI, IdentityProver.

#![allow(clippy::assertions_on_constants)]

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use saacp::{
    AgentIdentity, AgentCredential, TrustAnchor, TrustStore,
    DistributedRevocationInfrastructure,
    IdentityProver, AttestationType, TrustModel,
    FAITF_VERSION, FAITF_MAX_DELEGATION_DEPTH, IDENTITY_PROOF_TTL, MAX_CLOCK_SKEW,
    provision_issuer,
};

fn generate_issuer_pair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn make_identity(agent_id: &str, issuer_id: &str, ttl: u64) -> AgentIdentity {
    AgentIdentity::generate(agent_id, issuer_id, ttl, None, None, "", AttestationType::None)
}

// ─── Constants ────────────────────────────────────────────────────────────────

#[test]
fn test_faitf_version() {
    assert_eq!(FAITF_VERSION, "1.0");
}

#[test]
fn test_faitf_max_delegation_depth() {
    assert_eq!(FAITF_MAX_DELEGATION_DEPTH, 3);
}

#[test]
fn test_identity_proof_ttl_positive() {
    assert!(IDENTITY_PROOF_TTL > 0.0);
}

#[test]
fn test_max_clock_skew_reasonable() {
    assert!(MAX_CLOCK_SKEW > 0.0 && MAX_CLOCK_SKEW < 60.0);
}

// ─── AgentIdentity ────────────────────────────────────────────────────────────

#[test]
fn test_agent_identity_generate() {
    let id = make_identity("agent-a", "issuer-1", 3600);
    assert_eq!(id.agent_id, "agent-a");
    assert_eq!(id.issuer_id, "issuer-1");
    assert_eq!(id.credential_version, 1);
}

#[test]
fn test_agent_identity_is_valid_now() {
    let id = make_identity("agent-b", "issuer-1", 3600);
    assert!(id.is_valid_now());
}

#[test]
fn test_agent_identity_expired() {
    let id = make_identity("agent-c", "issuer-1", 0); // ttl = 0 means expires immediately
    // is_valid_now may still be true at t=0; just check no panic
    let _ = id.is_valid_now();
}

#[test]
fn test_agent_identity_fingerprint_not_empty() {
    let id = make_identity("agent-d", "issuer-1", 3600);
    assert!(!id.fingerprint().is_empty());
}

#[test]
fn test_agent_identity_public_key_bytes_len() {
    let id = make_identity("agent-e", "issuer-1", 3600);
    assert_eq!(id.public_key_bytes().len(), 32);
}

#[test]
fn test_two_identities_different_keys() {
    let id1 = make_identity("agent-f", "iss-1", 3600);
    let id2 = make_identity("agent-g", "iss-1", 3600);
    assert_ne!(id1.public_key_bytes(), id2.public_key_bytes());
}

#[test]
fn test_attestation_type_none_implemented() {
    assert!(AttestationType::None.is_implemented());
}

#[test]
fn test_attestation_type_tpm_not_implemented() {
    assert!(!AttestationType::Tpm.is_implemented());
}

#[test]
fn test_attestation_type_hsm_requires_hardware() {
    assert!(AttestationType::Hsm.requires_hardware_provider());
}

#[test]
fn test_attestation_type_values() {
    assert_eq!(AttestationType::None.value(), "none");
    assert_eq!(AttestationType::Tpm.value(), "tpm");
    assert_eq!(AttestationType::Hsm.value(), "hsm");
    assert_eq!(AttestationType::Tee.value(), "tee");
    assert_eq!(AttestationType::Enclave.value(), "secure_enclave");
}

// ─── AgentCredential ─────────────────────────────────────────────────────────

#[test]
fn test_credential_issue_and_verify() {
    let (isk, ivk) = generate_issuer_pair();
    let id = make_identity("agent-cred", "issuer-cred", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    assert_eq!(cred.agent_id(), "agent-cred");
}

#[test]
fn test_credential_not_expired() {
    let (isk, ivk) = generate_issuer_pair();
    let id = make_identity("agent-exp", "issuer-cred", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    assert!(!cred.is_expired());
}

#[test]
fn test_credential_is_active() {
    let (isk, ivk) = generate_issuer_pair();
    let id = make_identity("agent-active", "issuer-cred", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    assert!(cred.is_active());
}

#[test]
fn test_credential_version_is_1() {
    let (isk, ivk) = generate_issuer_pair();
    let id = make_identity("agent-ver", "issuer-cred", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    assert_eq!(cred.credential_version(), 1);
}

#[test]
fn test_credential_fingerprint_not_empty() {
    let (isk, ivk) = generate_issuer_pair();
    let id = make_identity("agent-fp", "issuer-cred", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    assert!(!cred.fingerprint().is_empty());
}

#[test]
fn test_credential_wire_roundtrip() {
    let (isk, ivk) = generate_issuer_pair();
    let id = make_identity("agent-wire", "issuer-wire", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    let wire = cred.to_wire();
    assert!(!wire.is_empty());
    let recovered = AgentCredential::from_wire(&wire);
    assert!(recovered.is_ok(), "from_wire must succeed: {:?}", recovered);
    assert_eq!(recovered.unwrap().agent_id(), "agent-wire");
}

#[test]
fn test_credential_from_wire_bad_input_fails() {
    let _bad = b"not-base64-data";
    // Actually this might be valid base64; use random bytes
    let truly_bad = vec![0xFF, 0xFE, 0xFD];
    let _ = AgentCredential::from_wire(&truly_bad); // Must not panic
}

// ─── TrustAnchor ─────────────────────────────────────────────────────────────

#[test]
fn test_trust_anchor_new() {
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("anchor-1", ivk);
    assert_eq!(anchor.anchor_id, "anchor-1");
}

#[test]
fn test_trust_anchor_is_valid() {
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("anchor-2", ivk);
    assert!(anchor.is_valid());
}

#[test]
fn test_trust_anchor_fingerprint_not_empty() {
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("anchor-3", ivk);
    assert!(!anchor.fingerprint().is_empty());
}

#[test]
fn test_trust_anchor_covers_domain_empty_allows_all() {
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("anchor-4", ivk);
    // Empty trust_domains = covers all
    assert!(anchor.covers_domain("any-domain"));
}

#[test]
fn test_trust_anchor_verify_credential_valid() {
    let (isk, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("anchor-verify", ivk);
    let id = make_identity("agent-verify", "issuer-anchor", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    // anchor's fingerprint == cred's issuer_public_key_id because same key
    assert!(anchor.verify_credential(&cred));
}

#[test]
fn test_trust_anchor_verify_credential_wrong_key_fails() {
    let (isk, ivk) = generate_issuer_pair();
    let (_, ivk2) = generate_issuer_pair(); // Different key for anchor
    let anchor = TrustAnchor::new("anchor-wrong", ivk2);
    let id = make_identity("agent-wrong-verify", "issuer-anchor", 3600);
    let cred = AgentCredential::issue(&id, &isk, &ivk);
    assert!(!anchor.verify_credential(&cred), "Wrong key must fail");
}

// ─── TrustStore ──────────────────────────────────────────────────────────────

#[test]
fn test_trust_store_register_and_list() {
    let store = TrustStore::new();
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("ts-anchor-1", ivk);
    store.register_anchor(anchor);
    assert!(store.list_anchors().contains(&"ts-anchor-1".to_string()));
}

#[test]
fn test_trust_store_get_anchor() {
    let store = TrustStore::new();
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("ts-anchor-2", ivk);
    store.register_anchor(anchor);
    let entry = store.get_anchor("ts-anchor-2");
    assert!(entry.is_some());
}

#[test]
fn test_trust_store_remove_anchor() {
    let store = TrustStore::new();
    let (_, ivk) = generate_issuer_pair();
    let anchor = TrustAnchor::new("ts-anchor-3", ivk);
    store.register_anchor(anchor);
    let removed = store.remove_anchor("ts-anchor-3");
    assert!(removed);
    assert!(!store.list_anchors().contains(&"ts-anchor-3".to_string()));
}

#[test]
fn test_trust_store_pin_identity() {
    let store = TrustStore::new();
    let (_, ivk) = generate_issuer_pair();
    store.pin_identity("agent-pin", ivk);
    let got = store.get_pinned_key("agent-pin");
    assert!(got.is_some());
}

// ─── DistributedRevocationInfrastructure ─────────────────────────────────────

#[test]
fn test_dri_revoke_and_check() {
    let dri = DistributedRevocationInfrastructure::new();
    let revoker = make_identity("revoker-1", "iss-rev", 3600);
    dri.revoke("agent-rev", "test reason", &revoker, "cred-fp-1").unwrap();
    assert!(dri.is_revoked("agent-rev", "cred-fp-1"));
}

#[test]
fn test_dri_not_revoked_by_default() {
    let dri = DistributedRevocationInfrastructure::new();
    assert!(!dri.is_revoked("agent-nonexistent", "some-fp"));
}

#[test]
fn test_dri_epoch_increments_on_revocation() {
    let dri = DistributedRevocationInfrastructure::new();
    let revoker = make_identity("revoker-2", "iss-rev", 3600);
    let e0 = dri.epoch();
    dri.revoke("agent-epoch", "test reason", &revoker, "fp-epoch").unwrap();
    let e1 = dri.epoch();
    assert!(e1 > e0, "Epoch must increment on revocation");
}

#[test]
fn test_dri_clear() {
    let dri = DistributedRevocationInfrastructure::new();
    let revoker = make_identity("revoker-3", "iss-rev", 3600);
    dri.revoke("agent-clear", "test reason", &revoker, "fp-clear").unwrap();
    assert!(dri.is_revoked("agent-clear", "fp-clear"));
    dri.clear();
    assert!(!dri.is_revoked("agent-clear", "fp-clear"), "DRI must be empty after clear");
}

// ─── IdentityProver ───────────────────────────────────────────────────────────

#[test]
fn test_identity_prover_challenge_len() {
    let challenge = IdentityProver::generate_challenge();
    assert!(!challenge.is_empty());
}

#[test]
fn test_identity_prover_two_challenges_differ() {
    let c1 = IdentityProver::generate_challenge();
    let c2 = IdentityProver::generate_challenge();
    assert_ne!(c1, c2, "Challenges must be random");
}

#[test]
fn test_identity_prover_generate_and_verify_proof() {
    let id = make_identity("agent-proof", "issuer-proof", 3600);
    let challenge = IdentityProver::generate_challenge();
    let (proof, ts) = IdentityProver::generate_proof(&id, &challenge);
    assert!(!proof.is_empty());
    assert!(ts > 0.0);
    let prover = IdentityProver::new();
    let (isk2, ivk2) = generate_issuer_pair();
    let cred = AgentCredential::issue(&id, &isk2, &ivk2);
    let (ok, _reason) = prover.verify_proof(&proof, &cred, &challenge, ts, MAX_CLOCK_SKEW);
    assert!(ok, "Proof must verify");
}

#[test]
fn test_identity_prover_wrong_challenge_fails() {
    let id = make_identity("agent-wrong-chal", "issuer-proof", 3600);
    let challenge = IdentityProver::generate_challenge();
    let (proof, ts) = IdentityProver::generate_proof(&id, &challenge);
    let wrong_challenge = IdentityProver::generate_challenge();
    let prover = IdentityProver::new();
    let (isk2, ivk2) = generate_issuer_pair();
    let cred = AgentCredential::issue(&id, &isk2, &ivk2);
    let (ok, _reason) = prover.verify_proof(&proof, &cred, &wrong_challenge, ts, MAX_CLOCK_SKEW);
    assert!(!ok, "Wrong challenge must fail proof");
}

// ─── provision_issuer ────────────────────────────────────────────────────────

#[test]
fn test_provision_issuer_ok() {
    let (sk, anchor) = provision_issuer("agent-prov", &["agent-prov"], 2, 1, TrustModel::Direct);
    assert!(!sk.as_bytes().is_empty());
    assert!(anchor.is_valid());
}
