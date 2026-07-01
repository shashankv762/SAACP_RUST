//! test_c3_identity_binding_rs.rs — C-3 Identity Binding tests
//!
//! Ports Python: tests/test_c3_identity_binding.py
//! AgentIdentityCertificate, IdentityVerifier, IdentityGate,
//! TranscriptBoundSession, SessionIdentityRegistry.

use saacp::{
    AgentIdentityCertificate, IdentityVerifier, IdentityGate,
    TranscriptBoundSession, SessionIdentityRegistry,
    IDENTITY_GATE_PHASES, SAACPBytecodes,
};

use rand::rngs::OsRng;
use ed25519_dalek::SigningKey;

fn make_ca_pair() -> (SigningKey, ed25519_dalek::VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    (sk, vk)
}

fn make_test_session() -> TranscriptBoundSession {
    let sid = vec![0xABu8; 16];
    TranscriptBoundSession::establish(
        sid,
        "client-agent",
        "server-agent",
        &"aa".repeat(32),
        &"bb".repeat(32),
        &"cc".repeat(16),
        &"dd".repeat(16),
        "SAACP/0.1-beta2",
        "Ed25519-AES256GCM",
        None,
    )
}

// ─── AgentIdentityCertificate ────────────────────────────────────────────────

#[test]
fn test_certificate_issue_fields() {
    let (ca_sk, _ca_vk) = make_ca_pair();
    let (_, agent_vk) = make_ca_pair();
    let agent_pk_hex = hex::encode(agent_vk.as_bytes());

    let cert = AgentIdentityCertificate::issue(
        "agent-001", &agent_pk_hex, &ca_sk,
        "ca-kid-01", "root-ca", 86400.0, "ed25519",
    );
    assert_eq!(cert.agent_id, "agent-001");
    assert_eq!(cert.ca_kid, "ca-kid-01");
    assert_eq!(cert.issuer_id, "root-ca");
    assert_eq!(cert.algorithm, "ed25519");
    assert_eq!(cert.public_key_hex, agent_pk_hex);
    assert!(!cert.cert_id.is_empty());
    assert_eq!(cert.cert_signature.len(), 64);
}

#[test]
fn test_certificate_not_expired_immediately() {
    let (ca_sk, _) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-x", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-k", "iss", 86400.0, "ed25519",
    );
    assert!(!cert.is_expired());
}

#[test]
fn test_certificate_fingerprint_is_64_chars() {
    let (ca_sk, _) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-fp", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-k", "iss", 86400.0, "ed25519",
    );
    assert_eq!(cert.fingerprint().len(), 64);
}

#[test]
fn test_certificate_serialization_roundtrip() {
    let (ca_sk, _) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-rt", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-rt", "issuer-rt", 3600.0, "ed25519",
    );
    let json = cert.to_json();
    let cert2 = AgentIdentityCertificate::from_json(&json).unwrap();
    assert_eq!(cert2.agent_id, cert.agent_id);
    assert_eq!(cert2.cert_signature, cert.cert_signature);
    assert_eq!(cert2.ca_kid, cert.ca_kid);
}

#[test]
fn test_certificate_body_bytes_not_empty() {
    let (ca_sk, _) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-body", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-k", "iss", 60.0, "ed25519",
    );
    let body = cert.body_bytes();
    assert!(!body.is_empty());
}

// ─── IdentityVerifier ────────────────────────────────────────────────────────

#[test]
fn test_verifier_valid_certificate_ok() {
    let (ca_sk, ca_vk) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-ok", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-01", "root", 86400.0, "ed25519",
    );

    let verifier = IdentityVerifier::new();
    verifier.register_ca_key("ca-01", ca_vk);
    assert!(verifier.verify_certificate(&cert).is_ok());
    assert!(verifier.is_identity_verified("agent-ok"));
}

#[test]
fn test_verifier_unknown_ca_fails() {
    let (ca_sk, _) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-x", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-unknown", "root", 86400.0, "ed25519",
    );
    let verifier = IdentityVerifier::new();
    let err = verifier.verify_certificate(&cert).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::IdentityBindingMissing);
}

#[test]
fn test_verifier_revoked_certificate_rejected() {
    let (ca_sk, ca_vk) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let cert = AgentIdentityCertificate::issue(
        "agent-rev", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-01", "root", 86400.0, "ed25519",
    );
    let cert_id = cert.cert_id.clone();

    let verifier = IdentityVerifier::new();
    verifier.register_ca_key("ca-01", ca_vk);
    verifier.revoke_certificate(&cert_id);
    let err = verifier.verify_certificate(&cert).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::KeyRevoked);
}

#[test]
fn test_verifier_tampered_signature_rejected() {
    let (ca_sk, ca_vk) = make_ca_pair();
    let (_, avk) = make_ca_pair();
    let mut cert = AgentIdentityCertificate::issue(
        "agent-tamper", &hex::encode(avk.as_bytes()),
        &ca_sk, "ca-01", "root", 86400.0, "ed25519",
    );
    cert.cert_signature[0] ^= 0xFF;

    let verifier = IdentityVerifier::new();
    verifier.register_ca_key("ca-01", ca_vk);
    assert!(verifier.verify_certificate(&cert).is_err());
}

#[test]
fn test_verifier_not_verified_before_check() {
    let verifier = IdentityVerifier::new();
    assert!(!verifier.is_identity_verified("nobody"));
}

#[test]
fn test_verifier_require_identity_verified_fails_if_not_done() {
    let verifier = IdentityVerifier::new();
    assert!(verifier.require_identity_verified("nobody", "cap_check").is_err());
}

// ─── TranscriptBoundSession ───────────────────────────────────────────────────

#[test]
fn test_transcript_session_thash_is_64_chars() {
    let s = make_test_session();
    assert_eq!(s.thash.len(), 64);
}

#[test]
fn test_transcript_session_integrity_ok() {
    let s = make_test_session();
    assert!(s.verify_thash_integrity());
}

#[test]
fn test_transcript_session_not_identity_verified_initially() {
    let s = make_test_session();
    assert!(!s.identity_verified);
}

#[test]
fn test_transcript_session_mark_identity_verified() {
    let mut s = make_test_session();
    s.mark_identity_verified();
    assert!(s.identity_verified);
}

#[test]
fn test_transcript_session_deterministic_thash() {
    let sid = vec![0x01u8; 16];
    let s1 = TranscriptBoundSession::establish(
        sid.clone(), "c", "s",
        &"aa".repeat(32), &"bb".repeat(32),
        &"cc".repeat(16), &"dd".repeat(16),
        "v1", "cs1", None,
    );
    let s2 = TranscriptBoundSession::establish(
        sid, "c", "s",
        &"aa".repeat(32), &"bb".repeat(32),
        &"cc".repeat(16), &"dd".repeat(16),
        "v1", "cs1", None,
    );
    assert_eq!(s1.thash, s2.thash);
}

#[test]
fn test_transcript_session_different_params_different_thash() {
    let sid = vec![0x01u8; 16];
    let s1 = TranscriptBoundSession::establish(
        sid.clone(), "client-A", "server",
        &"aa".repeat(32), &"bb".repeat(32),
        &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
    );
    let s2 = TranscriptBoundSession::establish(
        sid, "client-B", "server",
        &"aa".repeat(32), &"bb".repeat(32),
        &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
    );
    assert_ne!(s1.thash, s2.thash);
}

// ─── IdentityVerifier transcript binding ─────────────────────────────────────

#[test]
fn test_verify_transcript_binding_client_ok() {
    let sid = vec![0x01u8; 16];
    let client_pk = "aa".repeat(32);
    let server_pk = "bb".repeat(32);
    let session = TranscriptBoundSession::establish(
        sid, "client-a", "server-b",
        &client_pk, &server_pk,
        &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
    );
    let verifier = IdentityVerifier::new();
    assert!(verifier.verify_transcript_binding(&session, "client-a", &client_pk, "client").is_ok());
}

#[test]
fn test_verify_transcript_binding_key_swap_detected() {
    let session = make_test_session();
    let verifier = IdentityVerifier::new();
    let err = verifier.verify_transcript_binding(
        &session, "client-agent", &"ff".repeat(32), "client",
    ).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::IdentityMisbinding);
}

#[test]
fn test_verify_transcript_binding_identity_splice_detected() {
    let session = make_test_session();
    let verifier = IdentityVerifier::new();
    let err = verifier.verify_transcript_binding(
        &session, "impostor-agent", &"aa".repeat(32), "client",
    ).unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::SessionSpliceDetected);
}

#[test]
fn test_verify_thash_matches_capability_ok() {
    let session = make_test_session();
    let verifier = IdentityVerifier::new();
    assert!(verifier.verify_thash_matches_capability(&session, &session.thash).is_ok());
}

#[test]
fn test_verify_thash_mismatch_detected() {
    let session = make_test_session();
    let verifier = IdentityVerifier::new();
    let err = verifier.verify_thash_matches_capability(&session, "wrong_hash_value").unwrap_err();
    assert_eq!(err.bytecode, SAACPBytecodes::TranscriptHashMismatch);
}

// ─── IdentityGate ─────────────────────────────────────────────────────────────

#[test]
fn test_identity_gate_phases_list() {
    assert!(!IDENTITY_GATE_PHASES.is_empty());
    assert!(IDENTITY_GATE_PHASES.contains(&"IDENTITY_VERIFIED"));
    assert!(IDENTITY_GATE_PHASES.contains(&"AUTHORIZED"));
    assert!(IDENTITY_GATE_PHASES.contains(&"EXECUTION_ALLOWED"));
}

#[test]
fn test_identity_gate_require_phase_fails_before_advance() {
    let gate = IdentityGate::new();
    assert!(gate.require_phase("agent-1", "session-1", "IDENTITY_VERIFIED").is_err());
}

#[test]
fn test_identity_gate_advance_and_require_ok() {
    let gate = IdentityGate::new();
    gate.advance("agent-1", "session-1", "IDENTITY_VERIFIED").unwrap();
    assert!(gate.require_phase("agent-1", "session-1", "IDENTITY_VERIFIED").is_ok());
}

#[test]
fn test_identity_gate_ordered_phases() {
    let gate = IdentityGate::new();
    let agent = "agent-g";
    let sid = "session-g";

    gate.advance(agent, sid, "IDENTITY_VERIFIED").unwrap();
    assert!(gate.require_phase(agent, sid, "AUTHORIZED").is_err());

    gate.advance(agent, sid, "AUTHORIZED").unwrap();
    assert!(gate.require_phase(agent, sid, "AUTHORIZED").is_ok());
    assert!(gate.require_phase(agent, sid, "CAPABILITY_VALIDATED").is_err());
}

#[test]
fn test_identity_gate_unknown_phase_advance_fails() {
    let gate = IdentityGate::new();
    let res = gate.advance("agent-x", "sid-x", "NONEXISTENT_PHASE");
    assert!(res.is_err());
}

#[test]
fn test_identity_gate_clear_resets_state() {
    let gate = IdentityGate::new();
    gate.advance("a1", "s1", "IDENTITY_VERIFIED").unwrap();
    gate.clear("a1", "s1");
    assert!(gate.require_phase("a1", "s1", "IDENTITY_VERIFIED").is_err());
}

#[test]
fn test_identity_gate_independent_per_agent_session() {
    let gate = IdentityGate::new();
    gate.advance("agent-A", "sess-A", "IDENTITY_VERIFIED").unwrap();
    // agent-B has not advanced yet
    assert!(gate.require_phase("agent-B", "sess-A", "IDENTITY_VERIFIED").is_err());
}

// ─── SessionIdentityRegistry ─────────────────────────────────────────────────

#[test]
fn test_session_registry_empty_initially() {
    let reg = SessionIdentityRegistry::new();
    assert_eq!(reg.count(), 0);
}

#[test]
fn test_session_registry_register_and_get_by_thash() {
    let reg = SessionIdentityRegistry::new();
    let session = make_test_session();
    let thash = session.thash.clone();
    reg.register(session);
    assert_eq!(reg.count(), 1);
    let found = reg.get_by_thash(&thash, |s| s.client_agent_id.clone());
    assert_eq!(found, Some("client-agent".to_string()));
}

#[test]
fn test_session_registry_get_by_session_id_hex() {
    let reg = SessionIdentityRegistry::new();
    let session = make_test_session();
    let sid_hex = session.session_id_hex();
    reg.register(session);
    let found = reg.get_by_session_id(&sid_hex, |s| s.server_agent_id.clone());
    assert_eq!(found, Some("server-agent".to_string()));
}

#[test]
fn test_session_registry_remove() {
    let reg = SessionIdentityRegistry::new();
    let session = make_test_session();
    let thash = session.thash.clone();
    reg.register(session);
    reg.remove(&thash);
    assert_eq!(reg.count(), 0);
    assert!(reg.get_by_thash(&thash, |s| s.client_agent_id.clone()).is_none());
}

#[test]
fn test_session_registry_get_nonexistent_returns_none() {
    let reg = SessionIdentityRegistry::new();
    assert!(reg.get_by_thash("nonexistent", |s| s.client_agent_id.clone()).is_none());
}
