//! test_ievl_rs.rs — Phase 6 item 3 (Part 8.1, Intent-Execution Verification Loop):
//! proves IEVL's registration hook, signature verification, and enforcement
//! (reward/penalize/revoke) are wired into the REAL production entry points —
//! `IevlEngine::register_declaration` (exactly what `handler.rs`'s Gate 1.5 hook
//! calls) and `ievl::handle_execution_receipt` (exactly what `daemon.rs`'s
//! schema_id=10 dispatch calls) — not just exercised against the isolated
//! `IevlEngine` in `ievl.rs`'s own unit tests. Mirrors
//! `test_trust_reward_wiring_rs.rs`'s and `test_gossip_daemon_wiring_rs.rs`'s
//! "prove it through the real entry point" convention.
//!
//! A genuine end-to-end drive through `intercept_packet_full` with a real
//! gateway-issued token carrying `root_intent_hash` is out of scope here for the
//! same documented reason `test_blackhat_agent_hijack_rs.rs`'s module doc gives:
//! the encrypting `measc::MEASCFrame` used for full-pipeline tests and the
//! `framing::MEASCFrame` Gate 0 actually decrypts are architecturally distinct,
//! so no test in this crate drives a real root-intent-bound token through
//! `intercept_packet_full` end-to-end. This file instead calls the exact
//! production functions `handler.rs`/`daemon.rs` call (not reimplementations of
//! them), which is this crate's established substitute for that gap — see
//! `gate_5_0b_scope_consistency`'s and `gate_1_5_reinforcement`'s own tests for
//! the same "call the real gate/hook function directly" precedent.

use std::collections::HashMap;
use std::sync::Arc;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

use saacp::identity_binding::{TranscriptBoundSession, DEFAULT_IDENTITY_REGISTRY};
use saacp::ievl::{self, IevlEngine, VerificationVerdict};
use saacp::trust_decay::{trust_key_for, TrustDecayEngine};
use saacp::{DistributedRevocationInfrastructure, GateTier, JsonValue, ParsedPacket};

/// Register a `TranscriptBoundSession` with a freshly-generated Ed25519 keypair
/// and return `(signing_key, session_id_hex, thash)` — the caller must
/// `DEFAULT_IDENTITY_REGISTRY.remove(&thash)` before the test ends (the registry
/// is a process-wide singleton shared across every test in this binary).
fn bind_session(session_id_byte: u8, client_agent_id: &str) -> (SigningKey, String, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let client_pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let sid = vec![session_id_byte; 16];
    let session = TranscriptBoundSession::establish(
        sid, client_agent_id, "server-x",
        &client_pk_hex, &"bb".repeat(32),
        &"cc".repeat(16), &"dd".repeat(16),
        "SAACP/0.1-beta2", "Ed25519-AES256GCM", None,
    );
    let session_id_hex = session.session_id_hex();
    let thash = session.thash.clone();
    DEFAULT_IDENTITY_REGISTRY.register(session);
    (signing_key, session_id_hex, thash)
}

/// Build a minimal `ParsedPacket` the way `daemon.rs` would after the full gate
/// pipeline (Gate 0 through Gate 12.0) has already accepted a schema_id=10
/// `ExecutionReceipt`. Only the fields `ievl::handle_execution_receipt` actually
/// reads are meaningfully populated.
fn receipt_parsed_packet(session_uuid: &str, source_agent: &str, action_class: u8, payload_dict: HashMap<String, JsonValue>) -> ParsedPacket {
    ParsedPacket {
        schema_id: 10,
        flags: 0,
        action_class,
        status_code: 0x10,
        session_uuid: Arc::from(session_uuid),
        sequence_id: 1,
        context_state_id: String::new(),
        context_version: 0,
        traceparent: Vec::new(),
        payload: Vec::new(),
        payload_dict,
        gate_tier: GateTier::Full,
        is_cover_traffic: false,
        source_agent: Arc::from(source_agent),
        is_binary_stream: false,
        max_action_class: action_class,
        token_sig_hash: Arc::from(""),
    }
}

fn receipt_payload(declaration_ref: &str, actual_action: &str, actual_targets: &[String], signature_b64: &str) -> HashMap<String, JsonValue> {
    let mut pd = HashMap::new();
    pd.insert("declaration_ref".to_string(), JsonValue::String(declaration_ref.to_string()));
    pd.insert("actual_action".to_string(), JsonValue::String(actual_action.to_string()));
    pd.insert("actual_targets".to_string(), JsonValue::Array(
        actual_targets.iter().map(|t| JsonValue::String(t.clone())).collect(),
    ));
    pd.insert("receipt_signature".to_string(), JsonValue::String(signature_b64.to_string()));
    pd
}

// ─── End-to-end: declare → sign → receipt → real enforcement ─────────────────

#[test]
fn consistent_receipt_through_real_entry_point_rewards_trust_score() {
    let (signing_key, session_id_hex, thash) = bind_session(0x21, "ievl-e2e-agent-1");
    let agent_id = "ievl-e2e-agent-1";
    let trust_key = trust_key_for(agent_id, &session_id_hex);

    // Drive the score down first — at TRUST_SCORE_INITIAL (1.0) a reward is a
    // no-op ceiling, so the very first pass wouldn't observably move the score.
    TrustDecayEngine::global().penalize(&trust_key, saacp::trust_decay::PenaltyKind::EpistemicOverclaim);
    let after_penalty = TrustDecayEngine::global().score(&trust_key);

    // Exactly what handler.rs's Gate 1.5 hook calls.
    IevlEngine::global().register_declaration(
        &session_id_hex, 1, agent_id,
        "archive the quarterly ledger".to_string(), 0x02, vec!["ledger-1".to_string()],
    );

    let declaration_ref = ievl::declaration_id(&session_id_hex, 1);
    let targets = vec!["ledger-1".to_string()];
    let sig = ievl::sign_receipt(&signing_key, &declaration_ref, "archive the quarterly ledger", &targets);
    let payload = receipt_payload(&declaration_ref, "archive the quarterly ledger", &targets, &sig);
    let parsed = receipt_parsed_packet(&session_id_hex, agent_id, 0x02, payload);

    // Exactly what daemon.rs's schema_id=10 dispatch calls.
    ievl::handle_execution_receipt(&parsed);

    let after_receipt = TrustDecayEngine::global().score(&trust_key);

    DEFAULT_IDENTITY_REGISTRY.remove(&thash);

    assert!(
        after_receipt > after_penalty,
        "a Consistent ExecutionReceipt through the real entry point must reward trust: \
         after_penalty={after_penalty} after_receipt={after_receipt}"
    );
}

#[test]
fn target_violation_receipt_through_real_entry_point_penalizes_trust() {
    let (signing_key, session_id_hex, thash) = bind_session(0x22, "ievl-e2e-agent-2");
    let agent_id = "ievl-e2e-agent-2";
    let trust_key = trust_key_for(agent_id, &session_id_hex);
    let before = TrustDecayEngine::global().score(&trust_key);

    IevlEngine::global().register_declaration(
        &session_id_hex, 1, agent_id,
        "archive the quarterly ledger".to_string(), 0x02, vec!["ledger-1".to_string()],
    );

    let declaration_ref = ievl::declaration_id(&session_id_hex, 1);
    // Reports touching a completely different target than what was declared.
    let actual_targets = vec!["unrelated-production-database".to_string()];
    let sig = ievl::sign_receipt(&signing_key, &declaration_ref, "archive the quarterly ledger", &actual_targets);
    let payload = receipt_payload(&declaration_ref, "archive the quarterly ledger", &actual_targets, &sig);
    let parsed = receipt_parsed_packet(&session_id_hex, agent_id, 0x02, payload);

    ievl::handle_execution_receipt(&parsed);

    let after = TrustDecayEngine::global().score(&trust_key);

    DEFAULT_IDENTITY_REGISTRY.remove(&thash);

    assert!(
        after < before,
        "a TargetViolation ExecutionReceipt through the real entry point must penalize trust: \
         before={before} after={after}"
    );
}

#[test]
fn class_escalation_receipt_through_real_entry_point_calls_real_dri_revoke() {
    let (signing_key, session_id_hex, thash) = bind_session(0x23, "ievl-e2e-agent-3");
    let agent_id = "ievl-e2e-agent-3";

    // Sanity: not revoked before the escalation is reported.
    assert!(!DistributedRevocationInfrastructure::global().is_revoked(agent_id, ""));

    IevlEngine::global().register_declaration(
        &session_id_hex, 1, agent_id,
        "archive the quarterly ledger".to_string(), 0x02, vec!["ledger-1".to_string()],
    );

    let declaration_ref = ievl::declaration_id(&session_id_hex, 1);
    let targets = vec!["ledger-1".to_string()];
    // "wipe" is in DANGEROUS_ACTION_TERMS and absent from the declared text —
    // the realistic production escalation signal (see ievl.rs's module docs:
    // numeric action_class alone can't fire once a declaration is already at
    // the protocol ceiling).
    let sig = ievl::sign_receipt(&signing_key, &declaration_ref, "wipe the quarterly ledger", &targets);
    let payload = receipt_payload(&declaration_ref, "wipe the quarterly ledger", &targets, &sig);
    let parsed = receipt_parsed_packet(&session_id_hex, agent_id, 0x02, payload);

    ievl::handle_execution_receipt(&parsed);

    DEFAULT_IDENTITY_REGISTRY.remove(&thash);

    assert!(
        DistributedRevocationInfrastructure::global().is_revoked(agent_id, ""),
        "a ClassEscalation ExecutionReceipt through the real entry point must call the real \
         DistributedRevocationInfrastructure::global().revoke"
    );
}

#[test]
fn forged_signature_through_real_entry_point_is_rejected_and_declaration_survives() {
    let (signing_key, session_id_hex, thash) = bind_session(0x24, "ievl-e2e-agent-4");
    let agent_id = "ievl-e2e-agent-4";
    let _ = &signing_key; // the attacker does NOT use the real session key below

    IevlEngine::global().register_declaration(
        &session_id_hex, 1, agent_id,
        "archive the quarterly ledger".to_string(), 0x02, vec!["ledger-1".to_string()],
    );

    let declaration_ref = ievl::declaration_id(&session_id_hex, 1);
    let targets = vec!["ledger-1".to_string()];
    // Sign with a DIFFERENT, unregistered keypair — forged relative to this session.
    let attacker_key = SigningKey::generate(&mut OsRng);
    let forged_sig = ievl::sign_receipt(&attacker_key, &declaration_ref, "archive the quarterly ledger", &targets);
    let payload = receipt_payload(&declaration_ref, "archive the quarterly ledger", &targets, &forged_sig);
    let parsed = receipt_parsed_packet(&session_id_hex, agent_id, 0x02, payload);

    ievl::handle_execution_receipt(&parsed);

    // The declaration must still be pending — a forged receipt must not be
    // able to consume/clear it (that would let an attacker suppress the
    // legitimate ReceiptTimeout penalty the real client's silence should
    // eventually earn).
    let still_pending = IevlEngine::global().process_receipt(&declaration_ref, "archive the quarterly ledger", &targets, 0x02);

    DEFAULT_IDENTITY_REGISTRY.remove(&thash);

    assert_eq!(
        still_pending, VerificationVerdict::Consistent,
        "the declaration must have survived the forged receipt untouched — this second, \
         correctly-unauthenticated-context call is the first thing to actually consume it"
    );
}

#[test]
fn receipt_missing_for_unknown_declaration_ref_through_real_entry_point() {
    let (signing_key, session_id_hex, thash) = bind_session(0x25, "ievl-e2e-agent-5");
    let agent_id = "ievl-e2e-agent-5";
    let trust_key = trust_key_for(agent_id, &session_id_hex);
    let before = TrustDecayEngine::global().score(&trust_key);

    // No declaration was ever registered for this session/sequence pair.
    let bogus_ref = ievl::declaration_id(&session_id_hex, 999);
    let targets = vec!["whatever".to_string()];
    let sig = ievl::sign_receipt(&signing_key, &bogus_ref, "do something", &targets);
    let payload = receipt_payload(&bogus_ref, "do something", &targets, &sig);
    let parsed = receipt_parsed_packet(&session_id_hex, agent_id, 0x02, payload);

    ievl::handle_execution_receipt(&parsed);

    let after = TrustDecayEngine::global().score(&trust_key);

    DEFAULT_IDENTITY_REGISTRY.remove(&thash);

    assert_eq!(after, before, "a receipt with no matching declaration must not move trust at all");
}

// ─── Schema wiring sanity ──────────────────────────────────────────────────

#[test]
fn schema_10_is_assigned_to_execution_receipt() {
    let payload = serde_json::json!({
        "declaration_ref": "r",
        "actual_action": "a",
        "actual_targets": ["t"],
        "receipt_signature": "sig",
    });
    assert!(saacp::PreCompiledSchemas::validate_payload(10, &payload).is_ok());
}
