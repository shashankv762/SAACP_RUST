//! test_crit2_stream_gate_bypass_rs.rs — CRIT-2 regression proof
//! (opusplan.md Part 1.4 / Part 2: "Stream Frames Bypass 10 of 12 Gates").
//!
//! Root cause (before fix): `handle_stream_continuation`/`handle_stream_end`
//! short-circuited out of `run_gates_1_through_12` and ran their own minimal
//! gate set — Gate 2.5 (kinetic firewall) and Gate 6.0 (audit checkpoint)
//! never ran on continuation/end frames at all. An agent that passed the full
//! pipeline on STREAM_START (with a token capped to e.g. READ_ONLY) could then
//! send a STREAM_CONTINUATION frame claiming a higher `action_class` and it
//! would sail through unchecked — a privilege-escalation-via-continuation-frame
//! attack — and none of that activity was ever written to the audit log.
//!
//! Fix: Gate 1.0's validated, trust-decay-capped `max_action_class` ceiling is
//! now stashed on the `StreamSession` at STREAM_START and re-enforced via
//! Gate 2.5 on every CONTINUATION/END frame; every accepted CONTINUATION frame
//! also now writes a Gate 6.0 audit entry, not just STREAM_END.
//!
//! End-to-end via real wire packets: builds genuinely AES-256-GCM-encrypted
//! `framing::MEASCFrame` packets (the CRIT-1 fix's real crypto path) and drives
//! them through `SAACPProtocolHandler::intercept_packet_full`, exactly as the
//! daemon does — not a direct call into the gate function.

use saacp::{
    SAACPProtocolHandler, ZeroTrustGateway, ImmutableAuditLog, SAACPBytecodes,
};
use saacp::framing::MEASCFrame as StructuralFrame;

/// Shared 32-byte HMAC/AES secret for this file's tests — both the Gate 0
/// AES-256-GCM key material (via `encode_encrypted`/`intercept_packet_full`)
/// and (as `ZeroTrustGateway::validate_lateral_movement`'s issuer_secret
/// fallback, since no per-issuer key is registered) the capability token's
/// HMAC key.
const SECRET: [u8; 32] = [0x7Cu8; 32];

fn build_frame(
    payload: &[u8],
    status_code: u8,
    action_class: u8,
    session_id: [u8; 16],
    psn: u64,
) -> Vec<u8> {
    let frame = StructuralFrame {
        schema_id: 1, status_code, flags: 0, action_class,
        payload_length: 0, // auto-corrected by encode_encrypted
        session_id, epoch_id: 0, psn,
        context_ref_id: [0u8; 32], context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    frame.encode_encrypted(payload, &SECRET).expect("encode_encrypted must succeed")
}

fn issue_token(source_agent: &str, target_agent: &str, max_action_class: u8) -> String {
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        &SECRET, source_agent, &[target_agent], &[], 3600, None, max_action_class, None,
    );
    String::from_utf8(token).expect("token bytes must be valid utf8 (base64)")
}

// ═══════════════════════════════════════════════════════════════════════════
// CRIT-2a — Gate 2.5 (kinetic firewall) now enforced on STREAM_CONTINUATION
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn crit2a_stream_continuation_action_class_escalation_blocked() {
    let gateway = ZeroTrustGateway::new();
    let source_agent = "crit2a-source-agent";
    let target_agent = "crit2a-target-agent";
    let session_id = [0xC2u8, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A,
                       0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A, 0x0A];

    // Token only ever authorizes READ_ONLY (max_action_class = 0).
    let token = issue_token(source_agent, target_agent, 0);
    let start_payload = serde_json::json!({
        "_capability_token": token,
        "task": "benign read-only stream",
        "priority": "normal",
    });
    let start_frame = build_frame(
        &serde_json::to_vec(&start_payload).unwrap(),
        SAACPBytecodes::StreamStart as u8, 0, session_id, 1,
    );
    let start_result = SAACPProtocolHandler::intercept_packet_full(
        &start_frame, &SECRET, target_agent, false,
        Some(&gateway), None, None, None, None,
    );
    assert!(
        start_result.is_ok(),
        "STREAM_START with a valid READ_ONLY-capped token must succeed: {:?}",
        start_result.err()
    );

    // Attack: a continuation frame claims action_class = IRREVERSIBLE (2) — far
    // beyond what the originating token was ever validated for. Pre-CRIT-2-fix,
    // handle_stream_continuation never ran Gate 2.5 at all, so this sailed through.
    let escalation_frame = build_frame(b"", SAACPBytecodes::StreamContinuation as u8, 2, session_id, 2);
    let escalation_result = SAACPProtocolHandler::intercept_packet_full(
        &escalation_frame, &SECRET, target_agent, false,
        Some(&gateway), None, None, None, None,
    );
    assert!(
        escalation_result.is_err(),
        "CRIT-2 regression: STREAM_CONTINUATION escalating action_class past the \
         originating token's validated ceiling must be rejected by Gate 2.5"
    );
    assert_eq!(
        escalation_result.unwrap_err().bytecode,
        SAACPBytecodes::ActionClassEscalation,
        "must be rejected specifically by Gate 2.5 (kinetic firewall), not some other gate"
    );
}

#[test]
fn crit2a_stream_continuation_within_authorized_ceiling_still_works() {
    // Regression guard for the fix itself: a continuation frame whose action_class
    // does NOT exceed the originating token's ceiling must still be accepted —
    // Gate 2.5 must not over-block legitimate same-class continuations.
    let gateway = ZeroTrustGateway::new();
    let source_agent = "crit2a-ok-source-agent";
    let target_agent = "crit2a-ok-target-agent";
    let session_id = [0xC2u8, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B,
                       0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B, 0x0B];

    // Token authorizes up to REVERSIBLE (1).
    let token = issue_token(source_agent, target_agent, 1);
    let start_payload = serde_json::json!({
        "_capability_token": token,
        "task": "reversible stream",
        "priority": "normal",
    });
    let start_frame = build_frame(
        &serde_json::to_vec(&start_payload).unwrap(),
        SAACPBytecodes::StreamStart as u8, 1, session_id, 1,
    );
    let start_result = SAACPProtocolHandler::intercept_packet_full(
        &start_frame, &SECRET, target_agent, false,
        Some(&gateway), None, None, None, None,
    );
    assert!(start_result.is_ok(), "STREAM_START must succeed: {:?}", start_result.err());

    // Continuation at the SAME action_class (1) — must pass Gate 2.5.
    let ok_frame = build_frame(b"benign continuation text", SAACPBytecodes::StreamContinuation as u8, 1, session_id, 2);
    let ok_result = SAACPProtocolHandler::intercept_packet_full(
        &ok_frame, &SECRET, target_agent, false,
        Some(&gateway), None, None, None, None,
    );
    assert!(
        ok_result.is_ok(),
        "Continuation frame within the token's authorized ceiling must still succeed: {:?}",
        ok_result.err()
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// CRIT-2b — Gate 6.0 (audit checkpoint) now written on every accepted
// STREAM_CONTINUATION frame, not just STREAM_END.
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn crit2b_stream_continuation_writes_audit_entry() {
    let gateway = ZeroTrustGateway::new();
    let source_agent = "crit2b-source-agent";
    let target_agent = "crit2b-target-agent";
    let session_id = [0xC2u8, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
                       0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C];

    let token = issue_token(source_agent, target_agent, 0);
    let start_payload = serde_json::json!({
        "_capability_token": token,
        "task": "audited stream",
        "priority": "normal",
    });
    let start_frame = build_frame(
        &serde_json::to_vec(&start_payload).unwrap(),
        SAACPBytecodes::StreamStart as u8, 0, session_id, 1,
    );
    let start_result = SAACPProtocolHandler::intercept_packet_full(
        &start_frame, &SECRET, target_agent, false,
        Some(&gateway), None, None, None, None,
    );
    assert!(start_result.is_ok(), "STREAM_START must succeed: {:?}", start_result.err());

    // Uses the global ImmutableAuditLog (audit_log: None falls back to it, same as
    // handle_stream_continuation's own fallback) — assert a monotonic increase
    // rather than an exact delta, since this global is shared with any other test
    // running concurrently in this binary.
    let before = ImmutableAuditLog::global().event_count();

    let cont_frame = build_frame(b"legitimate stream text", SAACPBytecodes::StreamContinuation as u8, 0, session_id, 2);
    let cont_result = SAACPProtocolHandler::intercept_packet_full(
        &cont_frame, &SECRET, target_agent, false,
        Some(&gateway), None, None, None, None,
    );
    assert!(cont_result.is_ok(), "Legitimate continuation frame must succeed: {:?}", cont_result.err());

    let after = ImmutableAuditLog::global().event_count();
    assert!(
        after > before,
        "CRIT-2 regression: an accepted STREAM_CONTINUATION frame must write a Gate 6.0 \
         audit entry (before={before}, after={after}) — previously only STREAM_END did"
    );
}
