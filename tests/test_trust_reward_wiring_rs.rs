//! test_trust_reward_wiring_rs.rs — Phase 6 item 1 (Part 8.5, positive behavioral trust
//! signals): proves `TrustDecayEngine::reward` is actually wired into the REAL gate
//! pipeline (`handler::intercept_packet_full`'s clean-pass tail), not just exercised
//! directly in `trust_decay.rs`'s own unit tests — mirroring
//! `test_telemetry_wiring_rs.rs`'s "prove it through the real entry point" convention.

use saacp::framing::MEASCFrame as StructuralFrame;
use saacp::trust_decay::{trust_key_for, PenaltyKind, TrustDecayEngine};
use saacp::{AgentRateLimiter, SAACPProtocolHandler};

/// See `test_telemetry_wiring_rs.rs::build_frame` for why `framing::MEASCFrame` (not
/// `measc::MEASCFrame`) is used here.
fn build_frame(session: [u8; 16], secret: &[u8], payload: &[u8], schema: u16, status_code: u8, action_class: u8) -> Vec<u8> {
    let frame = StructuralFrame {
        schema_id: schema,
        status_code,
        flags: 0,
        action_class,
        payload_length: 0, // auto-corrected by encode_encrypted
        session_id: session,
        epoch_id: 0,
        psn: 1,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    frame.encode_encrypted(payload, secret).expect("encode_encrypted must succeed")
}

#[test]
fn clean_pipeline_pass_rewards_trust_score() {
    let secret = [0xB1u8; 32];
    let session = [0xB2u8; 16];
    let agent_id = "reward-wiring-test-agent";
    // No `TranscriptBoundSession` is registered for this connection (no identity binding
    // configured), so `trust_key_for` falls back to the bare `aid:{agent_id}` key
    // regardless of the session_uuid string passed in — see its doc comment.
    let trust_key = trust_key_for(agent_id, "");

    // Drive the score down first: at `TRUST_SCORE_INITIAL` (1.0) a reward is a
    // no-op ceiling, so a fresh agent's very first clean pass wouldn't observably move
    // the score. Penalizing first, then proving a clean pass moves it back up, is the
    // only way to observe the reward path through the real pipeline.
    TrustDecayEngine::global().penalize(&trust_key, PenaltyKind::EpistemicOverclaim);
    let after_penalty = TrustDecayEngine::global().score(&trust_key);
    assert!(after_penalty < 1.0, "penalize must have lowered the score below the initial ceiling");

    // A clean, structurally-valid, non-injection packet. Schema 1 ("Task") requires
    // both `task` and `priority`. `action_class: 0` (READ_ONLY) — not the IRREVERSIBLE
    // 2x-multiplier path, which is covered by the pure unit test in `trust_decay.rs`.
    let clean_payload = serde_json::json!({
        "task": "summarize the quarterly report",
        "priority": 1,
        "_capability_token": "structural-test-token",
    }).to_string();
    let frame = build_frame(session, &secret, clean_payload.as_bytes(), 1, 0x10, 0);

    let rl = AgentRateLimiter::new();
    let result = SAACPProtocolHandler::intercept_packet_full(
        &frame, &secret, agent_id, false, None, Some(&rl), None, None, None,
    );
    assert!(result.is_ok(), "clean packet must pass the full pipeline: {result:?}");

    let after_clean_pass = TrustDecayEngine::global().score(&trust_key);
    assert!(
        after_clean_pass > after_penalty,
        "a clean full-pipeline pass must reward the trust score: after_penalty={after_penalty} after_clean_pass={after_clean_pass}"
    );
}
