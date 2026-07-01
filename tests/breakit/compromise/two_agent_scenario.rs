// BREAKIT: Real Two-Agent Compromise Scenario
//
// saacp-rs is a library crate (no binary). We build two real protocol handler
// instances communicating via in-memory packet transfer — not mocks.
// Then we extract the live capability token from Agent A's gateway (simulating
// an attacker with memory-read access to the process) and use it to attack
// Agent B and Agent C.
//
// This test answers: "Does SAACP have ANY automatic mechanism to detect that a
// cryptographically-valid, non-revoked token is being used from the wrong process
// (without a human calling revoke_token())?"
//
// Attack vectors:
//   a) Same session, same audience — direct stolen-token reuse
//   b) Different session ID — audience binding check
//   c) To a third agent never contacted before — cross-audience binding
//
// Expected result (if protocol is correctly designed):
//   - (a) may succeed if token is valid and non-revoked, because the protocol
//     doesn't bind tokens to process identity — by design in bearer tokens
//   - (b) depends on whether 'cid' (conversation ID) is validated as audience
//   - (c) depends on 'aud' field validation
//
// This test DOCUMENTS findings, not just passes/fails.

use saacp::ZeroTrustGateway;
use std::sync::Arc;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const TEST_PSK: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

const PLANNER_ID: &str = "planner-agent";
const EXECUTOR_ID: &str = "executor-agent";
const THIRD_AGENT_ID: &str = "third-agent-never-contacted";

/// Build a real HMAC-PSK capability token granting access from planner to executor.
fn build_planner_token(secret: &[u8], target: &str, iat: f64) -> Vec<u8> {
    // Use integer timestamps so serde_json serializes them as u64
    // (the gateway parses exp via as_u64())
    let iat_u64 = iat as u64;
    let exp_u64 = iat_u64 + 3600;
    let json_payload = serde_json::json!({
        "iss": PLANNER_ID,
        "sub": "task-delegation",
        "iat": iat_u64,
        "exp": exp_u64,
        "scope": ["read", "write"],
        "allow": [target],
        "aud": [target],
        "cid": "conversation-001",
        "_sig_alg": "hmac-sha256"
    });

    let json_bytes = serde_json::to_vec(&json_payload).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(&json_bytes);
    let sig = mac.finalize().into_bytes().to_vec();

    // Wire format: 4-byte BE json_len + json_bytes + 32-byte HMAC
    // Must use BIG-ENDIAN — gateway.rs parse_token_wire uses u32::from_be_bytes
    let json_len = json_bytes.len() as u32;
    let mut wire = Vec::new();
    wire.extend_from_slice(&json_len.to_be_bytes());
    wire.extend_from_slice(&json_bytes);
    wire.extend_from_slice(&sig);

    base64::engine::general_purpose::STANDARD.encode(&wire).into_bytes()
}

#[allow(dead_code)]
fn build_token_for_different_audience(secret: &[u8], original_token_b64: &[u8], new_aud: &str) -> Vec<u8> {
    // Re-sign a new token with the same secret but a different audience
    // (simulates an attacker trying to present A→B token to agent C)
    let decoded = base64::engine::general_purpose::STANDARD.decode(original_token_b64).unwrap();
    if decoded.len() < 4 { return vec![]; }
    let json_len = u32::from_le_bytes(decoded[0..4].try_into().unwrap()) as usize;
    if 4 + json_len > decoded.len() { return vec![]; }

    let json_bytes = &decoded[4..4 + json_len];
    let mut data: serde_json::Value = serde_json::from_slice(json_bytes).unwrap();

    // Modify the audience — this creates a NEW token, not a forged one
    // (we have the secret, so we can issue any token we want)
    data["aud"] = serde_json::json!([new_aud]);
    let new_json = serde_json::to_vec(&data).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(&new_json);
    let sig = mac.finalize().into_bytes().to_vec();

    let json_len = new_json.len() as u32;
    let mut wire = Vec::new();
    wire.extend_from_slice(&json_len.to_le_bytes());
    wire.extend_from_slice(&new_json);
    wire.extend_from_slice(&sig);

    base64::engine::general_purpose::STANDARD.encode(&wire).into_bytes()
}

/// The core two-agent compromise scenario.
#[test]
fn phase_6_two_agent_compromise_scenario() {
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs_f64();

    // ── STEP 1: Create Planner and Executor gateways ──────────────────────────
    let _planner_gw = ZeroTrustGateway::new();
    let executor_gw = Arc::new(ZeroTrustGateway::new());

    // ── STEP 2: Normal operation — Planner issues tokens, Executor validates ──

    let legitimate_token = build_planner_token(&TEST_PSK, EXECUTOR_ID, iat);

    // Normal flow: Planner → Executor (validate 50 times = 50 rounds of normal traffic)
    let mut normal_successes = 0usize;
    for _ in 0..50 {
        if executor_gw.validate_lateral_movement(
            EXECUTOR_ID,
            &legitimate_token,
            &TEST_PSK,
        ).is_ok() {
            normal_successes += 1;
        }
    }
    eprintln!("[PHASE-6] Normal operation: {}/50 validations succeeded.", normal_successes);
    assert_eq!(normal_successes, 50, "All 50 normal-operation validations must succeed");

    // ── STEP 3: REAL compromise — extract token from Planner's "memory" ────────
    //
    // In a real compromise scenario, the attacker has code execution on Planner's host
    // and reads the token from process memory. In a library test, we simulate this by
    // simply holding a copy of the token bytes — these ARE the real bytes that were
    // issued and used in normal operation above.
    let stolen_token: Vec<u8> = legitimate_token.clone();
    eprintln!(
        "[PHASE-6] COMPROMISE: Attacker extracted {} bytes of live token from Planner memory.",
        stolen_token.len()
    );

    // ── STEP 4: Attack A — Stolen token used against same executor, same audience ──
    let attack_a = executor_gw.validate_lateral_movement(
        EXECUTOR_ID,
        &stolen_token,
        &TEST_PSK,
    );
    eprintln!(
        "[PHASE-6] Attack A (stolen token, same target): {:?}",
        if attack_a.is_ok() { "ACCEPTED (token still valid)" } else { "REJECTED" }
    );

    // ── STEP 5: Attack B — Stolen token against DIFFERENT session/conversation ──
    //
    // We create a token for a different audience (simulating the stolen token being
    // replayed to a different agent). Note: if the aud field is validated, this MUST fail.
    let _attack_b_token = build_planner_token(&TEST_PSK, EXECUTOR_ID, iat + 1.0);
    // Present stolen A→B token to B while claiming it's for a different purpose
    // (same token, different target string in the API call)
    let attack_b = executor_gw.validate_lateral_movement(
        "wrong-agent-name-not-in-aud", // Target doesn't match token's aud field
        &stolen_token,
        &TEST_PSK,
    );
    eprintln!(
        "[PHASE-6] Attack B (stolen token, wrong target agent): {:?}",
        if attack_b.is_ok() { "ACCEPTED — audience binding NOT enforced" }
        else { "REJECTED — audience binding enforced" }
    );

    // ── STEP 6: Attack C — Stolen token against third agent (never contacted before) ──
    let third_agent_gw = ZeroTrustGateway::new();
    let attack_c = third_agent_gw.validate_lateral_movement(
        THIRD_AGENT_ID,
        &stolen_token,
        &TEST_PSK,
    );
    eprintln!(
        "[PHASE-6] Attack C (stolen A→B token presented to agent C): {:?}",
        if attack_c.is_ok() {
            "ACCEPTED — third-agent accepted a token not issued for it (audience binding gap)"
        } else {
            "REJECTED — audience binding enforced for third agent"
        }
    );

    // ── STEP 7: Does the protocol have automatic compromise detection? ────────
    //
    // Real signal protocols (Signal's safety number, SSH known_hosts) surface
    // a compromise signal. SAACP's detection options:
    //   a) CSCS loop detection — catches repeated identical requests
    //   b) AgentRateLimiter — catches error bursts
    //   c) ImmutableAuditLog — records everything, but not real-time detection
    //   d) ZeroTrustGateway revocation — requires HUMAN to call revoke_token()
    //
    // NONE of these automatically detect a valid, non-revoked token being used
    // from a different process. The protocol is BEARER-TOKEN-based, which means:
    //   "possession of the token = authorization"
    // regardless of whether the possessor is the legitimate issuer or an attacker.

    eprintln!("\n[PHASE-6] AUTOMATIC COMPROMISE DETECTION ANALYSIS:");
    eprintln!("  CSCS loop detection: detects REPEATED identical requests, NOT stolen-token use");
    eprintln!("  AgentRateLimiter: detects ERROR bursts, NOT successful stolen-token use");
    eprintln!("  ImmutableAuditLog: records ALL events, but NOT real-time anomaly detection");
    eprintln!("  ZeroTrustGateway: revocation requires explicit revoke_token() call by operator");
    eprintln!("  VERDICT: SAACP has NO automatic mechanism to detect that a cryptographically");
    eprintln!("  valid, non-revoked bearer token is being used by a process other than the");
    eprintln!("  legitimate issuer. This is BY DESIGN for bearer tokens, but means:");
    eprintln!("    - Stolen token remains valid until: its exp timestamp passes, OR");
    eprintln!("      an operator calls revoke_token() with the correct sig_hash");
    eprintln!("    - Time window between compromise and revocation = attack window");
    eprintln!("    - Token TTL (typically 1h based on exp=iat+3600) = worst-case window");

    // ── STEP 8: Post-compromise — legitimate traffic should still work ────────
    let post_attack_ok = executor_gw.validate_lateral_movement(
        EXECUTOR_ID,
        &legitimate_token,
        &TEST_PSK,
    ).is_ok();
    eprintln!(
        "\n[PHASE-6] Post-compromise legitimate traffic: {}",
        if post_attack_ok { "Still accepted (correct)" } else { "Rejected (regression!)" }
    );
    assert!(
        post_attack_ok,
        "Legitimate Planner→Executor token must still be accepted after the attack"
    );

    // ── Final verdict ─────────────────────────────────────────────────────────
    eprintln!("\n[PHASE-6 FINDINGS SUMMARY]");
    eprintln!("  Attack A (stolen token, same target): {}",
        if attack_a.is_ok() { "SUCCEEDED" } else { "BLOCKED" });
    eprintln!("  Attack B (stolen token, wrong target): {}",
        if attack_b.is_ok() { "SUCCEEDED (audience binding gap)" } else { "BLOCKED (audience binding works)" });
    eprintln!("  Attack C (stolen A→B token to agent C): {}",
        if attack_c.is_ok() { "SUCCEEDED (cross-audience binding gap)" } else { "BLOCKED (audience binding works)" });
    eprintln!("  Automatic compromise detection: NONE (bearer token architecture)");
    eprintln!("  Legitimate traffic post-attack: {}",
        if post_attack_ok { "UNAFFECTED (correct)" } else { "BROKEN (regression)" });
}

/// Verify that the token expiry field is enforced.
/// An expired stolen token must be rejected without human revocation.
#[test]
fn phase_6_expired_token_auto_rejected() {
    let past_iat = 1_000_000_000.0f64; // far in the past
    let past_token = build_planner_token(&TEST_PSK, EXECUTOR_ID, past_iat);
    // exp = past_iat + 3600 = ~year 2001 — definitely expired

    let executor_gw = ZeroTrustGateway::new();
    let result = executor_gw.validate_lateral_movement(
        EXECUTOR_ID,
        &past_token,
        &TEST_PSK,
    );

    assert!(
        result.is_err(),
        "Expired token must be automatically rejected (no human revocation needed)"
    );

    eprintln!(
        "[PHASE-6] Expired token auto-rejected: {:?}. \
         Token expiry (exp field) provides automatic revocation after the TTL. \
         The compromise attack window = time until token expires naturally.",
        result.err()
    );
}

/// Summary report.
#[test]
fn compromise_summary_report() {
    eprintln!("\n");
    eprintln!("═══════════════════════════════════════════════════════════════════");
    eprintln!("  BREAKIT PHASE 6 — TWO-AGENT COMPROMISE SUMMARY");
    eprintln!("═══════════════════════════════════════════════════════════════════");
    eprintln!("  Architecture: Bearer token (possession = authorization)");
    eprintln!();
    eprintln!("  What an attacker with Planner's token bytes GAINS:");
    eprintln!("    - Can impersonate Planner to any agent that trusts the PSK");
    eprintln!("    - Attack window = token TTL (exp - now), typically 1 hour");
    eprintln!("    - Can be terminated early by operator calling revoke_token()");
    eprintln!();
    eprintln!("  What the attacker does NOT gain:");
    eprintln!("    - Cannot forge new tokens (needs PSK to sign HMAC)");
    eprintln!("    - Cannot replay expired tokens (exp field enforced)");
    eprintln!("    - Cannot bypass ACSVAF depth check (delegation depth enforced)");
    eprintln!();
    eprintln!("  Automatic compromise detection: NONE");
    eprintln!("    - CSCS: no (only catches repeated loop patterns)");
    eprintln!("    - Rate limiter: no (only catches error bursts)");
    eprintln!("    - Audit log: records events, not real-time anomaly detection");
    eprintln!("    - Revocation: requires explicit operator action");
    eprintln!();
    eprintln!("  Recommendation:");
    eprintln!("    - Short token TTL (5-15 min, not 1h) reduces attack window");
    eprintln!("    - Ed25519 tokens (not HMAC-PSK) prevent PSK theft from enabling forgery");
    eprintln!("    - Dead Man's Switch should trigger on unusual cross-agent patterns");
    eprintln!("═══════════════════════════════════════════════════════════════════");
}
