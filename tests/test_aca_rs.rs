//! test_aca_rs.rs — Phase 6 item 6 (Part 8.4, Agent Capability Attestation):
//! proves `aca::enforce_attestation` is actually wired into the REAL gate
//! pipeline (`handler::intercept_packet_full`, immediately after Gate 2.5),
//! not just exercised directly in `aca.rs`'s own unit tests — driving a
//! genuinely AES-256-GCM-encrypted `framing::MEASCFrame` packet carrying a
//! REAL HMAC-PSK capability token through a REAL `ZeroTrustGateway`, mirroring
//! `test_trust_reward_wiring_rs.rs`'s "prove it through the real entry point"
//! convention (same frame builder, same rationale for using `framing::
//! MEASCFrame` over `measc::MEASCFrame` — see that file's own doc comment) —
//! extended here with a real, gateway-validated capability token (that file's
//! `gateway: None` structural-mode path caps `max_action_class` at 0, which
//! can't reach ACA's IRREVERSIBLE-class enforcement at all).
//!
//! `#[serial]` throughout: `aca::set_required` is a process-wide static (see
//! `aca.rs`'s own doc comment) — matching that module's unit tests' own
//! `#[serial]` convention (`serial_test`, already a dev-dependency, used the
//! same way by `pecf.rs`/`telemetry.rs`).

use serial_test::serial;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use saacp::aca::{self, AttestationAuthority, AttestationRegistry, SafetyLevel};
use saacp::framing::MEASCFrame as StructuralFrame;
use saacp::gateway::ZeroTrustGateway;
use saacp::{SAACPBytecodes, SAACPProtocolHandler};

fn now_u64() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// Hand-rolled HMAC-PSK capability token wire builder — matches
/// `test_blackhat_agent_hijack_rs.rs::forge_token`'s exact proven wire format
/// (4-byte BE json_len + json_bytes + 32-byte HMAC, base64'd), the format
/// `gateway::ZeroTrustGateway::validate_lateral_movement` actually parses.
fn build_token(secret: &[u8], issuer: &str, target: &str, max_action_class: u8) -> String {
    let exp = now_u64() + 3600;
    let payload = serde_json::json!({
        "iss": issuer,
        "exp": exp,
        "allow": [target],
        "forbid": [],
        "max_action_class": max_action_class,
    });
    let json_bytes = serde_json::to_vec(&payload).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(&json_bytes);
    let sig = mac.finalize().into_bytes().to_vec();

    let json_len = u32::try_from(json_bytes.len()).unwrap();
    let mut wire = Vec::with_capacity(4 + json_bytes.len() + sig.len());
    wire.extend_from_slice(&json_len.to_be_bytes());
    wire.extend_from_slice(&json_bytes);
    wire.extend_from_slice(&sig);
    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &wire)
}

/// See `test_trust_reward_wiring_rs.rs::build_frame` for why `framing::
/// MEASCFrame` (not `measc::MEASCFrame`) is used here.
fn build_frame(session: [u8; 16], secret: &[u8], payload: &[u8], action_class: u8) -> Vec<u8> {
    let frame = StructuralFrame {
        schema_id: 1, // "Task": requires task + priority
        status_code: 0x10,
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

/// Drive one IRREVERSIBLE-class (`action_class = 0x02`), fully-authorized
/// (`max_action_class = 0x02` in the token) packet through the real pipeline.
/// `session_byte` must be distinct per call within this file: `AEGFGovernor`'s
/// DEG is a process-wide singleton keyed by a hash of `(session_uuid,
/// sequence_id)` — reusing the same session/sequence pair across independent
/// test calls collides with an already-registered DEG node from a prior call.
fn drive_irreversible_packet(secret: &[u8], gw: &ZeroTrustGateway, issuer: &str, target: &str, session_byte: u8) -> Result<saacp::ParsedPacket, saacp::SAACPHardDrop> {
    let session = [session_byte; 16];
    let token_b64 = build_token(secret, issuer, target, 0x02);
    let clean_payload = serde_json::json!({
        "task": "archive the quarterly ledger",
        "priority": 1,
        "_capability_token": token_b64,
    }).to_string();
    let frame = build_frame(session, secret, clean_payload.as_bytes(), 0x02);

    SAACPProtocolHandler::intercept_packet_full(
        &frame, secret, target, false, Some(gw), None, None, None, None,
    )
}

#[test]
#[serial]
fn aca_disabled_by_default_irreversible_packet_passes_without_attestation() {
    aca::set_required(false);
    let secret = [0xACu8; 32];
    let gw = ZeroTrustGateway::new();
    gw.register_issuer_key("aca-e2e-orchestrator-1", &secret).unwrap();

    let result = drive_irreversible_packet(&secret, &gw, "aca-e2e-orchestrator-1", "aca-e2e-worker-1", 0xA1);
    assert!(result.is_ok(), "with ACA not required, an IRREVERSIBLE packet from a never-attested \
        agent must still pass the real pipeline: {result:?}");
}

#[test]
#[serial]
fn aca_enabled_rejects_irreversible_packet_from_unattested_agent_through_real_pipeline() {
    AttestationRegistry::global().trust_operator(AttestationAuthority::generate().verifying_key());
    aca::set_required(true);

    let secret = [0xACu8; 32];
    let gw = ZeroTrustGateway::new();
    gw.register_issuer_key("aca-e2e-orchestrator-2", &secret).unwrap();

    let result = drive_irreversible_packet(&secret, &gw, "aca-e2e-orchestrator-2", "aca-e2e-worker-2", 0xA2);

    aca::set_required(false);

    let err = result.expect_err("an IRREVERSIBLE packet from a never-attested agent must be \
        rejected by the real pipeline once ACA is required");
    assert_eq!(err.bytecode, SAACPBytecodes::InsufficientAttestation);
}

#[test]
#[serial]
fn aca_enabled_allows_irreversible_packet_from_sufficiently_attested_agent_through_real_pipeline() {
    let authority = AttestationAuthority::generate();
    AttestationRegistry::global().trust_operator(authority.verifying_key());
    AttestationRegistry::global().install_claim(
        authority.issue("aca-e2e-orchestrator-3", SafetyLevel::AlignedModel, "docker: no-network", 3600)
    ).unwrap();
    aca::set_required(true);

    let secret = [0xACu8; 32];
    let gw = ZeroTrustGateway::new();
    gw.register_issuer_key("aca-e2e-orchestrator-3", &secret).unwrap();

    let result = drive_irreversible_packet(&secret, &gw, "aca-e2e-orchestrator-3", "aca-e2e-worker-3", 0xA3);

    aca::set_required(false);

    assert!(result.is_ok(), "a sufficiently (AlignedModel-)attested agent's IRREVERSIBLE packet \
        must pass the real pipeline once ACA is required: {result:?}");
}
