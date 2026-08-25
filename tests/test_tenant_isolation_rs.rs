//! test_tenant_isolation_rs.rs — Phase 4 de-globalization proof (kimiplan #1).
//!
//! Two properties, both exercised end-to-end with real AES-256-GCM wire
//! packets driven through `intercept_packet_full_with_ctx` (the same entry
//! point the daemon calls):
//!
//! 1. **`SaacpContext::new()` is hermetic** — two contexts in one process
//!    (the multi-tenant shape) share NOTHING: trust penalties, stream
//!    sessions, audit-chain entries, and packet telemetry counters stay in
//!    the context that produced them, and the process-wide legacy globals'
//!    packet counters do not move at all.
//!
//! 2. **`SaacpContext::shared_default()` is the globals** — every field of
//!    the shared default context is pointer-identical to the instance the
//!    corresponding legacy `::global()`/`global_arc()` accessor returns, so
//!    code still on the globals and code on the default context observe the
//!    exact same state (byte-identical behavior for existing deployments).
//!
//! Diagnostic-only telemetry (gate latencies via `timed_gate!`, gate
//! rejection counters + the security alert feed via `report_gate_rejection`)
//! deliberately remains process-wide — those are performance/ops signals,
//! not per-tenant authorization state; see `src/context.rs`'s scope note.
//! Accordingly the globals assertion below covers the pipeline-level packet
//! counters (`packets_accepted`/`packets_rejected`) only.

use std::sync::Arc;

use saacp::framing::MEASCFrame as StructuralFrame;
use saacp::gateway::AgentRateLimiter;
use saacp::telemetry::{global_telemetry, global_telemetry_arc, SecurityAlertFeed};
use saacp::trust_decay::TrustDecayEngine;
use saacp::{
    ImmutableAuditLog, RulePackStore, SAACPBytecodes, SAACPProtocolHandler, SaacpContext,
    StreamRegistry, ZeroTrustGateway,
};

/// Shared 32-byte HMAC/AES secret for this file's tests — both the Gate 0
/// AES-256-GCM key material (via `encode_encrypted`) and the capability
/// token's HMAC issuer key (mirrors `test_crit2_stream_gate_bypass_rs.rs`).
const SECRET: [u8; 32] = [0x4Au8; 32];

fn build_frame(
    payload: &[u8],
    status_code: u8,
    action_class: u8,
    session_id: [u8; 16],
    psn: u64,
) -> Vec<u8> {
    let frame = StructuralFrame {
        schema_id: 1,
        status_code,
        flags: 0,
        action_class,
        payload_length: 0, // auto-corrected by encode_encrypted
        session_id,
        epoch_id: 0,
        psn,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    frame
        .encode_encrypted(payload, &SECRET)
        .expect("encode_encrypted must succeed")
}

fn issue_token(source_agent: &str, target_agent: &str, max_action_class: u8) -> String {
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        &SECRET,
        source_agent,
        &[target_agent],
        &[],
        3600,
        None,
        max_action_class,
        None,
    );
    String::from_utf8(token).expect("token bytes must be valid utf8 (base64)")
}

/// A hermetic context whose audit log writes to a unique temp file — never
/// the process-global `SAACP_AUDIT_LOG` path, so WAL bytes from the two
/// tenants can never interleave in one file.
fn hermetic_ctx(tag: &str) -> SaacpContext {
    let log_path = std::env::temp_dir().join(format!(
        "saacp_tenant_iso_{}_{}.log",
        std::process::id(),
        tag
    ));
    let sentinel = format!("{}.sentinel", log_path.to_str().unwrap());
    let audit = ImmutableAuditLog::with_paths(log_path.to_str().unwrap(), &sentinel);
    SaacpContext::new().with_audit(Arc::new(audit))
}

// ═══════════════════════════════════════════════════════════════════════════
// Property 2 — shared_default IS the legacy globals (zero behavior change)
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn shared_default_aliases_the_legacy_globals() {
    let ctx = SaacpContext::shared_default();
    assert!(
        Arc::ptr_eq(&ctx.trust, TrustDecayEngine::global_arc()),
        "shared_default().trust must BE TrustDecayEngine::global()"
    );
    assert!(
        Arc::ptr_eq(&ctx.telemetry, &global_telemetry_arc()),
        "shared_default().telemetry must BE global_telemetry()"
    );
    assert!(
        Arc::ptr_eq(&ctx.alerts, SecurityAlertFeed::global_arc()),
        "shared_default().alerts must BE SecurityAlertFeed::global()"
    );
    assert!(
        Arc::ptr_eq(&ctx.rulepacks, RulePackStore::global_arc()),
        "shared_default().rulepacks must BE RulePackStore::global()"
    );
    assert!(
        Arc::ptr_eq(&ctx.streams, StreamRegistry::global_arc()),
        "shared_default().streams must BE StreamRegistry::global()"
    );
    assert!(
        Arc::ptr_eq(&ctx.audit, ImmutableAuditLog::global_arc()),
        "shared_default().audit must BE ImmutableAuditLog::global()"
    );

    // And the default context is a stable singleton for the whole process.
    assert!(Arc::ptr_eq(
        SaacpContext::shared_default_arc(),
        SaacpContext::shared_default_arc()
    ));
}

// ═══════════════════════════════════════════════════════════════════════════
// Property 1 — two hermetic contexts share nothing
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn two_tenants_isolate_trust_streams_audit_and_telemetry() {
    let ctx_a = Arc::new(hermetic_ctx("a"));
    let ctx_b = Arc::new(hermetic_ctx("b"));

    // Fresh, per-test gateway + rate limiter — injected explicitly, so this
    // test never touches the process-global limiter either.
    let gw = ZeroTrustGateway::new();
    let rl = AgentRateLimiter::new();

    // Baseline global packet counters — ctx-scoped traffic must not move them.
    let g_before = global_telemetry().snapshot();
    let g_acc_before = g_before.get("packets_accepted").copied().unwrap_or(0);
    let g_rej_before = g_before.get("packets_rejected").copied().unwrap_or(0);

    // ── Tenant A: one valid STREAM_START ──────────────────────────────────
    let session_a = [0xA1u8; 16];
    let stream_key_a = hex_encode(session_a);
    let token_a = issue_token("iso-src-a", "iso-dst-a", 0);
    let start_payload_a = serde_json::json!({
        "_capability_token": token_a,
        "task": "tenant A benign read-only stream",
        "priority": "normal",
    });
    let start_a = build_frame(
        &serde_json::to_vec(&start_payload_a).unwrap(),
        SAACPBytecodes::StreamStart as u8,
        0,
        session_a,
        1,
    );
    let res_a = SAACPProtocolHandler::intercept_packet_full_with_ctx(
        &ctx_a,
        &start_a,
        &SECRET,
        "iso-dst-a",
        false,
        Some(&gw),
        Some(&rl),
        None,
        None,
        None,
    );
    assert!(
        res_a.is_ok(),
        "tenant A STREAM_START must be accepted: {:?}",
        res_a.err()
    );

    // Streams: registered in A, invisible to B.
    assert!(
        ctx_a.streams.get_stream_info(&stream_key_a).is_some(),
        "tenant A's stream must exist in ctx_a's registry"
    );
    assert!(
        ctx_b.streams.get_stream_info(&stream_key_a).is_none(),
        "tenant A's stream must NOT leak into ctx_b's registry"
    );

    // Telemetry: accepted counter moved in A only.
    let snap_a = ctx_a.telemetry.snapshot();
    assert!(
        snap_a.get("packets_accepted").copied().unwrap_or(0) >= 1,
        "ctx_a telemetry must count the accepted packet"
    );
    assert_eq!(
        ctx_b
            .telemetry
            .snapshot()
            .get("packets_accepted")
            .copied()
            .unwrap_or(0),
        0,
        "ctx_b telemetry must not see tenant A's accepted packet"
    );

    // Audit: Gate 6.0 checkpoint landed on A's chain only.
    assert!(
        ctx_a.audit.event_count() >= 1,
        "ctx_a's audit chain must hold the STREAM_START checkpoint"
    );
    assert_eq!(
        ctx_b.audit.event_count(),
        0,
        "ctx_b's audit chain must stay empty"
    );

    // ── Tenant A: one garbage packet → rejected + trust penalized in A only ──
    let garbage = vec![0x33u8; 96]; // fails Gate 0 integrity
    let res_bad = SAACPProtocolHandler::intercept_packet_full_with_ctx(
        &ctx_a,
        &garbage,
        &SECRET,
        "iso-dst-a",
        false,
        Some(&gw),
        Some(&rl),
        None,
        None,
        None,
    );
    assert!(res_bad.is_err(), "garbage packet must be rejected");

    assert!(
        ctx_a.trust.tracked_count() >= 1,
        "ctx_a's trust engine must have tracked the penalized trust key"
    );
    assert_eq!(
        ctx_b.trust.tracked_count(),
        0,
        "ctx_b's trust engine must be untouched by tenant A's penalty"
    );
    let snap_a2 = ctx_a.telemetry.snapshot();
    assert!(
        snap_a2.get("packets_rejected").copied().unwrap_or(0) >= 1,
        "ctx_a telemetry must count the rejected packet"
    );
    assert_eq!(
        ctx_b
            .telemetry
            .snapshot()
            .get("packets_rejected")
            .copied()
            .unwrap_or(0),
        0,
        "ctx_b telemetry must not see tenant A's rejection"
    );

    // ── Tenant B: its own valid STREAM_START — independent universe ───────
    let session_b = [0xB2u8; 16];
    let stream_key_b = hex_encode(session_b);
    let token_b = issue_token("iso-src-b", "iso-dst-b", 0);
    let start_payload_b = serde_json::json!({
        "_capability_token": token_b,
        "task": "tenant B benign read-only stream",
        "priority": "normal",
    });
    let start_b = build_frame(
        &serde_json::to_vec(&start_payload_b).unwrap(),
        SAACPBytecodes::StreamStart as u8,
        0,
        session_b,
        1,
    );
    let res_b = SAACPProtocolHandler::intercept_packet_full_with_ctx(
        &ctx_b,
        &start_b,
        &SECRET,
        "iso-dst-b",
        false,
        Some(&gw),
        Some(&rl),
        None,
        None,
        None,
    );
    assert!(
        res_b.is_ok(),
        "tenant B STREAM_START must be accepted: {:?}",
        res_b.err()
    );

    // Cross-checks: B's stream is invisible to A and vice versa.
    assert!(ctx_b.streams.get_stream_info(&stream_key_b).is_some());
    assert!(ctx_a.streams.get_stream_info(&stream_key_b).is_none());
    assert!(
        ctx_b.audit.event_count() >= 1,
        "ctx_b's audit chain must hold its own checkpoint"
    );
    assert_eq!(
        ctx_a
            .telemetry
            .snapshot()
            .get("packets_accepted")
            .copied()
            .unwrap_or(0),
        snap_a.get("packets_accepted").copied().unwrap_or(0),
        "tenant B's accepted packet must not bump tenant A's counters"
    );

    // ── Globals: ctx-scoped traffic never moved the process-wide counters ──
    let g_after = global_telemetry().snapshot();
    assert_eq!(
        g_after.get("packets_accepted").copied().unwrap_or(0),
        g_acc_before,
        "ctx-scoped packets must not count toward GLOBAL_TELEMETRY packets_accepted"
    );
    assert_eq!(
        g_after.get("packets_rejected").copied().unwrap_or(0),
        g_rej_before,
        "ctx-scoped packets must not count toward GLOBAL_TELEMETRY packets_rejected"
    );

    // Cleanup: close tenant streams so registries drop the sessions.
    ctx_a.streams.abort_stream(&stream_key_a);
    ctx_b.streams.abort_stream(&stream_key_b);
}

/// hex-encode without pulling the hex crate into the test's extern list —
/// the pipeline registers streams under `hex::encode(session_id)`.
fn hex_encode(bytes: [u8; 16]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
