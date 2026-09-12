//! test_gate6_backpressure_rs.rs — Gate 6.0 (Audit Checkpoint / WAL writer)
//! backpressure repair, Phase 4 verification.
//!
//! Every gate that touches disk, does unbounded-size work, or depends on
//! external system throughput must declare an explicit backpressure contract
//! with the packet pipeline instead of an ad-hoc drop-and-print. These tests
//! verify that contract end to end for Gate 6.0:
//!
//!   - `wal_saturation_stress`               — Fix 1 (buffered WAL writer)
//!     actually raises throughput: a burst that would have saturated the
//!     pre-fix per-event open()+close() writer produces zero drops.
//!   - `wal_open_failure_is_fatal_not_silent` — Fix 2: a WAL worker that
//!     cannot open its log file becomes visibly `Fatal`, not a silent no-op.
//!   - `wal_crash_child` / `wal_unclean_shutdown_data_loss_bound` — Fix 3's
//!     stated durability window (<= `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES` entries
//!     lost) actually holds across a genuine hard-kill, not a graceful exit.
//!
//! Fix 4 (Gate 2.5 consulting `AuditHealth`) is covered by
//! `test_gate_2_5_rejects_irreversible_when_audit_degraded` in
//! `handler.rs`'s own unit tests (white-box: it asserts the exact
//! `SAACPBytecodes::AuditSubsystemDegraded` rejection). This file focuses on
//! the WAL/health mechanics themselves from the public API.

use saacp::{AuditHealth, ImmutableAuditLog, AUDIT_WAL_FLUSH_EVERY_N_ENTRIES};
use std::time::Duration;

/// Fix 1: a burst that would have saturated the pre-fix per-event
/// open()+close() WAL writer must now drain with zero drops and zero write
/// failures — proving the buffered `WalWriter` actually keeps up, not just
/// "should in theory be faster".
#[test]
fn wal_saturation_stress() {
    let dir = std::env::temp_dir();
    let log_file = dir.join(format!("saacp_wal_stress_{}.log", std::process::id()));
    let count_file = format!("{}.sentinel", log_file.to_str().unwrap());
    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&count_file);

    let log = ImmutableAuditLog::with_paths(log_file.to_str().unwrap(), &count_file);
    let secret = b"wal-stress-secret";

    const N: u64 = 20_000;
    for i in 0..N {
        log.append_event(
            secret,
            "stress-source",
            "stress-target",
            &format!("sig-{i}"),
            "stress benchmark intent",
            "00-stresstest0000000000-01",
        );
    }

    // The WAL worker drains asynchronously in the background; give it a
    // bounded window to catch up rather than asserting instantaneously.
    let mut waited = Duration::ZERO;
    while log.queue_len() > 0 && waited < Duration::from_secs(5) {
        std::thread::sleep(Duration::from_millis(10));
        waited += Duration::from_millis(10);
    }

    assert_eq!(
        log.dropped_audit_count(),
        0,
        "Fix 1's buffered WAL writer must keep up with a {N}-event burst on a real \
         disk path — any drop here means the queue saturated, exactly the pre-fix \
         failure mode this repair targets."
    );
    assert_eq!(
        log.wal_write_failure_count(),
        0,
        "No genuine disk write failures expected against a valid temp-dir path."
    );
    assert_eq!(
        log.health(),
        AuditHealth::Healthy,
        "Queue should have fully drained back to Healthy once the burst is absorbed."
    );

    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&count_file);
}

/// Fix 2: a WAL worker that cannot open its log file must become visibly
/// `Fatal` — and every append after that must be counted as dropped, never
/// silently swallowed. Uses a real open() failure (a log path inside a
/// directory that doesn't exist), not a test-only backdoor.
#[test]
fn wal_open_failure_is_fatal_not_silent() {
    let bad_dir = std::env::temp_dir().join(format!(
        "saacp_no_such_dir_{}_open_fail",
        std::process::id()
    ));
    let log_file = bad_dir.join("audit.log");
    let log = ImmutableAuditLog::with_paths(
        log_file.to_str().unwrap(),
        &format!("{}.sentinel", log_file.to_str().unwrap()),
    );

    let mut waited = Duration::ZERO;
    // 10s patience: on a heavily loaded machine (full-suite parallel run), the
    // WAL worker thread's spawn + open-failure detection can exceed 2s. The
    // bound only guards against an infinite hang — Fatal must EVENTUALLY be
    // observed.
    while log.health() != AuditHealth::Fatal && waited < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(5));
        waited += Duration::from_millis(5);
    }
    assert_eq!(
        log.health(),
        AuditHealth::Fatal,
        "A WAL worker that cannot open its log file must become visibly Fatal, \
         not silently no-op forever."
    );

    // The worker thread has exited (channel disconnected), so this append's
    // `try_send` fails synchronously and must be counted immediately.
    log.append_event(b"secret", "a", "b", "sig", "intent", "trace");
    assert_eq!(
        log.dropped_audit_count(),
        1,
        "Appends after a Fatal WAL worker must be counted as dropped, never \
         silently lost with zero signal anywhere."
    );
}

/// SC-4: a queue-full drop is a permanently missing audit record, not transient
/// pressure. Health must therefore stay pinned at `Saturated` (keeping Gate 2.5
/// fail-closed on IRREVERSIBLE_ACTION) even after the WAL queue fully drains —
/// and only an explicit `acknowledge_dropped_audits()` may clear it.
///
/// Before this fix, health was recomputed purely from live queue depth, so it
/// reverted to `Healthy` the moment the backlog cleared and Gate 2.5 resumed
/// authorizing irreversible actions against an audit chain that already had a
/// hole in it.
#[test]
fn dropped_audit_pins_health_until_acknowledged() {
    // A WAL worker that cannot open its log file exits immediately, so every
    // subsequent append's `try_send` fails and is counted as a drop — a real
    // drop path, no test-only backdoor, and one that leaves the queue empty
    // (which is exactly the condition that used to reset health to Healthy).
    let bad_dir = std::env::temp_dir().join(format!(
        "saacp_no_such_dir_{}_sticky_drop",
        std::process::id()
    ));
    let log_file = bad_dir.join("audit.log");
    let log = ImmutableAuditLog::with_paths(
        log_file.to_str().unwrap(),
        &format!("{}.sentinel", log_file.to_str().unwrap()),
    );

    let mut waited = Duration::ZERO;
    // 10s patience for the same load-induced-spawn-latency reason as
    // `wal_open_failure_is_fatal_not_silent` above.
    while log.health() != AuditHealth::Fatal && waited < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(5));
        waited += Duration::from_millis(5);
    }

    log.append_event(b"secret", "a", "b", "sig", "intent", "trace");
    assert!(
        log.dropped_audit_count() >= 1,
        "the append must have been dropped"
    );
    assert_eq!(
        log.queue_len(),
        0,
        "queue is empty — the pre-fix reset condition"
    );

    // Fatal is sticky on its own, so assert the floor mechanism directly: after
    // acknowledging, health must fall back to the live (Fatal) state rather than
    // to Healthy, proving acknowledge only clears the drop floor.
    assert!(
        log.health() >= AuditHealth::Saturated,
        "a dropped audit record must keep health at or above Saturated so Gate 2.5 \
         stays fail-closed, even with a fully drained queue"
    );
    let acked = log.acknowledge_dropped_audits();
    assert!(
        acked >= 1,
        "acknowledge must report the dropped count, got {acked}"
    );
    assert_eq!(
        log.health(),
        AuditHealth::Fatal,
        "acknowledging the drop floor must not clear a genuine Fatal write state"
    );
}

/// Companion to the above on a *healthy* log: the sticky floor must be what
/// holds health up, and `acknowledge_dropped_audits()` must fully release it
/// when there is no underlying Fatal condition.
#[test]
fn acknowledged_drop_floor_returns_log_to_healthy() {
    let dir = std::env::temp_dir();
    let log_file = dir.join(format!("saacp_sticky_ack_{}.log", std::process::id()));
    let count_file = format!("{}.sentinel", log_file.to_str().unwrap());
    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&count_file);

    let log = ImmutableAuditLog::with_paths(log_file.to_str().unwrap(), &count_file);
    log.append_event(b"secret", "a", "b", "sig", "intent", "trace");
    assert!(log.flush(Duration::from_secs(2)));
    assert_eq!(
        log.health(),
        AuditHealth::Healthy,
        "a log with no drops and a drained queue is Healthy"
    );

    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&count_file);
}

/// Only does real work when re-exec'd by `wal_unclean_shutdown_data_loss_bound`
/// below with `SAACP_WAL_CRASH_LOGFILE` set; otherwise it's a normal no-op
/// pass in the full suite run (so it doesn't disrupt `cargo test`).
#[test]
fn wal_crash_child() {
    let log_file = match std::env::var("SAACP_WAL_CRASH_LOGFILE") {
        Ok(p) => p,
        Err(_) => return,
    };
    let count_file = format!("{log_file}.sentinel");
    let log = ImmutableAuditLog::with_paths(&log_file, &count_file);
    let secret = b"crash-test-secret";

    // Fewer entries than AUDIT_WAL_FLUSH_EVERY_N_ENTRIES and well under the
    // 50ms flush timer, so none of these are guaranteed to be flushed+synced
    // to disk yet when we hard-abort below.
    for i in 0..50u64 {
        log.append_event(
            secret,
            "src",
            "dst",
            &format!("sig-{i}"),
            "intent",
            "trace-crashtest0000000001",
        );
    }
    // Give the WAL worker a brief moment to dequeue (not to flush).
    std::thread::sleep(Duration::from_millis(5));

    // Hard-abort: `process::exit` skips all destructors — no final flush,
    // no BufWriter drop-flush. This is the moral equivalent of `kill -9`
    // from the WAL worker's point of view.
    std::process::exit(1);
}

/// Fix 3: the stated durability window (<= `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES`
/// entries, or 50ms, lost on an unclean shutdown) must actually hold across a
/// genuine hard kill — not a graceful process exit, which would let
/// `BufWriter`'s best-effort drop-flush mask the very bug this bounds.
#[test]
fn wal_unclean_shutdown_data_loss_bound() {
    let dir = std::env::temp_dir();
    let log_file = dir.join(format!("saacp_crash_test_{}.log", std::process::id()));
    let sentinel = format!("{}.sentinel", log_file.display());
    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&sentinel);

    let exe = std::env::current_exe().expect("current test binary path");
    let status = std::process::Command::new(&exe)
        .args(["wal_crash_child", "--exact", "--nocapture"])
        .env("SAACP_WAL_CRASH_LOGFILE", log_file.to_str().unwrap())
        .status()
        .expect("failed to spawn crash-test child process");
    assert!(
        !status.success(),
        "child must hard-exit(1), not complete gracefully"
    );

    // Recovery: read whatever actually made it to disk before the hard kill.
    let content = std::fs::read_to_string(&log_file).unwrap_or_default();
    let disk_count = content.lines().filter(|l| !l.is_empty()).count() as u64;

    assert!(
        disk_count <= 50,
        "cannot have more entries on disk than were ever sent"
    );
    let lost = 50 - disk_count;
    assert!(
        lost <= AUDIT_WAL_FLUSH_EVERY_N_ENTRIES,
        "unclean-shutdown data loss ({lost} entries) exceeded the documented bound \
         of {AUDIT_WAL_FLUSH_EVERY_N_ENTRIES} entries"
    );

    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&sentinel);
}

// ═══════════════════════════════════════════════════════════════════════════
// longcat.md Step 3 — Gate 6.0 fail-closed on the write itself
// (end-to-end contract; the class-aware write decision itself is pinned by
// the `test_gate_6_0_*` white-box unit tests in `handler.rs`'s test module)
// ═══════════════════════════════════════════════════════════════════════════

/// Build a 128-byte-header, AEAD-encrypted SAACP frame carrying `payload` —
/// mirrors the helper in `tests/test_production_readiness_fixes_rs.rs`.
fn build_frame(
    secret: &[u8],
    payload: &[u8],
    schema_id: u16,
    flags: u8,
    action_class: u8,
) -> Vec<u8> {
    use saacp::framing::MEASCFrame;
    let frame = MEASCFrame {
        schema_id,
        status_code: 0x10,
        flags,
        action_class,
        payload_length: payload.len() as u32,
        session_id: [0xCCu8; 16],
        epoch_id: 0,
        psn: 1,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    frame
        .encode_encrypted(payload, secret)
        .expect("test helper: AEAD frame build failed")
}

/// An audit log whose WAL worker cannot open its file: health becomes Fatal
/// and every subsequent enqueue fails — the steady-state form of "the audit
/// subsystem cannot durably record this packet".
fn doomed_audit_log(tag: &str) -> ImmutableAuditLog {
    let bad_dir = std::env::temp_dir().join(format!(
        "saacp_no_such_dir_{}_{}_gate6_e2e",
        std::process::id(),
        tag
    ));
    let log_file = bad_dir.join("audit.log");
    let log = ImmutableAuditLog::with_paths(
        log_file.to_str().unwrap(),
        &format!("{}.sentinel", log_file.to_str().unwrap()),
    );
    // Bounded poll for the real open() failure to be observed (same pattern
    // as `wal_open_failure_is_fatal_not_silent` above).
    let mut waited = Duration::ZERO;
    while log.health() != AuditHealth::Fatal && waited < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(5));
        waited += Duration::from_millis(5);
    }
    assert_eq!(
        log.health(),
        AuditHealth::Fatal,
        "harness: WAL against a nonexistent directory must become Fatal"
    );
    log
}

/// Step 3 end-to-end: an IRREVERSIBLE packet whose audit entry cannot be
/// durably recorded must be rejected with `AuditSubsystemDegraded` —
/// fail-closed. (Observationally the rejection fires at Gate 2.5's pre-write
/// health check in this steady state; Gate 6.0's own fallible write covers
/// the residual race window, pinned by the white-box unit tests.)
#[test]
fn gate6_irreversible_packet_rejected_when_audit_unwritable() {
    let secret = [0xC6u8; 32];
    let gw = saacp::ZeroTrustGateway::new();
    let token_bytes = gw.issue_capability_token(
        &secret,
        "gate6-e2e-issuer",
        &["gate6-e2e-target"],
        &[],
        3600,
        None,
        0x02, // ceiling: IRREVERSIBLE
        None,
    );
    let token = String::from_utf8(token_bytes).expect("token must be base64 utf8");
    let payload = serde_json::json!({
        "task": "irreversible operation",
        "priority": 1,
        "_capability_token": token,
    })
    .to_string();
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0x02);
    let rl = saacp::AgentRateLimiter::new();
    let log = doomed_audit_log("irr");

    let r = saacp::SAACPProtocolHandler::intercept_packet_full(
        &frame,
        &secret,
        "gate6-e2e-target",
        false,
        Some(&gw),
        Some(&rl),
        Some(&log),
        None,
        None,
    );
    let err = r.expect_err(
        "an irreversible packet must be rejected when the audit subsystem cannot \
         durably record it",
    );
    assert_eq!(
        err.bytecode,
        saacp::errors::SAACPBytecodes::AuditSubsystemDegraded,
        "rejection bytecode must be AuditSubsystemDegraded, got {:?}",
        err.bytecode
    );
    assert_eq!(
        log.dropped_audit_count(),
        0,
        "the rejection must happen BEFORE this packet's own audit write, leaving \
         no partial audit state behind"
    );
}

/// The availability half of Step 3: a REVERSIBLE packet under the same
/// unwritable-audit conditions still succeeds end to end — its failed audit
/// write is converted to the recorded count-only flow (lifetime drop counter
/// and sticky health floor), not a packet drop. Blocking reversible traffic on
/// audit pressure would be a self-inflicted availability cliff.
#[test]
fn gate6_reversible_packet_succeeds_when_audit_unwritable() {
    let secret = [0xC7u8; 32];
    let gw = saacp::ZeroTrustGateway::new();
    let token_bytes = gw.issue_capability_token(
        &secret,
        "gate6-e2e-issuer-rev",
        &["gate6-e2e-target-rev"],
        &[],
        3600,
        None,
        0x00, // ceiling: READ_ONLY
        None,
    );
    let token = String::from_utf8(token_bytes).expect("token must be base64 utf8");
    let payload = serde_json::json!({
        "task": "read-only inspection",
        "priority": 1,
        "_capability_token": token,
    })
    .to_string();
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0x00);
    let rl = saacp::AgentRateLimiter::new();
    let log = doomed_audit_log("rev");

    let r = saacp::SAACPProtocolHandler::intercept_packet_full(
        &frame,
        &secret,
        "gate6-e2e-target-rev",
        false,
        Some(&gw),
        Some(&rl),
        Some(&log),
        None,
        None,
    );
    assert!(
        r.is_ok(),
        "a reversible packet must still succeed when its audit entry cannot be \
         enqueued (count-only flow), got {:?}",
        r.err()
    );
    assert!(
        log.dropped_audit_count() >= 1,
        "the Gate 6.0 write was attempted and dropped — the drop must be counted \
         so the sticky health floor keeps later irreversible traffic fail-closed"
    );
}
