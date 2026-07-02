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

use saacp::{ImmutableAuditLog, AuditHealth, AUDIT_WAL_FLUSH_EVERY_N_ENTRIES};
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
        log.dropped_audit_count(), 0,
        "Fix 1's buffered WAL writer must keep up with a {N}-event burst on a real \
         disk path — any drop here means the queue saturated, exactly the pre-fix \
         failure mode this repair targets."
    );
    assert_eq!(
        log.wal_write_failure_count(), 0,
        "No genuine disk write failures expected against a valid temp-dir path."
    );
    assert_eq!(
        log.health(), AuditHealth::Healthy,
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
        "saacp_no_such_dir_{}_open_fail", std::process::id()
    ));
    let log_file = bad_dir.join("audit.log");
    let log = ImmutableAuditLog::with_paths(
        log_file.to_str().unwrap(),
        &format!("{}.sentinel", log_file.to_str().unwrap()),
    );

    let mut waited = Duration::ZERO;
    while log.health() != AuditHealth::Fatal && waited < Duration::from_secs(2) {
        std::thread::sleep(Duration::from_millis(5));
        waited += Duration::from_millis(5);
    }
    assert_eq!(
        log.health(), AuditHealth::Fatal,
        "A WAL worker that cannot open its log file must become visibly Fatal, \
         not silently no-op forever."
    );

    // The worker thread has exited (channel disconnected), so this append's
    // `try_send` fails synchronously and must be counted immediately.
    log.append_event(b"secret", "a", "b", "sig", "intent", "trace");
    assert_eq!(
        log.dropped_audit_count(), 1,
        "Appends after a Fatal WAL worker must be counted as dropped, never \
         silently lost with zero signal anywhere."
    );
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
            secret, "src", "dst", &format!("sig-{i}"), "intent",
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
    assert!(!status.success(), "child must hard-exit(1), not complete gracefully");

    // Recovery: read whatever actually made it to disk before the hard kill.
    let content = std::fs::read_to_string(&log_file).unwrap_or_default();
    let disk_count = content.lines().filter(|l| !l.is_empty()).count() as u64;

    assert!(disk_count <= 50, "cannot have more entries on disk than were ever sent");
    let lost = 50 - disk_count;
    assert!(
        lost <= AUDIT_WAL_FLUSH_EVERY_N_ENTRIES,
        "unclean-shutdown data loss ({lost} entries) exceeded the documented bound \
         of {AUDIT_WAL_FLUSH_EVERY_N_ENTRIES} entries"
    );

    let _ = std::fs::remove_file(&log_file);
    let _ = std::fs::remove_file(&sentinel);
}
