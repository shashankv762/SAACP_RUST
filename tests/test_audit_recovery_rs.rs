// Same security invariant as the library crate: safe Rust only, enforced.
#![forbid(unsafe_code)]

//! M-A remediation regression (production audit G1/R1): audit-chain recovery
//! wiring in `SAACPNetworkDaemon::start_with_shutdown`.
//!
//! This file is deliberately a SINGLE sequential test function: it drives the
//! process-global `ImmutableAuditLog` via `SAACP_AUDIT_LOG`, and the env var
//! is read once at the global's first access in this test process, so
//! parallel tests could race it. One process + one function = deterministic.

use std::path::PathBuf;
use std::time::Duration;

use saacp::daemon::SAACPNetworkDaemon;
use saacp::security::ImmutableAuditLog;
use tokio_util::sync::CancellationToken;

const SECRET: &[u8] = b"audit-recovery-regression-secret-0123456";

fn temp_dir() -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "saacp_audit_recovery_{}_{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::create_dir_all(&d);
    d
}

/// The daemon must adopt a valid persisted chain at startup, refuse to start
/// (fail closed) when the on-disk chain no longer verifies, and leave
/// recovery-off behavior completely untouched.
#[tokio::test]
async fn audit_chain_recovery_adopt_refuse_and_off_paths() {
    // ---- Workspace + process-global log path (read at first global access).
    let dir = temp_dir();
    let log_path = dir.join("chain.log");
    let log_str = log_path.to_string_lossy().to_string();
    std::env::set_var("SAACP_AUDIT_LOG", &log_str);

    // Force the global to materialize with the temp path, then write a real,
    // verifiable chain with the SAME secret the daemon below will use.
    let global = ImmutableAuditLog::global();
    global.append_event(
        SECRET,
        "agent-a",
        "agent-b",
        "toksig",
        "recovery fixture intent",
        "00-trace-00",
    );
    global.append_event(
        SECRET,
        "agent-b",
        "agent-c",
        "toksig2",
        "recovery fixture intent 2",
        "00-trace-01",
    );
    assert!(
        global.flush(Duration::from_secs(5)),
        "WAL flush must persist the fixture chain"
    );
    assert!(log_path.exists(), "fixture chain must be on disk");
    assert!(
        global.verify_chain_disk(SECRET),
        "fixture chain must verify before the daemon-level assertions"
    );

    // ---- Path 1: recovery enabled + valid chain => start succeeds and adopts.
    // (The in-memory global_seq was already advanced by our appends; the
    // material assertion is that start does not refuse a verifiable chain.)
    let token_ok = CancellationToken::new();
    let daemon_ok = SAACPNetworkDaemon::new("127.0.0.1", 0, Some(SECRET.to_vec()))
        .with_audit_chain_recovery(true);
    let handle_ok = {
        let t = token_ok.clone();
        tokio::spawn(async move { daemon_ok.start_with_shutdown(t).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The accept loop runs until shutdown; a recovery failure would have
    // completed this handle with an Err by now.
    assert!(
        !handle_ok.is_finished(),
        "daemon with a verifiable chain must keep running (recovery adopted, not refused)"
    );
    token_ok.cancel();
    let result_ok = handle_ok.await.expect("start task must not panic");
    assert!(
        result_ok.is_ok(),
        "clean shutdown after adoption: {result_ok:?}"
    );

    // ---- Path 2: recovery enabled + corrupt tail => refuse (fail closed).
    // A torn/garbage final line is untrusted input (H-6): recovery must turn
    // it into a startup refusal, not a silent genesis reset.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&log_path)
            .expect("open fixture log for corruption");
        f.write_all(b"{ this line is not json\n")
            .expect("append corrupt tail");
    }
    let daemon_refuse = SAACPNetworkDaemon::new("127.0.0.1", 0, Some(SECRET.to_vec()))
        .with_audit_chain_recovery(true);
    let err = daemon_refuse
        .start_with_shutdown(CancellationToken::new())
        .await
        .expect_err("unverifiable chain must refuse startup");
    assert_eq!(
        err.kind(),
        std::io::ErrorKind::InvalidData,
        "refusal must surface as InvalidData (got: {err})"
    );
    assert!(
        err.to_string().contains("audit-chain recovery failed"),
        "refusal must be actionable (got: {err})"
    );

    // ---- Path 3: recovery explicitly OFF via the builder => the same corrupt
    // file must not block startup. (v0.2.2+ note: `Some(secret)` now auto-enables
    // recovery via M1, so "default" no longer means "off" — the builder override
    // is the only in-code way to pin the off behavior this assertion originally
    // guarded.)
    let daemon_off = SAACPNetworkDaemon::new("127.0.0.1", 0, Some(SECRET.to_vec()))
        .with_audit_chain_recovery(false);
    let token_off = CancellationToken::new();
    let handle_off = {
        let t = token_off.clone();
        tokio::spawn(async move { daemon_off.start_with_shutdown(t).await })
    };
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(
        !handle_off.is_finished(),
        "recovery-off daemon must start even with a corrupt chain on disk (builder override)"
    );
    token_off.cancel();
    let result_off = handle_off.await.expect("start task must not panic");
    assert!(
        result_off.is_ok(),
        "clean shutdown for recovery-off: {result_off:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
