//! test_daemon_shutdown_rs.rs — proves the M-15/R-2 graceful-shutdown fix on
//! `SAACPNetworkDaemon`.
//!
//! Before this fix, `start()` ran an unconditional `loop { listener.accept().await }`
//! with no way to stop it short of killing the process. `start_with_shutdown` adds a
//! `CancellationToken`-driven exit: stop accepting new connections, drain in-flight
//! ones (bounded by `SHUTDOWN_DRAIN_TIMEOUT_SECS`), flush the audit-log WAL, then
//! return. This test drives the whole sequence end to end over a real loopback
//! connection and asserts it completes well within the drain bound.

use std::time::Duration;

use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use saacp::SAACPNetworkDaemon;

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Cancelling the shutdown token before any connection is ever made must let
/// `start_with_shutdown` return almost immediately (no in-flight work to drain).
#[tokio::test]
async fn start_with_shutdown_returns_promptly_with_no_connections() {
    let port = free_port().await;
    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, None);
    let shutdown = CancellationToken::new();

    let shutdown_clone = shutdown.clone();
    let handle = tokio::spawn(async move { daemon.start_with_shutdown(shutdown_clone).await });

    // Give the daemon a moment to bind before cancelling.
    tokio::time::sleep(Duration::from_millis(150)).await;
    shutdown.cancel();

    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("start_with_shutdown did not return within 10s")
        .expect("daemon task panicked");
    assert!(result.is_ok(), "start_with_shutdown returned an error: {:?}", result);
}

/// A real client connection is open when shutdown is signalled — `start_with_shutdown`
/// must still return (the connection either finishes naturally or gets drained/aborted
/// within `SHUTDOWN_DRAIN_TIMEOUT_SECS`), proving the accept loop actually stops and the
/// drain step doesn't hang forever.
#[tokio::test]
async fn start_with_shutdown_drains_in_flight_connection() {
    let port = free_port().await;
    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, None);
    let shutdown = CancellationToken::new();

    let shutdown_clone = shutdown.clone();
    let handle = tokio::spawn(async move { daemon.start_with_shutdown(shutdown_clone).await });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Open a real TCP connection and leave it idle (never completing the ECDH
    // handshake) — this is exactly the "in-flight connection at shutdown time" case
    // the drain step exists for.
    let _client = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("client connect failed");

    shutdown.cancel();

    // Bounded well within SHUTDOWN_DRAIN_TIMEOUT_SECS (30s) + WAL flush timeout (5s):
    // the connection never sends a valid header, so `handle_client`'s 2s header-read
    // timeout ends it long before the drain bound would ever need to hard-abort it.
    let result = tokio::time::timeout(Duration::from_secs(20), handle)
        .await
        .expect("start_with_shutdown did not return within 20s")
        .expect("daemon task panicked");
    assert!(result.is_ok(), "start_with_shutdown returned an error: {:?}", result);
}

/// `start()` (the zero-arg wrapper) must still behave exactly as before for any caller
/// that never touches shutdown at all — proves the M-15 change didn't alter the
/// "runs forever" default behavior for existing callers, only added an opt-in exit path.
#[tokio::test]
async fn start_without_shutdown_keeps_accepting_connections() {
    let port = free_port().await;
    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, None);
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let stream = TcpStream::connect(("127.0.0.1", port)).await;
    assert!(stream.is_ok(), "daemon should still be accepting connections");
}
