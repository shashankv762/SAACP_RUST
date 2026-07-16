//! test_shared_circuit_breaker_rs.rs — proves the R-5 fix (opusplan.md Part 7 / 7.2):
//! a `daemon::SharedCircuitBreakers` instance wired into BOTH a raw-TCP
//! `SAACPNetworkDaemon` and a `transport::ws::SAACPWebSocketDaemon` via
//! `.with_circuit_breakers(shared)` must actually propagate a per-IP lockout across
//! transports — an attacker tripping the breaker over TCP cannot evade it by
//! reconnecting over WebSocket (or vice versa) against the same shared instance.
//!
//! Before this test existed, `SharedCircuitBreakers`/`new_shared_circuit_breakers()`/
//! `with_circuit_breakers()` were fully implemented and unit-tested at the type level
//! (`daemon.rs`'s own `CircuitBreakerEntry` tests), but nothing in this crate's test
//! suite or production binaries ever actually constructed one instance and handed it to
//! two different transport daemons — the cross-transport propagation this type exists
//! for was, in practice, never exercised end-to-end. `transport/ws.rs::with_circuit_breakers`'s
//! own doc comment states: "Not calling this preserves today's exact behavior: this
//! daemon tracks per-IP lockouts independently of any other daemon" — i.e. the SAFE,
//! shared behavior is opt-in, and this test is what proves the opt-in path actually works.
//!
//! Important transport-boundary note: `daemon::handle_client`'s Step 0 circuit-breaker
//! check runs AFTER the WebSocket upgrade already completes (`serve_ws_connection`
//! completes the WS handshake first, then tunnels into the shared `handle_client`), so a
//! locked-out IP's `tokio_tungstenite::connect_async` call itself still succeeds — the
//! rejection instead shows up as `handle_client` silently returning without ever reading
//! or responding to the SAACP-level ECDH handshake bytes sent over that now-open WS
//! tunnel. This test therefore asserts on the SAACP handshake response, not the WS
//! upgrade itself.

use std::time::Duration;

use futures_util::SinkExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Message;

use saacp::daemon::{new_shared_circuit_breakers, SAACPNetworkDaemon};
use saacp::transport::ws::SAACPWebSocketDaemon;

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Trip the raw-TCP daemon's circuit breaker for `127.0.0.1` by opening and
/// immediately closing a connection `CIRCUIT_BREAKER_ERROR_THRESHOLD` (5) times
/// without ever sending the 64-byte ECDH handshake message — each attempt fails
/// `ecdh_handshake`'s initial `read_exact` (via `HANDSHAKE_TIMEOUT_SECS` = 0.1s
/// timeout on a plain daemon), which calls `record_error` on the daemon's
/// `circuit_breakers` map for this peer IP.
async fn trip_circuit_breaker_via_tcp(port: u16) {
    for _ in 0..5 {
        let stream = TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("client connect failed");
        drop(stream); // never send the handshake bytes — forces a handshake failure
        // Give the server's spawned task time to observe the timeout/EOF and call
        // `record_error` before the next attempt connects (avoids a race where two
        // attempts land concurrently and only one increments the counter in time).
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

/// Send a well-formed SAACP client handshake message (32-byte nonce + 32-byte
/// X25519 public key) over an already-open WS tunnel and wait up to `wait` for a
/// 32-byte server public-key response. Returns `true` if a response arrived,
/// `false` on timeout/close — the observable signal for whether `handle_client`
/// ever got past its Step 0 circuit-breaker check for this connection.
async fn attempt_saacp_handshake_gets_response<S>(
    ws: &mut tokio_tungstenite::WebSocketStream<S>,
    wait: Duration,
) -> bool
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use futures_util::StreamExt;

    let client_nonce = [0x11u8; 32];
    let client_pub = [0x22u8; 32]; // doesn't need to be a real curve point — a locked-out
                                   // connection is dropped before any key material is parsed
    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(&client_pub);
    let _ = ws.send(Message::Binary(client_msg)).await;

    let mut received = Vec::new();
    let deadline = tokio::time::Instant::now() + wait;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            return false;
        }
        match tokio::time::timeout(remaining, ws.next()).await {
            Ok(Some(Ok(Message::Binary(data)))) => {
                received.extend_from_slice(&data);
                if received.len() >= 32 {
                    return true;
                }
            }
            Ok(Some(Ok(_other))) => continue, // ignore Ping/Pong/Text
            Ok(Some(Err(_))) | Ok(None) => return false, // connection closed/errored
            Err(_) => return false,                       // timed out waiting
        }
    }
}

/// R-5: a lockout tripped over the TCP transport must also block a NEW connection
/// attempt over the WS transport, when both daemons share one `SharedCircuitBreakers`
/// instance via `.with_circuit_breakers(shared)`. The WS upgrade itself still succeeds
/// (it happens before `handle_client`'s Step 0 check), but the SAACP handshake sent
/// over that tunnel must never get a response.
#[tokio::test]
async fn tcp_lockout_blocks_subsequent_ws_handshake_when_breakers_are_shared() {
    let shared = new_shared_circuit_breakers();

    let tcp_port = free_port().await;
    let tcp_daemon = SAACPNetworkDaemon::new("127.0.0.1", tcp_port, None)
        .with_circuit_breakers(shared.clone());
    tokio::spawn(async move {
        let _ = tcp_daemon.start().await;
    });

    let ws_port = free_port().await;
    let ws_daemon = SAACPWebSocketDaemon::new("127.0.0.1", ws_port, None)
        .with_circuit_breakers(shared.clone());
    tokio::spawn(async move {
        let _ = ws_daemon.start().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    // Trip the breaker for 127.0.0.1 via the TCP transport.
    trip_circuit_breaker_via_tcp(tcp_port).await;

    // The shared map must now hold an entry for 127.0.0.1 — confirms the TCP side
    // actually recorded the failures (via `record_error`) before asserting on the WS
    // side's behavior below.
    {
        let cbs = shared.lock();
        assert!(
            cbs.contains_key("127.0.0.1"),
            "127.0.0.1 must have a circuit breaker entry after 5 failed handshakes"
        );
    }

    // The WS upgrade itself completes fine (it precedes `handle_client`'s Step 0
    // check) — but the SAACP-level handshake tunneled through it must never get a
    // response, because `handle_client` returns immediately after Step 0's silent
    // drop for this locked-out IP.
    let ws_url = format!("ws://127.0.0.1:{}/", ws_port);
    let (mut ws_stream, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS upgrade itself must still succeed (lockout is enforced after this point)");

    let got_response = attempt_saacp_handshake_gets_response(&mut ws_stream, Duration::from_secs(3)).await;
    assert!(
        !got_response,
        "expected no SAACP handshake response from a TCP-locked-out IP over the WS transport — \
         SharedCircuitBreakers is not actually being consulted by the WS transport"
    );
}

/// Negative control: WITHOUT sharing circuit breakers, tripping the TCP daemon's
/// breaker for an IP must NOT affect a separate WS daemon's independent breaker map —
/// proves the shared-vs-unshared distinction in the test above is real, not an
/// artifact of some other global lockout mechanism (e.g. Step 0b's IP-level
/// `TrustDecayEngine` reauth check, which IS process-wide and would otherwise make
/// the positive test above pass for the wrong reason).
#[tokio::test]
async fn tcp_lockout_does_not_block_ws_handshake_when_breakers_are_independent() {
    let tcp_port = free_port().await;
    let tcp_daemon = SAACPNetworkDaemon::new("127.0.0.1", tcp_port, None); // no with_circuit_breakers
    tokio::spawn(async move {
        let _ = tcp_daemon.start().await;
    });

    let ws_port = free_port().await;
    let ws_daemon = SAACPWebSocketDaemon::new("127.0.0.1", ws_port, None); // independent breaker map
    tokio::spawn(async move {
        let _ = ws_daemon.start().await;
    });

    tokio::time::sleep(Duration::from_millis(150)).await;

    trip_circuit_breaker_via_tcp(tcp_port).await;

    // A fresh WS connection + SAACP handshake must still get a response, since this
    // WS daemon's circuit-breaker map was never told about the TCP failures. If this
    // fails, Step 0b's process-wide IP-trust check (not circuit breakers) may be
    // interfering, which would invalidate the positive test's premise above.
    let ws_url = format!("ws://127.0.0.1:{}/", ws_port);
    let (mut ws_stream, _resp) = tokio_tungstenite::connect_async(&ws_url)
        .await
        .expect("WS upgrade must succeed");

    let got_response = attempt_saacp_handshake_gets_response(&mut ws_stream, Duration::from_secs(5)).await;
    assert!(
        got_response,
        "expected a SAACP handshake response when circuit breakers are independent"
    );
}
