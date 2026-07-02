//! test_transport_ws_rs.rs — end-to-end WebSocket tunnel integration test.
//!
//! Only compiled/run with `--features transport-ws` (see the `[[test]]`
//! entry in Cargo.toml with `required-features`). Proves that a real
//! `tokio-tungstenite` WebSocket client can complete the SAACP X25519 ECDH
//! handshake and exchange a MEASC frame through `SAACPWebSocketDaemon`,
//! getting the same wire response the raw-TCP daemon would produce — the
//! entire gate pipeline, crypto, and framing logic is untouched by this
//! module; only the byte transport differs (see `src/transport/ws.rs`).

use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use tokio_tungstenite::tungstenite::Message;
use x25519_dalek::{EphemeralSecret, PublicKey};

use saacp::transport::ws::SAACPWebSocketDaemon;
use saacp::{FLAG_COVER_TRAFFIC, MEASCFrame, SessionEpochManager};

/// Bind to an ephemeral port, read back the assigned port, then drop the
/// listener so the daemon can bind it. Small TOCTOU window is acceptable for
/// a local single-process test.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Read exactly `n` bytes out of the WS binary-message stream. `handle_client`
/// on the server side may split one logical write across message boundaries
/// (it doesn't, in practice, for these tiny responses) — this helper is
/// robust to either case, mirroring what `WsByteStream` does on read.
async fn recv_exact<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>, n: usize) -> Vec<u8>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let mut out = Vec::with_capacity(n);
    while out.len() < n {
        match ws.next().await {
            Some(Ok(Message::Binary(data))) => out.extend_from_slice(&data),
            Some(Ok(_other)) => continue, // ignore Ping/Pong/Text
            Some(Err(e)) => panic!("WS error while reading: {}", e),
            None => panic!("WS closed before {} bytes were received (got {})", n, out.len()),
        }
    }
    out.truncate(n);
    out
}

/// Client-side mirror of `daemon::ecdh_handshake` in unauthenticated mode:
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
///   session_key = HKDF-SHA256(salt=client_nonce, ikm=shared).expand(
///       info=b"SAACP-daemon-handshake-v1", 32)
async fn ws_client_handshake<S>(ws: &mut tokio_tungstenite::WebSocketStream<S>) -> [u8; 32]
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());
    ws.send(Message::Binary(client_msg)).await.expect("send handshake");

    let server_pub_bytes = recv_exact(ws, 32).await;
    let server_pub = PublicKey::from(
        <[u8; 32]>::try_from(server_pub_bytes.as_slice()).expect("32-byte server pubkey"),
    );

    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .expect("HKDF expand");
    session_key
}

#[tokio::test]
async fn ws_tunnel_cover_traffic_roundtrip() {
    let port = free_port().await;
    let daemon = SAACPWebSocketDaemon::new("127.0.0.1", port, None);
    tokio::spawn(async move {
        daemon.start().await;
    });
    // Give the daemon a moment to bind before connecting.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let url = format!("ws://127.0.0.1:{}/", port);
    let (mut ws_stream, _resp) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("client WS connect failed");

    let session_key = ws_client_handshake(&mut ws_stream).await;

    // Build a cover-traffic MEASC frame with the negotiated session key.
    // Cover traffic (FLAG_COVER_TRAFFIC) is authenticated by Gate 0 but
    // short-circuits before token validation — no capability token needed —
    // and the daemon always acks cover traffic with WIRE_SUCCESS (b"SUCCESS").
    let sid = [0xCCu8; 16];
    let mgr = SessionEpochManager::new();
    mgr.create_session(sid, session_key, 1_000_000, 3600.0, None)
        .expect("create_session");
    let eid = mgr.get_current_epoch_id(&sid).expect("epoch id");
    let (frame, _psn) = mgr
        .with_epoch_mut(&sid, eid, |epoch| {
            MEASCFrame::build_frame(
                epoch, 1, 0x10, FLAG_COVER_TRAFFIC, 0,
                b"", &[0u8; 32], &[0u8; 24], 0,
            )
            .expect("build_frame")
        })
        .expect("with_epoch_mut");

    ws_stream.send(Message::Binary(frame)).await.expect("send frame");

    let response = recv_exact(&mut ws_stream, 7).await; // b"SUCCESS" = 7 bytes
    assert_eq!(&response, b"SUCCESS", "cover traffic must ack with WIRE_SUCCESS over the WS tunnel");

    let _ = ws_stream.close(None).await;
}

/// Confirms two independent WS connections to the same `SAACPWebSocketDaemon`
/// each complete their own handshake and get independent session keys —
/// i.e. the daemon isn't accidentally sharing per-connection state across
/// the `WsByteStream` adapter.
#[tokio::test]
async fn ws_tunnel_two_connections_independent_sessions() {
    let port = free_port().await;
    let daemon = SAACPWebSocketDaemon::new("127.0.0.1", port, None);
    tokio::spawn(async move {
        daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let url = format!("ws://127.0.0.1:{}/", port);

    let (mut ws_a, _) = tokio_tungstenite::connect_async(&url).await.expect("connect A");
    let (mut ws_b, _) = tokio_tungstenite::connect_async(&url).await.expect("connect B");

    let key_a = ws_client_handshake(&mut ws_a).await;
    let key_b = ws_client_handshake(&mut ws_b).await;
    assert_ne!(key_a, key_b, "each WS connection must derive an independent session key");

    for (ws, key, sid_byte) in [(&mut ws_a, key_a, 0xAAu8), (&mut ws_b, key_b, 0xBBu8)] {
        let sid = [sid_byte; 16];
        let mgr = SessionEpochManager::new();
        mgr.create_session(sid, key, 1_000_000, 3600.0, None).expect("create_session");
        let eid = mgr.get_current_epoch_id(&sid).expect("epoch id");
        let (frame, _psn) = mgr
            .with_epoch_mut(&sid, eid, |epoch| {
                MEASCFrame::build_frame(
                    epoch, 1, 0x10, FLAG_COVER_TRAFFIC, 0,
                    b"", &[0u8; 32], &[0u8; 24], 0,
                )
                .expect("build_frame")
            })
            .expect("with_epoch_mut");
        ws.send(Message::Binary(frame)).await.expect("send frame");
        let response = recv_exact(ws, 7).await;
        assert_eq!(&response, b"SUCCESS");
    }

    let _ = ws_a.close(None).await;
    let _ = ws_b.close(None).await;
}
