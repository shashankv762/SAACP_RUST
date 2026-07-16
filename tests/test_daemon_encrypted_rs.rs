//! test_daemon_encrypted_rs.rs — proves the DAEMON-NO-AEAD / DAEMON-NO-TOKEN-VERIFY fixes.
//!
//! Before this fix, `SAACPNetworkDaemon::handle_client` never actually AES-GCM-decrypted
//! wire payloads (Gate 0 used the structural-only `framing::MEASCFrame::parse_header`) and
//! never verified capability-token signatures (always called `intercept_packet` with
//! `gateway: None`, which grants a hardcoded pass-through). `.with_gateway(...)` and
//! `.with_encrypted_transport(...)` are the opt-in fix; this file drives a real
//! `SAACPNetworkDaemon` over a real loopback TCP connection (mirroring
//! `tests/test_transport_ws_rs.rs`'s pattern) to prove:
//!   (a) a real AES-256-GCM frame carrying a validly-signed token is accepted and decoded,
//!   (b) tampered ciphertext is AEAD-rejected,
//!   (c) a token signed with the wrong secret is rejected,
//!   (d) the plain `SAACPNetworkDaemon::new()` default (no builders) is unchanged.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

use saacp::{FLAG_COVER_TRAFFIC, MEASCFrame, SAACPNetworkDaemon, SessionEpochManager, ZeroTrustGateway};

/// Bind to an ephemeral port, read back the assigned port, then drop the listener so the
/// daemon can bind it. Small TOCTOU window is acceptable for a local single-process test.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Client-side mirror of `daemon::ecdh_handshake` in unauthenticated mode — same pattern as
/// `tests/test_transport_ws_rs.rs`'s `ws_client_handshake`, just over a raw `TcpStream`
/// instead of a WebSocket. `daemon::client_handshake` (added in a later phase of this work)
/// promotes this exact logic into real library code; this test predates that and hand-rolls
/// it, proving the wire protocol independent of that helper.
async fn tcp_client_handshake(stream: &mut TcpStream) -> [u8; 32] {
    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());
    stream.write_all(&client_msg).await.expect("send handshake");

    let mut server_pub_bytes = [0u8; 32];
    stream.read_exact(&mut server_pub_bytes).await.expect("read server pubkey");
    let server_pub = PublicKey::from(server_pub_bytes);

    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key).expect("HKDF expand");
    session_key
}

/// Build a real AES-256-GCM-encrypted schema-1 ("Task") frame, optionally corrupting a
/// ciphertext byte to simulate tampering.
fn build_task_frame(
    session_secret: [u8; 32],
    session_id: [u8; 16],
    task: &str,
    cap_token_b64: &str,
    corrupt_ciphertext: bool,
) -> Vec<u8> {
    let mgr = SessionEpochManager::new();
    mgr.create_session(session_id, session_secret, 1_000_000, 3600.0, None)
        .expect("create_session");
    let eid = mgr.get_current_epoch_id(&session_id).expect("epoch id");
    let payload = serde_json::json!({
        "task": task,
        "priority": 1,
        "_capability_token": cap_token_b64,
    }).to_string();
    let (mut frame, _psn) = mgr
        .with_epoch_mut(&session_id, eid, |epoch| {
            MEASCFrame::build_frame(
                epoch, 1, 0x10, 0, 0,
                payload.as_bytes(), &[0u8; 32], &[0u8; 24], 0,
            ).expect("build_frame")
        })
        .expect("with_epoch_mut");
    if corrupt_ciphertext {
        // Wire layout: header(128) || tag(16) || ciphertext. Flip a ciphertext byte.
        let ct_offset = 128 + 16;
        frame[ct_offset] ^= 0xFF;
    }
    frame
}

fn issue_token(secret: &[u8], issuer: &str, allow: &[&str], max_action_class: u8) -> String {
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(secret, issuer, allow, &[], 60, None, max_action_class, None);
    String::from_utf8(token).expect("token is valid utf8")
}

async fn read_response(stream: &mut TcpStream, max_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max_len];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    buf.truncate(n);
    buf
}

#[tokio::test]
async fn daemon_encrypted_valid_signed_token_accepted_and_decodes() {
    let mesh_secret = [0x42u8; 32];
    let port = free_port().await;

    let delivered: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let delivered_cb = Arc::clone(&delivered);

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()))
        .with_on_delivered(Arc::new(move |parsed| {
            if let Some(saacp::handler::JsonValue::String(task)) = parsed.payload_dict.get("task") {
                delivered_cb.lock().unwrap().push(task.clone());
            }
        }));
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let session_key = tcp_client_handshake(&mut stream).await;

    let token = issue_token(&mesh_secret, "client-agent", &["unknown"], 0);
    let frame = build_task_frame(session_key, [0xAAu8; 16], "do the real thing", &token, false);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(&response, b"SUCCESS", "validly-signed encrypted frame must be accepted");

    // Give the (already-awaited-response) on_delivered callback a moment — it runs
    // synchronously before the ack is written, so this is just defensive.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        delivered.lock().unwrap().as_slice(),
        &["do the real thing".to_string()],
        "on_delivered must observe the genuinely decrypted payload"
    );
}

#[tokio::test]
async fn daemon_encrypted_tampered_ciphertext_rejected() {
    let mesh_secret = [0x43u8; 32];
    let port = free_port().await;

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let session_key = tcp_client_handshake(&mut stream).await;

    let token = issue_token(&mesh_secret, "client-agent", &["unknown"], 0);
    let frame = build_task_frame(session_key, [0xBBu8; 16], "tampered", &token, true);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_ne!(&response, b"SUCCESS", "AES-GCM auth failure must not be silently accepted");
}

#[tokio::test]
async fn daemon_encrypted_wrong_issuer_secret_rejected() {
    let mesh_secret = [0x44u8; 32];
    let wrong_secret = [0x45u8; 32];
    let port = free_port().await;

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let session_key = tcp_client_handshake(&mut stream).await;

    // Token is well-formed and correctly encrypted, but signed with a secret the daemon
    // was never configured with — Gate 1.0 must reject the HMAC signature check.
    let token = issue_token(&wrong_secret, "client-agent", &["unknown"], 0);
    let frame = build_task_frame(session_key, [0xCCu8; 16], "forged", &token, false);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_ne!(&response, b"SUCCESS", "a token signed with the wrong secret must be rejected");
}

#[tokio::test]
async fn daemon_plain_new_default_behavior_unchanged() {
    // Regression guard: a plain `SAACPNetworkDaemon::new()` with no builders must still
    // ack cover traffic with WIRE_SUCCESS exactly as before this fix — proving the
    // structural (non-encrypted, non-gateway-verified) path is untouched by default.
    //
    // Gate 0 for this path is `framing::MEASCFrame::parse_header`, which (post CRIT-1
    // fix) performs REAL AES-256-GCM verification keyed directly off the ECDH
    // `session_key` via `framing::MEASCFrame::derive_frame_key_iv` — a different
    // derivation from `measc::MEASCFrame`'s `SessionEpochManager`-based scheme used
    // by the `.with_encrypted_transport(...)` tests above (see that scheme's own
    // "SAACP-MEASC-epoch-key-v1" HKDF info string vs. this one's
    // "SAACP-FRAMING-MEASCFrame-key-iv-v1" — they can never produce the same key).
    // So the wire frame here must be built with `framing::MEASCFrame::encode_encrypted`,
    // the matching counterpart to `parse_header` — its own doc comment notes this is
    // exactly what it's for ("this exists for tests"). Building it with
    // `measc::MEASCFrame::build_frame` (as this test previously did, before the CRIT-1
    // fix made Gate 0 verify real crypto instead of accepting any well-shaped bytes)
    // now fails AES-GCM authentication unconditionally.
    let port = free_port().await;
    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, None);
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let session_key = tcp_client_handshake(&mut stream).await;

    let header = saacp::framing::MEASCFrame {
        schema_id: 1,
        status_code: 0x10,
        flags: FLAG_COVER_TRAFFIC,
        action_class: 0,
        payload_length: 0,
        session_id: [0xDDu8; 16],
        epoch_id: 0,
        psn: 0,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    let frame = header.encode_encrypted(b"", &session_key).expect("encode_encrypted");
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(&response, b"SUCCESS", "default daemon behavior (no builders) must be unchanged");
}

/// Sanity check that the two-frame-per-connection sequencing used above doesn't leak
/// state across independent connections/sessions (each gets its own epoch-0 session).
#[tokio::test]
async fn daemon_encrypted_two_independent_sessions() {
    let mesh_secret = [0x46u8; 32];
    let port = free_port().await;
    let count = Arc::new(AtomicUsize::new(0));
    let count_cb = Arc::clone(&count);

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()))
        .with_on_delivered(Arc::new(move |_parsed| {
            count_cb.fetch_add(1, Ordering::SeqCst);
        }));
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    for (i, sid_byte) in [0xE0u8, 0xE1u8].into_iter().enumerate() {
        let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
        let session_key = tcp_client_handshake(&mut stream).await;
        let token = issue_token(&mesh_secret, "client-agent", &["unknown"], 0);
        let frame = build_task_frame(session_key, [sid_byte; 16], &format!("task-{i}"), &token, false);
        stream.write_all(&frame).await.expect("send frame");
        let response = read_response(&mut stream, 128).await;
        assert_eq!(&response, b"SUCCESS");
    }

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(count.load(Ordering::SeqCst), 2, "both independent sessions must be delivered");
}
