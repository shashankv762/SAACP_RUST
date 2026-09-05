//! test_session_affinity_policy_rs.rs — M11 hardening (Phase 3) regression tests.
//!
//! Proves the `AffinityViolationPolicy` enforcement split for session-affinity
//! violations (a session_id appearing on a node that did not create it — proof
//! the load balancer is not session-affine):
//!
//! 1. **AlertOnly (the default)**: the violation is counted in the new
//!    `session_affinity_violations` telemetry counter, alerted, and fed to the
//!    per-IP error counter — but the packet is still processed (the connection
//!    gets a normal SUCCESS ack). Byte-identical to the pre-Phase-3 behavior.
//! 2. **HardDrop**: the same violation additionally terminates the connection
//!    with a hard drop (fail closed) — the counter still moves.
//!
//! Both scenarios run through a REAL `SAACPNetworkDaemon` over a real loopback
//! TCP connection (mirroring `test_daemon_encrypted_rs.rs`'s harness), with a
//! SHARED `SessionAffinityTracker` pre-seeded so the session is already
//! recorded under a different node id — the only way a violation is
//! observable (a fresh per-daemon tracker records the first sighting as its
//! own node, which is exactly why `with_affinity_tracker` exists).
//!
//! Both scenarios live in ONE `#[test]` fn because the telemetry counter is
//! process-global and the assertions are counter deltas; sequential execution
//! inside one test avoids cross-scenario races.

use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use x25519_dalek::{EphemeralSecret, PublicKey};

use saacp::framing::MEASCFrame;
use saacp::session_affinity::{AffinityViolationPolicy, SessionAffinityTracker};
use saacp::telemetry::global_telemetry;
use saacp::{SAACPNetworkDaemon, FLAG_COVER_TRAFFIC};

/// Bind to an ephemeral port, read back the assigned port, then drop the
/// listener so the daemon can bind it.
async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Client-side mirror of `daemon::ecdh_handshake` in unauthenticated mode
/// (same pattern as `test_daemon_encrypted_rs.rs`'s `tcp_client_handshake`).
async fn tcp_client_handshake(stream: &mut TcpStream) -> [u8; 32] {
    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());
    stream.write_all(&client_msg).await.expect("send handshake");

    let mut server_pub_bytes = [0u8; 32];
    stream
        .read_exact(&mut server_pub_bytes)
        .await
        .expect("read server pubkey");
    let server_pub = PublicKey::from(server_pub_bytes);

    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .expect("HKDF expand");
    session_key
}

/// Cover-traffic frame carrying `session_id` in its header (bytes 16..32) —
/// the exact bytes the affinity check inspects.
fn build_cover_frame(session_key: [u8; 32], session_id: [u8; 16]) -> Vec<u8> {
    let header = MEASCFrame {
        schema_id: 1,
        status_code: 0x10,
        flags: FLAG_COVER_TRAFFIC,
        action_class: 0,
        payload_length: 0,
        session_id,
        epoch_id: 0,
        psn: 0,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    header
        .encode_encrypted(b"", &session_key)
        .expect("encode_encrypted")
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
async fn affinity_violation_alert_only_processes_but_hard_drop_terminates() {
    let snap = || global_telemetry().snapshot();
    let violations_before = snap()["session_affinity_violations"];

    // Shared tracker: the session is ALREADY recorded under "node-a", so any
    // daemon presenting it as another node is an affinity violation.
    let tracker = Arc::new(SessionAffinityTracker::new());
    let foreign_sid: [u8; 16] = [0x5Au8; 16];
    tracker
        .record_session(&foreign_sid, "node-a")
        .expect("first sighting must record cleanly");

    // ── Scenario 1: AlertOnly (default) — violation counted, packet processed ──
    let port = free_port().await;
    let daemon = SAACPNetworkDaemon::insecure_for_testing("127.0.0.1", port, None)
        .with_affinity_tracker("node-b", Arc::clone(&tracker));
    // NOTE: policy deliberately left at its default (AlertOnly).
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let session_key = tcp_client_handshake(&mut stream).await;
    let frame = build_cover_frame(session_key, foreign_sid);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert!(
        response.starts_with(b"SUCCESS"),
        "AlertOnly must still PROCESS the violating packet (detection must not \
         become a self-inflicted outage), got: {response:?}"
    );
    assert_eq!(
        snap()["session_affinity_violations"],
        violations_before + 1,
        "the AlertOnly violation must be counted in session_affinity_violations"
    );

    // ── Scenario 2: HardDrop — same violation terminates the connection ────
    let port2 = free_port().await;
    let daemon2 = SAACPNetworkDaemon::insecure_for_testing("127.0.0.1", port2, None)
        .with_affinity_tracker("node-b", Arc::clone(&tracker))
        .affinity_violation_policy(AffinityViolationPolicy::HardDrop);
    tokio::spawn(async move {
        let _ = daemon2.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream2 = TcpStream::connect(("127.0.0.1", port2))
        .await
        .expect("connect");
    let session_key2 = tcp_client_handshake(&mut stream2).await;
    let frame2 = build_cover_frame(session_key2, foreign_sid);
    stream2.write_all(&frame2).await.expect("send frame");

    let response2 = read_response(&mut stream2, 128).await;
    assert!(
        !response2.starts_with(b"SUCCESS"),
        "HardDrop must terminate the violating connection with a hard drop \
         (fail closed), got: {response2:?}"
    );
    assert_eq!(
        snap()["session_affinity_violations"],
        violations_before + 2,
        "the HardDrop violation must be counted too — the policy decides only \
         whether the connection is dropped, never whether detection is counted"
    );
}
