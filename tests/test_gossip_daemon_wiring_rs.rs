//! test_gossip_daemon_wiring_rs.rs — Phase 6 item 4 remainder (revocation gossip mesh
//! daemon wiring, `gossip.rs` module docs / Part 8.6): proves `SAACPNetworkDaemon::
//! with_gossip_engine` actually decodes an inbound schema_id=11 `Gossip Envelope` packet
//! and hands it to `gossip::GossipEngine::receive` through the REAL gate pipeline over a
//! real loopback TCP connection — not just exercised directly against `GossipEngine` in
//! `gossip.rs`'s own unit tests. Mirrors `test_daemon_encrypted_rs.rs`'s
//! real-TCP-daemon-plus-client test pattern.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use saacp::faitf::{
    AgentIdentity, AttestationType, DistributedRevocationInfrastructure, TrustAnchor, TrustStore,
};
use saacp::gossip::{GossipEngine, GossipEnvelope, GossipTransport};
use saacp::framing::MEASCFrame as StructuralFrame;
use saacp::{SAACPNetworkDaemon, ZeroTrustGateway};

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Client-side mirror of `daemon::ecdh_handshake` in unauthenticated mode — see
/// `test_daemon_encrypted_rs.rs::tcp_client_handshake` for the canonical version this
/// duplicates (that helper is private to its own test binary).
async fn tcp_client_handshake(stream: &mut TcpStream) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
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

async fn read_response(stream: &mut TcpStream, max_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max_len];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    buf.truncate(n);
    buf
}

/// A `GossipTransport` with no known peers — this test only cares about the inbound
/// `receive` path storing the revocation, not further re-forwarding.
struct NoopTransport;
impl GossipTransport for NoopTransport {
    fn known_peers(&self) -> Vec<String> { Vec::new() }
    fn send_to_peer(&self, _peer_id: &str, _bytes: &[u8]) {}
}

#[tokio::test]
async fn inbound_schema_11_packet_is_delivered_to_gossip_engine() {
    let mesh_secret = [0x51u8; 32];
    let port = free_port().await;

    // Build a validly-signed revocation record from a "peer node"'s identity, verifiable
    // against a TrustStore anchor this daemon's GossipEngine is configured with.
    let revoker = AgentIdentity::generate(
        "peer-revoker", "issuer-gossip-daemon-test", 86_400, None, None, "", AttestationType::None,
    );
    let record = DistributedRevocationInfrastructure::new()
        .revoke("victim-agent", "compromised", &revoker, "fp-victim")
        .expect("revoke");
    let revocation_id = GossipEnvelope::derive_revocation_id(&record);

    let trust_store = Arc::new(TrustStore::new());
    trust_store.register_anchor(TrustAnchor::new(&revoker.agent_id, revoker.verifying_key));
    let dri = Arc::new(DistributedRevocationInfrastructure::new());
    let engine = Arc::new(GossipEngine::new(
        Arc::new(NoopTransport),
        dri.clone(),
        trust_store,
        "daemon-under-test",
    ));

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_gossip_engine(engine);
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    // The ECDH handshake still runs as a protocol formality, but its derived session_key is
    // discarded below: with `.with_gateway(...)` configured WITHOUT `.with_encrypted_transport(...)`,
    // `daemon::handle_client` decrypts Gate 0's structural frame using `gate_secret`
    // (`token_issuer_secret`, i.e. `mesh_secret`) rather than the per-connection ECDH
    // `session_key` — see its own doc comment on the `gate_secret` local. Only the
    // `.with_gateway` + `.with_encrypted_transport` combination (measc `SessionEpochManager`
    // path, `test_daemon_encrypted_rs.rs`) actually keys AEAD off the ECDH session_key.
    let _session_key = tcp_client_handshake(&mut stream).await;

    // Structural, not measc-epoch — matches the `.with_gateway` (no `.with_encrypted_transport`)
    // combination's Gate 0, exactly as `test_telemetry_wiring_rs.rs::build_frame` does.
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(&mesh_secret, "peer-daemon-agent", &["unknown"], &[], 60, None, 0, None);
    let token_b64 = String::from_utf8(token).expect("token utf8");

    let gossip_record_b64 = B64.encode(record.to_wire());
    let payload = serde_json::json!({
        "gossip_record": gossip_record_b64,
        "hop_count": 0,
        "origin_id": "remote-peer-node",
        "revocation_id": revocation_id,
        "_capability_token": token_b64,
    }).to_string();

    let frame = StructuralFrame {
        schema_id: 11,
        status_code: 0x10,
        flags: 0,
        action_class: 0,
        payload_length: 0,
        session_id: [0xF1u8; 16],
        epoch_id: 0,
        psn: 1,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    }.encode_encrypted(payload.as_bytes(), &mesh_secret).expect("encode_encrypted");

    stream.write_all(&frame).await.expect("send frame");
    let response = read_response(&mut stream, 128).await;
    assert_eq!(&response, b"SUCCESS", "a well-formed gossip envelope must clear the gate pipeline");

    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        dri.is_revoked("victim-agent", "fp-victim"),
        "GossipEngine::receive must have verified and stored the revocation via the daemon's wired GossipEngine"
    );
}
