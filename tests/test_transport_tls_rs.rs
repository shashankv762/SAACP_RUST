//! test_transport_tls_rs.rs — end-to-end TLS-terminated-raw-TCP integration test.
//!
//! Only compiled/run with `--features transport-tls` (see the `[[test]]` entry in
//! Cargo.toml with `required-features`). Proves that a real `tokio-rustls` TLS client can
//! complete a TLS handshake, then the SAACP X25519 ECDH handshake, then exchange a MEASC
//! frame through `SAACPTlsDaemon`, getting the same wire response the raw-TCP daemon would
//! produce — the entire gate pipeline, crypto, and framing logic is untouched by this
//! module; only the outer transport is TLS instead of plaintext TCP (see
//! `src/transport/tls.rs`).

use std::sync::Arc;
use std::time::Duration;

use hkdf::Hkdf;
use rand::rngs::OsRng;
use rcgen::{generate_simple_self_signed, CertifiedKey};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::rustls;
use tokio_rustls::TlsConnector;
use x25519_dalek::{EphemeralSecret, PublicKey};

use saacp::transport::tls::{server_config_from_cert_and_key, SAACPTlsDaemon};
use saacp::FLAG_COVER_TRAFFIC;

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Generates a fresh self-signed cert for `localhost` and builds both the server-side
/// `rustls::ServerConfig` (for `SAACPTlsDaemon`) and a client-side `TlsConnector` that
/// trusts exactly that cert (added directly to the client's root store — this is a test
/// fixture, not a CA-chain validation test).
fn self_signed_tls_pair() -> (Arc<rustls::ServerConfig>, TlsConnector) {
    let CertifiedKey { cert, key_pair } =
        generate_simple_self_signed(vec!["localhost".to_string()]).expect("generate self-signed cert");
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let server_config = server_config_from_cert_and_key(
        vec![cert_der.clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )
    .expect("build server TLS config");

    let mut root_store = rustls::RootCertStore::empty();
    root_store.add(cert_der).expect("add self-signed cert to client root store");
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("client protocol versions")
        .with_root_certificates(root_store)
        .with_no_client_auth();

    (server_config, TlsConnector::from(Arc::new(client_config)))
}

/// Client-side mirror of `daemon::ecdh_handshake` in unauthenticated mode, run directly
/// over the byte-oriented TLS stream (no WebSocket message framing to worry about here):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
///   session_key = HKDF-SHA256(salt=client_nonce, ikm=shared).expand(
///       info=b"SAACP-daemon-handshake-v1", 32)
async fn tls_client_handshake<S>(stream: &mut S) -> [u8; 32]
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
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

#[tokio::test]
async fn tls_tunnel_cover_traffic_roundtrip() {
    let port = free_port().await;
    let (server_config, connector) = self_signed_tls_pair();
    let daemon = SAACPTlsDaemon::new("127.0.0.1", port, None, server_config);
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.expect("tcp connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.expect("TLS handshake failed");

    let session_key = tls_client_handshake(&mut tls).await;

    // Cover traffic (FLAG_COVER_TRAFFIC) is authenticated by Gate 0 but short-circuits
    // before token validation — no capability token needed — and the daemon always acks
    // cover traffic with WIRE_SUCCESS (b"SUCCESS"). See
    // `tests/test_transport_ws_rs.rs::ws_tunnel_cover_traffic_roundtrip` for the equivalent
    // WebSocket-transport case; the framing here is identical, only the outer transport
    // differs (TLS-terminated raw TCP instead of a WebSocket tunnel).
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
    tls.write_all(&frame).await.expect("send frame");

    let mut response = [0u8; 7]; // b"SUCCESS" = 7 bytes
    tls.read_exact(&mut response).await.expect("read response");
    assert_eq!(&response, b"SUCCESS", "cover traffic must ack with WIRE_SUCCESS over the TLS transport");
}

/// M-15/R-2 fix: `start_with_shutdown` on `SAACPTlsDaemon` must stop accepting new
/// connections and return once cancelled, mirroring
/// `tests/test_daemon_shutdown_rs.rs`'s coverage of the raw-TCP daemon.
#[tokio::test]
async fn tls_start_with_shutdown_returns_promptly_with_no_connections() {
    let port = free_port().await;
    let (server_config, _connector) = self_signed_tls_pair();
    let daemon = SAACPTlsDaemon::new("127.0.0.1", port, None, server_config);
    let shutdown = tokio_util::sync::CancellationToken::new();

    let shutdown_clone = shutdown.clone();
    let handle = tokio::spawn(async move { daemon.start_with_shutdown(shutdown_clone).await });
    tokio::time::sleep(Duration::from_millis(150)).await;
    shutdown.cancel();

    let result = tokio::time::timeout(Duration::from_secs(10), handle)
        .await
        .expect("start_with_shutdown did not return within 10s")
        .expect("daemon task panicked");
    assert!(result.is_ok(), "start_with_shutdown returned an error: {:?}", result);
}
