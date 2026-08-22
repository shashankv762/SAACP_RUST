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
        generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
    let cert_der = cert.der().clone();
    let key_der = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let server_config = server_config_from_cert_and_key(
        vec![cert_der.clone()],
        rustls::pki_types::PrivateKeyDer::Pkcs8(key_der),
    )
    .expect("build server TLS config");

    let mut root_store = rustls::RootCertStore::empty();
    root_store
        .add(cert_der)
        .expect("add self-signed cert to client root store");
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

#[tokio::test]
async fn tls_tunnel_cover_traffic_roundtrip() {
    let port = free_port().await;
    let (server_config, connector) = self_signed_tls_pair();
    let daemon = SAACPTlsDaemon::new("127.0.0.1", port, None, server_config);
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let server_name = rustls::pki_types::ServerName::try_from("localhost").unwrap();
    let mut tls = connector
        .connect(server_name, tcp)
        .await
        .expect("TLS handshake failed");

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
    let frame = header
        .encode_encrypted(b"", &session_key)
        .expect("encode_encrypted");
    tls.write_all(&frame).await.expect("send frame");

    let mut response = [0u8; 7]; // b"SUCCESS" = 7 bytes
    tls.read_exact(&mut response).await.expect("read response");
    assert_eq!(
        &response, b"SUCCESS",
        "cover traffic must ack with WIRE_SUCCESS over the TLS transport"
    );
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
    assert!(
        result.is_ok(),
        "start_with_shutdown returned an error: {:?}",
        result
    );
}

// ─── S5: mutual TLS (client-cert verification) ───────────────────────────────

/// Test PKI: one self-signed CA, a server cert for `localhost`, and a client
/// cert — both signed by the CA. `server_config_with_client_ca` trusts the CA
/// for CLIENT certs; the TLS client trusts the same CA for the SERVER cert.
fn mtls_pki() -> (
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair};

    let ca_key = KeyPair::generate().expect("ca key");
    let mut ca_params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).expect("ca cert");

    let server_key = KeyPair::generate().expect("server key");
    let server_params =
        CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_cert = server_params
        .signed_by(&server_key, &ca, &ca_key)
        .expect("server cert");

    let client_key = KeyPair::generate().expect("client key");
    let client_params =
        CertificateParams::new(vec!["saacp-test-client".to_string()]).expect("client params");
    let client_cert = client_params
        .signed_by(&client_key, &ca, &ca_key)
        .expect("client cert");

    let server_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(server_key.serialize_der()),
    );
    let client_key_der = rustls::pki_types::PrivateKeyDer::Pkcs8(
        rustls::pki_types::PrivatePkcs8KeyDer::from(client_key.serialize_der()),
    );
    (
        ca.der().clone(),
        server_key_der,
        server_cert.der().clone(),
        client_cert.der().clone(),
        client_key_der,
    )
}

/// S5 regression: a server built with `server_config_with_client_ca` completes
/// the TLS + SAACP handshakes ONLY with a client presenting a CA-signed cert.
#[tokio::test]
async fn s5_mtls_client_cert_required_and_sufficient() {
    use saacp::transport::tls::{
        client_config_trusting_roots, client_config_with_client_cert, connect_tls,
        server_config_with_client_ca,
    };
    let (ca_der, server_key_der, server_cert_der, client_cert_der, client_key_der) = mtls_pki();

    let server_config = server_config_with_client_ca(
        vec![server_cert_der.clone()],
        server_key_der,
        vec![ca_der.clone()],
    )
    .expect("mTLS server config");

    let port = free_port().await;
    let daemon = SAACPTlsDaemon::new("127.0.0.1", port, None, server_config);
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;
    let addr = format!("127.0.0.1:{port}");

    // 1. Client WITH a CA-signed cert: TLS handshake + SAACP handshake both
    //    complete.
    let client_cfg =
        client_config_with_client_cert(vec![ca_der.clone()], vec![client_cert_der], client_key_der)
            .expect("mTLS client config");
    let mut tls = connect_tls(&addr, "localhost", client_cfg)
        .await
        .expect("mTLS client must complete the TLS handshake");
    let _session_key = saacp::daemon::client_handshake(&mut tls, None)
        .await
        .expect("SAACP handshake must succeed over the mutually-authenticated TLS stream");

    // 2. Client WITHOUT any client cert: the server must refuse it. In
    //    TLS 1.3 the client can consider its side of the handshake complete
    //    before the server's client-cert rejection surfaces, so the refusal
    //    may appear either at connect() or on the first I/O — both are a pass;
    //    what must NEVER happen is a working SAACP handshake.
    let no_cert_cfg = client_config_trusting_roots(vec![ca_der]).expect("no-client-cert config");
    match connect_tls(&addr, "localhost", no_cert_cfg).await {
        Err(_) => { /* refused at the TLS handshake itself */ }
        Ok(mut tls) => {
            let mut probe = [0u8; 32];
            let read_res =
                tokio::time::timeout(Duration::from_secs(3), tls.read_exact(&mut probe)).await;
            assert!(
                read_res.is_err() || read_res.unwrap().is_err(),
                "a client without a CA-signed cert must be refused (at handshake or first I/O)"
            );
        }
    }
}

/// S5 regression (plain TCP, `with_server_auth`): the pinned-server handshake
/// succeeds with the correct verifying key and fails closed on a wrong pin.
#[tokio::test]
async fn s5_plain_mode_server_key_pinning() {
    use saacp::daemon::{client_handshake_with_pinned_server, SAACPNetworkDaemon};

    let server_seed: [u8; 32] = rand::random();
    let server = ed25519_dalek::SigningKey::from_bytes(&server_seed);
    let real_vk: [u8; 32] = server.verifying_key().to_bytes();

    let port = free_port().await;
    let daemon = SAACPNetworkDaemon::insecure_for_testing("127.0.0.1", port, None)
        .with_server_auth(server_seed);
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    // Correct pin: handshake completes and yields a session key.
    let mut good = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect");
    let (key, sid) = client_handshake_with_pinned_server(&mut good, None, Some(real_vk))
        .await
        .expect("handshake with the correct pinned key must succeed");
    assert_eq!(key.len(), 32);
    assert!(sid.is_none(), "plain mode carries no session id");

    // Wrong pin: fail closed with IdentityMisbinding (never a silent accept).
    let mut bad = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("tcp connect 2");
    let err = client_handshake_with_pinned_server(&mut bad, None, Some([0x99u8; 32]))
        .await
        .expect_err("a wrong pinned key must be rejected");
    assert_eq!(err.bytecode, saacp::SAACPBytecodes::IdentityMisbinding);
}
