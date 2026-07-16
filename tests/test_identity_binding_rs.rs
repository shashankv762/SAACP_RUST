//! test_identity_binding_rs.rs — proves the C-3 identity binding wiring fix.
//!
//! Before this fix, the fully-built `identity_binding.rs` module (`AgentIdentityCertificate`,
//! `TranscriptBoundSession`, `IdentityVerifier`, `IdentityGate`) had zero production call
//! sites: `handler.rs` never referenced it, and `daemon.rs` only called
//! `GLOBAL_IDENTITY_GATE.advance(...)` *after* the full gate pipeline already succeeded, as
//! inert bookkeeping. Gate 1.0's real token-validation path
//! (`ZeroTrustGateway::validate_lateral_movement`) checks only signature/expiry/allow-forbid —
//! nothing bound a capability token to the specific connection presenting it, so any holder
//! of a leaked bearer token (no private key required) could impersonate the agent it names.
//!
//! `SAACPNetworkDaemon::with_identity_binding` + `daemon::client_handshake`'s extended wire
//! mode are the opt-in fix: the client proves possession of a CA-certified Ed25519 identity
//! key during the ECDH handshake, and `handler.rs`'s Gate 1.0 cross-checks every capability
//! token's claimed identity against the cryptographically proven one. This file drives a
//! real `SAACPNetworkDaemon` over a real loopback TCP connection (mirroring
//! `tests/test_daemon_encrypted_rs.rs`'s pattern) to prove:
//!   (a) a client that proves its identity and presents a matching token is accepted,
//!   (b) a token claiming a different identity than the one proven at handshake is rejected,
//!   (c) a certificate signed by an untrusted CA is rejected during the handshake itself,
//!   (d) a forged proof-of-possession (valid cert, wrong private key) is rejected,
//!   (e) a connection that is not identity-bound at all is completely unaffected (regression
//!       guard for the opt-in, backward-compatible design).

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use saacp::daemon::{client_handshake, ClientIdentityConfig};
use saacp::{
    AgentIdentityCertificate, MEASCFrame, SAACPNetworkDaemon, SessionEpochManager,
    ZeroTrustGateway,
};

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

fn issue_token(secret: &[u8], issuer: &str, allow: &[&str], max_action_class: u8) -> String {
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(secret, issuer, allow, &[], 60, None, max_action_class, None);
    String::from_utf8(token).expect("token is valid utf8")
}

fn build_task_frame(
    session_secret: [u8; 32],
    session_id: [u8; 16],
    task: &str,
    cap_token_b64: &str,
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
    let (frame, _psn) = mgr
        .with_epoch_mut(&session_id, eid, |epoch| {
            MEASCFrame::build_frame(
                epoch, 1, 0x10, 0, 0,
                payload.as_bytes(), &[0u8; 32], &[0u8; 24], 0,
            ).expect("build_frame")
        })
        .expect("with_epoch_mut");
    frame
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

/// An issued certificate + its matching agent signing key, plus the CA's own keys for
/// convenience when a test needs to construct an *untrusted* CA scenario.
struct IssuedIdentity {
    cert: AgentIdentityCertificate,
    agent_signing_key: SigningKey,
}

fn issue_identity(ca_signing_key: &SigningKey, ca_kid: &str, agent_id: &str) -> IssuedIdentity {
    let agent_signing_key = SigningKey::generate(&mut OsRng);
    let agent_pk_hex = hex::encode(agent_signing_key.verifying_key().as_bytes());
    let cert = AgentIdentityCertificate::issue(
        agent_id, &agent_pk_hex, ca_signing_key, ca_kid, "root-ca", 86400.0, "ed25519",
    );
    IssuedIdentity { cert, agent_signing_key }
}

#[tokio::test]
async fn identity_bound_matching_token_accepted() {
    let mesh_secret = [0x51u8; 32];
    let port = free_port().await;
    let server_seed = [0x52u8; 32];

    let ca_signing_key = SigningKey::generate(&mut OsRng);
    let ca_vk = ca_signing_key.verifying_key();
    // A CA kid unique to this test — `DEFAULT_IDENTITY_VERIFIER` is a process-wide global
    // singleton shared by every test in this binary, which `cargo test` runs concurrently;
    // reusing a kid across tests would race two different registered keys under the same
    // name.
    let identity = issue_identity(&ca_signing_key, "ca-accept-01", "agent-alpha");

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_identity_binding(server_seed, "daemon-main", &[("ca-accept-01", ca_vk)])
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    let server_vk = daemon.server_verifying_key().expect("server auth enabled");
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let cfg = ClientIdentityConfig {
        certificate: identity.cert,
        signing_key: identity.agent_signing_key,
        expected_server_verifying_key: server_vk,
    };
    let (session_key, session_id) = client_handshake(&mut stream, Some(&cfg))
        .await
        .expect("identity-bound handshake must succeed with a valid cert + PoP");
    let session_id = session_id.expect("identity-bound handshake must return a session_id");

    // Bootstrap authorization scope is always "unknown" for the first packet on a fresh
    // connection (see sidecar.rs's doc comment on this exact convention) — identity binding
    // is enforced independently by Gate 1.0's cross-check against the proven agent_id, not
    // by pre-seeding this bootstrap value.
    let token = issue_token(&mesh_secret, "agent-alpha", &["unknown"], 0);
    let frame = build_task_frame(*session_key, session_id, "do the real thing", &token);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(
        &response, b"SUCCESS",
        "a token whose claimed identity matches the proven handshake identity must be accepted"
    );
}

#[tokio::test]
async fn identity_bound_token_claiming_different_agent_rejected() {
    let mesh_secret = [0x53u8; 32];
    let port = free_port().await;
    let server_seed = [0x54u8; 32];

    let ca_signing_key = SigningKey::generate(&mut OsRng);
    let ca_vk = ca_signing_key.verifying_key();
    let identity = issue_identity(&ca_signing_key, "ca-mismatch-01", "agent-beta");

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_identity_binding(server_seed, "daemon-main", &[("ca-mismatch-01", ca_vk)])
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    let server_vk = daemon.server_verifying_key().expect("server auth enabled");
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let cfg = ClientIdentityConfig {
        certificate: identity.cert,
        signing_key: identity.agent_signing_key,
        expected_server_verifying_key: server_vk,
    };
    let (session_key, session_id) = client_handshake(&mut stream, Some(&cfg))
        .await
        .expect("identity-bound handshake must succeed — the cert and PoP are both valid");
    let session_id = session_id.expect("identity-bound handshake must return a session_id");

    // This connection cryptographically proved it is "agent-beta", but the token it
    // presents claims a *different* identity ("agent-mallory"). Without the C-3 fix, this
    // was accepted outright (Gate 1.0 only checks the token's own signature) — exactly the
    // impersonation gap S-1 describes: possessing any validly-signed token for an identity
    // was sufficient, regardless of who actually holds that identity's private key.
    let token = issue_token(&mesh_secret, "agent-mallory", &["unknown"], 0);
    let frame = build_task_frame(*session_key, session_id, "steal data", &token);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_ne!(
        &response, b"SUCCESS",
        "a token claiming an identity other than the one proven at handshake must be rejected"
    );
}

#[tokio::test]
async fn identity_bound_untrusted_ca_certificate_rejected() {
    let mesh_secret = [0x55u8; 32];
    let port = free_port().await;
    let server_seed = [0x56u8; 32];

    let trusted_ca = SigningKey::generate(&mut OsRng);
    let trusted_ca_vk = trusted_ca.verifying_key();
    // Cert signed by a CA the daemon never registers.
    let untrusted_ca = SigningKey::generate(&mut OsRng);
    let identity = issue_identity(&untrusted_ca, "ca-untrusted", "agent-gamma");

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_identity_binding(server_seed, "daemon-main", &[("ca-trusted-01", trusted_ca_vk)])
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    let server_vk = daemon.server_verifying_key().expect("server auth enabled");
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let cfg = ClientIdentityConfig {
        certificate: identity.cert,
        signing_key: identity.agent_signing_key,
        expected_server_verifying_key: server_vk,
    };
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        client_handshake(&mut stream, Some(&cfg)),
    ).await;
    match result {
        Ok(handshake_result) => assert!(
            handshake_result.is_err(),
            "a certificate from an unregistered CA must not complete the handshake"
        ),
        Err(_timeout) => { /* server silently dropped the connection — also acceptable */ }
    }
}

#[tokio::test]
async fn identity_bound_forged_proof_of_possession_rejected() {
    let mesh_secret = [0x57u8; 32];
    let port = free_port().await;
    let server_seed = [0x58u8; 32];

    let ca_signing_key = SigningKey::generate(&mut OsRng);
    let ca_vk = ca_signing_key.verifying_key();
    let identity = issue_identity(&ca_signing_key, "ca-forged-01", "agent-delta");
    // A legitimate certificate for "agent-delta", but the handshake will be signed with an
    // unrelated private key — simulating an attacker who captured the certificate JSON
    // (e.g. from a log, a relayed message, or a stolen bearer token) but never obtained the
    // actual private key it certifies.
    let attacker_signing_key = SigningKey::generate(&mut OsRng);

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_identity_binding(server_seed, "daemon-main", &[("ca-forged-01", ca_vk)])
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    let server_vk = daemon.server_verifying_key().expect("server auth enabled");
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let cfg = ClientIdentityConfig {
        certificate: identity.cert,
        signing_key: attacker_signing_key, // does NOT match the certificate's public key
        expected_server_verifying_key: server_vk,
    };
    let result = tokio::time::timeout(
        Duration::from_millis(500),
        client_handshake(&mut stream, Some(&cfg)),
    ).await;
    match result {
        Ok(handshake_result) => assert!(
            handshake_result.is_err(),
            "a proof-of-possession signature not matching the certificate's key must be rejected"
        ),
        Err(_timeout) => { /* server silently dropped the connection — also acceptable */ }
    }
}

/// Regression guard: a daemon that never opts into identity binding behaves exactly as
/// before — plain `client_handshake(&mut stream, None)` unauthenticated wire format,
/// no session_id returned, no identity cross-check performed in `handler.rs`.
#[tokio::test]
async fn non_identity_bound_connection_unaffected() {
    let mesh_secret = [0x59u8; 32];
    let port = free_port().await;

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_encrypted_transport(Arc::new(SessionEpochManager::new()));
    tokio::spawn(async move { let _ = daemon.start().await; });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let (session_key, session_id) = client_handshake(&mut stream, None)
        .await
        .expect("unauthenticated handshake must still work");
    assert!(session_id.is_none(), "non-identity-bound handshake must not produce a session_id");

    let token = issue_token(&mesh_secret, "client-agent", &["unknown"], 0);
    let frame = build_task_frame(*session_key, [0xEEu8; 16], "business as usual", &token);
    stream.write_all(&frame).await.expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(&response, b"SUCCESS", "non-identity-bound connections must be entirely unaffected");
}
