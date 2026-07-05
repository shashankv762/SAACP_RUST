//! test_sidecar_rs.rs — end-to-end test of the sidecar HTTP proxy (`src/sidecar.rs`).
//!
//! Two in-process sidecars, driven purely through plain HTTP/JSON (as a Python agent
//! would), with a real loopback TCP connection + real X25519 ECDH + real AES-256-GCM +
//! real HMAC capability-token verification underneath — proving the Python-facing surface
//! actually rides on the Phase-0 daemon fixes end to end, not just that the HTTP routes
//! exist.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use saacp::security::{AuditRecord, ImmutableAuditLog};
use saacp::sidecar::{run, SidecarConfig, SIDECAR_INBOX_CAPACITY};

async fn free_addr() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Spawn a sidecar on two fresh ephemeral ports (SAACP protocol + local HTTP API) and give
/// it a moment to bind before returning.
async fn spawn_sidecar(agent_id: &str, secret: [u8; 32]) -> (SocketAddr, SocketAddr) {
    spawn_sidecar_with(agent_id, secret, |_| {}).await
}

/// Same as `spawn_sidecar`, but lets the caller customize the config (e.g. `peer_secrets`,
/// `max_concurrent_sends`) before starting it.
async fn spawn_sidecar_with(
    agent_id: &str,
    secret: [u8; 32],
    customize: impl FnOnce(&mut SidecarConfig),
) -> (SocketAddr, SocketAddr) {
    let saacp_addr = free_addr().await;
    let http_addr = free_addr().await;
    let mut config = SidecarConfig::new(agent_id, secret, saacp_addr, http_addr);
    customize(&mut config);
    tokio::spawn(async move { run(config).await; });
    tokio::time::sleep(Duration::from_millis(200)).await;
    (saacp_addr, http_addr)
}

#[tokio::test]
async fn sidecar_send_receive_round_trip() {
    let mesh_secret = [0x11u8; 32];
    let (_agent_a_saacp, agent_a_http) = spawn_sidecar("agent-a", mesh_secret).await;
    let (agent_b_saacp, agent_b_http) = spawn_sidecar("agent-b", mesh_secret).await;

    let client = reqwest::Client::new();

    let send_resp = client
        .post(format!("http://{}/send", agent_a_http))
        .json(&serde_json::json!({
            "to_agent": "agent-b",
            "target_addr": agent_b_saacp.to_string(),
            "task": "do the real thing",
            "priority": 5,
        }))
        .send()
        .await
        .expect("send request failed");
    assert_eq!(send_resp.status(), 200);
    let send_body: serde_json::Value = send_resp.json().await.expect("send body json");
    assert_eq!(send_body["status"], "success", "body: {send_body}");

    let recv_resp = client
        .get(format!("http://{}/receive?wait_secs=5", agent_b_http))
        .send()
        .await
        .expect("receive request failed");
    assert_eq!(recv_resp.status(), 200);
    let recv_body: serde_json::Value = recv_resp.json().await.expect("receive body json");
    assert_eq!(recv_body["task"], "do the real thing");
    assert_eq!(recv_body["priority"], 5);
    assert_eq!(recv_body["from_agent"], "agent-a");
}

#[tokio::test]
async fn sidecar_receive_times_out_with_204_when_empty() {
    let (_saacp_addr, http_addr) = spawn_sidecar("agent-solo", [0x12u8; 32]).await;

    let client = reqwest::Client::new();
    let recv_resp = client
        .get(format!("http://{}/receive?wait_secs=0.2", http_addr))
        .send()
        .await
        .expect("receive request failed");
    assert_eq!(recv_resp.status(), 204);
}

#[tokio::test]
async fn sidecar_wrong_shared_secret_rejected() {
    let (_a_saacp, agent_a_http) = spawn_sidecar("agent-a2", [0x21u8; 32]).await;
    let (agent_b_saacp, agent_b_http) = spawn_sidecar("agent-b2", [0x22u8; 32]).await;

    let client = reqwest::Client::new();
    let send_resp = client
        .post(format!("http://{}/send", agent_a_http))
        .json(&serde_json::json!({
            "to_agent": "agent-b2",
            "target_addr": agent_b_saacp.to_string(),
            "task": "forged",
        }))
        .send()
        .await
        .expect("send request failed");
    assert_eq!(send_resp.status(), 200);
    let send_body: serde_json::Value = send_resp.json().await.expect("send body json");
    assert_eq!(send_body["status"], "rejected", "body: {send_body}");

    // Confirm the forged message never actually reached agent-b2's inbox.
    let recv_resp = client
        .get(format!("http://{}/receive?wait_secs=0.3", agent_b_http))
        .send()
        .await
        .expect("receive request failed");
    assert_eq!(recv_resp.status(), 204);
}

#[tokio::test]
async fn sidecar_healthz() {
    let (_saacp, http_addr) = spawn_sidecar("agent-health", [0x33u8; 32]).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/healthz", http_addr))
        .send()
        .await
        .expect("healthz failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["agent_id"], "agent-health");
    assert_eq!(body["status"], "ok");
}

/// Production-hardening regression proof #1: a peer with its own pairwise `peer_secrets`
/// entry is accepted end to end, exercising `SidecarState::secret_for` picking the
/// pairwise secret over the mesh-wide shared one on both the signing and verifying side.
#[tokio::test]
async fn sidecar_peer_secret_accepted() {
    let secret_ab = [0x55u8; 32];
    let (_a_saacp, agent_a_http) = spawn_sidecar_with("agent-a3", [0xAAu8; 32], |cfg| {
        cfg.peer_secrets.insert("agent-b3".into(), secret_ab);
    })
    .await;
    let (agent_b_saacp, agent_b_http) = spawn_sidecar_with("agent-b3", [0xBBu8; 32], |cfg| {
        cfg.peer_secrets.insert("agent-a3".into(), secret_ab);
    })
    .await;

    let client = reqwest::Client::new();
    let send_resp = client
        .post(format!("http://{}/send", agent_a_http))
        .json(&serde_json::json!({
            "to_agent": "agent-b3",
            "target_addr": agent_b_saacp.to_string(),
            "task": "pairwise-secured message",
        }))
        .send()
        .await
        .expect("send request failed");
    assert_eq!(send_resp.status(), 200);
    let send_body: serde_json::Value = send_resp.json().await.expect("send body json");
    assert_eq!(send_body["status"], "success", "body: {send_body}");

    let recv_resp = client
        .get(format!("http://{}/receive?wait_secs=5", agent_b_http))
        .send()
        .await
        .expect("receive request failed");
    assert_eq!(recv_resp.status(), 200);
    let recv_body: serde_json::Value = recv_resp.json().await.expect("receive body json");
    assert_eq!(recv_body["task"], "pairwise-secured message");
    assert_eq!(recv_body["from_agent"], "agent-a3");
}

/// Production-hardening regression proof #2: once a sidecar has registered *any*
/// `peer_secrets` entry, `ZeroTrustGateway`'s registry becomes authoritative — an issuer
/// not in that registry is hard-rejected outright, even though it signed with its own
/// otherwise-valid 32-byte secret. This is the real allowlist behavior confirmed via
/// `gateway.rs::validate_lateral_movement`, not just "wrong secret" rejection.
#[tokio::test]
async fn sidecar_peer_secret_allowlist_rejects_unregistered_issuer() {
    let secret_ab = [0x66u8; 32];
    let (agent_b_saacp, agent_b_http) = spawn_sidecar_with("agent-b4", [0xBBu8; 32], |cfg| {
        cfg.peer_secrets.insert("agent-a4".into(), secret_ab);
    })
    .await;
    // A totally different, unregistered sidecar using its own mesh secret.
    let (_c_saacp, agent_c_http) = spawn_sidecar("agent-c4", [0xCCu8; 32]).await;

    let client = reqwest::Client::new();
    let send_resp = client
        .post(format!("http://{}/send", agent_c_http))
        .json(&serde_json::json!({
            "to_agent": "agent-b4",
            "target_addr": agent_b_saacp.to_string(),
            "task": "should be rejected",
        }))
        .send()
        .await
        .expect("send request failed");
    assert_eq!(send_resp.status(), 200);
    let send_body: serde_json::Value = send_resp.json().await.expect("send body json");
    assert_eq!(send_body["status"], "rejected", "body: {send_body}");

    // Confirm the untrusted-issuer message never actually reached agent-b4's inbox.
    let recv_resp = client
        .get(format!("http://{}/receive?wait_secs=0.3", agent_b_http))
        .send()
        .await
        .expect("receive request failed");
    assert_eq!(recv_resp.status(), 204);
}

#[tokio::test]
async fn sidecar_healthz_reports_inbox_and_peer_counts() {
    let (_saacp, http_addr) = spawn_sidecar_with("agent-health2", [0x77u8; 32], |cfg| {
        cfg.peer_secrets.insert("peer-x".into(), [0x01u8; 32]);
        cfg.peer_secrets.insert("peer-y".into(), [0x02u8; 32]);
    })
    .await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/healthz", http_addr))
        .send()
        .await
        .expect("healthz failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["agent_id"], "agent-health2");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["inbox_depth"], 0);
    assert_eq!(body["inbox_capacity"], SIDECAR_INBOX_CAPACITY);
    assert_eq!(body["peers_configured"], 2);
}

/// Production-hardening regression proof #3: `max_concurrent_sends` is a real bound, not
/// just a config field — a send that's stuck (peer accepts but never responds) holds its
/// permit, and a concurrent second send observes saturation (`503`) rather than queuing
/// silently.
#[tokio::test]
async fn sidecar_send_saturation_returns_503() {
    // A "slow peer": accepts the TCP connection but never writes anything back, so the
    // sender's handshake read blocks — simulating a stuck/unresponsive peer without
    // needing to touch production code to inject an artificial delay.
    let slow_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = slow_listener.local_addr().unwrap();
    tokio::spawn(async move {
        if let Ok((stream, _)) = slow_listener.accept().await {
            // Deliberately never dropped/closed and never written to — keeps the
            // connection open with no response for the lifetime of this test process.
            std::mem::forget(stream);
        }
    });

    let (_saacp, http_addr) = spawn_sidecar_with("agent-slow", [0x44u8; 32], |cfg| {
        cfg.max_concurrent_sends = 1;
    })
    .await;

    let client = reqwest::Client::new();
    let body = serde_json::json!({
        "to_agent": "whoever",
        "target_addr": slow_addr.to_string(),
        "task": "will hang",
    });

    // Fire the first send in the background — it will hold the sole permit until its own
    // internal timeout, long after this test has finished its assertions.
    let bg_client = client.clone();
    let bg_url = format!("http://{}/send", http_addr);
    let bg_body = body.clone();
    tokio::spawn(async move {
        let _ = bg_client.post(bg_url).json(&bg_body).send().await;
    });

    // Give the first request a moment to actually acquire the permit and start blocking
    // in the handshake read.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let second = client
        .post(format!("http://{}/send", http_addr))
        .json(&body)
        .send()
        .await
        .expect("second send request failed");
    assert_eq!(second.status(), 503);
    let second_body: serde_json::Value = second.json().await.expect("second body json");
    assert_eq!(second_body["status"], "saturated", "body: {second_body}");
}

/// Command Center wiring regression proof: `/send` now logs a real
/// `[FAITF:DELEGATION]` audit entry via `ImmutableAuditLog::global()`
/// carrying the actual semantic recipient (`to_agent`), not the token's
/// internal bootstrap `"unknown"` placeholder — see `sidecar.rs::send_message`'s
/// wiring note and CLAUDE.md's "SAACP Command Center" section.
#[tokio::test]
async fn sidecar_send_logs_delegation_edge_with_real_target_agent() {
    let received: Arc<Mutex<Vec<AuditRecord>>> = Arc::new(Mutex::new(Vec::new()));
    let received2 = Arc::clone(&received);
    ImmutableAuditLog::global().subscribe(Arc::new(move |record: &AuditRecord| {
        received2.lock().unwrap().push(record.clone());
    }));

    let mesh_secret = [0x99u8; 32];
    let (_agent_a_saacp, agent_a_http) = spawn_sidecar("agent-delegator", mesh_secret).await;
    let (agent_b_saacp, _agent_b_http) = spawn_sidecar("agent-delegate-target", mesh_secret).await;

    let client = reqwest::Client::new();
    let send_resp = client
        .post(format!("http://{}/send", agent_a_http))
        .json(&serde_json::json!({
            "to_agent": "agent-delegate-target",
            "target_addr": agent_b_saacp.to_string(),
            "task": "delegated work",
        }))
        .send()
        .await
        .expect("send request failed");
    assert_eq!(send_resp.status(), 200);

    let recs = received.lock().unwrap();
    // Filter on OUR specific agent pair, not just the `[FAITF:DELEGATION]` prefix —
    // `ImmutableAuditLog::global()` is a process-wide singleton shared with every other
    // test in this binary, several of which run concurrently and log their own
    // delegation entries for their own agent pairs.
    let delegation = recs.iter()
        .find(|r| r.intent.starts_with("[FAITF:DELEGATION]") && r.source == "agent-delegator")
        .expect("expected a [FAITF:DELEGATION] audit entry for agent-delegator to have been logged");
    assert_eq!(delegation.source, "agent-delegator");
    assert_eq!(delegation.target, "agent-delegate-target");
    assert!(delegation.intent.contains("parent=agent-delegator"));
    assert!(delegation.intent.contains("child=agent-delegate-target"));
}
