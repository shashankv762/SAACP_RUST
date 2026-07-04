//! test_sidecar_rs.rs — end-to-end test of the sidecar HTTP proxy (`src/sidecar.rs`).
//!
//! Two in-process sidecars, driven purely through plain HTTP/JSON (as a Python agent
//! would), with a real loopback TCP connection + real X25519 ECDH + real AES-256-GCM +
//! real HMAC capability-token verification underneath — proving the Python-facing surface
//! actually rides on the Phase-0 daemon fixes end to end, not just that the HTTP routes
//! exist.

use std::net::SocketAddr;
use std::time::Duration;

use saacp::sidecar::{run, SidecarConfig};

async fn free_addr() -> SocketAddr {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Spawn a sidecar on two fresh ephemeral ports (SAACP protocol + local HTTP API) and give
/// it a moment to bind before returning.
async fn spawn_sidecar(agent_id: &str, secret: [u8; 32]) -> (SocketAddr, SocketAddr) {
    let saacp_addr = free_addr().await;
    let http_addr = free_addr().await;
    let config = SidecarConfig {
        agent_id: agent_id.to_string(),
        token_issuer_secret: secret,
        saacp_listen_addr: saacp_addr,
        http_listen_addr: http_addr,
    };
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
