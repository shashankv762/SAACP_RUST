//! saacp-sidecar — standalone local HTTP proxy for `saacp::sidecar`.
//!
//! Run one instance per agent. Configuration is via environment variables so the binary
//! itself carries no assumptions about deployment shape (systemd unit, container, plain
//! shell). See `src/sidecar.rs` for what each address/secret is used for.
//!
//! Environment variables:
//!   SAACP_AGENT_ID            — this sidecar's agent identity (required)
//!   SAACP_TOKEN_SECRET        — base64-encoded 32-byte shared mesh secret (required
//!                               unless SAACP_TOKEN_SECRET_FILE is set)
//!   SAACP_TOKEN_SECRET_FILE   — path to a file containing the base64 secret instead of
//!                               passing it directly via env (avoids the secret being
//!                               visible via /proc/<pid>/environ or process listings).
//!                               Takes precedence over SAACP_TOKEN_SECRET if both are set.
//!   SAACP_PEER_SECRETS_FILE   — optional path to a JSON file
//!                               {"peer-agent-id": "<base64 32 bytes>", ...} of pairwise
//!                               per-peer secrets (see sidecar.rs's "per-peer issuer
//!                               secrets" doc section). Omitted = today's single-shared-
//!                               secret mesh, unchanged.
//!   SAACP_LISTEN_ADDR         — address the real SAACP protocol listener binds
//!                               (default: 127.0.0.1:7443)
//!   SAACP_HTTP_ADDR           — address the local plain-HTTP/JSON API binds
//!                               (default: 127.0.0.1:8787)
//!   SAACP_MAX_CONCURRENT_SENDS — bound on concurrent outbound /send dispatches
//!                               (default: SIDECAR_DEFAULT_MAX_CONCURRENT_SENDS)
//!   SAACP_SEND_RETRY_ATTEMPTS — retries for a transient TCP-connect failure only
//!                               (default: SIDECAR_DEFAULT_SEND_RETRY_ATTEMPTS)

use std::collections::HashMap;
use std::net::SocketAddr;

use saacp::sidecar::{run, SidecarConfig};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_token_secret(raw: &str) -> [u8; 32] {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .unwrap_or_else(|e| panic!("token secret is not valid base64: {e}"));
    <[u8; 32]>::try_from(bytes.as_slice())
        .unwrap_or_else(|_| panic!("token secret must decode to exactly 32 bytes"))
}

/// `SAACP_TOKEN_SECRET_FILE` (if set) takes precedence over `SAACP_TOKEN_SECRET` — lets an
/// operator keep the secret out of the process environment entirely.
fn read_token_secret() -> [u8; 32] {
    if let Ok(path) = std::env::var("SAACP_TOKEN_SECRET_FILE") {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read SAACP_TOKEN_SECRET_FILE '{path}': {e}"));
        return parse_token_secret(raw.trim());
    }
    let raw = std::env::var("SAACP_TOKEN_SECRET").unwrap_or_else(|_| {
        panic!("either SAACP_TOKEN_SECRET or SAACP_TOKEN_SECRET_FILE environment variable is required")
    });
    parse_token_secret(&raw)
}

/// Optional per-peer pairwise secrets — see `sidecar.rs`'s module doc. Absent env var =
/// empty map = today's single-shared-secret behavior, unchanged.
fn read_peer_secrets() -> HashMap<String, [u8; 32]> {
    let Ok(path) = std::env::var("SAACP_PEER_SECRETS_FILE") else {
        return HashMap::new();
    };
    let raw = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("failed to read SAACP_PEER_SECRETS_FILE '{path}': {e}"));
    let parsed: HashMap<String, String> = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("SAACP_PEER_SECRETS_FILE '{path}' is not valid JSON: {e}"));
    parsed
        .into_iter()
        .map(|(agent_id, secret_b64)| (agent_id, parse_token_secret(&secret_b64)))
        .collect()
}

#[tokio::main]
async fn main() {
    let agent_id = std::env::var("SAACP_AGENT_ID")
        .unwrap_or_else(|_| panic!("SAACP_AGENT_ID environment variable is required"));
    let token_issuer_secret = read_token_secret();
    let peer_secrets = read_peer_secrets();

    let saacp_listen_addr: SocketAddr = env_or("SAACP_LISTEN_ADDR", "127.0.0.1:7443")
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_LISTEN_ADDR: {e}"));
    let http_listen_addr: SocketAddr = env_or("SAACP_HTTP_ADDR", "127.0.0.1:8787")
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_HTTP_ADDR: {e}"));

    let mut config = SidecarConfig::new(agent_id, token_issuer_secret, saacp_listen_addr, http_listen_addr);
    config.peer_secrets = peer_secrets;
    if let Ok(v) = std::env::var("SAACP_MAX_CONCURRENT_SENDS") {
        config.max_concurrent_sends = v
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_MAX_CONCURRENT_SENDS: {e}"));
    }
    if let Ok(v) = std::env::var("SAACP_SEND_RETRY_ATTEMPTS") {
        config.send_retry_attempts = v
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_SEND_RETRY_ATTEMPTS: {e}"));
    }

    run(config).await;
}
