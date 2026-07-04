//! saacp-sidecar — standalone local HTTP proxy for `saacp::sidecar`.
//!
//! Run one instance per agent. Configuration is via environment variables so the binary
//! itself carries no assumptions about deployment shape (systemd unit, container, plain
//! shell). See `src/sidecar.rs` for what each address/secret is used for.
//!
//! Environment variables:
//!   SAACP_AGENT_ID     — this sidecar's agent identity (required)
//!   SAACP_TOKEN_SECRET — base64-encoded 32-byte shared mesh secret (required)
//!   SAACP_LISTEN_ADDR  — address the real SAACP protocol listener binds
//!                        (default: 127.0.0.1:7443)
//!   SAACP_HTTP_ADDR    — address the local plain-HTTP/JSON API binds
//!                        (default: 127.0.0.1:8787)

use std::net::SocketAddr;

use saacp::sidecar::{run, SidecarConfig};

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_token_secret(raw: &str) -> [u8; 32] {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .unwrap_or_else(|e| panic!("SAACP_TOKEN_SECRET is not valid base64: {e}"));
    <[u8; 32]>::try_from(bytes.as_slice())
        .unwrap_or_else(|_| panic!("SAACP_TOKEN_SECRET must decode to exactly 32 bytes"))
}

#[tokio::main]
async fn main() {
    let agent_id = std::env::var("SAACP_AGENT_ID")
        .unwrap_or_else(|_| panic!("SAACP_AGENT_ID environment variable is required"));
    let token_secret_raw = std::env::var("SAACP_TOKEN_SECRET")
        .unwrap_or_else(|_| panic!("SAACP_TOKEN_SECRET environment variable is required"));
    let token_issuer_secret = parse_token_secret(&token_secret_raw);

    let saacp_listen_addr: SocketAddr = env_or("SAACP_LISTEN_ADDR", "127.0.0.1:7443")
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_LISTEN_ADDR: {e}"));
    let http_listen_addr: SocketAddr = env_or("SAACP_HTTP_ADDR", "127.0.0.1:8787")
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_HTTP_ADDR: {e}"));

    run(SidecarConfig {
        agent_id,
        token_issuer_secret,
        saacp_listen_addr,
        http_listen_addr,
    }).await;
}
