//! saacp-command-center — standalone dashboard backend for `saacp::command_center`.
//!
//! Runs the Command Center's REST+SSE HTTP API. By default it also stands up a bare,
//! in-process `SAACPNetworkDaemon` (unauthenticated handshake, same shape as running
//! `saacp-sidecar` with no gateway/encrypted-transport builders) purely so the dashboard
//! has some live traffic to show out of the box — set `SAACP_DISABLE_DEMO_DAEMON=1` to skip
//! this and run the dashboard alone against a real gateway process's shared global state
//! instead (see `command_center.rs`'s module doc: this dashboard is designed to run
//! **in-process** alongside a real gateway, not as a separate observer).
//!
//! Environment variables:
//!   SAACP_DASHBOARD_TOKEN       — base64-encoded 32-byte shared dashboard bearer secret
//!                                 (required unless SAACP_DASHBOARD_TOKEN_FILE is set)
//!   SAACP_DASHBOARD_TOKEN_FILE  — path to a file containing the base64 secret instead of
//!                                 passing it directly via env (same secret-hygiene pattern
//!                                 as saacp-sidecar's SAACP_TOKEN_SECRET_FILE). Takes
//!                                 precedence over SAACP_DASHBOARD_TOKEN if both are set.
//!   SAACP_COMMAND_CENTER_ADDR  — address the dashboard's HTTP API binds
//!                                 (default: 127.0.0.1:9090)
//!   SAACP_DOLLARS_PER_TOKEN    — override the illustrative $/token conversion used by
//!                                 /api/financial (default: COMMAND_CENTER_DEFAULT_DOLLARS_PER_TOKEN)
//!   SAACP_DISABLE_DEMO_DAEMON  — set to "1" to skip starting the demo SAACPNetworkDaemon
//!   SAACP_DEMO_DAEMON_ADDR     — address the demo daemon binds, if not disabled
//!                                 (default: 127.0.0.1:7444)

use std::net::SocketAddr;

use saacp::command_center::{run, CommandCenterConfig};
use saacp::daemon::SAACPNetworkDaemon;

fn env_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn parse_secret(raw: &str) -> [u8; 32] {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .unwrap_or_else(|e| panic!("dashboard token is not valid base64: {e}"));
    <[u8; 32]>::try_from(bytes.as_slice())
        .unwrap_or_else(|_| panic!("dashboard token must decode to exactly 32 bytes"))
}

/// `SAACP_DASHBOARD_TOKEN_FILE` (if set) takes precedence over
/// `SAACP_DASHBOARD_TOKEN` — same secret-hygiene pattern as `saacp-sidecar`.
fn read_dashboard_token() -> [u8; 32] {
    if let Ok(path) = std::env::var("SAACP_DASHBOARD_TOKEN_FILE") {
        let raw = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read SAACP_DASHBOARD_TOKEN_FILE '{path}': {e}"));
        return parse_secret(raw.trim());
    }
    let raw = std::env::var("SAACP_DASHBOARD_TOKEN").unwrap_or_else(|_| {
        panic!("either SAACP_DASHBOARD_TOKEN or SAACP_DASHBOARD_TOKEN_FILE environment variable is required")
    });
    parse_secret(&raw)
}

#[tokio::main]
async fn main() {
    let dashboard_token = read_dashboard_token();

    let listen_addr: SocketAddr = env_or("SAACP_COMMAND_CENTER_ADDR", "127.0.0.1:9090")
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_COMMAND_CENTER_ADDR: {e}"));

    let mut config = CommandCenterConfig::new(listen_addr, dashboard_token);
    if let Ok(v) = std::env::var("SAACP_DOLLARS_PER_TOKEN") {
        config.dollars_per_token = v
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_DOLLARS_PER_TOKEN: {e}"));
    }

    if std::env::var("SAACP_DISABLE_DEMO_DAEMON").as_deref() != Ok("1") {
        let demo_addr: SocketAddr = env_or("SAACP_DEMO_DAEMON_ADDR", "127.0.0.1:7444")
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_DEMO_DAEMON_ADDR: {e}"));
        let daemon = SAACPNetworkDaemon::new(&demo_addr.ip().to_string(), demo_addr.port(), None);
        tokio::spawn(async move { daemon.start().await; });
        eprintln!("[SAACP Command Center] Demo daemon listening on {demo_addr} (set SAACP_DISABLE_DEMO_DAEMON=1 to skip)");
    }

    run(config).await;
}
