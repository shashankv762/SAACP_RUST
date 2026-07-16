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
//!   SAACP_HTTP_BEARER_TOKEN   — optional bearer token required on every
//!                               /send and /receive request (constant-time
//!                               compared). REQUIRED when SAACP_HTTP_ADDR binds a
//!                               non-loopback interface — the binary refuses to
//!                               start an unauthenticated message-issuance API on
//!                               a reachable address.
//!   SAACP_HTTP_BEARER_TOKEN_FILE — path to a file containing the bearer token
//!                               instead of passing it via env (same secret-
//!                               hygiene pattern as SAACP_TOKEN_SECRET_FILE).
//!                               Takes precedence over SAACP_HTTP_BEARER_TOKEN.
//!   SAACP_MAX_CONCURRENT_SENDS — bound on concurrent outbound /send dispatches
//!                               (default: SIDECAR_DEFAULT_MAX_CONCURRENT_SENDS)
//!   SAACP_SEND_RETRY_ATTEMPTS — retries for a transient TCP-connect failure only
//!                               (default: SIDECAR_DEFAULT_SEND_RETRY_ATTEMPTS)

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use saacp::maintenance::MaintenanceCoordinator;
use saacp::sidecar::{run_with_shutdown, SidecarConfig};

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

/// Bearer token for the local HTTP API. `SAACP_HTTP_BEARER_TOKEN_FILE` (if set)
/// takes precedence over `SAACP_HTTP_BEARER_TOKEN`. Returns `None` when neither
/// is set. Any surrounding whitespace is trimmed; an empty value is treated as
/// unset so a blank env var can't silently disable auth with a token that
/// matches the empty string.
fn read_http_bearer_token() -> Option<String> {
    let raw = if let Ok(path) = std::env::var("SAACP_HTTP_BEARER_TOKEN_FILE") {
        std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("failed to read SAACP_HTTP_BEARER_TOKEN_FILE '{path}': {e}"))
    } else {
        std::env::var("SAACP_HTTP_BEARER_TOKEN").unwrap_or_default()
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
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

    // Fail closed: the local HTTP/JSON API can issue outbound messages and drain
    // this agent's inbox, so it must never be reachable from off-host without
    // authentication. If the operator binds a non-loopback interface, a bearer
    // token is mandatory. On loopback (the default) it stays optional, matching
    // the library's opt-in default for the co-located-agent case.
    let http_bearer_token = read_http_bearer_token();
    if !http_listen_addr.ip().is_loopback() && http_bearer_token.is_none() {
        panic!(
            "SAACP_HTTP_ADDR binds non-loopback address {http_listen_addr} but no \
             SAACP_HTTP_BEARER_TOKEN(_FILE) is set — refusing to expose an \
             unauthenticated message-issuance API. Set a bearer token or bind loopback."
        );
    }

    let mut config = SidecarConfig::new(agent_id, token_issuer_secret, saacp_listen_addr, http_listen_addr);
    config.peer_secrets = peer_secrets;
    config.http_bearer_token = http_bearer_token;
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

    // R-6 fix: same rationale as `saacp_command_center.rs`'s identical wiring — this
    // binary's inner `SAACPNetworkDaemon` (constructed inside `sidecar::run_with_shutdown`)
    // drives packets through the same `handler.rs` gate pipeline, which mutates the same
    // process-wide `TrustDecayEngine`/`FederatedMemory`/`StreamRegistry`/`IevlEngine`
    // `::global()` singletons. See that binary's comment for why these are wired via
    // `with_custom` closures reaching `T::global()` directly rather than
    // `with_trust_decay`/etc. (which require an owned `Arc<T>` this process never has).
    // Multi-Agent Collusion Detection (MACE, Part 8.2) — opt-in via
    // `SAACP_ENABLE_MACE=1`. `activate()` subscribes the global engine to the
    // live alert feed (so real gate rejections populate Sybil fingerprints and
    // the Coordinated-Exhaustion window) and flips its enabled flag; the
    // registered `mace_global` sweeper then runs the detectors + enforcement
    // every cycle off the packet path. Left off by default so deployments that
    // never opt in get zero MACE observation or background work.
    let mace_enabled = matches!(
        std::env::var("SAACP_ENABLE_MACE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    );
    if mace_enabled {
        saacp::mace::activate();
    }

    let maintenance = Arc::new({
        let coordinator = MaintenanceCoordinator::new()
            .with_custom("trust_decay_global", || {
                let _ = saacp::trust_decay::TrustDecayEngine::global().sweep_stale();
            })
            .with_custom("federated_memory_global", || {
                let _ = saacp::memory::FederatedMemory::global().evict_expired();
            })
            .with_custom("stream_registry_global", || {
                let _ = saacp::streaming::StreamRegistry::global().sweep_expired();
            })
            .with_custom("ievl_global", || {
                let _ = saacp::ievl::IevlEngine::global().sweep_expired();
            })
            .with_custom("dead_mans_switch_global", || {
                // Reap sessions whose heartbeat lapsed past DEAD_MAN_MAX_TIMEOUT.
                // Without this periodic sweep the switch tracks liveness (via the
                // handler's heartbeat registration) but never actually times a
                // dead session out — opusplan.md Phase 4 "Timeout: DeadMansSwitch
                // triggers session cleanup".
                let _ = saacp::temporal::DeadMansSwitch::global().check_timeouts();
            });
        if mace_enabled {
            coordinator.with_custom("mace_global", saacp::mace::sweep_and_enforce)
        } else {
            coordinator
        }
    });
    let _maintenance_handle = Arc::clone(&maintenance).start();

    run_with_shutdown(config, tokio_util::sync::CancellationToken::new()).await;
}
