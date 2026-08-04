//! saacp-sidecar — standalone local HTTP proxy for `saacp::sidecar`.
//!
//! Run one instance per agent. Configuration is via environment variables so the binary
//! itself carries no assumptions about deployment shape (systemd unit, container, plain
//! shell). See `src/sidecar.rs` for what each address/secret is used for.
//!
//! ## Choosing an authentication mode (read this first)
//!
//! Capability tokens are authenticated with symmetric HMAC, so **whoever can verify a
//! token can also mint one**. That makes the choice between the two modes below a
//! security decision, not a deployment convenience:
//!
//! - **Per-peer secrets (`SAACP_PEER_SECRETS_FILE`) — recommended.** Each peer gets its
//!   own pairwise secret, so compromising one sidecar does not let the attacker forge
//!   messages from any *other* agent in the mesh. Registering any peer makes the registry
//!   authoritative: unknown issuers are hard-rejected with no shared-secret fallback.
//! - **Single shared mesh secret (`SAACP_TOKEN_SECRET`) — v1 default, weakest.** One
//!   32-byte value is held by *every* sidecar in the mesh. Any one of them (or anyone who
//!   reads the secret from any one host) can impersonate any agent, and the audit trail
//!   cannot distinguish the real sender from the forger. This is exactly the
//!   "every verifier can also forge" property Ed25519 was adopted in the core to
//!   eliminate. Acceptable only for single-tenant dev/test meshes where every peer is
//!   already fully trusted.
//!
//! Running on the shared secret with no per-peer entries logs a startup warning. Set
//! `SAACP_REQUIRE_PEER_SECRETS=1` to make that configuration a hard startup failure
//! instead — the fail-closed posture for production.
//!
//! Environment variables:
//!   SAACP_AGENT_ID            — this sidecar's agent identity (required)
//!   SAACP_TOKEN_SECRET        — base64-encoded 32-byte shared mesh secret (required
//!                               unless SAACP_TOKEN_SECRET_FILE is set). Shared by every
//!                               sidecar in the mesh, so any holder can forge any
//!                               agent's messages — see the mode comparison above.
//!   SAACP_TOKEN_SECRET_FILE   — path to a file containing the base64 secret instead of
//!                               passing it directly via env (avoids the secret being
//!                               visible via /proc/<pid>/environ or process listings).
//!                               Takes precedence over SAACP_TOKEN_SECRET if both are set.
//!   SAACP_PEER_SECRETS_FILE   — RECOMMENDED. Path to a JSON file
//!                               {"peer-agent-id": "<base64 32 bytes>", ...} of pairwise
//!                               per-peer secrets (see sidecar.rs's "per-peer issuer
//!                               secrets" doc section). Confines forgery to a single
//!                               compromised pair instead of the whole mesh. Omitted =
//!                               the weaker single-shared-secret mode.
//!   SAACP_REQUIRE_PEER_SECRETS=1 — refuse to start unless SAACP_PEER_SECRETS_FILE
//!                               supplies at least one peer. Turns the shared-secret
//!                               warning into a hard failure (fail-closed).
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
//!   SAACP_HTTP_TOKEN_OUT_FILE — path this binary WRITES a freshly generated bearer
//!                               token to when none was supplied (S-5). Enables the
//!                               auto-generate path below; the co-located agent reads
//!                               the token from this file. Never exposed over HTTP.
//!   SAACP_ALLOW_UNAUTHENTICATED_HTTP=1 — opt out of S-5 auto-generation and run the
//!                               loopback API with no auth at all (pre-S-5 behavior).
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
/// empty map = the weaker single-shared-secret mode (see this module's doc).
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

/// SC-1: a mesh running on one shared symmetric secret gives every sidecar the power to
/// forge every other agent's messages — the exact "every verifier can also forge"
/// property the core adopted Ed25519 to eliminate. `SAACP_PEER_SECRETS_FILE` is the real
/// fix, so an operator who hasn't configured it must be told, on the default path,
/// rather than discovering it buried in a hardening section.
///
/// `SAACP_REQUIRE_PEER_SECRETS=1` upgrades that warning to a hard startup failure, which
/// is the correct posture for a production mesh: fail closed instead of silently running
/// mesh-wide-forgeable.
fn enforce_peer_secret_posture(peer_secrets: &HashMap<String, [u8; 32]>, agent_id: &str) {
    if !peer_secrets.is_empty() {
        return;
    }
    let required = matches!(
        std::env::var("SAACP_REQUIRE_PEER_SECRETS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE")
    );
    if required {
        panic!(
            "SAACP_REQUIRE_PEER_SECRETS is set but no per-peer secrets were supplied — \
             refusing to start '{agent_id}' on a single shared mesh secret, where any \
             sidecar in the mesh can forge messages from any agent. Set \
             SAACP_PEER_SECRETS_FILE to a JSON map of per-peer pairwise secrets."
        );
    }
    eprintln!(
        "[saacp-sidecar] WARNING: '{agent_id}' is running on the single shared mesh \
         secret (SAACP_TOKEN_SECRET). Capability tokens are symmetric-HMAC, so EVERY \
         sidecar holding this secret can forge messages from ANY agent, and the audit \
         trail cannot tell a forgery from the real sender. Set SAACP_PEER_SECRETS_FILE \
         to give each peer its own pairwise secret, or SAACP_REQUIRE_PEER_SECRETS=1 to \
         make this configuration a hard startup failure."
    );
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

/// S-5 fix: generate a fresh 32-byte hex bearer token and write it to `path` so a
/// co-located agent (same UID) can read it. On POSIX the file is created 0600 via
/// `OpenOptions::mode`, so the window where it exists with looser permissions never
/// occurs; on Windows it inherits the directory ACL (POSIX mode bits are not honored
/// there, so the operator is responsible for the directory's ACL).
///
/// The token is deliberately NOT published on `/healthz`: that route is intentionally
/// unauthenticated (see `sidecar.rs::require_bearer_auth`), and S-5's stated threat is
/// exactly "any local process on the same host" — serving the token there would hand it
/// to the attacker it defends against. A file gated on UID is what opusplan2.md §3 (S-5)
/// prescribes.
fn generate_and_write_http_token(path: &str) -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let token = hex::encode(raw);

    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts
        .open(path)
        .unwrap_or_else(|e| panic!("failed to open SAACP_HTTP_TOKEN_OUT_FILE '{path}': {e}"));
    {
        use std::io::Write;
        f.write_all(token.as_bytes())
            .unwrap_or_else(|e| panic!("failed to write SAACP_HTTP_TOKEN_OUT_FILE '{path}': {e}"));
        f.flush()
            .unwrap_or_else(|e| panic!("failed to flush SAACP_HTTP_TOKEN_OUT_FILE '{path}': {e}"));
    }
    token
}

#[tokio::main]
async fn main() {
    let agent_id = std::env::var("SAACP_AGENT_ID")
        .unwrap_or_else(|_| panic!("SAACP_AGENT_ID environment variable is required"));
    let token_issuer_secret = read_token_secret();
    let peer_secrets = read_peer_secrets();
    enforce_peer_secret_posture(&peer_secrets, &agent_id);

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
    let mut http_bearer_token = read_http_bearer_token();
    if !http_listen_addr.ip().is_loopback() && http_bearer_token.is_none() {
        panic!(
            "SAACP_HTTP_ADDR binds non-loopback address {http_listen_addr} but no \
             SAACP_HTTP_BEARER_TOKEN(_FILE) is set — refusing to expose an \
             unauthenticated message-issuance API. Set a bearer token or bind loopback."
        );
    }

    // S-5 fix: previously a loopback bind with no token supplied ran the local API
    // fully unauthenticated, so ANY same-host process could issue messages as this
    // agent and drain its inbox. When the operator names an output path we now
    // generate a token and write it there for the co-located agent to read, closing
    // that gap without breaking the managed-spawn path (sidecar_manager.py supplies
    // SAACP_HTTP_BEARER_TOKEN_FILE itself, so this branch never fires for it).
    //
    // Not unconditional: with no output path there is nowhere to publish the token,
    // so auto-generating one would lock out every existing hand-started agent with no
    // way to authenticate. Instead the unauthenticated case warns loudly and remains
    // opt-out-able, matching opusplan2.md Open Question #3's deprecation-path concern.
    if http_bearer_token.is_none() {
        let opted_out = std::env::var("SAACP_ALLOW_UNAUTHENTICATED_HTTP")
            .map(|v| v == "1")
            .unwrap_or(false);
        match std::env::var("SAACP_HTTP_TOKEN_OUT_FILE") {
            Ok(path) if !path.trim().is_empty() => {
                http_bearer_token = Some(generate_and_write_http_token(path.trim()));
                eprintln!(
                    "[saacp-sidecar] no bearer token supplied — generated one and wrote it \
                     to {} (S-5). The co-located agent must send it as `Authorization: Bearer`.",
                    path.trim()
                );
            }
            _ if !opted_out => {
                eprintln!(
                    "[saacp-sidecar] WARNING: the local HTTP API on {http_listen_addr} is \
                     running UNAUTHENTICATED — any process on this host can issue messages \
                     as '{agent_id}' and drain its inbox (opusplan2.md S-5). Set \
                     SAACP_HTTP_BEARER_TOKEN(_FILE), or SAACP_HTTP_TOKEN_OUT_FILE to have one \
                     generated. Set SAACP_ALLOW_UNAUTHENTICATED_HTTP=1 to silence this."
                );
            }
            _ => {}
        }
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
            })
            .with_custom("revoked_tokens_global", || {
                // S-2 fix: reclaim individually-revoked token entries whose bound
                // token has expired. An expired token can't pass Gate 1.0's expiry
                // check anyway, so its revocation record is dead weight past `exp`.
                // Without this sweep the set only ever grows (see gateway.rs
                // `revoked_tokens` doc). Same global-singleton wiring rationale as
                // the four sweepers above.
                let _ = saacp::gateway::ZeroTrustGateway::global().prune_expired_revocations();
            })
            // Drop an installed injection rule pack once its `valid_until` passes.
            // The sidecar exposes no `/api/rules/reload` route, so no pack can be
            // pushed *here* today — but `RulePackStore` is a process-global, and
            // anything that installs one in-process (embedding this binary's
            // modules, or a future sidecar reload route) would otherwise keep an
            // expired pack active forever, since expiry is swept and never checked
            // on the scan path. Registering it unconditionally costs one atomic
            // load per 60s cycle when no pack is installed.
            .with_rulepack();
        if mace_enabled {
            coordinator.with_custom("mace_global", saacp::mace::sweep_and_enforce)
        } else {
            coordinator
        }
    });
    let _maintenance_handle = Arc::clone(&maintenance).start();

    run_with_shutdown(config, tokio_util::sync::CancellationToken::new()).await;
}
