//! saacp-command-center — standalone dashboard backend for `saacp::command_center`.
//!
//! Runs the Command Center's REST+SSE HTTP API. By default it also stands up a bare,
//! in-process `SAACPNetworkDaemon` (unauthenticated handshake, same shape as running
//! `saacp-sidecar` with no gateway/encrypted-transport builders) AND a synthetic activity
//! generator (`command_center_demo`) that drives live agents, trust-mesh edges, gate
//! rejections and Gate 0.5 financial blocks through the same process-wide global engines a
//! real gateway drives — so the dashboard's panels are populated out of the box instead of
//! showing (correct but alarming) empty state. Set `SAACP_DISABLE_DEMO_DAEMON=1` to skip
//! BOTH and run the dashboard alone against a real gateway process's shared global state
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
//!   SAACP_DASHBOARD_ALLOWED_ORIGINS — comma-separated exact-match browser Origin CORS
//!                                 allowlist (default: http://localhost:3000,
//!                                 http://127.0.0.1:3000). Set to empty to disable all
//!                                 cross-origin browser access (fail-closed).
//!   SAACP_RULEPACK_ISSUER      — issuer id signed rule packs must claim. Required
//!                                 (with SAACP_RULEPACK_KEY) to enable
//!                                 POST /api/rules/reload; unset ⇒ every push is
//!                                 refused with `no_trust_anchor`.
//!   SAACP_RULEPACK_KEY         — hex-encoded 32-byte Ed25519 PUBLIC key that must have
//!                                 signed any accepted rule pack. Read once at startup
//!                                 and never re-read: changing who may push injection
//!                                 rules requires a restart, by design.

use std::net::SocketAddr;
use std::sync::Arc;

use saacp::command_center::{run, CommandCenterConfig};
use saacp::daemon::SAACPNetworkDaemon;
use saacp::maintenance::MaintenanceCoordinator;

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

/// Provision the one Ed25519 key allowed to sign injection rule packs
/// (`rulepack.rs`), from `SAACP_RULEPACK_KEY` (hex, 32 bytes) plus
/// `SAACP_RULEPACK_ISSUER`. Both must be set or nothing is provisioned and
/// `POST /api/rules/reload` refuses every push with `no_trust_anchor` — the
/// fail-closed default, never "unconfigured means unrestricted".
///
/// Deliberately read exactly once here, at startup, and never re-read: the
/// authority over injection rules must require a full re-provisioning restart to
/// change, which is what makes hot-reloading the *rules* compatible with
/// Architecture Principle #3/#4 (see `rulepack.rs`'s module doc).
fn provision_rulepack_anchor() {
    let (Ok(issuer), Ok(key_hex)) = (
        std::env::var("SAACP_RULEPACK_ISSUER"),
        std::env::var("SAACP_RULEPACK_KEY"),
    ) else {
        eprintln!(
            "[SAACP Command Center] No rule-pack trust anchor configured \
             (set SAACP_RULEPACK_ISSUER + SAACP_RULEPACK_KEY to enable \
             POST /api/rules/reload); Gate 4.0 uses the built-in signature baseline"
        );
        return;
    };
    let bytes = hex::decode(key_hex.trim())
        .unwrap_or_else(|e| panic!("SAACP_RULEPACK_KEY is not valid hex: {e}"));
    let key_bytes = <[u8; 32]>::try_from(bytes.as_slice())
        .unwrap_or_else(|_| panic!("SAACP_RULEPACK_KEY must decode to exactly 32 bytes"));
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes)
        .unwrap_or_else(|e| panic!("SAACP_RULEPACK_KEY is not a valid Ed25519 public key: {e}"));

    saacp::rulepack::RulePackStore::global().provision_trust_anchor(&issuer, verifying_key);
    saacp::telemetry::global_telemetry()
        .set_rulepack_active_rules(saacp::handler::builtin_injection_patterns().len() as u64);
    eprintln!("[SAACP Command Center] Rule-pack trust anchor provisioned for issuer '{issuer}'");
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let dashboard_token = read_dashboard_token();
    provision_rulepack_anchor();

    let listen_addr: SocketAddr = env_or("SAACP_COMMAND_CENTER_ADDR", "127.0.0.1:9090")
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_COMMAND_CENTER_ADDR: {e}"));

    let mut config = CommandCenterConfig::new(listen_addr, dashboard_token);
    if let Ok(v) = std::env::var("SAACP_DOLLARS_PER_TOKEN") {
        config.dollars_per_token = v
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_DOLLARS_PER_TOKEN: {e}"));
    }

    // CORS: comma-separated exact-match browser Origin allowlist. Unset ⇒ keep the
    // built-in localhost:3000 / 127.0.0.1:3000 dev defaults; set-but-empty ⇒ an
    // explicit, fail-closed "no cross-origin browser access at all". Each entry is
    // trimmed and empties are dropped, so trailing commas / stray spaces are benign.
    if let Ok(v) = std::env::var("SAACP_DASHBOARD_ALLOWED_ORIGINS") {
        config.allowed_origins = v
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    if std::env::var("SAACP_DISABLE_DEMO_DAEMON").as_deref() != Ok("1") {
        let demo_addr: SocketAddr = env_or("SAACP_DEMO_DAEMON_ADDR", "127.0.0.1:7444")
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_DEMO_DAEMON_ADDR: {e}"));
        let daemon = SAACPNetworkDaemon::new(&demo_addr.ip().to_string(), demo_addr.port(), None);
        tokio::spawn(async move { let _ = daemon.start().await; });
        eprintln!("[SAACP Command Center] Demo daemon listening on {demo_addr} (set SAACP_DISABLE_DEMO_DAEMON=1 to skip)");

        // A listening daemon with no client connecting to it generates zero packets, so the
        // gate pipeline never runs and every dashboard panel stays (correctly) empty — which
        // read as "the dashboard is broken". Drive synthetic activity through the same global
        // engines a real gateway drives so the panels populate out of the box. This is
        // demo-only and shares the daemon's opt-out: run against a real gateway with
        // SAACP_DISABLE_DEMO_DAEMON=1 and no synthetic data is produced.
        tokio::spawn(saacp::command_center_demo::run());
        eprintln!("[SAACP Command Center] Demo activity generator started (feeds live agents, mesh, alerts, financial)");
    }

    // R-6 fix: the gate pipeline (`handler.rs`) processes packets through several
    // process-wide `::global()` singletons (`TrustDecayEngine`, `FederatedMemory`,
    // `StreamRegistry`, `ievl::IevlEngine`) whose bounded stores were previously only
    // reclaimed reactively — on the next capacity-triggered eviction inside whatever
    // packet happened to push a given shard over its cap, per each type's own doc
    // comment. `MaintenanceCoordinator` (opusplan.md Part 7 / 7.2 R-6) exists precisely
    // to run their `sweep_*`/`evict_expired` methods proactively on a shared 60s
    // cadence, but — matching `daemon.rs`'s own "opt-in, caller decides" convention
    // (see `SAACPNetworkDaemon::with_gossip_engine`'s doc comment) — it is never
    // auto-started by constructing a daemon, so a caller has to actually do this.
    // These four are wired via `with_custom` (not `with_trust_decay`/
    // `with_federated_memory`/`with_stream_registry`/`with_ievl`) because those
    // builders take an owned `Arc<T>` naming a caller-constructed instance, while the
    // real, live singletons the packet path actually mutates are `&'static T` behind
    // each type's own `OnceLock`-backed `::global()` — there is no way to obtain an
    // `Arc` aliasing that same process-wide instance, so a closure calling
    // `T::global().sweep_*()` directly is the only way to reach the state that matters.
    // Multi-Agent Collusion Detection (MACE, Part 8.2) — opt-in via
    // `SAACP_ENABLE_MACE=1`; see `saacp_sidecar.rs`'s identical wiring comment.
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
                // Reap sessions whose heartbeat lapsed past DEAD_MAN_MAX_TIMEOUT
                // (opusplan.md Phase 4 "Timeout: DeadMansSwitch triggers session
                // cleanup"); see saacp_sidecar.rs's identical wiring comment.
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
            // Drop an active signed rule pack once its `valid_until` passes, so a
            // pack signed with a since-rotated key stops applying without an
            // operator action. Cheap no-op when no pack is installed.
            .with_rulepack();
        if mace_enabled {
            coordinator.with_custom("mace_global", saacp::mace::sweep_and_enforce)
        } else {
            coordinator
        }
    });
    let _maintenance_handle = Arc::clone(&maintenance).start();

    run(config).await
}
