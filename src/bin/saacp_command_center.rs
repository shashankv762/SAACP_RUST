// Same security invariant as the library crate: safe Rust only, enforced.
#![forbid(unsafe_code)]

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
//!   SAACP_CONFIG              — OPTIONAL path to a TOML configuration file
//!                               (`[command_center]` section; see
//!                               `saacp::config`). Every variable below can
//!                               be set there instead (names drop the
//!                               `SAACP_` prefix); the dashboard secret may
//!                               only be referenced via `dashboard_token_file`.
//!                               An env var, when set, always overrides the
//!                               file value. Unset ⇒ identical behavior to
//!                               pre-file releases.
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
//!   SAACP_DEMO_MODE            — set to "1" to ENABLE the demo SAACPNetworkDaemon
//!                               + synthetic activity generator (OPT-IN since
//!                               v0.2.1; the demo used to be default-on, which
//!                               let synthetic data masquerade as real telemetry)
//!   SAACP_DISABLE_DEMO_DAEMON  — legacy force-off switch: set to "1" to skip the
//!                               demo SAACPNetworkDaemon (wins over SAACP_DEMO_MODE)
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
use saacp::config::{resolve, resolve_flag, SaacpConfig};
use saacp::daemon::SAACPNetworkDaemon;
use saacp::maintenance::MaintenanceCoordinator;

/// Plan item 3: typed configuration errors for the command-center
/// binary. Mirror of `saacp_sidecar::SidecarConfigError` with the
/// variants this binary actually exercises. Same non-leak guarantee
/// for `Display` — no raw secret / file body in the rendered message.
#[allow(dead_code)]
#[derive(Debug)]
enum CommandCenterConfigError {
    /// A required env var was missing at startup.
    MissingEnv {
        var: &'static str,
        hint: &'static str,
    },
    /// A token could not be base64-decoded.
    InvalidBase64 {
        var: &'static str,
        source: base64::DecodeError,
    },
    /// A token was not exactly 32 bytes after decoding.
    WrongSecretLength { var: &'static str, got: usize },
    /// A file (e.g. rulepack key file, dashboard-token file) could not
    /// be read.
    FileRead {
        path: String,
        source: std::io::Error,
    },
}

impl std::fmt::Display for CommandCenterConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEnv { var, hint } => {
                write!(f, "missing required environment variable {var}: {hint}")
            }
            Self::InvalidBase64 { var, .. } => {
                // Omit the decode-error source: base64 includes byte
                // offsets into the input, which is a credential leak
                // vector if the malformed value was a partial secret.
                write!(
                    f,
                    "{var} is not valid base64 (rejected without printing the input)"
                )
            }
            Self::WrongSecretLength { var, got } => {
                write!(f, "{var} must decode to exactly 32 bytes, got {got}")
            }
            Self::FileRead { path, source } => write!(f, "failed to read {path:?}: {source}"),
        }
    }
}

impl std::error::Error for CommandCenterConfigError {}

/// Print the error to stderr and exit with status 1.
fn config_error_exit(err: CommandCenterConfigError) -> ! {
    tracing::error!(error = %err, "saacp-command-center startup failed");
    eprintln!("[saacp-command-center] startup failed: {err}");
    std::process::exit(1);
}

/// M-G remediation (production audit R7/G6): the demo daemon + synthetic
/// activity generator are OPT-IN since v0.2.1 — they were default-on, so an
/// operator using the dashboard as an ops console could mistake synthetic
/// telemetry for real data. `env_demo`/`toml_demo` opt in; the legacy
/// `SAACP_DISABLE_DEMO_DAEMON` switch (env or TOML) still forces the demo
/// off and wins, preserving its meaning for existing deployments.
fn demo_mode_enabled(
    env_demo: Option<String>,
    env_disable: Option<String>,
    toml_demo: Option<bool>,
    toml_disable: Option<bool>,
) -> bool {
    let force_off = matches!(env_disable.as_deref(), Some("1")) || toml_disable == Some(true);
    if force_off {
        return false;
    }
    matches!(env_demo.as_deref(), Some("1") | Some("true") | Some("TRUE"))
        || toml_demo == Some(true)
}

fn parse_secret_with_var(
    raw: &str,
    var: &'static str,
) -> Result<[u8; 32], CommandCenterConfigError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|source| CommandCenterConfigError::InvalidBase64 { var, source })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| {
        CommandCenterConfigError::WrongSecretLength {
            var,
            got: bytes.len(),
        }
    })
}

fn read_dashboard_token(cfg: &SaacpConfig) -> Result<[u8; 32], CommandCenterConfigError> {
    use zeroize::Zeroizing;
    let path = match std::env::var("SAACP_DASHBOARD_TOKEN_FILE")
        .ok()
        .or_else(|| cfg.command_center.dashboard_token_file.clone())
    {
        Some(p) => p,
        None => {
            return parse_env_dashboard_token();
        }
    };
    let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|source| {
        CommandCenterConfigError::FileRead {
            path: path.clone(),
            source,
        }
    })?);
    parse_secret_with_var(raw.trim(), "SAACP_DASHBOARD_TOKEN_FILE")
}

fn parse_env_dashboard_token() -> Result<[u8; 32], CommandCenterConfigError> {
    use zeroize::Zeroizing;
    tracing::warn!(
        "dashboard token read from the SAACP_DASHBOARD_TOKEN environment variable — prefer \
         SAACP_DASHBOARD_TOKEN_FILE in production (process environments are readable via \
         /proc/<pid>/environ by same-user processes)."
    );
    let raw = Zeroizing::new(std::env::var("SAACP_DASHBOARD_TOKEN").map_err(|_| {
        CommandCenterConfigError::MissingEnv {
            var: "SAACP_DASHBOARD_TOKEN",
            hint: "set SAACP_DASHBOARD_TOKEN (or SAACP_DASHBOARD_TOKEN_FILE, or \
                   command_center.dashboard_token_file in the SAACP_CONFIG file) to a \
                   base64-encoded 32-byte secret. The command center refuses to start \
                   without one — see the binary's module doc for details.",
        }
    })?);
    parse_secret_with_var(&raw, "SAACP_DASHBOARD_TOKEN")
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
fn provision_rulepack_anchor(cfg: &SaacpConfig) {
    let issuer = resolve(
        "SAACP_RULEPACK_ISSUER",
        cfg.command_center.rulepack_issuer.as_deref(),
    );
    let key_hex = resolve(
        "SAACP_RULEPACK_KEY",
        cfg.command_center.rulepack_key.as_deref(),
    );
    let (Some(issuer), Some(key_hex)) = (issuer, key_hex) else {
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
    // Plan item 2c: structured logging (idempotent). See `src/logging.rs`.
    saacp::logging::init_logging(saacp::logging::LogConfig::default());

    // §2.4 mitigation: load the optional TOML config file (SAACP_CONFIG) once,
    // validated, before anything binds. `default()` (env unset) is behavior-
    // identical to pre-file releases.
    let bin_cfg = match SaacpConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[saacp-command-center] startup failed: {e}");
            std::process::exit(1);
        }
    };
    if matches!(std::env::var("SAACP_CONFIG").as_deref(), Ok(p) if !p.trim().is_empty()) {
        eprintln!(
            "[SAACP Command Center] config file posture: {}",
            bin_cfg.redacted_summary()
        );
    }

    let dashboard_token = match read_dashboard_token(&bin_cfg) {
        Ok(t) => t,
        Err(e) => config_error_exit(e),
    };
    provision_rulepack_anchor(&bin_cfg);

    let listen_addr: SocketAddr = resolve(
        "SAACP_COMMAND_CENTER_ADDR",
        bin_cfg.command_center.listen_addr.as_deref(),
    )
    .unwrap_or_else(|| "127.0.0.1:9090".into())
    .parse()
    .unwrap_or_else(|e| panic!("invalid SAACP_COMMAND_CENTER_ADDR: {e}"));

    let mut config = CommandCenterConfig::new(listen_addr, dashboard_token);
    if let Some(v) = resolve(
        "SAACP_DOLLARS_PER_TOKEN",
        bin_cfg
            .command_center
            .dollars_per_token
            .map(|d| d.to_string())
            .as_deref(),
    ) {
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
    } else if let Some(origins) = &bin_cfg.command_center.dashboard_allowed_origins {
        // Env-unset + file-provided: same exact-match list semantics, trimmed.
        config.allowed_origins = origins
            .iter()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    // M-G remediation (production audit R7/G6): the demo daemon + synthetic
    // activity generator are now OPT-IN. They were default-on, so an operator
    // using the dashboard as an ops console saw synthetic data mistaken for
    // real telemetry. Enable explicitly with SAACP_DEMO_MODE=1 (or
    // `[command_center] demo_mode = true` in the SAACP_CONFIG file);
    // SAACP_DISABLE_DEMO_DAEMON=1 (and the config field of the same name)
    // still force the demo off and win over the opt-in.
    let demo_enabled = demo_mode_enabled(
        std::env::var("SAACP_DEMO_MODE").ok(),
        std::env::var("SAACP_DISABLE_DEMO_DAEMON").ok(),
        bin_cfg.command_center.demo_mode,
        bin_cfg.command_center.disable_demo_daemon,
    );
    if demo_enabled {
        let demo_addr: SocketAddr = resolve(
            "SAACP_DEMO_DAEMON_ADDR",
            bin_cfg.command_center.demo_daemon_addr.as_deref(),
        )
        .unwrap_or_else(|| "127.0.0.1:7444".into())
        .parse()
        .unwrap_or_else(|e| panic!("invalid SAACP_DEMO_DAEMON_ADDR: {e}"));
        let daemon = SAACPNetworkDaemon::new(&demo_addr.ip().to_string(), demo_addr.port(), None);
        tokio::spawn(async move {
            let _ = daemon.start().await;
        });
        eprintln!("[SAACP Command Center] Demo daemon listening on {demo_addr} (set SAACP_DEMO_MODE=0 or unset to disable)");

        // A listening daemon with no client connecting to it generates zero packets, so the
        // gate pipeline never runs and every dashboard panel stays (correctly) empty — which
        // read as "the dashboard is broken". Drive synthetic activity through the same global
        // engines a real gateway drives so the panels populate out of the box. This is
        // demo-only, OPT-IN since v0.2.1 (M-G), and shares the force-off switch.
        tokio::spawn(saacp::command_center_demo::run());
        eprintln!("[SAACP Command Center] Demo activity generator started (feeds live agents, mesh, alerts, financial)");
    } else {
        eprintln!(
            "[SAACP Command Center] Demo daemon DISABLED (default since v0.2.1 — set \
             SAACP_DEMO_MODE=1 to enable the synthetic demo). Point the dashboard at a \
             real gateway process for live data."
        );
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
    let mace_enabled = resolve_flag("SAACP_ENABLE_MACE", bin_cfg.command_center.enable_mace);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// M-G regression: the demo is OFF by default and requires an explicit
    /// opt-in through either channel; the legacy force-off switch wins over
    /// the opt-in.
    #[test]
    fn demo_mode_is_opt_in() {
        let none: Option<String> = None;
        // Default posture (no env, no TOML): OFF.
        assert!(!demo_mode_enabled(none.clone(), None, None, None));
        // Explicit opt-in via env or TOML enables it.
        assert!(demo_mode_enabled(Some("1".into()), None, None, None));
        assert!(demo_mode_enabled(Some("true".into()), None, None, None));
        assert!(demo_mode_enabled(none.clone(), None, Some(true), None));
        // The legacy force-off switch wins over the opt-in (both channels).
        assert!(!demo_mode_enabled(
            Some("1".into()),
            Some("1".into()),
            Some(true),
            None
        ));
        assert!(!demo_mode_enabled(
            Some("1".into()),
            None,
            Some(true),
            Some(true)
        ));
        // Any other env value is not an opt-in ("0", garbage).
        assert!(!demo_mode_enabled(Some("0".into()), None, None, None));
        assert!(!demo_mode_enabled(Some("yes".into()), None, None, None));
    }
}
