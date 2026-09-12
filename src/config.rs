//! Scoped file-based configuration for the two standalone binaries
//! (`saacp-sidecar`, `saacp-command-center`) — the §2.4 mitigation.
//!
//! ## Why this exists
//!
//! Both binaries grew to a few dozen `SAACP_*` environment variables. Env vars
//! alone scale poorly for fleet deployments: there is no single artifact to
//! review in a PR, no way to diff running posture against intended posture, and
//! every variable is visible via `/proc/<pid>/environ` to same-user processes.
//! This module adds an **optional** TOML file layered under the env vars.
//!
//! ## Precedence (load order)
//!
//! 1. `SaacpConfig::load()` reads `SAACP_CONFIG` (a file path). Unset or empty
//!    ⇒ the all-default config and **byte-identical behavior** to pre-file
//!    releases: no environment variable changes meaning, no default changes.
//! 2. The file is parsed once into typed sections (`sidecar`, `command_center`)
//!    and **validated once before any listener binds** (address parseability,
//!    numeric ranges, enum spellings).
//! 3. At each setting's read site, the environment variable — when set at all —
//!    **overrides** the file value (via [`resolve`] / [`resolve_flag`]). This
//!    keeps existing env-only deployments (systemd units, container env, k8s
//!    secrets) authoritative and makes the file the fallback baseline.
//!
//! ## Secret hygiene (deliberate restriction)
//!
//! Raw secret material (token secrets, bearer tokens, peer secret *contents*)
//! is **structurally impossible** to put in the TOML file: the sections expose
//! only `*_file` path fields (`token_secret_file`, `http_bearer_token_file`,
//! `dashboard_token_file`, `peer_secrets_file`), so the `*_FILE` indirection —
//! the S-8-recommended posture that keeps secrets out of the process
//! environment — is preserved, not weakened. The file's paths are the only
//! thing it can carry. [`redacted_summary`] prints the resolved posture at
//! startup without any secret material ever passing through it (none exists
//! here to begin with).
//!
//! Scope: consumed **only** by the two binaries' `main()`s. Library APIs are
//! unchanged; `SidecarConfig` / `CommandCenterConfig` (the library structs the
//! binaries construct) keep their existing semantics.

use std::borrow::Cow;
use std::net::SocketAddr;

use serde::Deserialize;

/// Typed failure for loading / parsing / validating the optional config file.
/// Carries the file path and the kind of failure — never file contents (which
/// can't hold secrets by construction, but a parse error quoting a whole
/// document into a log line is still noise an operator doesn't need).
#[derive(Debug)]
pub enum ConfigError {
    /// `SAACP_CONFIG` pointed at a file that could not be read.
    Unreadable {
        path: String,
        source: std::io::Error,
    },
    /// The file was readable but not valid TOML, or violated a section's
    /// shape (unknown key, wrong type — `deny_unknown_fields` is load-bearing
    /// here so a typo like `listen_adr` fails loudly instead of being
    /// silently ignored while the default binds).
    Parse {
        path: String,
        source: toml::de::Error,
    },
    /// The file parsed but failed startup validation (unparseable address,
    /// out-of-range numeric, unrecognized enum spelling). Fails closed before
    /// any listener binds.
    Validation { detail: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreadable { path, source } => {
                write!(f, "failed to read config file {path:?}: {source}")
            }
            Self::Parse { path, source } => {
                write!(f, "config file {path:?} is not valid TOML: {source}")
            }
            Self::Validation { detail } => write!(f, "config validation failed: {detail}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// File-backed configuration for both binaries. `default()` (what an absent
/// `SAACP_CONFIG` yields) is the all-`None` posture: every field falls back to
/// the exact same environment-variable / built-in default chain as before this
/// module existed.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SaacpConfig {
    #[serde(default)]
    pub sidecar: SidecarSection,
    #[serde(default)]
    pub command_center: CommandCenterSection,
}

/// `[sidecar]` section — consumed by `saacp_sidecar.rs`. Only `*_file` paths
/// may carry secret *references*; raw secret values have no field to land in
/// (see the module doc).
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct SidecarSection {
    pub agent_id: Option<String>,
    pub listen_addr: Option<String>,
    pub http_addr: Option<String>,
    pub handshake_mode: Option<String>,
    pub server_seed_file: Option<String>,
    pub peer_pins_file: Option<String>,
    pub peer_secrets_file: Option<String>,
    pub require_peer_secrets: Option<bool>,
    pub token_secret_file: Option<String>,
    pub http_bearer_token_file: Option<String>,
    pub http_token_out_file: Option<String>,
    pub allow_unauthenticated_http: Option<bool>,
    pub max_concurrent_sends: Option<u32>,
    pub send_retry_attempts: Option<u32>,
    pub enable_mpf: Option<bool>,
    pub enable_mace: Option<bool>,
    /// M2 remediation: path to a file containing a Redis URL (e.g.
    /// `rediss://user:pass@host:6379/`). The URL itself is secret material
    /// (may contain credentials), so only a file path is accepted — no raw
    /// URL in TOML or env. When set, the sidecar constructs a
    /// `RedisBackend` wrapped in `CircuitBreakerBackend`.
    pub state_backend_url_file: Option<String>,
}

/// `[command_center]` section — consumed by `saacp_command_center.rs`.
#[derive(Debug, Clone, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CommandCenterSection {
    pub listen_addr: Option<String>,
    pub dashboard_token_file: Option<String>,
    pub dollars_per_token: Option<f64>,
    pub disable_demo_daemon: Option<bool>,
    /// M-G remediation (v0.2.1): the demo daemon + synthetic activity
    /// generator are OPT-IN — set `demo_mode = true` (or `SAACP_DEMO_MODE=1`)
    /// to enable them. `disable_demo_daemon = true` still forces the demo
    /// off and wins over this field.
    pub demo_mode: Option<bool>,
    pub demo_daemon_addr: Option<String>,
    /// TOML-native array form of the CORS allowlist (the env var is the
    /// comma-separated form of the same list; the set-but-empty fail-closed
    /// env semantics are unchanged).
    pub dashboard_allowed_origins: Option<Vec<String>>,
    pub rulepack_issuer: Option<String>,
    /// Ed25519 *public* verifying key (hex) — not secret material; it is the
    /// trust anchor for signed rule packs and is printed by provisioning
    /// anyway.
    pub rulepack_key: Option<String>,
    pub enable_mace: Option<bool>,
}

impl SaacpConfig {
    /// Load the optional config file. Unset **or empty** `SAACP_CONFIG` ⇒
    /// `Ok(Self::default())` — identical to pre-file behavior.
    pub fn load() -> Result<Self, ConfigError> {
        if let Ok(path) = std::env::var("SAACP_CONFIG") {
            if !path.trim().is_empty() {
                return Self::from_file(path.trim());
            }
        }
        Ok(Self::default())
    }

    /// Parse + validate a config file from disk.
    pub fn from_file(path: &str) -> Result<Self, ConfigError> {
        let raw = std::fs::read_to_string(path).map_err(|source| ConfigError::Unreadable {
            path: path.to_string(),
            source,
        })?;
        Self::from_toml_str(path, &raw)
    }

    /// Parse + validate a TOML document (split out for testability).
    pub fn from_toml_str(path: &str, raw: &str) -> Result<Self, ConfigError> {
        let cfg: Self = toml::from_str(raw).map_err(|source| ConfigError::Parse {
            path: path.to_string(),
            source,
        })?;
        cfg.validate()?;
        Ok(cfg)
    }

    /// Startup validation — runs once in `load()`, before any listener binds,
    /// so a malformed file fails closed at startup rather than surfacing as a
    /// bind-time panic deep in `main()`. Spellings that the binaries' own
    /// parsers handle (handshake mode aliases) are re-checked here with the
    /// same accepted set so the failure happens before side effects.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let bad = |detail: String| Err(ConfigError::Validation { detail });
        for (name, addr) in [
            ("sidecar.listen_addr", self.sidecar.listen_addr.as_deref()),
            ("sidecar.http_addr", self.sidecar.http_addr.as_deref()),
            (
                "command_center.listen_addr",
                self.command_center.listen_addr.as_deref(),
            ),
            (
                "command_center.demo_daemon_addr",
                self.command_center.demo_daemon_addr.as_deref(),
            ),
        ] {
            if let Some(v) = addr {
                if v.parse::<SocketAddr>().is_err() {
                    return bad(format!("{name}={v:?} is not a valid host:port address"));
                }
            }
        }
        if let Some(v) = self.sidecar.handshake_mode.as_deref() {
            if parse_handshake_mode_str(v).is_none() {
                return bad(format!(
                    "sidecar.handshake_mode={v:?} is not one of LEGACY_ONLY | PREFER_PINNED | \
                     REQUIRE_PINNED (case-insensitive)"
                ));
            }
        }
        for (name, n) in [
            (
                "sidecar.max_concurrent_sends",
                self.sidecar.max_concurrent_sends,
            ),
            (
                "sidecar.send_retry_attempts",
                self.sidecar.send_retry_attempts,
            ),
        ] {
            if n == Some(0) {
                return bad(format!("{name} must be at least 1"));
            }
        }
        if let Some(d) = self.command_center.dollars_per_token {
            if !(d.is_finite()) || d <= 0.0 {
                return bad(format!(
                    "command_center.dollars_per_token={d} must be a positive finite number"
                ));
            }
        }
        // M2 remediation: reject an explicitly-set but empty URL file path.
        if let Some(ref path) = self.sidecar.state_backend_url_file {
            if path.trim().is_empty() {
                return bad(
                    "sidecar.state_backend_url_file must not be empty when set".to_string(),
                );
            }
        }
        Ok(())
    }

    /// One-line startup dump of the resolved file posture. By construction
    /// this can never contain secret material — the sections have no fields
    /// for raw secrets, only `*_file` paths — so printing values verbatim is
    /// safe and gives operators a diffable record of the intended posture.
    pub fn redacted_summary(&self) -> String {
        fn fmt_bool(v: Option<bool>) -> String {
            v.map(|b| b.to_string()).unwrap_or_else(|| "unset".into())
        }
        let mut lines: Vec<String> = Vec::new();
        let s = &self.sidecar;
        for (k, v) in [
            ("agent_id", s.agent_id.as_deref()),
            ("listen_addr", s.listen_addr.as_deref()),
            ("http_addr", s.http_addr.as_deref()),
            ("handshake_mode", s.handshake_mode.as_deref()),
            ("server_seed_file", s.server_seed_file.as_deref()),
            ("peer_pins_file", s.peer_pins_file.as_deref()),
            ("peer_secrets_file", s.peer_secrets_file.as_deref()),
            ("token_secret_file", s.token_secret_file.as_deref()),
            (
                "http_bearer_token_file",
                s.http_bearer_token_file.as_deref(),
            ),
            ("http_token_out_file", s.http_token_out_file.as_deref()),
            (
                "state_backend_url_file",
                s.state_backend_url_file.as_deref(),
            ),
            (
                "max_concurrent_sends",
                s.max_concurrent_sends.map(|v| v.to_string()).as_deref(),
            ),
            (
                "send_retry_attempts",
                s.send_retry_attempts.map(|v| v.to_string()).as_deref(),
            ),
        ] {
            if let Some(v) = v {
                lines.push(format!("sidecar.{k}={v:?}"));
            }
        }
        for (k, v) in [
            ("require_peer_secrets", fmt_bool(s.require_peer_secrets)),
            (
                "allow_unauthenticated_http",
                fmt_bool(s.allow_unauthenticated_http),
            ),
            ("enable_mpf", fmt_bool(s.enable_mpf)),
            ("enable_mace", fmt_bool(s.enable_mace)),
        ] {
            if v != "unset" {
                lines.push(format!("sidecar.{k}={v}"));
            }
        }
        let c = &self.command_center;
        for (k, v) in [
            ("listen_addr", c.listen_addr.as_deref()),
            ("dashboard_token_file", c.dashboard_token_file.as_deref()),
            ("demo_daemon_addr", c.demo_daemon_addr.as_deref()),
            ("rulepack_issuer", c.rulepack_issuer.as_deref()),
            ("rulepack_key", c.rulepack_key.as_deref()),
        ] {
            if let Some(v) = v {
                lines.push(format!("command_center.{k}={v:?}"));
            }
        }
        if let Some(d) = c.dollars_per_token {
            lines.push(format!("command_center.dollars_per_token={d}"));
        }
        if let Some(origins) = &c.dashboard_allowed_origins {
            lines.push(format!(
                "command_center.dashboard_allowed_origins={origins:?}"
            ));
        }
        for (k, v) in [
            ("disable_demo_daemon", fmt_bool(c.disable_demo_daemon)),
            ("demo_mode", fmt_bool(c.demo_mode)),
            ("enable_mace", fmt_bool(c.enable_mace)),
        ] {
            if v != "unset" {
                lines.push(format!("command_center.{k}={v}"));
            }
        }
        if lines.is_empty() {
            "no settings (all defaults)".to_string()
        } else {
            lines.join("; ")
        }
    }
}

/// Precedence primitive: the environment variable — when set at all, even to
/// the empty string — overrides the file value; otherwise the file value (if
/// any) wins; otherwise `None` (the read site's built-in default applies).
/// "Any set env var overrides" (not just non-empty) preserves existing
/// set-but-empty semantics such as `SAACP_DASHBOARD_ALLOWED_ORIGINS=""` meaning
/// the fail-closed "no cross-origin access" configuration.
pub fn resolve_opt<'a>(env_val: Option<String>, toml_val: Option<&'a str>) -> Option<Cow<'a, str>> {
    match env_val {
        Some(v) => Some(Cow::Owned(v)),
        None => toml_val.map(Cow::Borrowed),
    }
}

/// [`resolve_opt`] against the real process environment.
pub fn resolve<'a>(env_var: &'static str, toml_val: Option<&'a str>) -> Option<Cow<'a, str>> {
    resolve_opt(std::env::var(env_var).ok(), toml_val)
}

/// Env flag parsing shared by the binaries: the sidecar's historical
/// `SAACP_REQUIRE_PEER_SECRETS` / `SAACP_ENABLE_MACE` truthy set. The env
/// var, when set at all, wins over the file's boolean; an unset env var falls
/// back to the file value, then `false`.
pub fn resolve_flag(env_var: &'static str, toml_val: Option<bool>) -> bool {
    match std::env::var(env_var) {
        Ok(v) => matches!(v.as_str(), "1" | "true" | "TRUE" | "True"),
        Err(_) => toml_val.unwrap_or(false),
    }
}

/// Shared recognizer for `SAACP_HANDSHAKE_MODE` / `sidecar.handshake_mode`
/// spellings — used by `config.rs` validation and the sidecar binary's parser
/// so both accept exactly the same set.
pub fn parse_handshake_mode_str(raw: &str) -> Option<&'static str> {
    match raw {
        "LegacyOnly" | "LEGACY_ONLY" | "legacy_only" => Some("LegacyOnly"),
        "PreferPinned" | "PREFER_PINNED" | "prefer_pinned" => Some("PreferPinned"),
        "RequirePinned" | "REQUIRE_PINNED" | "require_pinned" => Some("RequirePinned"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal valid document parses and fills the right sections.
    #[test]
    fn minimal_toml_parses() {
        let cfg = SaacpConfig::from_toml_str(
            "test.toml",
            r#"
[sidecar]
agent_id = "agent-a"
listen_addr = "127.0.0.1:7443"
require_peer_secrets = true

[command_center]
listen_addr = "127.0.0.1:9090"
dashboard_allowed_origins = ["http://localhost:3000"]
"#,
        )
        .expect("valid toml should parse");
        assert_eq!(cfg.sidecar.agent_id.as_deref(), Some("agent-a"));
        assert_eq!(cfg.sidecar.require_peer_secrets, Some(true));
        assert_eq!(
            cfg.command_center.dashboard_allowed_origins.as_deref(),
            Some(&["http://localhost:3000".to_string()][..])
        );
        // Untouched fields stay None/absent — the default chain owns them.
        assert!(cfg.sidecar.token_secret_file.is_none());
        assert!(cfg.command_center.disable_demo_daemon.is_none());
    }

    /// Unknown keys must fail loudly (`deny_unknown_fields`): a typo such as
    /// `listen_adr` must not be silently ignored while the built-in default
    /// binds instead of the operator's intended address.
    #[test]
    fn unknown_keys_rejected() {
        let err =
            SaacpConfig::from_toml_str("test.toml", "[sidecar]\nlisten_adr = \"127.0.0.1:7443\"\n")
                .expect_err("typo'd key must be rejected");
        assert!(matches!(err, ConfigError::Parse { .. }), "got {err:?}");
    }

    /// Secret-by-value has no field to land in — this is the structural
    /// guarantee the module doc promises. A document attempting to inline a
    /// token secret is just an unknown key.
    #[test]
    fn raw_secret_in_toml_is_impossible() {
        let err =
            SaacpConfig::from_toml_str("test.toml", "[sidecar]\ntoken_secret = \"c2VjcmV0\"\n")
                .expect_err("raw secret must be rejected");
        assert!(matches!(err, ConfigError::Parse { .. }), "got {err:?}");
    }

    #[test]
    fn validation_rejects_bad_address_and_zero_bound() {
        let err =
            SaacpConfig::from_toml_str("test.toml", "[sidecar]\nlisten_addr = \"not-an-addr\"\n")
                .expect_err("bad addr must fail validation");
        assert!(matches!(err, ConfigError::Validation { .. }), "got {err:?}");
        let err = SaacpConfig::from_toml_str("test.toml", "[sidecar]\nmax_concurrent_sends = 0\n")
            .expect_err("zero bound must fail validation");
        assert!(matches!(err, ConfigError::Validation { .. }), "got {err:?}");
        // The accepted handshake-mode spellings all validate.
        for spelling in ["LEGACY_ONLY", "prefer_pinned", "RequirePinned"] {
            SaacpConfig::from_toml_str(
                "test.toml",
                &format!("[sidecar]\nhandshake_mode = \"{spelling}\"\n"),
            )
            .unwrap_or_else(|e| panic!("spelling {spelling} should validate: {e}"));
        }
        let err =
            SaacpConfig::from_toml_str("test.toml", "[sidecar]\nhandshake_mode = \"BOGUS\"\n")
                .expect_err("bogus handshake mode must fail validation");
        assert!(matches!(err, ConfigError::Validation { .. }), "got {err:?}");
    }

    /// Precedence primitive: env (when set) beats file; unset env falls back
    /// to the file; both absent falls through to the read site's default.
    /// Tested via `resolve_opt` (the env-injected variant of `resolve`) so the
    /// test does not race other tests over the real process environment.
    #[test]
    fn precedence_env_over_toml_over_default() {
        assert_eq!(
            resolve_opt(Some("from-env".into()), Some("from-toml")).as_deref(),
            Some("from-env")
        );
        assert_eq!(
            resolve_opt(None, Some("from-toml")).as_deref(),
            Some("from-toml")
        );
        assert_eq!(resolve_opt(None, None), None);
        // Set-but-empty env still overrides — preserves existing semantics
        // like `SAACP_DASHBOARD_ALLOWED_ORIGINS=""` = fail-closed no-CORS.
        assert_eq!(
            resolve_opt(Some(String::new()), Some("from-toml")).as_deref(),
            Some("")
        );
    }

    /// The redacted summary prints configured values and omits unset ones.
    /// It can never contain secret *material* — the struct has no field for
    /// any — which is the invariant this test pins.
    #[test]
    fn redacted_summary_lists_configured_fields_only() {
        let cfg = SaacpConfig::from_toml_str(
            "test.toml",
            "[sidecar]\nagent_id = \"agent-a\"\nrequire_peer_secrets = true\n",
        )
        .unwrap();
        let s = cfg.redacted_summary();
        assert!(s.contains("sidecar.agent_id=\"agent-a\""), "got {s:?}");
        assert!(s.contains("sidecar.require_peer_secrets=true"), "got {s:?}");
        assert!(
            !s.contains("token_secret"),
            "unset fields must be omitted: {s:?}"
        );
        // And the all-default config summarizes to the explicit no-settings line.
        assert_eq!(
            SaacpConfig::default().redacted_summary(),
            "no settings (all defaults)"
        );
    }

    /// Handshake-mode recognizer covers exactly the binary parser's accepted
    /// spellings — config validation and the binary parser cannot drift.
    #[test]
    fn handshake_mode_str_covers_all_spellings() {
        for (s, expected) in [
            ("LegacyOnly", "LegacyOnly"),
            ("LEGACY_ONLY", "LegacyOnly"),
            ("legacy_only", "LegacyOnly"),
            ("PreferPinned", "PreferPinned"),
            ("PREFER_PINNED", "PreferPinned"),
            ("RequirePinned", "RequirePinned"),
            ("require_pinned", "RequirePinned"),
        ] {
            assert_eq!(parse_handshake_mode_str(s), Some(expected));
        }
        assert_eq!(parse_handshake_mode_str("PinnedOnly"), None);
        assert_eq!(parse_handshake_mode_str(""), None);
    }
}
