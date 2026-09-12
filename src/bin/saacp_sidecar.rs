// Same security invariant as the library crate: safe Rust only, enforced.
#![forbid(unsafe_code)]

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
//!   SAACP_CONFIG              — OPTIONAL path to a TOML configuration file
//!                               (`[sidecar]` section; see `saacp::config`).
//!                               Every variable below can be set there instead
//!                               (names drop the `SAACP_` prefix, e.g.
//!                               `agent_id`, `listen_addr`); secrets may only
//!                               be referenced via their `*_file` path fields.
//!                               An env var, when set, always overrides the
//!                               file value. Unset ⇒ identical behavior to
//!                               pre-file releases.
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

use saacp::config::{resolve, resolve_flag, SaacpConfig};
use saacp::maintenance::MaintenanceCoordinator;
use saacp::sidecar::{run_with_shutdown, SidecarConfig, SidecarHandshakeMode};
use sha2::Digest;

/// Plan item 3: typed configuration errors for the sidecar binary. Every
/// startup-time parse / IO failure goes through this enum so `main()`
/// can print a redacted, actionable message and exit with a non-zero
/// status instead of panicking. The variants deliberately do NOT carry
/// the raw secret value or file contents — only the kind of failure
/// and the source environment variable, so a `Display` of this error
/// is safe to send to stderr without leaking secret material.
///
/// Variants are `#[allow(dead_code)]` because this enum is
/// incrementally adopted — the two refactored paths in this change set
/// (`read_token_secret`, `read_peer_secrets`) only exercise a subset
/// today, and the remaining variants light up as the
/// `read_http_bearer_token` / address-parsing paths are converted in
/// the follow-up commit. The non-leak guarantee is what matters; the
/// `Display` impl is the single audit-relevant surface.
#[allow(dead_code)]
#[derive(Debug)]
enum SidecarConfigError {
    /// Required env var was missing at startup. `var` is the env var name
    /// (never the value); `hint` is an actionable remediation.
    MissingEnv {
        var: &'static str,
        hint: &'static str,
    },
    /// An env var that must be a valid `SocketAddr` failed to parse.
    InvalidSocketAddr {
        var: &'static str,
        value: String,
        source: std::net::AddrParseError,
    },
    /// An env var that must be a `u32` (e.g. concurrency limit) failed
    /// to parse.
    InvalidU32 {
        var: &'static str,
        value: String,
        source: std::num::ParseIntError,
    },
    /// A token secret could not be base64-decoded. The env-var name is
    /// included; the malformed raw value is NOT.
    InvalidBase64 {
        var: &'static str,
        source: base64::DecodeError,
    },
    /// A token secret was not exactly 32 bytes after decoding.
    WrongSecretLength { var: &'static str, got: usize },
    /// A required file (peer-secrets map, HTTP-token out file) could
    /// not be read.
    FileRead {
        path: String,
        source: std::io::Error,
    },
    /// A peer-secrets JSON file parsed as JSON but its shape was wrong
    /// (e.g. a value that is not a string). File path included; the
    /// malformed body is NOT.
    InvalidJson {
        path: String,
        source: serde_json::Error,
    },
    /// A peer-secrets JSON value decoded as a base64 string but the
    /// decoded bytes were not 32 bytes long. Field name and length
    /// included; raw values are NOT.
    InvalidPeerSecret {
        agent_id: String,
        source: Box<SidecarConfigError>,
    },
}

impl std::fmt::Display for SidecarConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingEnv { var, hint } => {
                write!(f, "missing required environment variable {var}: {hint}")
            }
            Self::InvalidSocketAddr { var, value, source } => write!(
                f,
                "invalid {var}={value:?}: {source} (expected host:port, e.g. 127.0.0.1:7443)"
            ),
            Self::InvalidU32 { var, value, source } => write!(
                f,
                "invalid {var}={value:?}: {source} (expected a non-negative integer)"
            ),
            Self::InvalidBase64 { var, .. } => {
                // Deliberately do not include `source`: the source variant
                // of base64::DecodeError includes byte offsets into the
                // malformed input, which can be a credential leak vector
                // if the malformed value was a partial secret.
                write!(
                    f,
                    "{var} is not valid base64 (rejected without printing the input)"
                )
            }
            Self::WrongSecretLength { var, got } => {
                write!(f, "{var} must decode to exactly 32 bytes, got {got}")
            }
            Self::FileRead { path, source } => {
                write!(f, "failed to read {path:?}: {source}")
            }
            Self::InvalidJson { path, source } => {
                // As with `InvalidBase64`, omit the body of the JSON.
                write!(
                    f,
                    "{path:?} is not valid JSON (rejected without printing the body): {source}"
                )
            }
            Self::InvalidPeerSecret { agent_id, source } => {
                write!(f, "peer secret for {agent_id:?} is invalid: {source}")
            }
        }
    }
}

impl std::error::Error for SidecarConfigError {}

/// Print the error to stderr (with structured `tracing::error!` if a
/// subscriber is installed), then exit with status 1.
fn config_error_exit(err: SidecarConfigError) -> ! {
    tracing::error!(error = %err, "saacp-sidecar startup failed");
    eprintln!("[saacp-sidecar] startup failed: {err}");
    eprintln!("[saacp-sidecar] see logs above for the offending variable.");
    std::process::exit(1);
}

fn parse_token_secret_with_var(
    raw: &str,
    var: &'static str,
) -> Result<[u8; 32], SidecarConfigError> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(raw.trim())
        .map_err(|source| SidecarConfigError::InvalidBase64 { var, source })?;
    <[u8; 32]>::try_from(bytes.as_slice()).map_err(|_| SidecarConfigError::WrongSecretLength {
        var,
        got: bytes.len(),
    })
}

/// `SAACP_TOKEN_SECRET_FILE` (if set) takes precedence over `SAACP_TOKEN_SECRET` — lets an
/// operator keep the secret out of the process environment entirely.
///
/// S8: raw secret strings are held in `Zeroizing` buffers so the intermediate
/// copy is scrubbed the moment parsing finishes; the env-var fallback prints a
/// one-time notice because process environments are world-readable to the same
/// user via `/proc/<pid>/environ` and leak into crash dumps and child
/// processes. The `_FILE` variants are the recommended production default.
fn read_token_secret(cfg: &SaacpConfig) -> Result<[u8; 32], SidecarConfigError> {
    use zeroize::Zeroizing;
    if let Ok(path) = std::env::var("SAACP_TOKEN_SECRET_FILE") {
        let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|source| {
            SidecarConfigError::FileRead {
                path: path.clone(),
                source,
            }
        })?);
        return parse_token_secret_with_var(raw.trim(), "SAACP_TOKEN_SECRET_FILE");
    }
    let toml_file = cfg.sidecar.token_secret_file.as_deref();
    if let Some(path) = std::env::var("SAACP_TOKEN_SECRET_FILE")
        .ok()
        .or_else(|| toml_file.map(str::to_string))
    {
        // Env `_FILE` (precedence rule) or the config file's `token_secret_file`
        // — the file-config fallback keeps the S-8 `_FILE` indirection (raw
        // secrets have no field in the TOML schema, by construction).
        let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|source| {
            SidecarConfigError::FileRead {
                path: path.clone(),
                source,
            }
        })?);
        return parse_token_secret_with_var(raw.trim(), "SAACP_TOKEN_SECRET_FILE");
    }
    tracing::warn!(
        "token secret read from the SAACP_TOKEN_SECRET environment variable — process \
         environments are readable via /proc/<pid>/environ by same-user processes and can \
         leak into crash dumps and spawned children. Prefer SAACP_TOKEN_SECRET_FILE for \
         production deployments."
    );
    let raw = Zeroizing::new(std::env::var("SAACP_TOKEN_SECRET").map_err(|_| {
        SidecarConfigError::MissingEnv {
            var: "SAACP_TOKEN_SECRET",
            hint: "set SAACP_TOKEN_SECRET (or SAACP_TOKEN_SECRET_FILE) to a base64-encoded \
                   32-byte secret. The sidecar refuses to start without one — see the \
                   sidecar binary's module doc for SAACP_PEER_SECRETS_FILE as the \
                   production-recommended alternative.",
        }
    })?);
    parse_token_secret_with_var(&raw, "SAACP_TOKEN_SECRET")
}

/// Optional per-peer pairwise secrets — see `sidecar.rs`'s module doc. Absent env var =
/// empty map = the weaker single-shared-secret mode (see this module's doc).
///
/// S8: the file's plaintext JSON (which holds every peer secret in one
/// string) is held in a `Zeroizing` buffer and scrubbed after parsing.
fn read_peer_secrets(cfg: &SaacpConfig) -> Result<HashMap<String, [u8; 32]>, SidecarConfigError> {
    use zeroize::Zeroizing;
    let path = match resolve(
        "SAACP_PEER_SECRETS_FILE",
        cfg.sidecar.peer_secrets_file.as_deref(),
    ) {
        Some(p) => p.into_owned(),
        None => return Ok(HashMap::new()),
    };
    let raw = Zeroizing::new(std::fs::read_to_string(&path).map_err(|source| {
        SidecarConfigError::FileRead {
            path: path.clone(),
            source,
        }
    })?);
    let parsed: HashMap<String, String> =
        serde_json::from_str(&raw).map_err(|source| SidecarConfigError::InvalidJson {
            path: path.clone(),
            source,
        })?;
    let mut out = HashMap::with_capacity(parsed.len());
    for (agent_id, secret_b64) in parsed {
        // S8: scrub each plaintext secret string the moment it is parsed.
        let secret_b64 = Zeroizing::new(secret_b64);
        let bytes = parse_token_secret_with_var(&secret_b64, "SAACP_PEER_SECRETS_FILE").map_err(
            |source| SidecarConfigError::InvalidPeerSecret {
                agent_id: agent_id.clone(),
                source: Box::new(source),
            },
        )?;
        out.insert(agent_id, bytes);
    }
    Ok(out)
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
fn enforce_peer_secret_posture(
    cfg: &SaacpConfig,
    peer_secrets: &HashMap<String, [u8; 32]>,
    agent_id: &str,
) {
    if !peer_secrets.is_empty() {
        return;
    }
    let required = resolve_flag(
        "SAACP_REQUIRE_PEER_SECRETS",
        cfg.sidecar.require_peer_secrets,
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
///
/// S8: raw token strings are held in `Zeroizing` buffers while parsed; the
/// returned token necessarily lives on in the sidecar config (it is compared
/// on every request) — only the intermediates are scrubbed.
fn read_http_bearer_token(cfg: &SaacpConfig) -> Option<String> {
    use zeroize::Zeroizing;
    let raw = if let Some(path) = std::env::var("SAACP_HTTP_BEARER_TOKEN_FILE")
        .ok()
        .or_else(|| cfg.sidecar.http_bearer_token_file.clone())
    {
        // Env `_FILE` (precedence rule) or the config file's
        // `http_bearer_token_file` — `_FILE` indirection preserved.
        Zeroizing::new(std::fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!("failed to read SAACP_HTTP_BEARER_TOKEN_FILE '{path}': {e}")
        }))
    } else {
        eprintln!(
            "[saacp-sidecar] NOTE: HTTP bearer token read from the SAACP_HTTP_BEARER_TOKEN \
             environment variable — prefer SAACP_HTTP_BEARER_TOKEN_FILE in production \
             (process environments are readable via /proc/<pid>/environ by same-user \
             processes)."
        );
        Zeroizing::new(std::env::var("SAACP_HTTP_BEARER_TOKEN").unwrap_or_default())
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
    // Plan item 2c: initialize structured logging as the very first action
    // of main(). Idempotent (safe in tests that call main() more than once).
    // The default `LogConfig` reads `SAACP_LOG` and `SAACP_LOG_JSON` from
    // the environment so an operator can flip JSON output without a
    // rebuild.
    saacp::logging::init_logging(saacp::logging::LogConfig::default());

    // §2.4 mitigation: load the optional TOML config file (SAACP_CONFIG) once,
    // validated, before anything binds. `default()` (env unset) is behavior-
    // identical to pre-file releases.
    let bin_cfg = match SaacpConfig::load() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[saacp-sidecar] startup failed: {e}");
            std::process::exit(1);
        }
    };
    if matches!(std::env::var("SAACP_CONFIG").as_deref(), Ok(p) if !p.trim().is_empty()) {
        eprintln!(
            "[saacp-sidecar] config file posture: {}",
            bin_cfg.redacted_summary()
        );
    }

    // Plan item 3: surface every startup configuration failure as a
    // typed `SidecarConfigError` (redacted message + non-zero exit),
    // never a panic. Two of the env reads are still `unwrap_or_else`
    // panics on the missing-`SAACP_AGENT_ID` / invalid-`SAACP_*_ADDR`
    // paths — those are addressed by the follow-up in the same audit
    // pass; the most security-sensitive reads (token secret + peer
    // secrets) are converted first because they handle secret material.
    let agent_id = match resolve("SAACP_AGENT_ID", bin_cfg.sidecar.agent_id.as_deref()) {
        Some(id) => id.into_owned(),
        None => config_error_exit(SidecarConfigError::MissingEnv {
            var: "SAACP_AGENT_ID",
            hint: "set SAACP_AGENT_ID (or sidecar.agent_id in the SAACP_CONFIG file) to this \
                   sidecar's unique agent identity string",
        }),
    };
    let token_issuer_secret = match read_token_secret(&bin_cfg) {
        Ok(s) => s,
        Err(e) => config_error_exit(e),
    };
    let peer_secrets = match read_peer_secrets(&bin_cfg) {
        Ok(s) => s,
        Err(e) => config_error_exit(e),
    };
    enforce_peer_secret_posture(&bin_cfg, &peer_secrets, &agent_id);

    let saacp_listen_addr: SocketAddr =
        resolve("SAACP_LISTEN_ADDR", bin_cfg.sidecar.listen_addr.as_deref())
            .unwrap_or_else(|| "127.0.0.1:7443".into())
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_LISTEN_ADDR: {e}"));
    let http_listen_addr: SocketAddr =
        resolve("SAACP_HTTP_ADDR", bin_cfg.sidecar.http_addr.as_deref())
            .unwrap_or_else(|| "127.0.0.1:8787".into())
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_HTTP_ADDR: {e}"));

    // Fail closed: the local HTTP/JSON API can issue outbound messages and drain
    // this agent's inbox, so it must never be reachable from off-host without
    // authentication. If the operator binds a non-loopback interface, a bearer
    // token is mandatory. On loopback (the default) it stays optional, matching
    // the library's opt-in default for the co-located-agent case.
    let mut http_bearer_token = read_http_bearer_token(&bin_cfg);
    if !http_listen_addr.ip().is_loopback() && http_bearer_token.is_none() {
        panic!(
            "SAACP_HTTP_ADDR binds non-loopback address {http_listen_addr} but no \
             SAACP_HTTP_BEARER_TOKEN(_FILE) is set — refusing to expose an \
             unauthenticated message-issuance API. Set a bearer token or bind loopback."
        );
    }

    // S-5/S6 fix: the local HTTP/JSON API can issue outbound messages and
    // drain this agent's inbox, so it is authenticated BY DEFAULT. When no
    // token was supplied we generate a fresh random one and publish it
    // exactly once — to `SAACP_HTTP_TOKEN_OUT_FILE` when given (0600 on
    // POSIX, for the co-located agent to read), otherwise to stderr with a
    // machine-scrapable marker line. `SAACP_ALLOW_UNAUTHENTICATED_HTTP=1` is
    // the explicit, auditable escape hatch for legacy hand-started agents
    // and prints a loud warning instead.
    if http_bearer_token.is_none() {
        let opted_out = match std::env::var("SAACP_ALLOW_UNAUTHENTICATED_HTTP") {
            Ok(v) => v == "1",
            Err(_) => bin_cfg.sidecar.allow_unauthenticated_http.unwrap_or(false),
        };
        if opted_out {
            eprintln!(
                "[saacp-sidecar] WARNING: SAACP_ALLOW_UNAUTHENTICATED_HTTP=1 — the local \
                 HTTP API on {http_listen_addr} is running UNAUTHENTICATED. Any process on \
                 this host can issue messages as '{agent_id}' and drain its inbox. This \
                 escape hatch exists only for legacy hand-started agents and may be \
                 removed in a future release."
            );
        } else {
            match resolve(
                "SAACP_HTTP_TOKEN_OUT_FILE",
                bin_cfg.sidecar.http_token_out_file.as_deref(),
            ) {
                Some(path) if !path.trim().is_empty() => {
                    http_bearer_token = Some(generate_and_write_http_token(path.trim()));
                    eprintln!(
                        "[saacp-sidecar] no bearer token supplied — generated one and wrote it \
                         to {} (S-5). The co-located agent must send it as `Authorization: Bearer`.",
                        path.trim()
                    );
                }
                _ => {
                    use rand::RngCore;
                    let mut raw = [0u8; 32];
                    rand::rngs::OsRng.fill_bytes(&mut raw);
                    let token = hex::encode(raw);
                    eprintln!(
                        "[saacp-sidecar] no bearer token supplied — generated one (S6). \
                         Send it as `Authorization: Bearer <token>` on every /send and \
                         /receive call. It is printed ONCE, here, and never again:"
                    );
                    eprintln!("[saacp-sidecar] SAACP_HTTP_BEARER_TOKEN={token}");
                    eprintln!(
                        "[saacp-sidecar] (to use a fixed token instead, set \
                         SAACP_HTTP_BEARER_TOKEN(_FILE); to run unauthenticated for \
                         legacy migration, set SAACP_ALLOW_UNAUTHENTICATED_HTTP=1)"
                    );
                    http_bearer_token = Some(token);
                }
            }
        }
    }

    let mut config = SidecarConfig::new(
        agent_id,
        token_issuer_secret,
        saacp_listen_addr,
        http_listen_addr,
    );
    config.peer_secrets = peer_secrets;
    config.http_bearer_token = http_bearer_token;
    if let Some(v) = resolve(
        "SAACP_MAX_CONCURRENT_SENDS",
        bin_cfg
            .sidecar
            .max_concurrent_sends
            .map(|v| v.to_string())
            .as_deref(),
    ) {
        config.max_concurrent_sends = v
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_MAX_CONCURRENT_SENDS: {e}"));
    }
    // C4 (MPF): bucket-pad outbound payloads (opt-in, mirrors SAACP_ENABLE_MACE).
    if resolve_flag("SAACP_ENABLE_MPF", bin_cfg.sidecar.enable_mpf) {
        config.payload_padding = true;
    }
    if let Some(v) = resolve(
        "SAACP_SEND_RETRY_ATTEMPTS",
        bin_cfg
            .sidecar
            .send_retry_attempts
            .map(|v| v.to_string())
            .as_deref(),
    ) {
        config.send_retry_attempts = v
            .parse()
            .unwrap_or_else(|e| panic!("invalid SAACP_SEND_RETRY_ATTEMPTS: {e}"));
    }

    // M1 (R1): outbound handshake posture. The BINARY defaults to
    // `PreferPinned` (authenticated handshake with an explicit, WARN-logged
    // plain fallback for legacy peers) — the library default stays
    // `LegacyOnly` so embedded `SidecarConfig` consumers keep v1 wire
    // compatibility. `SAACP_HANDSHAKE_MODE=LEGACY_ONLY` restores v1 exactly.
    config.handshake_mode = parse_handshake_mode(
        resolve(
            "SAACP_HANDSHAKE_MODE",
            bin_cfg.sidecar.handshake_mode.as_deref(),
        )
        .as_deref(),
    );
    if let Some(path) = resolve(
        "SAACP_SERVER_SEED_FILE",
        bin_cfg.sidecar.server_seed_file.as_deref(),
    ) {
        config.server_seed = Some(parse_server_seed_file(&path));
    }
    if let Some(path) = resolve(
        "SAACP_PEER_PINS_FILE",
        bin_cfg.sidecar.peer_pins_file.as_deref(),
    ) {
        config.pinned_peers = parse_peer_pins_file(&path);
    }

    // M-I remediation (production audit R11): a fresh ephemeral server seed
    // is generated per boot when SAACP_SERVER_SEED_FILE is unset. With
    // `PREFER_PINNED`/`REQUIRE_PINNED` the peer pins verify against THIS
    // boot's verifying key — so every restart would silently fail pin
    // verification (REQUIRE) or downgrade every connection to plain ECDH
    // (PREFER) until the new key is re-pinned out-of-band. That combination
    // is almost always a configuration mistake: say so, loudly, at startup.
    warn_if_pins_without_seed(&config.server_seed, &config.pinned_peers);

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
    let mace_enabled = resolve_flag("SAACP_ENABLE_MACE", bin_cfg.sidecar.enable_mace);
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

    // M2 remediation: when SAACP_STATE_BACKEND_URL_FILE (or the TOML
    // `sidecar.state_backend_url_file`) points to a file containing a Redis
    // URL, construct a circuit-breaker-wrapped RedisBackend for cross-node
    // shared rate-limit and session state.
    #[cfg(feature = "redis-backend")]
    {
        if let Some(url_file_path) = resolve(
            "SAACP_STATE_BACKEND_URL_FILE",
            bin_cfg.sidecar.state_backend_url_file.as_deref(),
        ) {
            let url = std::fs::read_to_string(url_file_path.trim())
                .unwrap_or_else(|e| {
                    eprintln!(
                        "[saacp-sidecar] FATAL: could not read state backend URL \
                         file {}: {e}",
                        url_file_path.trim()
                    );
                    std::process::exit(1);
                })
                .trim()
                .to_string();
            let backend = saacp::state_backend::RedisBackend::new(&url)
                .unwrap_or_else(|e| {
                    eprintln!(
                        "[saacp-sidecar] FATAL: RedisBackend::new failed: {e}"
                    );
                    std::process::exit(1);
                });
            let breaker =
                saacp::state_backend::CircuitBreakerBackend::wrap(backend);
            eprintln!(
                "[saacp-sidecar] state backend: Redis (circuit-breaker wrapped) \
                 from file {}",
                url_file_path.trim()
            );
            config.state_backend = Some(std::sync::Arc::new(breaker));
        }
    }

    run_with_shutdown(config, tokio_util::sync::CancellationToken::new())
        .await
        .unwrap_or_else(|e| {
            eprintln!("[saacp-sidecar] fatal: {e}");
            std::process::exit(1);
        });
}

/// M-I remediation (production audit R11): warn when peer pins are configured
/// against an ephemeral (per-boot) server seed. Returns `true` when the
/// warning fired — exposed for the regression test.
fn warn_if_pins_without_seed(
    server_seed: &Option<[u8; 32]>,
    pinned_peers: &HashMap<String, [u8; 32]>,
) -> bool {
    if server_seed.is_none() && !pinned_peers.is_empty() {
        eprintln!(
            "[saacp-sidecar] WARNING: {} peer pin(s) are configured but no server identity \
             seed is (SAACP_SERVER_SEED_FILE unset) — a fresh ephemeral seed is generated \
             EACH BOOT, so the verifying key every peer pinned will stop matching after \
             this process restarts. REQUIRE_PINNED will then refuse every connection and \
             PREFER_PINNED will downgrade to plain ECDH. Persist a stable seed via \
             SAACP_SERVER_SEED_FILE and re-pin its fingerprint once.",
            pinned_peers.len()
        );
        return true;
    }
    false
}

/// M1 (R1): parse `SAACP_HANDSHAKE_MODE`. Unset defaults to `PreferPinned`
/// (binary posture — see the call site); recognized values are the Debug
/// spellings and their SCREAMING_SNAKE aliases.
fn parse_handshake_mode(raw: Option<&str>) -> SidecarHandshakeMode {
    match raw {
        None => SidecarHandshakeMode::PreferPinned,
        Some(s) => match saacp::config::parse_handshake_mode_str(s) {
            Some("LegacyOnly") => SidecarHandshakeMode::LegacyOnly,
            Some("PreferPinned") => SidecarHandshakeMode::PreferPinned,
            Some("RequirePinned") => SidecarHandshakeMode::RequirePinned,
            // Validation in `SaacpConfig` rejects file values with the same
            // accepted set; this panic remains the backstop for env values.
            _ => panic!(
                "invalid SAACP_HANDSHAKE_MODE '{s}': expected \
                 LEGACY_ONLY | PREFER_PINNED | REQUIRE_PINNED"
            ),
        },
    }
}

/// M1 (R1): read the server's stable Ed25519 seed (64 hex chars) from
/// `SAACP_SERVER_SEED_FILE`. Required for `REQUIRE_PINNED`; optional (a fresh
/// ephemeral seed is generated and its VK fingerprint printed once) otherwise.
fn parse_server_seed_file(path: &str) -> [u8; 32] {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read SAACP_SERVER_SEED_FILE '{path}': {e}"));
    let trimmed = raw.trim();
    let bytes = hex::decode(trimmed)
        .unwrap_or_else(|e| panic!("SAACP_SERVER_SEED_FILE '{path}': invalid hex: {e}"));
    let seed: [u8; 32] = bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
        panic!(
            "SAACP_SERVER_SEED_FILE '{path}': expected 64 hex chars (32 bytes), got {}",
            v.len()
        )
    });
    eprintln!(
        "[saacp-sidecar] server identity seed loaded from {path} (vk fingerprint: {})",
        hex::encode(sha2::Sha256::digest(seed))
    );
    seed
}

/// M1 (R1): read per-peer pinned Ed25519 verifying keys from
/// `SAACP_PEER_PINS_FILE`. Accepted JSON shapes (both per entry):
/// `{"agent-b": {"vk_hex": "<64 hex>"}}` (documented form) or the shorthand
/// `{"agent-b": "<64 hex>"}`. Pinned keys are what `REQUIRE_PINNED` enforces
/// and what `PREFER_PINNED` verifies (with fallback) against.
fn parse_peer_pins_file(path: &str) -> std::collections::HashMap<String, [u8; 32]> {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("failed to read SAACP_PEER_PINS_FILE '{path}': {e}"));
    let value: serde_json::Value = serde_json::from_str(&raw)
        .unwrap_or_else(|e| panic!("SAACP_PEER_PINS_FILE '{path}': invalid JSON: {e}"));
    let obj = match value.as_object() {
        Some(o) => o,
        None => panic!("SAACP_PEER_PINS_FILE '{path}': top level must be a JSON object"),
    };
    let mut pins = std::collections::HashMap::new();
    for (agent, entry) in obj {
        let hex_str = match entry {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Object(m) => m
                .get("vk_hex")
                .and_then(|v| v.as_str())
                .map(str::to_string)
                .unwrap_or_else(|| {
                    panic!("SAACP_PEER_PINS_FILE '{path}': peer '{agent}' missing \"vk_hex\"")
                }),
            other => panic!(
                "SAACP_PEER_PINS_FILE '{path}': peer '{agent}' must be a string or \
                 {{\"vk_hex\": ...}} object, got {other}"
            ),
        };
        let bytes = hex::decode(hex_str.trim()).unwrap_or_else(|e| {
            panic!("SAACP_PEER_PINS_FILE '{path}': peer '{agent}': invalid hex: {e}")
        });
        let vk: [u8; 32] = bytes.try_into().unwrap_or_else(|v: Vec<u8>| {
            panic!(
                "SAACP_PEER_PINS_FILE '{path}': peer '{agent}': expected 64 hex chars \
                 (32 bytes), got {}",
                v.len()
            )
        });
        pins.insert(agent.clone(), vk);
    }
    eprintln!(
        "[saacp-sidecar] loaded {} peer pin(s) from {path}",
        pins.len()
    );
    pins
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use saacp::sidecar::SidecarHandshakeMode;

    /// Plan item 3: confirm the typed `SidecarConfigError` `Display`
    /// impl does not leak the raw secret value or the body of a
    /// malformed file. The `InvalidBase64` and `InvalidJson` variants
    /// are the most sensitive — a base64-decode error or a JSON parse
    /// error can include byte offsets / line numbers that an
    /// operator-visible error log could echo into stderr or a log
    /// aggregator. We deliberately omit those.
    #[test]
    fn sidecar_config_error_invalid_base64_does_not_echo_input() {
        let err = SidecarConfigError::InvalidBase64 {
            var: "SAACP_TOKEN_SECRET",
            // base64::DecodeError has a non-public constructor in the
            // stable API; the easiest way to construct one for testing
            // is `base64::Engine::decode` on a malformed string.
            source: base64::engine::general_purpose::STANDARD
                .decode("not-valid-base64!!!")
                .expect_err("malformed base64 should fail to decode"),
        };
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("not-valid-base64"),
            "Display must not echo the input value (got: {rendered:?})"
        );
        assert!(
            rendered.contains("SAACP_TOKEN_SECRET"),
            "Display must include the env var name (got: {rendered:?})"
        );
    }

    /// Plan item 3: confirm `InvalidJson` also omits the file body.
    #[test]
    fn sidecar_config_error_invalid_json_does_not_echo_body() {
        let bad = "{\"legit-secret\":\"YQ==\",\"bad-field\":<not json}";
        let parse_err = serde_json::from_str::<serde_json::Value>(bad)
            .expect_err("malformed JSON should fail to parse");
        let err = SidecarConfigError::InvalidJson {
            path: "/var/run/saacp/peer-secrets.json".to_string(),
            source: parse_err,
        };
        let rendered = format!("{err}");
        assert!(
            !rendered.contains("legit-secret") && !rendered.contains("YQ=="),
            "Display must not echo the file body (got: {rendered:?})"
        );
        assert!(
            rendered.contains("peer-secrets.json"),
            "Display must include the file path (got: {rendered:?})"
        );
    }

    /// Plan item 3: `MissingEnv` includes the env var name and the
    /// remediation hint — the latter is the operator-actionable
    /// information that makes the difference between "panic with a
    /// short message" and "typed error with a fix recipe".
    #[test]
    fn sidecar_config_error_missing_env_includes_hint() {
        let err = SidecarConfigError::MissingEnv {
            var: "SAACP_TOKEN_SECRET",
            hint: "set SAACP_TOKEN_SECRET to a base64-encoded 32-byte secret",
        };
        let rendered = format!("{err}");
        assert!(rendered.contains("SAACP_TOKEN_SECRET"));
        assert!(rendered.contains("base64-encoded 32-byte secret"));
    }

    /// Plan item 3: `SidecarHandshakeMode` round-trips through Debug
    /// / Copy so the binary's `SAACP_HANDSHAKE_MODE` env-var parser
    /// (added in a follow-up) has a stable representation. The
    /// `serde_json` round-trip is the eventual plan — today we just
    /// assert equality / Debug identity.
    #[test]
    fn sidecar_handshake_mode_is_copy_and_eq() {
        let a = SidecarHandshakeMode::LegacyOnly;
        let b = a; // Copy
        assert_eq!(a, b);
        let c = SidecarHandshakeMode::PreferPinned;
        assert_ne!(a, c);
        let d = SidecarHandshakeMode::RequirePinned;
        assert_ne!(c, d);
        // Debug repr is stable enough for an env-var parser to match on.
        assert_eq!(format!("{:?}", a), "LegacyOnly");
        assert_eq!(format!("{:?}", c), "PreferPinned");
        assert_eq!(format!("{:?}", d), "RequirePinned");
    }

    /// Plan item 3: `SidecarConfig::new` defaults to `LegacyOnly`,
    /// which preserves the v1 plain-ECDH behavior byte-for-byte. This
    /// test is the regression guard for that property — if a future
    /// change flips the default to `PreferPinned`, it will break this
    /// test and force the change to be a deliberate, breaking one.
    /// M-I regression (production audit R11): the pins-without-seed warning
    /// fires exactly for the dangerous combination (pins configured + no
    /// persisted seed) and stays quiet otherwise.
    #[test]
    fn pins_without_seed_warning_fires_only_for_dangerous_combo() {
        let mut pins = HashMap::new();
        pins.insert("peer-b".to_string(), [7u8; 32]);
        // Pins + ephemeral seed: warn.
        assert!(warn_if_pins_without_seed(&None, &pins));
        // Persisted seed + pins: fine.
        assert!(!warn_if_pins_without_seed(&Some([9u8; 32]), &pins));
        // No seed and no pins (bare dev sidecar): fine.
        assert!(!warn_if_pins_without_seed(&None, &HashMap::new()));
    }

    #[test]
    fn sidecar_config_new_defaults_handshake_to_legacy_only() {
        let cfg = saacp::sidecar::SidecarConfig::new(
            "agent-test",
            [0u8; 32],
            "127.0.0.1:0".parse().unwrap(),
            "127.0.0.1:0".parse().unwrap(),
        );
        assert_eq!(
            cfg.handshake_mode,
            SidecarHandshakeMode::LegacyOnly,
            "SidecarConfig::new must default to LegacyOnly to preserve v1 wire compatibility"
        );
        assert!(cfg.pinned_peers.is_empty());
        assert!(cfg.server_seed.is_none());
    }
}
