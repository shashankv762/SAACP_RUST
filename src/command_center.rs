//! command_center.rs — SAACP Command Center: live dashboard backend (REST + SSE).
//!
//! The pitch: a web dashboard for operators to see, in real time, what a fleet of SAACP
//! gateways is actually doing — which agents are trusted, who has delegated capability to
//! whom, when Gate 4.0 blocks a prompt-injection attempt, and how much claimed token spend
//! the Financial Circuit Breaker (Gate 0.5) has prevented. Feature-gated (`command-center`,
//! off by default — see "Optional Cargo Features" in CLAUDE.md), adding zero new
//! dependencies: reuses the already-optional `axum` (shared with `sidecar`) and
//! `futures-util` (for `stream::unfold`, used to adapt a `tokio::sync::broadcast` receiver
//! into an SSE `Stream` without pulling in `tokio-stream`).
//!
//! ## Architecture: in-process, not a separate observer
//!
//! [`run`] is meant to run **in the same process** as a real gateway's
//! `daemon::SAACPNetworkDaemon` — one more async task alongside it, sharing
//! `security::ImmutableAuditLog::global()` / `trust_decay::TrustDecayEngine::global()` /
//! `telemetry::global_telemetry()` / `telemetry::global_alert_feed()` directly, with zero
//! IPC. It is **not** designed to observe a *different* process's state — there is no
//! cross-process channel here, only in-process subscriber callbacks on the global
//! singletons above. `src/bin/saacp_command_center.rs` also stands up its own in-process
//! demo daemon purely so the dashboard has example traffic out of the box.
//!
//! ## Prerequisite plumbing (already wired elsewhere, listed here for one place to look)
//!
//! None of this dashboard's data existed in a durable/enumerable form before this session:
//!
//! | Need | Fix | Where |
//! |---|---|---|
//! | Live agent list + trust scores | `TrustDecayEngine::snapshot()` | `trust_decay.rs` |
//! | Trust-mesh delegation graph | `sidecar.rs::send_message` now logs a real `FAITFAuditLog::log_delegation` entry per dispatch (the live HMAC capability-token path has no `parent_jti`/`jti` fields to hook per-packet — token *issuance*, not per-packet Gate 1.0 validation, is the correct low-frequency event) | `sidecar.rs`, `faitf_audit.rs` |
//! | Security alert feed | `telemetry::SecurityAlertFeed` (network-safe by design — deliberately NOT `pecf.rs`'s `SecureDiagnosticLedger`, whose own doc comment forbids network exposure) | `telemetry.rs` |
//! | "Tokens Blocked" financial metric | `Counters::financial_tokens_rejected`, summed at `gate_financial_cb`'s `BudgetExceeded` site | `telemetry.rs`, `handler.rs` |
//! | Gate-rejection counters actually incremented | `telemetry::report_gate_rejection` wired at every gate reject site | `handler.rs` |
//! | Live audit-log tail | `ImmutableAuditLog::subscribe` (push hook, fires after the hash-chain lock is released — never touches `CanonicalAuditRecord`/chain-hash integrity) | `security.rs` |
//!
//! ## V1 scope limits (honest, not hidden)
//!
//! - The trust-mesh graph's edges are `(from_agent, to_agent)` capability-grant pairs from
//!   `sidecar.rs::send_message`, not a genuine multi-hop delegation lineage — fully fixing
//!   that would need a wire-protocol change (a `parent_rid`/`parent_jti` field carried on
//!   every packet) and touching Gate 11.0/12.0's live governance code, out of proportion to
//!   a dashboard feature. See `sidecar.rs`'s wiring note for the full reasoning.
//! - No de-dup on delegation edges: a chatty `(from_agent, to_agent)` pair produces one
//!   audit entry (and one `DashboardEvent::DelegationEdge`) per message. The `/api/trust-mesh`
//!   REST snapshot itself IS deduped (one entry per pair, `last_seen`/`depth` updated
//!   in place) — only the live SSE feed repeats.
//! - `/events` (SSE) accepts the dashboard token as a `?token=` query parameter as well as
//!   an `Authorization` header, since browsers' native `EventSource` cannot set custom
//!   headers — a stated v1 simplification (tokens in URLs can leak via logs/referrers). A
//!   session-cookie-based v2 is the natural fix if a deployment's threat model cares.
//! - "Tokens Blocked" / "dollars saved" measures *rejected claimed cost*
//!   (`estimated_cost` summed at every `BudgetExceeded` rejection), never *actual*
//!   prevented spend, which this system has no way to observe. Label it honestly in any
//!   UI built on `/api/financial` (e.g. "Estimated Exposure Prevented", not an unqualified
//!   "$ Saved").
//! - `pecf.rs::SecureDiagnosticLedger` is never used here — see the table above.

use std::collections::{HashMap, HashSet};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Query, Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::middleware::{self, Next};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use futures_util::stream::unfold;
use serde::{Deserialize, Serialize};

use crate::security::{AuditRecord, ImmutableAuditLog};
use crate::telemetry::{self, SecurityAlert};
use crate::trust_decay::{AgentTrustSnapshot, TrustDecayEngine, TrustEvent, TrustSignal};
use crate::MAX_PAYLOAD_SIZE;

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// M-1 fix: use the crate's single canonical constant-time comparison
/// (`security::constant_time_eq`) instead of a local byte-identical copy —
/// see that function's doc comment for why the crate no longer carries one
/// private copy per module.
use crate::security::constant_time_eq;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Bound on distinct `(source, target)` trust-mesh edges tracked before
/// oldest-(by-last_seen)-evicted, mirroring this codebase's established
/// sweep-on-overflow idiom (`gateway::RATE_LIMITER_MAX_ENTRIES`,
/// `trust_decay::TRUST_MAX_ENTRIES`, etc.).
pub const COMMAND_CENTER_MAX_EDGES: usize = 5_000;
/// Default cap on `/api/agents` response size.
pub const COMMAND_CENTER_DEFAULT_MAX_AGENTS: usize = 500;
/// Default cap on `/api/alerts` response size.
pub const COMMAND_CENTER_DEFAULT_MAX_ALERTS: usize = 500;
/// Illustrative default $/token conversion for `/api/financial` — clearly an
/// operator-configurable value, not a real pricing claim. Override via
/// `CommandCenterConfig::dollars_per_token`.
pub const COMMAND_CENTER_DEFAULT_DOLLARS_PER_TOKEN: f64 = 0.00002;
/// Bounded broadcast channel capacity for the `/events` SSE fan-out. A slow
/// SSE consumer that falls this far behind silently misses older events
/// (`RecvError::Lagged`) rather than blocking the (permanent, process-wide)
/// publishing subscriptions on the global engines.
const DASHBOARD_EVENT_CHANNEL_CAPACITY: usize = 1024;

/// Default browser `Origin`s permitted to make cross-origin requests to this API
/// (CORS allowlist). The dashboard-ui frontend (`dashboard-ui/`, a separate
/// Next.js app on a different port than this backend) is a genuine cross-origin
/// client, so without an allowlisted CORS response the browser blocks every
/// `fetch`/`EventSource` call — which is exactly what the E2E smoke test caught.
///
/// `http://localhost:3000` and `http://127.0.0.1:3000` are *distinct* browser
/// origins (the browser never treats them as equal), so both spellings of the
/// default Next.js dev port are listed. Override the whole set at startup via
/// `SAACP_DASHBOARD_ALLOWED_ORIGINS` (see `saacp_command_center.rs`).
pub const COMMAND_CENTER_DEFAULT_ALLOWED_ORIGINS: [&str; 2] =
    ["http://localhost:3000", "http://127.0.0.1:3000"];

/// Methods advertised on a CORS preflight — exactly the verbs this router serves
/// (`GET` for reads + SSE, `POST` for `/api/config/reload`), plus `OPTIONS`.
const CORS_ALLOW_METHODS: &str = "GET, POST, OPTIONS";
/// Request headers a cross-origin caller may set: the bearer `Authorization`
/// header every `/api/*` fetch presents, and `Content-Type` for JSON POSTs.
const CORS_ALLOW_HEADERS: &str = "Authorization, Content-Type";
/// How long (seconds) a browser may cache a preflight result, so the dashboard
/// doesn't re-preflight every single authenticated request.
const CORS_MAX_AGE_SECS: &str = "600";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct CommandCenterConfig {
    /// Address the dashboard's REST+SSE HTTP API binds.
    pub listen_addr: SocketAddr,
    /// Shared bearer secret required on every route except `/healthz`.
    pub dashboard_token: [u8; 32],
    /// $/token conversion used to compute `/api/financial`'s dollars figure.
    pub dollars_per_token: f64,
    /// Cap on `/api/alerts`' response size (also the `limit` query param's ceiling).
    pub max_recent_alerts: usize,
    /// Cap on `/api/agents`' response size.
    pub max_agents: usize,
    /// Cap on tracked trust-mesh edges before oldest-evicted.
    pub max_trust_mesh_edges: usize,
    /// Exact-match browser `Origin` allowlist for CORS. A cross-origin request
    /// whose `Origin` is not byte-for-byte one of these gets no
    /// `Access-Control-Allow-Origin` header, so the browser blocks it. Empty ⇒
    /// CORS effectively disabled (no browser cross-origin access at all) — a
    /// deliberate fail-closed default posture, never a wildcard. Non-browser
    /// clients (no `Origin` header) are unaffected. See
    /// `COMMAND_CENTER_DEFAULT_ALLOWED_ORIGINS`.
    pub allowed_origins: Vec<String>,
}

impl CommandCenterConfig {
    /// Convenience constructor with sane defaults for everything but the two
    /// values every deployment must actually choose: where to listen, and
    /// the shared dashboard bearer secret.
    pub fn new(listen_addr: SocketAddr, dashboard_token: [u8; 32]) -> Self {
        Self {
            listen_addr,
            dashboard_token,
            dollars_per_token: COMMAND_CENTER_DEFAULT_DOLLARS_PER_TOKEN,
            max_recent_alerts: COMMAND_CENTER_DEFAULT_MAX_ALERTS,
            max_agents: COMMAND_CENTER_DEFAULT_MAX_AGENTS,
            max_trust_mesh_edges: COMMAND_CENTER_MAX_EDGES,
            allowed_origins: COMMAND_CENTER_DEFAULT_ALLOWED_ORIGINS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

// ---------------------------------------------------------------------------
// Trust mesh store
// ---------------------------------------------------------------------------

/// One deduped `(source -> target)` capability-grant edge for the trust-mesh
/// graph. See module doc's "V1 scope limits" for what this is (and isn't).
#[derive(Debug, Clone, Serialize)]
pub struct TrustMeshEdge {
    pub source: String,
    pub target: String,
    pub depth: u32,
    pub last_seen: f64,
}

struct TrustMeshInner {
    edges: HashMap<(String, String), TrustMeshEdge>,
}

/// Bounded, deduped store of trust-mesh edges, fed by a permanent
/// `ImmutableAuditLog::subscribe` hook registered once in [`run`] — never
/// per-SSE-connection, so reconnecting dashboard clients don't grow this.
pub struct TrustMeshStore {
    inner: Mutex<TrustMeshInner>,
    max_edges: usize,
}

impl TrustMeshStore {
    fn new(max_edges: usize) -> Self {
        Self {
            inner: Mutex::new(TrustMeshInner { edges: HashMap::new() }),
            max_edges: max_edges.max(1),
        }
    }

    /// Record (or refresh) one edge. Oldest-by-`last_seen` evicted if a
    /// genuinely new edge would exceed `max_edges` — existing edges are
    /// always updated in place regardless of current size.
    fn record_edge(&self, source: String, target: String, depth: u32) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (source.clone(), target.clone());
        let now = now_epoch_secs();

        if !inner.edges.contains_key(&key) && inner.edges.len() >= self.max_edges {
            if let Some(oldest_key) = inner.edges.iter()
                .min_by(|a, b| a.1.last_seen.partial_cmp(&b.1.last_seen).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, _)| k.clone())
            {
                inner.edges.remove(&oldest_key);
            }
        }

        inner.edges.insert(key, TrustMeshEdge { source, target, depth, last_seen: now });
    }

    /// Current `(nodes, edges)` snapshot for `/api/trust-mesh`.
    fn snapshot(&self) -> (Vec<String>, Vec<TrustMeshEdge>) {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let mut nodes: HashSet<String> = HashSet::new();
        let mut edges: Vec<TrustMeshEdge> = Vec::with_capacity(inner.edges.len());
        for e in inner.edges.values() {
            nodes.insert(e.source.clone());
            nodes.insert(e.target.clone());
            edges.push(e.clone());
        }
        (nodes.into_iter().collect(), edges)
    }
}

/// `[FAITF:DELEGATION]`-prefixed `AuditRecord`s carry `token_signature =
/// "depth:{N}"` (see `faitf_audit.rs::FAITFAuditLog::log_delegation`) — parse
/// it back out. Returns `None` for any non-delegation record (the common
/// case — every other accepted packet's audit entry).
fn parse_delegation_depth(record: &AuditRecord) -> Option<u32> {
    if !record.intent.starts_with("[FAITF:DELEGATION]") {
        return None;
    }
    Some(
        record.token_signature
            .strip_prefix("depth:")
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(0),
    )
}

// ---------------------------------------------------------------------------
// Live event feed (SSE)
// ---------------------------------------------------------------------------

/// One live event pushed to every connected `/events` SSE client.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type")]
pub enum DashboardEvent {
    InjectionAlert(SecurityAlert),
    DelegationEdge { source: String, target: String, depth: u32 },
    TrustSignal { agent_id: String, score: f64, event: TrustEvent },
    AuditEntry { source: String, target: String, intent_prefix: String },
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

struct CommandCenterState {
    /// Hex encoding of `CommandCenterConfig::dashboard_token` — the actual
    /// wire representation clients present via `Authorization: Bearer
    /// <hex>` or `?token=<hex>`. Computed once at [`run`] startup rather
    /// than comparing a header string's raw bytes against the 32 raw secret
    /// bytes directly: a random 32-byte key is not, in general, valid
    /// ASCII/UTF-8, so no real HTTP client could construct a header (or URL
    /// query parameter) carrying it literally. Hex keeps the wire value
    /// ASCII-safe for both transports while `constant_time_eq` still does a
    /// full-length, branch-resistant comparison (never a plain `==`).
    ///
    /// Deliberately NOT part of `HotReloadableConfig` (R-4): the dashboard bearer
    /// secret is security-critical, and Architecture Principle #3/#4 (opusplan.md Part
    /// 12: Fail-Closed by Default, Zero-Trust Identity) rule out silently swapping
    /// trust-relevant config at runtime without a full re-provisioning/restart — the
    /// same reasoning that keeps token secrets, TLS certs, and gateway policy out of
    /// R-4's scope everywhere else in this crate.
    dashboard_token_hex: String,
    /// R-4 (opusplan.md Part 7 / 7.2): the three explicitly non-security display/limit
    /// knobs, hot-reloadable via `POST /api/config/reload` without a process restart.
    hot_config: HotReloadableConfig,
    trust_mesh: Arc<TrustMeshStore>,
    event_tx: tokio::sync::broadcast::Sender<DashboardEvent>,
    /// Exact-match CORS origin allowlist (see `CommandCenterConfig::allowed_origins`).
    /// Fixed at bind time — deliberately NOT hot-reloadable, same reasoning as
    /// `dashboard_token_hex`: which browser origins may reach the API is a
    /// security-relevant trust decision, excluded from `HotReloadableConfig`.
    allowed_origins: Vec<String>,
}

/// R-4: the illustrative $/token conversion and the two response-size caps —
/// deliberately the ONLY three `CommandCenterConfig` fields this dashboard ever
/// re-reads from the environment after startup. Every other field on
/// `CommandCenterConfig` (`listen_addr`, `dashboard_token`) is either fixed at bind
/// time or is the security-critical bearer secret excluded above.
///
/// Atomics-backed (not a `RwLock<CommandCenterConfig>`) to keep this crate's existing
/// "zero additional deps by default" convention for command-center/sidecar features —
/// no `arc-swap`/config-watcher dependency is added just for three scalars. `f64` has
/// no native atomic type, so `dollars_per_token` is stored as its `to_bits()`/
/// `from_bits()` representation in an `AtomicU64`, the same bit-reinterpretation
/// idiom Rust's own ecosystem uses for lock-free float storage.
struct HotReloadableConfig {
    dollars_per_token_bits: std::sync::atomic::AtomicU64,
    max_recent_alerts: std::sync::atomic::AtomicUsize,
    max_agents: std::sync::atomic::AtomicUsize,
}

impl HotReloadableConfig {
    fn new(dollars_per_token: f64, max_recent_alerts: usize, max_agents: usize) -> Self {
        Self {
            dollars_per_token_bits: std::sync::atomic::AtomicU64::new(dollars_per_token.to_bits()),
            max_recent_alerts: std::sync::atomic::AtomicUsize::new(max_recent_alerts),
            max_agents: std::sync::atomic::AtomicUsize::new(max_agents),
        }
    }

    fn dollars_per_token(&self) -> f64 {
        f64::from_bits(self.dollars_per_token_bits.load(std::sync::atomic::Ordering::Relaxed))
    }

    fn max_recent_alerts(&self) -> usize {
        self.max_recent_alerts.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn max_agents(&self) -> usize {
        self.max_agents.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Re-read `SAACP_DOLLARS_PER_TOKEN`/`SAACP_MAX_RECENT_ALERTS`/`SAACP_MAX_AGENTS`
    /// from the process environment and swap in any that parse successfully, leaving
    /// the current value untouched for anything unset or unparseable (never a partial
    /// failure that zeroes a field). Returns the values actually applied, for the
    /// reload endpoint's response body.
    fn reload_from_env(&self) -> ReloadedConfig {
        if let Ok(v) = std::env::var("SAACP_DOLLARS_PER_TOKEN") {
            if let Ok(parsed) = v.parse::<f64>() {
                if parsed.is_finite() && parsed >= 0.0 {
                    self.dollars_per_token_bits.store(parsed.to_bits(), std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        if let Ok(v) = std::env::var("SAACP_MAX_RECENT_ALERTS") {
            if let Ok(parsed) = v.parse::<usize>() {
                self.max_recent_alerts.store(parsed, std::sync::atomic::Ordering::Relaxed);
            }
        }
        if let Ok(v) = std::env::var("SAACP_MAX_AGENTS") {
            if let Ok(parsed) = v.parse::<usize>() {
                self.max_agents.store(parsed, std::sync::atomic::Ordering::Relaxed);
            }
        }
        ReloadedConfig {
            dollars_per_token: self.dollars_per_token(),
            max_recent_alerts: self.max_recent_alerts(),
            max_agents: self.max_agents(),
        }
    }
}

#[derive(Serialize)]
struct ReloadedConfig {
    dollars_per_token: f64,
    max_recent_alerts: usize,
    max_agents: usize,
}

fn bearer_token(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .map(|s| s.to_string())
}

fn unauthorized_response() -> Response {
    (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "unauthorized"}))).into_response()
}

/// Applied via `route_layer` to every `/api/*` route (never `/healthz`,
/// never `/events` — see [`handle_events`]'s own inline check, since
/// `EventSource` can't set headers).
async fn require_auth(State(state): State<Arc<CommandCenterState>>, request: Request, next: Next) -> Response {
    let authorized = bearer_token(request.headers())
        .map(|tok| constant_time_eq(tok.as_bytes(), state.dashboard_token_hex.as_bytes()))
        .unwrap_or(false);
    if authorized {
        next.run(request).await
    } else {
        unauthorized_response()
    }
}

/// Hand-rolled CORS layer — deliberately NOT `tower-http`'s `CorsLayer`, to keep
/// the `command-center` feature's standing "adds ZERO new dependencies" invariant
/// (see this crate's `Cargo.toml` feature comment): `tower-http` is only a
/// transitive dep here and its `cors` feature isn't enabled. This mirrors the
/// same "write the small middleware by hand rather than pull a crate" choice
/// [`require_auth`] already makes.
///
/// This layer wraps the WHOLE router (outermost), so it runs BEFORE the
/// `/api/*` `require_auth` route-layer. That ordering is load-bearing: a browser
/// CORS **preflight** (`OPTIONS`) never carries the `Authorization` header, so if
/// preflight reached `require_auth` first it would 401 and the real request would
/// never be sent. Here `OPTIONS` is answered directly with the CORS grant and
/// short-circuited; auth is still fully enforced on the actual `GET`/`POST` that
/// follows.
///
/// Security posture (fail-closed, zero-trust — Architecture Principles #3/#4):
/// - Only an `Origin` that is **byte-for-byte** in the allowlist is reflected
///   back; anything else gets no `Access-Control-Allow-Origin` and the browser
///   blocks it. No wildcard, no prefix/substring matching (the classic
///   allowlist-bypass footgun).
/// - The *specific* matched origin is echoed (never `*`) alongside `Vary: Origin`
///   so a shared cache can't serve one origin's grant to another.
/// - No `Access-Control-Allow-Credentials`: the dashboard authenticates with a
///   manual `Authorization` header, not cookies, so credentialed CORS mode is
///   neither needed nor advertised.
/// - CORS is purely a browser-side control layered on top of — never a
///   replacement for — `require_auth`. A non-browser client (curl/reqwest, LB
///   probe) sends no `Origin` and is passed through untouched.
async fn cors_layer(State(state): State<Arc<CommandCenterState>>, request: Request, next: Next) -> Response {
    // The request's `Origin`, if it's a well-formed header AND on the allowlist.
    let allowed_origin: Option<String> = request
        .headers()
        .get(axum::http::header::ORIGIN)
        .and_then(|v| v.to_str().ok())
        .filter(|origin| state.allowed_origins.iter().any(|a| a == origin))
        .map(|origin| origin.to_string());

    let is_preflight = request.method() == axum::http::Method::OPTIONS;

    // A CORS preflight is answered here and never forwarded to a route (there is
    // no `OPTIONS` handler registered, by design). A disallowed/absent origin
    // still gets a 204 but WITHOUT the allow headers, so the browser blocks it.
    let mut response = if is_preflight {
        StatusCode::NO_CONTENT.into_response()
    } else {
        next.run(request).await
    };

    if let Some(origin) = allowed_origin {
        let headers = response.headers_mut();
        // `from_str` cannot fail here: `origin` was already a valid header string
        // (it round-tripped through `to_str()` above), but guard rather than
        // `unwrap()` to keep this middleware panic-free on any future edit.
        if let Ok(val) = axum::http::HeaderValue::from_str(&origin) {
            headers.insert(axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN, val);
            headers.insert(axum::http::header::VARY, axum::http::HeaderValue::from_static("Origin"));
            if is_preflight {
                headers.insert(
                    axum::http::header::ACCESS_CONTROL_ALLOW_METHODS,
                    axum::http::HeaderValue::from_static(CORS_ALLOW_METHODS),
                );
                headers.insert(
                    axum::http::header::ACCESS_CONTROL_ALLOW_HEADERS,
                    axum::http::HeaderValue::from_static(CORS_ALLOW_HEADERS),
                );
                headers.insert(
                    axum::http::header::ACCESS_CONTROL_MAX_AGE,
                    axum::http::HeaderValue::from_static(CORS_MAX_AGE_SECS),
                );
            }
        }
    }

    response
}

async fn handle_agents(State(state): State<Arc<CommandCenterState>>) -> Json<Vec<AgentTrustSnapshot>> {
    Json(TrustDecayEngine::global().snapshot(state.hot_config.max_agents()))
}

#[derive(Serialize)]
struct TrustMeshResponse {
    nodes: Vec<String>,
    edges: Vec<TrustMeshEdge>,
}

async fn handle_trust_mesh(State(state): State<Arc<CommandCenterState>>) -> Json<TrustMeshResponse> {
    let (nodes, edges) = state.trust_mesh.snapshot();
    Json(TrustMeshResponse { nodes, edges })
}

#[derive(Deserialize)]
struct AlertsQuery {
    #[serde(default = "default_alert_limit")]
    limit: usize,
}
fn default_alert_limit() -> usize { 100 }

async fn handle_alerts(
    State(state): State<Arc<CommandCenterState>>,
    Query(q): Query<AlertsQuery>,
) -> Json<Vec<SecurityAlert>> {
    let limit = q.limit.min(state.hot_config.max_recent_alerts());
    Json(telemetry::global_alert_feed().recent(limit))
}

#[derive(Serialize)]
struct FinancialResponse {
    tokens_rejected: u64,
    dollars_per_token: f64,
    /// `tokens_rejected * dollars_per_token` — see module doc's honesty note:
    /// this is claimed-cost-prevented, not observed actual spend avoided.
    dollars_saved: f64,
}

async fn handle_financial(State(state): State<Arc<CommandCenterState>>) -> Json<FinancialResponse> {
    let tokens_rejected = telemetry::global_telemetry()
        .snapshot()
        .get("financial_tokens_rejected")
        .copied()
        .unwrap_or(0);
    let dollars_per_token = state.hot_config.dollars_per_token();
    Json(FinancialResponse {
        tokens_rejected,
        dollars_per_token,
        dollars_saved: tokens_rejected as f64 * dollars_per_token,
    })
}

async fn handle_metrics() -> String {
    telemetry::global_telemetry().render_prometheus()
}

/// R-3 (opusplan.md Part 7 / 7.2): one bundled snapshot of `audit_health` +
/// `connections` + `trust_stats` + `gate_latencies` — the exact fields that plan item
/// asks for. Deliberately a NEW, separately-authenticated route rather than a change to
/// `/healthz`: `/healthz` must stay the bare, unauthenticated liveness check L-32 scoped
/// it down to (load balancers/orchestrators can't present a bearer token, so it must
/// leak nothing beyond bare up/down), while this "deep health"/readiness view carries
/// genuinely more detail and therefore belongs behind the same `require_auth` every
/// other `/api/*` route already sits behind.
#[derive(Serialize)]
struct ReadyzAuditHealth {
    /// `security::AuditHealth` doesn't derive `Serialize` (it's a small, internal
    /// `#[repr(u8)]` enum) — rendered as its lowercase variant name instead of adding a
    /// serde dependency to that module's public API surface for one dashboard field.
    status: &'static str,
    wal_queue_depth: usize,
    wal_dropped_total: u64,
    wal_write_failures_total: u64,
}

#[derive(Serialize)]
struct ReadyzConnections {
    tcp_active: usize,
    ws_active: usize,
}

#[derive(Serialize)]
struct ReadyzTrustStats {
    agents_tracked: usize,
    /// Count of currently-tracked agents whose score sits at/below the reauth
    /// lockout threshold — the single most actionable trust-health number for an
    /// operator glancing at this endpoint, without shipping the full per-agent
    /// list `/api/agents` already serves.
    agents_requiring_reauth: usize,
}

#[derive(Serialize)]
struct ReadyzGateLatency {
    gate: &'static str,
    avg_seconds: f64,
    count: u64,
}

#[derive(Serialize)]
struct ReadyzResponse {
    audit_health: ReadyzAuditHealth,
    connections: ReadyzConnections,
    trust_stats: ReadyzTrustStats,
    gate_latencies: Vec<ReadyzGateLatency>,
}

async fn handle_readyz(State(state): State<Arc<CommandCenterState>>) -> Json<ReadyzResponse> {
    let audit = crate::security::ImmutableAuditLog::global();
    let audit_health = ReadyzAuditHealth {
        status: match audit.health() {
            crate::security::AuditHealth::Healthy => "healthy",
            crate::security::AuditHealth::Degraded => "degraded",
            crate::security::AuditHealth::Saturated => "saturated",
            crate::security::AuditHealth::Fatal => "fatal",
        },
        wal_queue_depth: audit.queue_len(),
        wal_dropped_total: audit.dropped_audit_count(),
        wal_write_failures_total: audit.wal_write_failure_count(),
    };

    let t = telemetry::global_telemetry();
    let connections = ReadyzConnections {
        tcp_active: t.active_tcp_connections(),
        ws_active: t.active_ws_connections(),
    };

    let snapshot = TrustDecayEngine::global().snapshot(state.hot_config.max_agents());
    let trust_stats = ReadyzTrustStats {
        agents_tracked: snapshot.len(),
        agents_requiring_reauth: snapshot.iter().filter(|a| a.requires_reauth).count(),
    };

    let gate_latencies = t
        .gate_latency_summary()
        .into_iter()
        .map(|(gate, avg_seconds, count)| ReadyzGateLatency { gate, avg_seconds, count })
        .collect();

    Json(ReadyzResponse { audit_health, connections, trust_stats, gate_latencies })
}

/// R-4: `POST /api/config/reload` re-reads `SAACP_DOLLARS_PER_TOKEN` /
/// `SAACP_MAX_RECENT_ALERTS` / `SAACP_MAX_AGENTS` from the process environment and
/// swaps in any that parse successfully via `HotReloadableConfig::reload_from_env`,
/// without a process restart. Authenticated via the same `require_auth` middleware
/// as every other `/api/*` route (this endpoint is deliberately NOT exempted like
/// `/healthz` — see `HotReloadableConfig`'s doc comment for why security-critical
/// config is excluded from this mechanism entirely rather than gated differently).
async fn handle_config_reload(State(state): State<Arc<CommandCenterState>>) -> Json<ReloadedConfig> {
    Json(state.hot_config.reload_from_env())
}

/// L-32 fix: `/healthz` is the one route deliberately excluded from `require_auth` (load
/// balancer / orchestrator liveness probes can't present a bearer token), so it must not
/// leak anything beyond bare liveness — process uptime was free reconnaissance
/// information (e.g. correlating a restart with a deploy or incident) at zero
/// authentication cost. Uptime-aware monitoring already has the authenticated
/// `/api/metrics` route available.
async fn handle_healthz(State(_state): State<Arc<CommandCenterState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
    }))
}

#[derive(Deserialize)]
struct EventsQuery {
    /// v1 accommodation for `EventSource` (see module doc's "V1 scope limits").
    #[serde(default)]
    token: Option<String>,
}

async fn handle_events(
    State(state): State<Arc<CommandCenterState>>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Response {
    let header_ok = bearer_token(&headers)
        .map(|tok| constant_time_eq(tok.as_bytes(), state.dashboard_token_hex.as_bytes()))
        .unwrap_or(false);
    let query_ok = q.token
        .as_deref()
        .map(|tok| constant_time_eq(tok.as_bytes(), state.dashboard_token_hex.as_bytes()))
        .unwrap_or(false);
    if !(header_ok || query_ok) {
        return unauthorized_response();
    }

    let rx = state.event_tx.subscribe();
    // `unfold` (from the already-optional `futures-util`) turns the broadcast
    // receiver into a `Stream` without pulling in `tokio-stream`. A `Lagged`
    // error (this connection fell behind the bounded channel) is skipped,
    // not fatal — dashboard telemetry, not a security-critical guarantee.
    let stream = unfold(rx, |mut rx| async move {
        loop {
            match rx.recv().await {
                Ok(ev) => {
                    let data = serde_json::to_string(&ev).unwrap_or_else(|_| "{}".to_string());
                    return Some((Ok::<Event, Infallible>(Event::default().data(data)), rx));
                }
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => continue,
                Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
            }
        }
    });

    Sse::new(stream).keep_alive(KeepAlive::default()).into_response()
}

/// Start the Command Center dashboard backend. Runs forever. See module doc
/// for the "runs in-process alongside a real gateway" architecture note.
///
/// M-37 fix: returns `std::io::Result<()>` instead of panicking on bind/serve
/// failure, matching `daemon::SAACPNetworkDaemon::start`'s /
/// `transport::ws`/`transport::tls`'s established `start()` convention — a
/// bind failure (port already in use, insufficient privilege, etc.) is an
/// ordinary, expected-to-happen environmental error, not a programmer bug;
/// the caller (`saacp_command_center`'s `main`, or any other process
/// embedding this dashboard in-process alongside a real gateway per the
/// module doc) decides how to report and exit, rather than this function
/// unwinding the whole process via `panic!`.
pub async fn run(config: CommandCenterConfig) -> std::io::Result<()> {
    let trust_mesh = Arc::new(TrustMeshStore::new(config.max_trust_mesh_edges));
    let (event_tx, _rx) = tokio::sync::broadcast::channel::<DashboardEvent>(DASHBOARD_EVENT_CHANNEL_CAPACITY);

    // ── Permanent, process-wide subscriptions ────────────────────────────
    // Registered exactly once here, NOT per-SSE-connection — none of
    // TrustDecayEngine/ImmutableAuditLog/SecurityAlertFeed's `subscribe`
    // methods support unsubscribing, so a per-connection registration would
    // grow their observer lists forever across dashboard reconnects. Each
    // `/events` connection instead just calls `event_tx.subscribe()` (cheap,
    // bounded, and cleaned up automatically when the receiver drops).
    {
        let tx = event_tx.clone();
        telemetry::global_alert_feed().subscribe(Arc::new(move |alert: &SecurityAlert| {
            let _ = tx.send(DashboardEvent::InjectionAlert(alert.clone()));
        }));
    }
    {
        let tx = event_tx.clone();
        let tm = Arc::clone(&trust_mesh);
        ImmutableAuditLog::global().subscribe(Arc::new(move |record: &AuditRecord| {
            if let Some(depth) = parse_delegation_depth(record) {
                tm.record_edge(record.source.clone(), record.target.clone(), depth);
                let _ = tx.send(DashboardEvent::DelegationEdge {
                    source: record.source.clone(),
                    target: record.target.clone(),
                    depth,
                });
            } else {
                let _ = tx.send(DashboardEvent::AuditEntry {
                    source: record.source.clone(),
                    target: record.target.clone(),
                    intent_prefix: record.intent.chars().take(120).collect(),
                });
            }
        }));
    }
    {
        let tx = event_tx.clone();
        TrustDecayEngine::global().subscribe(Arc::new(move |signal: TrustSignal| {
            let _ = tx.send(DashboardEvent::TrustSignal {
                agent_id: signal.agent_id,
                score: signal.score,
                event: signal.event,
            });
        }));
    }

    let state = Arc::new(CommandCenterState {
        dashboard_token_hex: hex::encode(config.dashboard_token),
        hot_config: HotReloadableConfig::new(
            config.dollars_per_token,
            config.max_recent_alerts,
            config.max_agents,
        ),
        trust_mesh,
        event_tx,
        allowed_origins: config.allowed_origins.clone(),
    });

    let protected = Router::new()
        .route("/api/agents", get(handle_agents))
        .route("/api/trust-mesh", get(handle_trust_mesh))
        .route("/api/alerts", get(handle_alerts))
        .route("/api/financial", get(handle_financial))
        .route("/api/metrics", get(handle_metrics))
        .route("/api/readyz", get(handle_readyz))
        .route("/api/config/reload", post(handle_config_reload))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), require_auth));

    let app = Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/events", get(handle_events))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE))
        // Outermost layer: runs before `require_auth` so browser CORS preflights
        // (unauthenticated `OPTIONS`) are answered directly instead of 401'd. See
        // `cors_layer`'s doc comment for why this ordering is load-bearing.
        .layer(middleware::from_fn_with_state(Arc::clone(&state), cors_layer))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr).await?;

    eprintln!("[SAACP Command Center] HTTP API listening on {}", config.listen_addr);
    axum::serve(listener, app).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn trust_mesh_store_dedupes_and_updates_in_place() {
        let store = TrustMeshStore::new(10);
        store.record_edge("a".into(), "b".into(), 0);
        store.record_edge("a".into(), "b".into(), 1); // same pair, updated depth
        let (nodes, edges) = store.snapshot();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0].depth, 1);
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn trust_mesh_store_evicts_oldest_when_over_cap() {
        let store = TrustMeshStore::new(2);
        store.record_edge("a".into(), "b".into(), 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.record_edge("c".into(), "d".into(), 0);
        std::thread::sleep(std::time::Duration::from_millis(5));
        store.record_edge("e".into(), "f".into(), 0); // should evict a->b (oldest)
        let (_, edges) = store.snapshot();
        assert_eq!(edges.len(), 2);
        assert!(!edges.iter().any(|e| e.source == "a"));
    }

    #[test]
    fn parse_delegation_depth_extracts_from_token_signature() {
        let rec = AuditRecord {
            timestamp: 0.0,
            source: "parent".into(),
            target: "child".into(),
            intent: "[FAITF:DELEGATION] parent=parent child=child depth=3 constraints=x".into(),
            token_signature: "depth:3".into(),
            traceparent: "".into(),
            prev_hash: "".into(),
            seq: 0,
        };
        assert_eq!(parse_delegation_depth(&rec), Some(3));
    }

    #[test]
    fn parse_delegation_depth_none_for_non_delegation_record() {
        let rec = AuditRecord {
            timestamp: 0.0,
            source: "a".into(),
            target: "b".into(),
            intent: "read:data".into(),
            token_signature: "sig".into(),
            traceparent: "".into(),
            prev_hash: "".into(),
            seq: 0,
        };
        assert_eq!(parse_delegation_depth(&rec), None);
    }

    #[test]
    fn dashboard_event_serializes_with_type_tag() {
        let ev = DashboardEvent::DelegationEdge { source: "a".into(), target: "b".into(), depth: 1 };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"type\":\"DelegationEdge\""));
        assert!(json.contains("\"source\":\"a\""));
    }
}
