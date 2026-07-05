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
use axum::routing::get;
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

/// Same branch-resistant comparison idiom used throughout this crate
/// (`gateway.rs`, `security.rs`) — duplicated locally rather than exposed
/// from another module, matching this codebase's existing precedent of one
/// small private copy per module rather than a shared public helper.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

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
        let mut inner = self.inner.lock().unwrap();
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
        let inner = self.inner.lock().unwrap();
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
    dashboard_token_hex: String,
    dollars_per_token: f64,
    max_recent_alerts: usize,
    max_agents: usize,
    trust_mesh: Arc<TrustMeshStore>,
    event_tx: tokio::sync::broadcast::Sender<DashboardEvent>,
    started_at: f64,
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

async fn handle_agents(State(state): State<Arc<CommandCenterState>>) -> Json<Vec<AgentTrustSnapshot>> {
    Json(TrustDecayEngine::global().snapshot(state.max_agents))
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
    let limit = q.limit.min(state.max_recent_alerts);
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
    Json(FinancialResponse {
        tokens_rejected,
        dollars_per_token: state.dollars_per_token,
        dollars_saved: tokens_rejected as f64 * state.dollars_per_token,
    })
}

async fn handle_metrics() -> String {
    telemetry::global_telemetry().render_prometheus()
}

async fn handle_healthz(State(state): State<Arc<CommandCenterState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "uptime_secs": now_epoch_secs() - state.started_at,
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
pub async fn run(config: CommandCenterConfig) {
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
        dollars_per_token: config.dollars_per_token,
        max_recent_alerts: config.max_recent_alerts,
        max_agents: config.max_agents,
        trust_mesh,
        event_tx,
        started_at: now_epoch_secs(),
    });

    let protected = Router::new()
        .route("/api/agents", get(handle_agents))
        .route("/api/trust-mesh", get(handle_trust_mesh))
        .route("/api/alerts", get(handle_alerts))
        .route("/api/financial", get(handle_financial))
        .route("/api/metrics", get(handle_metrics))
        .route_layer(middleware::from_fn_with_state(Arc::clone(&state), require_auth));

    let app = Router::new()
        .route("/healthz", get(handle_healthz))
        .route("/events", get(handle_events))
        .merge(protected)
        .layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.listen_addr)
        .await
        .unwrap_or_else(|e| panic!("saacp-command-center: bind HTTP {} failed: {}", config.listen_addr, e));

    eprintln!("[SAACP Command Center] HTTP API listening on {}", config.listen_addr);
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| panic!("saacp-command-center: HTTP server failed: {}", e));
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
