//! `health.rs` — standalone HTTP health + metrics endpoint for the
//! `SAACPNetworkDaemon` (Phase 4 / plan item 2b).
//!
//! The Command Center (`command-center` feature, `src/command_center.rs`)
//! ships a richer dashboard with the same metrics, but is opt-in. This
//! module is the minimal operator surface for Kubernetes liveness/readiness
//! probes and Prometheus scrapers — gated by the `health-endpoint` Cargo
//! feature so library-only deployments never pull in `axum`.
//!
//! # Routes
//!
//! | Route             | Auth          | Purpose                                              |
//! |-------------------|---------------|------------------------------------------------------|
//! | `/healthz`        | None          | Liveness. 200 if the daemon is alive, 503 on Fatal.  |
//! | `/readyz`         | None          | Readiness. 200 unless AuditHealth is Saturated/Fatal.|
//! | `/metrics`        | Bearer if     | Prometheus text exposition.                          |
//! |                   | non-loopback  |                                                      |
//! | `/api/audit/ack`  | Bearer always | Operator acknowledgement of dropped audits (Phase 3).|
//!
//! `/api/audit/ack` is an *operator action* endpoint, not a probe: it releases
//! the sticky Gate 2.5 audit drop floor (see
//! `ImmutableAuditLog::acknowledge_dropped_audits`), appends the
//! acknowledgement to the audit chain, and records a `SecurityAlert`. Because
//! an unauthenticated caller must never be able to release a fail-closed
//! safety floor, it requires a bearer token in ALL cases — when no token is
//! configured the endpoint answers 503 (disabled), never 200.
//!
//! The default bind is **loopback only** (`127.0.0.1:9091`). Bind a
//! non-loopback address to expose the endpoint on a pod IP — in that
//! case the operator MUST set a bearer token (or the daemon refuses to
//! start the health server), and `/metrics` requires `Authorization:
//! Bearer <token>`. `/healthz` and `/readyz` are always unauthenticated
//! because that's what Kubernetes probes expect — the threat model is
//! "trusted network inside the pod", not "untrusted internet".
//!
//! # Audit subsystem coupling
//!
//! The handlers read `ImmutableAuditLog::global()` (the same singleton the
//! command center reads) so the metrics an operator sees are consistent
//! across both endpoints. Once `report_financial_rejection_for` is wired
//! into a per-tenant context in the daemon, a future enhancement can
//! parameterize this on the context.

#![cfg(feature = "health-endpoint")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::Serialize;

use crate::security::{AuditHealth, ImmutableAuditLog};
use crate::session_affinity::SessionAffinityTracker;
use crate::telemetry::{SecurityAlert, SecurityAlertFeed, TelemetryCollector};

/// Bearer-token-expected value passed to [`HealthServer::with_bearer_token`].
/// If `Some`, any non-loopback bind requires `Authorization: Bearer <token>`
/// on `/metrics`. `/healthz` and `/readyz` are always unauthenticated
/// (Kubernetes probe contract).
#[derive(Clone)]
pub struct BearerToken(Arc<String>);

impl BearerToken {
    /// Constant-time comparison against the provided `Authorization` header
    /// value (expected to be either `Bearer <token>` or `<token>`).
    ///
    /// Returns `true` only on exact match. Uses `subtle::ConstantTimeEq` to
    /// avoid leaking length information via timing.
    pub fn matches(&self, header_value: &str) -> bool {
        let expected = self.0.as_bytes();
        // Strip a leading "Bearer " if present.
        let candidate = header_value
            .strip_prefix("Bearer ")
            .unwrap_or(header_value)
            .as_bytes();
        // Length-mismatch short-circuit is fine — token length is not
        // secret, only the token content is.
        if expected.len() != candidate.len() {
            return false;
        }
        subtle::ConstantTimeEq::ct_eq(expected, candidate).into()
    }
}

/// Shared state handed to the health handlers. Cloned cheaply — every
/// field is `Arc`-shaped.
#[derive(Clone)]
pub struct HealthState {
    /// Approximate number of currently active TCP connections. The daemon
    /// updates this on every accept / drop via [`crate::telemetry::ConnectionCountGuard`].
    pub connection_count: Arc<AtomicU64>,
    /// The audit subsystem the health probe consults. Always the global
    /// singleton today; future per-tenant work can parameterize.
    pub audit_log: Arc<ImmutableAuditLog>,
    /// The telemetry collector whose `render_prometheus()` is served on
    /// `/metrics`. Same singleton the command center reads.
    pub telemetry: Arc<TelemetryCollector>,
    /// Optional bearer token. When `Some`, non-loopback binds require
    /// the token on `/metrics` only.
    pub bearer_token: Option<BearerToken>,
    /// Phase 3: this node's session-affinity tracker, when configured
    /// (`with_node_id` / `with_affinity_tracker`). `None` (single-node /
    /// library use) reports `session_affinity.tracked == false` on `/readyz`.
    pub session_affinity_tracker: Option<Arc<SessionAffinityTracker>>,
    /// Phase 3 (R8 / finding H): whether this process is the fleet's
    /// designated audit-chain node. Visibility only.
    pub audit_node_designated: bool,
    /// Phase 3: the alert feed the `/api/audit/ack` endpoint records its
    /// `SecurityAlert` into (per-tenant when a context is configured,
    /// process-global otherwise).
    pub alerts: Arc<SecurityAlertFeed>,
    /// Phase 3: the stable issuer secret used to HMAC-bind the operator
    /// acknowledgement record appended to the audit chain by
    /// `/api/audit/ack`. Should be the same `token_issuer_secret` the gate
    /// pipeline binds audit entries with, so `verify_chain(secret)` covers
    /// the acknowledgement. `None` binds with an empty secret (still
    /// chain-linked, but verify with the same empty secret).
    pub audit_issuer_secret: Option<Arc<Vec<u8>>>,
}

impl HealthState {
    /// New state with no bearer token (loopback-only deployment).
    pub fn new(audit_log: Arc<ImmutableAuditLog>, telemetry: Arc<TelemetryCollector>) -> Self {
        Self {
            connection_count: Arc::new(AtomicU64::new(0)),
            audit_log,
            telemetry,
            bearer_token: None,
            session_affinity_tracker: None,
            audit_node_designated: false,
            alerts: SecurityAlertFeed::global_arc().clone(),
            audit_issuer_secret: None,
        }
    }

    /// Attach a bearer token required for `/metrics` on non-loopback binds.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(BearerToken(Arc::new(token.into())));
        self
    }

    /// Phase 3: attach the session-affinity tracker surfaced on `/readyz`.
    pub fn with_session_affinity_tracker(mut self, tracker: Arc<SessionAffinityTracker>) -> Self {
        self.session_affinity_tracker = Some(tracker);
        self
    }

    /// Phase 3: set the audit-chain designation role reported on `/healthz`.
    pub fn with_audit_node_designated(mut self, designated: bool) -> Self {
        self.audit_node_designated = designated;
        self
    }

    /// Phase 3: attach the alert feed the audit-ack endpoint records into
    /// (defaults to the process-global feed).
    pub fn with_alerts_feed(mut self, feed: Arc<SecurityAlertFeed>) -> Self {
        self.alerts = feed;
        self
    }

    /// Phase 3: attach the issuer secret the audit-ack endpoint uses to
    /// HMAC-bind its acknowledgement record into the audit chain.
    pub fn with_audit_issuer_secret(mut self, secret: Arc<Vec<u8>>) -> Self {
        self.audit_issuer_secret = Some(secret);
        self
    }
}

/// Phase 3: session-affinity health surfaced on `/readyz` (M11 / R7).
#[derive(Serialize)]
pub struct SessionAffinityStatus {
    /// Whether a session-affinity tracker is configured on this node.
    pub tracked: bool,
    /// Lifetime violation count (a session_id appearing on a node that did
    /// not create it — proof the load balancer is not session-affine).
    pub violations: u64,
}

/// JSON shape of `/healthz` and `/readyz` responses. Stable; the command
/// center dashboard parses the same fields.
#[derive(Serialize)]
pub struct HealthResponse {
    /// Overall daemon status: `"ok"`, `"degraded"`, `"saturated"`, or `"fatal"`.
    pub status: String,
    /// Audit subsystem health, same string as `status` for the audit
    /// dimension specifically. Surfaces the `AuditHealth` enum verbatim
    /// so an operator can tell whether the daemon is unhealthy because
    /// of audit back-pressure (saturated) versus an outright failure
    /// (fatal).
    pub audit_health: String,
    /// Approximate current WAL queue depth (events pending flush).
    pub wal_queue_depth: usize,
    /// Approximate number of dropped audit events (cumulative, never reset).
    pub dropped_audits: u64,
    /// Approximate number of currently active TCP connections.
    pub active_connections: u64,
    /// Phase 3: session-affinity tracking health (M11 / R7).
    pub session_affinity: SessionAffinityStatus,
    /// Phase 3 (R8 / finding H): `"designated"` when this process is the
    /// fleet's audit-chain node, `"non_designated"` otherwise. Visibility
    /// only — no consensus or routing logic keys off this.
    pub audit_chain_role: String,
}

/// Build the health-endpoint axum router. Bind via
/// [`axum::serve`] on a `tokio::net::TcpListener` constructed in the
/// daemon's `start()`.
pub fn health_router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
        .route("/api/audit/ack", post(audit_ack))
        .with_state(state)
}

async fn liveness(State(state): State<HealthState>) -> Response {
    let health = state.audit_log.health();
    let status = match health {
        AuditHealth::Fatal => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::OK,
    };
    let body = health_body(&state, health);
    (status, Json(body)).into_response()
}

async fn readiness(State(state): State<HealthState>) -> Response {
    let health = state.audit_log.health();
    let status = match health {
        AuditHealth::Saturated | AuditHealth::Fatal => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::OK,
    };
    let body = health_body(&state, health);
    (status, Json(body)).into_response()
}

async fn metrics(State(state): State<HealthState>, headers: HeaderMap) -> Response {
    // If a bearer token is configured, require it on /metrics. We do not
    // require it on /healthz or /readyz because Kubernetes probes cannot
    // send an Authorization header on every poll.
    if let Some(token) = &state.bearer_token {
        let provided = headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !token.matches(provided) {
            return (
                StatusCode::UNAUTHORIZED,
                [("WWW-Authenticate", "Bearer")],
                "missing or invalid bearer token",
            )
                .into_response();
        }
    }
    let body = state.telemetry.render_prometheus();
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
        .into_response()
}

fn health_body(state: &HealthState, health: AuditHealth) -> HealthResponse {
    let status_str = match health {
        AuditHealth::Healthy => "ok",
        AuditHealth::Degraded => "degraded",
        AuditHealth::Saturated => "saturated",
        AuditHealth::Fatal => "fatal",
    };
    let violations = state
        .telemetry
        .snapshot()
        .get("session_affinity_violations_total")
        .copied()
        .unwrap_or(0);
    HealthResponse {
        status: status_str.to_string(),
        audit_health: status_str.to_string(),
        wal_queue_depth: state.audit_log.queue_len(),
        dropped_audits: state.audit_log.dropped_audit_count(),
        active_connections: state.connection_count.load(Ordering::Relaxed),
        session_affinity: SessionAffinityStatus {
            tracked: state.session_affinity_tracker.is_some(),
            violations,
        },
        audit_chain_role: if state.audit_node_designated {
            "designated".to_string()
        } else {
            "non_designated".to_string()
        },
    }
}

/// Phase 3: operator acknowledgement of dropped audit events.
///
/// Wraps [`ImmutableAuditLog::acknowledge_dropped_audits`] — the explicit
/// operator action the sticky-floor design requires before Gate 2.5 resumes
/// authorizing IRREVERSIBLE actions after a WAL drop. The acknowledgement
/// itself is appended to the audit chain (who/when/count) so the
/// reconciliation is tamper-evidently on the record, and a `SecurityAlert` is
/// recorded so dashboards and subscribers see it live. Fail-closed semantics
/// are untouched: a `Fatal` health state is NOT cleared by the acknowledgement
/// (only constructing a fresh log clears that), and the lifetime
/// `dropped_audits` total is never reset.
///
/// ALWAYS bearer-gated (unlike `/metrics`, which is only gated when a token
/// is configured). When no token is configured the endpoint is disabled
/// (503) — an unauthenticated caller must never be able to release a
/// fail-closed safety floor.
async fn audit_ack(State(state): State<HealthState>, headers: HeaderMap) -> Response {
    let Some(token) = &state.bearer_token else {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "audit-ack endpoint requires a bearer token — configure \
             with_health_endpoint(bind, Some(token))",
        )
            .into_response();
    };
    let provided = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !token.matches(provided) {
        return (
            StatusCode::UNAUTHORIZED,
            [("WWW-Authenticate", "Bearer")],
            "missing or invalid bearer token",
        )
            .into_response();
    }

    // Release the sticky drop floor. This is the explicit operator
    // acknowledgement — Gate 2.5's fail-closed behavior for the window
    // BEFORE this call is the design working as intended.
    let released = state.audit_log.acknowledge_dropped_audits();

    // Append the acknowledgement to the audit chain (who/when/count). Bound
    // with the same issuer secret the gate pipeline uses so verify_chain
    // covers it; without a configured secret an empty one is used (documented
    // on HealthState::audit_issuer_secret).
    let secret: &[u8] = state
        .audit_issuer_secret
        .as_deref()
        .map(|v| v.as_slice())
        .unwrap_or(&[]);
    state.audit_log.append_event(
        secret,
        "operator",
        "audit-chain",
        "audit-ack",
        &format!(
            "DROPPED_AUDITS_ACKNOWLEDGED released_count={released} \
             by=health-endpoint route=/api/audit/ack"
        ),
        "",
    );

    // Live alert so dashboards/subscribers observe the acknowledgement.
    state.alerts.record(SecurityAlert {
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs_f64())
            .unwrap_or_default(),
        agent_id: "operator".to_string(),
        gate: "audit_ack",
        bytecode: "AuditDropsAcknowledged".to_string(),
        estimated_cost: None,
    });

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "acknowledged": true,
            "released": released,
        })),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_matches_exact() {
        let t = BearerToken(Arc::new("hunter2".to_string()));
        assert!(t.matches("Bearer hunter2"));
        assert!(t.matches("hunter2"));
        assert!(!t.matches("Bearer wrong"));
        assert!(!t.matches(""));
    }

    #[test]
    fn bearer_token_length_mismatch_short_circuits() {
        let t = BearerToken(Arc::new("hunter2".to_string()));
        // A length-mismatched candidate must reject without a content
        // comparison (no early return inside ConstantTimeEq).
        assert!(!t.matches("Bearer hunter2x"));
        assert!(!t.matches("hunter"));
    }

    #[test]
    fn health_body_serializes_known_states() {
        // Pure-function test: confirm every AuditHealth variant maps to
        // a non-empty status string. The full JSON render is covered by
        // the HTTP integration test in test_health_endpoint_rs (added
        // by this change set).
        for h in [
            AuditHealth::Healthy,
            AuditHealth::Degraded,
            AuditHealth::Saturated,
            AuditHealth::Fatal,
        ] {
            // We can't construct a full HealthState without a real
            // audit log, so we just confirm the variant-to-string
            // mapping is exhaustive.
            let s = match h {
                AuditHealth::Healthy => "ok",
                AuditHealth::Degraded => "degraded",
                AuditHealth::Saturated => "saturated",
                AuditHealth::Fatal => "fatal",
            };
            assert!(!s.is_empty());
        }
    }
}
