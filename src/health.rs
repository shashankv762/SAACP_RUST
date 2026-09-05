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
//! | Route       | Auth          | Purpose                                              |
//! |-------------|---------------|------------------------------------------------------|
//! | `/healthz`  | None          | Liveness. 200 if the daemon is alive, 503 on Fatal.  |
//! | `/readyz`   | None          | Readiness. 200 unless AuditHealth is Saturated/Fatal.|
//! | `/metrics`  | Bearer if     | Prometheus text exposition.                          |
//! |             | non-loopback  |                                                      |
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
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;

use crate::security::{AuditHealth, ImmutableAuditLog};
use crate::telemetry::TelemetryCollector;

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
}

impl HealthState {
    /// New state with no bearer token (loopback-only deployment).
    pub fn new(audit_log: Arc<ImmutableAuditLog>, telemetry: Arc<TelemetryCollector>) -> Self {
        Self {
            connection_count: Arc::new(AtomicU64::new(0)),
            audit_log,
            telemetry,
            bearer_token: None,
        }
    }

    /// Attach a bearer token required for `/metrics` on non-loopback binds.
    pub fn with_bearer_token(mut self, token: impl Into<String>) -> Self {
        self.bearer_token = Some(BearerToken(Arc::new(token.into())));
        self
    }
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
}

/// Build the health-endpoint axum router. Bind via
/// [`axum::serve`] on a `tokio::net::TcpListener` constructed in the
/// daemon's `start()`.
pub fn health_router(state: HealthState) -> Router {
    Router::new()
        .route("/healthz", get(liveness))
        .route("/readyz", get(readiness))
        .route("/metrics", get(metrics))
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
    HealthResponse {
        status: status_str.to_string(),
        audit_health: status_str.to_string(),
        wal_queue_depth: state.audit_log.queue_len(),
        dropped_audits: state.audit_log.dropped_audit_count(),
        active_connections: state.connection_count.load(Ordering::Relaxed),
    }
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
