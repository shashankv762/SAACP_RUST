//! `SaacpContext` — the Phase 4 de-globalization seam (kimiplan #1).
//!
//! SAACP grew ~30 process-global mutable singletons (trust engine, telemetry,
//! rulepack store, stream registry, audit log, alert feed, ...). That model
//! has three documented costs (see kimiplan's "Architecture / scalability"
//! and this repo's own benchmark notes):
//!
//! 1. **No tenant isolation** — one process = one trust/audit/capability
//!    universe; two logically separate SAACP meshes cannot safely share a
//!    process.
//! 2. **Test serialization** — tests mutating global state leak into each
//!    other (the `serial_test` dev-dependency exists purely to serialize
//!    them).
//! 3. **Lock contention** — every connection serializes on the same global
//!    engines (the `cscs_1000_unique_sessions_burst` variance in
//!    `benchmark_results.md`).
//!
//! `SaacpContext` owns one instance of each pipeline-facing subsystem behind
//! an `Arc`. Two constructors cover the two modes:
//!
//! - [`SaacpContext::new`] — a FRESH, hermetic context (every subsystem
//!   privately owned). This is the multi-tenant/serverless shape: N contexts
//!   in one process, zero cross-talk. Trust penalties, telemetry counters,
//!   audit chains, and stream state are per-context.
//! - [`SaacpContext::shared_default`] — a process-wide default context whose
//!   fields alias the EXACT instances the legacy `::global()` accessors
//!   return (each subsystem's `global_arc()`), so existing deployments, the
//!   dashboard, and the command center observe identical behavior. The gate
//!   pipeline runs on this context when no explicit one is injected.
//!
//! The handler's intercept entry points take an optional context
//! (`None` → `shared_default()`), mirroring the pre-existing `Option<&..>`
//! injection seam `intercept_packet_full` already used for the gateway and
//! rate limiter. The legacy globals remain as deprecated-in-spirit shims;
//! no production path is REQUIRED to touch them anymore.
//!
//! **Scope note (honest support matrix):** this context owns the six
//! subsystems the intercept pipeline itself reads/writes per packet
//! (trust, telemetry, alerts, rulepacks, streams, audit). Subsystems that
//! remain process-global by design — the daemon-injected
//! [`crate::gateway::ZeroTrustGateway`]/[`crate::gateway::AgentRateLimiter`]
//! (the daemon owns per-deployment instances and injects them explicitly),
//! the cluster/gossip engines, and the diagnostic-only singletons
//! (`DeadMansSwitch`, `FederatedMemory`, `IevlEngine`,
//! `IntentDriftTracker`) — are documented as such in their modules; none of
//! them carry per-tenant authorization state on the packet path.

use std::sync::{Arc, LazyLock};

use crate::rulepack::RulePackStore;
use crate::security::ImmutableAuditLog;
use crate::streaming::StreamRegistry;
use crate::telemetry::{SecurityAlertFeed, TelemetryCollector};
use crate::trust_decay::TrustDecayEngine;

/// One isolated set of SAACP pipeline state. See the module doc.
///
/// `Clone` is deliberately cheap (every field is an `Arc` clone — atomic
/// refcount bumps, no data copied): handing the same context to a daemon and
/// its diagnostic endpoints shares state; handing each tenant its own
/// `SaacpContext::new()` isolates them.
#[derive(Clone)]
pub struct SaacpContext {
    /// Trust-decay engine: penalties, rewards, scope caps, reauth floors.
    pub trust: Arc<TrustDecayEngine>,
    /// Telemetry counters/histograms + the Prometheus renderer's source.
    pub telemetry: Arc<TelemetryCollector>,
    /// Live security alert ring + subscribers (feeds MACE and the dashboard).
    pub alerts: Arc<SecurityAlertFeed>,
    /// Signed injection-rulepack store (Gate 4.0's dynamic rules).
    pub rulepacks: Arc<RulePackStore>,
    /// Binary-stream session registry (STREAM_START/CONT/END state).
    pub streams: Arc<StreamRegistry>,
    /// HMAC-chained immutable audit log (Gate 6.0, WAL-backed).
    pub audit: Arc<ImmutableAuditLog>,
}

impl Default for SaacpContext {
    fn default() -> Self {
        Self::new()
    }
}

impl SaacpContext {
    /// A fresh, hermetic context — every subsystem privately owned. For
    /// multi-tenant deployments: construct one per tenant and thread it into
    /// that tenant's daemon(s). Nothing here is reachable from any other
    /// context or from the legacy process globals.
    pub fn new() -> Self {
        Self {
            trust: Arc::new(TrustDecayEngine::new()),
            telemetry: Arc::new(TelemetryCollector::new()),
            alerts: Arc::new(SecurityAlertFeed::new()),
            rulepacks: Arc::new(RulePackStore::new()),
            streams: Arc::new(StreamRegistry::new()),
            audit: Arc::new(ImmutableAuditLog::with_default_path()),
        }
    }

    /// The process-wide default context — every field is the EXACT instance
    /// the legacy `::global()` accessor returns, so code still using the
    /// globals and code using this context observe the same state. The gate
    /// pipeline uses this when no explicit context is injected.
    pub fn shared_default() -> &'static Self {
        Self::shared_default_arc()
    }

    /// `Arc` handle to the shared default — for `spawn_blocking` dispatch.
    pub fn shared_default_arc() -> &'static Arc<Self> {
        static DEFAULT: LazyLock<Arc<SaacpContext>> = LazyLock::new(|| {
            Arc::new(SaacpContext {
                trust: Arc::clone(TrustDecayEngine::global_arc()),
                telemetry: crate::telemetry::global_telemetry_arc(),
                alerts: Arc::clone(SecurityAlertFeed::global_arc()),
                rulepacks: Arc::clone(RulePackStore::global_arc()),
                streams: Arc::clone(StreamRegistry::global_arc()),
                audit: Arc::clone(ImmutableAuditLog::global_arc()),
            })
        });
        &DEFAULT
    }

    /// `Some(arc)` when `ctx` is `None` — the pipeline's injection helper.
    pub fn or_shared_default(ctx: Option<&SaacpContext>) -> &SaacpContext {
        match ctx {
            Some(c) => c,
            None => Self::shared_default(),
        }
    }

    /// Replace individual subsystems (builder-style) on a clone.
    pub fn with_trust(mut self, trust: Arc<TrustDecayEngine>) -> Self {
        self.trust = trust;
        self
    }
    pub fn with_telemetry(mut self, telemetry: Arc<TelemetryCollector>) -> Self {
        self.telemetry = telemetry;
        self
    }
    pub fn with_rulepacks(mut self, rulepacks: Arc<RulePackStore>) -> Self {
        self.rulepacks = rulepacks;
        self
    }
    pub fn with_streams(mut self, streams: Arc<StreamRegistry>) -> Self {
        self.streams = streams;
        self
    }
    pub fn with_audit(mut self, audit: Arc<ImmutableAuditLog>) -> Self {
        self.audit = audit;
        self
    }
    pub fn with_alerts(mut self, alerts: Arc<SecurityAlertFeed>) -> Self {
        self.alerts = alerts;
        self
    }
}
