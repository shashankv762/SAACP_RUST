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
//!   audit chains, stream state, rate limits, revocations, and loop/governor
//!   state are per-context.
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
//! **Scope note (support matrix after the longcat.md re-verification):**
//! every subsystem the intercept pipeline reads/writes per packet now lives
//! here — trust, telemetry, alerts, rulepacks, streams, audit (Phase 4) plus
//! the rate limiter, gateway, AEGF governor, CSCS loop detector, intent-drift
//! tracker, dead-man's-switch, federated memory, IEVL engine, and identity
//! gate (Gap B completion). Handler fallbacks resolve
//! `param → context → legacy global`, and the daemon injects its
//! context-owned instances explicitly, so the legacy process globals are no
//! longer reachable from the packet hot path. The cluster/gossip engines
//! remain daemon-owned (topology state, not per-packet pipeline state) and
//! are documented as such in their modules.

use std::sync::{Arc, LazyLock};

use crate::aegf::{AEGFGovernor, DistributedExecutionGraph};
use crate::cscs::CSCSLoopDetector;
use crate::gateway::{AgentRateLimiter, ZeroTrustGateway};
use crate::identity_binding::IdentityGate;
use crate::ievl::IevlEngine;
use crate::memory::FederatedMemory;
use crate::rulepack::RulePackStore;
use crate::security::ImmutableAuditLog;
use crate::streaming::StreamRegistry;
use crate::telemetry::{SecurityAlertFeed, TelemetryCollector};
use crate::temporal::DeadMansSwitch;
use crate::trust_decay::{IntentDriftTracker, TrustDecayEngine};

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
    /// Per-agent circuit breaker / rate limiter (pregate + Gate 2.5).
    pub rate_limiter: Arc<AgentRateLimiter>,
    /// Fallback capability gateway (Gate 1.0 stream revocation checks).
    ///
    /// NOTE: a daemon that injects its own gateway via `with_gateway` keeps
    /// using that one on the Gate 1.0 path; this field is the None-gateway
    /// revocation fallback (aliased to `ZeroTrustGateway::global_arc()` in
    /// the shared default).
    pub gateway: Arc<ZeroTrustGateway>,
    /// AEGF causal-graph governor (Gate 11.0).
    pub aegf: Arc<AEGFGovernor>,
    /// CSCS loop detector (Gate 12.0).
    pub cscs: Arc<CSCSLoopDetector>,
    /// Delegation-chain cumulative drift tracker (Gate 1.5).
    pub intent_drift: Arc<IntentDriftTracker>,
    /// Liveness/heartbeat switch (HEARTBEAT_PING context validation).
    pub dead_mans_switch: Arc<DeadMansSwitch>,
    /// Federated context-state memory (context_state_id validation).
    pub federated_memory: Arc<FederatedMemory>,
    /// Intent-declaration receipt engine (IEVL registration hook).
    pub ievl: Arc<IevlEngine>,
    /// Session identity-phase gate (C-3 ordering bookkeeping).
    pub identity_gate: Arc<IdentityGate>,
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
            rate_limiter: Arc::new(AgentRateLimiter::new()),
            gateway: Arc::new(ZeroTrustGateway::new()),
            aegf: Arc::new(AEGFGovernor::new(None)),
            cscs: Arc::new(CSCSLoopDetector::new(Arc::new(
                DistributedExecutionGraph::new(),
            ))),
            intent_drift: Arc::new(IntentDriftTracker::new()),
            dead_mans_switch: Arc::new(DeadMansSwitch::new()),
            federated_memory: Arc::new(FederatedMemory::new()),
            ievl: Arc::new(IevlEngine::new()),
            identity_gate: Arc::new(IdentityGate::new()),
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
                rate_limiter: Arc::clone(AgentRateLimiter::global_arc()),
                gateway: Arc::clone(ZeroTrustGateway::global_arc()),
                aegf: Arc::clone(&*crate::aegf::GLOBAL_AEGF_GOVERNOR),
                cscs: Arc::clone(&*crate::cscs::GLOBAL_CSCS),
                intent_drift: Arc::clone(IntentDriftTracker::global_arc()),
                dead_mans_switch: Arc::clone(DeadMansSwitch::global_arc()),
                federated_memory: Arc::clone(FederatedMemory::global_arc()),
                ievl: Arc::clone(IevlEngine::global_arc()),
                identity_gate: Arc::clone(&*crate::identity_binding::GLOBAL_IDENTITY_GATE),
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
    pub fn with_rate_limiter(mut self, rate_limiter: Arc<AgentRateLimiter>) -> Self {
        self.rate_limiter = rate_limiter;
        self
    }
    pub fn with_gateway(mut self, gateway: Arc<ZeroTrustGateway>) -> Self {
        self.gateway = gateway;
        self
    }
    pub fn with_aegf(mut self, aegf: Arc<AEGFGovernor>) -> Self {
        self.aegf = aegf;
        self
    }
    pub fn with_cscs(mut self, cscs: Arc<CSCSLoopDetector>) -> Self {
        self.cscs = cscs;
        self
    }
    pub fn with_intent_drift(mut self, intent_drift: Arc<IntentDriftTracker>) -> Self {
        self.intent_drift = intent_drift;
        self
    }
    pub fn with_dead_mans_switch(mut self, dead_mans_switch: Arc<DeadMansSwitch>) -> Self {
        self.dead_mans_switch = dead_mans_switch;
        self
    }
    pub fn with_federated_memory(mut self, federated_memory: Arc<FederatedMemory>) -> Self {
        self.federated_memory = federated_memory;
        self
    }
    pub fn with_ievl(mut self, ievl: Arc<IevlEngine>) -> Self {
        self.ievl = ievl;
        self
    }
    pub fn with_identity_gate(mut self, identity_gate: Arc<IdentityGate>) -> Self {
        self.identity_gate = identity_gate;
        self
    }
}
