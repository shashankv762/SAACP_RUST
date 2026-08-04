//! telemetry.rs — Structured Metrics & Observability for SAACP
//!
//! Tracks per-gate rejection counts, circuit breaker trips, token cache metrics,
//! stream statistics, injection detections, and AEGF/CSCS decisions.
//!
//! Exports metrics in Prometheus text format via `render_prometheus()` so any
//! standard scraper (Prometheus, VictoriaMetrics, Grafana Agent) can consume them
//! without adding an HTTP server dependency to this library.
//!
//! # Usage
//! ```ignore
//! use saacp::telemetry::global_telemetry;
//! global_telemetry().record_gate_rejection("gate_4_0_injection");
//! let report = global_telemetry().render_prometheus();
//! ```

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::Serialize;

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ---------------------------------------------------------------------------
// Global singleton
// ---------------------------------------------------------------------------

/// Process-wide telemetry collector.
pub static GLOBAL_TELEMETRY: OnceLock<TelemetryCollector> = OnceLock::new();

/// Initialise and return the global collector (idempotent).
pub fn global_telemetry() -> &'static TelemetryCollector {
    GLOBAL_TELEMETRY.get_or_init(TelemetryCollector::new)
}

/// Subscribe the global telemetry collector to `TrustDecayEngine::global()`'s
/// signal stream, so Trust Decay Engine activity (penalties, downgrades,
/// reauth) shows up in `render_prometheus()`'s output.
///
/// Opt-in, matching this module's existing philosophy — nothing in this
/// crate calls `global_telemetry()` automatically (every counter here is
/// only ever updated by a caller choosing to instrument its own call site).
/// Call this once at process startup if you want Trust Decay Engine metrics
/// scraped; skipping it costs nothing (the engine itself works identically
/// either way, this only affects observability).
pub fn wire_trust_decay_metrics() {
    use crate::trust_decay::{TrustDecayEngine, TrustEvent};
    use std::sync::Arc;
    TrustDecayEngine::global().subscribe(Arc::new(|signal| {
        let t = global_telemetry();
        if let TrustEvent::Penalized(kind) = signal.event {
            t.record_trust_penalty(kind);
        }
        if let TrustEvent::Rewarded(kind) = signal.event {
            t.record_trust_reward(kind);
        }
        match signal.event {
            TrustEvent::Downgraded => t.record_trust_downgrade(),
            TrustEvent::ReauthRequired => t.record_trust_reauth_required(),
            TrustEvent::Penalized(_) | TrustEvent::Recovered | TrustEvent::Rewarded(_) => {}
        }
    }));
}

// ---------------------------------------------------------------------------
// Counter bank (lock-free atomic u64)
// ---------------------------------------------------------------------------

/// All named counters.  Adding a new metric = one line here + one arm in render.
pub struct Counters {
    // ── Gate-level rejections ────────────────────────────────────────────────
    pub gate_0_crypto_failures:        AtomicU64,
    pub gate_1_0_token_invalid:        AtomicU64,
    pub gate_1_5_intent_mismatch:      AtomicU64,
    pub gate_2_5_escalation:           AtomicU64,
    pub gate_3_0_lateral_blocked:      AtomicU64,
    pub gate_4_0_injection_detected:   AtomicU64,
    pub gate_4_0_encoded_injection:    AtomicU64,
    pub gate_5_0_epistemic_low:        AtomicU64,
    pub gate_6_0_audit_drop:           AtomicU64,
    pub gate_9_0_schema_invalid:       AtomicU64,
    pub gate_11_0_aegf_blocked:        AtomicU64,
    pub gate_12_0_cscs_loop:           AtomicU64,
    /// Gates that reject in the live pipeline but had no dedicated counter until
    /// their `record_gate_rejection` arms were added. Kept here (not folded into
    /// a neighbouring gate) so each renders as its own
    /// `saacp_gate_rejections_total{gate=…}` series.
    pub gate_0_5_financial_blocked:    AtomicU64,
    pub aca_attestation_failed:        AtomicU64,
    pub sid_semantic_blocked:          AtomicU64,
    pub ievl_receipt_rejected:         AtomicU64,

    // ── Token lifecycle ──────────────────────────────────────────────────────
    pub tokens_issued:                 AtomicU64,
    pub tokens_expired:                AtomicU64,
    pub tokens_revoked:                AtomicU64,
    pub token_cache_hits:              AtomicU64,
    pub token_cache_misses:            AtomicU64,
    pub rrbc_redeemed:                 AtomicU64,
    pub rrbc_replay_blocked:           AtomicU64,
    pub rrbc_pop_failed:               AtomicU64,

    // ── Circuit breakers ─────────────────────────────────────────────────────
    pub circuit_breaker_trips:         AtomicU64,
    pub cover_traffic_rate_exceeded:   AtomicU64,
    pub ping_flood_detected:           AtomicU64,

    // ── Stream lifecycle ─────────────────────────────────────────────────────
    pub streams_started:               AtomicU64,
    pub streams_completed:             AtomicU64,
    pub streams_aborted:               AtomicU64,
    pub stream_frames_processed:       AtomicU64,
    pub stream_bytes_processed:        AtomicU64,

    // ── Cryptographic events ─────────────────────────────────────────────────
    pub epoch_rotations:               AtomicU64,
    /// KLMS key rotations (Phase 5, item 4) — distinct from `epoch_rotations`
    /// (per-epoch MEASC traffic-key rotation); this counts
    /// `KeyLifecycleManager::rotate_key` calls, both manual and automatic
    /// (`sweep_and_rotate`).
    pub key_rotations_total:           AtomicU64,
    pub psk_compromise_recoveries:     AtomicU64,

    // ── Active-Active clustering (`cluster.rs`) ──────────────────────────────
    /// Inbound cluster membership messages refused by `ClusterEngine`. Deliberately a
    /// single counter rather than one series per `ClusterRejection` variant or per peer
    /// node id — see this struct's cardinality note above.
    pub cluster_messages_rejected:     AtomicU64,
    /// Leadership changes observed by this node, including stepping down on quorum loss.
    /// Equals this node's fencing epoch, so a rising rate means election flapping.
    pub cluster_leadership_changes:    AtomicU64,
    /// Members transitioned to `Dead` by the failure detector — the failover trigger.
    pub cluster_members_failed:        AtomicU64,

    // ── Dynamic injection rule packs (`rulepack.rs`) ─────────────────────────
    /// Signed rule packs successfully verified and adopted.
    pub rulepack_installs_total:       AtomicU64,
    /// Rule packs refused for any reason. Bounded-cardinality by design: a single
    /// counter, never one series per `RulePackRejection` variant, per pack id, or
    /// per issuer — the specific reason goes to the alert feed instead.
    pub rulepack_rejections_total:     AtomicU64,
    /// Active packs dropped by the maintenance sweep because `valid_until` passed.
    pub rulepack_expirations_total:    AtomicU64,
    /// Gauge (not a counter): injection signatures currently loaded, built-ins
    /// included. Equals the built-in count when no pack is installed.
    pub rulepack_active_rules:         AtomicU64,
    pub easi_encryptions:              AtomicU64,
    pub easi_decryptions:              AtomicU64,
    pub replay_attacks_blocked:        AtomicU64,
    pub psn_out_of_window:             AtomicU64,

    // ── Delegation / identity ────────────────────────────────────────────────
    pub delegation_depth_exceeded:     AtomicU64,
    pub identity_binding_failed:       AtomicU64,
    pub acsvaf_verifications:          AtomicU64,
    pub factf_quorum_met:              AtomicU64,
    pub factf_quorum_failed:           AtomicU64,

    // ── Throughput ───────────────────────────────────────────────────────────
    pub packets_accepted:              AtomicU64,
    pub packets_rejected:              AtomicU64,
    pub cover_traffic_frames:          AtomicU64,

    // ── Trust Decay Engine (trust_decay.rs) ──────────────────────────────────
    // Bounded-cardinality by design: one counter per PenaltyKind variant (6
    // total), never a per-agent label — an unbounded number of distinct
    // agent_ids as Prometheus label values would be a real memory/scrape-cost
    // risk on a metrics endpoint. `trust_agents_tracked` (the live map size)
    // is rendered directly from `TrustDecayEngine::global()` at render time,
    // not stored here, since it's a gauge, not a monotonic counter.
    pub trust_penalties_replay:            AtomicU64,
    pub trust_penalties_intent_drift:      AtomicU64,
    pub trust_penalties_scope_violation:   AtomicU64,
    pub trust_penalties_injection:         AtomicU64,
    pub trust_penalties_epistemic:         AtomicU64,
    pub trust_penalties_generic:           AtomicU64,
    /// Phase 6 / Part 8.1 (IEVL): `PenaltyKind::TargetViolation`.
    pub trust_penalties_target_violation:  AtomicU64,
    /// Phase 6 / Part 8.1 (IEVL): `PenaltyKind::ReceiptTimeout`.
    pub trust_penalties_receipt_timeout:   AtomicU64,
    /// Phase 6 / Part 8.2 (MACE): `PenaltyKind::CollusionSuspected`.
    pub trust_penalties_collusion:         AtomicU64,
    pub trust_downgrades_total:            AtomicU64,
    pub trust_reauth_required_total:       AtomicU64,
    /// Phase 6 / Part 8.5: total `TrustDecayEngine::reward()` calls that
    /// actually credited a score change (i.e. were not rate-limited away by
    /// `TRUST_MAX_REWARDS_PER_MINUTE`), by `RewardKind`.
    pub trust_rewards_clean_passage:       AtomicU64,
    pub trust_rewards_valid_receipt:       AtomicU64,

    // ── Financial Circuit Breaker (Gate 0.5, handler.rs::gate_financial_cb) ──
    // Sum of `estimated_cost` across every rejected (BudgetExceeded) packet.
    // This is "tokens the caller claimed it would spend and was prevented
    // from spending" — NOT a claim about actual downstream cost avoidance,
    // which this system has no way to observe. A single global counter, not
    // per-agent, to keep this bounded-cardinality like the trust-penalty
    // counters above.
    pub financial_tokens_rejected:         AtomicU64,
}

impl Counters {
    fn new() -> Self {
        macro_rules! z { () => { AtomicU64::new(0) } }
        Self {
            gate_0_crypto_failures:        z!(),
            gate_1_0_token_invalid:        z!(),
            gate_1_5_intent_mismatch:      z!(),
            gate_2_5_escalation:           z!(),
            gate_3_0_lateral_blocked:      z!(),
            gate_4_0_injection_detected:   z!(),
            gate_4_0_encoded_injection:    z!(),
            gate_5_0_epistemic_low:        z!(),
            gate_6_0_audit_drop:           z!(),
            gate_9_0_schema_invalid:       z!(),
            gate_11_0_aegf_blocked:        z!(),
            gate_12_0_cscs_loop:           z!(),
            gate_0_5_financial_blocked:    z!(),
            aca_attestation_failed:        z!(),
            sid_semantic_blocked:          z!(),
            ievl_receipt_rejected:         z!(),
            tokens_issued:                 z!(),
            tokens_expired:                z!(),
            tokens_revoked:                z!(),
            token_cache_hits:              z!(),
            token_cache_misses:            z!(),
            rrbc_redeemed:                 z!(),
            rrbc_replay_blocked:           z!(),
            rrbc_pop_failed:               z!(),
            circuit_breaker_trips:         z!(),
            cover_traffic_rate_exceeded:   z!(),
            ping_flood_detected:           z!(),
            streams_started:               z!(),
            streams_completed:             z!(),
            streams_aborted:               z!(),
            stream_frames_processed:       z!(),
            stream_bytes_processed:        z!(),
            epoch_rotations:               z!(),
            key_rotations_total:           z!(),
            psk_compromise_recoveries:     z!(),
            cluster_messages_rejected:     z!(),
            cluster_leadership_changes:    z!(),
            cluster_members_failed:        z!(),
            rulepack_installs_total:       z!(),
            rulepack_rejections_total:     z!(),
            rulepack_expirations_total:    z!(),
            rulepack_active_rules:         z!(),
            easi_encryptions:              z!(),
            easi_decryptions:              z!(),
            replay_attacks_blocked:        z!(),
            psn_out_of_window:             z!(),
            delegation_depth_exceeded:     z!(),
            identity_binding_failed:       z!(),
            acsvaf_verifications:          z!(),
            factf_quorum_met:              z!(),
            factf_quorum_failed:           z!(),
            packets_accepted:              z!(),
            packets_rejected:              z!(),
            cover_traffic_frames:          z!(),
            trust_penalties_replay:          z!(),
            trust_penalties_intent_drift:    z!(),
            trust_penalties_scope_violation: z!(),
            trust_penalties_injection:       z!(),
            trust_penalties_epistemic:       z!(),
            trust_penalties_generic:         z!(),
            trust_penalties_target_violation: z!(),
            trust_penalties_receipt_timeout:  z!(),
            trust_penalties_collusion:        z!(),
            trust_downgrades_total:          z!(),
            trust_reauth_required_total:     z!(),
            trust_rewards_clean_passage:     z!(),
            trust_rewards_valid_receipt:     z!(),
            financial_tokens_rejected:       z!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Per-gate latency histograms (O-1)
// ---------------------------------------------------------------------------
//
// Hand-rolled, matching this module's existing house style (`render_prometheus`
// is entirely hand-written text formatting — no external metrics/histogram
// crate is used anywhere in this codebase). Bucket boundaries in seconds,
// spanning microseconds (cheap structural gates) to low-hundreds-of-milliseconds
// (Gate 0's real AES-256-GCM decrypt under load), with a `+Inf` overflow bucket.

/// Cumulative Prometheus-style histogram bucket upper bounds ("le"), in seconds.
/// Each `Histogram::observe` call increments every bucket whose bound is >= the
/// observed value, so a bucket's raw counter IS the cumulative count already —
/// exactly Prometheus's `_bucket{le="..."}` wire semantics, no post-processing
/// needed at render time.
const LATENCY_BUCKET_BOUNDS_SECS: &[f64] = &[
    0.00001, 0.00005, 0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, f64::INFINITY,
];

/// A single gate's latency distribution. Lock-free hot path: every field is an
/// atomic, so `observe()` never blocks a concurrent packet on another one.
struct Histogram {
    buckets: Vec<AtomicU64>,
    /// Total elapsed time across all observations, in nanoseconds. A `u64` of
    /// nanoseconds overflows only after ~584 years of cumulative observed
    /// latency, which is not a realistic operational concern for a single
    /// process's uptime.
    sum_nanos: AtomicU64,
    count: AtomicU64,
}

impl Histogram {
    fn new() -> Self {
        Self {
            buckets: (0..LATENCY_BUCKET_BOUNDS_SECS.len()).map(|_| AtomicU64::new(0)).collect(),
            sum_nanos: AtomicU64::new(0),
            count: AtomicU64::new(0),
        }
    }

    fn observe(&self, elapsed: Duration) {
        let secs = elapsed.as_secs_f64();
        for (i, bound) in LATENCY_BUCKET_BOUNDS_SECS.iter().enumerate() {
            if secs <= *bound {
                self.buckets[i].fetch_add(1, Ordering::Relaxed);
            }
        }
        // `min(u64::MAX as u128)` defends against the astronomically unlikely
        // (but not type-impossible) case of `as_nanos()` exceeding u64::MAX.
        let nanos = elapsed.as_nanos().min(u64::MAX as u128) as u64;
        self.sum_nanos.fetch_add(nanos, Ordering::Relaxed);
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    fn render(&self, gate: &str, out: &mut String) {
        for (i, bound) in LATENCY_BUCKET_BOUNDS_SECS.iter().enumerate() {
            let le = if bound.is_infinite() { "+Inf".to_string() } else { format!("{bound}") };
            out.push_str(&format!(
                "saacp_gate_latency_seconds_bucket{{gate=\"{gate}\",le=\"{le}\"}} {}\n",
                self.buckets[i].load(Ordering::Relaxed)
            ));
        }
        let sum_secs = self.sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;
        out.push_str(&format!(
            "saacp_gate_latency_seconds_sum{{gate=\"{gate}\"}} {sum_secs:.9}\n"
        ));
        out.push_str(&format!(
            "saacp_gate_latency_seconds_count{{gate=\"{gate}\"}} {}\n",
            self.count.load(Ordering::Relaxed)
        ));
    }

    /// R-3: mean latency (seconds) + observation count for this gate, for compact
    /// JSON summaries (e.g. `/api/readyz`) that don't need the full bucket
    /// distribution `render` emits in Prometheus text form.
    fn avg_and_count(&self) -> (f64, u64) {
        let count = self.count.load(Ordering::Relaxed);
        let sum_secs = self.sum_nanos.load(Ordering::Relaxed) as f64 / 1_000_000_000.0;
        let avg = if count > 0 { sum_secs / count as f64 } else { 0.0 };
        (avg, count)
    }
}

/// Registry of per-gate `Histogram`s, keyed by the same `&'static str` gate
/// names used by `record_gate_rejection`/`report_gate_rejection`. Gate names
/// are a small, fixed, compile-time-constant set (not attacker-controlled
/// input), so an `RwLock<HashMap<..>>` is bounded by construction — never an
/// unbounded-cardinality label risk the way a per-agent label would be.
///
/// Read-lock fast path once a gate's histogram exists (the common case after
/// process warm-up): only the very first observation of each distinct gate
/// name pays a write-lock. `Histogram::observe` itself is then lock-free.
struct GateLatencyHistograms {
    histograms: RwLock<HashMap<&'static str, Histogram>>,
}

impl GateLatencyHistograms {
    fn new() -> Self {
        Self { histograms: RwLock::new(HashMap::new()) }
    }

    fn observe(&self, gate: &'static str, elapsed: Duration) {
        {
            let map = self.histograms.read().unwrap_or_else(|e| e.into_inner());
            if let Some(h) = map.get(gate) {
                h.observe(elapsed);
                return;
            }
        }
        let mut map = self.histograms.write().unwrap_or_else(|e| e.into_inner());
        map.entry(gate).or_insert_with(Histogram::new).observe(elapsed);
    }

    fn render(&self, out: &mut String) {
        let map = self.histograms.read().unwrap_or_else(|e| e.into_inner());
        let mut gates: Vec<&'static str> = map.keys().copied().collect();
        gates.sort();
        for gate in gates {
            if let Some(h) = map.get(gate) {
                h.render(gate, out);
            }
        }
    }

    /// R-3: `(gate, avg_seconds, count)` for every gate observed so far, sorted by
    /// gate name — the compact form `/api/readyz` needs, versus `render`'s full
    /// Prometheus bucket text.
    fn summary(&self) -> Vec<(&'static str, f64, u64)> {
        let map = self.histograms.read().unwrap_or_else(|e| e.into_inner());
        let mut gates: Vec<&'static str> = map.keys().copied().collect();
        gates.sort();
        gates
            .into_iter()
            .filter_map(|gate| map.get(gate).map(|h| {
                let (avg, count) = h.avg_and_count();
                (gate, avg, count)
            }))
            .collect()
    }

    fn reset(&self) {
        self.histograms.write().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

// ---------------------------------------------------------------------------
// Per-(gate, bytecode) rejection counters (O-2 fine-grained dimension)
// ---------------------------------------------------------------------------
//
// `TelemetryCollector::record_gate_rejection` (above) already counts
// rejections per gate; this adds the bytecode dimension the O-2 spec calls
// for ("Counter per gate per bytecode"). Bounded cardinality: both the gate
// name and the bytecode's `Debug` string come from fixed, finite, non-
// attacker-controlled enums (≤12 gates × a few dozen `SAACPBytecodes`
// variants — a few hundred entries at most, never growing further).
struct GateBytecodeCounters {
    counts: Mutex<HashMap<(&'static str, String), u64>>,
}

impl GateBytecodeCounters {
    fn new() -> Self {
        Self { counts: Mutex::new(HashMap::new()) }
    }

    fn record(&self, gate: &'static str, bytecode: &str) {
        let mut m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        *m.entry((gate, bytecode.to_string())).or_insert(0) += 1;
    }

    fn render(&self, out: &mut String) {
        let m = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        let mut entries: Vec<((&'static str, String), u64)> =
            m.iter().map(|(k, v)| (k.clone(), *v)).collect();
        entries.sort();
        for ((gate, bytecode), count) in entries {
            out.push_str(&format!(
                "saacp_gate_rejections_by_bytecode_total{{gate=\"{gate}\",bytecode=\"{bytecode}\"}} {count}\n"
            ));
        }
    }

    fn reset(&self) {
        self.counts.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }
}

// ---------------------------------------------------------------------------
// Connection-count gauges (O-4)
// ---------------------------------------------------------------------------
//
// TCP (`daemon.rs`) and WebSocket (`transport/ws.rs`) each own an independent
// `connection_semaphore`/`per_ip_connections` pair (CRIT-9 fix) but neither
// exposes live occupancy anywhere — these two process-wide atomics, paired
// with the `ConnectionCountGuard` RAII type below, close that gap without
// requiring either transport daemon to become a singleton.
struct ConnectionGauges {
    tcp_active: AtomicUsize,
    ws_active: AtomicUsize,
}

impl ConnectionGauges {
    fn new() -> Self {
        Self { tcp_active: AtomicUsize::new(0), ws_active: AtomicUsize::new(0) }
    }
}

#[derive(Clone, Copy)]
enum ConnectionKind {
    Tcp,
    Ws,
}

/// RAII guard pairing a connection-count gauge increment with its eventual
/// decrement. Construct one (`ConnectionCountGuard::tcp()`/`::ws()`) right
/// alongside a transport daemon's existing `_permit`/`_per_ip_guard` locals
/// inside the spawned per-connection task — its `Drop` fires on every exit
/// path (normal return, early return, or `JoinSet::abort_all()` during
/// shutdown drain-timeout), exactly mirroring `daemon::PerIpConnectionGuard`'s
/// idiom, so the gauge can never leak an increment without a matching
/// decrement.
pub struct ConnectionCountGuard {
    kind: ConnectionKind,
}

impl ConnectionCountGuard {
    /// Increment the TCP active-connection gauge; decremented on drop.
    pub fn tcp() -> Self {
        global_telemetry().counters_connections().tcp_active.fetch_add(1, Ordering::Relaxed);
        Self { kind: ConnectionKind::Tcp }
    }

    /// Increment the WebSocket active-connection gauge; decremented on drop.
    pub fn ws() -> Self {
        global_telemetry().counters_connections().ws_active.fetch_add(1, Ordering::Relaxed);
        Self { kind: ConnectionKind::Ws }
    }
}

impl Drop for ConnectionCountGuard {
    fn drop(&mut self) {
        let gauges = global_telemetry().counters_connections();
        let counter = match self.kind {
            ConnectionKind::Tcp => &gauges.tcp_active,
            ConnectionKind::Ws => &gauges.ws_active,
        };
        // Saturating decrement: an unpaired drop (which should never happen
        // given the RAII pairing above, but must never be trusted blindly on
        // a security-relevant gauge) must never wrap a usize to near-MAX.
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| Some(v.saturating_sub(1)));
    }
}

// ---------------------------------------------------------------------------
// Mutex contention probes (O-6)
// ---------------------------------------------------------------------------
//
// Instrumentation only — never a behavior change. Each instrumented call site
// does a non-blocking `try_lock()` first; on `WouldBlock` it records one
// contention observation here and then falls through to the normal blocking
// `.lock()`, so the guarded critical section still executes exactly as
// before. Deliberately limited to the two genuinely hot, per-packet locks
// identified during Phase 3's own performance audit — `ImmutableAuditLog`'s
// per-event hash-chain lock and AEGF's combined DEG state lock — rather than
// every mutex in the codebase, since a `try_lock()` probe on a cold path adds
// overhead for no signal.
struct ContentionProbes {
    wal_append: AtomicU64,
    deg_state: AtomicU64,
}

impl ContentionProbes {
    fn new() -> Self {
        Self { wal_append: AtomicU64::new(0), deg_state: AtomicU64::new(0) }
    }
}

// ---------------------------------------------------------------------------
// Per-agent error histogram (top-N by error count)
// ---------------------------------------------------------------------------

const AGENT_ERROR_TOP_N: usize = 50;

struct AgentErrorEntry {
    count: u64,
    last_seen: f64,
}

// ---------------------------------------------------------------------------
// TelemetryCollector
// ---------------------------------------------------------------------------

/// Main telemetry collector — lock-free for hot-path counters, mutex only for
/// per-agent histogram which is updated infrequently.
pub struct TelemetryCollector {
    pub counters: Counters,
    /// Per-agent error counts (guarded by mutex — updated on errors only).
    agent_errors: Mutex<HashMap<String, AgentErrorEntry>>,
    /// Timestamp when this collector was created (for uptime metric).
    created_at: f64,
    /// Per-gate latency distributions (O-1).
    gate_latencies: GateLatencyHistograms,
    /// Per-(gate, bytecode) rejection counts (O-2 fine-grained dimension).
    gate_bytecode_rejections: GateBytecodeCounters,
    /// Live TCP/WS active-connection gauges (O-4).
    connections: ConnectionGauges,
    /// Mutex `try_lock()` contention probes (O-6).
    contention: ContentionProbes,
}

impl TelemetryCollector {
    pub fn new() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            counters: Counters::new(),
            agent_errors: Mutex::new(HashMap::new()),
            created_at: now,
            gate_latencies: GateLatencyHistograms::new(),
            gate_bytecode_rejections: GateBytecodeCounters::new(),
            connections: ConnectionGauges::new(),
            contention: ContentionProbes::new(),
        }
    }

    /// Internal accessor for `ConnectionCountGuard` — not part of the public
    /// counter-recording API surface (those all go through the named
    /// `record_*`/`active_*` methods below).
    fn counters_connections(&self) -> &ConnectionGauges {
        &self.connections
    }

    // ── Recording helpers ────────────────────────────────────────────────────

    pub fn record_gate_rejection(&self, gate: &str) {
        match gate {
            "gate_0_crypto"   => { self.counters.gate_0_crypto_failures.fetch_add(1, Ordering::Relaxed); }
            "gate_1_0_token"  => { self.counters.gate_1_0_token_invalid.fetch_add(1, Ordering::Relaxed); }
            "gate_1_5_intent" => { self.counters.gate_1_5_intent_mismatch.fetch_add(1, Ordering::Relaxed); }
            "gate_2_5_kinetic"=> { self.counters.gate_2_5_escalation.fetch_add(1, Ordering::Relaxed); }
            "gate_3_0_lateral"=> { self.counters.gate_3_0_lateral_blocked.fetch_add(1, Ordering::Relaxed); }
            "gate_4_0_inject" => { self.counters.gate_4_0_injection_detected.fetch_add(1, Ordering::Relaxed); }
            "gate_4_0_encoded"=> { self.counters.gate_4_0_encoded_injection.fetch_add(1, Ordering::Relaxed); }
            "gate_5_0_epistemic"=>{ self.counters.gate_5_0_epistemic_low.fetch_add(1, Ordering::Relaxed); }
            "gate_6_0_audit"  => { self.counters.gate_6_0_audit_drop.fetch_add(1, Ordering::Relaxed); }
            "gate_9_0_schema" => { self.counters.gate_9_0_schema_invalid.fetch_add(1, Ordering::Relaxed); }
            "gate_11_0_aegf"  => { self.counters.gate_11_0_aegf_blocked.fetch_add(1, Ordering::Relaxed); }
            "gate_12_0_cscs"  => { self.counters.gate_12_0_cscs_loop.fetch_add(1, Ordering::Relaxed); }
            // Gates that reject at live sites in handler.rs / ievl.rs but were
            // previously absent from this match, so their dedicated per-gate
            // counter never moved during a real attack (the by-bytecode map did
            // record them, but the flat `saacp_gate_rejections_total{gate=…}`
            // series read zero). `gate_1_0_identity_binding` reuses the existing
            // `identity_binding_failed` counter — that is exactly what it counts.
            "gate_1_0_identity_binding" => { self.counters.identity_binding_failed.fetch_add(1, Ordering::Relaxed); }
            "gate_0_5_financial" => { self.counters.gate_0_5_financial_blocked.fetch_add(1, Ordering::Relaxed); }
            "aca_attestation"    => { self.counters.aca_attestation_failed.fetch_add(1, Ordering::Relaxed); }
            "sid_semantic"       => { self.counters.sid_semantic_blocked.fetch_add(1, Ordering::Relaxed); }
            "ievl_receipt"       => { self.counters.ievl_receipt_rejected.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    pub fn record_packet_accepted(&self) {
        self.counters.packets_accepted.fetch_add(1, Ordering::Relaxed);
    }

    /// M-38 fix: every `self.agent_errors.lock()` in this impl block recovers
    /// via `into_inner()` on poison rather than panicking —
    /// `global_telemetry()`'s `TelemetryCollector` is a process-wide
    /// singleton, so one poisoning panic must not cascade into every other
    /// packet's error-tracking/telemetry-rendering calls.
    pub fn record_packet_rejected(&self, agent_id: &str) {
        self.counters.packets_rejected.fetch_add(1, Ordering::Relaxed);
        if !agent_id.is_empty() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let mut map = self.agent_errors.lock().unwrap_or_else(|e| e.into_inner());
            let e = map.entry(agent_id.to_string()).or_insert(AgentErrorEntry { count: 0, last_seen: now });
            e.count += 1;
            e.last_seen = now;
            // Evict if over cap — remove the entry with smallest count
            if map.len() > AGENT_ERROR_TOP_N {
                if let Some(min_key) = map.iter()
                    .min_by_key(|(_, v)| v.count)
                    .map(|(k, _)| k.clone())
                {
                    map.remove(&min_key);
                }
            }
        }
    }

    pub fn record_circuit_breaker_trip(&self, agent_id: &str) {
        self.counters.circuit_breaker_trips.fetch_add(1, Ordering::Relaxed);
        self.record_packet_rejected(agent_id);
    }

    pub fn record_cover_traffic(&self)   { self.counters.cover_traffic_frames.fetch_add(1, Ordering::Relaxed); }
    pub fn record_stream_start(&self)    { self.counters.streams_started.fetch_add(1, Ordering::Relaxed); }
    pub fn record_stream_complete(&self) { self.counters.streams_completed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_stream_abort(&self)    { self.counters.streams_aborted.fetch_add(1, Ordering::Relaxed); }
    pub fn record_stream_frame(&self, bytes: usize) {
        self.counters.stream_frames_processed.fetch_add(1, Ordering::Relaxed);
        self.counters.stream_bytes_processed.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    pub fn record_epoch_rotation(&self)      { self.counters.epoch_rotations.fetch_add(1, Ordering::Relaxed); }
    pub fn record_key_rotation(&self)        { self.counters.key_rotations_total.fetch_add(1, Ordering::Relaxed); }
    pub fn record_replay_blocked(&self)      { self.counters.replay_attacks_blocked.fetch_add(1, Ordering::Relaxed); }
    pub fn record_psn_out_of_window(&self)   { self.counters.psn_out_of_window.fetch_add(1, Ordering::Relaxed); }
    pub fn record_ping_flood(&self)          { self.counters.ping_flood_detected.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rrbc_replay(&self)         { self.counters.rrbc_replay_blocked.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rrbc_pop_failed(&self)     { self.counters.rrbc_pop_failed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rrbc_redeemed(&self)       { self.counters.rrbc_redeemed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_token_issued(&self)        { self.counters.tokens_issued.fetch_add(1, Ordering::Relaxed); }
    pub fn record_token_revoked(&self)       { self.counters.tokens_revoked.fetch_add(1, Ordering::Relaxed); }
    pub fn record_token_expired(&self)       { self.counters.tokens_expired.fetch_add(1, Ordering::Relaxed); }
    pub fn record_cache_hit(&self)           { self.counters.token_cache_hits.fetch_add(1, Ordering::Relaxed); }
    pub fn record_cache_miss(&self)          { self.counters.token_cache_misses.fetch_add(1, Ordering::Relaxed); }
    pub fn record_delegation_exceeded(&self) { self.counters.delegation_depth_exceeded.fetch_add(1, Ordering::Relaxed); }
    pub fn record_identity_failed(&self)     { self.counters.identity_binding_failed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_psk_recovery(&self)        { self.counters.psk_compromise_recoveries.fetch_add(1, Ordering::Relaxed); }
    pub fn record_cluster_message_rejected(&self)  { self.counters.cluster_messages_rejected.fetch_add(1, Ordering::Relaxed); }
    pub fn record_cluster_leadership_change(&self) { self.counters.cluster_leadership_changes.fetch_add(1, Ordering::Relaxed); }
    pub fn record_cluster_member_failed(&self)     { self.counters.cluster_members_failed.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rulepack_installed(&self)  { self.counters.rulepack_installs_total.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rulepack_rejected(&self)   { self.counters.rulepack_rejections_total.fetch_add(1, Ordering::Relaxed); }
    pub fn record_rulepack_expired(&self)    { self.counters.rulepack_expirations_total.fetch_add(1, Ordering::Relaxed); }

    /// Set the live injection-signature count (a gauge, not a counter — it can
    /// fall when a pack expires and the process reverts to the built-in baseline).
    pub fn set_rulepack_active_rules(&self, n: u64) {
        self.counters.rulepack_active_rules.store(n, Ordering::Relaxed);
    }

    /// Record one gate's processing latency (O-1). `gate` should be the same
    /// `&'static str` used at that call site's `report_gate_rejection`/
    /// `timed_gate!` invocation (e.g. `"gate_0_crypto"`). Recorded on BOTH the
    /// accept and reject path — a gate that always rejects fast would
    /// otherwise look artificially cheap in the exported histogram.
    pub fn record_gate_latency(&self, gate: &'static str, elapsed: Duration) {
        self.gate_latencies.observe(gate, elapsed);
    }

    /// Record one gate rejection's bytecode (O-2 fine-grained dimension).
    /// Called by `report_gate_rejection` alongside the existing per-gate-only
    /// counter — see `GateBytecodeCounters` for the bounded-cardinality
    /// rationale.
    pub fn record_gate_rejection_bytecode(&self, gate: &'static str, bytecode: &str) {
        self.gate_bytecode_rejections.record(gate, bytecode);
    }

    /// Current number of live TCP connections (O-4), maintained by
    /// `ConnectionCountGuard::tcp()`/its `Drop` impl.
    pub fn active_tcp_connections(&self) -> usize {
        self.connections.tcp_active.load(Ordering::Relaxed)
    }

    /// Current number of live WebSocket connections (O-4), maintained by
    /// `ConnectionCountGuard::ws()`/its `Drop` impl.
    pub fn active_ws_connections(&self) -> usize {
        self.connections.ws_active.load(Ordering::Relaxed)
    }

    /// R-3: `(gate, avg_latency_seconds, observation_count)` for every gate observed
    /// so far — the compact summary `/api/readyz` bundles alongside audit health,
    /// connection counts, and trust stats. See `GateLatencyHistograms::summary`.
    pub fn gate_latency_summary(&self) -> Vec<(&'static str, f64, u64)> {
        self.gate_latencies.summary()
    }

    /// Record one `try_lock()` contention observation (O-6) for a named
    /// instrumented lock. `lock` must be one of the fixed, compile-time
    /// constant names below — an unrecognized name is a caller bug (a typo
    /// at a new call site) and is deliberately a silent no-op rather than a
    /// panic, since this is pure instrumentation and must never be able to
    /// bring down the packet path it's observing.
    pub fn record_mutex_contention(&self, lock: &'static str) {
        match lock {
            "wal_append" => { self.contention.wal_append.fetch_add(1, Ordering::Relaxed); }
            "deg_state"  => { self.contention.deg_state.fetch_add(1, Ordering::Relaxed); }
            _ => {}
        }
    }

    /// Current contention count for a named instrumented lock (test/introspection use).
    pub fn mutex_contention_count(&self, lock: &str) -> u64 {
        match lock {
            "wal_append" => self.contention.wal_append.load(Ordering::Relaxed),
            "deg_state"  => self.contention.deg_state.load(Ordering::Relaxed),
            _ => 0,
        }
    }

    /// Record a Trust Decay Engine penalty by kind (bounded cardinality —
    /// see the `Counters` struct doc comment on why this is per-kind, not
    /// per-agent).
    pub fn record_trust_penalty(&self, kind: crate::trust_decay::PenaltyKind) {
        use crate::trust_decay::PenaltyKind;
        match kind {
            PenaltyKind::ReplaySuspicion    => { self.counters.trust_penalties_replay.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::IntentDriftCeiling => { self.counters.trust_penalties_intent_drift.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::ScopeViolation     => { self.counters.trust_penalties_scope_violation.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::InjectionAttempt   => { self.counters.trust_penalties_injection.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::EpistemicOverclaim => { self.counters.trust_penalties_epistemic.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::TargetViolation    => { self.counters.trust_penalties_target_violation.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::ReceiptTimeout     => { self.counters.trust_penalties_receipt_timeout.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::CollusionSuspected => { self.counters.trust_penalties_collusion.fetch_add(1, Ordering::Relaxed); }
            PenaltyKind::GenericHardDrop    => { self.counters.trust_penalties_generic.fetch_add(1, Ordering::Relaxed); }
        }
    }
    pub fn record_trust_downgrade(&self)       { self.counters.trust_downgrades_total.fetch_add(1, Ordering::Relaxed); }
    pub fn record_trust_reauth_required(&self) { self.counters.trust_reauth_required_total.fetch_add(1, Ordering::Relaxed); }

    /// Record one credited (not rate-limited-away) `TrustDecayEngine::reward()`
    /// call by kind (Phase 6 / Part 8.5).
    pub fn record_trust_reward(&self, kind: crate::trust_decay::RewardKind) {
        use crate::trust_decay::RewardKind;
        match kind {
            RewardKind::CleanPassage => { self.counters.trust_rewards_clean_passage.fetch_add(1, Ordering::Relaxed); }
            RewardKind::ValidReceipt => { self.counters.trust_rewards_valid_receipt.fetch_add(1, Ordering::Relaxed); }
        }
    }

    /// Record one Gate 0.5 (Financial Circuit Breaker) rejection's claimed
    /// cost. `estimated_cost` is the caller-supplied value already validated
    /// finite/non-negative by `gate_financial_cb` before this is called;
    /// non-finite/negative values are defensively treated as zero here too.
    pub fn record_financial_rejection(&self, estimated_cost: f64) {
        let tokens = if estimated_cost.is_finite() && estimated_cost > 0.0 {
            estimated_cost.round() as u64
        } else {
            0
        };
        self.counters.financial_tokens_rejected.fetch_add(tokens, Ordering::Relaxed);
    }

    // ── Snapshot ─────────────────────────────────────────────────────────────

    /// Return all counters as a flat `HashMap<String, u64>`.
    pub fn snapshot(&self) -> HashMap<String, u64> {
        let c = &self.counters;
        let mut m = HashMap::new();
        macro_rules! snap {
            ($name:expr, $field:expr) => {
                m.insert($name.to_string(), $field.load(Ordering::Relaxed));
            }
        }
        snap!("gate_0_crypto_failures",      c.gate_0_crypto_failures);
        snap!("gate_1_0_token_invalid",      c.gate_1_0_token_invalid);
        snap!("gate_1_5_intent_mismatch",    c.gate_1_5_intent_mismatch);
        snap!("gate_2_5_escalation",         c.gate_2_5_escalation);
        snap!("gate_3_0_lateral_blocked",    c.gate_3_0_lateral_blocked);
        snap!("gate_4_0_injection_detected", c.gate_4_0_injection_detected);
        snap!("gate_4_0_encoded_injection",  c.gate_4_0_encoded_injection);
        snap!("gate_5_0_epistemic_low",      c.gate_5_0_epistemic_low);
        snap!("gate_6_0_audit_drop",         c.gate_6_0_audit_drop);
        snap!("gate_9_0_schema_invalid",     c.gate_9_0_schema_invalid);
        snap!("gate_11_0_aegf_blocked",      c.gate_11_0_aegf_blocked);
        snap!("gate_12_0_cscs_loop",         c.gate_12_0_cscs_loop);
        snap!("gate_0_5_financial_blocked",  c.gate_0_5_financial_blocked);
        snap!("gate_aca_attestation_failed", c.aca_attestation_failed);
        snap!("gate_sid_semantic_blocked",   c.sid_semantic_blocked);
        snap!("gate_ievl_receipt_rejected",  c.ievl_receipt_rejected);
        snap!("tokens_issued",               c.tokens_issued);
        snap!("tokens_expired",              c.tokens_expired);
        snap!("tokens_revoked",              c.tokens_revoked);
        snap!("token_cache_hits",            c.token_cache_hits);
        snap!("token_cache_misses",          c.token_cache_misses);
        snap!("rrbc_redeemed",               c.rrbc_redeemed);
        snap!("rrbc_replay_blocked",         c.rrbc_replay_blocked);
        snap!("rrbc_pop_failed",             c.rrbc_pop_failed);
        snap!("circuit_breaker_trips",       c.circuit_breaker_trips);
        snap!("cover_traffic_rate_exceeded", c.cover_traffic_rate_exceeded);
        snap!("ping_flood_detected",         c.ping_flood_detected);
        snap!("streams_started",             c.streams_started);
        snap!("streams_completed",           c.streams_completed);
        snap!("streams_aborted",             c.streams_aborted);
        snap!("stream_frames_processed",     c.stream_frames_processed);
        snap!("stream_bytes_processed",      c.stream_bytes_processed);
        snap!("epoch_rotations",             c.epoch_rotations);
        snap!("key_rotations_total",         c.key_rotations_total);
        snap!("psk_compromise_recoveries",   c.psk_compromise_recoveries);
        snap!("cluster_messages_rejected",   c.cluster_messages_rejected);
        snap!("rulepack_installs_total",     c.rulepack_installs_total);
        snap!("rulepack_rejections_total",   c.rulepack_rejections_total);
        snap!("rulepack_expirations_total",  c.rulepack_expirations_total);
        snap!("rulepack_active_rules",       c.rulepack_active_rules);
        snap!("cluster_leadership_changes",  c.cluster_leadership_changes);
        snap!("cluster_members_failed",      c.cluster_members_failed);
        snap!("easi_encryptions",            c.easi_encryptions);
        snap!("easi_decryptions",            c.easi_decryptions);
        snap!("replay_attacks_blocked",      c.replay_attacks_blocked);
        snap!("psn_out_of_window",           c.psn_out_of_window);
        snap!("delegation_depth_exceeded",   c.delegation_depth_exceeded);
        snap!("identity_binding_failed",     c.identity_binding_failed);
        snap!("acsvaf_verifications",        c.acsvaf_verifications);
        snap!("factf_quorum_met",            c.factf_quorum_met);
        snap!("factf_quorum_failed",         c.factf_quorum_failed);
        snap!("packets_accepted",            c.packets_accepted);
        snap!("packets_rejected",            c.packets_rejected);
        snap!("cover_traffic_frames",        c.cover_traffic_frames);
        snap!("trust_penalties_replay",          c.trust_penalties_replay);
        snap!("trust_penalties_intent_drift",    c.trust_penalties_intent_drift);
        snap!("trust_penalties_scope_violation", c.trust_penalties_scope_violation);
        snap!("trust_penalties_injection",       c.trust_penalties_injection);
        snap!("trust_penalties_epistemic",       c.trust_penalties_epistemic);
        snap!("trust_penalties_generic",         c.trust_penalties_generic);
        snap!("trust_penalties_target_violation", c.trust_penalties_target_violation);
        snap!("trust_penalties_receipt_timeout",  c.trust_penalties_receipt_timeout);
        snap!("trust_penalties_collusion",        c.trust_penalties_collusion);
        snap!("trust_downgrades_total",          c.trust_downgrades_total);
        snap!("trust_reauth_required_total",     c.trust_reauth_required_total);
        snap!("trust_rewards_clean_passage",     c.trust_rewards_clean_passage);
        snap!("trust_rewards_valid_receipt",     c.trust_rewards_valid_receipt);
        snap!("financial_tokens_rejected",       c.financial_tokens_rejected);
        m
    }

    /// Render metrics in Prometheus text exposition format.
    ///
    /// Endpoint example (no HTTP dep required — embed into your HTTP handler):
    /// ```ignore
    /// let body = saacp::telemetry::global_telemetry().render_prometheus();
    /// // write body to HTTP response with Content-Type: text/plain; version=0.0.4
    /// ```
    pub fn render_prometheus(&self) -> String {
        let now_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let uptime = now_ms as f64 / 1000.0 - self.created_at;

        let snap = self.snapshot();
        let mut out = String::with_capacity(4096);

        // ── Uptime ───────────────────────────────────────────────────────────
        out.push_str("# HELP saacp_uptime_seconds Seconds since the telemetry collector was created.\n");
        out.push_str("# TYPE saacp_uptime_seconds gauge\n");
        out.push_str(&format!("saacp_uptime_seconds {uptime:.3}\n"));

        // ── Gate rejections ──────────────────────────────────────────────────
        out.push_str("# HELP saacp_gate_rejections_total Gate-level packet rejections.\n");
        out.push_str("# TYPE saacp_gate_rejections_total counter\n");
        for (key, val) in &snap {
            if key.starts_with("gate_") {
                out.push_str(&format!(
                    "saacp_gate_rejections_total{{gate=\"{key}\"}} {val}\n"
                ));
            }
        }

        // ── Packet throughput ────────────────────────────────────────────────
        let accepted = snap.get("packets_accepted").copied().unwrap_or(0);
        let rejected = snap.get("packets_rejected").copied().unwrap_or(0);
        out.push_str("# HELP saacp_packets_total Total packets through the gate pipeline.\n");
        out.push_str("# TYPE saacp_packets_total counter\n");
        out.push_str(&format!("saacp_packets_total{{result=\"accepted\"}} {accepted}\n"));
        out.push_str(&format!("saacp_packets_total{{result=\"rejected\"}} {rejected}\n"));

        // ── Token metrics ────────────────────────────────────────────────────
        out.push_str("# HELP saacp_tokens_total Token lifecycle events.\n");
        out.push_str("# TYPE saacp_tokens_total counter\n");
        for event in &["issued", "expired", "revoked"] {
            let key = format!("tokens_{event}");
            out.push_str(&format!(
                "saacp_tokens_total{{event=\"{event}\"}} {}\n",
                snap.get(&key).copied().unwrap_or(0)
            ));
        }

        // ── Token cache ──────────────────────────────────────────────────────
        let hits  = snap.get("token_cache_hits").copied().unwrap_or(0);
        let misses = snap.get("token_cache_misses").copied().unwrap_or(0);
        let total = hits + misses;
        let hit_rate = if total > 0 { hits as f64 / total as f64 } else { 0.0 };
        out.push_str("# HELP saacp_token_cache_hit_ratio Token cache hit ratio (0.0–1.0).\n");
        out.push_str("# TYPE saacp_token_cache_hit_ratio gauge\n");
        out.push_str(&format!("saacp_token_cache_hit_ratio {hit_rate:.4}\n"));

        // ── Security events ──────────────────────────────────────────────────
        out.push_str("# HELP saacp_security_events_total Security-relevant events.\n");
        out.push_str("# TYPE saacp_security_events_total counter\n");
        for event in &[
            "circuit_breaker_trips", "replay_attacks_blocked", "psn_out_of_window",
            "ping_flood_detected", "rrbc_replay_blocked", "rrbc_pop_failed",
            "delegation_depth_exceeded", "identity_binding_failed",
            "psk_compromise_recoveries", "cover_traffic_rate_exceeded",
            "cluster_messages_rejected", "cluster_leadership_changes",
            "cluster_members_failed",
            "rulepack_installs_total", "rulepack_rejections_total",
            "rulepack_expirations_total",
        ] {
            out.push_str(&format!(
                "saacp_security_events_total{{event=\"{event}\"}} {}\n",
                snap.get(*event).copied().unwrap_or(0)
            ));
        }

        // Gauge, so it gets its own metric family rather than riding the
        // `saacp_security_events_total` counter block above.
        out.push_str(
            "# HELP saacp_injection_rules_active Injection signatures currently loaded (built-ins plus any signed rule pack).\n",
        );
        out.push_str("# TYPE saacp_injection_rules_active gauge\n");
        out.push_str(&format!(
            "saacp_injection_rules_active {}\n",
            snap.get("rulepack_active_rules").copied().unwrap_or(0)
        ));

        // ── Trust Decay Engine ────────────────────────────────────────────────
        out.push_str("# HELP saacp_trust_penalties_total Trust Decay Engine penalties applied, by kind.\n");
        out.push_str("# TYPE saacp_trust_penalties_total counter\n");
        for kind in &[
            "replay", "intent_drift", "scope_violation", "injection", "epistemic", "generic",
            "target_violation", "receipt_timeout", "collusion",
        ] {
            let key = format!("trust_penalties_{kind}");
            out.push_str(&format!(
                "saacp_trust_penalties_total{{kind=\"{kind}\"}} {}\n",
                snap.get(&key).copied().unwrap_or(0)
            ));
        }
        out.push_str("# HELP saacp_trust_downgrades_total Agents whose effective scope was downgraded to READ_ONLY.\n");
        out.push_str("# TYPE saacp_trust_downgrades_total counter\n");
        out.push_str(&format!(
            "saacp_trust_downgrades_total {}\n",
            snap.get("trust_downgrades_total").copied().unwrap_or(0)
        ));
        out.push_str("# HELP saacp_trust_reauth_required_total Agents forced into the reauth soft-reset state.\n");
        out.push_str("# TYPE saacp_trust_reauth_required_total counter\n");
        out.push_str(&format!(
            "saacp_trust_reauth_required_total {}\n",
            snap.get("trust_reauth_required_total").copied().unwrap_or(0)
        ));
        // Phase 6 / Part 8.5: positive behavioral trust signals.
        out.push_str("# HELP saacp_trust_rewards_total Trust Decay Engine rewards credited, by kind.\n");
        out.push_str("# TYPE saacp_trust_rewards_total counter\n");
        for kind in &["clean_passage", "valid_receipt"] {
            let key = format!("trust_rewards_{kind}");
            out.push_str(&format!(
                "saacp_trust_rewards_total{{kind=\"{kind}\"}} {}\n",
                snap.get(&key).copied().unwrap_or(0)
            ));
        }
        // Live gauge, not a stored counter — bounded cardinality (a single
        // scalar), read directly from the engine at render time.
        out.push_str("# HELP saacp_trust_agents_tracked Agents currently tracked by the Trust Decay Engine.\n");
        out.push_str("# TYPE saacp_trust_agents_tracked gauge\n");
        out.push_str(&format!(
            "saacp_trust_agents_tracked {}\n",
            crate::trust_decay::TrustDecayEngine::global().tracked_count()
        ));

        // ── Trust score distribution (O-5) ───────────────────────────────────
        self.render_trust_score_distribution(&mut out);

        // ── Stream metrics ────────────────────────────────────────────────────
        out.push_str("# HELP saacp_streams_total Stream lifecycle counts.\n");
        out.push_str("# TYPE saacp_streams_total counter\n");
        for state in &["started", "completed", "aborted"] {
            let key = format!("streams_{state}");
            out.push_str(&format!(
                "saacp_streams_total{{state=\"{state}\"}} {}\n",
                snap.get(&key).copied().unwrap_or(0)
            ));
        }
        out.push_str("# HELP saacp_stream_bytes_total Total stream payload bytes processed.\n");
        out.push_str("# TYPE saacp_stream_bytes_total counter\n");
        out.push_str(&format!(
            "saacp_stream_bytes_total {}\n",
            snap.get("stream_bytes_processed").copied().unwrap_or(0)
        ));

        // ── Financial Circuit Breaker ────────────────────────────────────────
        out.push_str("# HELP saacp_financial_tokens_rejected_total Sum of estimated_cost across every Gate 0.5 BudgetExceeded rejection (claimed cost prevented, not observed actual spend).\n");
        out.push_str("# TYPE saacp_financial_tokens_rejected_total counter\n");
        out.push_str(&format!(
            "saacp_financial_tokens_rejected_total {}\n",
            snap.get("financial_tokens_rejected").copied().unwrap_or(0)
        ));

        // ── Per-gate latency histograms (O-1) ────────────────────────────────
        out.push_str("# HELP saacp_gate_latency_seconds Per-gate processing latency (accept + reject paths).\n");
        out.push_str("# TYPE saacp_gate_latency_seconds histogram\n");
        self.gate_latencies.render(&mut out);

        // ── Per-(gate, bytecode) rejection counters (O-2 fine-grained) ──────
        out.push_str("# HELP saacp_gate_rejections_by_bytecode_total Gate rejections broken down by bytecode.\n");
        out.push_str("# TYPE saacp_gate_rejections_by_bytecode_total counter\n");
        self.gate_bytecode_rejections.render(&mut out);

        // ── Connection-count gauges (O-4) ────────────────────────────────────
        out.push_str("# HELP saacp_active_connections Live connections per transport.\n");
        out.push_str("# TYPE saacp_active_connections gauge\n");
        out.push_str(&format!("saacp_active_connections{{transport=\"tcp\"}} {}\n", self.active_tcp_connections()));
        out.push_str(&format!("saacp_active_connections{{transport=\"ws\"}} {}\n", self.active_ws_connections()));

        // ── Mutex contention probes (O-6) ────────────────────────────────────
        out.push_str("# HELP saacp_mutex_contention_total Times a try_lock() probe observed contention before falling back to a blocking lock() on a named hot-path mutex.\n");
        out.push_str("# TYPE saacp_mutex_contention_total counter\n");
        out.push_str(&format!("saacp_mutex_contention_total{{lock=\"wal_append\"}} {}\n", self.mutex_contention_count("wal_append")));
        out.push_str(&format!("saacp_mutex_contention_total{{lock=\"deg_state\"}} {}\n", self.mutex_contention_count("deg_state")));

        // ── WAL queue depth / health gauges (O-3) ────────────────────────────
        // Read directly from the process-wide `ImmutableAuditLog::global()`
        // singleton at render time — same pattern as `saacp_trust_agents_tracked`
        // above (no opt-in wiring needed: `daemon.rs` already unconditionally
        // depends on this exact singleton for its shutdown-flush step, so
        // reading it here introduces no new global state or side effect).
        {
            let audit = crate::security::ImmutableAuditLog::global();
            out.push_str("# HELP saacp_wal_queue_depth Approximate current WAL queue depth (best-effort).\n");
            out.push_str("# TYPE saacp_wal_queue_depth gauge\n");
            out.push_str(&format!("saacp_wal_queue_depth {}\n", audit.queue_len()));

            out.push_str("# HELP saacp_wal_dropped_total Audit events dropped because the WAL queue was full.\n");
            out.push_str("# TYPE saacp_wal_dropped_total counter\n");
            out.push_str(&format!("saacp_wal_dropped_total {}\n", audit.dropped_audit_count()));

            out.push_str("# HELP saacp_wal_write_failures_total WAL disk write failures (distinct from queue-full drops).\n");
            out.push_str("# TYPE saacp_wal_write_failures_total counter\n");
            out.push_str(&format!("saacp_wal_write_failures_total {}\n", audit.wal_write_failure_count()));

            out.push_str("# HELP saacp_wal_health Gate 6.0 backpressure health (0=Healthy,1=Degraded,2=Saturated,3=Fatal).\n");
            out.push_str("# TYPE saacp_wal_health gauge\n");
            out.push_str(&format!("saacp_wal_health {}\n", audit.health() as u8));
        }

        // ── Per-agent error table (top-N) ─────────────────────────────────────
        out.push_str("# HELP saacp_agent_errors_total Error count per agent (top-50).\n");
        out.push_str("# TYPE saacp_agent_errors_total counter\n");
        {
            let map = self.agent_errors.lock().unwrap_or_else(|e| e.into_inner());
            let mut entries: Vec<(&String, &AgentErrorEntry)> = map.iter().collect();
            entries.sort_by_key(|b| core::cmp::Reverse(b.1.count));
            for (agent, rec) in entries.iter().take(AGENT_ERROR_TOP_N) {
                // Sanitize agent name for Prometheus label (no quotes/newlines/backslashes —
                // an unescaped trailing backslash would escape our closing quote and let
                // a crafted agent id splice fake label/metric data into the scrape output)
                let safe = agent.replace(['"', '\n', '\\'], "_");
                out.push_str(&format!(
                    "saacp_agent_errors_total{{agent=\"{safe}\"}} {}\n",
                    rec.count
                ));
            }
        }

        out
    }

    /// O-5 (opusplan.md Part 7 / 7.1): cumulative-histogram distribution of current
    /// Trust Decay Engine scores, mirroring `GateLatencyHistograms::render`'s own
    /// cumulative-bucket Prometheus semantics (a bucket's raw count IS the cumulative
    /// count already — no post-processing needed at scrape time). Read directly from
    /// `TrustDecayEngine::global()` at render time — no new counter-recording call
    /// sites in `trust_decay.rs`'s hot `penalize`/`reward` path, same "compute at
    /// render time" idiom already used for `saacp_trust_agents_tracked` above and the
    /// WAL gauges (`saacp_wal_queue_depth` etc.).
    ///
    /// Fixed 0.0–1.0 buckets (11 boundaries, matching `TrustDecayEngine`'s own score
    /// domain — see `TRUST_SCORE_INITIAL`/`penalize`'s `.max(0.0)`/`reward`'s
    /// `.min(1.0)` clamps) rather than a per-agent gauge: bounded cardinality by
    /// construction, consistent with this module's stated policy elsewhere (see the
    /// `Counters` struct's own doc comment on why trust penalties are recorded
    /// per-`PenaltyKind`, never per-agent-id, to avoid an unbounded label-cardinality
    /// blowup on a metrics endpoint).
    ///
    /// `TrustDecayEngine::snapshot` is itself already bounded by `TRUST_MAX_ENTRIES`
    /// (10,000, sweep-on-overflow), so passing that same bound here as `limit` costs at
    /// most one full-capacity scan per scrape — no additional cap is needed.
    fn render_trust_score_distribution(&self, out: &mut String) {
        use crate::trust_decay::{TrustDecayEngine, TRUST_MAX_ENTRIES};

        const SCORE_BUCKET_BOUNDS: &[f64] = &[
            0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0,
        ];

        let snapshot = TrustDecayEngine::global().snapshot(TRUST_MAX_ENTRIES);
        let mut buckets = [0u64; SCORE_BUCKET_BOUNDS.len()];
        let mut sum = 0.0f64;
        for agent in &snapshot {
            sum += agent.score;
            for (i, bound) in SCORE_BUCKET_BOUNDS.iter().enumerate() {
                if agent.score <= *bound {
                    buckets[i] += 1;
                }
            }
        }
        let count = snapshot.len() as u64;

        out.push_str("# HELP saacp_trust_score Distribution of current Trust Decay Engine agent scores (0.0-1.0).\n");
        out.push_str("# TYPE saacp_trust_score histogram\n");
        for (i, bound) in SCORE_BUCKET_BOUNDS.iter().enumerate() {
            out.push_str(&format!(
                "saacp_trust_score_bucket{{le=\"{bound}\"}} {}\n",
                buckets[i]
            ));
        }
        out.push_str(&format!("saacp_trust_score_sum {sum:.9}\n"));
        out.push_str(&format!("saacp_trust_score_count {count}\n"));
    }

    /// Reset all counters to zero (for testing).
    pub fn reset(&self) {
        macro_rules! rst { ($f:expr) => { $f.store(0, Ordering::SeqCst); } }
        let c = &self.counters;
        rst!(c.gate_0_crypto_failures); rst!(c.gate_1_0_token_invalid);
        rst!(c.gate_1_5_intent_mismatch); rst!(c.gate_2_5_escalation);
        rst!(c.gate_3_0_lateral_blocked); rst!(c.gate_4_0_injection_detected);
        rst!(c.gate_4_0_encoded_injection); rst!(c.gate_5_0_epistemic_low);
        rst!(c.gate_6_0_audit_drop); rst!(c.gate_9_0_schema_invalid);
        rst!(c.gate_11_0_aegf_blocked); rst!(c.gate_12_0_cscs_loop);
        rst!(c.gate_0_5_financial_blocked); rst!(c.aca_attestation_failed);
        rst!(c.sid_semantic_blocked); rst!(c.ievl_receipt_rejected);
        rst!(c.tokens_issued); rst!(c.tokens_expired); rst!(c.tokens_revoked);
        rst!(c.token_cache_hits); rst!(c.token_cache_misses);
        rst!(c.rrbc_redeemed); rst!(c.rrbc_replay_blocked); rst!(c.rrbc_pop_failed);
        rst!(c.circuit_breaker_trips); rst!(c.cover_traffic_rate_exceeded);
        rst!(c.ping_flood_detected);
        rst!(c.streams_started); rst!(c.streams_completed); rst!(c.streams_aborted);
        rst!(c.stream_frames_processed); rst!(c.stream_bytes_processed);
        rst!(c.epoch_rotations); rst!(c.key_rotations_total); rst!(c.psk_compromise_recoveries);
        rst!(c.cluster_messages_rejected); rst!(c.cluster_leadership_changes);
        rst!(c.rulepack_installs_total); rst!(c.rulepack_rejections_total);
        rst!(c.rulepack_expirations_total); rst!(c.rulepack_active_rules);
        rst!(c.cluster_members_failed);
        rst!(c.easi_encryptions); rst!(c.easi_decryptions);
        rst!(c.replay_attacks_blocked); rst!(c.psn_out_of_window);
        rst!(c.delegation_depth_exceeded); rst!(c.identity_binding_failed);
        rst!(c.acsvaf_verifications); rst!(c.factf_quorum_met); rst!(c.factf_quorum_failed);
        rst!(c.packets_accepted); rst!(c.packets_rejected); rst!(c.cover_traffic_frames);
        rst!(c.trust_penalties_replay); rst!(c.trust_penalties_intent_drift);
        rst!(c.trust_penalties_scope_violation); rst!(c.trust_penalties_injection);
        rst!(c.trust_penalties_epistemic); rst!(c.trust_penalties_generic);
        rst!(c.trust_penalties_target_violation); rst!(c.trust_penalties_receipt_timeout);
        rst!(c.trust_penalties_collusion);
        rst!(c.trust_downgrades_total); rst!(c.trust_reauth_required_total);
        rst!(c.trust_rewards_clean_passage); rst!(c.trust_rewards_valid_receipt);
        rst!(c.financial_tokens_rejected);
        self.agent_errors.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.gate_latencies.reset();
        self.gate_bytecode_rejections.reset();
        rst!(self.contention.wal_append); rst!(self.contention.deg_state);
        // Deliberately NOT resetting `self.connections`: unlike the counters
        // above (pure test bookkeeping), the connection gauges mirror actual
        // live OS resources (real accepted sockets) that may belong to a
        // daemon running concurrently on another thread in the same test
        // binary — zeroing them here would desync the gauge from reality
        // rather than just resetting a test fixture.
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// SecurityAlertFeed — bounded, network-safe live feed of gate rejections
// ---------------------------------------------------------------------------
//
// Deliberately a separate, always-network-safe structure from `pecf.rs`'s
// `SecureDiagnosticLedger` (whose own doc comment forbids network exposure)
// — this holds only the same level of detail already returned to legitimate
// callers via `SAACPHardDrop` (bytecode + message), nothing more sensitive.
// Built for the SAACP Command Center dashboard's live alert feed.

/// One gate rejection, recorded for the live alert feed.
///
/// Deliberately does NOT carry `SAACPHardDrop::message` (CRIT-10): that field
/// can contain key fingerprints, exact validation-failure detail, or other
/// internal diagnostic state that PECF (`pecf.rs`) is expressly designed to
/// strip from anything reachable off-box. `/api/alerts` is network-reachable,
/// so only the bytecode + gate name (already non-sensitive, coarse-grained
/// classifiers) are recorded here.
#[derive(Debug, Clone, Serialize)]
pub struct SecurityAlert {
    pub timestamp: f64,
    pub agent_id: String,
    pub gate: &'static str,
    pub bytecode: String,
    /// Claimed cost associated with this rejection, when the rejecting gate has one
    /// (currently only Gate 0.5 / `report_financial_rejection`). `None` for every other
    /// gate — never fabricated for gates that don't carry a cost figure.
    pub estimated_cost: Option<f64>,
}

/// Bounded capacity of `SecurityAlertFeed`'s ring buffer — oldest entries
/// evicted first, mirroring `pecf.rs::SecureDiagnosticLedger`'s eviction
/// idiom (but this is a distinct, purpose-built, network-safe structure).
pub const ALERT_FEED_MAX_ENTRIES: usize = 2000;

pub struct SecurityAlertFeed {
    ring: Mutex<VecDeque<SecurityAlert>>,
    #[allow(clippy::type_complexity)]
    subscribers: Mutex<Vec<Arc<dyn Fn(&SecurityAlert) + Send + Sync>>>,
}

impl SecurityAlertFeed {
    fn new() -> Self {
        Self {
            ring: Mutex::new(VecDeque::new()),
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Process-wide singleton.
    pub fn global() -> &'static SecurityAlertFeed {
        static GLOBAL: OnceLock<SecurityAlertFeed> = OnceLock::new();
        GLOBAL.get_or_init(SecurityAlertFeed::new)
    }

    /// Record one alert: push to the bounded ring, then notify subscribers.
    /// The subscriber-list mutex is held across the callback loop (same
    /// precedent as `trust_decay.rs`'s signal dispatch) — never the ring
    /// mutex, which is dropped first.
    ///
    /// M-38 fix: every lock in this impl block recovers via `into_inner()` on
    /// poison rather than panicking — `SecurityAlertFeed::global()` is a
    /// process-wide singleton, so one poisoning panic must not cascade into
    /// every other in-flight packet losing the security alert feed entirely.
    pub fn record(&self, alert: SecurityAlert) {
        {
            let mut ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
            if ring.len() >= ALERT_FEED_MAX_ENTRIES {
                ring.pop_front();
            }
            ring.push_back(alert.clone());
        }
        let subs = self.subscribers.lock().unwrap_or_else(|e| e.into_inner());
        for cb in subs.iter() {
            cb(&alert);
        }
    }

    /// Most recent `limit` alerts, newest first.
    pub fn recent(&self, limit: usize) -> Vec<SecurityAlert> {
        let ring = self.ring.lock().unwrap_or_else(|e| e.into_inner());
        ring.iter().rev().take(limit).cloned().collect()
    }

    pub fn subscribe(&self, cb: Arc<dyn Fn(&SecurityAlert) + Send + Sync>) {
        self.subscribers.lock().unwrap_or_else(|e| e.into_inner()).push(cb);
    }

    pub fn len(&self) -> usize {
        self.ring.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Process-wide `SecurityAlertFeed` singleton — convenience alias for
/// `SecurityAlertFeed::global()`, matching this module's `global_telemetry()`
/// naming convention.
pub fn global_alert_feed() -> &'static SecurityAlertFeed {
    SecurityAlertFeed::global()
}

/// Record a gate rejection to both the counter bank and the live alert feed
/// in one call — the standard instrumentation point for every gate's reject
/// site in `handler.rs`. `gate` should be one of the strings recognized by
/// `TelemetryCollector::record_gate_rejection` (e.g. `"gate_4_0_inject"`).
pub fn report_gate_rejection(gate: &'static str, agent_id: &str, err: &crate::errors::SAACPHardDrop) {
    global_telemetry().record_gate_rejection(gate);
    let bytecode = format!("{:?}", err.bytecode);
    global_telemetry().record_gate_rejection_bytecode(gate, &bytecode);
    global_alert_feed().record(SecurityAlert {
        timestamp: now_epoch_secs(),
        agent_id: agent_id.to_string(),
        gate,
        bytecode,
        estimated_cost: None,
    });
}

/// Record a Gate 0.5 (Financial Circuit Breaker) `BudgetExceeded` rejection to the
/// counter bank AND the live alert feed, carrying the real claimed `estimated_cost` —
/// the analogue of [`report_gate_rejection`] for the one gate whose rejections have a
/// dollar figure attached. `gate_financial_cb` (`handler.rs`) calls this instead of
/// `record_financial_rejection` directly so the Command Center dashboard's "Blocked
/// Transactions" ledger sees a real per-event entry instead of only the aggregate
/// counter moving. `estimated_cost` is expected already validated finite/non-negative
/// by the caller (same contract as `record_financial_rejection`).
pub fn report_financial_rejection(agent_id: &str, estimated_cost: f64) {
    const GATE: &str = "gate_0_5_financial";
    global_telemetry().record_financial_rejection(estimated_cost);
    global_telemetry().record_gate_rejection(GATE);
    global_telemetry().record_gate_rejection_bytecode(GATE, "BudgetExceeded");
    global_alert_feed().record(SecurityAlert {
        timestamp: now_epoch_secs(),
        agent_id: agent_id.to_string(),
        gate: GATE,
        bytecode: "BudgetExceeded".to_string(),
        estimated_cost: Some(estimated_cost),
    });
}

/// Record a refused signed injection rule pack (`rulepack.rs`) to the live alert
/// feed. The counter is bumped by `RulePackStore::install` itself so every entry
/// point shares it; this adds the operator-visible event.
///
/// `reason` must be a `RulePackRejection::as_str()` value — a fixed, low-cardinality
/// set that never contains a pattern, a pack id, or an issuer. `/api/alerts` is
/// network-reachable, so the same CRIT-10 posture applies here as to
/// `SecurityAlert`'s omission of `SAACPHardDrop::message`: a rejected push must not
/// become an oracle for the active rule set. The `agent_id` slot carries the fixed
/// string `"rulepack"` rather than a caller identity, since a rule pack arrives on
/// the authenticated admin plane, not from an agent.
pub fn report_rulepack_rejection(reason: &str) {
    const GATE: &str = "rulepack_install";
    global_telemetry().record_gate_rejection_bytecode(GATE, reason);
    global_alert_feed().record(SecurityAlert {
        timestamp: now_epoch_secs(),
        agent_id: "rulepack".to_string(),
        gate: GATE,
        bytecode: format!("RulePackRejected:{reason}"),
        estimated_cost: None,
    });
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    #[test]
    fn test_counters_increment() {
        let t = TelemetryCollector::new();
        t.record_packet_accepted();
        t.record_packet_accepted();
        t.record_packet_rejected("agent-a");
        t.record_gate_rejection("gate_4_0_inject");
        t.record_circuit_breaker_trip("agent-b");

        let snap = t.snapshot();
        assert_eq!(snap["packets_accepted"], 2);
        assert_eq!(snap["packets_rejected"], 2); // record_packet_rejected + trip
        assert_eq!(snap["gate_4_0_injection_detected"], 1);
        assert_eq!(snap["circuit_breaker_trips"], 1);
    }

    #[test]
    fn test_mutex_contention_probe_records_and_renders() {
        let t = TelemetryCollector::new();
        assert_eq!(t.mutex_contention_count("wal_append"), 0);
        assert_eq!(t.mutex_contention_count("deg_state"), 0);

        t.record_mutex_contention("wal_append");
        t.record_mutex_contention("wal_append");
        t.record_mutex_contention("deg_state");
        // Unrecognized lock name is a silent no-op, not a panic (see doc
        // comment on `record_mutex_contention`).
        t.record_mutex_contention("not_a_real_lock");

        assert_eq!(t.mutex_contention_count("wal_append"), 2);
        assert_eq!(t.mutex_contention_count("deg_state"), 1);

        let rendered = t.render_prometheus();
        assert!(rendered.contains("saacp_mutex_contention_total{lock=\"wal_append\"} 2"));
        assert!(rendered.contains("saacp_mutex_contention_total{lock=\"deg_state\"} 1"));
    }

    #[test]
    fn test_trust_penalty_counters_by_kind() {
        use crate::trust_decay::PenaltyKind;
        let t = TelemetryCollector::new();
        t.record_trust_penalty(PenaltyKind::ReplaySuspicion);
        t.record_trust_penalty(PenaltyKind::ReplaySuspicion);
        t.record_trust_penalty(PenaltyKind::ScopeViolation);
        t.record_trust_downgrade();
        t.record_trust_reauth_required();

        let snap = t.snapshot();
        assert_eq!(snap["trust_penalties_replay"], 2);
        assert_eq!(snap["trust_penalties_scope_violation"], 1);
        assert_eq!(snap["trust_penalties_intent_drift"], 0);
        assert_eq!(snap["trust_downgrades_total"], 1);
        assert_eq!(snap["trust_reauth_required_total"], 1);
    }

    #[test]
    fn test_trust_metrics_appear_in_prometheus_render() {
        use crate::trust_decay::PenaltyKind;
        let t = TelemetryCollector::new();
        t.record_trust_penalty(PenaltyKind::InjectionAttempt);
        t.record_trust_downgrade();
        let prom = t.render_prometheus();
        assert!(prom.contains("saacp_trust_penalties_total"));
        assert!(prom.contains("kind=\"injection\""));
        assert!(prom.contains("saacp_trust_downgrades_total"));
        assert!(prom.contains("saacp_trust_agents_tracked"));
    }

    #[test]
    fn test_wire_trust_decay_metrics_does_not_panic() {
        // Smoke test only — this wires the GLOBAL TrustDecayEngine to the
        // GLOBAL telemetry collector, so it can't assert on isolated counts
        // without risking cross-test interference from other tests touching
        // the same globals. Just confirm the wiring call itself is sound.
        wire_trust_decay_metrics();
    }

    #[test]
    fn test_prometheus_render_non_empty() {
        let t = TelemetryCollector::new();
        t.record_packet_accepted();
        t.record_gate_rejection("gate_0_crypto");
        let prom = t.render_prometheus();
        assert!(prom.contains("saacp_packets_total"));
        assert!(prom.contains("saacp_gate_rejections_total"));
        assert!(prom.contains("saacp_uptime_seconds"));
    }

    #[test]
    fn test_agent_error_top_n_eviction() {
        let t = TelemetryCollector::new();
        // Fill beyond cap
        for i in 0..=AGENT_ERROR_TOP_N + 5 {
            t.record_packet_rejected(&format!("agent-{i}"));
        }
        let map = t.agent_errors.lock().unwrap();
        assert!(map.len() <= AGENT_ERROR_TOP_N);
    }

    /// H-32 regression: a trailing backslash in an agent id must not be able to
    /// escape the closing quote of the `agent="..."` Prometheus label. If it
    /// did, a Prometheus-compliant parser would treat the quote as escaped and
    /// keep consuming subsequent exposition-format text as part of the label
    /// value, corrupting/splicing later metric lines.
    #[test]
    fn test_agent_error_label_backslash_cannot_escape_quote() {
        let t = TelemetryCollector::new();
        t.record_packet_rejected("evil-agent\\");
        let prom = t.render_prometheus();
        // The rendered label must be properly terminated: a quote immediately
        // followed by `}` and never preceded by an unescaped backslash.
        assert!(prom.contains("agent=\"evil-agent_\"}"));
        assert!(!prom.contains("agent=\"evil-agent\\\"}"));
    }

    #[test]
    fn test_reset_clears_all() {
        let t = TelemetryCollector::new();
        t.record_packet_accepted();
        t.record_gate_rejection("gate_12_0_cscs");
        t.reset();
        let snap = t.snapshot();
        assert!(snap.values().all(|&v| v == 0));
    }

    #[test]
    fn test_cache_hit_ratio() {
        let t = TelemetryCollector::new();
        t.record_cache_hit();
        t.record_cache_hit();
        t.record_cache_miss();
        let prom = t.render_prometheus();
        assert!(prom.contains("saacp_token_cache_hit_ratio 0.6667")
             || prom.contains("saacp_token_cache_hit_ratio 0.666"));
    }

    #[test]
    fn test_financial_rejection_accumulates_and_renders() {
        let t = TelemetryCollector::new();
        t.record_financial_rejection(150.0);
        t.record_financial_rejection(50.4);
        let snap = t.snapshot();
        assert_eq!(snap["financial_tokens_rejected"], 200); // 150 + round(50.4)
        let prom = t.render_prometheus();
        assert!(prom.contains("saacp_financial_tokens_rejected_total 200"));
    }

    #[test]
    fn test_financial_rejection_ignores_non_finite_and_negative() {
        let t = TelemetryCollector::new();
        t.record_financial_rejection(f64::NAN);
        t.record_financial_rejection(f64::INFINITY);
        t.record_financial_rejection(-5.0);
        let snap = t.snapshot();
        assert_eq!(snap["financial_tokens_rejected"], 0);
    }

    #[test]
    fn test_security_alert_feed_records_and_notifies_subscribers() {
        use std::sync::atomic::AtomicUsize;
        use crate::errors::{SAACPBytecodes, SAACPHardDrop};

        let feed = SecurityAlertFeed::new();
        let seen = Arc::new(AtomicUsize::new(0));
        let seen_clone = Arc::clone(&seen);
        feed.subscribe(Arc::new(move |_alert: &SecurityAlert| {
            seen_clone.fetch_add(1, Ordering::Relaxed);
        }));

        let err = SAACPHardDrop::new(SAACPBytecodes::PromptInjectionDetected, "test message");
        feed.record(SecurityAlert {
            timestamp: 123.0,
            agent_id: "agent-x".to_string(),
            gate: "gate_4_0_inject",
            bytecode: format!("{:?}", err.bytecode),
            estimated_cost: None,
        });

        assert_eq!(feed.len(), 1);
        assert_eq!(seen.load(Ordering::Relaxed), 1);
        let recent = feed.recent(10);
        assert_eq!(recent.len(), 1);
        assert_eq!(recent[0].agent_id, "agent-x");
        assert_eq!(recent[0].gate, "gate_4_0_inject");
    }

    #[test]
    fn test_security_alert_feed_bounded_eviction() {
        let feed = SecurityAlertFeed::new();
        for i in 0..(ALERT_FEED_MAX_ENTRIES + 10) {
            feed.record(SecurityAlert {
                timestamp: i as f64,
                agent_id: format!("agent-{i}"),
                gate: "gate_4_0_inject",
                bytecode: "PromptInjectionDetected".to_string(),
                estimated_cost: None,
            });
        }
        assert_eq!(feed.len(), ALERT_FEED_MAX_ENTRIES);
        // Newest-first: the very last recorded entry should be first.
        let recent = feed.recent(1);
        assert_eq!(recent[0].agent_id, format!("agent-{}", ALERT_FEED_MAX_ENTRIES + 9));
    }

    #[test]
    #[serial]
    fn test_report_gate_rejection_updates_counter_and_feed() {
        use crate::errors::{SAACPBytecodes, SAACPHardDrop};

        let before = global_telemetry().snapshot()["gate_4_0_injection_detected"];
        let before_alerts = global_alert_feed().len();
        let err = SAACPHardDrop::new(SAACPBytecodes::PromptInjectionDetected, "unit test injection");
        report_gate_rejection("gate_4_0_inject", "agent-report-test", &err);
        let after = global_telemetry().snapshot()["gate_4_0_injection_detected"];
        assert_eq!(after, before + 1);
        assert!(global_alert_feed().len() > before_alerts || global_alert_feed().len() == ALERT_FEED_MAX_ENTRIES);
    }

    #[test]
    #[serial]
    fn test_report_financial_rejection_updates_counter_and_feed_with_cost() {
        let before_tokens = global_telemetry().snapshot()["financial_tokens_rejected"];
        let before_alerts = global_alert_feed().len();

        report_financial_rejection("agent-financial-test", 42.5);

        let after_tokens = global_telemetry().snapshot()["financial_tokens_rejected"];
        assert_eq!(after_tokens, before_tokens + 43); // 42.5 rounds to 43

        assert!(global_alert_feed().len() > before_alerts || global_alert_feed().len() == ALERT_FEED_MAX_ENTRIES);
        let recent = global_alert_feed().recent(1);
        assert_eq!(recent[0].agent_id, "agent-financial-test");
        assert_eq!(recent[0].gate, "gate_0_5_financial");
        assert_eq!(recent[0].bytecode, "BudgetExceeded");
        assert_eq!(recent[0].estimated_cost, Some(42.5));
    }

    /// CRIT-10 regression: a `SecurityAlert` built from a hard-drop carrying
    /// sensitive diagnostic text must never serialize that text — the struct
    /// has no `message` field at all, so this locks in the wire contract.
    #[test]
    #[serial]
    fn test_security_alert_never_leaks_hard_drop_message() {
        use crate::errors::{SAACPBytecodes, SAACPHardDrop};

        let secret_detail = "key fingerprint=deadbeef internal validation state XYZ";
        let err = SAACPHardDrop::new(SAACPBytecodes::PromptInjectionDetected, secret_detail);
        report_gate_rejection("gate_4_0_inject", "agent-leak-test", &err);

        let recent = global_alert_feed().recent(1);
        let json = serde_json::to_string(&recent[0]).unwrap();
        assert!(!json.contains("message"));
        assert!(!json.contains(secret_detail));
    }

    // ── Phase 5 (Observability & Compliance) ────────────────────────────────

    #[test]
    fn test_gate_latency_histogram_buckets_are_cumulative() {
        let t = TelemetryCollector::new();
        t.record_gate_latency("gate_test_hist", Duration::from_micros(2)); // falls in the 10µs bucket and above
        t.record_gate_latency("gate_test_hist", Duration::from_millis(2)); // falls in the 5ms bucket and above
        let prom = t.render_prometheus();
        assert!(prom.contains("saacp_gate_latency_seconds_bucket{gate=\"gate_test_hist\",le=\"0.00001\"} 1"));
        assert!(prom.contains("saacp_gate_latency_seconds_bucket{gate=\"gate_test_hist\",le=\"0.005\"} 2"));
        assert!(prom.contains("saacp_gate_latency_seconds_bucket{gate=\"gate_test_hist\",le=\"+Inf\"} 2"));
        assert!(prom.contains("saacp_gate_latency_seconds_count{gate=\"gate_test_hist\"} 2"));
    }

    #[test]
    fn test_gate_latency_reset_clears_histograms() {
        let t = TelemetryCollector::new();
        t.record_gate_latency("gate_test_reset", Duration::from_micros(1));
        t.reset();
        let prom = t.render_prometheus();
        assert!(!prom.contains("gate=\"gate_test_reset\""));
    }

    #[test]
    fn test_gate_rejection_bytecode_dimension() {
        use crate::errors::SAACPBytecodes;
        let t = TelemetryCollector::new();
        t.record_gate_rejection_bytecode("gate_4_0_inject", &format!("{:?}", SAACPBytecodes::PromptInjectionDetected));
        t.record_gate_rejection_bytecode("gate_4_0_inject", &format!("{:?}", SAACPBytecodes::PromptInjectionDetected));
        t.record_gate_rejection_bytecode("gate_4_0_inject", &format!("{:?}", SAACPBytecodes::SchemaMismatch));
        let prom = t.render_prometheus();
        assert!(prom.contains(&format!(
            "saacp_gate_rejections_by_bytecode_total{{gate=\"gate_4_0_inject\",bytecode=\"{:?}\"}} 2",
            SAACPBytecodes::PromptInjectionDetected
        )));
        assert!(prom.contains(&format!(
            "saacp_gate_rejections_by_bytecode_total{{gate=\"gate_4_0_inject\",bytecode=\"{:?}\"}} 1",
            SAACPBytecodes::SchemaMismatch
        )));
    }

    #[test]
    #[serial]
    fn test_report_gate_rejection_updates_bytecode_counter_too() {
        use crate::errors::{SAACPBytecodes, SAACPHardDrop};
        let err = SAACPHardDrop::new(SAACPBytecodes::AegfLoopDetected, "unit test");
        report_gate_rejection("gate_11_0_aegf", "agent-bytecode-test", &err);
        let prom = global_telemetry().render_prometheus();
        assert!(prom.contains("saacp_gate_rejections_by_bytecode_total{gate=\"gate_11_0_aegf\""));
    }

    #[test]
    fn test_connection_count_guard_increments_and_decrements() {
        let t = TelemetryCollector::new();
        // These tests use a fresh, non-global collector so they can't interfere
        // with concurrently-running tests that touch `global_telemetry()`'s
        // process-wide connection gauges — `ConnectionCountGuard` only ever
        // operates on the global singleton, so this test instead exercises the
        // underlying gauge type directly to stay isolated.
        assert_eq!(t.active_tcp_connections(), 0);
        t.connections.tcp_active.fetch_add(1, Ordering::Relaxed);
        assert_eq!(t.active_tcp_connections(), 1);
        t.connections.tcp_active.fetch_sub(1, Ordering::Relaxed);
        assert_eq!(t.active_tcp_connections(), 0);
    }

    #[test]
    #[serial]
    fn test_connection_count_guard_raii_pairs_on_global() {
        let before_tcp = global_telemetry().active_tcp_connections();
        let before_ws = global_telemetry().active_ws_connections();
        {
            let _tcp_guard = ConnectionCountGuard::tcp();
            let _ws_guard = ConnectionCountGuard::ws();
            assert_eq!(global_telemetry().active_tcp_connections(), before_tcp + 1);
            assert_eq!(global_telemetry().active_ws_connections(), before_ws + 1);
        }
        assert_eq!(global_telemetry().active_tcp_connections(), before_tcp);
        assert_eq!(global_telemetry().active_ws_connections(), before_ws);
    }

    #[test]
    fn test_wal_gauges_present_in_prometheus_render() {
        let prom = global_telemetry().render_prometheus();
        assert!(prom.contains("saacp_wal_queue_depth"));
        assert!(prom.contains("saacp_wal_dropped_total"));
        assert!(prom.contains("saacp_wal_write_failures_total"));
        assert!(prom.contains("saacp_wal_health"));
    }

    /// O-5: `saacp_trust_score_bucket`/`_sum`/`_count` must appear in the rendered
    /// output, and the buckets must actually reflect a real agent's score in
    /// `TrustDecayEngine::global()` — not just be present-but-always-empty. Uses
    /// `#[serial]` because `TrustDecayEngine::global()` is a process-wide singleton
    /// shared with every other test that touches trust state.
    #[test]
    #[serial]
    fn test_trust_score_distribution_present_and_reflects_real_score() {
        use crate::trust_decay::{PenaltyKind, TrustDecayEngine};

        let agent_id = "telemetry-o5-distribution-test-agent";
        TrustDecayEngine::global().reset(Some(agent_id));
        // One penalty moves this agent below 1.0, landing it in a specific bucket
        // rather than the always-populated le="1.0" bucket every fresh agent starts in.
        TrustDecayEngine::global().penalize(agent_id, PenaltyKind::ReplaySuspicion);
        let score = TrustDecayEngine::global().score(agent_id);
        assert!(score < 1.0, "penalize must move the score below the initial 1.0");

        let prom = global_telemetry().render_prometheus();
        assert!(prom.contains("saacp_trust_score_bucket{le=\"0.1\"}"));
        assert!(prom.contains("saacp_trust_score_bucket{le=\"1\"}"));
        assert!(prom.contains("saacp_trust_score_sum "));
        assert!(prom.contains("saacp_trust_score_count "));

        // The le="1" (final) bucket is cumulative, so it must count at least this
        // one tracked agent — proves the render path actually read live engine state,
        // not just emitted a static, always-zero template.
        let count_line = prom
            .lines()
            .find(|l| l.starts_with("saacp_trust_score_count "))
            .expect("count line must be present");
        let count: u64 = count_line
            .trim_start_matches("saacp_trust_score_count ")
            .trim()
            .parse()
            .expect("count must be a valid integer");
        assert!(count >= 1, "expected at least the one tracked test agent, got count={count}");

        TrustDecayEngine::global().reset(Some(agent_id));
    }
}
