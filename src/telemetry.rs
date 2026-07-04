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

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

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
        match signal.event {
            TrustEvent::Downgraded => t.record_trust_downgrade(),
            TrustEvent::ReauthRequired => t.record_trust_reauth_required(),
            TrustEvent::Penalized(_) | TrustEvent::Recovered => {}
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
    pub psk_compromise_recoveries:     AtomicU64,
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
    pub trust_downgrades_total:            AtomicU64,
    pub trust_reauth_required_total:       AtomicU64,
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
            psk_compromise_recoveries:     z!(),
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
            trust_downgrades_total:          z!(),
            trust_reauth_required_total:     z!(),
        }
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
        }
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
            _ => {}
        }
    }

    pub fn record_packet_accepted(&self) {
        self.counters.packets_accepted.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_packet_rejected(&self, agent_id: &str) {
        self.counters.packets_rejected.fetch_add(1, Ordering::Relaxed);
        if !agent_id.is_empty() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64();
            let mut map = self.agent_errors.lock().unwrap();
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
            PenaltyKind::GenericHardDrop    => { self.counters.trust_penalties_generic.fetch_add(1, Ordering::Relaxed); }
        }
    }
    pub fn record_trust_downgrade(&self)       { self.counters.trust_downgrades_total.fetch_add(1, Ordering::Relaxed); }
    pub fn record_trust_reauth_required(&self) { self.counters.trust_reauth_required_total.fetch_add(1, Ordering::Relaxed); }

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
        snap!("psk_compromise_recoveries",   c.psk_compromise_recoveries);
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
        snap!("trust_downgrades_total",          c.trust_downgrades_total);
        snap!("trust_reauth_required_total",     c.trust_reauth_required_total);
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
        ] {
            out.push_str(&format!(
                "saacp_security_events_total{{event=\"{event}\"}} {}\n",
                snap.get(*event).copied().unwrap_or(0)
            ));
        }

        // ── Trust Decay Engine ────────────────────────────────────────────────
        out.push_str("# HELP saacp_trust_penalties_total Trust Decay Engine penalties applied, by kind.\n");
        out.push_str("# TYPE saacp_trust_penalties_total counter\n");
        for kind in &[
            "replay", "intent_drift", "scope_violation", "injection", "epistemic", "generic",
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
        // Live gauge, not a stored counter — bounded cardinality (a single
        // scalar), read directly from the engine at render time.
        out.push_str("# HELP saacp_trust_agents_tracked Agents currently tracked by the Trust Decay Engine.\n");
        out.push_str("# TYPE saacp_trust_agents_tracked gauge\n");
        out.push_str(&format!(
            "saacp_trust_agents_tracked {}\n",
            crate::trust_decay::TrustDecayEngine::global().tracked_count()
        ));

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

        // ── Per-agent error table (top-N) ─────────────────────────────────────
        out.push_str("# HELP saacp_agent_errors_total Error count per agent (top-50).\n");
        out.push_str("# TYPE saacp_agent_errors_total counter\n");
        {
            let map = self.agent_errors.lock().unwrap();
            let mut entries: Vec<(&String, &AgentErrorEntry)> = map.iter().collect();
            entries.sort_by_key(|b| core::cmp::Reverse(b.1.count));
            for (agent, rec) in entries.iter().take(AGENT_ERROR_TOP_N) {
                // Sanitize agent name for Prometheus label (no quotes/newlines)
                let safe = agent.replace(['"', '\n'], "_");
                out.push_str(&format!(
                    "saacp_agent_errors_total{{agent=\"{safe}\"}} {}\n",
                    rec.count
                ));
            }
        }

        out
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
        rst!(c.tokens_issued); rst!(c.tokens_expired); rst!(c.tokens_revoked);
        rst!(c.token_cache_hits); rst!(c.token_cache_misses);
        rst!(c.rrbc_redeemed); rst!(c.rrbc_replay_blocked); rst!(c.rrbc_pop_failed);
        rst!(c.circuit_breaker_trips); rst!(c.cover_traffic_rate_exceeded);
        rst!(c.ping_flood_detected);
        rst!(c.streams_started); rst!(c.streams_completed); rst!(c.streams_aborted);
        rst!(c.stream_frames_processed); rst!(c.stream_bytes_processed);
        rst!(c.epoch_rotations); rst!(c.psk_compromise_recoveries);
        rst!(c.easi_encryptions); rst!(c.easi_decryptions);
        rst!(c.replay_attacks_blocked); rst!(c.psn_out_of_window);
        rst!(c.delegation_depth_exceeded); rst!(c.identity_binding_failed);
        rst!(c.acsvaf_verifications); rst!(c.factf_quorum_met); rst!(c.factf_quorum_failed);
        rst!(c.packets_accepted); rst!(c.packets_rejected); rst!(c.cover_traffic_frames);
        rst!(c.trust_penalties_replay); rst!(c.trust_penalties_intent_drift);
        rst!(c.trust_penalties_scope_violation); rst!(c.trust_penalties_injection);
        rst!(c.trust_penalties_epistemic); rst!(c.trust_penalties_generic);
        rst!(c.trust_downgrades_total); rst!(c.trust_reauth_required_total);
        self.agent_errors.lock().unwrap().clear();
    }
}

impl Default for TelemetryCollector {
    fn default() -> Self { Self::new() }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
}
