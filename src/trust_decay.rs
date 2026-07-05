//! trust_decay.rs — Continuous Behavioral Trust Scoring (sidecar, not a gate)
//!
//! *New in Rust* — no Python-reference analog.
//!
//! # Why this exists
//!
//! Every gate in the pipeline (`handler.rs`) makes a binary block/allow decision
//! on a single packet. That's correct and necessary, but it has a blind spot: an
//! agent that is quietly compromised — still holding a valid capability token,
//! still sending individually well-formed packets — gets no protocol-level
//! response until a human notices and calls `revoke()`. Real zero-trust
//! architectures (Google BeyondCorp, SPIFFE/SPIRE in production) don't just gate
//! each request in isolation; they maintain a decaying trust score per identity
//! that degrades on anomalies and forces re-authentication or step-up
//! verification when it drops, without waiting for a human in the loop.
//!
//! [`TrustDecayEngine`] is that continuous signal. It is deliberately **not** a
//! 13th numbered gate in the linear pipeline — it is a sidecar every gate
//! reports *to*, sitting outside the numbered 16-step list exactly like the
//! existing `AgentRateLimiter::is_locked()` circuit-breaker check already does
//! (`handler.rs`, pre-gate). Gate order remains a protocol invariant; nothing
//! about it changes here.
//!
//! # Model
//!
//! Each tracked agent has a behavioral trust `score` in `[0.0, 1.0]`, starting
//! at [`TRUST_SCORE_INITIAL`] the first time an agent is seen (identity trust
//! already came from the handshake/capability token — this tracks *behavior*,
//! not identity). A gate violation calls [`TrustDecayEngine::penalize`] with a
//! [`PenaltyKind`], which subtracts a fixed weight (floored at 0.0). Recovery is
//! **lazy and time-based**: elapsed time since the last touch is folded in
//! whenever the entry is next read or written — there is no background sweep
//! thread and clean traffic never touches this map, so well-behaved agents add
//! zero overhead beyond the single map lookup already needed to check
//! [`TrustDecayEngine::scope_cap`] (itself the same cost class as the existing
//! `AgentRateLimiter::is_locked()` check).
//!
//! Two thresholds convert the continuous score into concrete protocol effects:
//!
//! - `score < TRUST_DOWNGRADE_THRESHOLD` → [`TrustDecayEngine::scope_cap`]
//!   returns `Some(0)` (READ_ONLY only). The handler intersects this into
//!   `max_action_class_from_token` **once**, at the point that value is first
//!   bound — every downstream gate that already reads it inherits the
//!   downgrade for free.
//! - `score < TRUST_REAUTH_THRESHOLD` → [`TrustDecayEngine::requires_reauth`]
//!   is `true`: all non-exempt packets from that agent are rejected
//!   (`SAACPBytecodes::TrustReauthRequired`) until *both* the score recovers
//!   above threshold *and* [`TRUST_REAUTH_MIN_COOLDOWN_SECONDS`] has elapsed
//!   since the lockout began — closing the "trip one big penalty, then flood
//!   clean-looking traffic to instantly reset" gaming loophole.
//!
//! # Honest scope (read this before assuming more than is implemented)
//!
//! This is a **v1, time/score-based soft reset** — not a cryptographic
//! proof-of-rehandshake. The capability token is never revoked; the agent is
//! merely time-boxed out. A v2 that requires the client to actually complete a
//! fresh ECDH/HTH exchange to clear `requires_reauth` early would be a real
//! wire-protocol addition and is explicitly **not** built here — don't assume
//! it from the name "reauth".
//!
//! # Signals
//!
//! [`TrustDecayEngine::subscribe`] registers a synchronous callback invoked on
//! every [`TrustEvent`] transition (`Downgraded` / `ReauthRequired` /
//! `Recovered`) — an operator or orchestrator can push these onto its own
//! channel for async handling. Callers are expected to also write a Gate
//! 6.0-style audit entry and update `telemetry.rs` counters at the call site
//! (kept out of this module to avoid a dependency cycle with `security.rs`).
//!
//! # Bounded memory
//!
//! Capped at [`TRUST_MAX_ENTRIES`] with sweep-on-overflow, the same idiom
//! `memory::FederatedMemory` already uses — only triggers once genuinely over
//! cap, so normal fleets never pay the sweep cost.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Starting score for an agent never seen before by this engine instance.
pub const TRUST_SCORE_INITIAL: f64 = 1.0;
/// Recovery rate applied lazily based on elapsed wall-clock seconds since the
/// entry was last touched. ~0.0005/s ⇒ full recovery from 0.0 in ~33 minutes.
pub const TRUST_RECOVERY_PER_SECOND: f64 = 0.0005;
/// Below this score, `scope_cap()` returns `Some(0)` (READ_ONLY only).
pub const TRUST_DOWNGRADE_THRESHOLD: f64 = 0.50;
/// Below this score, `requires_reauth()` is true.
pub const TRUST_REAUTH_THRESHOLD: f64 = 0.25;
/// Minimum lockout duration once `requires_reauth` trips, regardless of how
/// fast the score would otherwise recover — prevents "one big penalty, then
/// immediately flood clean traffic to reset" gaming.
pub const TRUST_REAUTH_MIN_COOLDOWN_SECONDS: f64 = 60.0;
/// Maximum tracked agent_ids before a stale-entry sweep runs (see module docs).
pub const TRUST_MAX_ENTRIES: usize = 10_000;

/// Penalty weight subtracted from an agent's score for each violation kind.
/// Tuned by signal strength: replay and cumulative intent drift are the
/// strongest evidence of genuine compromise/manipulation; a generic hard drop
/// (malformed packet, etc.) is the weakest and gets the smallest weight so it
/// doesn't dominate the score on its own.
fn penalty_weight(kind: PenaltyKind) -> f64 {
    match kind {
        PenaltyKind::ReplaySuspicion => 0.40,
        PenaltyKind::IntentDriftCeiling => 0.35,
        PenaltyKind::InjectionAttempt => 0.30,
        PenaltyKind::ScopeViolation => 0.25,
        PenaltyKind::EpistemicOverclaim => 0.20,
        PenaltyKind::GenericHardDrop => 0.05,
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// The category of gate violation that triggered a trust penalty. Maps 1:1
/// onto the existing gate-pipeline reject points (`handler.rs`) — see the
/// module docs for the exact wiring and weight rationale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum PenaltyKind {
    /// PSN/sequence replay detected on a stream frame.
    ReplaySuspicion,
    /// Cumulative chain-wide intent divergence exceeded its ceiling (Gate 1.5).
    IntentDriftCeiling,
    /// Gate 3.0: high-risk mutative operation without secondary token.
    ScopeViolation,
    /// Gate 4.0: prompt-injection pattern matched.
    InjectionAttempt,
    /// Gate 5.0 / 5.0b: confidence overclaim or claimed-scope inconsistency.
    EpistemicOverclaim,
    /// Any other `SAACPHardDrop` — the catch-all, lightly weighted.
    GenericHardDrop,
}

/// A trust-score state transition worth telling an operator about.
#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub enum TrustEvent {
    /// A penalty was applied (score may or may not have crossed a threshold).
    Penalized(PenaltyKind),
    /// Score crossed below `TRUST_DOWNGRADE_THRESHOLD`.
    Downgraded,
    /// Score crossed below `TRUST_REAUTH_THRESHOLD`.
    ReauthRequired,
    /// Score recovered back above `TRUST_DOWNGRADE_THRESHOLD` after having
    /// been below it.
    Recovered,
}

/// Payload delivered to subscribers on every trust state transition.
#[derive(Debug, Clone, Serialize)]
pub struct TrustSignal {
    pub agent_id: String,
    pub score: f64,
    pub event: TrustEvent,
}

/// One agent's current trust state, for the Command Center dashboard's live
/// agent list. Returned by [`TrustDecayEngine::snapshot`].
#[derive(Debug, Clone, Serialize)]
pub struct AgentTrustSnapshot {
    pub agent_id: String,
    pub score: f64,
    pub requires_reauth: bool,
}

struct TrustEntry {
    score: f64,
    last_update: f64,
    /// Wall-clock time this entry most recently crossed into the reauth-locked
    /// state, if it's currently locked. `None` when not currently locked.
    locked_at: Option<f64>,
}

impl TrustEntry {
    fn fresh(now: f64) -> Self {
        Self { score: TRUST_SCORE_INITIAL, last_update: now, locked_at: None }
    }

    /// Apply lazy time-based recovery up to `now`, in place.
    fn recover_to(&mut self, now: f64) {
        let elapsed = (now - self.last_update).max(0.0);
        if elapsed > 0.0 {
            self.score = (self.score + elapsed * TRUST_RECOVERY_PER_SECOND).min(1.0);
        }
        self.last_update = now;
    }
}

// ---------------------------------------------------------------------------
// TrustDecayEngine
// ---------------------------------------------------------------------------

/// Process-wide (or per-instance, for tests) continuous behavioral trust
/// tracker. See module docs for the full model.
pub struct TrustDecayEngine {
    entries: Mutex<HashMap<String, TrustEntry>>,
    #[allow(clippy::type_complexity)]
    observers: Mutex<Vec<Arc<dyn Fn(TrustSignal) + Send + Sync>>>,
}

impl Default for TrustDecayEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustDecayEngine {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            observers: Mutex::new(Vec::new()),
        }
    }

    /// Process-wide singleton, matching `AgentRateLimiter::global()` /
    /// `ZeroTrustGateway::global()`'s established pattern.
    pub fn global() -> &'static TrustDecayEngine {
        static GLOBAL: OnceLock<TrustDecayEngine> = OnceLock::new();
        GLOBAL.get_or_init(TrustDecayEngine::new)
    }

    /// Register a callback invoked synchronously on every trust-state
    /// transition. Keep callbacks fast and non-blocking — they run inline on
    /// the packet-processing path that triggered the transition.
    pub fn subscribe(&self, cb: Arc<dyn Fn(TrustSignal) + Send + Sync>) {
        self.observers.lock().unwrap().push(cb);
    }

    fn emit(&self, agent_id: &str, score: f64, event: TrustEvent) {
        let signal = TrustSignal { agent_id: agent_id.to_string(), score, event };
        for cb in self.observers.lock().unwrap().iter() {
            cb(signal.clone());
        }
    }

    /// Current (recovery-adjusted) score for an agent. Never seen ⇒ `TRUST_SCORE_INITIAL`.
    pub fn score(&self, agent_id: &str) -> f64 {
        let mut entries = self.entries.lock().unwrap();
        let now = now_secs();
        match entries.get_mut(agent_id) {
            Some(e) => { e.recover_to(now); e.score }
            None => TRUST_SCORE_INITIAL,
        }
    }

    /// Apply a penalty for the given violation kind. Returns the resulting
    /// (recovery-adjusted, then penalized) score. Fires `Downgraded` /
    /// `ReauthRequired` signals on threshold crossings.
    pub fn penalize(&self, agent_id: &str, kind: PenaltyKind) -> f64 {
        let mut entries = self.entries.lock().unwrap();
        let now = now_secs();

        // IoT / low-resource fix: sweep stale entries only once the cap is
        // exceeded — mirrors FederatedMemory. Two passes:
        //   1. Lazily recover every entry, then drop ones that are fully
        //      recovered (score >= 1.0) and not currently reauth-locked —
        //      those are safe to forget, functionally identical to never
        //      having been tracked.
        //   2. If still over cap (e.g. many distinct agents each penalized
        //      exactly once and never touched again — recovery alone can't
        //      reclaim those), fall back to oldest-touched-first eviction,
        //      mirroring `streaming::StreamRegistry`'s eviction strategy.
        if entries.len() >= TRUST_MAX_ENTRIES && !entries.contains_key(agent_id) {
            for e in entries.values_mut() {
                e.recover_to(now);
            }
            entries.retain(|_, e| e.score < TRUST_SCORE_INITIAL || e.locked_at.is_some());

            if entries.len() >= TRUST_MAX_ENTRIES {
                let evict_count = entries.len() + 1 - TRUST_MAX_ENTRIES;
                let mut by_age: Vec<(String, f64)> = entries.iter()
                    .map(|(k, v)| (k.clone(), v.last_update))
                    .collect();
                by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                for (k, _) in by_age.into_iter().take(evict_count) {
                    entries.remove(&k);
                }
            }
        }

        let entry = entries.entry(agent_id.to_string()).or_insert_with(|| TrustEntry::fresh(now));
        entry.recover_to(now);
        let was_downgraded = entry.score < TRUST_DOWNGRADE_THRESHOLD;

        entry.score = (entry.score - penalty_weight(kind)).max(0.0);

        let now_downgraded = entry.score < TRUST_DOWNGRADE_THRESHOLD;
        let now_reauth = entry.score < TRUST_REAUTH_THRESHOLD;
        if now_reauth && entry.locked_at.is_none() {
            entry.locked_at = Some(now);
        }
        let score = entry.score;
        drop(entries);

        self.emit(agent_id, score, TrustEvent::Penalized(kind));
        if now_downgraded && !was_downgraded {
            self.emit(agent_id, score, TrustEvent::Downgraded);
        }
        if now_reauth {
            self.emit(agent_id, score, TrustEvent::ReauthRequired);
        }
        score
    }

    /// `Some(0)` (READ_ONLY only) when the agent's score is below
    /// `TRUST_DOWNGRADE_THRESHOLD`; `None` (no cap) otherwise.
    pub fn scope_cap(&self, agent_id: &str) -> Option<u8> {
        if self.score(agent_id) < TRUST_DOWNGRADE_THRESHOLD { Some(0) } else { None }
    }

    /// True while the agent must be rejected outright (soft reset in effect).
    /// Requires *both* score recovery above threshold *and* the minimum
    /// cooldown floor to have elapsed since lockout began.
    pub fn requires_reauth(&self, agent_id: &str) -> bool {
        let mut entries = self.entries.lock().unwrap();
        let now = now_secs();
        let Some(entry) = entries.get_mut(agent_id) else { return false; };
        entry.recover_to(now);

        let Some(locked_at) = entry.locked_at else { return false; };
        let cooldown_elapsed = (now - locked_at) >= TRUST_REAUTH_MIN_COOLDOWN_SECONDS;
        let score_recovered = entry.score >= TRUST_REAUTH_THRESHOLD;

        if cooldown_elapsed && score_recovered {
            entry.locked_at = None;
            let score = entry.score;
            let was_below_downgrade = score < TRUST_DOWNGRADE_THRESHOLD;
            drop(entries);
            if !was_below_downgrade {
                self.emit(agent_id, score, TrustEvent::Recovered);
            }
            false
        } else {
            true
        }
    }

    /// Reset an agent's trust state back to `TRUST_SCORE_INITIAL` (or clear
    /// all tracked agents if `None`). Test/ops utility, mirrors
    /// `AgentRateLimiter::reset`.
    pub fn reset(&self, agent_id: Option<&str>) {
        let mut entries = self.entries.lock().unwrap();
        match agent_id {
            Some(id) => { entries.remove(id); }
            None => entries.clear(),
        }
    }

    /// Number of currently-tracked agents (for the bounded-cardinality
    /// `saacp_trust_agents_tracked` telemetry gauge).
    pub fn tracked_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    /// Snapshot of up to `limit` tracked agents, sorted ascending by score
    /// (most-concerning-first) — for the Command Center dashboard's live
    /// agent list. Bounded by construction: `entries` is already capped at
    /// `TRUST_MAX_ENTRIES`, so a full snapshot is always bounded-size even
    /// without the `limit` truncation.
    ///
    /// `requires_reauth` here mirrors [`Self::requires_reauth`]'s logic
    /// read-only — it does NOT clear an expired lock or emit a `Recovered`
    /// signal the way the real method does, since a dashboard poll must
    /// never have a side effect on live gate decisions. It may therefore
    /// show `true` for a brief window after the real cooldown+recovery
    /// conditions are met, until the next actual packet from that agent
    /// clears it for real.
    pub fn snapshot(&self, limit: usize) -> Vec<AgentTrustSnapshot> {
        let mut entries = self.entries.lock().unwrap();
        let now = now_secs();

        let mut out: Vec<AgentTrustSnapshot> = entries.iter_mut().map(|(id, e)| {
            e.recover_to(now);
            let requires_reauth = match e.locked_at {
                Some(locked_at) => {
                    let cooldown_elapsed = (now - locked_at) >= TRUST_REAUTH_MIN_COOLDOWN_SECONDS;
                    let score_recovered = e.score >= TRUST_REAUTH_THRESHOLD;
                    !(cooldown_elapsed && score_recovered)
                }
                None => false,
            };
            AgentTrustSnapshot { agent_id: id.clone(), score: e.score, requires_reauth }
        }).collect();

        out.sort_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(std::cmp::Ordering::Equal));
        out.truncate(limit);
        out
    }
}

// ---------------------------------------------------------------------------
// IntentDriftTracker — chain-wide cumulative divergence ceiling (Gate 1.5)
// ---------------------------------------------------------------------------

/// Maximum distinct `session_uuid`s tracked before oldest-first eviction runs.
/// Same bounded-map rationale as `TrustDecayEngine`/`AgentRateLimiter`.
pub const DRIFT_MAX_TRACKED_SESSIONS: usize = 50_000;

/// Cumulative chain-wide intent divergence ceiling. Gate 1.5's base check
/// (`enforce_root_intent`) only ever looks at one hop in isolation; this is
/// the running total across every hop seen for a given `session_uuid`,
/// independent of whether any single hop passed its own per-hop check.
/// Rationale: "small, individually-plausible scope creep at every hop,
/// compounding into something the root task never asked for."
pub const CHAIN_DRIFT_CEILING: f64 = 2.0;

struct DriftEntry {
    total: f64,
    last_update: f64,
}

/// Per-session running total of Gate 1.5 intent divergence, used to enforce
/// `CHAIN_DRIFT_CEILING`. Bounded via the same oldest-first eviction idiom as
/// `streaming::StreamRegistry`.
pub struct IntentDriftTracker {
    sessions: Mutex<HashMap<String, DriftEntry>>,
}

impl Default for IntentDriftTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl IntentDriftTracker {
    pub fn new() -> Self {
        Self { sessions: Mutex::new(HashMap::new()) }
    }

    /// Process-wide singleton.
    pub fn global() -> &'static IntentDriftTracker {
        static GLOBAL: OnceLock<IntentDriftTracker> = OnceLock::new();
        GLOBAL.get_or_init(IntentDriftTracker::new)
    }

    /// Add `divergence` to the running total for `session_uuid` and return the
    /// new total. Callers compare this against `CHAIN_DRIFT_CEILING`.
    pub fn accumulate(&self, session_uuid: &str, divergence: f64) -> f64 {
        let mut sessions = self.sessions.lock().unwrap();
        let now = now_secs();

        if sessions.len() >= DRIFT_MAX_TRACKED_SESSIONS && !sessions.contains_key(session_uuid) {
            let evict_count = sessions.len() + 1 - DRIFT_MAX_TRACKED_SESSIONS;
            let mut by_age: Vec<(String, f64)> = sessions.iter()
                .map(|(k, v)| (k.clone(), v.last_update))
                .collect();
            by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (k, _) in by_age.into_iter().take(evict_count) {
                sessions.remove(&k);
            }
        }

        let entry = sessions.entry(session_uuid.to_string())
            .or_insert(DriftEntry { total: 0.0, last_update: now });
        entry.total += divergence;
        entry.last_update = now;
        entry.total
    }

    /// Clear tracking for a session (e.g. on clean completion) or all sessions.
    pub fn reset(&self, session_uuid: Option<&str>) {
        let mut sessions = self.sessions.lock().unwrap();
        match session_uuid {
            Some(id) => { sessions.remove(id); }
            None => sessions.clear(),
        }
    }

    pub fn tracked_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_agent_starts_fully_trusted() {
        let e = TrustDecayEngine::new();
        assert_eq!(e.score("agent-a"), TRUST_SCORE_INITIAL);
        assert_eq!(e.scope_cap("agent-a"), None);
        assert!(!e.requires_reauth("agent-a"));
    }

    #[test]
    fn penalize_subtracts_weight() {
        let e = TrustDecayEngine::new();
        let s = e.penalize("agent-a", PenaltyKind::ScopeViolation);
        assert!((s - (1.0 - 0.25)).abs() < 1e-9);
    }

    #[test]
    fn score_floors_at_zero() {
        let e = TrustDecayEngine::new();
        for _ in 0..10 {
            e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        }
        // Not exact equality: lazy time-based recovery means any nonzero
        // wall-clock gap between the last `penalize()` and this `score()`
        // read (even sub-microsecond, as in a tight test loop) adds a tiny
        // positive residual by design — recovery is monotonic in elapsed
        // time, it doesn't wait for a "tick." The design invariant under
        // test is "floors at (effectively) zero," not "stays at bit-exact
        // 0.0 forever," which would contradict lazy recovery entirely.
        assert!(e.score("agent-a") < 1e-6, "score must floor at effectively zero");
    }

    #[test]
    fn downgrade_threshold_caps_scope() {
        let e = TrustDecayEngine::new();
        // Two ScopeViolations: 1.0 -> 0.75 -> 0.50 (not yet below threshold)
        e.penalize("agent-a", PenaltyKind::ScopeViolation);
        e.penalize("agent-a", PenaltyKind::ScopeViolation);
        assert_eq!(e.scope_cap("agent-a"), None, "0.50 is not strictly below the 0.50 threshold");
        // One more push below 0.50
        e.penalize("agent-a", PenaltyKind::EpistemicOverclaim);
        assert_eq!(e.scope_cap("agent-a"), Some(0));
    }

    #[test]
    fn reauth_threshold_triggers_and_holds_for_cooldown() {
        let e = TrustDecayEngine::new();
        // Drive score below TRUST_REAUTH_THRESHOLD (0.25) with two replay penalties: 1.0 -> 0.6 -> 0.2
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        assert!(e.score("agent-a") < TRUST_REAUTH_THRESHOLD);
        assert!(e.requires_reauth("agent-a"), "must require reauth immediately after crossing threshold");
        // Cooldown floor hasn't elapsed yet (real time), so it must still be locked
        // even though the score itself may recover slightly on repeated queries.
        assert!(e.requires_reauth("agent-a"));
    }

    #[test]
    fn reset_clears_state() {
        let e = TrustDecayEngine::new();
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        assert!(e.score("agent-a") < 1.0);
        e.reset(Some("agent-a"));
        assert_eq!(e.score("agent-a"), TRUST_SCORE_INITIAL);
    }

    #[test]
    fn reset_all_clears_every_agent() {
        let e = TrustDecayEngine::new();
        e.penalize("agent-a", PenaltyKind::ScopeViolation);
        e.penalize("agent-b", PenaltyKind::ScopeViolation);
        e.reset(None);
        assert_eq!(e.score("agent-a"), TRUST_SCORE_INITIAL);
        assert_eq!(e.score("agent-b"), TRUST_SCORE_INITIAL);
        assert_eq!(e.tracked_count(), 0);
    }

    #[test]
    fn subscribers_receive_penalized_signal() {
        let e = TrustDecayEngine::new();
        let received = Arc::new(Mutex::new(Vec::new()));
        let received2 = received.clone();
        e.subscribe(Arc::new(move |sig: TrustSignal| {
            received2.lock().unwrap().push(sig);
        }));
        e.penalize("agent-a", PenaltyKind::InjectionAttempt);
        let sigs = received.lock().unwrap();
        assert!(!sigs.is_empty());
        assert_eq!(sigs[0].agent_id, "agent-a");
        assert!(matches!(sigs[0].event, TrustEvent::Penalized(PenaltyKind::InjectionAttempt)));
    }

    #[test]
    fn subscribers_receive_downgraded_signal_on_crossing() {
        let e = TrustDecayEngine::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let events2 = events.clone();
        e.subscribe(Arc::new(move |sig: TrustSignal| {
            events2.lock().unwrap().push(sig.event);
        }));
        e.penalize("agent-a", PenaltyKind::ScopeViolation); // 1.0 -> 0.75
        e.penalize("agent-a", PenaltyKind::ScopeViolation); // 0.75 -> 0.50
        e.penalize("agent-a", PenaltyKind::EpistemicOverclaim); // 0.50 -> 0.30, crosses 0.50
        let evs = events.lock().unwrap();
        assert!(evs.iter().any(|e| matches!(e, TrustEvent::Downgraded)));
    }

    #[test]
    fn different_agents_are_independent() {
        let e = TrustDecayEngine::new();
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        assert_eq!(e.score("agent-b"), TRUST_SCORE_INITIAL);
    }

    #[test]
    fn snapshot_returns_agents_sorted_ascending_by_score() {
        let e = TrustDecayEngine::new();
        e.penalize("agent-low", PenaltyKind::ReplaySuspicion); // 1.0 -> 0.60
        e.penalize("agent-low", PenaltyKind::ReplaySuspicion); // 0.60 -> 0.20
        e.penalize("agent-mid", PenaltyKind::ScopeViolation);  // 1.0 -> 0.75
        e.penalize("agent-high", PenaltyKind::GenericHardDrop); // 1.0 -> 0.95

        let snap = e.snapshot(10);
        assert_eq!(snap.len(), 3);
        assert_eq!(snap[0].agent_id, "agent-low");
        assert_eq!(snap[1].agent_id, "agent-mid");
        assert_eq!(snap[2].agent_id, "agent-high");
        assert!(snap[0].score < snap[1].score);
        assert!(snap[1].score < snap[2].score);
    }

    #[test]
    fn snapshot_respects_limit() {
        let e = TrustDecayEngine::new();
        for i in 0..20 {
            e.penalize(&format!("agent-{i}"), PenaltyKind::GenericHardDrop);
        }
        let snap = e.snapshot(5);
        assert_eq!(snap.len(), 5);
    }

    #[test]
    fn snapshot_reports_requires_reauth_for_locked_agent() {
        let e = TrustDecayEngine::new();
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion); // drops below TRUST_REAUTH_THRESHOLD
        let snap = e.snapshot(10);
        let entry = snap.iter().find(|s| s.agent_id == "agent-a").unwrap();
        assert!(entry.requires_reauth, "just-locked agent should show requires_reauth=true");
    }

    #[test]
    fn snapshot_is_bounded_by_construction() {
        let e = TrustDecayEngine::new();
        for i in 0..(TRUST_MAX_ENTRIES + 500) {
            e.penalize(&format!("bounded-agent-{i}"), PenaltyKind::GenericHardDrop);
        }
        let snap = e.snapshot(usize::MAX);
        assert!(snap.len() <= TRUST_MAX_ENTRIES);
    }

    #[test]
    fn bounded_map_does_not_grow_past_cap_forever() {
        let e = TrustDecayEngine::new();
        // Simulate the worst case for eviction: many distinct agents, each
        // penalized exactly once and never touched again, with essentially no
        // elapsed wall-clock time between them — so lazy time-based recovery
        // cannot reclaim any of them and the oldest-touched-first fallback
        // eviction (mirroring `streaming::StreamRegistry`) must be what bounds
        // the map instead.
        for i in 0..(TRUST_MAX_ENTRIES + 500) {
            e.penalize(&format!("bounded-agent-{i}"), PenaltyKind::GenericHardDrop);
        }
        assert!(e.tracked_count() <= TRUST_MAX_ENTRIES, "map must not grow unbounded past its cap");
    }

    // ── IntentDriftTracker ───────────────────────────────────────────────────

    #[test]
    fn drift_accumulates_across_calls() {
        let t = IntentDriftTracker::new();
        let total1 = t.accumulate("session-a", 0.3);
        assert!((total1 - 0.3).abs() < 1e-9);
        let total2 = t.accumulate("session-a", 0.5);
        assert!((total2 - 0.8).abs() < 1e-9);
    }

    #[test]
    fn drift_is_independent_per_session() {
        let t = IntentDriftTracker::new();
        t.accumulate("session-a", 0.9);
        let total_b = t.accumulate("session-b", 0.1);
        assert!((total_b - 0.1).abs() < 1e-9);
    }

    #[test]
    fn drift_reset_clears_session() {
        let t = IntentDriftTracker::new();
        t.accumulate("session-a", 1.0);
        t.reset(Some("session-a"));
        let total = t.accumulate("session-a", 0.2);
        assert!((total - 0.2).abs() < 1e-9, "reset must zero the running total");
    }

    #[test]
    fn drift_tracker_bounded_map_does_not_grow_forever() {
        let t = IntentDriftTracker::new();
        for i in 0..(DRIFT_MAX_TRACKED_SESSIONS + 500) {
            t.accumulate(&format!("session-{i}"), 0.1);
        }
        assert!(t.tracked_count() <= DRIFT_MAX_TRACKED_SESSIONS, "session map must not grow unbounded past its cap");
    }
}
