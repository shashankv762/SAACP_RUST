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
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Starting score for an agent never seen before by this engine instance.
pub const TRUST_SCORE_INITIAL: f64 = 1.0;
/// Recovery rate applied lazily based on elapsed wall-clock seconds since the
/// entry was last touched. ~0.0005/s ⇒ full recovery from 0.0 in ~33 minutes.
pub const TRUST_RECOVERY_PER_SECOND: f64 = 0.0005;
/// L-23 fix: each recorded `penalize()` call against an entry divides its effective
/// recovery rate by roughly `1.0 + penalty_count * TRUST_REPEAT_PENALTY_DECAY` — so
/// repeat offenders recover markedly slower than an agent penalized once by accident.
pub const TRUST_REPEAT_PENALTY_DECAY: f64 = 0.5;
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
/// opusplan.md 6.5 ("Memory Steady-State Targets"): an entry untouched (no `penalize`/
/// `reward` call) for this long is considered stale and eligible for proactive removal
/// by [`TrustDecayEngine::sweep_stale`] — 24 hours of complete inactivity is far longer
/// than any legitimate agent's normal traffic gap, so this only reclaims memory from
/// agents that have genuinely gone away, never one that's merely quiet for a while.
pub const TRUST_ENTRY_STALENESS_SECONDS: f64 = 86_400.0;

/// Penalty weight subtracted from an agent's score for each violation kind.
/// Tuned by signal strength: replay and cumulative intent drift are the
/// strongest evidence of genuine compromise/manipulation; a generic hard drop
/// (malformed packet, etc.) is the weakest and gets the smallest weight so it
/// doesn't dominate the score on its own.
fn penalty_weight(kind: PenaltyKind) -> f64 {
    match kind {
        PenaltyKind::ReplaySuspicion => 0.40,
        PenaltyKind::IntentDriftCeiling => 0.35,
        PenaltyKind::CollusionSuspected => 0.35,
        PenaltyKind::InjectionAttempt => 0.30,
        PenaltyKind::TargetViolation => 0.30,
        PenaltyKind::ScopeViolation => 0.25,
        PenaltyKind::EpistemicOverclaim => 0.20,
        // Weaker evidence than a confirmed IEVL target/class mismatch: a
        // missing execution receipt could just be agent/network latency
        // rather than malice, so it sits below `TargetViolation` but above
        // the generic catch-all (Phase 6 / Part 8.1).
        PenaltyKind::ReceiptTimeout => 0.15,
        PenaltyKind::GenericHardDrop => 0.05,
    }
}

// ---------------------------------------------------------------------------
// Positive Behavioral Trust Signals (Phase 6 / Part 8.5)
// ---------------------------------------------------------------------------
//
// The model above is purely punitive: a single glitch costs up to 33 minutes
// of lockout recovery time with no way to earn it back faster than passive
// per-second decay. `reward()` adds a bounded, anti-gaming positive signal so
// continuously well-behaved agents recover meaningfully faster than agents
// that go quiet and just wait out the passive recovery clock — without
// letting an agent grind trivial clean traffic back to full trust instantly
// after a real violation (which would defeat the entire point of a
// behavioral signal).

/// Reward granted for one clean pipeline pass (all mandatory gates passed,
/// non-cover-traffic, non-stream-continuation) with no IEVL involvement.
pub const TRUST_REWARD_CLEAN_PASSAGE: f64 = 0.001;
/// Reward granted when an `ExecutionReceipt` (IEVL, `ievl.rs`) is verified
/// `Consistent` with its declared intent — stronger positive evidence than a
/// clean passage alone, since it proves post-execution reality matched the
/// declaration, not just that the packet was well-formed.
pub const TRUST_REWARD_VALID_RECEIPT: f64 = 0.005;
/// Reward alone can never lift a score above this ceiling — prevents an
/// agent from grinding trust back to a bit-exact 1.0 through volume alone;
/// only genuine passive recovery (`TRUST_RECOVERY_PER_SECOND`) or the
/// combination of both can approach full trust.
pub const TRUST_REWARD_CEILING: f64 = 0.95;
/// Reward alone can never lift a score above this floor from a deeper
/// penalty in one call — i.e. an agent sitting at 0.10 cannot reward its way
/// past 0.30 no matter how many clean passages it grinds; genuine recovery
/// from a deep penalty still requires passive time-based decay (or further,
/// larger rewards accumulating below the floor first). This is the reward
/// path's mirror of `TRUST_REAUTH_MIN_COOLDOWN_SECONDS` — both exist so "trip
/// one big penalty, then immediately grind/wait it away" never works.
pub const TRUST_REWARD_FLOOR: f64 = 0.30;
/// Maximum number of reward calls credited per agent per rolling 60-second
/// window — anti-grinding: without this an agent could fire clean passages
/// as fast as the wire allows and approach the ceiling in seconds rather than
/// the ~3.2-minute active-recovery window the design targets.
pub const TRUST_MAX_REWARDS_PER_MINUTE: u32 = 10;
/// Multiplier applied to the base reward when the clean passage/receipt was
/// for an IRREVERSIBLE-class action — clean handling of the riskiest action
/// class is stronger positive evidence than a READ_ONLY passage, so it earns
/// proportionally more trust back.
pub const TRUST_REWARD_IRREVERSIBLE_MULTIPLIER: f64 = 2.0;

/// The category of positive behavioral signal that triggered a trust reward.
/// Mirrors `PenaltyKind`'s role for penalties — see module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum RewardKind {
    /// A full pipeline pass with no gate rejection, no cover traffic, no
    /// mid-stream continuation frame.
    CleanPassage,
    /// An IEVL `ExecutionReceipt` verified `Consistent` with its declaration.
    ValidReceipt,
}

fn reward_weight(kind: RewardKind) -> f64 {
    match kind {
        RewardKind::CleanPassage => TRUST_REWARD_CLEAN_PASSAGE,
        RewardKind::ValidReceipt => TRUST_REWARD_VALID_RECEIPT,
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Derive the map key used to track behavioral trust for an agent on a given
/// wire session (S-2 hardening).
///
/// Prefers the SHA-256 fingerprint of the agent's Ed25519 public key over the
/// bare, self-claimed `agent_id` string a capability token's `iss` claim
/// asserts. The public key comes from a `TranscriptBoundSession`
/// (`identity_binding.rs`'s C-3 subsystem) registered for `session_id_hex` —
/// proven via ECDH possession, an `AgentIdentityCertificate`, and a
/// proof-of-possession signature at handshake time, not a bearer claim.
///
/// Rationale: without this, an attacker who can mint or replay capability
/// tokens for more than one `iss` value can "launder" an accumulated trust
/// penalty by presenting a fresh, never-before-seen `agent_id` on its very
/// next packet — instantly resetting back to `TRUST_SCORE_INITIAL` and
/// defeating the entire point of a continuous behavioral signal (this is
/// exactly the gap `daemon.rs`'s separate IP-keyed `requires_reauth` check
/// was already working around at the connection level; this closes the same
/// gap per-packet, at the source, for every gate violation tracked in this
/// module). A cryptographic keypair cannot be rotated for free the way a
/// self-chosen string can — doing so requires a genuinely different,
/// CA-certified identity.
///
/// Falls back to a namespaced `agent_id`-keyed entry — preserving prior
/// behavior exactly — when this connection did not opt into identity binding
/// (`SAACPNetworkDaemon::with_identity_binding`), i.e. no
/// `TranscriptBoundSession` is registered for `session_id_hex`. The `pk:`/
/// `aid:` namespaces can never collide with each other or with the
/// pre-existing `ip:`-prefixed keys `daemon.rs` writes into this same map.
pub fn trust_key_for(agent_id: &str, session_id_hex: &str) -> String {
    let fingerprint = crate::identity_binding::DEFAULT_IDENTITY_REGISTRY
        .get_by_session_id(session_id_hex, |session| session.client_public_key_hex.clone())
        .filter(|pk_hex| !pk_hex.is_empty())
        .and_then(|pk_hex| hex::decode(&pk_hex).ok())
        .map(|pk_bytes| hex::encode(Sha256::digest(&pk_bytes)));

    match fingerprint {
        Some(fp) => format!("pk:{fp}"),
        None => format!("aid:{agent_id}"),
    }
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
    /// IEVL (`ievl.rs`, Phase 6 / Part 8.1): an `ExecutionReceipt`'s
    /// `actual_targets` diverged from the matching `IntentDeclaration`'s
    /// `targets` beyond `overlap_threshold` (but without an action_class
    /// escalation, which instead triggers immediate revocation — see
    /// `SAACPBytecodes::IntentClassEscalationDetected`).
    TargetViolation,
    /// IEVL (`ievl.rs`, Phase 6 / Part 8.1): an `IntentDeclaration`'s TTL
    /// expired with no matching `ExecutionReceipt` ever submitted.
    ReceiptTimeout,
    /// MACE (`mace.rs`, Phase 6 / Part 8.2): this agent was implicated in a
    /// confirmed circular-delegation cycle or Sybil-cluster match.
    CollusionSuspected,
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
    /// A reward was credited (Phase 6 / Part 8.5) — not fired when a reward
    /// call was rate-limited away with no score change.
    Rewarded(RewardKind),
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
    /// Start of the current rolling reward-rate-limit window (Phase 6 / Part
    /// 8.5's `TRUST_MAX_REWARDS_PER_MINUTE` anti-grinding cap). `None` until
    /// the first `reward()` call ever made against this entry.
    reward_window_start: Option<f64>,
    /// Reward calls credited within the current window. Reset to 0 whenever
    /// `now` has advanced a full 60s past `reward_window_start`.
    rewards_in_window: u32,
    /// L-23 fix: total `penalize()` calls ever recorded against this entry, used by
    /// `recover_to` to slow passive recovery for repeat offenders — without this, an
    /// agent penalized many times over recovers at exactly the same rate as one
    /// penalized once by accident, so "get penalized, wait, repeat" costs nothing extra
    /// each time. Reset to 0 once the entry fully recovers to `TRUST_SCORE_INITIAL`
    /// (see `recover_to`), so a genuinely reformed agent isn't penalized forever.
    penalty_count: u32,
}

impl TrustEntry {
    fn fresh(now: f64) -> Self {
        Self {
            score: TRUST_SCORE_INITIAL,
            last_update: now,
            locked_at: None,
            reward_window_start: None,
            rewards_in_window: 0,
            penalty_count: 0,
        }
    }

    /// Apply lazy time-based recovery up to `now`, in place.
    fn recover_to(&mut self, now: f64) {
        let elapsed = (now - self.last_update).max(0.0);
        if elapsed > 0.0 {
            // L-23 fix: each recorded penalty further dampens the effective recovery
            // rate, asymptotically approaching (never reaching) a 10%-of-base floor —
            // recovery always eventually remains possible, just slower for repeat
            // offenders. `penalty_count` is `u32`, so this can't grow unbounded either.
            let effective_rate = (TRUST_RECOVERY_PER_SECOND
                / (1.0 + self.penalty_count as f64 * TRUST_REPEAT_PENALTY_DECAY))
                .max(TRUST_RECOVERY_PER_SECOND * 0.10);
            self.score = (self.score + elapsed * effective_rate).min(1.0);
        }
        self.last_update = now;
        if self.score >= TRUST_SCORE_INITIAL {
            // Fully recovered — a clean slate going forward, not a permanent record.
            self.penalty_count = 0;
        }
    }

    /// Returns `true` and books one reward credit if the rolling 60s window
    /// has room left; `false` (no state changed) if the window is already at
    /// `TRUST_MAX_REWARDS_PER_MINUTE`. Lazily rolls the window forward the
    /// same way `recover_to` lazily folds in elapsed time — no background
    /// sweep needed.
    fn try_consume_reward_slot(&mut self, now: f64) -> bool {
        match self.reward_window_start {
            Some(start) if now - start < 60.0 => {
                if self.rewards_in_window >= TRUST_MAX_REWARDS_PER_MINUTE {
                    return false;
                }
                self.rewards_in_window += 1;
                true
            }
            _ => {
                self.reward_window_start = Some(now);
                self.rewards_in_window = 1;
                true
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TrustDecayEngine
// ---------------------------------------------------------------------------

/// Number of independent lock shards for [`TrustDecayEngine`]'s entry map
/// (Phase 3 / P-1 / Part 6.3: sharded on `agent_fingerprint[0] % 16`, i.e. the
/// first byte of the (possibly namespaced — `pk:`/`aid:`/`ip:`) map key).
/// Before sharding, every gate violation across every agent in the entire
/// fleet serialized behind one process-wide `Mutex` — one busy/compromised
/// agent's penalty traffic could add lock-contention latency to every other
/// agent's unrelated packets.
const TRUST_SHARDS: usize = 16;

/// Per-shard soft capacity, chosen so the aggregate cap across all shards
/// still matches [`TRUST_MAX_ENTRIES`] under a roughly uniform key
/// distribution — sharding must not silently multiply the effective capacity
/// bound (Part 12 principle 5, "Bounded Everything"). H-24's "never evict a
/// locked entry" protection is preserved because it is enforced identically
/// within each shard's own eviction sweep.
const TRUST_PER_SHARD_MAX_ENTRIES: usize = TRUST_MAX_ENTRIES / TRUST_SHARDS;

/// Maps a trust-map key to its shard index by hashing the whole key.
///
/// Every key this function sees is namespaced (`pk:<fp>` / `aid:<id>` /
/// `ip:<ip>`, see `trust_key_for`/`ip_trust_key`). Sampling `key.as_bytes()
/// .first()` would always yield one of the constant prefix letters
/// `'p'`/`'a'`/`'i'`, collapsing each namespace onto a single shard and leaving
/// 13 of 16 dead. Skipping past the `':'` fixed that, but still sampled ONE
/// byte — so `pk:` keys (raw SHA-256 hex fingerprints, drawn from `[0-9a-f]`)
/// still reached only ten of sixteen shards, and `aid:` keys sharing a common
/// agent-id prefix still concentrated.
///
/// `fnv1a_shard` mixes every byte, which fixes both the namespace tag and the
/// hex-alphabet cases at once. See `shard.rs`.
fn trust_shard_index(key: &str) -> usize {
    crate::shard::fnv1a_shard(key, TRUST_SHARDS)
}

/// L-25 fix: opaque handle returned by [`TrustDecayEngine::subscribe`], usable with
/// [`TrustDecayEngine::unsubscribe`] to stop receiving signals. Previously `subscribe`
/// returned `()`, so a caller (or a buggy retry loop) that subscribed repeatedly leaked
/// callback closures in the (then-unbounded) observer list forever, with no way back
/// out — this gives real callers a way to close that leak at the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TrustObserverHandle(u64);

/// L-25 fix: hard cap on concurrently registered observers — see
/// [`TrustDecayEngine::subscribe`].
pub const TRUST_MAX_OBSERVERS: usize = 64;

/// Process-wide (or per-instance, for tests) continuous behavioral trust
/// tracker. See module docs for the full model.
pub struct TrustDecayEngine {
    shards: Vec<Mutex<HashMap<String, TrustEntry>>>,
    #[allow(clippy::type_complexity)]
    observers: Mutex<HashMap<u64, Arc<dyn Fn(TrustSignal) + Send + Sync>>>,
    next_observer_id: AtomicU64,
}

impl Default for TrustDecayEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl TrustDecayEngine {
    pub fn new() -> Self {
        Self {
            shards: (0..TRUST_SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            observers: Mutex::new(HashMap::new()),
            next_observer_id: AtomicU64::new(0),
        }
    }

    /// Lock and return the shard responsible for `key`.
    ///
    /// M-38 fix: every lock in this impl block recovers via `into_inner()` on
    /// poison rather than panicking — `TrustDecayEngine::global()` is a
    /// process-wide singleton, so one poisoning panic must not cascade into
    /// every other agent's trust-score checks.
    fn shard(&self, key: &str) -> std::sync::MutexGuard<'_, HashMap<String, TrustEntry>> {
        self.shards[trust_shard_index(key)].lock().unwrap_or_else(|e| e.into_inner())
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
    ///
    /// L-25 fix: returns a [`TrustObserverHandle`] usable with [`Self::unsubscribe`],
    /// and registration is capped at [`TRUST_MAX_OBSERVERS`] — previously this list grew
    /// without bound and had no way to shrink, a slow leak for any caller (or retry
    /// loop) that subscribed more than once. Returns `None` (no-op, nothing registered)
    /// if already at the cap, rather than evicting an active subscriber a caller may
    /// still be relying on.
    pub fn subscribe(&self, cb: Arc<dyn Fn(TrustSignal) + Send + Sync>) -> Option<TrustObserverHandle> {
        let mut observers = self.observers.lock().unwrap_or_else(|e| e.into_inner());
        if observers.len() >= TRUST_MAX_OBSERVERS {
            return None;
        }
        let id = self.next_observer_id.fetch_add(1, Ordering::Relaxed);
        observers.insert(id, cb);
        Some(TrustObserverHandle(id))
    }

    /// L-25 fix: stop receiving signals for a handle returned by [`Self::subscribe`].
    /// A no-op (returns `false`) if the handle was already unsubscribed.
    pub fn unsubscribe(&self, handle: TrustObserverHandle) -> bool {
        self.observers.lock().unwrap_or_else(|e| e.into_inner()).remove(&handle.0).is_some()
    }

    /// M-27 fix: snapshot-clone the observer list (a `Vec<Arc<dyn Fn...>>` —
    /// cloning is a bounded number of atomic refcount bumps, not a deep
    /// copy) and drop the `observers` lock BEFORE invoking any callback,
    /// instead of holding it for the callback loop's entire duration.
    /// Previously, a slow or blocking observer callback (or simply many
    /// registered observers) held `observers` locked for the whole loop,
    /// blocking any concurrent `subscribe()` call and — because `emit` runs
    /// synchronously on the packet-processing path per this type's own
    /// `subscribe` doc comment — indirectly extending gate-pipeline latency
    /// for every other in-flight packet touching this engine. Matches the
    /// same "release the lock, then notify" pattern
    /// `security::ImmutableAuditLog`'s subscriber mechanism already uses
    /// (and had already documented emit's own behavior as matching, before
    /// this fix made that true).
    fn emit(&self, agent_id: &str, score: f64, event: TrustEvent) {
        let signal = TrustSignal { agent_id: agent_id.to_string(), score, event };
        let observers: Vec<_> = self.observers.lock().unwrap_or_else(|e| e.into_inner())
            .values().cloned().collect();
        for cb in observers.iter() {
            cb(signal.clone());
        }
    }

    /// Current (recovery-adjusted) score for an agent. Never seen ⇒ `TRUST_SCORE_INITIAL`.
    pub fn score(&self, agent_id: &str) -> f64 {
        let mut entries = self.shard(agent_id);
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
        let mut entries = self.shard(agent_id);
        let now = now_secs();

        // IoT / low-resource fix: sweep stale entries only once this shard's
        // (aggregate-cap-preserving) per-shard cap is exceeded — mirrors
        // FederatedMemory. Two passes, scoped to this one shard only:
        //   1. Lazily recover every entry, then drop ones that are fully
        //      recovered (score >= 1.0) and not currently reauth-locked —
        //      those are safe to forget, functionally identical to never
        //      having been tracked.
        //   2. If still over cap (e.g. many distinct agents each penalized
        //      exactly once and never touched again — recovery alone can't
        //      reclaim those), evict from the *unlocked* remainder only,
        //      closest-to-`TRUST_SCORE_INITIAL` first (H-24).
        if entries.len() >= TRUST_PER_SHARD_MAX_ENTRIES && !entries.contains_key(agent_id) {
            for e in entries.values_mut() {
                e.recover_to(now);
            }
            entries.retain(|_, e| e.score < TRUST_SCORE_INITIAL || e.locked_at.is_some());

            if entries.len() >= TRUST_PER_SHARD_MAX_ENTRIES {
                let evict_count = entries.len() + 1 - TRUST_PER_SHARD_MAX_ENTRIES;
                // H-24: a reauth-locked entry is precisely the record an
                // attacker wants purged — flooding the map with fresh
                // agent_ids to force this sweep must never be able to evict
                // one, even if that means the map temporarily stays over
                // TRUST_PER_SHARD_MAX_ENTRIES until enough locks clear
                // naturally. Among the unlocked remainder, entries whose
                // score sits closest to TRUST_SCORE_INITIAL carry the least
                // signal (nearly/fully recovered, no active penalty) and are
                // safest to forget first — evict those before anything with
                // a lower, more diagnostic score.
                let mut candidates: Vec<(String, f64)> = entries.iter()
                    .filter(|(_, e)| e.locked_at.is_none())
                    .map(|(k, e)| (k.clone(), e.score))
                    .collect();
                candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                for (k, _) in candidates.into_iter().take(evict_count) {
                    entries.remove(&k);
                }
            }
        }

        let entry = entries.entry(agent_id.to_string()).or_insert_with(|| TrustEntry::fresh(now));
        entry.recover_to(now);
        let was_downgraded = entry.score < TRUST_DOWNGRADE_THRESHOLD;

        entry.score = (entry.score - penalty_weight(kind)).max(0.0);
        // L-23 fix: record this penalty so future `recover_to` calls apply a slower,
        // repeat-offender-adjusted recovery rate to this entry.
        entry.penalty_count = entry.penalty_count.saturating_add(1);

        let now_downgraded = entry.score < TRUST_DOWNGRADE_THRESHOLD;
        let now_reauth = entry.score < TRUST_REAUTH_THRESHOLD;
        // M-29 fix: `just_locked` captures whether THIS call is the one that
        // transitions `locked_at` from `None` to `Some` — i.e. the exact
        // moment reauth lockout begins. Reusing this existing guard (instead
        // of adding a separate flag) is sufficient: `locked_at.is_none()`
        // here is only ever true on the call that crosses the threshold: any
        // later call while still locked leaves `locked_at` as `Some(earlier
        // time)`, so this same condition naturally evaluates false and
        // `just_locked` correctly stays false on those later calls.
        let just_locked = now_reauth && entry.locked_at.is_none();
        if just_locked {
            entry.locked_at = Some(now);
        }
        let score = entry.score;
        drop(entries);

        self.emit(agent_id, score, TrustEvent::Penalized(kind));
        if now_downgraded && !was_downgraded {
            self.emit(agent_id, score, TrustEvent::Downgraded);
        }
        // M-29 fix: emit `ReauthRequired` only on the transition into
        // lockout (`just_locked`), not on every subsequent `penalize` call
        // while the agent remains below `TRUST_REAUTH_THRESHOLD`. Previously
        // `if now_reauth { ... }` re-fired this signal on every single call,
        // flooding any subscriber (e.g. an alerting/audit feed) with
        // duplicate "reauth required" events for what is, from the
        // subscriber's point of view, a single ongoing lockout state, not N
        // separate lockout events.
        if just_locked {
            self.emit(agent_id, score, TrustEvent::ReauthRequired);
        }
        score
    }

    /// Apply a positive behavioral signal for the given reward kind. Returns
    /// the resulting (recovery-adjusted, then rewarded) score. A no-op on the
    /// score (returns the current recovery-adjusted score unchanged) when the
    /// agent has already used its `TRUST_MAX_REWARDS_PER_MINUTE` budget for
    /// the current rolling window — anti-grinding (Phase 6 / Part 8.5).
    ///
    /// Never seen before ⇒ starts at `TRUST_SCORE_INITIAL`, so rewarding a
    /// never-penalized agent is a harmless no-op capped at
    /// `TRUST_SCORE_INITIAL` by `TRUST_REWARD_CEILING`/`.min(1.0)` below —
    /// consistent with `penalize()`'s symmetric behavior of creating a fresh
    /// entry on first touch.
    ///
    /// `is_irreversible_class` applies `TRUST_REWARD_IRREVERSIBLE_MULTIPLIER`
    /// when `true` — clean handling of the riskiest action class is stronger
    /// positive evidence than a READ_ONLY passage.
    pub fn reward(&self, agent_id: &str, kind: RewardKind, is_irreversible_class: bool) -> f64 {
        let mut entries = self.shard(agent_id);
        let now = now_secs();

        // Same capacity-bounded eviction precedent as `penalize()` — a reward
        // call must never be the mechanism by which the per-shard cap is
        // silently exceeded. H-24 protection (never evict a locked entry)
        // applies identically here.
        if entries.len() >= TRUST_PER_SHARD_MAX_ENTRIES && !entries.contains_key(agent_id) {
            for e in entries.values_mut() {
                e.recover_to(now);
            }
            entries.retain(|_, e| e.score < TRUST_SCORE_INITIAL || e.locked_at.is_some());

            if entries.len() >= TRUST_PER_SHARD_MAX_ENTRIES {
                let evict_count = entries.len() + 1 - TRUST_PER_SHARD_MAX_ENTRIES;
                let mut candidates: Vec<(String, f64)> = entries.iter()
                    .filter(|(_, e)| e.locked_at.is_none())
                    .map(|(k, e)| (k.clone(), e.score))
                    .collect();
                candidates.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
                for (k, _) in candidates.into_iter().take(evict_count) {
                    entries.remove(&k);
                }
            }
        }

        let entry = entries.entry(agent_id.to_string()).or_insert_with(|| TrustEntry::fresh(now));
        entry.recover_to(now);

        if !entry.try_consume_reward_slot(now) {
            let score = entry.score;
            drop(entries);
            return score;
        }

        let base = reward_weight(kind);
        let amount = if is_irreversible_class {
            base * TRUST_REWARD_IRREVERSIBLE_MULTIPLIER
        } else {
            base
        };

        let was_downgraded = entry.score < TRUST_DOWNGRADE_THRESHOLD;

        // Reward can lift a deeply-penalized score only up to
        // `TRUST_REWARD_FLOOR`, and can never push any score above
        // `TRUST_REWARD_CEILING` — both anti-gaming bounds are independent of
        // (and generally tighter than) the `.min(1.0)` hard ceiling
        // `recover_to` uses for passive recovery. The final `.max(entry.score)`
        // guards the case where passive recovery has already carried the
        // score above the applicable cap (e.g. a fully-recovered agent at
        // 1.0 rewarded again) — reward must never *decrease* a score, only
        // ever leave it unchanged or raise it.
        let raw_new_score = entry.score + amount;
        let cap = if entry.score < TRUST_REWARD_FLOOR { TRUST_REWARD_FLOOR } else { TRUST_REWARD_CEILING };
        entry.score = raw_new_score.min(cap).max(entry.score);

        let now_downgraded = entry.score < TRUST_DOWNGRADE_THRESHOLD;
        let score = entry.score;
        drop(entries);

        self.emit(agent_id, score, TrustEvent::Rewarded(kind));
        if was_downgraded && !now_downgraded {
            self.emit(agent_id, score, TrustEvent::Recovered);
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
        self.requires_reauth_at(agent_id, now_secs())
    }

    /// opusplan.md 6.4 item 1: same as [`Self::requires_reauth`], but takes an
    /// already-captured wall-clock reading instead of calling `now_secs()` internally
    /// — see `gateway::AgentRateLimiter::is_locked_at`'s doc comment for the shared
    /// rationale (this method runs immediately alongside `is_locked` at every packet
    /// pipeline's pre-gate checkpoint). `requires_reauth` itself is untouched and
    /// remains the right choice for any caller that doesn't already have a `now` in
    /// hand.
    pub fn requires_reauth_at(&self, agent_id: &str, now: f64) -> bool {
        let mut entries = self.shard(agent_id);
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
        match agent_id {
            Some(id) => { self.shard(id).remove(id); }
            None => { for shard in &self.shards { shard.lock().unwrap_or_else(|e| e.into_inner()).clear(); } }
        }
    }

    /// Number of currently-tracked agents (for the bounded-cardinality
    /// `saacp_trust_agents_tracked` telemetry gauge).
    pub fn tracked_count(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len()).sum()
    }

    /// opusplan.md 6.5: proactively remove every entry that has gone completely
    /// untouched (no `penalize`/`reward` call) for more than
    /// `TRUST_ENTRY_STALENESS_SECONDS`, independent of whether any shard has hit
    /// `TRUST_PER_SHARD_MAX_ENTRIES`. Before this, a shard under its capacity cap never
    /// evicted anything — `penalize`/`reward`'s existing eviction only triggers once a
    /// shard is already full — so an agent that stops sending traffic entirely still
    /// held its entry in memory indefinitely as long as the shard never filled up.
    ///
    /// Deliberately does NOT replace the existing score-proximity-to-initial eviction
    /// heuristic used when a shard IS at capacity (see `penalize`/`reward`) — that
    /// heuristic protects entries with the most earned trust or the most accumulated
    /// penalty, a genuine behavioral signal, not just "oldest first". This sweep is
    /// purely additive: a second, independent reclaim path keyed on inactivity instead
    /// of capacity pressure.
    ///
    /// H-24 is preserved identically to every other eviction path in this type: a
    /// currently reauth-locked entry (`locked_at.is_some()`) is never removed here,
    /// even if it's gone stale by wall-clock time — the whole point of a lockout is
    /// that it survives until its own cooldown, not until a maintenance sweep runs.
    /// Returns the number of entries removed.
    pub fn sweep_stale(&self) -> usize {
        let now = now_secs();
        let mut removed = 0usize;
        for shard in &self.shards {
            let mut entries = shard.lock().unwrap_or_else(|e| e.into_inner());
            let before = entries.len();
            entries.retain(|_, e| {
                e.locked_at.is_some() || (now - e.last_update) < TRUST_ENTRY_STALENESS_SECONDS
            });
            removed += before - entries.len();
        }
        removed
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
        let now = now_secs();

        // Each shard's lock is acquired independently and released before
        // moving to the next — this never holds more than one shard lock at
        // a time, so a concurrent `penalize()`/`score()` on a different shard
        // is never blocked by a snapshot in progress (only same-shard callers
        // briefly contend, same as before sharding).
        let mut out: Vec<AgentTrustSnapshot> = Vec::new();
        for shard in &self.shards {
            let mut entries = shard.lock().unwrap_or_else(|e| e.into_inner());
            out.extend(entries.iter_mut().map(|(id, e)| {
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
            }));
        }

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

/// (H-30) Decay rate applied lazily to a session's cumulative drift total,
/// based on elapsed wall-clock seconds since that session's last hop.
/// Mirrors `TrustEntry::recover_to`'s lazy-decay idiom: no background sweep,
/// folded in on next read/write. Defined relative to `CHAIN_DRIFT_CEILING` so
/// it stays self-documenting if the ceiling is retuned — a session sitting
/// exactly at the ceiling decays back to 0.0 after 10 minutes of total
/// inactivity. Without this, `total` only ever grew, so a long-lived,
/// otherwise well-behaved session would eventually and permanently trip the
/// ceiling from distant history alone.
pub const DRIFT_DECAY_PER_SECOND: f64 = CHAIN_DRIFT_CEILING / 600.0;

struct DriftEntry {
    total: f64,
    last_update: f64,
}

impl DriftEntry {
    /// Apply lazy time-based decay up to `now`, in place.
    fn decay_to(&mut self, now: f64) {
        let elapsed = (now - self.last_update).max(0.0);
        if elapsed > 0.0 {
            self.total = (self.total - elapsed * DRIFT_DECAY_PER_SECOND).max(0.0);
        }
        self.last_update = now;
    }
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
    ///
    /// M-38 fix: every `self.sessions.lock()` in this impl block recovers via
    /// `into_inner()` on poison rather than panicking — `IntentDriftTracker::global()`
    /// is a process-wide singleton, so one poisoning panic must not cascade
    /// into every other session's intent-drift tracking.
    pub fn accumulate(&self, session_uuid: &str, divergence: f64) -> f64 {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
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
        // (H-30) Decay before accumulating so a burst of hops in quick
        // succession — the pattern this ceiling actually defends against —
        // still accumulates fully (elapsed ~= 0 between hops), while a
        // session that goes quiet for minutes isn't penalized by stale
        // history when it resumes.
        entry.decay_to(now);
        entry.total += divergence;
        entry.total
    }

    /// Clear tracking for a session (e.g. on clean completion) or all sessions.
    pub fn reset(&self, session_uuid: Option<&str>) {
        let mut sessions = self.sessions.lock().unwrap_or_else(|e| e.into_inner());
        match session_uuid {
            Some(id) => { sessions.remove(id); }
            None => sessions.clear(),
        }
    }

    pub fn tracked_count(&self) -> usize {
        self.sessions.lock().unwrap_or_else(|e| e.into_inner()).len()
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

    /// opusplan.md 6.4 item 1: `requires_reauth_at` must agree with `requires_reauth`
    /// — same answer whether the caller supplies `now` explicitly or lets
    /// `requires_reauth` capture it internally.
    #[test]
    fn requires_reauth_at_agrees_with_requires_reauth() {
        let e = TrustDecayEngine::new();
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        assert!(e.score("agent-a") < TRUST_REAUTH_THRESHOLD);

        let now = now_secs();
        assert!(e.requires_reauth_at("agent-a", now), "a `now` at the current instant must still require reauth");
        assert!(!e.requires_reauth_at("never-tracked-agent", now));
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

    /// M-29 regression: `ReauthRequired` must fire exactly ONCE — on the
    /// call that actually crosses `TRUST_REAUTH_THRESHOLD` — not on every
    /// subsequent `penalize` call while the agent remains locked out.
    #[test]
    fn reauth_required_emitted_exactly_once_on_transition() {
        let e = TrustDecayEngine::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let events2 = events.clone();
        e.subscribe(Arc::new(move |sig: TrustSignal| {
            events2.lock().unwrap().push(sig.event);
        }));

        // 1.0 -> 0.60 (ReplaySuspicion weight 0.40): not yet below 0.25.
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        // 0.60 -> 0.20: crosses TRUST_REAUTH_THRESHOLD (0.25) — the ONE
        // call that should emit ReauthRequired.
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        // Score is floored at 0.0 already (0.20 - 0.40 -> 0.0 via .max(0.0)),
        // still well below threshold — must NOT re-emit ReauthRequired.
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);

        let evs = events.lock().unwrap();
        let reauth_count = evs.iter().filter(|e| matches!(e, TrustEvent::ReauthRequired)).count();
        assert_eq!(
            reauth_count, 1,
            "M-29: ReauthRequired must fire exactly once across repeated \
             penalize calls that keep the score below threshold, got {} \
             emissions: {:?}",
            reauth_count, *evs
        );
    }

    /// M-29: after an agent's tracked state is cleared (`reset`, e.g.
    /// simulating a fully-recovered, forgotten entry the way the natural
    /// recovery path in `requires_reauth` eventually would), a SUBSEQUENT
    /// lockout on a fresh entry must fire `ReauthRequired` again — the fix
    /// must not permanently suppress the signal for an agent's whole
    /// lifetime, only within a single ongoing lockout on one `TrustEntry`.
    #[test]
    fn reauth_required_fires_again_after_entry_reset() {
        let e = TrustDecayEngine::new();
        let events = Arc::new(Mutex::new(Vec::new()));
        let events2 = events.clone();
        e.subscribe(Arc::new(move |sig: TrustSignal| {
            events2.lock().unwrap().push(sig.event);
        }));

        // Cross into lockout.
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion); // 0.20, locked
        assert!(e.requires_reauth("agent-a"), "test setup: must be locked");

        // Wipe the tracked entry entirely (test/ops utility) — the next
        // penalize() call creates a brand-new `TrustEntry::fresh` with
        // `locked_at: None`, the same shape a genuinely-recovered-then-
        // forgotten entry would have.
        e.reset(Some("agent-a"));
        events.lock().unwrap().clear();

        // Cross into lockout a SECOND time, on the fresh entry — must emit
        // ReauthRequired again.
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);
        e.penalize("agent-a", PenaltyKind::ReplaySuspicion);

        let evs = events.lock().unwrap();
        let reauth_count = evs.iter().filter(|e| matches!(e, TrustEvent::ReauthRequired)).count();
        assert_eq!(
            reauth_count, 1,
            "a second, independent lockout must re-emit ReauthRequired, got {:?}",
            *evs
        );
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

    /// M-27 regression: a callback that itself calls `subscribe()` (re-
    /// entrant registration, e.g. an observer that wires up a follow-on
    /// observer the first time it fires) must not deadlock. Before the fix,
    /// `emit` held the `observers` lock for the whole callback loop, so a
    /// callback invoking `subscribe()` — which also locks `observers` —
    /// would deadlock against itself (same thread, same non-reentrant
    /// `std::sync::Mutex`).
    #[test]
    fn observer_callback_can_call_subscribe_without_deadlocking() {
        let e = Arc::new(TrustDecayEngine::new());
        let e2 = Arc::clone(&e);
        let second_fired = Arc::new(Mutex::new(false));
        let second_fired2 = Arc::clone(&second_fired);

        e.subscribe(Arc::new(move |_sig: TrustSignal| {
            // Re-entrant: register a second observer from inside the first
            // observer's callback, on the SAME engine, while `emit` is (or
            // was) mid-iteration over the first observer list.
            let second_fired3 = Arc::clone(&second_fired2);
            e2.subscribe(Arc::new(move |_sig2: TrustSignal| {
                *second_fired3.lock().unwrap() = true;
            }));
        }));

        // Must return promptly (no deadlock) — first emit triggers
        // subscribe(), which must succeed without blocking on `emit`'s own
        // (already-released, post-fix) observers lock.
        e.penalize("agent-a", PenaltyKind::InjectionAttempt);

        // A second emit must now also invoke the newly-registered observer.
        e.penalize("agent-a", PenaltyKind::InjectionAttempt);
        assert!(
            *second_fired.lock().unwrap(),
            "M-27: the re-entrantly-registered observer must fire on a later emit"
        );
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
        // cannot reclaim any of them and the closest-to-`TRUST_SCORE_INITIAL`
        // fallback eviction (H-24) must be what bounds the map instead.
        for i in 0..(TRUST_MAX_ENTRIES + 500) {
            e.penalize(&format!("bounded-agent-{i}"), PenaltyKind::GenericHardDrop);
        }
        assert!(e.tracked_count() <= TRUST_MAX_ENTRIES, "map must not grow unbounded past its cap");
    }

    #[test]
    fn h24_locked_entry_survives_eviction_flood() {
        // A single agent is penalized hard enough to trip `requires_reauth`
        // (score < TRUST_REAUTH_THRESHOLD), locking it. An attacker then
        // floods the map with fresh agent_ids past TRUST_MAX_ENTRIES, trying
        // to force the locked entry out via the cap-eviction sweep. Before
        // the H-24 fix this succeeded whenever the locked entry happened to
        // have the oldest `last_update` timestamp among all tracked agents —
        // silently un-suspecting a compromised identity. It must not happen
        // now, regardless of timestamp ordering.
        let e = TrustDecayEngine::new();
        let victim = "victim-agent";
        // Three penalties of 0.40 (ReplaySuspicion) drop the victim well
        // below TRUST_REAUTH_THRESHOLD (0.25) and below TRUST_DOWNGRADE_
        // THRESHOLD too, locking it via `locked_at`.
        e.penalize(victim, PenaltyKind::ReplaySuspicion);
        e.penalize(victim, PenaltyKind::ReplaySuspicion);
        e.penalize(victim, PenaltyKind::ReplaySuspicion);
        assert!(e.requires_reauth(victim), "victim must be reauth-locked before the flood");

        // Flood with enough distinct, freshly-penalized (near-full-trust)
        // agents to blow well past the cap and force repeated eviction
        // sweeps.
        for i in 0..(TRUST_MAX_ENTRIES + 2_000) {
            e.penalize(&format!("flood-agent-{i}"), PenaltyKind::GenericHardDrop);
        }

        assert!(
            e.requires_reauth(victim),
            "a locked (reauth-required) entry must never be evicted by the capacity sweep, \
             even under sustained flooding past TRUST_MAX_ENTRIES"
        );
    }

    // ── sweep_stale (opusplan.md 6.5 background staleness sweep) ────────────

    /// An entry whose `last_update` is older than `TRUST_ENTRY_STALENESS_SECONDS`
    /// must be removed by `sweep_stale`, even though its shard is nowhere near
    /// `TRUST_PER_SHARD_MAX_ENTRIES` — proving this is a genuinely independent
    /// reclaim path, not just a relabeling of the existing capacity-triggered sweep.
    #[test]
    fn sweep_stale_removes_entries_past_the_staleness_threshold() {
        let e = TrustDecayEngine::new();
        e.penalize("stale-agent", PenaltyKind::GenericHardDrop);
        assert_eq!(e.tracked_count(), 1);

        // Directly backdate `last_update` past the staleness threshold — this test
        // lives in `trust_decay`'s own `tests` submodule (`use super::*`), so it can
        // reach the private `shards`/`TrustEntry` fields the same way the module's
        // other white-box tests already do.
        {
            let mut shard = e.shard("stale-agent");
            let entry = shard.get_mut("stale-agent").expect("entry must exist after penalize");
            entry.last_update = now_secs() - TRUST_ENTRY_STALENESS_SECONDS - 1.0;
        }

        assert_eq!(e.sweep_stale(), 1, "sweep_stale must report exactly one entry removed");
        assert_eq!(e.tracked_count(), 0, "the stale entry must actually be gone");
    }

    /// A fresh (recently-touched) entry must survive `sweep_stale` untouched —
    /// the sweep must not be so aggressive it reclaims active agents.
    #[test]
    fn sweep_stale_leaves_fresh_entries_alone() {
        let e = TrustDecayEngine::new();
        e.penalize("fresh-agent", PenaltyKind::GenericHardDrop);
        assert_eq!(e.sweep_stale(), 0);
        assert_eq!(e.tracked_count(), 1);
    }

    /// H-24 must hold for `sweep_stale` exactly as it does for the existing
    /// capacity-triggered eviction paths: a currently reauth-locked entry must
    /// never be removed by the staleness sweep either, even once it's gone stale
    /// by wall-clock time — a lockout must survive until its own cooldown, not
    /// until a maintenance sweep happens to run.
    #[test]
    fn sweep_stale_never_removes_a_locked_entry_even_if_stale() {
        let e = TrustDecayEngine::new();
        let victim = "locked-and-stale-agent";
        e.penalize(victim, PenaltyKind::ReplaySuspicion);
        e.penalize(victim, PenaltyKind::ReplaySuspicion);
        e.penalize(victim, PenaltyKind::ReplaySuspicion);
        assert!(e.requires_reauth(victim), "test setup: victim must be reauth-locked");

        {
            let mut shard = e.shard(victim);
            let entry = shard.get_mut(victim).expect("entry must exist");
            entry.last_update = now_secs() - TRUST_ENTRY_STALENESS_SECONDS - 1.0;
        }

        assert_eq!(e.sweep_stale(), 0, "a locked entry must never be counted as swept");
        assert!(
            e.requires_reauth(victim),
            "a locked entry must survive sweep_stale even when it has also gone stale"
        );
    }

    // ── trust_key_for (S-2 fingerprint-keyed trust) ─────────────────────────

    #[test]
    fn trust_key_for_falls_back_to_agent_id_when_not_identity_bound() {
        // No TranscriptBoundSession registered for this session_id — must fall
        // back to the namespaced agent_id key, preserving prior behavior.
        let key = trust_key_for("agent-plain", "no-such-session-id-hex");
        assert_eq!(key, "aid:agent-plain");
    }

    #[test]
    fn trust_key_for_uses_public_key_fingerprint_when_identity_bound() {
        use crate::identity_binding::{TranscriptBoundSession, DEFAULT_IDENTITY_REGISTRY};

        // Unique, test-local session_id so this can't collide with any other
        // test's use of the process-wide DEFAULT_IDENTITY_REGISTRY singleton.
        let sid = vec![0xE5; 16];
        let client_pk_hex = "aa".repeat(32);
        let session = TranscriptBoundSession::establish(
            sid, "agent-claim-1", "server-x",
            &client_pk_hex, &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let session_id_hex = session.session_id_hex();
        DEFAULT_IDENTITY_REGISTRY.register(session);

        let key1 = trust_key_for("agent-claim-1", &session_id_hex);
        // The whole point of the fix: a different self-claimed agent_id on the
        // SAME identity-bound session resolves to the SAME trust key, because
        // it's derived from the proven public key, not the bearer claim.
        let key2 = trust_key_for("agent-claim-2-rotated", &session_id_hex);

        DEFAULT_IDENTITY_REGISTRY.remove(&DEFAULT_IDENTITY_REGISTRY
            .get_by_session_id(&session_id_hex, |s| s.thash.clone())
            .unwrap());

        assert!(key1.starts_with("pk:"), "expected a pk: fingerprint key, got {key1}");
        assert_eq!(key1, key2, "rotating the claimed agent_id on a fixed identity-bound \
            session must not change the trust key");
        assert_ne!(key1, "aid:agent-claim-1");
    }

    #[test]
    fn trust_key_for_differs_across_distinct_public_keys() {
        use crate::identity_binding::{TranscriptBoundSession, DEFAULT_IDENTITY_REGISTRY};

        let sid_a = vec![0xE6; 16];
        let session_a = TranscriptBoundSession::establish(
            sid_a, "agent-a", "server-x",
            &"11".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let sid_b = vec![0xE7; 16];
        let session_b = TranscriptBoundSession::establish(
            sid_b, "agent-b", "server-x",
            &"22".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let sid_hex_a = session_a.session_id_hex();
        let sid_hex_b = session_b.session_id_hex();
        let thash_a = session_a.thash.clone();
        let thash_b = session_b.thash.clone();
        DEFAULT_IDENTITY_REGISTRY.register(session_a);
        DEFAULT_IDENTITY_REGISTRY.register(session_b);

        let key_a = trust_key_for("agent-a", &sid_hex_a);
        let key_b = trust_key_for("agent-b", &sid_hex_b);

        DEFAULT_IDENTITY_REGISTRY.remove(&thash_a);
        DEFAULT_IDENTITY_REGISTRY.remove(&thash_b);

        assert_ne!(key_a, key_b, "distinct public keys must produce distinct trust keys");
    }

    // ── trust_shard_index (Part 6.3 sharding) ───────────────────────────────

    #[test]
    fn trust_shard_index_distributes_across_namespace_prefixes() {
        // Regression test: every key here is namespaced (`pk:` / `aid:` / `ip:`),
        // so a shard function that samples the FIRST byte sees only the constant
        // prefix letter and collapses each namespace onto a single shard —
        // 13 of 16 shards permanently dead, and the one live shard per namespace
        // reproducing the pre-sharding single-`Mutex` bottleneck.
        //
        // Asserted as a DISTRIBUTION over many keys rather than "these two keys
        // differ". Two arbitrary keys collide with probability 1/16 under any
        // sound hash, so a pairwise assertion would be flaky by construction —
        // it only held for the old scheme because it compared bytes that
        // happened to differ. What actually matters is that no namespace
        // concentrates.
        const SHARDS: usize = TRUST_SHARDS;
        const N: usize = 4_000;

        for (label, keys) in [
            ("pk:", (0..N).map(|i| format!("pk:{:064x}", i)).collect::<Vec<_>>()),
            ("aid:", (0..N).map(|i| format!("aid:agent-{i:05}")).collect()),
            ("ip:", (0..N).map(|i| format!("ip:10.{}.{}.{}", i / 65536 % 256, i / 256 % 256, i % 256)).collect()),
        ] {
            let mut counts = vec![0usize; SHARDS];
            for k in &keys {
                counts[trust_shard_index(k)] += 1;
            }
            let ideal = N as f64 / SHARDS as f64;
            let (lo, hi) = (ideal * 0.85, ideal * 1.15);
            assert!(
                counts.iter().all(|&c| (c as f64) >= lo && (c as f64) <= hi),
                "namespace {label} concentrates: {counts:?} \
                 (ideal {ideal:.0}/shard, tolerance {lo:.0}..={hi:.0}) — the shard \
                 function is likely sampling the namespace prefix rather than \
                 mixing the whole key",
            );
        }
    }

    #[test]
    fn trust_shard_index_handles_missing_or_trailing_colon_without_panicking() {
        // Degenerate keys must not panic and must stay in range. No current
        // caller produces these (every caller goes through `trust_key_for` /
        // `ip_trust_key`), so this is purely defensive.
        //
        // Deliberately asserts only the range invariant, not a specific shard
        // number: which shard the empty key lands on is an artifact of the hash
        // (FNV's offset basis mod 16), not a property worth pinning.
        for key in ["", "no-namespace-here", "pk:", ":", "::::"] {
            assert!(
                trust_shard_index(key) < TRUST_SHARDS,
                "trust_shard_index({key:?}) escaped the shard range",
            );
        }
    }

    // ── IntentDriftTracker ───────────────────────────────────────────────────

    #[test]
    fn drift_accumulates_across_calls() {
        let t = IntentDriftTracker::new();
        let total1 = t.accumulate("session-a", 0.3);
        assert!((total1 - 0.3).abs() < 1e-9);
        // (H-30) `total` now decays lazily by real elapsed wall-clock time
        // between calls, so the second call's result is `0.8` minus however
        // many microseconds actually passed between these two statements —
        // negligible (< 1e-4 even under heavy CI scheduling jitter) but no
        // longer exactly zero, unlike before decay was introduced.
        let total2 = t.accumulate("session-a", 0.5);
        assert!((total2 - 0.8).abs() < 1e-4, "unexpected drift beyond decay tolerance: total2={total2}");
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

    #[test]
    fn h30_intent_drift_total_decays_over_elapsed_time() {
        let t = IntentDriftTracker::new();
        let total1 = t.accumulate("session-decay", 1.0);
        assert!((total1 - 1.0).abs() < 1e-9);
        std::thread::sleep(std::time::Duration::from_millis(150));
        // Accumulating zero additional divergence after a real delay must
        // still show the existing total has decayed — proves `total` is no
        // longer purely monotonic (the bug H-30 fixes).
        let total2 = t.accumulate("session-decay", 0.0);
        assert!(
            total2 < total1,
            "cumulative drift must decay over elapsed time (H-30): total1={total1} total2={total2}"
        );
        // Sanity bound: 150ms of decay at DRIFT_DECAY_PER_SECOND should be a
        // small fraction of the total, not a cliff — confirms the *rate*, not
        // just the direction, is sane.
        let expected_decay = 0.150 * DRIFT_DECAY_PER_SECOND;
        assert!(
            (total1 - total2) < expected_decay * 3.0,
            "decay over 150ms was implausibly large: total1={total1} total2={total2}"
        );
    }

    #[test]
    fn h30_drift_decay_rate_fully_clears_ceiling_within_documented_window() {
        // DRIFT_DECAY_PER_SECOND is defined as CHAIN_DRIFT_CEILING / 600.0 —
        // a session sitting exactly at the ceiling must decay to zero after
        // 600s of total inactivity. Assert the relationship holds so a future
        // edit to either constant can't silently break that invariant.
        assert!(
            (DRIFT_DECAY_PER_SECOND * 600.0 - CHAIN_DRIFT_CEILING).abs() < 1e-9,
            "DRIFT_DECAY_PER_SECOND must fully decay CHAIN_DRIFT_CEILING within 600s"
        );
    }

    #[test]
    fn h30_quiet_session_after_reset_does_not_inherit_stale_drift() {
        let t = IntentDriftTracker::new();
        t.accumulate("session-quiet", CHAIN_DRIFT_CEILING - 0.1);
        t.reset(Some("session-quiet"));
        let total = t.accumulate("session-quiet", 0.05);
        assert!(
            total < CHAIN_DRIFT_CEILING,
            "a reset session must not spuriously trip the ceiling from prior history"
        );
    }
}
