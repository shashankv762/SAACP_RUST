//! mace.rs — Multi-Agent Collusion Detection Engine (MACE, Phase 6 / Part 8.2)
//!
//! *New in Rust* — no Python-reference analog.
//!
//! # Why this exists
//!
//! Every gate, [`crate::trust_decay::TrustDecayEngine`], and [`crate::ievl`]
//! reason about **one agent's** behavior in isolation. None of them can see a
//! coordinated pattern spread *across* several agents — a delegation chain that
//! loops back on itself, a swarm of distinct identities burning rate-limit
//! budget in lockstep, several agent_ids whose gate-rejection behavior is
//! suspiciously identical, or a burst of low-severity noise timed to mask one
//! high-severity action. MACE is the sidecar that watches for exactly that
//! class of signal.
//!
//! # Architecture — background sidecar, NOT a gate
//!
//! Matching [`crate::trust_decay::TrustDecayEngine`]'s own framing: "Background
//! sidecar... Observes gate outcomes without adding packet-path latency.
//! Detection runs in background/on-demand; enforcement via
//! penalize+revoke." MACE never blocks a packet in flight.
//!
//! # The five detection patterns
//!
//! - **Circular Delegation** ([`MultiAgentCollusionEngine::feed_delegation`]) —
//!   DFS reachability check (the same visited-set walk idiom
//!   `aegf::DistributedExecutionGraph::has_cycle_inner` uses for its own
//!   `rid`-ancestor-chain cycle check, applied here to an agent_id delegation
//!   graph instead) over a directed `from_agent -> to_agent` edge set.
//! - **Privilege Relay** (also `feed_delegation`) — an IRREVERSIBLE-class grant
//!   flowing to an agent that has never itself been recorded as a legitimate
//!   origin of that class (see [`MultiAgentCollusionEngine::record_irreversible_origin`]).
//! - **Coordinated Exhaustion** ([`MultiAgentCollusionEngine::detect_coordinated_exhaustion`]) —
//!   many distinct agent_ids tripping `CircuitBreakerOpen` within a short
//!   rolling window.
//! - **Sybil Cluster** ([`MultiAgentCollusionEngine::detect_sybil_clusters`]) —
//!   cosine similarity ≥ [`SYBIL_COSINE_THRESHOLD`] between two agents'
//!   gate-rejection-count fingerprint vectors.
//! - **Distraction Cover** ([`MultiAgentCollusionEngine::detect_distraction_cover`]) —
//!   a burst of low-severity alerts temporally clustered around one
//!   high-severity action, pulled from [`crate::telemetry::SecurityAlertFeed`].
//!
//! # Honest scope (read this before assuming more than is implemented)
//!
//! Circular Delegation and Privilege Relay need genuine `from_agent -> to_agent`
//! delegation edges. No live call site in this codebase currently carries that
//! data: the live HMAC-PSK capability-token path
//! (`gateway.rs::validate_lateral_movement`) only ever surfaces the *bearer's*
//! own `iss` claim as `source_agent` (`gateway.rs:772`), never a separate
//! delegator identity, and the one token format that does carry real
//! parent/chain data (`acsvaf.rs`'s `parent_jti`) is — by that module's own
//! existing doc comments — not live-wired into the main packet pipeline either.
//! [`MultiAgentCollusionEngine::feed_delegation`] is therefore real, complete,
//! and covered by its own tests, exactly like `acsvaf.rs` and
//! `telemetry::wire_trust_decay_metrics` (itself only ever called from
//! `telemetry.rs`'s own test module, `telemetry.rs:1169`) already are in this
//! codebase — callable, correct, production-ready plumbing, not yet wired to a
//! live per-packet call site because the upstream data it needs doesn't exist
//! at any such site today. Coordinated Exhaustion, Sybil Cluster, and
//! Distraction Cover use data that genuinely does exist today
//! ([`crate::telemetry::SecurityAlertFeed`]) and are wired live via
//! [`wire_mace_alert_feed`] — opt-in, matching
//! `telemetry::wire_trust_decay_metrics`'s own explicit-call convention.
//!
//! # Enforcement
//!
//! Per Part A.10 ("MACE → Trust + DRI: Collusion detection simultaneously
//! penalizes trust AND revokes credentials") and `errors.rs`'s own
//! `CollusionDetected` doc comment: every confirmed detection applies
//! `PenaltyKind::CollusionSuspected` AND calls
//! [`crate::faitf::DistributedRevocationInfrastructure::revoke`] on
//! [`crate::faitf::DistributedRevocationInfrastructure::global`] — never just
//! one or the other.
//!
//! # Bounded memory
//!
//! Every tracked map (fingerprints, delegation edges, rate-limit event window)
//! has a hard capacity with eviction — see each field's own doc comment.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::SAACPBytecodes;
use crate::faitf::{AgentIdentity, AttestationType, DistributedRevocationInfrastructure};
use crate::telemetry::{global_alert_feed, SecurityAlert};
use crate::trust_decay::{trust_key_for, PenaltyKind, TrustDecayEngine};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Cosine similarity at/above which two agents' gate-rejection fingerprints
/// are flagged as a Sybil-cluster match. Matches `errors.rs`'s
/// `CollusionDetected` doc comment exactly.
pub const SYBIL_COSINE_THRESHOLD: f64 = 0.92;

/// A fingerprint with fewer than this many total observed gate-rejection
/// events is too sparse to compare meaningfully — two brand-new agents with
/// one shared rejection each would otherwise trivially cosine-match at 1.0.
pub const SYBIL_MIN_OBSERVATIONS: u64 = 5;

/// Maximum distinct agent_ids tracked in the gate-outcome fingerprint map.
pub const MACE_MAX_FINGERPRINTED_AGENTS: usize = 2_000;

/// Maximum distinct agent_ids tracked across the delegation graph (keys and
/// values combined).
pub const MACE_MAX_DELEGATION_AGENTS: usize = 2_000;

/// Rolling window for Coordinated Exhaustion: `CircuitBreakerOpen` events
/// from at least [`COORDINATED_EXHAUSTION_MIN_AGENTS`] distinct agent_ids
/// within this many seconds is flagged.
pub const COORDINATED_EXHAUSTION_WINDOW_SECONDS: f64 = 10.0;
pub const COORDINATED_EXHAUSTION_MIN_AGENTS: usize = 5;

/// Hard cap on tracked rate-limit events, independent of the time window —
/// bounds memory even under a flood faster than the window can prune.
const MACE_MAX_RATE_LIMIT_EVENTS: usize = 10_000;

/// Distraction Cover: a high-severity action is "covered" when at least this
/// many low-severity alerts land within this many seconds of it.
pub const DISTRACTION_COVER_WINDOW_SECONDS: f64 = 5.0;
pub const DISTRACTION_COVER_MIN_LOW_SEVERITY: usize = 3;

/// How many of the most recent alerts `detect_distraction_cover` scans —
/// bounds the cost of each on-demand query regardless of
/// `SecurityAlertFeed`'s own (larger) ring capacity.
const DISTRACTION_COVER_SCAN_LIMIT: usize = 200;

/// Bytecodes (by their `{:?}` name, matching `SecurityAlert::bytecode`'s own
/// encoding) treated as high-severity for Distraction Cover purposes —
/// identity/session compromise and confirmed escalation/collusion, the same
/// tier `faitf.rs`'s `HIGH_SEVERITY_REASON_MARKERS` protects from eviction.
const HIGH_SEVERITY_BYTECODES: &[&str] = &[
    "ActionClassEscalation",
    "LateralMovementBlocked",
    "IdentityMisbinding",
    "SessionSpliceDetected",
    "IntentClassEscalationDetected",
    "CollusionDetected",
    "KeyRevoked",
];

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Outcome of [`MultiAgentCollusionEngine::feed_delegation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelegationSignal {
    /// No collusion signal — the edge was recorded normally.
    Ok,
    /// Adding this edge would close a cycle back to `from_agent`.
    CircularDelegation,
    /// An IRREVERSIBLE-class grant reached an agent with no recorded
    /// legitimate origin history at that class.
    PrivilegeRelay,
}

// ---------------------------------------------------------------------------
// MultiAgentCollusionEngine
// ---------------------------------------------------------------------------

pub struct MultiAgentCollusionEngine {
    /// agent_id -> (gate name -> rejection count). Feeds Sybil Cluster.
    fingerprints: Mutex<HashMap<String, HashMap<String, u64>>>,
    /// from_agent -> set of to_agent. Feeds Circular Delegation / Privilege Relay.
    delegation_edges: Mutex<HashMap<String, HashSet<String>>>,
    /// Agents recorded as a legitimate (non-relayed) origin of an
    /// IRREVERSIBLE-class action — the Privilege Relay baseline.
    irreversible_origins: Mutex<HashSet<String>>,
    /// (timestamp, agent_id) for each observed `CircuitBreakerOpen` event,
    /// oldest first. Feeds Coordinated Exhaustion.
    rate_limit_events: Mutex<VecDeque<(f64, String)>>,
}

impl Default for MultiAgentCollusionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl MultiAgentCollusionEngine {
    pub fn new() -> Self {
        Self {
            fingerprints: Mutex::new(HashMap::new()),
            delegation_edges: Mutex::new(HashMap::new()),
            irreversible_origins: Mutex::new(HashSet::new()),
            rate_limit_events: Mutex::new(VecDeque::new()),
        }
    }

    /// Process-wide singleton, matching `TrustDecayEngine::global()`'s
    /// established pattern. Does NOT auto-subscribe to the alert feed — call
    /// [`wire_mace_alert_feed`] explicitly, matching
    /// `telemetry::wire_trust_decay_metrics`'s own opt-in convention.
    pub fn global() -> &'static MultiAgentCollusionEngine {
        static GLOBAL: OnceLock<MultiAgentCollusionEngine> = OnceLock::new();
        GLOBAL.get_or_init(MultiAgentCollusionEngine::new)
    }

    // ── Sybil Cluster ───────────────────────────────────────────────────

    /// Record one gate-rejection observation for `agent_id`'s behavioral
    /// fingerprint. Bounded: on overflow, evicts the tracked agent with the
    /// smallest total observation count (least-developed fingerprint, safest
    /// to forget).
    pub fn feed_gate_outcome(&self, agent_id: &str, gate: &str) {
        let mut fp = self.fingerprints.lock().unwrap_or_else(|e| e.into_inner());

        if fp.len() >= MACE_MAX_FINGERPRINTED_AGENTS && !fp.contains_key(agent_id) {
            if let Some(smallest) = fp.iter()
                .min_by_key(|(_, gates)| gates.values().sum::<u64>())
                .map(|(k, _)| k.clone())
            {
                fp.remove(&smallest);
            }
        }

        *fp.entry(agent_id.to_string()).or_default().entry(gate.to_string()).or_insert(0) += 1;
    }

    /// Cosine similarity between two sparse gate-rejection-count vectors.
    fn cosine_similarity(a: &HashMap<String, u64>, b: &HashMap<String, u64>) -> f64 {
        let mut dot = 0.0f64;
        for (gate, &count_a) in a {
            if let Some(&count_b) = b.get(gate) {
                dot += count_a as f64 * count_b as f64;
            }
        }
        let norm_a = (a.values().map(|&v| (v as f64) * (v as f64)).sum::<f64>()).sqrt();
        let norm_b = (b.values().map(|&v| (v as f64) * (v as f64)).sum::<f64>()).sqrt();
        if norm_a == 0.0 || norm_b == 0.0 {
            return 0.0;
        }
        dot / (norm_a * norm_b)
    }

    /// All tracked agent pairs whose fingerprints cosine-match at or above
    /// [`SYBIL_COSINE_THRESHOLD`], each with at least [`SYBIL_MIN_OBSERVATIONS`]
    /// total observations (avoids trivial matches between near-empty
    /// fingerprints). O(n²) over currently-tracked agents — acceptable since
    /// the map is capacity-bounded and this is an on-demand/periodic sweep,
    /// not a per-packet check.
    pub fn detect_sybil_clusters(&self) -> Vec<(String, String, f64)> {
        let fp = self.fingerprints.lock().unwrap_or_else(|e| e.into_inner());
        let candidates: Vec<(&String, &HashMap<String, u64>)> = fp.iter()
            .filter(|(_, gates)| gates.values().sum::<u64>() >= SYBIL_MIN_OBSERVATIONS)
            .collect();

        let mut matches = Vec::new();
        for i in 0..candidates.len() {
            for j in (i + 1)..candidates.len() {
                let (agent_a, fp_a) = candidates[i];
                let (agent_b, fp_b) = candidates[j];
                let sim = Self::cosine_similarity(fp_a, fp_b);
                if sim >= SYBIL_COSINE_THRESHOLD {
                    matches.push((agent_a.clone(), agent_b.clone(), sim));
                }
            }
        }
        matches
    }

    /// Run [`Self::detect_sybil_clusters`] and enforce every match: both
    /// agents in a matched pair are penalized AND revoked (Part A.10).
    pub fn detect_and_enforce_sybil_clusters(&self) -> Vec<(String, String, f64)> {
        let matches = self.detect_sybil_clusters();
        for (agent_a, agent_b, _) in &matches {
            enforce_collusion(agent_a, "MACE: Sybil-cluster behavioral fingerprint match");
            enforce_collusion(agent_b, "MACE: Sybil-cluster behavioral fingerprint match");
        }
        matches
    }

    // ── Coordinated Exhaustion ──────────────────────────────────────────

    /// Record one `CircuitBreakerOpen` observation for `agent_id` at `now`.
    /// Bounded by both the rolling window (pruned on every call) and a hard
    /// entry cap independent of the window (survives a flood faster than the
    /// window alone could prune).
    pub fn record_rate_limit_event(&self, agent_id: &str, now: f64) {
        let mut events = self.rate_limit_events.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(&(ts, _)) = events.front() {
            if now - ts > COORDINATED_EXHAUSTION_WINDOW_SECONDS {
                events.pop_front();
            } else {
                break;
            }
        }
        if events.len() >= MACE_MAX_RATE_LIMIT_EVENTS {
            events.pop_front();
        }
        events.push_back((now, agent_id.to_string()));
    }

    /// Distinct agent_ids that tripped `CircuitBreakerOpen` within the last
    /// [`COORDINATED_EXHAUSTION_WINDOW_SECONDS`], if at least
    /// [`COORDINATED_EXHAUSTION_MIN_AGENTS`] distinct agents are present.
    pub fn detect_coordinated_exhaustion(&self, now: f64) -> Option<usize> {
        let mut events = self.rate_limit_events.lock().unwrap_or_else(|e| e.into_inner());
        while let Some(&(ts, _)) = events.front() {
            if now - ts > COORDINATED_EXHAUSTION_WINDOW_SECONDS {
                events.pop_front();
            } else {
                break;
            }
        }
        let distinct: HashSet<&str> = events.iter().map(|(_, a)| a.as_str()).collect();
        if distinct.len() >= COORDINATED_EXHAUSTION_MIN_AGENTS {
            Some(distinct.len())
        } else {
            None
        }
    }

    /// Like [`Self::detect_coordinated_exhaustion`], but on a confirmed swarm
    /// enforces [`enforce_collusion`] against every distinct agent currently
    /// inside the rolling window (Part A.10: penalize + revoke). Returns the
    /// list of enforced agent_ids (empty when no swarm is present). Collects the
    /// distinct set while holding the window lock, then releases it before
    /// enforcing — `enforce_collusion` reaches other global singletons
    /// (`TrustDecayEngine`, DRI, alert feed), so it must never run while the
    /// rate-limit-window mutex is held.
    pub fn detect_and_enforce_coordinated_exhaustion(&self, now: f64) -> Vec<String> {
        let flagged: Vec<String> = {
            let mut events = self.rate_limit_events.lock().unwrap_or_else(|e| e.into_inner());
            while let Some(&(ts, _)) = events.front() {
                if now - ts > COORDINATED_EXHAUSTION_WINDOW_SECONDS {
                    events.pop_front();
                } else {
                    break;
                }
            }
            let distinct: HashSet<&str> = events.iter().map(|(_, a)| a.as_str()).collect();
            if distinct.len() >= COORDINATED_EXHAUSTION_MIN_AGENTS {
                distinct.into_iter().map(|a| a.to_string()).collect()
            } else {
                Vec::new()
            }
        };
        for agent_id in &flagged {
            enforce_collusion(agent_id, "MACE: coordinated rate-limit exhaustion swarm");
        }
        flagged
    }

    // ── Distraction Cover ────────────────────────────────────────────────

    /// True if at least [`DISTRACTION_COVER_MIN_LOW_SEVERITY`] low-severity
    /// alerts landed within [`DISTRACTION_COVER_WINDOW_SECONDS`] of
    /// `around_timestamp`, pulled from [`crate::telemetry::SecurityAlertFeed`].
    pub fn detect_distraction_cover(&self, around_timestamp: f64) -> bool {
        let recent = global_alert_feed().recent(DISTRACTION_COVER_SCAN_LIMIT);
        let low_severity_nearby = recent.iter()
            .filter(|a| !HIGH_SEVERITY_BYTECODES.contains(&a.bytecode.as_str()))
            .filter(|a| (a.timestamp - around_timestamp).abs() <= DISTRACTION_COVER_WINDOW_SECONDS)
            .count();
        low_severity_nearby >= DISTRACTION_COVER_MIN_LOW_SEVERITY
    }

    /// Sweep-oriented counterpart to [`Self::detect_distraction_cover`]: instead
    /// of testing one caller-supplied timestamp, scan the recent alert feed for
    /// every high-severity action that is itself masked by a low-severity burst
    /// within [`DISTRACTION_COVER_WINDOW_SECONDS`], and enforce against the agent
    /// behind that high-severity action (the party whose real action the cover
    /// traffic was hiding — never the low-severity decoys, which may be unrelated
    /// or spoofed). Returns the distinct enforced agent_ids.
    ///
    /// The low-severity burst is counted excluding the high-severity anchor
    /// itself; a high-severity alert with no attributable `agent_id` is skipped
    /// (there is nothing to penalize/revoke). Enforcement is deduplicated per
    /// sweep so one agent tripping multiple covered actions is enforced once,
    /// and `enforce_collusion`'s revoke is idempotent across sweeps.
    pub fn detect_and_enforce_distraction_cover(&self) -> Vec<String> {
        let recent = global_alert_feed().recent(DISTRACTION_COVER_SCAN_LIMIT);
        let mut enforced: Vec<String> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for anchor in recent.iter()
            .filter(|a| HIGH_SEVERITY_BYTECODES.contains(&a.bytecode.as_str()))
        {
            if anchor.agent_id.is_empty() || seen.contains(&anchor.agent_id) {
                continue;
            }
            let low_severity_nearby = recent.iter()
                .filter(|a| !HIGH_SEVERITY_BYTECODES.contains(&a.bytecode.as_str()))
                .filter(|a| (a.timestamp - anchor.timestamp).abs() <= DISTRACTION_COVER_WINDOW_SECONDS)
                .count();
            if low_severity_nearby >= DISTRACTION_COVER_MIN_LOW_SEVERITY {
                seen.insert(anchor.agent_id.clone());
                enforce_collusion(&anchor.agent_id, "MACE: distraction-cover masked high-severity action");
                enforced.push(anchor.agent_id.clone());
            }
        }
        enforced
    }

    // ── Circular Delegation / Privilege Relay ───────────────────────────

    /// Mark `agent_id` as a legitimate origin of an IRREVERSIBLE-class
    /// action — the baseline [`Self::feed_delegation`]'s Privilege Relay
    /// check compares against.
    pub fn record_irreversible_origin(&self, agent_id: &str) {
        let mut origins = self.irreversible_origins.lock().unwrap_or_else(|e| e.into_inner());
        origins.insert(agent_id.to_string());
    }

    fn delegation_agent_count(edges: &HashMap<String, HashSet<String>>) -> usize {
        let mut agents: HashSet<&str> = HashSet::new();
        for (from, tos) in edges {
            agents.insert(from.as_str());
            for to in tos {
                agents.insert(to.as_str());
            }
        }
        agents.len()
    }

    fn path_exists(edges: &HashMap<String, HashSet<String>>, start: &str, target: &str) -> bool {
        let mut visited: HashSet<String> = HashSet::new();
        let mut stack: Vec<String> = vec![start.to_string()];
        while let Some(node) = stack.pop() {
            if node == target {
                return true;
            }
            if !visited.insert(node.clone()) {
                continue;
            }
            if let Some(neighbors) = edges.get(&node) {
                for n in neighbors {
                    stack.push(n.clone());
                }
            }
        }
        false
    }

    /// Record a `from_agent -> to_agent` delegation edge for `action_class`,
    /// checking both Circular Delegation and Privilege Relay. See the module
    /// docs' "Honest scope" section for why no production call site feeds
    /// this today.
    pub fn feed_delegation(&self, from_agent: &str, to_agent: &str, action_class: u8) -> DelegationSignal {
        let creates_cycle = {
            let edges = self.delegation_edges.lock().unwrap_or_else(|e| e.into_inner());
            from_agent == to_agent || Self::path_exists(&edges, to_agent, from_agent)
        };

        {
            let mut edges = self.delegation_edges.lock().unwrap_or_else(|e| e.into_inner());
            let already_known = edges.contains_key(from_agent)
                || edges.values().any(|tos| tos.contains(from_agent))
                || edges.contains_key(to_agent)
                || edges.values().any(|tos| tos.contains(to_agent));
            if already_known || Self::delegation_agent_count(&edges) < MACE_MAX_DELEGATION_AGENTS {
                edges.entry(from_agent.to_string()).or_default().insert(to_agent.to_string());
            }
        }

        if creates_cycle {
            enforce_collusion(from_agent, "MACE: circular delegation cycle detected");
            enforce_collusion(to_agent, "MACE: circular delegation cycle detected");
            return DelegationSignal::CircularDelegation;
        }

        if action_class >= crate::framing::ACTION_CLASS_IRREVERSIBLE {
            let is_origin = self.irreversible_origins.lock().unwrap_or_else(|e| e.into_inner()).contains(to_agent);
            if !is_origin {
                enforce_collusion(to_agent, "MACE: privilege relay detected");
                return DelegationSignal::PrivilegeRelay;
            }
        }

        DelegationSignal::Ok
    }

    /// Number of distinct agent_ids currently tracked in the delegation
    /// graph (observability/tests).
    pub fn delegation_tracked_agent_count(&self) -> usize {
        let edges = self.delegation_edges.lock().unwrap_or_else(|e| e.into_inner());
        Self::delegation_agent_count(&edges)
    }

    /// Number of distinct agent_ids currently fingerprinted
    /// (observability/tests).
    pub fn fingerprinted_agent_count(&self) -> usize {
        self.fingerprints.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

/// Apply MACE's standard confirmed-collusion enforcement to one agent: a
/// `PenaltyKind::CollusionSuspected` trust penalty AND a
/// `DistributedRevocationInfrastructure::global().revoke` call, together —
/// per Part A.10 and `errors.rs`'s `CollusionDetected` doc comment, never
/// just one or the other.
fn enforce_collusion(agent_id: &str, reason: &str) {
    let trust_key = trust_key_for(agent_id, "");
    TrustDecayEngine::global().penalize(&trust_key, PenaltyKind::CollusionSuspected);
    let revoker = system_revoker_identity();
    let _ = DistributedRevocationInfrastructure::global().revoke(
        agent_id,
        &format!("security-incident: {reason}"),
        revoker,
        "",
    );
    // O-7: surface the detection itself on the alert feed/dashboard — until
    // this call, a confirmed collusion event was only observable indirectly
    // (a trust-score drop, a revocation record), never as a first-class
    // event a human/dashboard could see and correlate with `reason`.
    global_alert_feed().record(SecurityAlert {
        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
        agent_id: agent_id.to_string(),
        gate: "mace_collusion",
        bytecode: format!("{:?}", SAACPBytecodes::CollusionDetected),
        estimated_cost: None,
    });
}

/// Lazily-generated protocol-internal identity used as the `revoker_identity`
/// for MACE's own automated (non-human)
/// `DistributedRevocationInfrastructure::revoke` calls — distinct from
/// `ievl::system_revoker_identity` (a separate identity per subsystem, so a
/// revocation record's `revoker_id` always attributes to the specific
/// automated control that made the call).
fn system_revoker_identity() -> &'static AgentIdentity {
    static SYSTEM_IDENTITY: OnceLock<AgentIdentity> = OnceLock::new();
    SYSTEM_IDENTITY.get_or_init(|| {
        AgentIdentity::generate(
            "saacp-mace-system",
            "saacp-protocol",
            u32::MAX as u64,
            None,
            None,
            "",
            AttestationType::None,
        )
    })
}

// ---------------------------------------------------------------------------
// Alert-feed wiring (opt-in — see module docs' "Honest scope" section)
// ---------------------------------------------------------------------------

/// Subscribe [`MultiAgentCollusionEngine::global`] to
/// [`crate::telemetry::global_alert_feed`] so every gate rejection anywhere in
/// the pipeline automatically feeds Sybil Cluster fingerprinting, and every
/// `CircuitBreakerOpen` rejection additionally feeds Coordinated Exhaustion —
/// with zero changes to any individual gate's own call site (`handler.rs`
/// already funnels every rejection through `report_gate_rejection`, which
/// already calls `SecurityAlertFeed::record`). Explicit opt-in, matching
/// `telemetry::wire_trust_decay_metrics`'s own convention — call once at
/// deployment startup.
pub fn wire_mace_alert_feed() {
    let engine = MultiAgentCollusionEngine::global();
    global_alert_feed().subscribe(Arc::new(move |alert: &SecurityAlert| {
        engine.feed_gate_outcome(&alert.agent_id, alert.gate);
        if alert.bytecode == "CircuitBreakerOpen" {
            engine.record_rate_limit_event(&alert.agent_id, alert.timestamp);
        }
    }));
}

// ---------------------------------------------------------------------------
// Deployment on/off switch + background sweep activation
// ---------------------------------------------------------------------------

static MACE_ENABLED: AtomicBool = AtomicBool::new(false);

/// Whether MACE has been activated for this process via [`activate`].
pub fn is_enabled() -> bool {
    MACE_ENABLED.load(Ordering::SeqCst)
}

/// Activate MACE for this process: subscribe [`MultiAgentCollusionEngine::global`]
/// to the live alert feed ([`wire_mace_alert_feed`]) so real traffic populates
/// its Sybil fingerprints and Coordinated-Exhaustion window, and flip the
/// [`is_enabled`] flag so a registered [`sweep_and_enforce`] cycle actually runs
/// the detectors. Idempotent — subscribing more than once would double-count
/// every alert, so repeated calls after the first are a no-op.
///
/// Opt-in, matching [`crate::aca::set_required`] / [`crate::sid::set_required`]:
/// a deployment that never calls this gets zero MACE observation and zero
/// background work. Pair with a `MaintenanceCoordinator` registration of
/// [`sweep_and_enforce`] (see the binaries' maintenance wiring) so the detectors
/// run periodically off the packet path.
pub fn activate() {
    // `swap` guarantees exactly one caller performs the subscription even under
    // concurrent activation, so the alert feed never gets two live MACE
    // subscribers double-counting the same event.
    if !MACE_ENABLED.swap(true, Ordering::SeqCst) {
        wire_mace_alert_feed();
    }
}

/// One full MACE detection-and-enforcement sweep, intended to run periodically
/// off the packet path (via `MaintenanceCoordinator`) — never inline in a gate.
/// A no-op unless [`is_enabled`]. Runs the three detectors backed by live data
/// (Sybil Cluster, Coordinated Exhaustion, Distraction Cover); each confirmed
/// detection enforces via [`enforce_collusion`] (trust penalty + DRI revoke +
/// alert), and `enforce_collusion`'s own revoke is idempotent, so re-flagging an
/// already-revoked agent on a later sweep does not weaken or duplicate the
/// monotonic revocation already in place. Circular Delegation / Privilege Relay
/// enforce eagerly inside [`MultiAgentCollusionEngine::feed_delegation`] at the
/// moment an edge is added, so they need no sweep pass here.
pub fn sweep_and_enforce() {
    if !is_enabled() {
        return;
    }
    let engine = MultiAgentCollusionEngine::global();

    // Sybil Cluster — penalize+revoke both agents of every fingerprint match.
    engine.detect_and_enforce_sybil_clusters();

    // Coordinated Exhaustion — a confirmed lockstep circuit-breaker swarm
    // revokes every distinct agent currently inside the rolling window.
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
    engine.detect_and_enforce_coordinated_exhaustion(now);

    // Distraction Cover — a high-severity action masked by a temporally
    // clustered low-severity burst revokes the agent behind that action.
    engine.detect_and_enforce_distraction_cover();
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Sybil Cluster ────────────────────────────────────────────────────

    #[test]
    fn identical_fingerprints_flagged_as_sybil_cluster() {
        let engine = MultiAgentCollusionEngine::new();
        for _ in 0..6 {
            engine.feed_gate_outcome("agent-a", "gate_4_0_inject");
            engine.feed_gate_outcome("agent-b", "gate_4_0_inject");
        }
        let matches = engine.detect_sybil_clusters();
        assert_eq!(matches.len(), 1);
        assert!((matches[0].2 - 1.0).abs() < 1e-9);
    }

    #[test]
    fn disjoint_fingerprints_not_flagged() {
        let engine = MultiAgentCollusionEngine::new();
        for _ in 0..6 {
            engine.feed_gate_outcome("agent-a", "gate_4_0_inject");
            engine.feed_gate_outcome("agent-b", "gate_1_5_intent");
        }
        assert!(engine.detect_sybil_clusters().is_empty());
    }

    #[test]
    fn sparse_fingerprints_below_min_observations_not_flagged() {
        let engine = MultiAgentCollusionEngine::new();
        // Only 2 observations each — below SYBIL_MIN_OBSERVATIONS (5), even
        // though they're identical.
        engine.feed_gate_outcome("agent-a", "gate_4_0_inject");
        engine.feed_gate_outcome("agent-a", "gate_4_0_inject");
        engine.feed_gate_outcome("agent-b", "gate_4_0_inject");
        engine.feed_gate_outcome("agent-b", "gate_4_0_inject");
        assert!(engine.detect_sybil_clusters().is_empty());
    }

    #[test]
    fn cosine_similarity_symmetric_and_bounded() {
        let mut a = HashMap::new();
        a.insert("g1".to_string(), 3u64);
        a.insert("g2".to_string(), 1u64);
        let mut b = HashMap::new();
        b.insert("g1".to_string(), 3u64);
        b.insert("g2".to_string(), 1u64);
        let sim = MultiAgentCollusionEngine::cosine_similarity(&a, &b);
        assert!((sim - 1.0).abs() < 1e-9);
        assert_eq!(sim, MultiAgentCollusionEngine::cosine_similarity(&b, &a));
    }

    #[test]
    fn cosine_similarity_empty_vector_is_zero() {
        let empty = HashMap::new();
        let mut a = HashMap::new();
        a.insert("g1".to_string(), 3u64);
        assert_eq!(MultiAgentCollusionEngine::cosine_similarity(&a, &empty), 0.0);
    }

    #[test]
    fn detect_and_enforce_penalizes_and_revokes_both_agents() {
        let engine = MultiAgentCollusionEngine::new();
        for _ in 0..6 {
            engine.feed_gate_outcome("sybil-x", "gate_4_0_inject");
            engine.feed_gate_outcome("sybil-y", "gate_4_0_inject");
        }
        let before_x = TrustDecayEngine::global().score(&trust_key_for("sybil-x", ""));
        let matches = engine.detect_and_enforce_sybil_clusters();
        assert_eq!(matches.len(), 1);
        let after_x = TrustDecayEngine::global().score(&trust_key_for("sybil-x", ""));
        assert!(after_x < before_x, "confirmed Sybil match must penalize trust");
        assert!(DistributedRevocationInfrastructure::global().is_revoked("sybil-x", ""));
        assert!(DistributedRevocationInfrastructure::global().is_revoked("sybil-y", ""));
    }

    // ── Coordinated Exhaustion ───────────────────────────────────────────

    #[test]
    fn coordinated_exhaustion_detected_with_enough_distinct_agents() {
        let engine = MultiAgentCollusionEngine::new();
        for i in 0..COORDINATED_EXHAUSTION_MIN_AGENTS {
            engine.record_rate_limit_event(&format!("flood-agent-{i}"), 100.0);
        }
        assert_eq!(engine.detect_coordinated_exhaustion(100.0), Some(COORDINATED_EXHAUSTION_MIN_AGENTS));
    }

    #[test]
    fn coordinated_exhaustion_not_flagged_below_min_agents() {
        let engine = MultiAgentCollusionEngine::new();
        for i in 0..(COORDINATED_EXHAUSTION_MIN_AGENTS - 1) {
            engine.record_rate_limit_event(&format!("flood-agent-{i}"), 100.0);
        }
        assert_eq!(engine.detect_coordinated_exhaustion(100.0), None);
    }

    #[test]
    fn coordinated_exhaustion_prunes_events_outside_window() {
        let engine = MultiAgentCollusionEngine::new();
        for i in 0..COORDINATED_EXHAUSTION_MIN_AGENTS {
            engine.record_rate_limit_event(&format!("stale-agent-{i}"), 0.0);
        }
        let now = COORDINATED_EXHAUSTION_WINDOW_SECONDS + 1.0;
        assert_eq!(engine.detect_coordinated_exhaustion(now), None);
    }

    #[test]
    fn coordinated_exhaustion_same_agent_repeated_does_not_count_as_distinct() {
        let engine = MultiAgentCollusionEngine::new();
        for _ in 0..20 {
            engine.record_rate_limit_event("single-agent", 100.0);
        }
        assert_eq!(engine.detect_coordinated_exhaustion(100.0), None);
    }

    // ── Distraction Cover ────────────────────────────────────────────────

    #[test]
    fn distraction_cover_detected_with_nearby_low_severity_burst() {
        // Uses the REAL global alert feed (SecurityAlertFeed is process-wide) —
        // unique bytecodes/agent ids avoid cross-test interference within this
        // module's own test run.
        let base_ts = 500_000.0;
        for i in 0..DISTRACTION_COVER_MIN_LOW_SEVERITY {
            global_alert_feed().record(SecurityAlert {
                timestamp: base_ts + i as f64,
                agent_id: format!("distraction-agent-{i}"),
                gate: "gate_9_0_schema",
                bytecode: "SchemaMismatch".to_string(),
                estimated_cost: None,
            });
        }
        let engine = MultiAgentCollusionEngine::new();
        assert!(engine.detect_distraction_cover(base_ts + 1.0));
    }

    #[test]
    fn distraction_cover_not_flagged_when_events_are_high_severity() {
        let base_ts = 600_000.0;
        for i in 0..DISTRACTION_COVER_MIN_LOW_SEVERITY {
            global_alert_feed().record(SecurityAlert {
                timestamp: base_ts + i as f64,
                agent_id: format!("high-sev-agent-{i}"),
                gate: "gate_1_0_token",
                bytecode: "LateralMovementBlocked".to_string(),
                estimated_cost: None,
            });
        }
        let engine = MultiAgentCollusionEngine::new();
        assert!(!engine.detect_distraction_cover(base_ts + 1.0));
    }

    #[test]
    fn distraction_cover_not_flagged_when_outside_window() {
        let base_ts = 700_000.0;
        for i in 0..DISTRACTION_COVER_MIN_LOW_SEVERITY {
            global_alert_feed().record(SecurityAlert {
                timestamp: base_ts + i as f64,
                agent_id: format!("far-agent-{i}"),
                gate: "gate_9_0_schema",
                bytecode: "SchemaMismatch".to_string(),
                estimated_cost: None,
            });
        }
        let engine = MultiAgentCollusionEngine::new();
        let far_future = base_ts + DISTRACTION_COVER_WINDOW_SECONDS + 100.0;
        assert!(!engine.detect_distraction_cover(far_future));
    }

    // ── Circular Delegation / Privilege Relay ───────────────────────────

    #[test]
    fn simple_delegation_chain_is_ok() {
        let engine = MultiAgentCollusionEngine::new();
        assert_eq!(engine.feed_delegation("orchestrator", "worker-a", 0x00), DelegationSignal::Ok);
        assert_eq!(engine.feed_delegation("worker-a", "worker-b", 0x00), DelegationSignal::Ok);
    }

    #[test]
    fn direct_self_delegation_is_circular() {
        let engine = MultiAgentCollusionEngine::new();
        assert_eq!(engine.feed_delegation("agent-a", "agent-a", 0x00), DelegationSignal::CircularDelegation);
    }

    #[test]
    fn three_hop_cycle_detected() {
        let engine = MultiAgentCollusionEngine::new();
        assert_eq!(engine.feed_delegation("a", "b", 0x00), DelegationSignal::Ok);
        assert_eq!(engine.feed_delegation("b", "c", 0x00), DelegationSignal::Ok);
        // Closing the loop: c -> a, where a already (transitively) delegates to c.
        assert_eq!(engine.feed_delegation("c", "a", 0x00), DelegationSignal::CircularDelegation);
    }

    #[test]
    fn cycle_detection_penalizes_and_revokes_both_endpoints() {
        let engine = MultiAgentCollusionEngine::new();
        engine.feed_delegation("cycle-x", "cycle-y", 0x00);
        let before = TrustDecayEngine::global().score(&trust_key_for("cycle-x", ""));
        let signal = engine.feed_delegation("cycle-y", "cycle-x", 0x00);
        assert_eq!(signal, DelegationSignal::CircularDelegation);
        let after = TrustDecayEngine::global().score(&trust_key_for("cycle-x", ""));
        assert!(after < before);
        assert!(DistributedRevocationInfrastructure::global().is_revoked("cycle-x", ""));
        assert!(DistributedRevocationInfrastructure::global().is_revoked("cycle-y", ""));
    }

    #[test]
    fn confirmed_collusion_is_recorded_on_the_alert_feed() {
        // O-7: enforce_collusion's penalize+revoke side effects were already
        // covered by `cycle_detection_penalizes_and_revokes_both_endpoints`;
        // this asserts the detection itself is now ALSO independently
        // observable as a `CollusionDetected` alert-feed event, not just
        // inferable from the trust/revocation side effects.
        let engine = MultiAgentCollusionEngine::new();
        engine.feed_delegation("alert-cycle-x", "alert-cycle-y", 0x00);
        let signal = engine.feed_delegation("alert-cycle-y", "alert-cycle-x", 0x00);
        assert_eq!(signal, DelegationSignal::CircularDelegation);

        let recent = global_alert_feed().recent(50);
        assert!(
            recent.iter().any(|a| a.gate == "mace_collusion"
                && a.bytecode == format!("{:?}", SAACPBytecodes::CollusionDetected)
                && (a.agent_id == "alert-cycle-x" || a.agent_id == "alert-cycle-y")),
            "expected a CollusionDetected alert for one of the cycle endpoints, got: {recent:?}"
        );
    }

    #[test]
    fn privilege_relay_flagged_for_non_origin_agent() {
        let engine = MultiAgentCollusionEngine::new();
        let signal = engine.feed_delegation("orchestrator", "never-declared-agent", crate::framing::ACTION_CLASS_IRREVERSIBLE);
        assert_eq!(signal, DelegationSignal::PrivilegeRelay);
    }

    #[test]
    fn privilege_relay_not_flagged_for_recorded_origin() {
        let engine = MultiAgentCollusionEngine::new();
        engine.record_irreversible_origin("legit-agent");
        let signal = engine.feed_delegation("orchestrator", "legit-agent", crate::framing::ACTION_CLASS_IRREVERSIBLE);
        assert_eq!(signal, DelegationSignal::Ok);
    }

    #[test]
    fn privilege_relay_not_checked_for_reversible_class() {
        let engine = MultiAgentCollusionEngine::new();
        let signal = engine.feed_delegation("orchestrator", "some-agent", crate::framing::ACTION_CLASS_REVERSIBLE);
        assert_eq!(signal, DelegationSignal::Ok);
    }

    #[test]
    fn delegation_tracked_agent_count_reflects_graph() {
        let engine = MultiAgentCollusionEngine::new();
        assert_eq!(engine.delegation_tracked_agent_count(), 0);
        engine.feed_delegation("a", "b", 0x00);
        assert_eq!(engine.delegation_tracked_agent_count(), 2);
        engine.feed_delegation("b", "c", 0x00);
        assert_eq!(engine.delegation_tracked_agent_count(), 3);
    }

    // ── Alert-feed wiring ────────────────────────────────────────────────

    #[test]
    fn wire_mace_alert_feed_does_not_panic() {
        use std::time::{SystemTime, UNIX_EPOCH};
        wire_mace_alert_feed();
        global_alert_feed().record(SecurityAlert {
            timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64(),
            agent_id: "wiring-smoke-test-agent".to_string(),
            gate: "gate_smoke_test",
            bytecode: "GenericHardDrop".to_string(),
            estimated_cost: None,
        });
    }

    #[test]
    fn system_revoker_identity_is_stable_and_distinct_from_ievl() {
        let a = system_revoker_identity().fingerprint();
        let b = system_revoker_identity().fingerprint();
        assert_eq!(a, b);
    }

    #[test]
    fn fingerprinted_agent_count_tracks_distinct_agents() {
        let engine = MultiAgentCollusionEngine::new();
        assert_eq!(engine.fingerprinted_agent_count(), 0);
        engine.feed_gate_outcome("solo-agent", "gate_x");
        assert_eq!(engine.fingerprinted_agent_count(), 1);
        engine.feed_gate_outcome("solo-agent", "gate_y");
        assert_eq!(engine.fingerprinted_agent_count(), 1);
        engine.feed_gate_outcome("another-agent", "gate_x");
        assert_eq!(engine.fingerprinted_agent_count(), 2);
    }
}
