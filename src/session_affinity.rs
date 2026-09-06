//! Session affinity tracking (M11 / R7 — opusreview.md).
//!
//! Detects when a session appears on a daemon node that did not create it,
//! which indicates a non-affine load balancer is silently breaking the
//! protocol's replay-protection guarantee.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

/// M-D remediation (production audit G4/R4): the tracker previously grew with
/// every session ever seen for the life of the process — an attacker (or just
/// churn) minting unique 16-byte session ids grew it without bound. Entries
/// are now capped at this many; the oldest-inserted session is evicted
/// FIFO-style when the cap is exceeded (same "bounded everything, evict on
/// overflow" idiom as the other engine stores). An evicted session loses its
/// violation memory — reappearing on a foreign node re-records it instead of
/// alerting — which is the deliberate bounded-memory tradeoff, identical in
/// kind to every other capped store in this codebase.
pub const AFFINITY_MAX_ENTRIES: usize = 100_000;

/// Tracks which daemon node accepted each session.
///
/// M11 (R7 / opusreview.md): a non-affine load balancer in front of a SAACP
/// fleet silently degrades replay protection to per-connection. This tracker
/// records the accepting node per session_id and detects violations.
#[derive(Clone)]
pub struct SessionAffinityTracker {
    inner: Arc<Mutex<AffinityMap>>,
}

#[derive(Default)]
struct AffinityMap {
    map: HashMap<String, String>,
    /// Insertion order for FIFO eviction — keys are pushed exactly once (on
    /// first insert); no other removal path exists, so map and queue stay in
    /// sync by construction.
    order: VecDeque<String>,
    max_entries: usize,
}

impl SessionAffinityTracker {
    pub fn new() -> Self {
        Self::with_max_entries(AFFINITY_MAX_ENTRIES)
    }

    /// Bounded tracker with an explicit cap (unit/integration tests use a
    /// small cap; production uses [`AFFINITY_MAX_ENTRIES`]).
    pub fn with_max_entries(max_entries: usize) -> Self {
        Self {
            inner: Arc::new(Mutex::new(AffinityMap {
                map: HashMap::new(),
                order: VecDeque::new(),
                max_entries,
            })),
        }
    }

    /// Record that `node_id` created `session_id`. Returns `Ok(())` if this is
    /// the first time we've seen this session, or if the same node is
    /// re-recording it (idempotent). Returns `Err` if a *different* node
    /// previously created the session — an affinity violation.
    pub fn record_session(&self, session_id: &[u8; 16], node_id: &str) -> Result<(), String> {
        let key = hex::encode(session_id);
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = inner.map.get(&key) {
            if existing != node_id {
                return Err(format!(
                    "SessionAffinityViolation: session {} created by node '{}' \
                     but now appearing on node '{}' — load balancer is not session-affine",
                    key, existing, node_id
                ));
            }
            // Idempotent re-record: deliberately NOT re-pushed onto `order` —
            // the FIFO eviction order tracks first-seen, and duplicating the
            // key would desync queue from map.
            return Ok(());
        }
        inner.map.insert(key.clone(), node_id.to_string());
        inner.order.push_back(key);
        if inner.map.len() > inner.max_entries {
            if let Some(oldest) = inner.order.pop_front() {
                inner.map.remove(&oldest);
            }
        }
        Ok(())
    }

    /// Check if `session_id` was created by `node_id` without recording.
    /// Returns `true` if the session is affine to this node. Unknown sessions
    /// (including FIFO-evicted ones) count as affine.
    pub fn check_affine(&self, session_id: &[u8; 16], node_id: &str) -> bool {
        let key = hex::encode(session_id);
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.map.get(&key).is_none_or(|n| n == node_id)
    }

    /// Current number of tracked sessions (bounded by the cap).
    pub fn len(&self) -> usize {
        self.inner
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .map
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl Default for SessionAffinityTracker {
    fn default() -> Self {
        Self::new()
    }
}

/// M11 hardening (Phase 3): what a daemon does when the affinity tracker
/// reports a violation.
///
/// - [`AffinityViolationPolicy::AlertOnly`] (the default) preserves today's
///   behavior byte-for-byte: the violation is logged once per connection and
///   fed to the per-IP error counter (so a persistently mis-routed peer trips
///   the existing IP circuit breaker), the packet itself is still processed.
///   Detection must not become a self-inflicted outage before the operator
///   has seen the signal.
/// - [`AffinityViolationPolicy::HardDrop`] additionally terminates the
///   connection with a hard drop (fail closed). Intended for fleets that have
///   already verified LB affinity (or run one node) and want a mis-routing to
///   be loud rather than silently replay-degrading.
///
/// The policy is a runtime configuration knob only — it never touches wire
/// format bytes. The hard drop reuses the existing `SessionSpliceDetected`
/// bytecode (same PECF external class: session terminated), so no protocol
/// surface changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AffinityViolationPolicy {
    /// Log once per connection + per-IP error counter; process the packet.
    #[default]
    AlertOnly,
    /// Additionally hard-drop the connection (fail closed).
    HardDrop,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(n: u8) -> [u8; 16] {
        let mut s = [0u8; 16];
        s[0] = n;
        s
    }

    /// M-D regression: the tracker is bounded — inserting past the cap evicts
    /// the oldest-inserted session FIFO-style, len stays at the cap, and the
    /// default constructor carries the production cap.
    #[test]
    fn tracker_is_bounded_with_fifo_eviction() {
        let t = SessionAffinityTracker::with_max_entries(4);
        for n in 0..6u8 {
            t.record_session(&sid(n), "node-1")
                .unwrap_or_else(|e| panic!("record {n} failed: {e}"));
        }
        assert_eq!(t.len(), 4, "cap must hold at max_entries");
        // FIFO order: the two oldest (sid 0, 1) must be evicted; sid 2..5 remain.
        assert!(
            t.check_affine(&sid(0), "node-1"),
            "evicted sid 0 counts as affine/unknown"
        );
        assert!(
            t.check_affine(&sid(1), "node-1"),
            "evicted sid 1 counts as affine/unknown"
        );
        for n in 2..6u8 {
            assert!(
                !t.check_affine(&sid(n), "node-2"),
                "sid {n} must still be tracked as node-1's"
            );
        }
        // A re-record of a live session must not grow the map past the cap.
        t.record_session(&sid(5), "node-1")
            .expect("idempotent re-record");
        assert_eq!(t.len(), 4, "idempotent re-record must not insert");
    }

    /// M-D regression: the production cap constant is the documented 100,000.
    #[test]
    fn default_tracker_uses_production_cap() {
        let t = SessionAffinityTracker::new();
        for n in 0..AFFINITY_MAX_ENTRIES as u32 + 1 {
            let mut s = [0u8; 16];
            s[..4].copy_from_slice(&n.to_be_bytes());
            t.record_session(&s, "node-1").expect("record");
        }
        assert_eq!(
            t.len(),
            AFFINITY_MAX_ENTRIES,
            "default tracker must stay bounded at AFFINITY_MAX_ENTRIES"
        );
    }

    /// Violation detection is unchanged by the bounding work: a foreign node
    /// re-recording a still-tracked session still errs.
    #[test]
    fn violation_detection_unchanged() {
        let t = SessionAffinityTracker::with_max_entries(4);
        t.record_session(&sid(1), "node-1").expect("first record");
        let err = t
            .record_session(&sid(1), "node-2")
            .expect_err("foreign re-record must be a violation");
        assert!(err.contains("SessionAffinityViolation"), "got: {err}");
        assert!(
            t.check_affine(&sid(9), "node-9"),
            "unknown session is affine"
        );
    }
}
