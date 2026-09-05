//! Session affinity tracking (M11 / R7 — opusreview.md).
//!
//! Detects when a session appears on a daemon node that did not create it,
//! which indicates a non-affine load balancer is silently breaking the
//! protocol's replay-protection guarantee.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Tracks which daemon node accepted each session.
///
/// M11 (R7 / opusreview.md): a non-affine load balancer in front of a SAACP
/// fleet silently degrades replay protection to per-connection. This tracker
/// records the accepting node per session_id and detects violations.
#[derive(Clone)]
pub struct SessionAffinityTracker {
    inner: Arc<Mutex<HashMap<String, String>>>,
}

impl SessionAffinityTracker {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Record that `node_id` created `session_id`. Returns `Ok(())` if this is
    /// the first time we've seen this session, or if the same node is
    /// re-recording it (idempotent). Returns `Err` if a *different* node
    /// previously created the session — an affinity violation.
    pub fn record_session(&self, session_id: &[u8; 16], node_id: &str) -> Result<(), String> {
        let key = hex::encode(session_id);
        let mut map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(existing) = map.get(&key) {
            if existing != node_id {
                return Err(format!(
                    "SessionAffinityViolation: session {} created by node '{}' \
                     but now appearing on node '{}' — load balancer is not session-affine",
                    key, existing, node_id
                ));
            }
            return Ok(());
        }
        map.insert(key, node_id.to_string());
        Ok(())
    }

    /// Check if `session_id` was created by `node_id` without recording.
    /// Returns `true` if the session is affine to this node.
    pub fn check_affine(&self, session_id: &[u8; 16], node_id: &str) -> bool {
        let key = hex::encode(session_id);
        let map = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        map.get(&key).is_none_or(|n| n == node_id)
    }

    /// Current number of tracked sessions.
    pub fn len(&self) -> usize {
        self.inner.lock().unwrap_or_else(|e| e.into_inner()).len()
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
