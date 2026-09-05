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
