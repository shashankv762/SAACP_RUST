use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, LazyLock};
use sha2::{Sha256, Digest};
use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::aegf::{AEGFMetadata, DistributedExecutionGraph};

pub const CSCS_MAX_OSCILLATION_COUNT: usize = 3;
pub const CSCS_WINDOW_SIZE: usize = 128;
/// Maximum distinct session_ids tracked by the outer history map before a
/// least-recently-seen sweep runs. IoT / low-resource fix: each per-session
/// window was already capped at `CSCS_WINDOW_SIZE`, but the outer
/// `HashMap<session_id, _>` itself had no cap — long-running deployments with
/// many short-lived sessions accumulated one permanent entry per session_id
/// ever seen. Mirrors `streaming::StreamRegistry`'s oldest-first eviction.
pub const CSCS_MAX_TRACKED_SESSIONS: usize = 50_000;

#[derive(Clone, Debug)]
pub struct OscillationRecord {
    pub hash: String,
    pub count: usize,
    pub timestamp: f64,
}

/// A session's fingerprint window plus the last time it was touched, so the
/// outer map can evict least-recently-seen sessions instead of growing forever.
struct SessionHistory {
    window: VecDeque<String>,
    last_seen: f64,
}

pub struct OscillationFingerprinter {
    /// Maps session ID -> limited sliding window of recent metadata hashes
    /// (plus a last-seen timestamp used only for outer-map eviction).
    history: Mutex<HashMap<String, SessionHistory>>,
}

impl Default for OscillationFingerprinter {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

impl OscillationFingerprinter {
    pub fn new() -> Self {
        Self {
            history: Mutex::new(HashMap::new()),
        }
    }

    /// Hashes stable causal identity (oaid+cid+action_class) to detect oscillation.
    ///
    /// SECURITY: `rid` is intentionally excluded — it is unique per request and would
    /// make every fingerprint unique, defeating detection. `hc` is also excluded:
    /// an attacker who controls hop count can increment it each step, producing a new
    /// fingerprint per iteration and rendering the sliding-window count permanently < 3.
    /// Depth-escalation is already bounded by AEGFMetadata::derive's MAX_HC check.
    /// The stable causal anchor is: who (oaid) + in what conversation (cid) + what (action_class).
    pub fn compute_fingerprint(
        meta: &AEGFMetadata,
        action_class: u8,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(meta.oaid.as_bytes());  // agent identity — stable across a cascade
        hasher.update(meta.cid.as_bytes());   // conversation context — stable within a session
        hasher.update([action_class]);        // what action is being requested
        // hc excluded: attacker-controlled hop count would defeat detection by making
        // each step in a cascade appear as a distinct fingerprint.
        hex::encode(hasher.finalize())
    }

    /// Records the fingerprint and returns the count of times it has been seen in the current window.
    pub fn record_and_count(&self, session_id: &str, fingerprint: &str) -> usize {
        let mut hist = self.history.lock().unwrap();
        let now = now_secs();

        // IoT / low-resource fix: sweep the least-recently-seen sessions once the
        // outer map exceeds its cap, so the process can't accumulate one entry per
        // session_id ever seen. Only triggers when actually over cap — active
        // fleets under the limit never pay this cost.
        if hist.len() >= CSCS_MAX_TRACKED_SESSIONS && !hist.contains_key(session_id) {
            let evict_count = hist.len() + 1 - CSCS_MAX_TRACKED_SESSIONS;
            let mut by_age: Vec<(String, f64)> = hist.iter()
                .map(|(k, v)| (k.clone(), v.last_seen))
                .collect();
            by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (k, _) in by_age.into_iter().take(evict_count) {
                hist.remove(&k);
            }
        }

        let entry = hist.entry(session_id.to_string()).or_insert_with(|| SessionHistory {
            window: VecDeque::new(),
            last_seen: now,
        });
        entry.last_seen = now;

        if entry.window.len() >= CSCS_WINDOW_SIZE {
            entry.window.pop_front();
        }
        entry.window.push_back(fingerprint.to_string());

        entry.window.iter().filter(|&h| h == fingerprint).count()
    }

    pub fn clear(&self, session_id: &str) {
        self.history.lock().unwrap().remove(session_id);
    }
}

pub struct CSCSLoopDetector {
    fingerprinter: OscillationFingerprinter,
    daeg: Arc<DistributedExecutionGraph>,
}

impl CSCSLoopDetector {
    pub fn new(daeg: Arc<DistributedExecutionGraph>) -> Self {
        Self {
            fingerprinter: OscillationFingerprinter::new(),
            daeg,
        }
    }

    /// Gate 12.0 core logic: detect infinite cascades
    pub fn cs_detect_loop(
        &self,
        session_id: &str,
        meta: &AEGFMetadata,
        action_class: u8,
    ) -> Result<(), SAACPHardDrop> {
        // 1. Oscillation Fingerprinting
        let fp = OscillationFingerprinter::compute_fingerprint(meta, action_class);
        let count = self.fingerprinter.record_and_count(session_id, &fp);

        if count >= CSCS_MAX_OSCILLATION_COUNT {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!(
                    "CSCS Oscillation detected for session {}. Fingerprint repeated {} times.",
                    session_id, count
                ),
            ));
        }

        // 2. DAEG DFS Loop Detection (rid chain)
        if self.daeg.detect_cycle(&meta.rid) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!("CSCS DAEG Cycle detected for rid {}.", meta.rid),
            ));
        }

        Ok(())
    }
}

impl Default for CSCSLoopDetector {
    fn default() -> Self {
        Self::new(Arc::new(DistributedExecutionGraph::new()))
    }
}

pub static GLOBAL_CSCS: LazyLock<CSCSLoopDetector> = LazyLock::new(|| CSCSLoopDetector::new(crate::aegf::GLOBAL_DAEG.clone()));

