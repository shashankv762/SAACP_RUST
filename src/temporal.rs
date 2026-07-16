//! temporal.rs — Dead Man's Switch + Temporal Heartbeat
//!
//! Tracks active agent sessions. If an agent fails to send a heartbeat ping
//! within the MAX_TIMEOUT limit, the session is terminated.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime};
use std::thread;

use serde::{Serialize, Deserialize};

use crate::state_backend::StateBackend;

/// Default max timeout before a session is considered dead (15 seconds).
pub const DEAD_MAN_MAX_TIMEOUT: f64 = 15.0;
/// OOM guard: reject registrations beyond this cap.
pub const DEAD_MAN_MAX_SESSIONS: usize = 10_000;
/// Default heartbeat interval (5 seconds).
pub const HEARTBEAT_INTERVAL_SECONDS: f64 = 5.0;
/// Maximum pings per context per window before ping-flood is declared.
/// A legitimate heartbeat fires at HEARTBEAT_INTERVAL_SECONDS = 5s → max 12/min.
/// Anything above 60/min is flood territory.
pub const DEAD_MAN_PING_FLOOD_THRESHOLD: usize = 60;
/// Window size in seconds for ping-flood counting.
pub const DEAD_MAN_PING_FLOOD_WINDOW_SECS: f64 = 60.0;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ===========================================================================
// DeadMansSwitch
// ===========================================================================

/// Tracks active agent sessions. If an agent fails to send a heartbeat ping
/// within the MAX_TIMEOUT limit, the session is terminated.
///
/// Backed by a process-local `HashMap` by default. [`DeadMansSwitch::with_backend`]
/// instead routes session/ping-flood state through a shared [`StateBackend`]
/// (e.g. Redis) so a heartbeat observed by one SAACP gateway node is visible
/// to every other node in the fleet — see `state_backend.rs` for the design.
pub struct DeadMansSwitch {
    inner: Mutex<DeadManInner>,
    max_timeout: f64,
    max_sessions: usize,
    backend: Option<Arc<dyn StateBackend>>,
}

struct PingRecord {
    /// Timestamp of the current ping-counting window start.
    window_start: f64,
    /// Number of pings in the current window.
    count: usize,
}

/// Wire format for a `PingRecord` stored in a `StateBackend`.
#[derive(Serialize, Deserialize)]
struct PingRecordWire {
    window_start: f64,
    count: usize,
}

struct DeadManInner {
    active_sessions: HashMap<Vec<u8>, f64>,
    /// Per-context ping-flood tracking: cid → PingRecord.
    ping_flood_records: HashMap<Vec<u8>, PingRecord>,
}

impl DeadMansSwitch {
    /// Create a new DeadMansSwitch with default settings.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(DeadManInner {
                active_sessions: HashMap::new(),
                ping_flood_records: HashMap::new(),
            }),
            max_timeout: DEAD_MAN_MAX_TIMEOUT,
            max_sessions: DEAD_MAN_MAX_SESSIONS,
            backend: None,
        }
    }

    /// Create with custom timeout and session cap.
    pub fn with_limits(max_timeout: f64, max_sessions: usize) -> Self {
        Self {
            inner: Mutex::new(DeadManInner {
                active_sessions: HashMap::new(),
                ping_flood_records: HashMap::new(),
            }),
            max_timeout,
            max_sessions,
            backend: None,
        }
    }

    /// Create a DeadMansSwitch backed by a shared [`StateBackend`] (e.g.
    /// Redis) instead of a process-local `HashMap`, using the default
    /// timeout/session-cap settings. See `state_backend.rs`.
    ///
    /// NOTE: `ping`'s flood-window read-then-write is not made atomic across
    /// the network round trip the way the in-process `Mutex` makes it atomic
    /// locally — two pings for the same session landing on different nodes
    /// at the same instant could both read the same window/count and both
    /// increment from it, undercounting the flood by at most the number of
    /// concurrent nodes. Heartbeats are low-frequency and per-session
    /// (a well-behaved agent has exactly one heartbeat source), so this is an
    /// acceptable, explicitly-documented trade-off rather than a correctness
    /// bug — unlike MEASC's per-packet replay window, which cannot tolerate
    /// this (see `state_backend.rs`'s module doc).
    pub fn with_backend(backend: Arc<dyn StateBackend>) -> Self {
        Self::with_backend_and_limits(DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS, backend)
    }

    /// Like [`DeadMansSwitch::with_backend`], with custom timeout/session-cap
    /// settings (mirrors [`DeadMansSwitch::with_limits`] for the local mode).
    pub fn with_backend_and_limits(max_timeout: f64, max_sessions: usize, backend: Arc<dyn StateBackend>) -> Self {
        Self {
            inner: Mutex::new(DeadManInner {
                active_sessions: HashMap::new(),
                ping_flood_records: HashMap::new(),
            }),
            max_timeout,
            max_sessions,
            backend: Some(backend),
        }
    }

    fn session_key(id: &[u8]) -> String {
        format!("dms:session:{}", hex::encode(id))
    }

    fn flood_key(id: &[u8]) -> String {
        format!("dms:flood:{}", hex::encode(id))
    }

    /// Start tracking a new session. Evicts oldest if at capacity.
    pub fn register_session(&self, context_state_id: &[u8]) {
        match &self.backend {
            Some(backend) => {
                // O(n) scan for the cap check — registration is a low-frequency,
                // non-hot-path operation (once per session lifetime, not per packet).
                let keys = backend.scan_prefix("dms:session:").unwrap_or_default();
                if keys.len() >= self.max_sessions {
                    if let Some(oldest) = keys.iter()
                        .filter_map(|k| backend.get(k).ok().flatten().map(|v| (k.clone(), v)))
                        .filter_map(|(k, v)| std::str::from_utf8(&v).ok()?.parse::<f64>().ok().map(|ts| (k, ts)))
                        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|(k, _)| k)
                    {
                        let _ = backend.delete(&oldest);
                    }
                }
                let _ = backend.set(
                    &Self::session_key(context_state_id),
                    now_secs().to_string().as_bytes(),
                    Some(Duration::from_secs_f64(self.max_timeout.max(1.0) * 2.0)),
                );
            }
            None => {
                // M-38 fix: every `self.inner.lock()` in this impl block recovers via
                // `into_inner()` on poison rather than panicking — `GLOBAL_DEAD_MANS_SWITCH`
                // is a process-wide singleton, so one poisoning panic must not cascade
                // into every other session's ping-tracking/timeout checks.
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                if inner.active_sessions.len() >= self.max_sessions {
                    // Evict the oldest session to stay under the cap
                    if let Some(oldest_key) = inner.active_sessions.iter()
                        .min_by(|a, b| a.1.partial_cmp(b.1).unwrap_or(std::cmp::Ordering::Equal))
                        .map(|(k, _)| k.clone())
                    {
                        inner.active_sessions.remove(&oldest_key);
                    }
                }
                inner.active_sessions.insert(context_state_id.to_vec(), now_secs());
            }
        }
    }

    /// Update the last_ping timestamp for the session.
    ///
    /// Returns `false` if a ping-flood is detected (> DEAD_MAN_PING_FLOOD_THRESHOLD
    /// pings within DEAD_MAN_PING_FLOOD_WINDOW_SECS). Callers should log and
    /// potentially terminate the session when this returns false.
    pub fn ping(&self, context_state_id: &[u8]) -> bool {
        let now = now_secs();
        match &self.backend {
            Some(backend) => self.ping_backend(backend, context_state_id, now),
            None => self.ping_local(context_state_id, now),
        }
    }

    fn ping_local(&self, context_state_id: &[u8], now: f64) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());

        // ── Ping-flood detection (DMS-PINGFLOOD fix) ─────────────────────────
        // A compromised context can call ping at maximum rate to stay alive forever.
        // Track pings per context per window and reject excess pings.
        let flood_rec = inner.ping_flood_records
            .entry(context_state_id.to_vec())
            .or_insert(PingRecord { window_start: now, count: 0 });

        if (now - flood_rec.window_start) > DEAD_MAN_PING_FLOOD_WINDOW_SECS {
            // Reset window
            flood_rec.window_start = now;
            flood_rec.count = 0;
        }
        flood_rec.count += 1;
        if flood_rec.count > DEAD_MAN_PING_FLOOD_THRESHOLD {
            // Flood detected — do NOT update the session timestamp so the DMS can
            // time out the context naturally. Return false to signal the caller.
            return false;
        }

        if let Some(ts) = inner.active_sessions.get_mut(context_state_id) {
            *ts = now;
        }
        true
    }

    fn ping_backend(&self, backend: &Arc<dyn StateBackend>, context_state_id: &[u8], now: f64) -> bool {
        let flood_key = Self::flood_key(context_state_id);
        let mut rec = backend.get(&flood_key).ok().flatten()
            .and_then(|b| serde_json::from_slice::<PingRecordWire>(&b).ok())
            .unwrap_or(PingRecordWire { window_start: now, count: 0 });

        if (now - rec.window_start) > DEAD_MAN_PING_FLOOD_WINDOW_SECS {
            rec.window_start = now;
            rec.count = 0;
        }
        rec.count += 1;
        let flood_detected = rec.count > DEAD_MAN_PING_FLOOD_THRESHOLD;

        if let Ok(bytes) = serde_json::to_vec(&rec) {
            let _ = backend.set(&flood_key, &bytes, Some(Duration::from_secs_f64(DEAD_MAN_PING_FLOOD_WINDOW_SECS * 2.0)));
        }

        if flood_detected {
            return false;
        }

        // Only refresh the session timestamp if the session is (still) tracked —
        // matches the local path's `get_mut` no-op-on-missing-key semantics.
        let session_key = Self::session_key(context_state_id);
        if backend.get(&session_key).ok().flatten().is_some() {
            let _ = backend.set(
                &session_key,
                now.to_string().as_bytes(),
                Some(Duration::from_secs_f64(self.max_timeout.max(1.0) * 2.0)),
            );
        }
        true
    }

    /// Remove the session from tracking.
    ///
    /// M-19 fix: the local-mode branch also removes `context_state_id`'s
    /// entry from `ping_flood_records`. That map has no TTL/expiry mechanism
    /// of its own — it is only ever pruned opportunistically inside `ping()`
    /// (see `ping_local`'s window-reset logic), which never runs again once a
    /// session stops pinging (e.g. because it was just unregistered). Without
    /// this, every session that is ever unregistered leaks one
    /// `ping_flood_records` entry permanently, growing unbounded under normal
    /// session churn. Backend mode is unaffected: its flood-key already
    /// carries its own TTL (`DEAD_MAN_PING_FLOOD_WINDOW_SECS * 2.0`, set in
    /// `ping_backend`), so it self-expires without needing an explicit
    /// delete here.
    pub fn unregister_session(&self, context_state_id: &[u8]) {
        match &self.backend {
            Some(backend) => { let _ = backend.delete(&Self::session_key(context_state_id)); }
            None => {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                inner.active_sessions.remove(context_state_id);
                inner.ping_flood_records.remove(context_state_id);
            }
        }
    }

    /// Check for timed-out sessions and remove them.
    /// Returns the list of dead session IDs.
    pub fn check_timeouts(&self) -> Vec<Vec<u8>> {
        let now = now_secs();
        match &self.backend {
            Some(backend) => {
                let keys = backend.scan_prefix("dms:session:").unwrap_or_default();
                let mut stale = Vec::new();
                for key in keys {
                    let Some(hex_id) = key.strip_prefix("dms:session:") else { continue };
                    let Ok(id) = hex::decode(hex_id) else { continue };
                    let Some(ts) = backend.get(&key).ok().flatten()
                        .and_then(|b| std::str::from_utf8(&b).ok()?.parse::<f64>().ok())
                    else { continue };
                    if (now - ts) > self.max_timeout {
                        let _ = backend.delete(&key);
                        stale.push(id);
                    }
                }
                stale
            }
            None => {
                let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
                let stale: Vec<Vec<u8>> = inner.active_sessions.iter()
                    .filter(|(_, &last_ping)| (now - last_ping) > self.max_timeout)
                    .map(|(k, _)| k.clone())
                    .collect();

                for cid in &stale {
                    inner.active_sessions.remove(cid);
                }
                stale
            }
        }
    }

    /// Return the number of active sessions.
    ///
    /// In backend mode this is a `scan_prefix` over the `dms:session:`
    /// namespace — an O(n) diagnostic operation, not a hot-path call.
    pub fn session_count(&self) -> usize {
        match &self.backend {
            Some(backend) => backend.scan_prefix("dms:session:").map(|k| k.len()).unwrap_or(0),
            None => self.inner.lock().unwrap_or_else(|e| e.into_inner()).active_sessions.len(),
        }
    }

    /// Check if a specific session is active.
    pub fn is_active(&self, context_state_id: &[u8]) -> bool {
        match &self.backend {
            Some(backend) => backend.get(&Self::session_key(context_state_id)).ok().flatten().is_some(),
            None => self.inner.lock().unwrap_or_else(|e| e.into_inner()).active_sessions.contains_key(context_state_id),
        }
    }

    /// Process-wide singleton DeadMansSwitch.
    pub fn global() -> &'static DeadMansSwitch {
        &GLOBAL_DEAD_MANS_SWITCH
    }
}

impl Default for DeadMansSwitch {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// TemporalHeartbeat
// ===========================================================================

/// Background heartbeat that periodically pings a DeadMansSwitch.
///
/// M-20 analysis (OS thread is deliberate here, not a stopgap): this type
/// spawns a dedicated `std::thread` per instance rather than a `tokio::spawn`
/// task. `TemporalHeartbeat` is public library API (exported from `lib.rs`
/// with a `TemporalHeartbeatThread` Python-parity alias) with no documented
/// requirement that a Tokio runtime be active — its own test coverage
/// (`test_heartbeat_starts_and_stops`) constructs and drives it from a plain
/// synchronous `#[test]`, not `#[tokio::test]`, and no call site anywhere in
/// this crate (`daemon.rs`, `sidecar.rs`, `command_center.rs`) references it
/// at all today. Switching to `tokio::spawn` would panic ("there is no
/// reactor running") for any synchronous caller or embedder — exactly the
/// same reasoning `maintenance.rs`'s module doc comment gives for why its own
/// coordinator thread is deliberately not built on `tokio::spawn` either. The
/// per-instance thread stack cost (2-8MB, OS-dependent) this finding flags is
/// real but bounded by however many concurrent `TemporalHeartbeat` instances
/// a caller chooses to run — if a future caller needs many concurrent
/// heartbeats from an async context specifically, that call site should
/// route through `tokio::spawn` + `tokio::time::interval` itself (or drive
/// `DeadMansSwitch::ping` from `MaintenanceCoordinator`, which already
/// consolidates several other per-subsystem background threads into one),
/// rather than this type's general-purpose, runtime-agnostic implementation
/// changing underneath every existing (synchronous) caller.
pub struct TemporalHeartbeat {
    // L-19 fix: `Condvar` paired with the stop flag lets `stop()` wake the
    // background thread immediately (`notify_one`) instead of it only
    // noticing the flag after `thread::sleep(interval)` returns on its own —
    // previously `.stop()` -> `.join()` could block the caller for up to one
    // full `interval_secs` even though the thread was idle the whole time.
    stop: Arc<(Mutex<bool>, Condvar)>,
    handle: Option<thread::JoinHandle<()>>,
}

impl TemporalHeartbeat {
    /// Start a heartbeat thread that pings the given switch at the specified interval.
    pub fn start(
        switch: Arc<DeadMansSwitch>,
        session_id: Vec<u8>,
        interval_secs: f64,
    ) -> Self {
        let stop = Arc::new((Mutex::new(false), Condvar::new()));
        let stop_clone = stop.clone();

        let handle = thread::Builder::new()
            .name("heartbeat".to_string())
            .spawn(move || {
                let interval = Duration::from_millis((interval_secs * 1000.0) as u64);
                let (lock, condvar) = &*stop_clone;
                loop {
                    let guard = match lock.lock() {
                        Ok(g) => g,
                        Err(_) => break,
                    };
                    let (stopped, _timeout_result) = match condvar.wait_timeout(guard, interval) {
                        Ok(pair) => pair,
                        Err(_) => break,
                    };
                    if *stopped {
                        break;
                    }
                    drop(stopped);
                    let _ = switch.ping(&session_id);
                }
            })
            .expect("failed to spawn heartbeat thread");

        Self {
            stop,
            handle: Some(handle),
        }
    }

    /// Start with default interval (5 seconds).
    pub fn start_default(switch: Arc<DeadMansSwitch>, session_id: Vec<u8>) -> Self {
        Self::start(switch, session_id, HEARTBEAT_INTERVAL_SECONDS)
    }

    /// Stop the heartbeat thread. Wakes it immediately via `Condvar::notify_one`
    /// rather than waiting for its current sleep window to elapse on its own.
    pub fn stop(&mut self) {
        let (lock, condvar) = &*self.stop;
        if let Ok(mut stopped) = lock.lock() {
            *stopped = true;
        }
        condvar.notify_one();
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }

    /// Check if the heartbeat thread is still running.
    pub fn is_running(&self) -> bool {
        self.handle.is_some()
    }
}

impl Drop for TemporalHeartbeat {
    fn drop(&mut self) {
        self.stop();
    }
}

// ── Process-wide singleton ──────────────────────────────────────────────────

/// Global `DeadMansSwitch` used by the gate pipeline and daemon layer.
/// Matches Python's class-level singleton semantics of `DeadMansSwitch`.
pub static GLOBAL_DEAD_MANS_SWITCH: std::sync::LazyLock<DeadMansSwitch> =
    std::sync::LazyLock::new(DeadMansSwitch::new);

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_register_and_is_active() {
        let dms = DeadMansSwitch::new();
        let sid = vec![1u8; 32];
        assert!(!dms.is_active(&sid));
        dms.register_session(&sid);
        assert!(dms.is_active(&sid));
        assert_eq!(dms.session_count(), 1);
    }

    #[test]
    fn test_ping_updates_timestamp() {
        let dms = DeadMansSwitch::new();
        let sid = vec![2u8; 32];
        dms.register_session(&sid);
        dms.ping(&sid);
        assert!(dms.is_active(&sid));
    }

    #[test]
    fn test_unregister() {
        let dms = DeadMansSwitch::new();
        let sid = vec![3u8; 32];
        dms.register_session(&sid);
        dms.unregister_session(&sid);
        assert!(!dms.is_active(&sid));
        assert_eq!(dms.session_count(), 0);
    }

    /// M-19 regression: `unregister_session` (local mode) must also clean up
    /// `ping_flood_records`, not just `active_sessions`. Before the fix, this
    /// entry would remain forever — `ping_flood_records` has no independent
    /// TTL/expiry, only opportunistic pruning inside `ping()` itself, which
    /// never runs again for an unregistered session.
    #[test]
    fn test_unregister_also_clears_ping_flood_record() {
        let dms = DeadMansSwitch::new();
        let sid = vec![6u8; 32];
        dms.register_session(&sid);
        // Ping at least once so a ping_flood_records entry actually exists.
        dms.ping(&sid);
        {
            let inner = dms.inner.lock().expect("lock poisoned");
            assert!(
                inner.ping_flood_records.contains_key(&sid),
                "test setup: a ping_flood_records entry must exist after ping()"
            );
        }

        dms.unregister_session(&sid);

        let inner = dms.inner.lock().expect("lock poisoned");
        assert!(
            !inner.ping_flood_records.contains_key(&sid),
            "M-19: ping_flood_records entry must be removed on unregister_session, \
             not leaked forever"
        );
    }

    /// M-19: repeated register -> ping -> unregister cycles for DIFFERENT
    /// session IDs must not leave `ping_flood_records` growing unbounded —
    /// proves the fix holds under session churn, not just a single instance.
    #[test]
    fn test_ping_flood_records_bounded_under_session_churn() {
        let dms = DeadMansSwitch::new();
        for i in 0..50u8 {
            let sid = vec![i; 32];
            dms.register_session(&sid);
            dms.ping(&sid);
            dms.unregister_session(&sid);
        }
        let inner = dms.inner.lock().expect("lock poisoned");
        assert_eq!(
            inner.ping_flood_records.len(),
            0,
            "M-19: ping_flood_records must not accumulate entries across \
             register/ping/unregister churn"
        );
    }

    #[test]
    fn test_check_timeouts_none_stale() {
        let dms = DeadMansSwitch::new();
        let sid = vec![4u8; 32];
        dms.register_session(&sid);
        let stale = dms.check_timeouts();
        assert!(stale.is_empty()); // Just registered, not stale
    }

    #[test]
    fn test_check_timeouts_with_expired() {
        let dms = DeadMansSwitch::with_limits(0.001, 100); // Very short timeout
        let sid = vec![5u8; 32];
        dms.register_session(&sid);
        // Sleep to exceed timeout
        thread::sleep(Duration::from_millis(10));
        let stale = dms.check_timeouts();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], sid);
        assert!(!dms.is_active(&sid)); // Removed
    }

    #[test]
    fn test_session_cap_eviction() {
        let dms = DeadMansSwitch::with_limits(1000.0, 3);
        dms.register_session(&[1u8; 32]);
        thread::sleep(Duration::from_millis(1));
        dms.register_session(&[2u8; 32]);
        thread::sleep(Duration::from_millis(1));
        dms.register_session(&[3u8; 32]);
        assert_eq!(dms.session_count(), 3);
        // Fourth should evict oldest
        thread::sleep(Duration::from_millis(1));
        dms.register_session(&[4u8; 32]);
        assert_eq!(dms.session_count(), 3);
    }

    #[test]
    fn test_heartbeat_starts_and_stops() {
        let switch = Arc::new(DeadMansSwitch::with_limits(100.0, 100));
        let sid = vec![10u8; 32];
        switch.register_session(&sid);

        let mut hb = TemporalHeartbeat::start(switch.clone(), sid.clone(), 0.05);
        assert!(hb.is_running());

        thread::sleep(Duration::from_millis(120));
        // Session should still be active due to heartbeat pings
        assert!(switch.is_active(&sid));

        hb.stop();
        assert!(!hb.is_running());
    }

    #[test]
    fn test_ping_nonexistent_session() {
        let dms = DeadMansSwitch::new();
        dms.ping(&[99u8; 32]); // Should not panic, just no-op
        assert_eq!(dms.session_count(), 0);
    }

    #[test]
    fn test_unregister_nonexistent() {
        let dms = DeadMansSwitch::new();
        dms.unregister_session(&[99u8; 32]); // Should not panic
    }

    // -- DeadMansSwitch::with_backend tests (state_backend.rs wiring) --

    fn backend_dms(max_timeout: f64, max_sessions: usize) -> DeadMansSwitch {
        use crate::state_backend::InMemoryBackend;
        DeadMansSwitch::with_backend_and_limits(max_timeout, max_sessions, Arc::new(InMemoryBackend::new()))
    }

    #[test]
    fn test_backend_register_and_is_active() {
        let dms = backend_dms(DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS);
        let sid = vec![1u8; 32];
        assert!(!dms.is_active(&sid));
        dms.register_session(&sid);
        assert!(dms.is_active(&sid));
        assert_eq!(dms.session_count(), 1);
    }

    #[test]
    fn test_backend_ping_updates_timestamp() {
        let dms = backend_dms(DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS);
        let sid = vec![2u8; 32];
        dms.register_session(&sid);
        assert!(dms.ping(&sid));
        assert!(dms.is_active(&sid));
    }

    #[test]
    fn test_backend_unregister() {
        let dms = backend_dms(DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS);
        let sid = vec![3u8; 32];
        dms.register_session(&sid);
        dms.unregister_session(&sid);
        assert!(!dms.is_active(&sid));
        assert_eq!(dms.session_count(), 0);
    }

    #[test]
    fn test_backend_check_timeouts_with_expired() {
        let dms = backend_dms(0.001, 100); // Very short timeout
        let sid = vec![5u8; 32];
        dms.register_session(&sid);
        thread::sleep(Duration::from_millis(10));
        let stale = dms.check_timeouts();
        assert_eq!(stale.len(), 1);
        assert_eq!(stale[0], sid);
        assert!(!dms.is_active(&sid)); // Removed
    }

    #[test]
    fn test_backend_session_cap_eviction() {
        let dms = backend_dms(1000.0, 3);
        dms.register_session(&[1u8; 32]);
        thread::sleep(Duration::from_millis(1));
        dms.register_session(&[2u8; 32]);
        thread::sleep(Duration::from_millis(1));
        dms.register_session(&[3u8; 32]);
        assert_eq!(dms.session_count(), 3);
        thread::sleep(Duration::from_millis(1));
        dms.register_session(&[4u8; 32]);
        assert_eq!(dms.session_count(), 3);
    }

    #[test]
    fn test_backend_ping_flood_detected() {
        let dms = backend_dms(DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS);
        let sid = vec![7u8; 32];
        dms.register_session(&sid);
        for _ in 0..DEAD_MAN_PING_FLOOD_THRESHOLD {
            assert!(dms.ping(&sid));
        }
        // One more within the same window should trip the flood guard.
        assert!(!dms.ping(&sid));
    }

    #[test]
    fn test_backend_and_local_instances_are_independent() {
        let local = DeadMansSwitch::new();
        let backend = backend_dms(DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS);
        let sid = vec![9u8; 32];
        local.register_session(&sid);
        assert!(local.is_active(&sid));
        assert!(!backend.is_active(&sid));
    }
}
