// SAACP Rust Implementation — Connection Pool
// Translated from SAACP/src/saacp/pool.py
//!
//! Pinned connection management and connection pooling for SAACP.
//!
//! * [`PinnedConnection`] tracks a single logical connection bound to
//!   an authentication token, with periodic token revalidation.
//!
//! * [`ConnectionPool`] manages reusable connections keyed by
//!   `(source_agent, target_agent)` pairs with idle-time eviction and a
//!   self-adjusting capacity target (see [`ConnectionPool::tune`]).
//!
//! The Python reference uses asyncio TCP streams; this Rust translation
//! focuses on the pool management logic (which is transport-agnostic)
//! and can be layered on top of any concrete transport (tokio, std, etc.).
//!
//! Internal elapsed-time tracking (idle duration, revalidation interval) uses
//! [`Instant`], which is monotonic and immune to wall-clock (NTP) adjustments —
//! a backward `SystemTime` step can no longer make a connection appear
//! artificially fresh, nor a forward step make it appear artificially stale
//! (Phase 7 / item 5 / L-17). `revocation_check_at` is the one exception: it is
//! compared against an externally supplied revocation-epoch value and so must
//! stay wall-clock-comparable — see [`PinnedConnection::is_pinned`].

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use crate::errors::SAACPHardDrop;

// ── Constants ──────────────────────────────────────────────────────────────

/// How often (seconds) the token binding must be revalidated.
pub const TOKEN_REVALIDATION_INTERVAL: f64 = 30.0;
/// Maximum connections in the pool (hard ceiling — [`ConnectionPool::tune`] never
/// grows `target_size` past this).
pub const MAX_POOL_SIZE: usize = 100;
/// Minimum connections the pool auto-tunes down to (floor — [`ConnectionPool::tune`]
/// never shrinks `target_size` below this).
pub const MIN_POOL_SIZE: usize = 10;
/// Seconds a connection may sit idle before eviction.
pub const MAX_IDLE_SECONDS: f64 = 60.0;

/// Step size (connections) by which [`ConnectionPool::tune`] grows or shrinks
/// `target_size` per call.
const POOL_TUNE_STEP: usize = 10;
/// Above this acquire() miss rate, with the pool near full, `tune()` grows `target_size`.
const POOL_TUNE_MISS_RATE_GROW: f64 = 0.5;
/// Below this acquire() miss rate, with the pool well under half full, `tune()` shrinks
/// `target_size`. Between the shrink and grow thresholds is a hysteresis dead zone where
/// `tune()` leaves `target_size` unchanged, so it doesn't oscillate every call.
const POOL_TUNE_MISS_RATE_SHRINK: f64 = 0.1;

// ── Helpers ────────────────────────────────────────────────────────────────

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// An `Instant` in the past, used by tests to simulate an old timestamp without
/// relying on wall-clock manipulation.
///
/// `Instant` is monotonic and anchored to a platform-defined origin (process start,
/// system boot, or an opaque counter depending on the OS). Subtracting a duration that
/// reaches before that origin is not representable, so `checked_sub` returns `None`.
/// On Windows in particular the origin can be recent enough that a large fixed offset
/// (e.g. 9999s) underflows even on a long-lived process. Collapsing to `Instant::now()`
/// on underflow — as an earlier version did — produced a *fresh* instant, silently
/// defeating every staleness assertion. Instead we saturate: halve the offset until the
/// subtraction is representable, yielding the oldest instant this platform can express.
/// The test suite itself runs for far longer than any staleness threshold
/// (`TOKEN_REVALIDATION_INTERVAL` = 30s, `MAX_IDLE_SECONDS` = 60s), so the saturated
/// offset always comfortably exceeds them.
#[cfg(test)]
fn instant_secs_ago(secs: u64) -> Instant {
    let now = Instant::now();
    let mut d = Duration::from_secs(secs);
    loop {
        if let Some(i) = now.checked_sub(d) {
            return i;
        }
        if d.is_zero() {
            return now;
        }
        d /= 2;
    }
}

// ── PinnedConnection ───────────────────────────────────────────────────────

/// A single pinned connection between two agents, bound to a token.
pub struct PinnedConnection {
    /// Source agent identifier.
    pub source_agent: String,
    /// Target agent identifier.
    pub target_agent: String,
    /// Hex-encoded token fingerprint (or kid) used for authentication.
    pub token_fingerprint: String,
    /// Monotonic instant at which the token was last successfully revalidated.
    pub last_revalidation: Instant,
    /// Epoch time at which the token's revocation epoch was last checked. Wall-clock
    /// (not `Instant`) by design — compared against an externally supplied revocation
    /// epoch in [`Self::is_pinned`], which requires a comparable, non-monotonic timeline.
    pub revocation_check_at: f64,
    /// Monotonic instant of the last use of this connection.
    pub last_used_at: Instant,
    /// Whether the connection has been closed.
    pub closed: bool,
}

impl PinnedConnection {
    /// Create a new pinned connection.
    pub fn new(
        source_agent: String,
        target_agent: String,
        token_fingerprint: String,
    ) -> Self {
        let now = Instant::now();
        Self {
            source_agent,
            target_agent,
            token_fingerprint,
            last_revalidation: now,
            revocation_check_at: now_epoch_secs(),
            last_used_at: now,
            closed: false,
        }
    }

    /// Check whether the connection is still pinned (i.e. the token
    /// has not been revoked or expired since the last revalidation).
    ///
    /// `revocation_epoch` is the current global revocation epoch
    /// from MEASC.  If the connection's `revocation_check_at` is
    /// older than the revocation epoch the token must be re-validated.
    pub fn is_pinned(&self, revocation_epoch: f64) -> bool {
        if self.closed {
            return false;
        }
        // If the revocation epoch has advanced past our last check,
        // the token may have been revoked.
        self.revocation_check_at >= revocation_epoch
    }

    /// Whether the token needs revalidation based on time interval.
    pub fn needs_revalidation(&self) -> bool {
        self.last_revalidation.elapsed().as_secs_f64() > TOKEN_REVALIDATION_INTERVAL
    }

    /// Mark the connection as revalidated.
    pub fn revalidate(&mut self) {
        let now = Instant::now();
        self.last_revalidation = now;
        self.revocation_check_at = now_epoch_secs();
        self.last_used_at = now;
    }

    /// Update the revocation check timestamp (called after MEASC epoch
    /// verification confirms the token is still valid).
    pub fn update_revocation_check(&mut self) {
        self.revocation_check_at = now_epoch_secs();
        self.last_used_at = Instant::now();
    }

    /// Close the connection.
    pub fn close(&mut self) {
        self.closed = true;
    }
}

// ── ConnectionPool ─────────────────────────────────────────────────────────

/// A pool of reusable [`PinnedConnection`]s keyed by `(source, target)`.
pub struct ConnectionPool {
    pool: Mutex<HashMap<(String, String), Vec<PooledEntry>>>,
    /// Current effective capacity, auto-tuned by [`Self::tune`] within
    /// `[MIN_POOL_SIZE, MAX_POOL_SIZE]`. Defaults to `MAX_POOL_SIZE`, so a pool that
    /// never calls `tune()` behaves exactly as it did before auto-tuning existed.
    target_size: AtomicUsize,
    /// `acquire()` calls since the last `tune()` that returned a reusable connection.
    hits: AtomicU64,
    /// `acquire()` calls since the last `tune()` that found nothing reusable.
    misses: AtomicU64,
}

struct PooledEntry {
    connection: PinnedConnection,
    idle_since: Instant,
}

impl ConnectionPool {
    /// Create a new empty pool.
    pub fn new() -> Self {
        Self {
            pool: Mutex::new(HashMap::new()),
            target_size: AtomicUsize::new(MAX_POOL_SIZE),
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
        }
    }

    /// Acquire a connection from the pool.
    ///
    /// Returns `Some(PinnedConnection)` if a healthy idle connection
    /// exists, or `None` if the caller must create a new one.
    ///
    /// SECURITY: a reused connection is only handed back if it is still
    /// authenticated. `revocation_epoch` is the current global revocation epoch
    /// (from MEASC): a connection whose token was last revocation-checked before
    /// that epoch, or whose time-based revalidation interval
    /// ([`TOKEN_REVALIDATION_INTERVAL`]) has elapsed, is discarded rather than
    /// returned — otherwise a token revoked while its connection sat idle
    /// (under `MAX_IDLE_SECONDS`) would be handed back as still-authenticated.
    /// This pool is bookkeeping-only (no live socket), so it cannot itself
    /// re-verify a token; the correct fail-closed behavior is to drop the
    /// connection and force the caller to establish a freshly authenticated one.
    pub fn acquire(
        &self,
        source_agent: &str,
        target_agent: &str,
        revocation_epoch: f64,
    ) -> Option<PinnedConnection> {
        let mut pool = self.pool.lock().unwrap();
        let key = (source_agent.to_string(), target_agent.to_string());

        if let Some(entries) = pool.get_mut(&key) {
            while let Some(entry) = entries.pop() {
                if entry.idle_since.elapsed().as_secs_f64() > MAX_IDLE_SECONDS {
                    continue; // stale — discard
                }
                if entry.connection.closed {
                    continue; // closed — discard
                }
                // Fail-closed authentication checks: revoked-epoch or stale
                // revalidation interval → discard, don't reuse.
                if !entry.connection.is_pinned(revocation_epoch)
                    || entry.connection.needs_revalidation()
                {
                    continue;
                }
                if entries.is_empty() {
                    pool.remove(&key);
                }
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(entry.connection);
            }
            if entries.is_empty() {
                pool.remove(&key);
            }
        }
        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Release a connection back into the pool.
    ///
    /// If the pool is at capacity the connection with the longest idle
    /// time is evicted.
    pub fn release(&self, connection: PinnedConnection) -> Result<(), SAACPHardDrop> {
        let mut pool = self.pool.lock().unwrap();
        let key = (
            connection.source_agent.clone(),
            connection.target_agent.clone(),
        );

        // Enforce current auto-tuned capacity (defaults to MAX_POOL_SIZE — see `tune()`).
        let target = self.target_size.load(Ordering::Relaxed);
        let total: usize = pool.values().map(|v| v.len()).sum();
        if total >= target {
            // Evict the entry that has been idle longest across all keys.
            let mut oldest_key: Option<(String, String)> = None;
            let mut oldest_idx: usize = 0;
            let mut oldest_elapsed = Duration::from_secs(0);
            let mut found = false;

            for (k, entries) in pool.iter() {
                for (idx, entry) in entries.iter().enumerate() {
                    let elapsed = entry.idle_since.elapsed();
                    if !found || elapsed > oldest_elapsed {
                        found = true;
                        oldest_elapsed = elapsed;
                        oldest_key = Some(k.clone());
                        oldest_idx = idx;
                    }
                }
            }

            if let Some(okey) = oldest_key {
                if let Some(entries) = pool.get_mut(&okey) {
                    entries.remove(oldest_idx);
                    if entries.is_empty() {
                        pool.remove(&okey);
                    }
                }
            }
        }

        let entry = PooledEntry {
            idle_since: Instant::now(),
            connection,
        };
        pool.entry(key).or_default().push(entry);
        Ok(())
    }

    /// Evict all idle connections that have exceeded `MAX_IDLE_SECONDS`.
    pub fn evict_idle(&self) -> usize {
        let mut pool = self.pool.lock().unwrap();
        let mut evicted = 0;

        let keys: Vec<(String, String)> = pool.keys().cloned().collect();
        for key in keys {
            if let Some(entries) = pool.get_mut(&key) {
                let before = entries.len();
                entries.retain(|e| e.idle_since.elapsed().as_secs_f64() <= MAX_IDLE_SECONDS);
                evicted += before - entries.len();
                if entries.is_empty() {
                    pool.remove(&key);
                }
            }
        }
        evicted
    }

    /// Total number of connections currently in the pool.
    pub fn size(&self) -> usize {
        self.pool.lock().unwrap().values().map(|v| v.len()).sum()
    }

    /// Remove and close all connections for a specific agent pair.
    pub fn purge(&self, source_agent: &str, target_agent: &str) -> usize {
        let mut pool = self.pool.lock().unwrap();
        let key = (source_agent.to_string(), target_agent.to_string());
        if let Some(entries) = pool.remove(&key) {
            entries.len()
        } else {
            0
        }
    }

    /// Current auto-tuned capacity target (see [`Self::tune`]). Always within
    /// `[MIN_POOL_SIZE, MAX_POOL_SIZE]`; defaults to `MAX_POOL_SIZE`.
    pub fn target_size(&self) -> usize {
        self.target_size.load(Ordering::Relaxed)
    }

    /// Phase 7 / item 6: adjust `target_size` based on `acquire()` hit/miss pressure
    /// observed since the last call, bounded to `[MIN_POOL_SIZE, MAX_POOL_SIZE]`.
    ///
    /// Intended to be called periodically (e.g. every 60s from a maintenance sweep,
    /// see `maintenance::MaintenanceCoordinator`) rather than after every request. A call
    /// with no `acquire()` traffic since the previous call is a no-op — there is no signal
    /// to act on. Deliberately simple (fixed step, two thresholds with a hysteresis dead
    /// zone) rather than a PID controller, so its behavior stays auditable:
    ///
    /// * grow by `POOL_TUNE_STEP` when misses dominate (demand exceeds what's cached)
    ///   AND the pool is already at least ~90% of `target_size` (there's no spare
    ///   capacity left to explain the misses away as something else);
    /// * shrink by `POOL_TUNE_STEP` when hits dominate (reuse is healthy) AND actual
    ///   occupancy is under half of `target_size` (the extra headroom is unused);
    /// * otherwise leave `target_size` unchanged.
    pub fn tune(&self) {
        let hits = self.hits.swap(0, Ordering::Relaxed);
        let misses = self.misses.swap(0, Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            return;
        }

        let miss_rate = misses as f64 / total as f64;
        let current_size = self.size();
        let target = self.target_size.load(Ordering::Relaxed);

        if miss_rate > POOL_TUNE_MISS_RATE_GROW && current_size * 10 >= target * 9 {
            let new_target = (target + POOL_TUNE_STEP).min(MAX_POOL_SIZE);
            self.target_size.store(new_target, Ordering::Relaxed);
        } else if miss_rate < POOL_TUNE_MISS_RATE_SHRINK && current_size * 2 < target {
            let new_target = target.saturating_sub(POOL_TUNE_STEP).max(MIN_POOL_SIZE);
            self.target_size.store(new_target, Ordering::Relaxed);
        }
    }
}

impl Default for ConnectionPool {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_conn(src: &str, tgt: &str) -> PinnedConnection {
        PinnedConnection::new(src.into(), tgt.into(), "tok-fp-001".into())
    }

    // ── PinnedConnection ───────────────────────────────────────────────

    #[test]
    fn test_pinned_connection_new() {
        let c = make_conn("a", "b");
        assert!(!c.closed);
        assert_eq!(c.source_agent, "a");
        assert_eq!(c.target_agent, "b");
    }

    #[test]
    fn test_is_pinned_no_revocation() {
        let c = make_conn("a", "b");
        // revocation_epoch == 0, revocation_check_at is now → pinned
        assert!(c.is_pinned(0.0));
    }

    #[test]
    fn test_is_pinned_after_revocation() {
        let mut c = make_conn("a", "b");
        c.revocation_check_at = 100.0;
        // revocation_epoch advanced past our check → not pinned
        assert!(!c.is_pinned(200.0));
    }

    #[test]
    fn test_is_pinned_closed() {
        let mut c = make_conn("a", "b");
        c.close();
        assert!(!c.is_pinned(0.0));
    }

    #[test]
    fn test_revalidate() {
        let mut c = make_conn("a", "b");
        c.last_revalidation = instant_secs_ago(9999);
        c.revalidate();
        assert!(c.last_revalidation.elapsed().as_secs_f64() < 1.0);
    }

    #[test]
    fn test_needs_revalidation_uses_monotonic_clock() {
        let mut c = make_conn("a", "b");
        assert!(!c.needs_revalidation());
        c.last_revalidation = instant_secs_ago(9999);
        assert!(c.needs_revalidation());
    }

    // ── ConnectionPool ─────────────────────────────────────────────────

    #[test]
    fn test_pool_release_and_acquire() {
        let pool = ConnectionPool::new();
        let c = make_conn("a", "b");
        assert!(pool.release(c).is_ok());
        assert_eq!(pool.size(), 1);

        let acquired = pool.acquire("a", "b", 0.0);
        assert!(acquired.is_some());
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_pool_acquire_empty() {
        let pool = ConnectionPool::new();
        assert!(pool.acquire("a", "b", 0.0).is_none());
    }

    #[test]
    fn test_pool_evict_idle() {
        let pool = ConnectionPool::new();
        let c = make_conn("a", "b");
        pool.release(c).unwrap();

        // Force idle_since to be old.
        {
            let mut p = pool.pool.lock().unwrap();
            let key = ("a".to_string(), "b".to_string());
            if let Some(entries) = p.get_mut(&key) {
                for e in entries.iter_mut() {
                    e.idle_since = instant_secs_ago(9999);
                }
            }
        }

        let evicted = pool.evict_idle();
        assert_eq!(evicted, 1);
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_pool_purge() {
        let pool = ConnectionPool::new();
        pool.release(make_conn("a", "b")).unwrap();
        pool.release(make_conn("a", "b")).unwrap();
        pool.release(make_conn("c", "d")).unwrap();

        let purged = pool.purge("a", "b");
        assert_eq!(purged, 2);
        assert_eq!(pool.size(), 1); // only c→d remains
    }

    #[test]
    fn test_pool_max_size_eviction() {
        let pool = ConnectionPool::new();
        for i in 0..MAX_POOL_SIZE {
            let c = make_conn(&format!("s{}", i), &format!("t{}", i));
            pool.release(c).unwrap();
        }
        assert_eq!(pool.size(), MAX_POOL_SIZE);

        // Adding one more should evict the oldest
        let c = make_conn("overflow-s", "overflow-t");
        pool.release(c).unwrap();
        assert_eq!(pool.size(), MAX_POOL_SIZE); // stays at cap
    }

    #[test]
    fn test_pool_acquire_skips_stale() {
        let pool = ConnectionPool::new();
        pool.release(make_conn("a", "b")).unwrap();

        // Force idle_since to the ancient past.
        {
            let mut p = pool.pool.lock().unwrap();
            let key = ("a".to_string(), "b".to_string());
            if let Some(entries) = p.get_mut(&key) {
                for e in entries.iter_mut() {
                    e.idle_since = instant_secs_ago(9999);
                }
            }
        }

        // acquire should skip stale entry
        assert!(pool.acquire("a", "b", 0.0).is_none());
    }

    /// SECURITY regression: a connection whose token was last revocation-checked
    /// before the current revocation epoch must NOT be reused — even though it is
    /// otherwise idle-fresh and open. Before the fix, `acquire` ignored the
    /// revocation epoch entirely and handed such a connection back as authenticated.
    #[test]
    fn test_pool_acquire_discards_revoked_epoch_connection() {
        let pool = ConnectionPool::new();
        let mut c = make_conn("a", "b");
        // Simulate: token last checked at epoch 100.
        c.revocation_check_at = 100.0;
        pool.release(c).unwrap();

        // Revocation epoch has since advanced to 200 → connection is stale-auth.
        assert!(
            pool.acquire("a", "b", 200.0).is_none(),
            "a connection checked before the current revocation epoch must be discarded"
        );
        // And the pool no longer holds it.
        assert_eq!(pool.size(), 0);
    }

    /// SECURITY regression: a connection past its time-based revalidation
    /// interval must not be reused, since its token binding is stale.
    #[test]
    fn test_pool_acquire_discards_connection_needing_revalidation() {
        let pool = ConnectionPool::new();
        let mut c = make_conn("a", "b");
        // Last revalidated long ago → needs_revalidation() is true.
        c.last_revalidation = instant_secs_ago(9999);
        pool.release(c).unwrap();

        assert!(
            pool.acquire("a", "b", 0.0).is_none(),
            "a connection past its revalidation interval must be discarded"
        );
        assert_eq!(pool.size(), 0);
    }

    // ── ConnectionPool::tune (Phase 7 / item 6) ─────────────────────────

    #[test]
    fn test_pool_target_size_defaults_and_tune_is_noop_without_traffic() {
        let pool = ConnectionPool::new();
        assert_eq!(pool.target_size(), MAX_POOL_SIZE);
        pool.tune();
        assert_eq!(pool.target_size(), MAX_POOL_SIZE);
    }

    #[test]
    fn test_pool_tune_grows_target_on_high_miss_rate_near_capacity() {
        let pool = ConnectionPool::new();
        pool.target_size.store(20, Ordering::Relaxed);

        // Fill to 90% of the (shrunk) target so the pool reads as "nearly full".
        for i in 0..18 {
            pool.release(make_conn(&format!("s{}", i), &format!("t{}", i))).unwrap();
        }
        // Drive a high miss rate against keys that were never released.
        for i in 0..10 {
            assert!(pool.acquire(&format!("miss{}", i), "x", 0.0).is_none());
        }

        pool.tune();
        assert!(pool.target_size() > 20, "expected growth, got {}", pool.target_size());
        assert!(pool.target_size() <= MAX_POOL_SIZE);
    }

    #[test]
    fn test_pool_tune_shrinks_target_when_mostly_idle_and_healthy() {
        let pool = ConnectionPool::new();
        pool.target_size.store(40, Ordering::Relaxed);

        // Only ever one connection alive (well under half of target) and every
        // acquire() call is a hit — low miss rate.
        pool.release(make_conn("a", "b")).unwrap();
        for _ in 0..10 {
            let c = pool.acquire("a", "b", 0.0).unwrap();
            pool.release(c).unwrap();
        }

        pool.tune();
        assert!(pool.target_size() < 40, "expected shrink, got {}", pool.target_size());
        assert!(pool.target_size() >= MIN_POOL_SIZE);
    }

    #[test]
    fn test_pool_tune_never_exceeds_bounds() {
        let pool = ConnectionPool::new();

        // Already at ceiling: growth pressure must not push past MAX_POOL_SIZE.
        pool.target_size.store(MAX_POOL_SIZE, Ordering::Relaxed);
        for i in 0..MAX_POOL_SIZE {
            pool.release(make_conn(&format!("s{}", i), &format!("t{}", i))).unwrap();
        }
        for i in 0..5 {
            assert!(pool.acquire(&format!("miss{}", i), "x", 0.0).is_none());
        }
        pool.tune();
        assert_eq!(pool.target_size(), MAX_POOL_SIZE);

        // Already at floor: shrink pressure must not push below MIN_POOL_SIZE.
        let pool2 = ConnectionPool::new();
        pool2.target_size.store(MIN_POOL_SIZE, Ordering::Relaxed);
        pool2.release(make_conn("a", "b")).unwrap();
        for _ in 0..10 {
            let c = pool2.acquire("a", "b", 0.0).unwrap();
            pool2.release(c).unwrap();
        }
        pool2.tune();
        assert_eq!(pool2.target_size(), MIN_POOL_SIZE);
    }
}
