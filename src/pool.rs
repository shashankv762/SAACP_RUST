// SAACP Rust Implementation — Connection Pool
// Translated from SAACP/src/saacp/pool.py
//!
//! Pinned connection management and connection pooling for SAACP.
//!
//! * [`PinnedConnection`] tracks a single logical connection bound to
//!   an authentication token, with periodic token revalidation.
//!
//! * [`ConnectionPool`] manages reusable connections keyed by
//!   `(source_agent, target_agent)` pairs with idle-time eviction.
//!
//! The Python reference uses asyncio TCP streams; this Rust translation
//! focuses on the pool management logic (which is transport-agnostic)
//! and can be layered on top of any concrete transport (tokio, std, etc.).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ── Constants ──────────────────────────────────────────────────────────────

/// How often (seconds) the token binding must be revalidated.
pub const TOKEN_REVALIDATION_INTERVAL: f64 = 30.0;
/// Maximum connections in the pool.
pub const MAX_POOL_SIZE: usize = 100;
/// Seconds a connection may sit idle before eviction.
pub const MAX_IDLE_SECONDS: f64 = 60.0;

// ── Helpers ────────────────────────────────────────────────────────────────

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
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
    /// Epoch time at which the token was last successfully validated.
    pub last_revalidation: f64,
    /// Epoch time at which the token's revocation epoch was last checked.
    pub revocation_check_at: f64,
    /// Epoch time of the last use of this connection.
    pub last_used_at: f64,
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
        let now = now_epoch_secs();
        Self {
            source_agent,
            target_agent,
            token_fingerprint,
            last_revalidation: now,
            revocation_check_at: now,
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
        let now = now_epoch_secs();
        now - self.last_revalidation > TOKEN_REVALIDATION_INTERVAL
    }

    /// Mark the connection as revalidated.
    pub fn revalidate(&mut self) {
        let now = now_epoch_secs();
        self.last_revalidation = now;
        self.revocation_check_at = now;
        self.last_used_at = now;
    }

    /// Update the revocation check timestamp (called after MEASC epoch
    /// verification confirms the token is still valid).
    pub fn update_revocation_check(&mut self) {
        let now = now_epoch_secs();
        self.revocation_check_at = now;
        self.last_used_at = now;
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
}

struct PooledEntry {
    connection: PinnedConnection,
    idle_since: f64,
}

impl ConnectionPool {
    /// Create a new empty pool.
    pub fn new() -> Self {
        Self {
            pool: Mutex::new(HashMap::new()),
        }
    }

    /// Acquire a connection from the pool.
    ///
    /// Returns `Some(PinnedConnection)` if a healthy idle connection
    /// exists, or `None` if the caller must create a new one.
    pub fn acquire(
        &self,
        source_agent: &str,
        target_agent: &str,
    ) -> Option<PinnedConnection> {
        let mut pool = self.pool.lock().unwrap();
        let key = (source_agent.to_string(), target_agent.to_string());

        if let Some(entries) = pool.get_mut(&key) {
            while let Some(entry) = entries.pop() {
                if now_epoch_secs() - entry.idle_since > MAX_IDLE_SECONDS {
                    continue; // stale — discard
                }
                if !entry.connection.closed {
                    if entries.is_empty() {
                        pool.remove(&key);
                    }
                    return Some(entry.connection);
                }
            }
            if entries.is_empty() {
                pool.remove(&key);
            }
        }
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

        // Enforce global pool size
        let total: usize = pool.values().map(|v| v.len()).sum();
        if total >= MAX_POOL_SIZE {
            // Try to evict the oldest idle entry across all keys
            let mut oldest_key: Option<(String, String)> = None;
            let mut oldest_time: f64 = f64::MAX;
            let mut oldest_idx: usize = 0;

            for (k, entries) in pool.iter() {
                for (idx, entry) in entries.iter().enumerate() {
                    if entry.idle_since < oldest_time {
                        oldest_time = entry.idle_since;
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
            idle_since: now_epoch_secs(),
            connection,
        };
        pool.entry(key).or_default().push(entry);
        Ok(())
    }

    /// Evict all idle connections that have exceeded `MAX_IDLE_SECONDS`.
    pub fn evict_idle(&self) -> usize {
        let mut pool = self.pool.lock().unwrap();
        let now = now_epoch_secs();
        let mut evicted = 0;

        let keys: Vec<(String, String)> = pool.keys().cloned().collect();
        for key in keys {
            if let Some(entries) = pool.get_mut(&key) {
                let before = entries.len();
                entries.retain(|e| now - e.idle_since <= MAX_IDLE_SECONDS);
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
        c.last_revalidation = 0.0;
        c.revalidate();
        assert!(c.last_revalidation > 0.0);
    }

    // ── ConnectionPool ─────────────────────────────────────────────────

    #[test]
    fn test_pool_release_and_acquire() {
        let pool = ConnectionPool::new();
        let c = make_conn("a", "b");
        assert!(pool.release(c).is_ok());
        assert_eq!(pool.size(), 1);

        let acquired = pool.acquire("a", "b");
        assert!(acquired.is_some());
        assert_eq!(pool.size(), 0);
    }

    #[test]
    fn test_pool_acquire_empty() {
        let pool = ConnectionPool::new();
        assert!(pool.acquire("a", "b").is_none());
    }

    #[test]
    fn test_pool_evict_idle() {
        let pool = ConnectionPool::new();
        let mut c = make_conn("a", "b");
        // Manually set idle_since to the past
        pool.release(c).unwrap();

        // Force the idle_since to be old
        {
            let mut p = pool.pool.lock().unwrap();
            let key = ("a".to_string(), "b".to_string());
            if let Some(entries) = p.get_mut(&key) {
                for e in entries.iter_mut() {
                    e.idle_since = 0.0;
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

        // Force idle_since to past
        {
            let mut p = pool.pool.lock().unwrap();
            let key = ("a".to_string(), "b".to_string());
            if let Some(entries) = p.get_mut(&key) {
                for e in entries.iter_mut() {
                    e.idle_since = 0.0; // ancient
                }
            }
        }

        // acquire should skip stale entry
        assert!(pool.acquire("a", "b").is_none());
    }
}
