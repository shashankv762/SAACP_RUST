//! state_backend.rs — pluggable KV+TTL storage for horizontally-scaled SAACP.
//!
//! ## The problem
//!
//! Every SAACP security subsystem that needs shared state — `FederatedMemory`,
//! `DeadMansSwitch`, `StreamRegistry`, `CSCSLoopDetector`, and others — is a
//! process-wide singleton wrapping a `Mutex<HashMap<...>>`. That's correct and
//! fast for a single-node deployment, but it means a fleet of SAACP gateways
//! behind a load balancer each have their own private view of the world: an
//! agent flagged as compromised on node A is invisible to node B until it
//! independently observes the same behaviour. For production horizontal
//! scaling, this state needs to be shareable across a cluster.
//!
//! ## The design
//!
//! [`StateBackend`] is a single, narrow KV+TTL+counter trait — not one
//! bespoke trait per subsystem. Every EASY-tier subsystem's storage need
//! reduces to "get/set/delete a value by key, optionally with a TTL,
//! optionally atomic-increment a counter", which maps 1:1 onto Redis's
//! `GET`/`SET EX`/`DEL`/`INCRBY`/`SCAN`. Keeping the trait this thin avoids
//! baking bespoke Redis data-structure choices in before there's a second
//! real backend to validate against.
//!
//! Two implementations ship here:
//!   - [`InMemoryBackend`] — the default. A `Mutex<HashMap<...>>`, byte-for-byte
//!     equivalent in behaviour to what each subsystem already did before this
//!     module existed.
//!   - [`RedisBackend`] (behind the `redis-backend` Cargo feature) — a thin
//!     wrapper over the synchronous `redis` crate client.
//!
//! ## What is deliberately OUT of scope here
//!
//! - **MEASC's `ReplayWindow`** (measc.rs) is never backed by this trait. It
//!   is checked and mutated on *every single packet* — a 4096-bit bitmap
//!   read-modify-write done under one mutex hold — and the C-1 REPLAY-TOCTOU
//!   fix depends on that check-and-mark happening as one atomic,
//!   uninterruptible operation with zero window for a second packet to slip
//!   through between check and mark. A network round-trip inserted into that
//!   per-packet critical section would cap per-session throughput at roughly
//!   1/round-trip-latency packets/second — an order-of-magnitude regression —
//!   and would reopen exactly the TOCTOU race the fix closed unless the
//!   check-and-mark became one atomic server-side script. MEASC sessions are
//!   already pinned to whichever daemon node accepted the connection (see
//!   `daemon.rs`), so no cross-node replay visibility is actually needed for
//!   them. Keep this subsystem strictly in-process.
//! - **`AgentRateLimiter` / `RRBCGateway`** (gateway.rs) are near-per-packet
//!   hot paths too. A future `with_backend()` for these should keep the
//!   existing in-process map as the authoritative fast-path read, with only a
//!   best-effort, non-blocking write-behind to the shared backend for
//!   cross-node *visibility* (monitoring, eventual convergence) — not a
//!   synchronous dependency on every packet. That is a deliberately separate,
//!   more delicate change from the plain KV wiring done for the EASY tier in
//!   this module, and is not implemented yet: shipping a half-tested
//!   distributed cache in front of the circuit breaker or the RRBC replay
//!   registry is a worse production risk than leaving them single-node for
//!   now. RRBC replay-safety across nodes in particular cannot be provided by
//!   read-through caching at all — it needs a synchronous atomic claim
//!   (Redis `SET key val NX EX ttl`) on the redemption path specifically.
//! - **`CSCSLoopDetector`** (cscs.rs) was initially scoped as EASY-tier (its
//!   128-slot sliding window looked like a small, simple KV value), but
//!   `handler.rs`'s Gate 12.0 (`cs_detect_loop`) runs on essentially every
//!   non-exempt packet — the same per-packet frequency as Gate 0 crypto or
//!   Gate 4.0 injection scanning, confirmed by reading the actual call site
//!   rather than trusting the earlier classification. A naive `with_backend()`
//!   here (get-then-set against the shared backend on every packet) would
//!   reintroduce the same synchronous-network-round-trip-per-packet problem
//!   `ReplayWindow` is exempted from above, just with a smaller payload.
//!   Unlike `AgentRateLimiter`/`RRBCGateway`, CSCS is a heuristic anomaly
//!   detector rather than a hard security boundary (a missed cross-node
//!   oscillation is a smaller risk than a missed token replay), so a future
//!   implementation can reasonably use the same local-cache-authoritative,
//!   best-effort-backend-mirror pattern proposed for the rate limiter above —
//!   but that is, deliberately, not implemented here either, for the same
//!   reason: this module ships the storage primitive and the subsystems where
//!   wiring it is unambiguously safe, not a rushed hot-path cache.
//! - **`ImmutableAuditLog`** (security.rs) is a hash chain where entry N's
//!   `prev_hash` must equal entry N-1's `chain_hash` — concurrent multi-node
//!   appends to one chain is a consensus problem, not a KV-storage problem.
//!   The recommended production pattern is a designated **single
//!   authoritative audit node** per deployment (an operations/config
//!   decision, not a code change): other nodes may still log locally for
//!   their own operational visibility, but the tamper-evident chain of
//!   record lives on one node. Building Raft/consensus from scratch for this
//!   is out of proportion to the actual requirement.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

// ─── Error type ────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BackendError(pub String);

impl std::fmt::Display for BackendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "state backend error: {}", self.0)
    }
}

impl std::error::Error for BackendError {}

pub type BackendResult<T> = Result<T, BackendError>;

// ─── StateBackend trait ──────────────────────────────────────────────────────

/// Low-level KV + TTL + atomic-counter primitive. Each EASY-tier subsystem
/// serializes its own records under keys it owns; this trait has no idea
/// what a `FederatedMemory` context or a `StreamSession` is.
///
/// Methods are synchronous (`fn`, not `async fn`) to match the existing
/// synchronous `Mutex<HashMap<...>>` call sites in the subsystems this
/// backs, without forcing async onto code reached from non-async
/// gate-pipeline paths (`handler.rs`'s pipeline itself is sync; only the
/// outer `daemon.rs` connection loop is async).
pub trait StateBackend: Send + Sync {
    /// Fetch a value by key. Returns `Ok(None)` if absent or expired.
    fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>>;

    /// Store a value with an optional TTL (`None` = no expiry).
    fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> BackendResult<()>;

    /// Delete a key. Returns `Ok(true)` if it existed.
    fn delete(&self, key: &str) -> BackendResult<bool>;

    /// Atomically increment a counter key (creating it at 0 if absent),
    /// returning the new value.
    fn incr(&self, key: &str, by: i64) -> BackendResult<i64>;

    /// List keys matching a prefix (eviction sweeps / session enumeration).
    /// `InMemoryBackend` does a `HashMap` scan; `RedisBackend` uses `SCAN`
    /// (never `KEYS`, which blocks the whole Redis server on large keyspaces).
    fn scan_prefix(&self, prefix: &str) -> BackendResult<Vec<String>>;
}

// ─── InMemoryBackend ─────────────────────────────────────────────────────────

struct Entry {
    value: Vec<u8>,
    expires_at: Option<Instant>,
}

impl Entry {
    fn is_expired(&self) -> bool {
        self.expires_at.is_some_and(|t| Instant::now() >= t)
    }
}

/// Default backend — a process-local `Mutex<HashMap<...>>`. Behaviourally
/// equivalent to what every EASY-tier subsystem already did before
/// `with_backend()` existed; used implicitly whenever a subsystem is
/// constructed via `::new()` / `::global()` without an explicit backend.
#[derive(Default)]
pub struct InMemoryBackend {
    store: Mutex<HashMap<String, Entry>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self { store: Mutex::new(HashMap::new()) }
    }
}

impl StateBackend for InMemoryBackend {
    fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>> {
        let mut store = self.store.lock().expect("lock poisoned");
        match store.get(key) {
            Some(e) if e.is_expired() => {
                store.remove(key);
                Ok(None)
            }
            Some(e) => Ok(Some(e.value.clone())),
            None => Ok(None),
        }
    }

    fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> BackendResult<()> {
        let mut store = self.store.lock().expect("lock poisoned");
        store.insert(key.to_string(), Entry {
            value: value.to_vec(),
            expires_at: ttl.map(|d| Instant::now() + d),
        });
        Ok(())
    }

    fn delete(&self, key: &str) -> BackendResult<bool> {
        let mut store = self.store.lock().expect("lock poisoned");
        Ok(store.remove(key).is_some())
    }

    fn incr(&self, key: &str, by: i64) -> BackendResult<i64> {
        let mut store = self.store.lock().expect("lock poisoned");
        let current: i64 = match store.get(key) {
            Some(e) if !e.is_expired() => {
                std::str::from_utf8(&e.value).ok().and_then(|s| s.parse().ok()).unwrap_or(0)
            }
            _ => 0,
        };
        let next = current.saturating_add(by);
        store.insert(key.to_string(), Entry {
            value: next.to_string().into_bytes(),
            expires_at: None, // INCR-created keys don't inherit a TTL, matching Redis INCR semantics.
        });
        Ok(next)
    }

    fn scan_prefix(&self, prefix: &str) -> BackendResult<Vec<String>> {
        let mut store = self.store.lock().expect("lock poisoned");
        // Sweep expired entries opportunistically so scan results (and
        // memory usage) don't accumulate stale keys indefinitely.
        store.retain(|_, e| !e.is_expired());
        Ok(store.keys().filter(|k| k.starts_with(prefix)).cloned().collect())
    }
}

// ─── RedisBackend ─────────────────────────────────────────────────────────

/// Redis-backed implementation, behind the `redis-backend` Cargo feature.
///
/// Uses the `redis` crate's **synchronous** client API deliberately — not
/// the async client bridged via `Handle::block_on`. Calling `block_on` from
/// inside a `StateBackend` method risks deadlocking if it's ever invoked from
/// code already running inside a Tokio task (e.g. gate-pipeline work reached
/// via `tokio::task::spawn_blocking` in `daemon.rs`); the plain synchronous
/// client has no such hazard and keeps this trait's synchronous contract
/// honest.
#[cfg(feature = "redis-backend")]
pub struct RedisBackend {
    client: redis::Client,
}

#[cfg(feature = "redis-backend")]
impl RedisBackend {
    /// `redis_url` example: `"redis://127.0.0.1:6379/"`.
    pub fn new(redis_url: &str) -> BackendResult<Self> {
        let client = redis::Client::open(redis_url).map_err(|e| BackendError(e.to_string()))?;
        Ok(Self { client })
    }

    fn conn(&self) -> BackendResult<redis::Connection> {
        self.client.get_connection().map_err(|e| BackendError(e.to_string()))
    }
}

#[cfg(feature = "redis-backend")]
impl StateBackend for RedisBackend {
    fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>> {
        use redis::Commands;
        let mut conn = self.conn()?;
        conn.get(key).map_err(|e| BackendError(e.to_string()))
    }

    fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> BackendResult<()> {
        use redis::Commands;
        let mut conn = self.conn()?;
        match ttl {
            Some(d) => {
                let secs = d.as_secs().max(1); // Redis EX requires a positive integer.
                conn.set_ex(key, value, secs).map_err(|e| BackendError(e.to_string()))
            }
            None => conn.set(key, value).map_err(|e| BackendError(e.to_string())),
        }
    }

    fn delete(&self, key: &str) -> BackendResult<bool> {
        use redis::Commands;
        let mut conn = self.conn()?;
        let removed: i64 = conn.del(key).map_err(|e| BackendError(e.to_string()))?;
        Ok(removed > 0)
    }

    fn incr(&self, key: &str, by: i64) -> BackendResult<i64> {
        use redis::Commands;
        let mut conn = self.conn()?;
        conn.incr(key, by).map_err(|e| BackendError(e.to_string()))
    }

    fn scan_prefix(&self, prefix: &str) -> BackendResult<Vec<String>> {
        use redis::Commands;
        let mut conn = self.conn()?;
        let pattern = format!("{prefix}*");
        // SCAN (cursor-based, non-blocking), never KEYS (blocks the server
        // for the duration of a full-keyspace scan).
        let iter: redis::Iter<'_, String> = conn
            .scan_match(pattern)
            .map_err(|e| BackendError(e.to_string()))?;
        Ok(iter.collect())
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_missing_key_returns_none() {
        let b = InMemoryBackend::new();
        assert_eq!(b.get("nope").unwrap(), None);
    }

    #[test]
    fn set_then_get_roundtrips() {
        let b = InMemoryBackend::new();
        b.set("k", b"hello", None).unwrap();
        assert_eq!(b.get("k").unwrap(), Some(b"hello".to_vec()));
    }

    #[test]
    fn set_overwrites_existing_value() {
        let b = InMemoryBackend::new();
        b.set("k", b"v1", None).unwrap();
        b.set("k", b"v2", None).unwrap();
        assert_eq!(b.get("k").unwrap(), Some(b"v2".to_vec()));
    }

    #[test]
    fn delete_removes_key_and_reports_existed() {
        let b = InMemoryBackend::new();
        b.set("k", b"v", None).unwrap();
        assert!(b.delete("k").unwrap());
        assert_eq!(b.get("k").unwrap(), None);
    }

    #[test]
    fn delete_missing_key_reports_false() {
        let b = InMemoryBackend::new();
        assert!(!b.delete("nope").unwrap());
    }

    #[test]
    fn ttl_expiry_makes_key_disappear() {
        let b = InMemoryBackend::new();
        b.set("k", b"v", Some(Duration::from_millis(20))).unwrap();
        assert_eq!(b.get("k").unwrap(), Some(b"v".to_vec()));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.get("k").unwrap(), None);
    }

    #[test]
    fn no_ttl_never_expires() {
        let b = InMemoryBackend::new();
        b.set("k", b"v", None).unwrap();
        std::thread::sleep(Duration::from_millis(30));
        assert_eq!(b.get("k").unwrap(), Some(b"v".to_vec()));
    }

    #[test]
    fn incr_creates_key_at_zero_then_increments() {
        let b = InMemoryBackend::new();
        assert_eq!(b.incr("c", 1).unwrap(), 1);
        assert_eq!(b.incr("c", 1).unwrap(), 2);
        assert_eq!(b.incr("c", 5).unwrap(), 7);
    }

    #[test]
    fn incr_supports_negative_deltas() {
        let b = InMemoryBackend::new();
        b.incr("c", 10).unwrap();
        assert_eq!(b.incr("c", -3).unwrap(), 7);
    }

    #[test]
    fn scan_prefix_filters_correctly() {
        let b = InMemoryBackend::new();
        b.set("agent:a", b"1", None).unwrap();
        b.set("agent:b", b"2", None).unwrap();
        b.set("stream:x", b"3", None).unwrap();
        let mut keys = b.scan_prefix("agent:").unwrap();
        keys.sort();
        assert_eq!(keys, vec!["agent:a".to_string(), "agent:b".to_string()]);
    }

    #[test]
    fn scan_prefix_excludes_expired_keys() {
        let b = InMemoryBackend::new();
        b.set("agent:a", b"1", Some(Duration::from_millis(20))).unwrap();
        b.set("agent:b", b"2", None).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        let keys = b.scan_prefix("agent:").unwrap();
        assert_eq!(keys, vec!["agent:b".to_string()]);
    }

    #[test]
    fn concurrent_incr_is_atomic() {
        use std::sync::Arc;
        use std::thread;

        let b = Arc::new(InMemoryBackend::new());
        let mut handles = vec![];
        for _ in 0..8 {
            let b = Arc::clone(&b);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    b.incr("shared", 1).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(b.get("shared").unwrap(), Some(b"800".to_vec()));
    }

    #[test]
    fn backend_is_object_safe_and_send_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<InMemoryBackend>();
        let _boxed: Box<dyn StateBackend> = Box::new(InMemoryBackend::new());
    }
}
