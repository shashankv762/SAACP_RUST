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
//! - **`AgentRateLimiter`** (gateway.rs) is a near-per-packet hot path
//!   (`is_locked` runs on every packet, before Gate 0 decryption). It is now
//!   wired via `AgentRateLimiter::with_backend()`: the in-process map stays
//!   the authoritative fast-path read for `is_locked` (zero network calls,
//!   ever, in any configuration), while `record_error` — the rare error path,
//!   not the hot path — uses `incr_with_ttl` (below) to atomically bump a
//!   shared fleet-wide error counter and, on trip, a shared lockout marker.
//!   A small background poller mirrors any fleet-wide lockout into the local
//!   map on a bounded interval (default 2s), so a node that hasn't personally
//!   seen an agent's bad traffic still learns of a lockout tripped elsewhere
//!   within that bound. A backend error on the write path fails *safe*, not
//!   open: `record_error` falls back to the original local-only algorithm for
//!   that call rather than either silently disabling the breaker or blocking
//!   the gate pipeline on a hung connection (bounded by `RedisBackend`'s
//!   connect timeout, see below). `record_cover_traffic` deliberately stays
//!   node-local even with a backend configured — its window is an order of
//!   magnitude higher-frequency than `record_error`'s and its consequence is
//!   lower-severity (traffic shaping, not a compromise signal); the same
//!   `incr_with_ttl` primitive is available to extend this later if a real
//!   incident demonstrates the need. `RRBCGateway`'s replay registry remains
//!   entirely out of scope here — it has no production call site in
//!   `handler.rs` today (confirmed by grep), and its replay-safety semantics
//!   would need a true atomic claim, not the write-behind pattern used above.
//! - **`CSCSLoopDetector`** (cscs.rs): `cs_detect_loop` runs on essentially
//!   every non-exempt packet — the same per-packet frequency as Gate 0 crypto
//!   or Gate 4.0 injection scanning — so it does **not** get the same
//!   synchronous atomic treatment as the rate limiter above; a naive
//!   get-then-set against a shared backend on every packet would reintroduce
//!   the same synchronous-network-round-trip-per-packet problem `ReplayWindow`
//!   is exempted from below. CSCS is also a heuristic anomaly detector rather
//!   than a hard security boundary (a missed cross-node oscillation is a
//!   smaller risk than a missed token replay). `CSCSLoopDetector::with_backend()`
//!   therefore only mirrors the rare **trip** event (never the per-packet
//!   fingerprint recording) to the backend, via a non-blocking bounded
//!   channel — zero cost on the common path, best-effort forensic/dashboard
//!   visibility only, never consulted by `cs_detect_loop`'s own decision. A
//!   session bouncing between two nodes that each individually stay under
//!   threshold is a known, deliberately unaddressed residual gap — closing it
//!   would require sharing the actual 128-entry sliding window across nodes,
//!   not justified without a demonstrated incident.
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

    /// Atomically increment a fixed-window counter, applying `ttl` only when
    /// the key is created (i.e. a fixed window, never refreshed/extended by
    /// later increments within the same window — matching Redis's own
    /// `INCR` + `EXPIRE NX` idiom).
    ///
    /// The default body below is a **non-atomic** get-then-incr-then-set
    /// fallback, provided only so a third-party `StateBackend` implementor
    /// doesn't fail to compile after this method was added — it is correct
    /// only under a single writer. Both backends shipped in this module
    /// (`InMemoryBackend`, `RedisBackend`) override this with a genuinely
    /// atomic implementation; any caller relying on cross-node correctness
    /// (e.g. `gateway::AgentRateLimiter`) requires one of those two, not the
    /// default body.
    fn incr_with_ttl(&self, key: &str, by: i64, ttl: Duration) -> BackendResult<i64> {
        let existed = self.get(key)?.is_some();
        let v = self.incr(key, by)?;
        if !existed {
            self.set(key, v.to_string().as_bytes(), Some(ttl))?;
        }
        Ok(v)
    }

    /// Atomically replace the value at `key` with `new` (applying `ttl`), but only if the
    /// value currently stored there equals `expected` byte-for-byte (`expected: None`
    /// means "only swap if `key` does not currently exist"). Returns `Ok(true)` if the
    /// swap happened, `Ok(false)` if the current value didn't match `expected` — in which
    /// case the caller must re-`get` the fresh value and retry its own read-modify-write
    /// logic against it, exactly as any optimistic-concurrency-control primitive requires.
    ///
    /// This is the primitive that lets callers turn a get-mutate-put sequence (otherwise
    /// racy across two writers sharing this backend, e.g. two SAACP daemon nodes handling
    /// frames for the same stream — see the H-23 fix in `streaming.rs::validate_frame`)
    /// into a safe compare-and-swap retry loop, without this trait needing to know
    /// anything about the caller's data model.
    ///
    /// The default body below is a **non-atomic** get-then-compare-then-set fallback,
    /// provided only so a third-party `StateBackend` implementor doesn't fail to compile
    /// after this method was added — correct only under a single writer, exactly like
    /// `incr_with_ttl`'s default body above. Both backends shipped in this module
    /// (`InMemoryBackend`, `RedisBackend`) override this with a genuinely atomic
    /// implementation; any caller relying on cross-writer correctness requires one of
    /// those two, not the default body.
    fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> BackendResult<bool> {
        let current = self.get(key)?;
        if current.as_deref() != expected {
            return Ok(false);
        }
        self.set(key, new, ttl)?;
        Ok(true)
    }
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

    fn incr_with_ttl(&self, key: &str, by: i64, ttl: Duration) -> BackendResult<i64> {
        let mut store = self.store.lock().expect("lock poisoned");
        match store.get_mut(key) {
            Some(e) if !e.is_expired() => {
                let current: i64 =
                    std::str::from_utf8(&e.value).ok().and_then(|s| s.parse().ok()).unwrap_or(0);
                let next = current.saturating_add(by);
                e.value = next.to_string().into_bytes();
                // Only set a TTL if this entry didn't already have one — a
                // fixed window is never extended by later increments.
                if e.expires_at.is_none() {
                    e.expires_at = Some(Instant::now() + ttl);
                }
                Ok(next)
            }
            _ => {
                let next = by;
                store.insert(key.to_string(), Entry {
                    value: next.to_string().into_bytes(),
                    expires_at: Some(Instant::now() + ttl),
                });
                Ok(next)
            }
        }
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> BackendResult<bool> {
        // Single lock acquisition spanning compare-and-write: atomic with respect to
        // every other `InMemoryBackend` method, which all take this same lock.
        let mut store = self.store.lock().expect("lock poisoned");
        let current = match store.get(key) {
            Some(e) if !e.is_expired() => Some(e.value.as_slice()),
            _ => None,
        };
        if current != expected {
            return Ok(false);
        }
        store.insert(key.to_string(), Entry {
            value: new.to_vec(),
            expires_at: ttl.map(|d| Instant::now() + d),
        });
        Ok(true)
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
///
/// ## Connection pooling (Phase 3 / P-5)
///
/// Every call used to open a brand-new TCP connection via
/// `get_connection_with_timeout` and drop it at the end of the method —
/// correct, but thousands of TCP handshakes/sec under load. `checkout`/
/// `checkin` below implement a small bounded free-list pool of already-open
/// `redis::Connection`s: a call pops a live connection if one is idle (or
/// opens a new one, up to `max_pool_size`, if the pool is empty), and pushes
/// it back when done. A connection that errors mid-command is dropped rather
/// than returned to the pool, since a Redis protocol/IO error typically means
/// the connection is no longer in a known-good state — the next caller just
/// opens a fresh one, which is exactly today's behaviour for that one call.
#[cfg(feature = "redis-backend")]
pub struct RedisBackend {
    client: redis::Client,
    timeout: Duration,
    pool: Mutex<Vec<redis::Connection>>,
    max_pool_size: usize,
}

/// Default connect timeout for `RedisBackend::new()`. Bounds how long a
/// caller (e.g. `AgentRateLimiter::record_error`, running inside a
/// `tokio::task::spawn_blocking` worker) can be blocked when Redis is
/// unreachable, instead of the previous unbounded `get_connection()` wait.
#[cfg(feature = "redis-backend")]
const REDIS_DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_millis(250);

/// Default cap on idle pooled connections. Bounded so a burst of concurrent
/// callers can't grow the pool unboundedly (Part 12 principle 5, "Bounded
/// Everything") — extra connections beyond this cap are simply closed
/// instead of pooled once the burst subsides.
#[cfg(feature = "redis-backend")]
const REDIS_DEFAULT_MAX_POOL_SIZE: usize = 32;

#[cfg(feature = "redis-backend")]
impl RedisBackend {
    /// `redis_url` example: `"redis://127.0.0.1:6379/"`. Uses a 250ms connect
    /// timeout and a 32-connection pool cap; use [`Self::with_timeout`] or
    /// [`Self::with_pool_size`] to configure different bounds.
    pub fn new(redis_url: &str) -> BackendResult<Self> {
        Self::with_timeout(redis_url, REDIS_DEFAULT_CONNECT_TIMEOUT)
    }

    pub fn with_timeout(redis_url: &str, timeout: Duration) -> BackendResult<Self> {
        Self::with_pool_size(redis_url, timeout, REDIS_DEFAULT_MAX_POOL_SIZE)
    }

    pub fn with_pool_size(redis_url: &str, timeout: Duration, max_pool_size: usize) -> BackendResult<Self> {
        let client = redis::Client::open(redis_url).map_err(|e| BackendError(e.to_string()))?;
        Ok(Self { client, timeout, pool: Mutex::new(Vec::new()), max_pool_size })
    }

    /// Take a pooled connection if one is idle, otherwise open a fresh one.
    fn checkout(&self) -> BackendResult<redis::Connection> {
        if let Some(conn) = self.pool.lock().expect("lock poisoned").pop() {
            return Ok(conn);
        }
        self.client
            .get_connection_with_timeout(self.timeout)
            .map_err(|e| BackendError(e.to_string()))
    }

    /// Return a still-healthy connection to the pool for reuse; drop it
    /// (closing the TCP connection) if the pool is already at capacity.
    fn checkin(&self, conn: redis::Connection) {
        let mut pool = self.pool.lock().expect("lock poisoned");
        if pool.len() < self.max_pool_size {
            pool.push(conn);
        }
    }

    /// Run `f` against a pooled connection, returning it to the pool only on
    /// success — a command that errors may have left the connection in an
    /// indeterminate protocol state, so it's dropped instead of reused.
    fn with_conn<T>(&self, f: impl FnOnce(&mut redis::Connection) -> BackendResult<T>) -> BackendResult<T> {
        let mut conn = self.checkout()?;
        let result = f(&mut conn);
        if result.is_ok() {
            self.checkin(conn);
        }
        result
    }
}

#[cfg(feature = "redis-backend")]
impl StateBackend for RedisBackend {
    fn get(&self, key: &str) -> BackendResult<Option<Vec<u8>>> {
        use redis::Commands;
        self.with_conn(|conn| conn.get(key).map_err(|e| BackendError(e.to_string())))
    }

    fn set(&self, key: &str, value: &[u8], ttl: Option<Duration>) -> BackendResult<()> {
        use redis::Commands;
        self.with_conn(|conn| match ttl {
            Some(d) => {
                let secs = d.as_secs().max(1); // Redis EX requires a positive integer.
                conn.set_ex(key, value, secs).map_err(|e| BackendError(e.to_string()))
            }
            None => conn.set(key, value).map_err(|e| BackendError(e.to_string())),
        })
    }

    fn delete(&self, key: &str) -> BackendResult<bool> {
        use redis::Commands;
        self.with_conn(|conn| {
            let removed: i64 = conn.del(key).map_err(|e| BackendError(e.to_string()))?;
            Ok(removed > 0)
        })
    }

    fn incr(&self, key: &str, by: i64) -> BackendResult<i64> {
        use redis::Commands;
        self.with_conn(|conn| conn.incr(key, by).map_err(|e| BackendError(e.to_string())))
    }

    fn scan_prefix(&self, prefix: &str) -> BackendResult<Vec<String>> {
        use redis::Commands;
        // SCAN (cursor-based, non-blocking), never KEYS (blocks the server
        // for the duration of a full-keyspace scan). The iterator borrows the
        // connection for its lifetime, so it's fully drained (collected)
        // before the connection is returned to the pool.
        self.with_conn(|conn| {
            let pattern = format!("{prefix}*");
            let iter: redis::Iter<'_, String> =
                conn.scan_match(pattern).map_err(|e| BackendError(e.to_string()))?;
            Ok(iter.collect())
        })
    }

    fn incr_with_ttl(&self, key: &str, by: i64, ttl: Duration) -> BackendResult<i64> {
        // Atomic server-side: INCRBY, then EXPIRE only if the key has no TTL
        // yet (TTL == -1) — a fixed window that later increments never
        // extend. `redis::Script` ships in the base `redis` crate already
        // declared in Cargo.toml; no new dependency.
        const SCRIPT: &str = r#"
            local v = redis.call('INCRBY', KEYS[1], ARGV[1])
            if redis.call('TTL', KEYS[1]) == -1 then
                redis.call('EXPIRE', KEYS[1], ARGV[2])
            end
            return v
        "#;
        self.with_conn(|conn| {
            redis::Script::new(SCRIPT)
                .key(key)
                .arg(by)
                .arg(ttl.as_secs().max(1))
                .invoke(conn)
                .map_err(|e| BackendError(e.to_string()))
        })
    }

    fn compare_and_swap(
        &self,
        key: &str,
        expected: Option<&[u8]>,
        new: &[u8],
        ttl: Option<Duration>,
    ) -> BackendResult<bool> {
        // Atomic server-side: a Lua script runs to completion with no other Redis
        // command interleaved, so GET-compare-SET here needs no client-side
        // WATCH/MULTI/EXEC transaction (and its own retry-on-conflict handling) — the
        // script IS the atomic unit. ARGV[2] is a presence flag ('1' if `expected` is
        // `Some`, '0' if `None`) since a Lua string can't distinguish "absent" from
        // "empty string" the way `Option<&[u8]>` can.
        const SCRIPT: &str = r#"
            local cur = redis.call('GET', KEYS[1])
            local has_expected = ARGV[2] == '1'
            local matches
            if cur == false then
                matches = not has_expected
            else
                matches = has_expected and cur == ARGV[1]
            end
            if not matches then
                return 0
            end
            if ARGV[3] == '0' then
                redis.call('SET', KEYS[1], ARGV[4])
            else
                redis.call('SET', KEYS[1], ARGV[4], 'EX', ARGV[3])
            end
            return 1
        "#;
        let has_expected = if expected.is_some() { "1" } else { "0" };
        let ttl_secs = ttl.map(|d| d.as_secs().max(1)).unwrap_or(0);
        self.with_conn(|conn| {
            let result: i64 = redis::Script::new(SCRIPT)
                .key(key)
                .arg(expected.unwrap_or(&[]))
                .arg(has_expected)
                .arg(ttl_secs)
                .arg(new)
                .invoke(conn)
                .map_err(|e| BackendError(e.to_string()))?;
            Ok(result == 1)
        })
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

    #[test]
    fn incr_with_ttl_creates_and_increments() {
        let b = InMemoryBackend::new();
        assert_eq!(b.incr_with_ttl("c", 1, Duration::from_secs(10)).unwrap(), 1);
        assert_eq!(b.incr_with_ttl("c", 1, Duration::from_secs(10)).unwrap(), 2);
        assert_eq!(b.incr_with_ttl("c", 3, Duration::from_secs(10)).unwrap(), 5);
    }

    #[test]
    fn incr_with_ttl_sets_ttl_only_on_creation() {
        let b = InMemoryBackend::new();
        // Creates with a short TTL.
        b.incr_with_ttl("c", 1, Duration::from_millis(40)).unwrap();
        // A second increment before expiry must NOT reset the TTL clock.
        std::thread::sleep(Duration::from_millis(20));
        b.incr_with_ttl("c", 1, Duration::from_secs(999)).unwrap();
        // Total lifetime is measured from the FIRST creation, not the second call.
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(b.get("c").unwrap(), None, "TTL should have expired from first creation, not been reset");
    }

    #[test]
    fn incr_with_ttl_is_atomic_under_concurrency() {
        use std::sync::Arc;
        use std::thread;

        let b = Arc::new(InMemoryBackend::new());
        let mut handles = vec![];
        for _ in 0..8 {
            let b = Arc::clone(&b);
            handles.push(thread::spawn(move || {
                for _ in 0..100 {
                    b.incr_with_ttl("shared", 1, Duration::from_secs(30)).unwrap();
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        assert_eq!(b.get("shared").unwrap(), Some(b"800".to_vec()));
    }

    // ─── compare_and_swap (H-23 fix support) ──────────────────────────────────

    #[test]
    fn cas_succeeds_when_key_absent_and_expected_is_none() {
        let b = InMemoryBackend::new();
        assert!(b.compare_and_swap("k", None, b"v1", None).unwrap());
        assert_eq!(b.get("k").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn cas_fails_when_key_absent_but_expected_is_some() {
        let b = InMemoryBackend::new();
        assert!(!b.compare_and_swap("k", Some(b"v0"), b"v1", None).unwrap());
        assert_eq!(b.get("k").unwrap(), None);
    }

    #[test]
    fn cas_fails_when_key_present_but_expected_is_none() {
        let b = InMemoryBackend::new();
        b.set("k", b"v0", None).unwrap();
        assert!(!b.compare_and_swap("k", None, b"v1", None).unwrap());
        assert_eq!(b.get("k").unwrap(), Some(b"v0".to_vec()));
    }

    #[test]
    fn cas_succeeds_when_current_value_matches_expected() {
        let b = InMemoryBackend::new();
        b.set("k", b"v0", None).unwrap();
        assert!(b.compare_and_swap("k", Some(b"v0"), b"v1", None).unwrap());
        assert_eq!(b.get("k").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn cas_fails_when_current_value_diverged_and_leaves_value_unchanged() {
        let b = InMemoryBackend::new();
        b.set("k", b"v0", None).unwrap();
        // Simulate a concurrent writer changing the value out from under us.
        b.set("k", b"v_other", None).unwrap();
        assert!(!b.compare_and_swap("k", Some(b"v0"), b"v1", None).unwrap());
        assert_eq!(b.get("k").unwrap(), Some(b"v_other".to_vec()));
    }

    #[test]
    fn cas_applies_ttl_on_success() {
        let b = InMemoryBackend::new();
        b.set("k", b"v0", None).unwrap();
        assert!(b
            .compare_and_swap("k", Some(b"v0"), b"v1", Some(Duration::from_millis(20)))
            .unwrap());
        assert_eq!(b.get("k").unwrap(), Some(b"v1".to_vec()));
        std::thread::sleep(Duration::from_millis(60));
        assert_eq!(b.get("k").unwrap(), None);
    }

    #[test]
    fn cas_treats_expired_entry_as_absent() {
        let b = InMemoryBackend::new();
        b.set("k", b"v0", Some(Duration::from_millis(20))).unwrap();
        std::thread::sleep(Duration::from_millis(60));
        // The entry has expired, so it should behave as if absent: `expected: None` wins.
        assert!(b.compare_and_swap("k", None, b"v1", None).unwrap());
        assert_eq!(b.get("k").unwrap(), Some(b"v1".to_vec()));
    }

    #[test]
    fn only_one_of_many_racing_cas_attempts_against_the_same_expected_value_wins() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use std::thread;

        let b = Arc::new(InMemoryBackend::new());
        b.set("k", b"v0", None).unwrap();
        let successes = Arc::new(AtomicUsize::new(0));

        let mut handles = vec![];
        for i in 0..16 {
            let b = Arc::clone(&b);
            let successes = Arc::clone(&successes);
            handles.push(thread::spawn(move || {
                let new_val = format!("v_from_{i}");
                if b.compare_and_swap("k", Some(b"v0"), new_val.as_bytes(), None).unwrap() {
                    successes.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        // Exactly one racer should observe the original "v0" and win the swap — all
        // others must see the post-swap value and fail, proving no lost updates.
        assert_eq!(successes.load(Ordering::SeqCst), 1);
    }
}
