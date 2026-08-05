//! gateway.rs — Zero-Trust Gateway
//!
//! Zero-Trust Tokenized Micro-Gateway.
//! Prevents prompt-injected agents from lateral movement using
//! cryptographically signed capability tokens.
//! Uses length-prefix format to prevent token delimiter injection.

use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock, LazyLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};
use zeroize::Zeroizing;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::faitf::TrustStore;
use crate::acsvaf::{CapabilityVerificationAuthority, ACSVAF_MAX_DELEGATION_DEPTH};
use crate::state_backend::StateBackend;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Circuit breaker threshold for legitimate packet errors.
pub const RATE_LIMITER_THRESHOLD: usize = 5;
/// Circuit breaker window in seconds.
pub const RATE_LIMITER_WINDOW_SECONDS: f64 = 10.0;
/// Circuit breaker lockout duration in seconds.
pub const RATE_LIMITER_LOCKOUT_SECONDS: f64 = 30.0;
/// Cover traffic rate limit per window.
pub const COVER_TRAFFIC_THRESHOLD: usize = 50;
/// Cover traffic window in seconds.
pub const COVER_TRAFFIC_WINDOW_SECONDS: f64 = 1.0;
/// Maximum token cache entries before eviction.
pub const TOKEN_CACHE_MAX: usize = 10_000;
/// Number of token-cache shards. Follows the `RATE_LIMITER_SHARDS` convention.
const TOKEN_CACHE_SHARDS: usize = 16;
/// Per-shard entry cap. The aggregate bound stays `TOKEN_CACHE_MAX`, enforced
/// per shard rather than globally so eviction never has to take every lock —
/// the same split `RATE_LIMITER_PER_SHARD_MAX_ENTRIES` uses. Keys distribute
/// evenly (`shard::fnv1a_shard`), so per-shard and global caps agree closely.
const TOKEN_CACHE_PER_SHARD_MAX: usize = TOKEN_CACHE_MAX / TOKEN_CACHE_SHARDS;
/// Token cache TTL cap (seconds).
pub const TOKEN_CACHE_TTL: f64 = 30.0;
/// L-9 fix: hard cap on distinct issuers `ZeroTrustGateway::register_issuer_key` will
/// track. Previously unbounded — a caller (or attacker) able to reach this method
/// repeatedly with distinct `issuer_agent` strings could grow `trusted_issuer_keys`
/// without limit, an OOM vector. Matches this codebase's established bound for other
/// unbounded-cardinality maps (`TOKEN_CACHE_MAX`, `RATE_LIMITER_MAX_ENTRIES`).
pub const MAX_TRUSTED_ISSUERS: usize = 10_000;
/// Maximum tracked agent_ids in each `AgentRateLimiter` map before a stale-entry
/// sweep runs. IoT / low-resource fix: these maps previously grew unbounded for
/// the process lifetime — one permanent entry per distinct agent_id ever seen,
/// with no TTL or cap. Mirrors `memory::FEDERATED_MAX_ENTRIES`'s sweep-on-overflow
/// idiom: only swept when the cap is exceeded, so well-behaved fleets (fewer than
/// this many concurrently-active agents) never pay the sweep cost at all.
pub const RATE_LIMITER_MAX_ENTRIES: usize = 10_000;
/// Phase 7 / item 2 / Part 6.3: number of independent lock shards for
/// `AgentRateLimiter`'s `records`/`cover_records` maps (sharded on
/// `agent_id.as_bytes()[0] % N`, mirroring `trust_decay::TRUST_SHARDS`). Before
/// sharding, every agent's rate-limit check across the entire process serialized on
/// one process-wide `Mutex` each — under load, an unrelated agent's `record_error`/
/// `record_cover_traffic` call could stall behind a completely different agent's.
const RATE_LIMITER_SHARDS: usize = 16;
/// Per-shard soft capacity, chosen so the aggregate cap across all shards still
/// equals `RATE_LIMITER_MAX_ENTRIES` — sharding must not silently multiply the
/// effective capacity of these bounded maps.
const RATE_LIMITER_PER_SHARD_MAX_ENTRIES: usize = RATE_LIMITER_MAX_ENTRIES / RATE_LIMITER_SHARDS;
/// Default interval at which `AgentRateLimiter::with_backend`'s background
/// poller mirrors fleet-wide lockouts (tripped on another node) into this
/// node's local map. Bounds the "already-known-here" staleness window —
/// see `state_backend.rs`'s module doc for the full design rationale.
pub const RATE_LIMITER_DEFAULT_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Part 6.2 P-1 (broadened scope) / Part 6.3: number of independent lock shards for
/// `ZeroTrustGateway::revoked_tokens`, mirroring `trust_decay::TRUST_SHARDS`'s
/// convention. This set is read on every Gate 1.0 pass (both the direct
/// `is_token_revoked` check used by stream continuation/end frames, and the
/// inline check inside `validate_lateral_movement`) and written on every
/// `revoke_token` call — before sharding it was a single process-wide `Mutex`
/// serializing every packet's revocation check behind every other packet's,
/// regardless of which token each one actually concerned.
const REVOKED_TOKENS_SHARDS: usize = 16;

/// S-2 fix: hard cap on the aggregate number of individually-revoked token
/// signature hashes retained across all `revoked_tokens` shards. Mirrors the
/// crate's other bounded-map caps (`TOKEN_CACHE_MAX`, `RATE_LIMITER_MAX_ENTRIES`,
/// `RRBC_REPLAY_REGISTRY_MAX`). Once exceeded, `revoke_token` first prunes
/// already-expired entries, then — if still over cap — evicts lowest-`exp`
/// (soonest-to-expire, hence least-valuable) entries until back under cap.
pub const REVOKED_TOKENS_MAX: usize = 100_000;

/// S-2 fix: fallback TTL (seconds) applied when a revoked token carries no
/// parseable `exp` claim, so a malformed/legacy token still gets an eventual
/// eviction deadline instead of pinning its entry forever. Generous relative to
/// normal capability-token lifetimes (this is only a memory-reclaim floor, never
/// a security window — the blanket-revocation `iat` check and Gate 1.0 expiry
/// still apply independently).
pub const REVOKED_TOKENS_FALLBACK_TTL: f64 = 30.0 * 24.0 * 3600.0;

/// Maps a token signature hash to its shard index.
///
/// The hash is a raw SHA-256 **hex** digest (see `sha256_hex`), so its first
/// byte is drawn only from `[0-9a-f]` — ten distinct residues mod 16, leaving
/// shards 10-15 permanently unreachable under the previous first-byte scheme.
/// `fnv1a_shard` mixes the whole digest instead. See `shard.rs`.
fn revoked_token_shard_index(sig_hash: &str) -> usize {
    crate::shard::fnv1a_shard(sig_hash, REVOKED_TOKENS_SHARDS)
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Maps an `AgentRateLimiter` map key (an `agent_id`) to its shard index.
///
/// Hashes the WHOLE key: agent ids in practice share a common prefix
/// (`agent-0001`, `agent-0002`, …), so the previous first-byte scheme sent every
/// one of them to a single shard and left the other 15 mutexes idle. See
/// `shard.rs` and the `t28_*` tests below.
fn ratelimit_shard_index(key: &str) -> usize {
    crate::shard::fnv1a_shard(key, RATE_LIMITER_SHARDS)
}

fn new_ratelimit_shards<V>() -> Vec<Mutex<HashMap<String, V>>> {
    (0..RATE_LIMITER_SHARDS).map(|_| Mutex::new(HashMap::new())).collect()
}

/// Lock and return the shard responsible for `key`.
///
/// M-38 fix: recovers via `into_inner()` on poison rather than panicking —
/// `AgentRateLimiter::global()` is a process-wide singleton, so one poisoning
/// panic must not cascade into every other agent's rate-limit checks.
fn ratelimit_shard<'a, V>(
    shards: &'a [Mutex<HashMap<String, V>>],
    key: &str,
) -> std::sync::MutexGuard<'a, HashMap<String, V>> {
    shards[ratelimit_shard_index(key)].lock().unwrap_or_else(|e| e.into_inner())
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// L-7 fix: HMAC's spec (RFC 2104) accepts any key length — short keys are
/// zero-padded, long keys are pre-hashed — so `Hmac::new_from_slice(key).unwrap()`
/// was not actually reachable as a panic. But a short (or empty) key is a genuine
/// *cryptographic weakness* regardless: a trivially guessable/brute-forceable MAC key.
/// Rather than thread a new `Result` through this function's ~7 call sites across this
/// file (a large blast radius for what the underlying weakness needs), any key shorter
/// than 32 bytes is strengthened here by hashing it with SHA-256 first — every caller
/// keeps compiling unchanged, but the *effective* key HMAC actually signs/verifies with
/// is always full-entropy-width-derived, never a short raw value.
fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let strengthened;
    let key = if key.len() < 32 {
        strengthened = Sha256::digest(key);
        strengthened.as_slice()
    } else {
        key
    };
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

/// M-1 fix: re-export the crate's single canonical constant-time comparison
/// (see `security::constant_time_eq`'s doc comment) instead of carrying a
/// separate byte-identical copy here. `gateway.rs` no longer defines its own —
/// this alias exists purely so existing callers spelled as
/// `crate::gateway::constant_time_eq` (e.g. `sidecar.rs`'s bearer-token auth,
/// M-22) keep compiling unchanged.
pub(crate) use crate::security::constant_time_eq;

fn serialize_sorted_json(data: &HashMap<String, serde_json::Value>) -> Vec<u8> {
    let sorted: BTreeMap<&String, &serde_json::Value> = data.iter().collect();
    serde_json::to_vec(&sorted).unwrap_or_default()
}

/// Sort a JSON array of strings in-place (for cross-language token compatibility).
fn sorted_str_array(items: &[&str]) -> serde_json::Value {
    let mut v: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    v.sort();
    serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect())
}

fn parse_token_wire(token_b64: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SAACPHardDrop> {
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_b64)
        .map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Missing or malformed Capability Token.",
        ))?;
    if raw.len() < 4 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Token too short.",
        ));
    }
    // u32→usize is always safe: u32 <= usize on all supported platforms.
    let json_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if json_len == 0 || json_len > raw.len().saturating_sub(4) {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Invalid token JSON length.",
        ));
    }
    let token_json = raw[4..4 + json_len].to_vec();
    let signature = raw[4 + json_len..].to_vec();
    if signature.len() != 32 && signature.len() != 64 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Invalid signature length.",
        ));
    }
    Ok((token_json, signature))
}

// ---------------------------------------------------------------------------
// Token validation result
// ---------------------------------------------------------------------------

/// Result of token validation.
#[derive(Debug, Clone)]
pub struct TokenValidationResult {
    pub is_valid: bool,
    pub source_agent: String,
    pub root_intent_hash: Option<String>,
    pub max_action_class: u8,
    /// Optional `delegation_depth` claim, read the same way ACSVAF tokens
    /// already do (`acsvaf.rs`), but treated as informational here rather
    /// than a mandatory authorization gate — legacy/plain tokens without the
    /// claim default to `0` ("no known delegation chain") and validate
    /// exactly as before. Feeds Gate 1.5's per-hop intent-drift tightening
    /// (`handler.rs`) — deeper delegation chains get a stricter overlap bar.
    pub delegation_depth: u32,
    /// Part 6.1 (SHA-256 hash caching): the token signature's SHA-256 hex
    /// digest, computed once here (the revocation-set lookup already needs
    /// it) and carried out so callers (Gate 1.0's audit log, `StreamRegistry`
    /// registration) don't independently re-derive it from the raw token
    /// bytes a second and third time for the same packet. Cached inside
    /// `CacheEntry` along with the rest of this struct, so a `token_cache`
    /// hit costs zero extra hashing, exactly as it does today.
    pub token_sig_hash: String,
}

// ---------------------------------------------------------------------------
// AgentRateLimiter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RateRecord {
    errors: usize,
    window_start: f64,
    locked_until: f64,
}

#[derive(Debug, Clone)]
struct CoverRecord {
    count: usize,
    window_start: f64,
}

/// Per-agent-identity circuit breaker with separate cover traffic budget.
///
/// Optionally backed by a [`StateBackend`] (see `state_backend.rs`'s module
/// doc for the full cross-node design) via [`Self::with_backend`]. Without a
/// backend (`::new()`/`::global()`), behavior is byte-for-byte identical to
/// before this was added — purely in-process, no thread spawned.
pub struct AgentRateLimiter {
    records: Arc<Vec<Mutex<HashMap<String, RateRecord>>>>,
    cover_records: Arc<Vec<Mutex<HashMap<String, CoverRecord>>>>,
    backend: Option<Arc<dyn StateBackend>>,
    poller_stop: Option<Arc<AtomicBool>>,
}

fn ratelimit_err_key(agent_id: &str) -> String {
    format!("ratelimit:err:{agent_id}")
}

fn ratelimit_lock_key(agent_id: &str) -> String {
    format!("ratelimit:lock:{agent_id}")
}

impl AgentRateLimiter {
    pub fn new() -> Self {
        Self {
            records: Arc::new(new_ratelimit_shards()),
            cover_records: Arc::new(new_ratelimit_shards()),
            backend: None,
            poller_stop: None,
        }
    }

    /// Construct with a shared [`StateBackend`] for cross-node visibility and
    /// atomic fleet-wide circuit-breaker enforcement on the (rare) error
    /// path. Spawns a background poller at the default interval — see
    /// [`Self::with_backend_and_poll_interval`] to customize it.
    pub fn with_backend(backend: Arc<dyn StateBackend>) -> Self {
        Self::with_backend_and_poll_interval(backend, RATE_LIMITER_DEFAULT_POLL_INTERVAL)
    }

    /// Same as [`Self::with_backend`], with a configurable poll interval for
    /// the background lockout-mirroring thread.
    pub fn with_backend_and_poll_interval(backend: Arc<dyn StateBackend>, poll_interval: Duration) -> Self {
        let records = Arc::new(new_ratelimit_shards());
        let stop = Arc::new(AtomicBool::new(false));

        let poll_records = Arc::clone(&records);
        let poll_backend = Arc::clone(&backend);
        let poll_stop = Arc::clone(&stop);
        let _ = std::thread::Builder::new()
            .name("saacp-ratelimit-poller".to_string())
            .spawn(move || {
                while !poll_stop.load(Ordering::Relaxed) {
                    Self::poll_once(&poll_records, poll_backend.as_ref());
                    std::thread::sleep(poll_interval);
                }
            });

        Self {
            records,
            cover_records: Arc::new(new_ratelimit_shards()),
            backend: Some(backend),
            poller_stop: Some(stop),
        }
    }

    /// Merge any fleet-wide lockouts visible on the backend into the local
    /// map. Called periodically by the background poller when constructed
    /// via `with_backend`; also callable directly for deterministic tests
    /// (avoids sleeping past the poll interval).
    pub fn refresh_from_backend(&self) {
        if let Some(backend) = &self.backend {
            Self::poll_once(&self.records, backend.as_ref());
        }
    }

    fn poll_once(records: &[Mutex<HashMap<String, RateRecord>>], backend: &dyn StateBackend) {
        // The `ratelimit:lock:` keyspace is small and self-cleaning (only
        // currently-locked-out agents, TTL-bounded at
        // RATE_LIMITER_LOCKOUT_SECONDS), so a SCAN here is cheap — this is
        // not a scan of the full production keyspace.
        let Ok(keys) = backend.scan_prefix("ratelimit:lock:") else { return };
        for key in keys {
            let agent_id = key.strip_prefix("ratelimit:lock:").unwrap_or(&key);
            let Ok(Some(bytes)) = backend.get(&key) else { continue };
            let Ok(text) = std::str::from_utf8(&bytes) else { continue };
            let Ok(locked_until) = text.parse::<f64>() else { continue };

            let mut r = ratelimit_shard(records, agent_id);
            let rec = r.entry(agent_id.to_string()).or_insert(RateRecord {
                errors: 0,
                window_start: now_epoch_secs(),
                locked_until: 0.0,
            });
            rec.locked_until = rec.locked_until.max(locked_until);
        }
    }

    /// Record one error. Raises CIRCUIT_BREAKER_OPEN if threshold exceeded.
    ///
    /// When a backend is configured, the shared fleet-wide error counter is
    /// bumped atomically (`StateBackend::incr_with_ttl`) so an agent can't
    /// evade the breaker by round-robining across nodes; on a backend error
    /// this fails *safe* (falls back to the local-only algorithm below) not
    /// open.
    pub fn record_error(&self, agent_id: &str) -> Result<(), SAACPHardDrop> {
        let now = now_epoch_secs();

        if let Some(backend) = &self.backend {
            // Already locked out locally — no backend call needed; avoids
            // hammering the backend with every subsequent bad packet during
            // an active lockout.
            {
                let records = ratelimit_shard(&self.records, agent_id);
                if let Some(rec) = records.get(agent_id) {
                    if now < rec.locked_until {
                        return Err(SAACPHardDrop::new(
                            SAACPBytecodes::CircuitBreakerOpen,
                            format!("Agent '{}' is locked out for malformed packet flooding.", agent_id),
                        ));
                    }
                }
            } // guard dropped before any backend I/O

            match backend.incr_with_ttl(
                &ratelimit_err_key(agent_id),
                1,
                Duration::from_secs_f64(RATE_LIMITER_WINDOW_SECONDS),
            ) {
                Ok(shared_count) => {
                    if shared_count >= RATE_LIMITER_THRESHOLD as i64 {
                        let locked_until = now + RATE_LIMITER_LOCKOUT_SECONDS;
                        {
                            let mut records = ratelimit_shard(&self.records, agent_id);
                            let rec = records.entry(agent_id.to_string()).or_insert(RateRecord {
                                errors: 0,
                                window_start: now,
                                locked_until: 0.0,
                            });
                            rec.errors = shared_count.max(0) as usize;
                            rec.locked_until = locked_until;
                        }
                        let _ = backend.set(
                            &ratelimit_lock_key(agent_id),
                            locked_until.to_string().as_bytes(),
                            Some(Duration::from_secs_f64(RATE_LIMITER_LOCKOUT_SECONDS)),
                        );
                        return Err(SAACPHardDrop::new(
                            SAACPBytecodes::CircuitBreakerOpen,
                            format!(
                                "Circuit breaker OPEN for '{}': {} errors in {}s (fleet-wide).",
                                agent_id, shared_count, RATE_LIMITER_WINDOW_SECONDS
                            ),
                        ));
                    }
                    let mut records = ratelimit_shard(&self.records, agent_id);
                    let rec = records.entry(agent_id.to_string()).or_insert(RateRecord {
                        errors: 0,
                        window_start: now,
                        locked_until: 0.0,
                    });
                    rec.errors = shared_count.max(0) as usize;
                    return Ok(());
                }
                Err(_backend_error) => {
                    // Fail-safe, not fail-open: fall through to the
                    // local-only algorithm for this one call.
                }
            }
        }

        let mut records = ratelimit_shard(&self.records, agent_id);

        // IoT / low-resource fix: this map previously grew unbounded — one permanent
        // entry per distinct agent_id ever seen. Sweep stale entries (not currently
        // locked out AND window already elapsed — i.e. functionally identical to
        // never having existed) only once this shard's (aggregate-cap-preserving)
        // per-shard cap is exceeded, mirroring `memory::FederatedMemory`'s
        // sweep-on-overflow idiom.
        if records.len() >= RATE_LIMITER_PER_SHARD_MAX_ENTRIES {
            records.retain(|_, r| {
                now < r.locked_until || (now - r.window_start) <= RATE_LIMITER_WINDOW_SECONDS
            });
        }

        let rec = records.entry(agent_id.to_string()).or_insert(RateRecord {
            errors: 0,
            window_start: now,
            locked_until: 0.0,
        });

        if now < rec.locked_until {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!("Agent '{}' is locked out for malformed packet flooding.", agent_id),
            ));
        }

        if (now - rec.window_start) > RATE_LIMITER_WINDOW_SECONDS {
            rec.errors = 0;
            rec.window_start = now;
        }

        rec.errors += 1;
        if rec.errors >= RATE_LIMITER_THRESHOLD {
            rec.locked_until = now + RATE_LIMITER_LOCKOUT_SECONDS;
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!(
                    "Circuit breaker OPEN for '{}': {} errors in {}s.",
                    agent_id, rec.errors, RATE_LIMITER_WINDOW_SECONDS
                ),
            ));
        }
        Ok(())
    }

    /// Record one cover traffic packet (M-8 fix).
    ///
    /// Deliberately node-local even when a backend is configured: this
    /// window is an order of magnitude higher-frequency than
    /// `record_error`'s (50 packets/1s vs 5 errors/10s), and its trip
    /// consequence is lower-severity (traffic-shaping, not a compromise
    /// signal) — a per-packet backend round trip here would reintroduce
    /// exactly the regression the hybrid design avoids for `record_error`.
    pub fn record_cover_traffic(&self, agent_id: &str) -> Result<(), SAACPHardDrop> {
        let mut records = ratelimit_shard(&self.cover_records, agent_id);
        let now = now_epoch_secs();

        // IoT / low-resource fix: same unbounded-growth issue as `record_error`'s map.
        if records.len() >= RATE_LIMITER_PER_SHARD_MAX_ENTRIES {
            records.retain(|_, r| (now - r.window_start) <= COVER_TRAFFIC_WINDOW_SECONDS);
        }

        let rec = records.entry(agent_id.to_string()).or_insert(CoverRecord {
            count: 0,
            window_start: now,
        });

        if (now - rec.window_start) > COVER_TRAFFIC_WINDOW_SECONDS {
            rec.count = 0;
            rec.window_start = now;
        }

        rec.count += 1;
        if rec.count > COVER_TRAFFIC_THRESHOLD {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!(
                    "Cover traffic rate limit exceeded for '{}': {} cover packets in {}s (limit: {}).",
                    agent_id, rec.count, COVER_TRAFFIC_WINDOW_SECONDS, COVER_TRAFFIC_THRESHOLD
                ),
            ));
        }
        Ok(())
    }

    /// Returns true if the agent is currently under circuit-breaker lockout.
    ///
    /// Always a pure local read — zero network calls in any configuration.
    /// This runs on every packet (before Gate 0 decryption), so it must
    /// never depend on backend latency; cross-node lockouts reach this map
    /// via `record_error`'s immediate local write (same node) or the
    /// background poller (other nodes, bounded by the poll interval).
    pub fn is_locked(&self, agent_id: &str) -> bool {
        self.is_locked_at(agent_id, now_epoch_secs())
    }

    /// opusplan.md 6.4 item 1: same as [`Self::is_locked`], but takes an
    /// already-captured wall-clock reading instead of calling `now_epoch_secs()`
    /// internally — lets a caller that's about to make several near-simultaneous
    /// time-sensitive checks (e.g. `intercept_packet_full`'s pre-gate circuit-breaker
    /// and trust-decay reauth checks, a few lines apart with no state change between
    /// them) share one syscall instead of each check taking its own. `is_locked`
    /// itself is untouched and remains the right choice for any caller that doesn't
    /// already have a `now` in hand.
    pub fn is_locked_at(&self, agent_id: &str, now: f64) -> bool {
        let records = ratelimit_shard(&self.records, agent_id);
        if let Some(rec) = records.get(agent_id) {
            return now < rec.locked_until;
        }
        false
    }

    /// Process-wide singleton AgentRateLimiter.
    ///
    /// Used by `SAACPProtocolHandler::intercept_packet()` as the unconditional
    /// circuit-breaker fallback when no rate_limiter is explicitly injected.
    /// Enforces GAP-3 (circuit breaker always checked) and GAP-10 (record_error
    /// always called on SAACPHardDrop) per Python `intercept_packet` parity.
    pub fn global() -> &'static AgentRateLimiter {
        static GLOBAL: OnceLock<AgentRateLimiter> = OnceLock::new();
        GLOBAL.get_or_init(AgentRateLimiter::new)
    }

    /// Reset records for an agent (or all agents if None).
    pub fn reset(&self, agent_id: Option<&str>) {
        if let Some(id) = agent_id {
            ratelimit_shard(&self.records, id).remove(id);
            ratelimit_shard(&self.cover_records, id).remove(id);
            if let Some(backend) = &self.backend {
                let _ = backend.delete(&ratelimit_err_key(id));
                let _ = backend.delete(&ratelimit_lock_key(id));
            }
        } else {
            for s in self.records.iter() {
                s.lock().unwrap_or_else(|e| e.into_inner()).clear();
            }
            for s in self.cover_records.iter() {
                s.lock().unwrap_or_else(|e| e.into_inner()).clear();
            }
            if let Some(backend) = &self.backend {
                if let Ok(keys) = backend.scan_prefix("ratelimit:") {
                    for key in keys {
                        let _ = backend.delete(&key);
                    }
                }
            }
        }
    }
}

impl Default for AgentRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for AgentRateLimiter {
    fn drop(&mut self) {
        if let Some(stop) = &self.poller_stop {
            stop.store(true, Ordering::Relaxed);
        }
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustGateway
// ---------------------------------------------------------------------------

/// Token cache entry.
#[derive(Clone)]
struct CacheEntry {
    expiry: f64,
    result: TokenValidationResult,
    /// The `GatewayEpochs::cache_generation` in force when this verdict was
    /// computed. A lookup whose generation differs is treated as a miss.
    ///
    /// This is what makes invalidation atomic independently of how the cache is
    /// physically sharded. Clearing 16 shards is NOT atomic — a concurrent
    /// lookup can hit a not-yet-cleared shard between shard 0 and shard 15 — and
    /// every caller that clears this cache is a revocation or key-registry
    /// change, so that window would serve a REVOKED token. Bumping one counter
    /// in a single atomic publish closes it; the physical clear afterwards is
    /// then pure memory reclamation with no correctness role.
    generation: u64,
}

/// The gateway's revocation/config scalars, read together as one snapshot.
///
/// These were four independent `Mutex`es. `validate_lateral_movement` reads
/// several of them per packet and its decision depends on their **mutual**
/// consistency, so four independent atomics would be actively unsafe here: a
/// packet could observe the NEW `revocation_epoch` (concluding its cached
/// verdict is fresh) alongside the OLD `blanket_revoked_before` (so the blanket
/// revocation is not applied) and admit a token that must have been rejected.
/// `revoke_all_tokens` updates exactly that pair together, which is precisely
/// the window an attacker would target during PSK-compromise recovery.
///
/// Holding them in one immutable struct behind an `ArcSwap` means a reader gets
/// all five fields from a single lock-free load, and a writer publishes all five
/// at once. A torn read is unrepresentable.
#[derive(Debug, Clone)]
struct GatewayEpochs {
    strict_asymmetric_mode: bool,
    revocation_epoch: u64,
    issuer_registry_epoch: u64,
    /// H-2: any capability token whose `iat` predates this is rejected.
    blanket_revoked_before: f64,
    /// Bumped on every event that invalidates cached token verdicts. A
    /// `CacheEntry` stamped with a stale generation is treated as a miss, which
    /// makes invalidation atomic and instantaneous regardless of how the cache
    /// is physically sharded — see `token_cache`.
    cache_generation: u64,
}

/// Zero-Trust Tokenized Micro-Gateway.
pub struct ZeroTrustGateway {
    /// Part 6.3: sharded 16-way on the signature hash's first byte (see
    /// `revoked_token_shard_index`) — access via `revoked_shard()`, never
    /// directly.
    ///
    /// S-2 fix: maps `sig_hash -> token exp (epoch seconds)` rather than a bare
    /// `HashSet<String>`. Previously this set had no TTL and no cap — every
    /// individually-revoked token's signature hash persisted for the entire
    /// process lifetime, so an operator/automation revoking tokens steadily grew
    /// it without bound (OOM on long-running daemons), unlike every other
    /// unbounded-cardinality map in this crate (`TOKEN_CACHE_MAX`,
    /// `RATE_LIMITER_MAX_ENTRIES`, `RRBC_REPLAY_REGISTRY_MAX`). Storing `exp`
    /// lets `prune_expired_revocations` drop entries whose bound token has
    /// already expired — an expired token is rejected by Gate 1.0's own expiry
    /// check regardless, so its revocation entry has zero protective value past
    /// `exp` and is safe to evict. `REVOKED_TOKENS_MAX` is a hard backstop cap
    /// (oldest-`exp`-first eviction) for the pathological case where every
    /// revoked token has a far-future `exp`.
    revoked_tokens: Vec<Mutex<HashMap<String, f64>>>,
    /// Sharded 16-way on the cache key (see `token_cache_shard`). Read on
    /// essentially every packet and written on every miss, so a single global
    /// mutex serialized the hot path.
    ///
    /// Correctness of invalidation does NOT depend on this sharding: entries
    /// carry a `generation` stamp and a stale one is a miss, so a partially
    /// cleared cache can never serve a revoked verdict. See `CacheEntry`.
    token_cache: Vec<Mutex<HashMap<String, CacheEntry>>>,
    // S-3 fix: issuer secrets are long-term key material held for the life of the
    // process — wrapped in `Zeroizing` so a value is cleared from heap memory
    // the moment it's overwritten (`register_issuer_key` re-registration),
    // removed (`clear_trusted_issuers`/`revoke_all_tokens`), or the map itself
    // is dropped, rather than lingering for forensic recovery (core dump, cold
    // boot attack, use-after-free in unrelated code).
    trusted_issuer_keys: Mutex<HashMap<String, Zeroizing<Vec<u8>>>>,
    /// Read-mostly scalars, published as one consistent snapshot — see
    /// [`GatewayEpochs`] for why these must not be independent atomics.
    epochs: arc_swap::ArcSwap<GatewayEpochs>,
    /// Serializes WRITERS to `epochs` only; never taken on the read path.
    ///
    /// Every mutation is read-modify-write (`epoch += 1`), which `ArcSwap`
    /// cannot make atomic on its own. Writes are rare (key registration,
    /// revocation, admin config), so a plain mutex around them costs nothing on
    /// the hot path while preventing two concurrent revocations from both
    /// reading epoch N and both publishing N+1 — which would leave cached
    /// verdicts from the first revocation looking current.
    epoch_write_lock: Mutex<()>,
    /// T3.1 — TrustStore integration (FAITF identity verification)
    trust_store: arc_swap::ArcSwapOption<TrustStore>,
    /// T3.2 — ACSVAF capability verification authority
    capability_authority: arc_swap::ArcSwapOption<CapabilityVerificationAuthority>,
}

impl ZeroTrustGateway {
    pub fn new() -> Self {
        Self {
            revoked_tokens: (0..REVOKED_TOKENS_SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            token_cache: (0..TOKEN_CACHE_SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
            trusted_issuer_keys: Mutex::new(HashMap::new()),
            epochs: arc_swap::ArcSwap::from_pointee(GatewayEpochs {
                strict_asymmetric_mode: false,
                revocation_epoch: 0,
                issuer_registry_epoch: 0,
                blanket_revoked_before: 0.0,
                cache_generation: 0,
            }),
            epoch_write_lock: Mutex::new(()),
            trust_store: arc_swap::ArcSwapOption::empty(),
            capability_authority: arc_swap::ArcSwapOption::empty(),
        }
    }

    /// Process-wide ZeroTrustGateway singleton used as fallback when no gateway is injected.
    /// Provides a shared revocation list and cache so that revocations performed via the
    /// global gateway are honoured by stream-continuation checks even without a per-call
    /// gateway reference.
    pub fn global() -> &'static ZeroTrustGateway {
        static GLOBAL_ZTG: LazyLock<ZeroTrustGateway> =
            LazyLock::new(ZeroTrustGateway::new);
        &GLOBAL_ZTG
    }

    /// When true, HMAC-PSK tokens are rejected outright.
    ///
    /// Lock and return the token-cache shard responsible for `cache_key`.
    fn token_cache_shard(&self, cache_key: &str) -> std::sync::MutexGuard<'_, HashMap<String, CacheEntry>> {
        let idx = crate::shard::fnv1a_shard(cache_key, TOKEN_CACHE_SHARDS);
        self.token_cache[idx].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Drop every cached verdict.
    ///
    /// Reclamation only — correctness comes from the `cache_generation` bump in
    /// `update_epochs`, which every caller of this method performs. Deliberately
    /// takes one shard lock at a time rather than all 16 at once: a torn clear
    /// is harmless here (stale entries are already unreachable by generation),
    /// whereas holding 16 locks simultaneously would be a lock-ordering hazard.
    fn clear_token_cache(&self) {
        for shard in &self.token_cache {
            shard.lock().unwrap_or_else(|e| e.into_inner()).clear();
        }
    }

    /// Atomically read-modify-write the epoch snapshot.
    ///
    /// `mutate` receives a copy of the current snapshot and adjusts whichever
    /// fields the caller owns; the result is published as one unit. The write
    /// lock makes the read-modify-write indivisible, so two concurrent
    /// revocations cannot both observe epoch N and both publish N+1.
    ///
    /// `cache_generation` is bumped here unconditionally, because every caller of
    /// this helper is an event that invalidates cached token verdicts. That makes
    /// cache invalidation a single atomic publish — see `token_cache_valid`.
    fn update_epochs(&self, mutate: impl FnOnce(&mut GatewayEpochs)) {
        let _w = self.epoch_write_lock.lock().unwrap_or_else(|e| e.into_inner());
        let mut next = (**self.epochs.load()).clone();
        next.cache_generation = next.cache_generation.wrapping_add(1);
        mutate(&mut next);
        self.epochs.store(Arc::new(next));
    }

    /// M-38 fix: every lock in this impl block recovers via `into_inner()` on
    /// poison rather than panicking (`.unwrap()`) — `ZeroTrustGateway::global()`
    /// is a process-wide singleton, so one poisoning panic must not cascade
    /// into every other in-flight packet losing token validation/revocation
    /// entirely.
    pub fn set_strict_asymmetric_mode(&self, enabled: bool) {
        self.update_epochs(|e| e.strict_asymmetric_mode = enabled);
        self.clear_token_cache();
    }

    /// T3.1 — Register a FAITF TrustStore for identity verification.
    pub fn register_trust_store(&self, ts: Arc<TrustStore>) {
        self.trust_store.store(Some(ts));
        self.update_epochs(|_| {});
        self.clear_token_cache();
    }

    /// T3.2 — Register an ACSVAF CapabilityVerificationAuthority.
    pub fn register_capability_authority(&self, ca: Arc<CapabilityVerificationAuthority>) {
        self.capability_authority.store(Some(ca));
        self.update_epochs(|_| {});
        self.clear_token_cache();
    }

    /// Register the canonical token-signing key for a trusted issuer.
    /// T3.8: validates non-empty agent string and exactly 32-byte secret.
    pub fn register_issuer_key(&self, issuer_agent: &str, issuer_secret: &[u8]) -> Result<(), SAACPHardDrop> {
        if issuer_agent.trim().is_empty() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                "register_issuer_key: issuer_agent must be non-empty",
            ));
        }
        // SECURITY: reject null bytes in agent IDs to prevent string-termination bypass
        // in downstream comparisons (e.g. "agent\x00" == "agent" in C-style matching).
        if issuer_agent.contains('\0') {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                "register_issuer_key: issuer_agent must not contain null bytes",
            ));
        }
        if issuer_secret.len() != 32 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                format!("register_issuer_key: secret must be exactly 32 bytes, got {}", issuer_secret.len()),
            ));
        }
        {
            let mut keys = self.trusted_issuer_keys.lock().unwrap_or_else(|e| e.into_inner());
            // L-9 fix: reject growing past the cap for a genuinely NEW issuer — but
            // always allow re-registering (rotating the key of) an issuer already
            // tracked, since that never grows the map.
            if keys.len() >= MAX_TRUSTED_ISSUERS && !keys.contains_key(issuer_agent) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::RgcResourceLimitExceeded,
                    format!(
                        "register_issuer_key: at capacity ({MAX_TRUSTED_ISSUERS} trusted issuers); rejecting new issuer '{issuer_agent}'"
                    ),
                ));
            }
            keys.insert(issuer_agent.to_string(), Zeroizing::new(issuer_secret.to_vec()));
        }
        self.clear_token_cache();
        self.update_epochs(|e| e.issuer_registry_epoch += 1);
        Ok(())
    }

    /// Clear trusted issuer registry.
    pub fn clear_trusted_issuers(&self) {
        self.trusted_issuer_keys.lock().unwrap_or_else(|e| e.into_inner()).clear();
        self.clear_token_cache();
        self.update_epochs(|e| e.issuer_registry_epoch += 1);
    }

    /// Issue a capability token (HMAC-SHA256 path).
    /// T3.5/T3.6: sorted allow/forbid lists; supports thash field for ACSVAF compatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_capability_token(
        &self,
        issuer_secret: &[u8],
        issuer_agent: &str,
        allowed_agents: &[&str],
        forbidden_agents: &[&str],
        ttl_seconds: u64,
        root_intent_hash: Option<&str>,
        max_action_class: u8,
        thash: Option<&str>,
    ) -> Vec<u8> {
        // f64→u64: epoch seconds always positive, fractional part discarded intentionally.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let iat = now_epoch_secs() as u64;
        let expiry = iat + ttl_seconds;

        let mut token_data = HashMap::new();
        token_data.insert("iss".into(), serde_json::Value::String(issuer_agent.into()));
        // H-2 fix: `iat` claim feeds the blanket-revocation check in
        // `validate_lateral_movement` (`blanket_revoked_before`).
        token_data.insert("iat".into(), serde_json::Value::Number(iat.into()));
        token_data.insert("exp".into(), serde_json::Value::Number(expiry.into()));
        // T3.6: sort lists for deterministic cross-language HMAC
        token_data.insert("allow".into(), sorted_str_array(allowed_agents));
        token_data.insert("forbid".into(), sorted_str_array(forbidden_agents));
        token_data.insert("max_action_class".into(), serde_json::Value::Number(max_action_class.into()));
        if let Some(rih) = root_intent_hash {
            token_data.insert("root_intent_hash".into(), serde_json::Value::String(rih.into()));
        }
        // T3.4: thash alias for ACSVAF transcript binding
        if let Some(th) = thash {
            token_data.insert("thash".into(), serde_json::Value::String(th.into()));
        }

        let token_json = serialize_sorted_json(&token_data);
        let signature = hmac_sha256(issuer_secret, &token_json);

        // SECURITY: validate json_len fits in u32 before packing into the 4-byte wire field.
        let json_len = u32::try_from(token_json.len()).unwrap_or(u32::MAX);
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&json_len.to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);

        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
    }

    /// Lock and return the shard responsible for `sig_hash`.
    ///
    /// M-38 fix: recovers via `into_inner()` on poison rather than panicking —
    /// `ZeroTrustGateway::global()` is a process-wide singleton, so one
    /// poisoning panic must not cascade into every other in-flight packet
    /// losing revocation enforcement entirely.
    fn revoked_shard(&self, sig_hash: &str) -> std::sync::MutexGuard<'_, HashMap<String, f64>> {
        self.revoked_tokens[revoked_token_shard_index(sig_hash)].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Revoke a token by adding its signature hash to the revocation set.
    ///
    /// S-2 fix: records the token's own `exp` (epoch seconds) as the entry value
    /// so `prune_expired_revocations` can later reclaim it — an expired token is
    /// already rejected by Gate 1.0's expiry check, so keeping its revocation
    /// entry past `exp` serves no protective purpose. After inserting, enforces
    /// `REVOKED_TOKENS_MAX` (prune-then-evict-oldest) so a flood of revocations
    /// can never grow this set without bound.
    pub fn revoke_token(&self, token_b64: &[u8]) -> Result<(), String> {
        let (token_json, signature) = parse_token_wire(token_b64)
            .map_err(|e| format!("Token revocation failed: {}", e))?;
        if signature.is_empty() {
            return Err("Token has no signature to revoke.".into());
        }
        // Extract the token's `exp` claim (epoch seconds) so the revocation entry
        // inherits the token's own expiry deadline. A token with no parseable
        // `exp` (malformed/legacy wire form) falls back to a fixed TTL from now so
        // it still eventually becomes eligible for eviction rather than pinning
        // its shard forever.
        let exp = serde_json::from_slice::<serde_json::Value>(&token_json)
            .ok()
            .and_then(|v| v.get("exp").and_then(|e| e.as_f64()))
            .unwrap_or_else(|| now_epoch_secs() + REVOKED_TOKENS_FALLBACK_TTL);
        let sig_hash = sha256_hex(&signature);
        {
            let mut shard = self.revoked_shard(&sig_hash);
            shard.insert(sig_hash, exp);
        }
        self.enforce_revoked_tokens_cap();
        self.clear_token_cache();
        self.update_epochs(|e| e.revocation_epoch += 1);
        Ok(())
    }

    /// S-2 fix: remove revocation entries whose bound token has already expired.
    /// Returns the number of entries pruned. Safe because an expired token can
    /// never pass Gate 1.0's own `exp` check, so its revocation record is dead
    /// weight past that point. Intended to be called periodically from
    /// `MaintenanceCoordinator` (wired in both bin entrypoints) and opportunistically
    /// from `enforce_revoked_tokens_cap`.
    pub fn prune_expired_revocations(&self) -> usize {
        let now = now_epoch_secs();
        let mut pruned = 0usize;
        for shard in &self.revoked_tokens {
            let mut map = shard.lock().unwrap_or_else(|e| e.into_inner());
            let before = map.len();
            map.retain(|_, &mut exp| now < exp);
            pruned += before - map.len();
        }
        pruned
    }

    /// Current aggregate number of individually-revoked tokens across all shards
    /// (for monitoring / tests).
    pub fn revoked_tokens_len(&self) -> usize {
        self.revoked_tokens
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len())
            .sum()
    }

    /// S-2 fix: enforce `REVOKED_TOKENS_MAX`. First prunes expired entries; if the
    /// aggregate is still over cap, evicts lowest-`exp` (soonest-to-expire, hence
    /// least-valuable) entries until back under cap. Cheap on the common path: the
    /// aggregate count is checked first and the expensive global sort only runs in
    /// the pathological over-cap case.
    fn enforce_revoked_tokens_cap(&self) {
        if self.revoked_tokens_len() <= REVOKED_TOKENS_MAX {
            return;
        }
        self.prune_expired_revocations();
        let total = self.revoked_tokens_len();
        if total <= REVOKED_TOKENS_MAX {
            return;
        }
        // Still over cap after pruning: gather every (exp, sig_hash) and evict the
        // lowest-exp entries. This is O(n log n) but only reached when >100k
        // far-future-exp tokens are actively revoked — a degenerate case.
        let mut all: Vec<(f64, String)> = Vec::with_capacity(total);
        for shard in &self.revoked_tokens {
            let map = shard.lock().unwrap_or_else(|e| e.into_inner());
            for (hash, &exp) in map.iter() {
                all.push((exp, hash.clone()));
            }
        }
        all.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        let evict_count = total - REVOKED_TOKENS_MAX;
        for (_, hash) in all.into_iter().take(evict_count) {
            self.revoked_shard(&hash).remove(&hash);
        }
    }

    /// Returns the current revocation epoch.
    pub fn get_revocation_epoch(&self) -> u64 {
        self.epochs.load().revocation_epoch
    }

    /// Check if a token signature hash is in the revocation set.
    pub fn is_token_revoked(&self, token_sig_hash: &str) -> bool {
        self.revoked_shard(token_sig_hash).contains_key(token_sig_hash)
    }

    /// PSK Compromise Recovery: revoke ALL tokens, flush ALL caches (M-6 fix).
    ///
    /// H-2 fix: this must NOT clear `revoked_tokens` — doing so silently
    /// un-revokes every token an operator individually revoked before the
    /// compromise event, a fail-open bug. Instead it records a blanket
    /// revocation timestamp (`blanket_revoked_before`): any token issued
    /// (`iat`) before this moment is rejected on next validation regardless
    /// of whether its specific signature hash is in `revoked_tokens`.
    pub fn revoke_all_tokens(&self) -> u64 {
        // Floored to whole seconds to match `iat`'s granularity (tokens embed
        // `iat` as a `u64`) — comparing a fractional timestamp against a
        // floored one could spuriously reject a token issued in the same
        // wall-clock second as this call, after it.
        //
        // All three fields are published in ONE swap. This is the site that
        // makes the snapshot mandatory: with independent atomics a concurrent
        // packet could see the bumped `revocation_epoch` (so its cache key looks
        // current) while still reading the pre-recovery `blanket_revoked_before`
        // of 0.0, and admit a token this call was meant to revoke — during PSK
        // compromise recovery, which is exactly when that must not happen.
        let now = now_epoch_secs().floor();
        self.clear_token_cache();
        self.trusted_issuer_keys.lock().unwrap_or_else(|e| e.into_inner()).clear();
        let mut new_epoch = 0;
        self.update_epochs(|e| {
            e.blanket_revoked_before = now;
            e.revocation_epoch += 1;
            e.issuer_registry_epoch += 1;
            new_epoch = e.revocation_epoch;
        });
        new_epoch
    }

    /// Evaluate the token before allowing lateral movement.
    ///
    /// HMAC-PSK path: verifies signature, checks expiry, allow/forbid lists.
    pub fn validate_lateral_movement(
        &self,
        target_agent: &str,
        token_b64: &[u8],
        issuer_secret: &[u8],
    ) -> Result<TokenValidationResult, SAACPHardDrop> {
        let now = now_epoch_secs();
        let fallback_key_hash = sha256_hex(issuer_secret);
        // ONE load for the whole validation. Every epoch/config field this
        // function consults comes from this single consistent snapshot, so no
        // interleaving with a concurrent `revoke_all_tokens` can produce a mixed
        // view (new epoch + stale blanket-revocation timestamp) that would admit
        // a token that should have been rejected.
        let epochs = self.epochs.load();
        let registry_epoch = epochs.issuer_registry_epoch;
        let revocation_epoch = epochs.revocation_epoch;

        // Hash the token before using it as a cache key — never store the plaintext
        // capability token in a data structure that could be heap-dumped or logged.
        let token_hash = sha256_hex(token_b64);
        let cache_key = format!(
            "{}:{}:{}:{}:{}",
            target_agent,
            token_hash,
            fallback_key_hash,
            registry_epoch,
            revocation_epoch,
        );

        // Check cache. An entry is usable only if it is unexpired AND was
        // computed under the CURRENT cache generation — a stale generation means
        // a revocation or key-registry change has happened since, so the cached
        // verdict is treated as absent regardless of whether the physical
        // clear-out has reached this shard yet.
        {
            let cache = self.token_cache_shard(&cache_key);
            if let Some(entry) = cache.get(&cache_key) {
                if now < entry.expiry && entry.generation == epochs.cache_generation {
                    return Ok(entry.result.clone());
                }
            }
        }

        // Parse token
        let (token_json, signature) = parse_token_wire(token_b64)?;

        // Parse JSON
        let data: serde_json::Value = serde_json::from_slice(&token_json).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "Missing or malformed Capability Token.",
            )
        })?;
        let obj = data.as_object().ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "Token payload must be a JSON object.",
            )
        })?;

        // Check revocation
        let sig_hash = sha256_hex(&signature);
        if self.revoked_shard(&sig_hash).contains_key(&sig_hash) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "Capability Token has been REVOKED.",
            ));
        }

        let source_agent = obj
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown_Issuer")
            .to_string();

        let sig_alg = obj
            .get("_sig_alg")
            .and_then(|v| v.as_str())
            .unwrap_or("hmac-sha256");

        // Reject HMAC in strict mode
        if epochs.strict_asymmetric_mode && sig_alg != "ed25519" {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "HMAC-PSK tokens are rejected in strict asymmetric mode.",
            ));
        }

        // HMAC-SHA256 verification
        if sig_alg != "ed25519" {
            let trusted_keys = self.trusted_issuer_keys.lock().unwrap_or_else(|e| e.into_inner());
            let has_registry = !trusted_keys.is_empty();
            let trusted_secret = trusted_keys.get(&source_agent).cloned();
            drop(trusted_keys);

            if has_registry && trusted_secret.is_none() {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Capability Token issuer is not trusted.",
                ));
            }

            // When no registry is configured, require an explicit secret of at least 32 bytes
            // to prevent acceptance of default/empty keys by callers that omit the parameter.
            if !has_registry && issuer_secret.len() < 32 {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "HMAC fallback requires at least a 32-byte issuer_secret when no registry is configured.",
                ));
            }

            // S-3 fix: both the resolved signing secret and the resulting MAC tag are
            // ephemeral, function-local copies of security-sensitive material — wrap
            // in `Zeroizing` so they're cleared from heap memory as soon as they go
            // out of scope, rather than lingering for forensic recovery.
            let verification_secret: Zeroizing<Vec<u8>> =
                trusted_secret.unwrap_or_else(|| Zeroizing::new(issuer_secret.to_vec()));
            let expected_sig: Zeroizing<Vec<u8>> =
                Zeroizing::new(hmac_sha256(&verification_secret, &token_json));
            if !constant_time_eq(&expected_sig, &signature) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Capability Token has been tampered with!",
                ));
            }
        } else {
            // Ed25519 (asymmetric) verification path. SECURITY (I-1/I-10 fail-closed):
            // previously this branch did NOTHING — a token declaring
            // `_sig_alg: "ed25519"` skipped the HMAC block above and reached the
            // authorization checks with its signature never verified, so any
            // attacker-supplied signature was accepted. Worse, `strict_asymmetric_mode`
            // *forces* every token onto this branch, so enabling "strict" security
            // actually disabled signature verification entirely. The token's
            // `kid` claim selects the issuer's registered verifying key from the
            // `CapabilityVerificationAuthority` wired via `register_capability_authority`;
            // as a fallback, the issuer's identity-pinned key in a registered FAITF
            // `TrustStore` (wired via `register_trust_store`, T3.1) is accepted too.
            // Absence of both key sources, an unknown kid/issuer, a missing kid, or a
            // bad signature all reject.
            let kid = obj.get("kid").and_then(|v| v.as_str()).ok_or_else(|| {
                SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Ed25519 capability token is missing its 'kid' claim.",
                )
            })?;
            let ca = self.capability_authority.load_full();
            let ca_key = ca.and_then(|ca| ca.get_verification_key(kid));
            let vk = match ca_key {
                Some(vk) => vk,
                None => {
                    // Fallback: FAITF TrustStore identity-pinned key for this issuer.
                    let ts = self.trust_store.load_full();
                    match ts.and_then(|ts| ts.get_pinned_key(&source_agent)) {
                        Some(vk) => vk,
                        None => {
                            return Err(SAACPHardDrop::new(
                                SAACPBytecodes::AcsvafKeyNotTrusted,
                                format!(
                                    "Ed25519 capability token kid '{kid}' (issuer '{source_agent}') \
                                     is not a trusted key in either the CapabilityVerificationAuthority \
                                     or the FAITF TrustStore. Register one via \
                                     register_capability_authority / register_trust_store (fail-closed).",
                                ),
                            ));
                        }
                    }
                }
            };
            verify_ed25519_signature_inner(&token_json, &signature, vk.as_bytes())?;
        }

        // H-2 fix: blanket, epoch-based rejection for PSK compromise recovery.
        // `revoke_all_tokens()` no longer clears `revoked_tokens` (that would
        // silently un-revoke every individually-revoked token) and instead
        // records the recovery timestamp in `blanket_revoked_before`. Any
        // token whose `iat` predates the last blanket revocation is rejected
        // here, covering tokens that were never individually enumerated in
        // `revoked_tokens`. A token missing `iat` (pre-fix wire format) is
        // treated as issued at time 0 — fail-closed once any blanket
        // revocation has occurred.
        let blanket_revoked_before = epochs.blanket_revoked_before;
        if blanket_revoked_before > 0.0 {
            let iat = obj.get("iat").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
            if iat < blanket_revoked_before {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::LateralMovementBlocked,
                    "Capability Token was issued before the most recent PSK compromise revocation.",
                ));
            }
        }

        // Check expiry
        let exp = obj.get("exp").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
        if now_epoch_secs() > exp {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "Capability Token EXPIRED.",
            ));
        }

        // Check forbidden list — H-4 fix: HashSet for O(1) lookup, no timing side-channel.
        // Vec::contains() is O(n) and short-circuits on first differing byte, leaking
        // information about which forbidden agents share a prefix with the target.
        let forbid: HashSet<&str> = obj
            .get("forbid")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if forbid.contains(target_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                format!("Strictly forbidden from calling {}.", target_agent),
            ));
        }

        // Check allowed list — H-4 fix: HashSet for O(1) lookup.
        let allow: HashSet<&str> = obj
            .get("allow")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !allow.contains(target_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScopeViolation,
                format!("Scope violation: '{}' is not in the allowed scope list.", target_agent),
            ));
        }

        // H-2 fix: Self-issue guard for the HMAC-PSK path.
        // DelegationGuard exists but was never wired into validate_lateral_movement.
        // A token where iss == target_agent grants an agent permission to call itself,
        // which is semantically identical to no authorization check at all.
        if source_agent == target_agent {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SelfIssuedCapability,
                format!(
                    "Self-issued lateral movement rejected: '{}' cannot authorize itself.",
                    source_agent
                ),
            ));
        }

        // T3.4: thash alias — treat "thash" as equivalent to "root_intent_hash"
        let root_intent_hash = obj
            .get("root_intent_hash")
            .or_else(|| obj.get("thash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // SECURITY: validate max_action_class fits in u8 before casting.
        // A value > 255 silently truncating could grant higher privilege than intended
        // (e.g. 0x102 → 0x02 = IRREVERSIBLE when only 0x01 was intended).
        let mac_raw = obj
            .get("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if mac_raw > u8::MAX as u64 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                format!("max_action_class value {mac_raw} exceeds valid range 0–255"),
            ));
        }
        let max_action_class = mac_raw as u8;

        // delegation_depth claim (feeds Trust Decay Engine / Gate 1.5 per-hop
        // tightening, and is itself now an authorization gate): the live
        // packet-processing path previously treated this claim as
        // informational-only, defaulting to 0 on anything absent or invalid,
        // while the separate (not-live-wired) ACSVAF token system enforced
        // ACSVAF_MAX_DELEGATION_DEPTH on its own, different token type. A
        // compromised agent holding the shared HMAC issuer secret could mint
        // a token claiming an arbitrarily deep delegation chain and it would
        // pass Gate 1.0 unchecked. Now rejects when the claim is present but
        // non-numeric, out of u32 range, or exceeds the max. An absent claim
        // still defaults to 0 — no regression for legacy tokens that never
        // set this field.
        let delegation_depth = match obj.get("delegation_depth") {
            None => 0,
            Some(v) => {
                let raw = v.as_u64().ok_or_else(|| SAACPHardDrop::new(
                    SAACPBytecodes::DelegationRejected,
                    "delegation_depth claim present but not a non-negative integer.",
                ))?;
                let depth = u32::try_from(raw).map_err(|_| SAACPHardDrop::new(
                    SAACPBytecodes::DelegationRejected,
                    format!("delegation_depth value {raw} exceeds valid u32 range."),
                ))?;
                if depth > ACSVAF_MAX_DELEGATION_DEPTH {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::DelegationRejected,
                        format!(
                            "delegation_depth {depth} exceeds max {ACSVAF_MAX_DELEGATION_DEPTH} \
                             on the live capability-token path.",
                        ),
                    ));
                }
                depth
            }
        };

        let result = TokenValidationResult {
            is_valid: true,
            source_agent,
            root_intent_hash,
            max_action_class,
            delegation_depth,
            token_sig_hash: sig_hash,
        };

        // T3.7: eviction — drop expired first, then soonest-expiring 20% if still full.
        // SECURITY FIX: The previous code used `.keys().take(n)` which iterates in
        // HashMap's internal (process-deterministic) order.  An attacker observing which
        // tokens survive eviction could time requests to prevent a compromised token from
        // being evicted, extending its effective validity window.  Evicting soonest-expiring
        // entries is deterministic (based on content, not iteration order) and correct:
        // entries closest to natural expiry provide the least residual value anyway.
        //
        // Now applied PER SHARD against `TOKEN_CACHE_PER_SHARD_MAX`, so eviction
        // touches one lock instead of the whole cache. Keys spread evenly
        // (`shard::fnv1a_shard`), so the aggregate bound still tracks
        // `TOKEN_CACHE_MAX`.
        let cache_expiry = (now_epoch_secs() + TOKEN_CACHE_TTL).min(exp);
        let mut cache = self.token_cache_shard(&cache_key);
        if cache.len() >= TOKEN_CACHE_PER_SHARD_MAX {
            let current_time = now_epoch_secs();
            // First pass: drop already-expired entries, and any left over from a
            // superseded generation (free, no ordering needed).
            cache.retain(|_, v| {
                v.expiry > current_time && v.generation == epochs.cache_generation
            });
            // Second pass: if still at/above capacity, evict the 20% soonest to expire.
            if cache.len() >= TOKEN_CACHE_PER_SHARD_MAX {
                let evict_count = TOKEN_CACHE_PER_SHARD_MAX / 5;
                let mut by_expiry: Vec<(String, f64)> = cache
                    .iter()
                    .map(|(k, v)| (k.clone(), v.expiry))
                    .collect();
                // Sort ascending by expiry — soonest-expiring entries first.
                by_expiry.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                for (k, _) in by_expiry.into_iter().take(evict_count) {
                    cache.remove(&k);
                }
            }
        }
        cache.insert(cache_key, CacheEntry {
            expiry: cache_expiry,
            result: result.clone(),
            generation: epochs.cache_generation,
        });

        Ok(result)
    }
}

// ---------------------------------------------------------------------------
// Module-level Ed25519 verification helper (shared by ZeroTrustGateway + RRBCGateway)
// ---------------------------------------------------------------------------

fn verify_ed25519_signature_inner(
    token_json: &[u8],
    signature: &[u8],
    pub_key_bytes: &[u8],
) -> Result<(), SAACPHardDrop> {
    if pub_key_bytes.len() != 32 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 public key must be 32 bytes",
        ));
    }
    if signature.len() != 64 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 signature must be 64 bytes",
        ));
    }
    let pub_key_arr: [u8; 32] = pub_key_bytes.try_into().map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 public key internal conversion failed (unexpected length)",
        )
    })?;
    let vk = VerifyingKey::from_bytes(&pub_key_arr)
        .map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Invalid Ed25519 public key bytes",
        ))?;
    let sig_arr: [u8; 64] = signature.try_into().map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 signature internal conversion failed (unexpected length)",
        )
    })?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(token_json, &sig)
        .map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 signature verification failed",
        ))
}

impl Default for ZeroTrustGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DelegationGuard
// ---------------------------------------------------------------------------

/// Prevents cascading token delegation.
pub struct DelegationGuard;

impl DelegationGuard {
    /// Validates the token is signed by the root orchestrator key.
    pub fn validate_not_self_signed(
        token_b64: &[u8],
        root_secret: &[u8],
    ) -> Result<(), SAACPHardDrop> {
        let (token_json, signature) = {
            let raw = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                token_b64,
            )
            .map_err(|_| SAACPHardDrop::new(
                SAACPBytecodes::DelegationRejected,
                "Delegation attempt with malformed token structure.",
            ))?;
            if raw.len() < 4 {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::DelegationRejected,
                    "Delegation attempt with malformed token structure.",
                ));
            }
            let json_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
            // SECURITY FIX (BUFFER-SAFETY): `json_len` is an attacker-controlled
            // 4-byte length prefix. `parse_token_wire` (this file) already
            // bounds-checks it (`json_len == 0 || json_len > raw.len().saturating_sub(4)`)
            // before slicing — this sibling function used to skip that check
            // entirely, so a token claiming a JSON length larger than the bytes
            // actually present (e.g. a 4-byte token declaring a 65535-byte body)
            // panicked on `raw[4..4 + json_len]` ("range end index out of range
            // for slice") instead of returning a clean `SAACPHardDrop`. Apply the
            // exact same bound here.
            if json_len == 0 || json_len > raw.len().saturating_sub(4) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::DelegationRejected,
                    "Delegation attempt with malformed token structure.",
                ));
            }
            let tj = raw[4..4 + json_len].to_vec();
            let sig = raw[4 + json_len..].to_vec();
            (tj, sig)
        };

        let expected_sig = hmac_sha256(root_secret, &token_json);
        if !constant_time_eq(&expected_sig, &signature) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::DelegationRejected,
                "DELEGATION REJECTED: Token is not signed by the root orchestrator key.",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RRBC (Replay-Resistant Bound Capabilities)
// ---------------------------------------------------------------------------

/// Result of a successful RRBC token redemption.
#[derive(Debug, Clone)]
pub struct RRBCRedemptionResult {
    pub jti: String,
    pub issuer_agent: String,
    pub allowed_agents: Vec<String>,
    pub forbidden_agents: Vec<String>,
    pub actions: Vec<String>,
    pub audience: Vec<String>,
    pub sid: String,
    pub cid: String,
    pub oaid: String,
    pub remaining_uses: i64,
    pub max_action_class: u8,
}

#[allow(dead_code)]
struct RRBCTokenRecord {
    data: serde_json::Value,
    remaining: i64,
    revoked: bool,
}

/// TTL for replay-registry entries: entries are kept until the bound token expires
/// (the token's own `exp` field), after which they can never be replayed anyway.
/// Hard cap prevents OOM if exp values are far in the future.
pub const RRBC_REPLAY_REGISTRY_MAX: usize = 500_000;

/// Replay-Resistant Bound Capabilities gateway.
pub struct RRBCGateway {
    /// Maps (jti, rnonce, sid) → token_exp_timestamp.
    /// Entries are pruned once now() > token_exp (replay is impossible then anyway).
    /// SECURITY FIX (RRBC-OOM): previously stored `i64` (count) with no eviction,
    /// growing without bound under sustained load.
    replay_registry: Mutex<HashMap<(String, String, String), f64>>,
    tokens: Mutex<HashMap<String, RRBCTokenRecord>>,
    revoked_jtis: Mutex<HashSet<String>>,
}

impl RRBCGateway {
    pub fn new() -> Self {
        Self {
            replay_registry: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            revoked_jtis: Mutex::new(HashSet::new()),
        }
    }

    /// Issue an RRBC token (HMAC-SHA256 path).
    ///
    /// `pop_verifying_key`: if `Some`, embeds the Ed25519 public key (32 raw bytes)
    /// in the token so that `redeem_token` enforces proof-of-possession (spec §8.2 step 4).
    #[allow(clippy::too_many_arguments)]
    pub fn issue_token(
        &self,
        issuer_secret: &[u8],
        issuer_agent: &str,
        allowed_agents: &[&str],
        forbidden_agents: &[&str],
        actions: &[&str],
        audience: &[&str],
        sid: &str,
        cid: &str,
        oaid: &str,
        max_use: i64,
        ttl_seconds: u64,
        max_action_class: u8,
        pop_verifying_key: Option<&[u8]>,
    ) -> Vec<u8> {
        let now = now_epoch_secs();
        let jti = uuid::Uuid::new_v4().to_string().replace('-', "");
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let iat = now as u64;
        let exp = iat + ttl_seconds;

        let mut token_data = serde_json::Map::new();
        token_data.insert("jti".into(), serde_json::Value::String(jti.clone()));
        token_data.insert("iat".into(), serde_json::json!(iat));
        token_data.insert("nbf".into(), serde_json::json!(iat));
        token_data.insert("exp".into(), serde_json::json!(exp));
        token_data.insert("iss".into(), serde_json::Value::String(issuer_agent.into()));
        token_data.insert(
            "aud".into(),
            serde_json::Value::Array(audience.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert("sid".into(), serde_json::Value::String(sid.into()));
        token_data.insert("cid".into(), serde_json::Value::String(cid.into()));
        token_data.insert("oaid".into(), serde_json::Value::String(oaid.into()));
        token_data.insert(
            "actions".into(),
            serde_json::Value::Array(actions.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert(
            "allow".into(),
            serde_json::Value::Array(allowed_agents.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert(
            "forbid".into(),
            serde_json::Value::Array(forbidden_agents.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert("max_use".into(), serde_json::json!(max_use));
        token_data.insert("max_action_class".into(), serde_json::json!(max_action_class));
        // PoP key embedded in token if provided (spec §8.2 step 4).
        // Absent = no PoP required; present = redeem_token enforces Ed25519 proof.
        if let Some(pop_key) = pop_verifying_key {
            use base64::Engine;
            let pop_key_b64 = base64::engine::general_purpose::STANDARD.encode(pop_key);
            token_data.insert("pop_key".into(), serde_json::Value::String(pop_key_b64));
        }

        let token_json = serde_json::to_vec(&serde_json::Value::Object(token_data)).unwrap_or_default();
        let signature = hmac_sha256(issuer_secret, &token_json);

        let json_len = u32::try_from(token_json.len()).unwrap_or(u32::MAX);
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&json_len.to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);

        // Register token
        let data: serde_json::Value = serde_json::from_slice(&token_json).unwrap_or(serde_json::Value::Null);
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.tokens.lock().unwrap().insert(jti, RRBCTokenRecord {
            data,
            remaining: max_use,
            revoked: false,
        });

        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
    }

    /// Redeem a single use of an RRBC token (spec §8.2).
    ///
    /// `pop_proof`: Ed25519 signature (64 bytes) over `rnonce.as_bytes()` made
    /// with the presenter's private key, required when the token contains a
    /// `pop_key` field (spec §8.2 step 4).  Pass `None` when no PoP was
    /// requested at issuance.
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_token(
        &self,
        token_b64: &[u8],
        rnonce: &str,
        presenting_agent: &str,
        presenting_sid: &str,
        presenting_cid: &str,
        presenting_oaid: &str,
        issuer_secret: &[u8],
    ) -> Result<RRBCRedemptionResult, SAACPHardDrop> {
        self.redeem_token_with_pop(
            token_b64, rnonce, presenting_agent,
            presenting_sid, presenting_cid, presenting_oaid,
            issuer_secret, None,
        )
    }

    /// Redeem with optional Ed25519 proof-of-possession (spec §8.2 step 4).
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_token_with_pop(
        &self,
        token_b64: &[u8],
        rnonce: &str,
        presenting_agent: &str,
        presenting_sid: &str,
        presenting_cid: &str,
        presenting_oaid: &str,
        issuer_secret: &[u8],
        pop_proof: Option<&[u8]>,
    ) -> Result<RRBCRedemptionResult, SAACPHardDrop> {
        // Parse token
        let (token_json, signature) = parse_token_wire(token_b64).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Missing or malformed capability token.",
            )
        })?;

        // Verify HMAC — SECURITY: must compare full-length signatures.
        // Truncated comparison (e.g. signature[..N]) allows a 1-byte signature
        // to pass if its first byte matches the expected HMAC output.
        // S-3 fix: the MAC tag is ephemeral security-sensitive material — wrap in
        // `Zeroizing` so it's cleared from heap memory as soon as it goes out of scope.
        let expected_sig: Zeroizing<Vec<u8>> = Zeroizing::new(hmac_sha256(issuer_secret, &token_json));
        if signature.len() != expected_sig.len()
            || !constant_time_eq(&expected_sig, &signature)
        {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "RRBC: Capability token signature verification failed.",
            ));
        }

        // Parse JSON
        let data: serde_json::Value = serde_json::from_slice(&token_json).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Malformed token payload.",
            )
        })?;
        let obj = data.as_object().ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Token payload must be a JSON object.",
            )
        })?;

        let jti = obj.get("jti").and_then(|v| v.as_str()).unwrap_or("").to_string();

        // Revocation check
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        if self.revoked_jtis.lock().unwrap().contains(&jti) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Token has been revoked.",
            ));
        }

        // Temporal validity
        let now = now_epoch_secs();
        let nbf = obj.get("nbf").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let exp = obj.get("exp").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if now < nbf {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "RRBC: Token not yet valid (nbf constraint).",
            ));
        }
        if now > exp {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "RRBC: Capability token has expired.",
            ));
        }

        // Binding checks
        let token_sid = obj.get("sid").and_then(|v| v.as_str()).unwrap_or("");
        let token_cid = obj.get("cid").and_then(|v| v.as_str()).unwrap_or("");
        let token_oaid = obj.get("oaid").and_then(|v| v.as_str()).unwrap_or("");

        if presenting_sid != token_sid
            || presenting_cid != token_cid
            || presenting_oaid != token_oaid
        {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RrbcBindingMismatch,
                "RRBC: Token binding mismatch (sid/cid/oaid).",
            ));
        }

        // Audience check
        let aud: Vec<&str> = obj
            .get("aud")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !aud.contains(&presenting_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScopeViolation,
                format!("RRBC: Agent '{}' not in token audience.", presenting_agent),
            ));
        }

        // Replay protection
        let replay_key = (jti.clone(), rnonce.to_string(), presenting_sid.to_string());
        {
            // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
            let mut registry = self.replay_registry.lock().unwrap();

            // TTL-based eviction: prune entries whose bound token has expired.
            // An expired token can never be replayed (it will fail the temporal check
            // above), so these entries provide zero replay-protection value.
            // This keeps the registry O(active_tokens) instead of O(all_time_uses).
            let current_time = now_epoch_secs();
            if registry.len() >= RRBC_REPLAY_REGISTRY_MAX / 2 {
                registry.retain(|_, &mut token_exp| current_time < token_exp);
            }
            // Hard cap: if still at limit after pruning, reject to prevent OOM.
            if registry.len() >= RRBC_REPLAY_REGISTRY_MAX {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::CircuitBreakerOpen,
                    "RRBC: Replay registry at capacity — rejecting to prevent OOM.",
                ));
            }

            if registry.contains_key(&replay_key) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::RrbcReplayDetected,
                    "RRBC: Replay detected — (jti, rnonce, sid) already consumed.",
                ));
            }
            // Store token_exp as the entry TTL so we know when it's safe to evict.
            registry.insert(replay_key, exp);
        }

        // Usage counter
        let remaining = {
            // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
            let mut tokens = self.tokens.lock().unwrap();
            if let Some(rec) = tokens.get_mut(&jti) {
                if rec.remaining <= 0 {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::RrbcUsageExhausted,
                        "RRBC: Token usage limit exhausted.",
                    ));
                }
                rec.remaining -= 1;
                rec.remaining
            } else {
                let max_use = obj.get("max_use").and_then(|v| v.as_i64()).unwrap_or(1);
                max_use - 1
            }
        };

        // Step 4 (spec §8.2): Proof-of-Possession verification.
        // If the token carries a pop_key field, the presenter MUST provide a
        // valid Ed25519 signature over `rnonce` bytes; absence of proof → RRBC_POP_FAILED.
        if let Some(pop_key_b64) = obj.get("pop_key").and_then(|v| v.as_str()) {
            let pop_key_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                pop_key_b64.as_bytes(),
            ).map_err(|_| SAACPHardDrop::new(
                SAACPBytecodes::RrbcPopFailed,
                "RRBC PoP: invalid pop_key encoding in token.",
            ))?;
            let proof = pop_proof.ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::RrbcPopFailed,
                "RRBC PoP: token requires proof-of-possession but none was supplied.",
            ))?;
            // Verify Ed25519(pop_key, message=rnonce, sig=proof)
            verify_ed25519_signature_inner(rnonce.as_bytes(), proof, &pop_key_bytes)
                .map_err(|_| SAACPHardDrop::new(
                    SAACPBytecodes::RrbcPopFailed,
                    "RRBC PoP: Ed25519 proof-of-possession verification failed.",
                ))?;
        } else if pop_proof.is_some() {
            // Token does not require PoP but caller supplied a proof — reject to prevent
            // bypass attempts where a forged pop_key field is stripped but proof remains.
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RrbcPopFailed,
                "RRBC PoP: proof-of-possession supplied but token does not require it.",
            ));
        }

        let extract_strings = |key: &str| -> Vec<String> {
            obj.get(key)
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };

        // H-1 fix: validate max_action_class fits in u8 before casting, instead of
        // truncating out-of-range values to u8::MAX. The token JSON is attacker-visible
        // (only HMAC-signed, not encrypted), so a forged or tampered token could carry a
        // max_action_class > 255. Falling back to u8::MAX on overflow was a fail-open bug:
        // it silently granted the *highest* possible action class (IRREVERSIBLE) instead
        // of rejecting. Mirrors the pattern already used in
        // `ZeroTrustGateway::validate_lateral_movement` above.
        let mac_raw = obj.get("max_action_class").and_then(|v| v.as_u64()).unwrap_or(0);
        if mac_raw > u8::MAX as u64 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ActionClassEscalation,
                format!(
                    "RRBC: max_action_class value {mac_raw} exceeds valid range 0-255 (rejected, not truncated)."
                ),
            ));
        }
        let max_action_class = mac_raw as u8;

        Ok(RRBCRedemptionResult {
            jti,
            issuer_agent: obj.get("iss").and_then(|v| v.as_str()).unwrap_or("").into(),
            allowed_agents: extract_strings("allow"),
            forbidden_agents: extract_strings("forbid"),
            actions: extract_strings("actions"),
            audience: extract_strings("aud"),
            sid: token_sid.into(),
            cid: token_cid.into(),
            oaid: token_oaid.into(),
            remaining_uses: remaining,
            max_action_class,
        })
    }

    /// Revoke a token by JTI.
    pub fn revoke_token(&self, jti: &str) {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut revoked = self.revoked_jtis.lock().unwrap();
        revoked.insert(jti.to_string());
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(rec) = tokens.get_mut(jti) {
            rec.revoked = true;
            rec.remaining = 0;
        }
    }

    /// Check if a JTI has been revoked.
    pub fn is_jti_revoked(&self, jti: &str) -> bool {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.revoked_jtis.lock().unwrap().contains(jti)
    }

    /// Return remaining uses for a JTI, or None if not in registry.
    pub fn get_remaining_uses(&self, jti: &str) -> Option<i64> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let tokens = self.tokens.lock().unwrap();
        tokens.get(jti).map(|rec| rec.remaining)
    }

    /// Clear all replay state. Returns count of cleared entries.
    pub fn clear_replay_registry(&self) -> usize {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut registry = self.replay_registry.lock().unwrap();
        let n = registry.len();
        registry.clear();
        n
    }

    /// Prune expired replay-registry entries (entries whose token_exp < now).
    /// Returns the count of pruned entries. Call periodically from a maintenance task.
    pub fn prune_expired_replay_entries(&self) -> usize {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut registry = self.replay_registry.lock().unwrap();
        let before = registry.len();
        let now = now_epoch_secs();
        registry.retain(|_, &mut token_exp| now < token_exp);
        before - registry.len()
    }

    /// Return the current size of the replay registry (for monitoring).
    pub fn replay_registry_size(&self) -> usize {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.replay_registry.lock().unwrap().len()
    }
}

impl Default for RRBCGateway {
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

    /// T28 — every shard must receive a roughly equal share of realistic agent
    /// IDs. Sharding exists to spread lock traffic; a shard function that maps a
    /// realistic workload onto one shard leaves the other 15 mutexes idle and
    /// silently reproduces the single-global-mutex behavior it was added to fix.
    ///
    /// `agent-0001`, `agent-0002`, ... is the naming convention this protocol's
    /// own tests, benchmarks, and docs use throughout, so it is the distribution
    /// that must be spread — not uniformly-random keys, which spread under any
    /// hash and therefore prove nothing.
    ///
    /// Tolerance is +/-10% of the ideal n/SHARDS. That is loose enough that no
    /// reasonable hash trips it and tight enough to catch a shard function that
    /// collapses onto a subset.
    #[test]
    fn t28_ratelimit_shard_index_distributes_realistic_agent_ids() {
        const N: usize = 16_000;
        let mut counts = vec![0usize; RATE_LIMITER_SHARDS];
        for i in 0..N {
            counts[ratelimit_shard_index(&format!("agent-{i:04}"))] += 1;
        }

        let ideal = N as f64 / RATE_LIMITER_SHARDS as f64;
        let (lo, hi) = (ideal * 0.9, ideal * 1.1);
        let live = counts.iter().filter(|&&c| c > 0).count();

        assert!(
            counts.iter().all(|&c| (c as f64) >= lo && (c as f64) <= hi),
            "shard distribution for realistic `agent-NNNN` ids is not even: {counts:?}\n\
             ideal {ideal:.0} per shard (+/-10% => {lo:.0}..={hi:.0}), \
             {live}/{} shards received any traffic.\n\
             A single-byte shard hash maps every `agent-*` key onto one shard, so \
             15 of 16 mutexes go unused and the hot path serializes exactly as it \
             did before sharding was introduced.",
            RATE_LIMITER_SHARDS,
        );
    }

    /// Companion to `t28_...`: even keys whose leading characters look "random"
    /// must reach every shard.
    ///
    /// This one is subtler than the `agent-NNNN` case and worth spelling out.
    /// Hex-encoded ids (fingerprints, session ids, hashes — used throughout this
    /// crate) begin with a character drawn from `[0-9a-f]`, whose ASCII codes are
    /// `0x30..=0x39` and `0x61..=0x66`. Under a shard function that hashes only
    /// the FIRST BYTE, `c % 16` maps that 16-character alphabet onto just ten
    /// residues (`'0'..'9'` -> 0..9, and `'a'..'f'` -> 1..6, colliding with the
    /// digits). Shards 10-15 are therefore **structurally unreachable**: no
    /// hex-prefixed key can ever land on them, no matter how much entropy the
    /// rest of the string carries.
    ///
    /// So "the keys are random" does NOT rescue a single-byte shard hash — the
    /// entropy has to be in the byte that is actually hashed.
    #[test]
    fn t28_hex_prefixed_keys_reach_every_shard() {
        const N: usize = 16_000;
        let mut counts = vec![0usize; RATE_LIMITER_SHARDS];
        for i in 0..N {
            // Hex-prefixed, like a key fingerprint or session id.
            let key = format!("{:08x}-agent", (i as u64).wrapping_mul(2_654_435_761));
            counts[ratelimit_shard_index(&key)] += 1;
        }

        let dead: Vec<usize> = counts.iter()
            .enumerate()
            .filter(|(_, &c)| c == 0)
            .map(|(i, _)| i)
            .collect();

        assert!(
            dead.is_empty(),
            "hex-prefixed keys never reach shards {dead:?}: {counts:?}\n\
             ASCII hex digits occupy only 0x30-0x39 and 0x61-0x66, so a shard \
             function that hashes just the first byte can only produce ten \
             distinct residues mod 16 — the remaining shards are unreachable by \
             construction, regardless of how random the rest of the key is.",
        );
    }

    #[test]
    fn test_rate_limiter_basic() {
        let rl = AgentRateLimiter::new();
        for _ in 0..4 {
            assert!(rl.record_error("agent1").is_ok());
        }
        // 5th error should trigger circuit breaker
        assert!(rl.record_error("agent1").is_err());
        assert!(rl.is_locked("agent1"));
    }

    #[test]
    fn test_rate_limiter_reset() {
        let rl = AgentRateLimiter::new();
        for _ in 0..5 {
            let _ = rl.record_error("agent1");
        }
        assert!(rl.is_locked("agent1"));
        rl.reset(Some("agent1"));
        assert!(!rl.is_locked("agent1"));
    }

    /// opusplan.md 6.4 item 1: `is_locked_at` must agree with `is_locked` — same
    /// answer whether the caller supplies `now` explicitly or lets `is_locked` capture
    /// it internally, since they're the same comparison against `locked_until`.
    #[test]
    fn is_locked_at_agrees_with_is_locked() {
        let rl = AgentRateLimiter::new();
        for _ in 0..5 {
            let _ = rl.record_error("agent1");
        }
        assert!(rl.is_locked("agent1"));

        let now = now_epoch_secs();
        assert!(rl.is_locked_at("agent1", now), "a `now` at the current instant must still read as locked");
        assert!(!rl.is_locked_at("agent1", now + RATE_LIMITER_LOCKOUT_SECONDS + 1.0),
            "a `now` far past the lockout window must read as unlocked");
        assert!(!rl.is_locked_at("never-locked-agent", now));
    }

    #[test]
    fn test_cover_traffic() {
        let rl = AgentRateLimiter::new();
        for _ in 0..50 {
            assert!(rl.record_cover_traffic("agent1").is_ok());
        }
        // 51st should exceed threshold
        assert!(rl.record_cover_traffic("agent1").is_err());
    }

    // ---------------------------------------------------------------------
    // AgentRateLimiter::with_backend — distributed state (Workstream A)
    // ---------------------------------------------------------------------

    #[test]
    fn rate_limiter_new_behavior_unchanged_without_backend() {
        // No backend configured: existing threshold/lockout behavior must be
        // bit-for-bit identical to before this feature existed.
        let rl = AgentRateLimiter::new();
        assert!(rl.poller_stop.is_none());
        for _ in 0..4 {
            assert!(rl.record_error("agentX").is_ok());
        }
        assert!(rl.record_error("agentX").is_err());
        assert!(rl.is_locked("agentX"));
    }

    #[test]
    fn rate_limiter_with_inmemory_backend_cross_instance_lockout() {
        use crate::state_backend::InMemoryBackend;

        // Simulate two gateway nodes sharing one backend.
        let shared: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::new());
        let node_a = AgentRateLimiter::with_backend(Arc::clone(&shared));
        let node_b = AgentRateLimiter::with_backend(Arc::clone(&shared));

        assert!(!node_b.is_locked("agentY"));

        // Drive enough errors into node A to trip the fleet-wide threshold.
        let mut tripped = false;
        for _ in 0..RATE_LIMITER_THRESHOLD {
            if node_a.record_error("agentY").is_err() {
                tripped = true;
            }
        }
        assert!(tripped, "node A should have tripped the circuit breaker");
        assert!(node_a.is_locked("agentY"));

        // Node B hasn't seen any traffic for this agent yet — deterministically
        // pull the fleet-wide lockout marker instead of sleeping.
        assert!(!node_b.is_locked("agentY"), "node B shouldn't know yet without a refresh");
        node_b.refresh_from_backend();
        assert!(node_b.is_locked("agentY"), "node B should observe the cross-node lockout after refresh");
    }

    #[test]
    fn rate_limiter_backend_error_fails_safe_not_open() {
        struct AlwaysErrBackend;
        impl StateBackend for AlwaysErrBackend {
            fn get(&self, _key: &str) -> crate::state_backend::BackendResult<Option<Vec<u8>>> {
                Err(crate::state_backend::BackendError("boom".into()))
            }
            fn set(&self, _key: &str, _value: &[u8], _ttl: Option<Duration>) -> crate::state_backend::BackendResult<()> {
                Err(crate::state_backend::BackendError("boom".into()))
            }
            fn delete(&self, _key: &str) -> crate::state_backend::BackendResult<bool> {
                Err(crate::state_backend::BackendError("boom".into()))
            }
            fn incr(&self, _key: &str, _by: i64) -> crate::state_backend::BackendResult<i64> {
                Err(crate::state_backend::BackendError("boom".into()))
            }
            fn scan_prefix(&self, _prefix: &str) -> crate::state_backend::BackendResult<Vec<String>> {
                Err(crate::state_backend::BackendError("boom".into()))
            }
            fn incr_with_ttl(&self, _key: &str, _by: i64, _ttl: Duration) -> crate::state_backend::BackendResult<i64> {
                Err(crate::state_backend::BackendError("boom".into()))
            }
        }

        let rl = AgentRateLimiter::with_backend(Arc::new(AlwaysErrBackend));
        // Even though every backend call fails, the breaker must still
        // enforce locally (fail-safe, not fail-open).
        let mut tripped = false;
        for _ in 0..RATE_LIMITER_THRESHOLD {
            if rl.record_error("agentZ").is_err() {
                tripped = true;
            }
        }
        assert!(tripped, "circuit breaker must still trip when the backend is unreachable");
        assert!(rl.is_locked("agentZ"));
    }

    #[test]
    fn test_issue_and_validate_token() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x01,
            None,
        );
        let result = gw.validate_lateral_movement("agent-b", &token, secret);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.is_valid);
        assert_eq!(r.source_agent, "agent-a");
        assert_eq!(r.max_action_class, 0x01);
    }

    #[test]
    fn test_token_scope_violation() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x00,
            None,
        );
        let result = gw.validate_lateral_movement("agent-c", &token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_revocation() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x00,
            None,
        );
        gw.revoke_token(&token).unwrap();
        assert_eq!(gw.get_revocation_epoch(), 1);
    }

    #[test]
    fn test_revoke_all_tokens() {
        let gw = ZeroTrustGateway::new();
        gw.register_issuer_key("agent-a", b"secret-key-32-bytes-long!!!!!!!!").unwrap();
        let epoch = gw.revoke_all_tokens();
        assert_eq!(epoch, 1);
    }

    /// H-2 regression: `revoke_all_tokens()` must NOT clear `revoked_tokens` —
    /// doing so would silently un-revoke a token an operator individually
    /// revoked before the PSK compromise event (fail-open). An individually
    /// revoked token must stay revoked across a `revoke_all_tokens()` call.
    #[test]
    fn test_revoke_all_tokens_preserves_individual_revocations() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret, "agent-a", &["agent-b"], &[], 3600, None, 0x00, None,
        );
        gw.revoke_token(&token).unwrap();
        assert!(gw.validate_lateral_movement("agent-b", &token, secret).is_err());

        gw.revoke_all_tokens();

        assert!(
            gw.validate_lateral_movement("agent-b", &token, secret).is_err(),
            "a token individually revoked before revoke_all_tokens() must remain revoked \
             afterwards — revoke_all_tokens() must not clear revoked_tokens"
        );
    }

    /// H-2 regression: `revoke_all_tokens()` must reject tokens issued before
    /// the recovery event even when they were never individually revoked,
    /// via the blanket `iat`-based check — not just tokens explicitly listed
    /// in `revoked_tokens`. A hand-crafted token with `iat: 0` simulates a
    /// pre-compromise token (avoids any real-clock timing flakiness).
    #[test]
    fn test_revoke_all_tokens_blanket_rejects_pre_compromise_iat() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";

        let json = serde_json::json!({
            "iss": "agent-a",
            "iat": 0,
            "exp": 9_999_999_999u64,
            "allow": ["agent-b"],
            "forbid": [],
            "max_action_class": 0,
        });
        let token_json = serde_json::to_vec(&json).unwrap();
        let signature = hmac_sha256(secret, &token_json);
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&(token_json.len() as u32).to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes();

        // Valid before any blanket revocation has occurred.
        assert!(gw.validate_lateral_movement("agent-b", &token, secret).is_ok());

        gw.revoke_all_tokens();

        let err = gw.validate_lateral_movement("agent-b", &token, secret).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::LateralMovementBlocked);
    }

    /// S-2 fix: `prune_expired_revocations` reclaims revocation entries whose
    /// bound token has already expired, but leaves still-live revocations intact.
    /// A pruned entry is safe to drop because an expired token is independently
    /// rejected by Gate 1.0's expiry check.
    #[test]
    fn test_prune_expired_revocations_reclaims_only_expired() {
        // Craft a signed token with an explicit `exp`, revoke it, return the b64 wire form.
        fn signed_token_with_exp(secret: &[u8], iss: &str, exp: f64) -> Vec<u8> {
            let json = serde_json::json!({
                "iss": iss,
                "iat": 0,
                "exp": exp,
                "allow": ["agent-b"],
                "forbid": [],
                "max_action_class": 0,
            });
            let token_json = serde_json::to_vec(&json).unwrap();
            let signature = hmac_sha256(secret, &token_json);
            let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
            packed.extend_from_slice(&(token_json.len() as u32).to_be_bytes());
            packed.extend_from_slice(&token_json);
            packed.extend_from_slice(&signature);
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
        }

        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";

        // One already-expired (exp in the past) and one long-lived revocation.
        let expired = signed_token_with_exp(secret, "agent-a", 1.0);
        let live = signed_token_with_exp(secret, "agent-a", 9_999_999_999.0);
        gw.revoke_token(&expired).unwrap();
        gw.revoke_token(&live).unwrap();
        assert_eq!(gw.revoked_tokens_len(), 2, "both revocations recorded");

        let pruned = gw.prune_expired_revocations();
        assert_eq!(pruned, 1, "exactly the expired-token revocation is reclaimed");
        assert_eq!(gw.revoked_tokens_len(), 1, "the live revocation survives");

        // The live revocation is still enforced end-to-end.
        assert!(
            gw.validate_lateral_movement("agent-b", &live, secret).is_err(),
            "a non-expired revoked token must still be blocked after a prune"
        );
    }

    /// S-2 fix: `revoke_all_tokens()` must NOT clear the (now `HashMap`) revocation
    /// set — the H-2 fail-open invariant is preserved across the HashSet→HashMap
    /// change. Mirrors `test_revoke_all_tokens_preserves_individual_revocations`
    /// but asserts on the map length directly.
    #[test]
    fn test_revoke_all_tokens_preserves_revocation_map_entries() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret, "agent-a", &["agent-b"], &[], 3600, None, 0x00, None,
        );
        gw.revoke_token(&token).unwrap();
        assert_eq!(gw.revoked_tokens_len(), 1);
        gw.revoke_all_tokens();
        assert_eq!(
            gw.revoked_tokens_len(), 1,
            "revoke_all_tokens must not clear individual revocation entries (H-2)"
        );
    }
    #[test]
    fn test_revoke_all_tokens_does_not_reject_freshly_issued_tokens() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        gw.revoke_all_tokens();
        let token = gw.issue_capability_token(
            secret, "agent-a", &["agent-b"], &[], 3600, None, 0x00, None,
        );
        assert!(
            gw.validate_lateral_movement("agent-b", &token, secret).is_ok(),
            "a token issued after revoke_all_tokens() must still validate"
        );
    }

    /// S-3 regression: `validate_lateral_movement` must verify against the
    /// per-issuer secret held in the (now `Zeroizing`-wrapped) `trusted_issuer_keys`
    /// registry, not the caller-supplied fallback `issuer_secret` param, once a
    /// registry entry exists for the token's issuer. Proven here by issuing the
    /// token with the REGISTERED secret while passing a completely different,
    /// wrong fallback secret to `validate_lateral_movement` — it must still
    /// validate successfully, which is only possible if the registered
    /// `Zeroizing<Vec<u8>>` value round-trips correctly through the registry
    /// lookup/clone and is usable as real HMAC key material.
    #[test]
    fn test_validate_lateral_movement_uses_registered_issuer_key() {
        let gw = ZeroTrustGateway::new();
        let registered_secret = b"registered-issuer-secret-32bytes";
        let wrong_fallback_secret = b"totally-different-fallback-key!!";
        gw.register_issuer_key("agent-a", registered_secret).unwrap();

        let token = gw.issue_capability_token(
            registered_secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x01,
            None,
        );

        let result = gw.validate_lateral_movement("agent-b", &token, wrong_fallback_secret);
        assert!(result.is_ok(), "must validate against the registered issuer key, not the fallback param");
        assert_eq!(result.unwrap().source_agent, "agent-a");

        // A token signed with the WRONG secret must still be rejected even though
        // a (mismatched) fallback secret was supplied — the registry takes priority.
        let forged_token = gw.issue_capability_token(
            wrong_fallback_secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x01,
            None,
        );
        assert!(gw.validate_lateral_movement("agent-b", &forged_token, wrong_fallback_secret).is_err());
    }

    /// S-3 regression: once ANY issuer key is registered, an issuer with no
    /// registry entry must be rejected outright ("issuer is not trusted"),
    /// regardless of what fallback `issuer_secret` is supplied — the registry,
    /// once non-empty, is authoritative.
    #[test]
    fn test_validate_lateral_movement_rejects_unregistered_issuer_when_registry_configured() {
        let gw = ZeroTrustGateway::new();
        let registered_secret = b"registered-issuer-secret-32bytes";
        let untrusted_secret = b"untrusted-issuer-own-secret-key!";
        gw.register_issuer_key("agent-a", registered_secret).unwrap();

        // "agent-x" has no registry entry, even though its own token is
        // internally self-consistent (signed with a secret only it knows).
        let token = gw.issue_capability_token(
            untrusted_secret,
            "agent-x",
            &["agent-b"],
            &[],
            3600,
            None,
            0x01,
            None,
        );
        let result = gw.validate_lateral_movement("agent-b", &token, untrusted_secret);
        assert!(result.is_err(), "an issuer absent from a non-empty registry must be rejected");
    }

    /// Build an Ed25519-signed capability token wire blob: sorted-JSON claims
    /// (including `_sig_alg:"ed25519"` and `kid`) with a real Ed25519 signature
    /// over those exact bytes, or — when `tamper` is true — a bogus signature.
    #[cfg(test)]
    fn build_ed25519_token(
        sk: &ed25519_dalek::SigningKey,
        kid: &str,
        issuer: &str,
        allow: &[&str],
        tamper: bool,
    ) -> Vec<u8> {
        use base64::Engine;
        use ed25519_dalek::Signer;
        let iat = now_epoch_secs() as u64;
        let mut token_data: HashMap<String, serde_json::Value> = HashMap::new();
        token_data.insert("iss".into(), serde_json::Value::String(issuer.into()));
        token_data.insert("kid".into(), serde_json::Value::String(kid.into()));
        token_data.insert("_sig_alg".into(), serde_json::Value::String("ed25519".into()));
        token_data.insert("iat".into(), serde_json::Value::Number(iat.into()));
        token_data.insert("exp".into(), serde_json::Value::Number((iat + 3600).into()));
        token_data.insert("allow".into(), sorted_str_array(allow));
        token_data.insert("forbid".into(), sorted_str_array(&[]));
        token_data.insert("max_action_class".into(), serde_json::Value::Number(1u8.into()));
        let token_json = serialize_sorted_json(&token_data);
        let signature = if tamper {
            [0x7u8; 64]
        } else {
            sk.sign(&token_json).to_bytes()
        };
        let json_len = u32::try_from(token_json.len()).unwrap_or(u32::MAX);
        let mut packed = Vec::with_capacity(4 + token_json.len() + 64);
        packed.extend_from_slice(&json_len.to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);
        base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
    }

    /// SECURITY regression (ed25519 fail-open): a token declaring
    /// `_sig_alg:"ed25519"` must have its signature verified. Before the fix the
    /// ed25519 branch did nothing, so ANY signature — including an all-0x07
    /// forgery — was accepted. Now: no CVA registered ⇒ reject; unknown kid ⇒
    /// reject; forged signature ⇒ reject; genuine signature over the claims ⇒ ok.
    #[test]
    fn test_ed25519_token_signature_is_verified_fail_closed() {
        use ed25519_dalek::SigningKey;
        let mut csprng = rand::thread_rng();
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();
        let kid = "ed25519-test-kid";

        // 1. No CapabilityVerificationAuthority registered ⇒ fail closed.
        let gw = ZeroTrustGateway::new();
        let genuine = build_ed25519_token(&sk, kid, "agent-a", &["agent-b"], false);
        assert!(
            gw.validate_lateral_movement("agent-b", &genuine, b"unused-secret").is_err(),
            "ed25519 token with no registered authority must be rejected (fail-closed)"
        );

        // 2. Authority registered but for a DIFFERENT kid ⇒ unknown kid ⇒ reject.
        let gw = ZeroTrustGateway::new();
        let ca = Arc::new(CapabilityVerificationAuthority::new());
        ca.register_key("some-other-kid", vk);
        gw.register_capability_authority(Arc::clone(&ca));
        assert!(
            gw.validate_lateral_movement("agent-b", &genuine, b"unused-secret").is_err(),
            "ed25519 token whose kid has no registered key must be rejected"
        );

        // 3. Correct kid registered but signature is forged ⇒ reject.
        let gw = ZeroTrustGateway::new();
        let ca = Arc::new(CapabilityVerificationAuthority::new());
        ca.register_key(kid, vk);
        gw.register_capability_authority(Arc::clone(&ca));
        let forged = build_ed25519_token(&sk, kid, "agent-a", &["agent-b"], true);
        assert!(
            gw.validate_lateral_movement("agent-b", &forged, b"unused-secret").is_err(),
            "ed25519 token with a forged signature must be rejected"
        );

        // 4. Correct kid + genuine signature over the claims ⇒ accepted.
        let result = gw.validate_lateral_movement("agent-b", &genuine, b"unused-secret");
        assert!(
            result.is_ok(),
            "ed25519 token with a valid signature over its claims must be accepted: {result:?}"
        );
        assert_eq!(result.unwrap().source_agent, "agent-a");
    }

    /// SECURITY regression: `strict_asymmetric_mode` forces every token onto the
    /// ed25519 branch. That branch must actually verify signatures — a forged
    /// ed25519 token must not sail through just because strict mode is on.
    #[test]
    fn test_strict_asymmetric_mode_still_verifies_ed25519_signature() {
        use ed25519_dalek::SigningKey;
        let mut csprng = rand::thread_rng();
        let sk = SigningKey::generate(&mut csprng);
        let vk = sk.verifying_key();
        let kid = "ed25519-strict-kid";

        let gw = ZeroTrustGateway::new();
        gw.set_strict_asymmetric_mode(true);
        let ca = Arc::new(CapabilityVerificationAuthority::new());
        ca.register_key(kid, vk);
        gw.register_capability_authority(Arc::clone(&ca));

        let forged = build_ed25519_token(&sk, kid, "agent-a", &["agent-b"], true);
        assert!(
            gw.validate_lateral_movement("agent-b", &forged, b"unused").is_err(),
            "strict mode must not accept a forged ed25519 signature"
        );

        let genuine = build_ed25519_token(&sk, kid, "agent-a", &["agent-b"], false);
        assert!(
            gw.validate_lateral_movement("agent-b", &genuine, b"unused").is_ok(),
            "strict mode must accept a genuine ed25519 signature"
        );
    }

    #[test]
    fn test_delegation_guard() {
        let secret = b"root-orchestrator-key-32-bytes!!";
        let gw = ZeroTrustGateway::new();
        let token = gw.issue_capability_token(
            secret,
            "root",
            &["agent-b"],
            &[],
            3600,
            None,
            0x00,
            None,
        );
        assert!(DelegationGuard::validate_not_self_signed(&token, secret).is_ok());
        assert!(DelegationGuard::validate_not_self_signed(&token, b"wrong-key-32-bytes-long!!!!!!!!!").is_err());
    }

    /// BUFFER-SAFETY regression: a 4-byte length prefix claiming far more JSON
    /// bytes than are actually present must be rejected cleanly, not panic on
    /// `raw[4..4+json_len]` ("range end index out of range for slice").
    #[test]
    fn test_delegation_guard_rejects_oversized_length_prefix() {
        use base64::Engine;
        // json_len = 0x0000FFFF (65535), but zero bytes follow — same attack
        // shape as parse_token_wire's own bounds check already guards against.
        let malicious_raw = vec![0x00, 0x00, 0xFF, 0xFF];
        let malicious_token = base64::engine::general_purpose::STANDARD.encode(&malicious_raw);
        let err = DelegationGuard::validate_not_self_signed(
            malicious_token.as_bytes(),
            b"root-orchestrator-key-32-bytes!!",
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::DelegationRejected);
    }

    #[test]
    fn test_delegation_guard_rejects_zero_length_json() {
        use base64::Engine;
        let malicious_raw = vec![0x00, 0x00, 0x00, 0x00, 0xAB]; // json_len=0, trailing sig byte
        let malicious_token = base64::engine::general_purpose::STANDARD.encode(&malicious_raw);
        let err = DelegationGuard::validate_not_self_signed(
            malicious_token.as_bytes(),
            b"root-orchestrator-key-32-bytes!!",
        ).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::DelegationRejected);
    }

    #[test]
    fn test_rrbc_issue_and_redeem() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = rbc.issue_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            &["read"],
            &["agent-b"],
            "session-1",
            "conv-1",
            "agent-b",
            1,
            3600,
            0x00,
            None,
        );
        let result = rbc.redeem_token(
            &token,
            "rnonce-1",
            "agent-b",
            "session-1",
            "conv-1",
            "agent-b",
            secret,
        );
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.issuer_agent, "agent-a");
        assert_eq!(r.remaining_uses, 0);
    }

    #[test]
    fn test_rrbc_replay_detection() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = rbc.issue_token(
            secret, "a", &["b"], &[], &["read"], &["b"],
            "s1", "c1", "b", 1, 3600, 0x00, None,
        );
        assert!(rbc.redeem_token(&token, "rn", "b", "s1", "c1", "b", secret).is_ok());
        // Second redemption with same rnonce should fail
        assert!(rbc.redeem_token(&token, "rn", "b", "s1", "c1", "b", secret).is_err());
    }

    #[test]
    fn test_rrbc_binding_mismatch() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = rbc.issue_token(
            secret, "a", &["b"], &[], &["read"], &["b"],
            "s1", "c1", "b", 1, 3600, 0x00, None,
        );
        assert!(rbc.redeem_token(&token, "rn", "b", "wrong-sid", "c1", "b", secret).is_err());
    }

    /// H-8 regression: `issue_token` must actually embed the PoP verifying key
    /// so `redeem_token_with_pop` enforces proof-of-possession end-to-end —
    /// previously the field was never written, making PoP permanently dead.
    #[test]
    fn test_rrbc_pop_enforced_when_key_embedded() {
        use ed25519_dalek::{Signer, SigningKey};
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key_bytes = signing_key.verifying_key().to_bytes();

        let token = rbc.issue_token(
            secret, "a", &["b"], &[], &["read"], &["b"],
            "s1", "c1", "b", 2, 3600, 0x00, Some(&verifying_key_bytes),
        );

        // No PoP proof supplied — must be rejected.
        let no_proof = rbc.redeem_token_with_pop(
            &token, "rn-1", "b", "s1", "c1", "b", secret, None,
        );
        assert!(no_proof.is_err());

        // Correct Ed25519 proof over the rnonce — must succeed.
        let sig = signing_key.sign(b"rn-2").to_bytes();
        let with_proof = rbc.redeem_token_with_pop(
            &token, "rn-2", "b", "s1", "c1", "b", secret, Some(&sig),
        );
        assert!(with_proof.is_ok());
    }

    /// H-1 regression: a forged/tampered RRBC token carrying an out-of-range
    /// `max_action_class` (> 255) must be hard-rejected, not silently truncated to
    /// `u8::MAX` (which would grant maximum privilege on parse overflow). `issue_token`
    /// always emits an in-range value, so this test hand-crafts the wire format
    /// directly to simulate an attacker-forged (but correctly HMAC-signed) token.
    #[test]
    fn test_rrbc_forged_max_action_class_rejected_not_truncated() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let json = serde_json::json!({
            "jti": "forged-jti-1",
            "iss": "attacker",
            "aud": ["b"],
            "sid": "s1",
            "cid": "c1",
            "oaid": "b",
            "nbf": 0,
            "exp": 9_999_999_999.0,
            "max_use": 1,
            "max_action_class": 999,
        });
        let token_json = serde_json::to_vec(&json).unwrap();
        let signature = hmac_sha256(secret, &token_json);
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&(token_json.len() as u32).to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);
        use base64::Engine;
        let forged_token = base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes();

        let result = rbc.redeem_token(&forged_token, "rn-forged", "b", "s1", "c1", "b", secret);
        let err = result.expect_err(
            "out-of-range max_action_class must be rejected, not truncated to u8::MAX",
        );
        assert_eq!(err.bytecode, SAACPBytecodes::ActionClassEscalation);
    }

    #[test]
    fn test_rrbc_revocation() {
        let rbc = RRBCGateway::new();
        rbc.revoke_token("jti-1");
        assert!(rbc.is_jti_revoked("jti-1"));
        assert!(!rbc.is_jti_revoked("jti-2"));
    }

    /// Task: revoke_all_tokens_increments_both_epochs
    #[test]
    fn revoke_all_tokens_increments_both_epochs() {
        let gw = ZeroTrustGateway::new();
        // Register an issuer to give issuer_registry_epoch a baseline to work with
        gw.register_issuer_key("agent-a", b"secret-key-32-bytes-long!!!!!!!!").unwrap();
        let rev_epoch_before = gw.get_revocation_epoch();
        let epoch = gw.revoke_all_tokens();
        // revoke_all_tokens() increments revocation_epoch by 1 and returns it
        assert_eq!(epoch, rev_epoch_before + 1, "revocation_epoch must increment");
        // Calling twice must keep incrementing
        let epoch2 = gw.revoke_all_tokens();
        assert_eq!(epoch2, epoch + 1, "revocation_epoch must increment on each call");
        // get_revocation_epoch() must match the return value
        assert_eq!(gw.get_revocation_epoch(), epoch2);
    }

    /// A cached verdict must become unusable the instant the generation is
    /// bumped — WITHOUT relying on the physical clear having run.
    ///
    /// This is the property that makes it safe to shard the token cache at all.
    /// Clearing 16 shards is not atomic, and every clear site is a revocation or
    /// key-registry change, so if correctness depended on the clear a concurrent
    /// lookup could hit a not-yet-cleared shard and be served a REVOKED token.
    /// Here the entry is left physically in place and must still be rejected.
    #[test]
    fn stale_generation_entry_is_never_served_even_if_not_cleared() {
        let gw = ZeroTrustGateway::new();
        let secret = b"secret-key-32-bytes-long!!!!!!!!";
        gw.register_issuer_key("issuer-gen", secret).unwrap();
        let token = gw.issue_capability_token(
            secret, "issuer-gen", &["target-gen"], &[], 3600, None, 0, None);

        // Populate the cache, then confirm the entry is really there.
        gw.validate_lateral_movement("target-gen", &token, secret).unwrap();
        let cached_key_count: usize =
            gw.token_cache.iter().map(|s| s.lock().unwrap().len()).sum();
        assert_eq!(cached_key_count, 1, "validation should have cached one verdict");

        // Bump the generation WITHOUT clearing — simulating the window between
        // the atomic publish and a shard's physical clear.
        gw.update_epochs(|_| {});
        let after: usize = gw.token_cache.iter().map(|s| s.lock().unwrap().len()).sum();
        assert_eq!(after, 1, "entry must still be physically present for this test to mean anything");

        // The stale entry must be ignored: re-validating recomputes and restamps
        // it with the current generation rather than returning the old verdict.
        let epochs_before = gw.epochs.load().cache_generation;
        gw.validate_lateral_movement("target-gen", &token, secret).unwrap();
        let stamped: Vec<u64> = gw.token_cache.iter()
            .flat_map(|s| s.lock().unwrap().values().map(|v| v.generation).collect::<Vec<_>>())
            .collect();
        assert!(
            stamped.iter().all(|&g| g == epochs_before),
            "cached entries must carry the current generation after revalidation, got {stamped:?}",
        );
    }

    /// `revoke_all_tokens` must publish `blanket_revoked_before` and the epoch
    /// counters together, so no reader can observe the bumped epoch alongside a
    /// stale (zero) blanket timestamp.
    ///
    /// That mixed view is exactly what independent atomics would permit, and it
    /// would admit a token during PSK-compromise recovery — the one moment the
    /// blanket revocation exists to cover.
    #[test]
    fn revoke_all_tokens_publishes_blanket_timestamp_with_the_epoch_bump() {
        let gw = ZeroTrustGateway::new();
        let before = gw.epochs.load();
        assert_eq!(before.blanket_revoked_before, 0.0);

        let epoch = gw.revoke_all_tokens();
        let after = gw.epochs.load();

        assert_eq!(after.revocation_epoch, epoch);
        assert!(
            after.blanket_revoked_before > 0.0,
            "blanket_revoked_before must be set in the SAME snapshot that carries \
             the bumped revocation_epoch — a reader seeing the new epoch with the \
             old 0.0 timestamp would skip the blanket revocation entirely",
        );
        assert!(after.cache_generation > before.cache_generation);
    }

    /// Task: cover_traffic_budget_separate_from_error_budget
    #[test]
    fn cover_traffic_budget_separate_from_error_budget() {
        let rl = AgentRateLimiter::new();
        // Fill the cover-traffic budget to the threshold (50 in COVER_TRAFFIC_WINDOW_SECONDS=1.0s).
        // All within one second, so count accumulates in the same window.
        for i in 0..COVER_TRAFFIC_THRESHOLD {
            assert!(
                rl.record_cover_traffic("agent-cover").is_ok(),
                "call {i} must be OK within threshold"
            );
        }
        // The (THRESHOLD+1)-th call must be rejected as rate-limited.
        let over_limit = rl.record_cover_traffic("agent-cover");
        assert!(over_limit.is_err(), "cover traffic over threshold must be rejected");

        // Meanwhile, a different agent has independent cover traffic budget.
        assert!(rl.record_cover_traffic("agent-other").is_ok(),
            "different agent must have its own budget");
    }
}
