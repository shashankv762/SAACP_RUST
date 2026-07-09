//! security.rs — Nonce Tracking + Immutable Audit Log
//!
//! Implements:
//! - `NonceTracker`: Tracks nonces to defeat Replay Attacks
//! - `ImmutableAuditLog`: Append-only cryptographic hash chain with WAL worker thread

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use sha2::Sha256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

type HmacSha256 = Hmac<Sha256>;

/// Constant-time comparison of two byte slices.
/// Returns true iff a.len() == b.len() AND all bytes are equal,
/// without short-circuiting on the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Constant-time comparison of two hex-encoded HMAC digests (as strings).
/// Decodes both to raw bytes before comparing so no timing information
/// about the first differing hex character leaks.
fn constant_time_eq_hex(a: &str, b: &str) -> bool {
    match (hex::decode(a), hex::decode(b)) {
        (Ok(ab), Ok(bb)) => constant_time_eq(&ab, &bb),
        _ => false,
    }
}

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ===========================================================================
// Audit-intent confidentiality (opt-in — STRIDE Information Disclosure fix)
// ===========================================================================
//
// `ImmutableAuditLog::append_event`'s `intent` field (task/action text,
// naming source/target agents) is written to disk in cleartext JSONL,
// integrity-protected by the chain-hash HMAC but never confidentiality-
// protected. An attacker with filesystem read access to the log — a
// different compromised process on the same host, a stolen backup, a
// misconfigured permission — gets a full plaintext history of every agent's
// tasks. `append_event_confidential` closes this gap by encrypting just the
// `intent` string before it ever reaches `append_event`, so the audit record
// schema, the canonical HMAC input, and `verify_chain`/`verify_chain_disk`
// are all completely unchanged — the chain-hash covers whatever string ends
// up in `intent`, plaintext or ciphertext, identically.
//
// Opt-in, mirroring this crate's established pattern for optional
// security/privacy enhancements (`mpf.rs`'s cover traffic/padding): the
// default `append_event` path is untouched so every existing deployment and
// test that expects a human-readable `intent` field keeps working exactly
// as before.

/// HKDF info string for audit-intent encryption key derivation — domain-
/// separated from the chain-hash HMAC (which uses `issuer_secret` directly
/// as MAC key input) so adding encryption never weakens or entangles with
/// the existing chain-integrity guarantee.
const AUDIT_INTENT_HKDF_INFO: &[u8] = b"SAACP-audit-intent-confidentiality-v1";

/// Derive a 32-byte AES-256-GCM key for audit-intent encryption from the same
/// `issuer_secret` already used for chain-hash HMACs, via HKDF-SHA256.
fn derive_intent_key(issuer_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, issuer_secret);
    let mut key = [0u8; 32];
    hk.expand(AUDIT_INTENT_HKDF_INFO, &mut key)
        .expect("HKDF-SHA256 expand: output length 32 is always valid");
    key
}

/// Encrypt an audit intent string for confidentiality-at-rest. Returns
/// `hex(nonce(12) || ciphertext || tag)` — pure lowercase ASCII hex, safe to
/// embed directly as a JSON string value with no escaping, exactly like the
/// existing `chain_hash` field. See module docs above for the security
/// rationale and `ImmutableAuditLog::append_event_confidential` for the
/// intended call site.
pub fn encrypt_intent(issuer_secret: &[u8], plaintext_intent: &str) -> String {
    let key_bytes = derive_intent_key(issuer_secret);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    // AES-256-GCM encryption of an in-memory audit string (well under the
    // cipher's data-size limits) cannot fail.
    let ciphertext = cipher
        .encrypt(nonce, plaintext_intent.as_bytes())
        .expect("AES-256-GCM encryption of audit intent cannot fail");
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    hex::encode(out)
}

/// Decrypt an intent string previously produced by `encrypt_intent`. Returns
/// `Err` on the wrong key, truncated/corrupt input, or authentication
/// failure (tampering).
pub fn decrypt_intent(issuer_secret: &[u8], encrypted_hex: &str) -> Result<String, String> {
    let raw = hex::decode(encrypted_hex).map_err(|e| format!("hex decode error: {e}"))?;
    if raw.len() < 12 + 16 {
        return Err("encrypted intent too short to contain nonce + auth tag".to_string());
    }
    let (nonce_bytes, ciphertext) = raw.split_at(12);
    let key_bytes = derive_intent_key(issuer_secret);
    let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "audit intent decryption/authentication failed".to_string())?;
    String::from_utf8(plaintext).map_err(|e| format!("decrypted intent not valid UTF-8: {e}"))
}

// ===========================================================================
// Environment variable constants (Appendix A)
// ===========================================================================

/// Env var that overrides the audit log file path.
pub const ENV_AUDIT_LOG: &str = "SAACP_AUDIT_LOG";
/// Env var that overrides the audit event-count sentinel file path.
pub const ENV_COUNT_FILE: &str = "SAACP_COUNT_FILE";

// ===========================================================================
// NonceTracker
// ===========================================================================

/// Maximum age of a nonce before it is pruned.
pub const NONCE_MAX_AGE_SECONDS: f64 = 30.0;
/// Hard cap to prevent OOM under sustained load.
pub const NONCE_MAX_ENTRIES: usize = 100_000;

/// Tracks nonces to defeat Replay Attacks. Automatically prunes to prevent memory leaks.
pub struct NonceTracker {
    inner: Mutex<NonceInner>,
}

struct NonceInner {
    seen_nonces: HashMap<u64, f64>,
    max_age_seconds: f64,
    max_entries: usize,
}

impl NonceTracker {
    /// Create a new NonceTracker with default settings.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(NonceInner {
                seen_nonces: HashMap::new(),
                max_age_seconds: NONCE_MAX_AGE_SECONDS,
                max_entries: NONCE_MAX_ENTRIES,
            }),
        }
    }

    /// Create a NonceTracker with custom settings.
    pub fn with_limits(max_age_seconds: f64, max_entries: usize) -> Self {
        Self {
            inner: Mutex::new(NonceInner {
                seen_nonces: HashMap::new(),
                max_age_seconds,
                max_entries,
            }),
        }
    }

    /// Track a nonce. Returns `Err` if the nonce was already used (replay attack).
    pub fn track(&self, nonce: u64) -> Result<(), SAACPHardDrop> {
        let current_time = now_secs();
        let mut inner = self.inner.lock().expect("lock poisoned");

        // Atomic check-and-insert (fixes TOCTOU race condition)
        if inner.seen_nonces.contains_key(&nonce) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "REPLAY ATTACK DETECTED: Nonce already used.",
            ));
        }

        inner.seen_nonces.insert(nonce, current_time);

        // Prune expired nonces to prevent OOM memory leaks
        if inner.seen_nonces.len() > inner.max_entries {
            let max_age = inner.max_age_seconds;
            inner.seen_nonces.retain(|_, &mut t| (current_time - t) <= max_age);

            // If STILL over capacity after time-based eviction, we are under
            // sustained flood attack.
            if inner.seen_nonces.len() > inner.max_entries {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::CircuitBreakerOpen,
                    "Nonce tracker capacity exceeded under sustained flood — \
                     rejecting to protect replay integrity.",
                ));
            }
        }

        Ok(())
    }

    /// Return the number of tracked nonces.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.seen_nonces.len()
    }

    /// Clear all tracked nonces.
    pub fn clear(&self) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.seen_nonces.clear();
    }
}

impl Default for NonceTracker {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// ImmutableAuditLog
// ===========================================================================

/// Default log file path (overridden by `SAACP_AUDIT_LOG` env var).
pub const AUDIT_LOG_FILE: &str = "saacp_audit.log";
/// Default sentinel file path (overridden by `SAACP_COUNT_FILE` env var).
pub const AUDIT_COUNT_FILE: &str = "saacp_event_count.sentinel";
/// Maximum log file size before rotation (50 MB).
pub const AUDIT_MAX_LOG_SIZE: u64 = 50_000_000;
/// WAL queue capacity — events are dropped (not rejected) when full.
pub const AUDIT_WAL_QUEUE_CAPACITY: usize = 100_000;

/// WAL flush cadence (Gate 6.0 backpressure repair, fix #1/#3): the WAL
/// worker batches disk writes behind a `BufWriter` and only calls `flush()` +
/// `sync_data()` after this many buffered entries, or after
/// `AUDIT_WAL_FLUSH_INTERVAL_MS` milliseconds — whichever comes first.
/// This is also the stated maximum audit-data-loss window on an unclean
/// shutdown (power loss, `kill -9`): **at most 200 entries or 50ms of audit
/// history**, whichever bound is hit first. This number is a documented
/// protocol contract, not an implementation detail — see `AuditHealth`.
pub const AUDIT_WAL_FLUSH_EVERY_N_ENTRIES: u64 = 200;
/// See `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES`.
pub const AUDIT_WAL_FLUSH_INTERVAL_MS: u64 = 50;

const AUDIT_WAL_FLUSH_INTERVAL: Duration = Duration::from_millis(AUDIT_WAL_FLUSH_INTERVAL_MS);

/// WAL queue-depth ratio above which `AuditHealth` becomes `Degraded`.
const AUDIT_HEALTH_DEGRADED_PCT: f64 = 0.70;
/// WAL queue-depth ratio above which `AuditHealth` becomes `Saturated`.
const AUDIT_HEALTH_SATURATED_PCT: f64 = 0.95;

/// Genesis hash for the audit chain.
const GENESIS_HASH: &str = "47454e455349535f424c4f434b"; // hex of b"GENESIS_BLOCK"

// ---------------------------------------------------------------------------
// AuditHealth — Gate 6.0 backpressure contract
// ---------------------------------------------------------------------------

/// Gate 6.0 (audit checkpoint / WAL writer) backpressure health.
///
/// Every gate that touches disk, does unbounded-size work, or depends on
/// external system throughput must declare an explicit backpressure contract
/// with the packet pipeline rather than an ad-hoc drop-and-print. For the
/// audit log, that contract is this three-state (plus terminal `Fatal`)
/// signal:
///
/// - `Healthy` — WAL queue below 70% capacity. Normal async enqueue, zero
///   packet-path cost beyond the atomic bookkeeping.
/// - `Degraded` — WAL queue 70-95% capacity. Still enqueuing and writing,
///   but behind. `handler::gate_2_5_kinetic_firewall` reads this (via `>=`)
///   to start rejecting new IRREVERSIBLE_ACTION packets once the state
///   reaches `Saturated` — fail-safe, not fail-open.
/// - `Saturated` — WAL queue >95% capacity. New events are dropped with an
///   atomic counter (`dropped_audit_count()`), never an inline `eprintln!`
///   on the hot path. `Degraded`'s rejection of IRREVERSIBLE_ACTION packets
///   is already in effect here, protecting against irreversible actions
///   proceeding without a durable audit trail.
/// - `Fatal` — The WAL writer cannot write at all (log file open failed, or
///   an actual write returned an OS error). Distinguishable from `Saturated`
///   (queue pressure) — this means the writer tried and failed, not merely
///   that it's behind. Sticky: only constructing a fresh `ImmutableAuditLog`
///   clears it.
///
/// Discriminants are chosen so `Healthy < Degraded < Saturated < Fatal`,
/// letting callers use a single `health() >= AuditHealth::Saturated` check.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AuditHealth {
    Healthy = 0,
    Degraded = 1,
    Saturated = 2,
    Fatal = 3,
}

impl AuditHealth {
    fn from_u8(v: u8) -> Self {
        match v {
            0 => AuditHealth::Healthy,
            1 => AuditHealth::Degraded,
            2 => AuditHealth::Saturated,
            _ => AuditHealth::Fatal,
        }
    }
}

/// An audit log entry record.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRecord {
    pub timestamp: f64,
    pub source: String,
    pub target: String,
    pub intent: String,
    pub token_signature: String,
    pub traceparent: String,
    pub prev_hash: String,
    pub seq: u64,
}

/// A complete audit log entry (record + chain_hash).
#[derive(Debug, Clone)]
pub struct AuditLogEntry {
    pub record: AuditRecord,
    pub chain_hash: String,
}

/// Borrowed, alphabetically-field-ordered mirror of [`AuditRecord`], used
/// only to serialize the canonical HMAC input in `append_event`.
///
/// Throughput fix: `serde_json::to_string` on a `#[derive(Serialize)]`
/// struct serializes directly, without building an intermediate
/// `serde_json::Value` tree the way the `json!` macro does (one boxed
/// `Value`/`String` per field, plus a `Map`) — measured to meaningfully cut
/// per-event allocation (see `benches/benchmarks.rs`'s
/// `T14_WAL_Sustained_Throughput`). Field order here is alphabetical and
/// MUST stay that way — it's the canonical form the chain hash is computed
/// over, and changing it would silently break `verify_chain()` against any
/// audit log written before the change. Deliberately a separate borrowed
/// struct rather than adding `#[derive(Serialize)]` directly to
/// `AuditRecord` (whose field *declaration* order is not alphabetical) —
/// that would require reordering `AuditRecord`'s public fields to get the
/// same output, a much larger and riskier diff for the same result.
#[derive(serde::Serialize)]
struct CanonicalAuditRecord<'a> {
    intent: &'a str,
    prev_hash: &'a str,
    seq: u64,
    source: &'a str,
    target: &'a str,
    timestamp: f64,
    token_signature: &'a str,
    traceparent: &'a str,
}

// ---------------------------------------------------------------------------
// WAL worker message
// ---------------------------------------------------------------------------

struct WalMessage {
    entry_json: String,
    event_count: u64,
}

// ---------------------------------------------------------------------------
// ImmutableAuditLog
// ---------------------------------------------------------------------------

/// Append-Only Cryptographic Hash Chain Audit Log.
///
/// Ties Distributed Tracing (traceparent) to lateral movement token signatures.
/// If a compromised agent alters a past entry, the chain breaks.
/// Detects file deletion and partial truncation attacks.
///
/// Disk I/O is handled by a background WAL worker thread (spec §15.2) that
/// holds a persistent, buffered file handle for its lifetime (see `WalWriter`)
/// instead of reopening the file per event. If the WAL queue is full, the
/// event is dropped and counted (`dropped_audit_count()` / the process-wide
/// `gate_6_0_audit_drop` telemetry counter) — dropping is preferred over
/// blocking or rejecting the packet, and the drop path itself does no
/// blocking I/O. See `AuditHealth` for the full backpressure contract that
/// feeds `handler::gate_2_5_kinetic_firewall`.
pub struct ImmutableAuditLog {
    inner: Mutex<AuditInner>,
    /// WAL worker sender. Always `Some` — even a "" log_file spawns the worker,
    /// but the worker thread no-ops on disk I/O for an empty path (see `new()`).
    wal_tx: Option<mpsc::SyncSender<WalMessage>>,
    /// Backpressure health shared with the WAL worker thread — see `AuditHealth`.
    health: Arc<AtomicU8>,
    /// Count of events dropped because the WAL queue was full (or the worker
    /// thread had already exited after a fatal open failure).
    dropped_audits: Arc<AtomicU64>,
    /// Count of WAL write failures — distinct from queue-full drops: the
    /// worker actually attempted a write and the OS returned an error.
    wal_write_failures: Arc<AtomicU64>,
    /// Approximate current WAL queue depth, maintained by hand since
    /// `mpsc::SyncSender` exposes no introspection API.
    queue_len: Arc<AtomicUsize>,
    /// Subscribers notified synchronously on every successful `append_event`
    /// — after the hash-chain mutex (`inner`) has been released, never
    /// while held, matching `trust_decay.rs::emit`'s precedent. Built for
    /// the Command Center dashboard's live-traffic and delegation-edge
    /// feeds; does not participate in the chain-hash/verification logic at
    /// all (that's driven entirely by `CanonicalAuditRecord`, untouched).
    #[allow(clippy::type_complexity)]
    subscribers: Mutex<Vec<Arc<dyn Fn(&AuditRecord) + Send + Sync>>>,
}

struct AuditInner {
    last_hash: String,
    event_count: u64,
    log_file: String,
    count_file: String,
    entries: Vec<AuditLogEntry>,
}

impl ImmutableAuditLog {
    /// Create a new ImmutableAuditLog with an explicit log file path.
    ///
    /// The sentinel/count file is derived from `log_file` (`"<log_file>.sentinel"`),
    /// NOT the global `AUDIT_COUNT_FILE` default — every `new()` instance must own
    /// an independent sentinel, otherwise unrelated `ImmutableAuditLog` instances
    /// (e.g. two different test files, or two subsystems in the same production
    /// process) would clobber one shared counter and `verify_chain()` would fail
    /// spuriously whenever another instance's event count raced ahead of this
    /// one's. Passing `log_file = ""` (in-memory-only mode) derives an empty
    /// count_file too, so the WAL worker's sentinel write never happens and
    /// `verify_chain()`'s sentinel check is skipped entirely (see its `Path::exists`
    /// guard). Use `with_default_path()`/`global()` to opt into the shared,
    /// env-var-configured default sentinel instead.
    pub fn new(log_file: &str) -> Self {
        let count_file = if log_file.is_empty() {
            String::new()
        } else {
            format!("{log_file}.sentinel")
        };
        Self::with_paths(log_file, &count_file)
    }

    /// Create with both log file and sentinel file paths.
    pub fn with_paths(log_file: &str, count_file: &str) -> Self {
        let (wal_tx, wal_rx) = mpsc::sync_channel::<WalMessage>(AUDIT_WAL_QUEUE_CAPACITY);

        let health: Arc<AtomicU8> = Arc::new(AtomicU8::new(AuditHealth::Healthy as u8));
        let dropped_audits: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let wal_write_failures: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let queue_len: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

        // Spawn WAL worker daemon thread. `log_file`/`count_file` never change
        // after construction (no setter exists), so the worker captures its own
        // copies once instead of receiving them on every message.
        let worker_health = Arc::clone(&health);
        let worker_wal_write_failures = Arc::clone(&wal_write_failures);
        let worker_queue_len = Arc::clone(&queue_len);
        let worker_log_file = log_file.to_string();
        let worker_count_file = count_file.to_string();
        thread::Builder::new()
            .name("saacp-wal-worker".into())
            .spawn(move || {
                run_wal_worker(
                    wal_rx,
                    &worker_log_file,
                    &worker_count_file,
                    &worker_health,
                    &worker_wal_write_failures,
                    &worker_queue_len,
                );
            })
            .expect("WAL worker thread spawn failed");

        Self {
            inner: Mutex::new(AuditInner {
                last_hash: GENESIS_HASH.to_string(),
                event_count: 0,
                log_file: log_file.to_string(),
                count_file: count_file.to_string(),
                entries: Vec::new(),
            }),
            wal_tx: Some(wal_tx),
            health,
            dropped_audits,
            wal_write_failures,
            queue_len,
            subscribers: Mutex::new(Vec::new()),
        }
    }

    /// Register a callback invoked synchronously on every successfully
    /// appended event (i.e. every call to `append_event`/`append_signed`),
    /// with the plaintext `AuditRecord` (before WAL persistence, after the
    /// hash-chain lock is released). Keep callbacks fast and non-blocking —
    /// they run inline on the packet-processing path that triggered the
    /// append. Mirrors `TrustDecayEngine::subscribe`'s established pattern.
    pub fn subscribe(&self, cb: Arc<dyn Fn(&AuditRecord) + Send + Sync>) {
        self.subscribers.lock().expect("lock poisoned").push(cb);
    }

    /// Create a new audit log with default file path (reads from env vars).
    pub fn with_default_path() -> Self {
        let log_file = std::env::var(ENV_AUDIT_LOG)
            .unwrap_or_else(|_| AUDIT_LOG_FILE.to_string());
        let count_file = std::env::var(ENV_COUNT_FILE)
            .unwrap_or_else(|_| AUDIT_COUNT_FILE.to_string());
        Self::with_paths(&log_file, &count_file)
    }

    /// Process-wide global singleton ImmutableAuditLog.
    /// Initializes from `SAACP_AUDIT_LOG` and `SAACP_COUNT_FILE` env vars.
    pub fn global() -> &'static ImmutableAuditLog {
        static GLOBAL: OnceLock<ImmutableAuditLog> = OnceLock::new();
        GLOBAL.get_or_init(ImmutableAuditLog::with_default_path)
    }

    /// Initialize the chain from an existing log file (re-reads disk state).
    ///
    /// SECURITY (H-6): the on-disk tail entry is untrusted input — a corrupted
    /// or attacker-tampered log file must not be silently adopted as the new
    /// chain head. This calls `verify_chain_disk()` (full HMAC recomputation +
    /// sentinel check) before trusting the re-read state; on failure the
    /// in-memory chain is reset to genesis and an error is returned, per the
    /// fail-closed architecture principle (never keep unverified state).
    ///
    /// The disk read (which populates `event_count`/`last_hash`) must release
    /// `self.inner`'s lock before calling `verify_chain_disk`, which re-locks
    /// `self.inner` itself — `std::sync::Mutex` is not reentrant.
    pub fn initialize_chain(&self, issuer_secret: &[u8]) -> Result<(), String> {
        {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let log_file = inner.log_file.clone();

            if Path::new(&log_file).exists() {
                if let Ok(content) = fs::read_to_string(&log_file) {
                    let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
                    inner.event_count = lines.len() as u64;
                    if let Some(last_line) = lines.last() {
                        if let Ok(entry) = serde_json::from_str::<serde_json::Value>(last_line) {
                            if let Some(hash) = entry["chain_hash"].as_str() {
                                inner.last_hash = hash.to_string();
                            }
                        }
                    }
                }
            }
        } // `inner` lock released before verify_chain_disk re-locks it.

        if !self.verify_chain_disk(issuer_secret) {
            let mut inner = self.inner.lock().expect("lock poisoned");
            inner.event_count = 0;
            inner.last_hash = GENESIS_HASH.to_string();
            return Err(
                "audit chain integrity verification failed on load — chain reset to genesis"
                    .to_string(),
            );
        }

        Ok(())
    }

    /// Append one audit event to the in-memory chain and enqueue for WAL persistence.
    ///
    /// The chain hash is computed inline (synchronous) so the in-memory chain is
    /// always coherent. Disk I/O is offloaded to the WAL worker thread.
    /// If the WAL queue is full, the event is dropped and counted via
    /// `telemetry::global_telemetry()`'s `gate_6_0_audit_drop` counter — the
    /// packet is NOT rejected (spec §15.2: "Dropping an event is preferred over
    /// rejecting the packet"), and the drop itself is a lock-free atomic
    /// increment, never blocking I/O.
    pub fn append_event(
        &self,
        issuer_secret: &[u8],
        source_agent: &str,
        target_agent: &str,
        token_signature: &str,
        evaluated_intent: &str,
        traceparent: &str,
    ) {
        let mut inner = self.inner.lock().expect("lock poisoned");

        let record = AuditRecord {
            timestamp: now_secs(),
            source: source_agent.to_string(),
            target: target_agent.to_string(),
            intent: evaluated_intent.to_string(),
            token_signature: token_signature.to_string(),
            traceparent: traceparent.to_string(),
            prev_hash: inner.last_hash.clone(),
            seq: inner.event_count,
        };

        // Serialize deterministically (canonical JSON, alphabetical field
        // order) via a derived struct rather than the `json!` macro — see
        // `CanonicalAuditRecord`'s doc comment for why this is both faster
        // and still exactly reproduces the prior byte-for-byte output.
        let record_json = serde_json::to_string(&CanonicalAuditRecord {
            intent: &record.intent,
            prev_hash: &record.prev_hash,
            seq: record.seq,
            source: &record.source,
            target: &record.target,
            timestamp: record.timestamp,
            token_signature: &record.token_signature,
            traceparent: &record.traceparent,
        }).unwrap_or_default();

        // HMAC-SHA256 over the canonical record JSON.
        let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
        mac.update(record_json.as_bytes());
        let chain_hash = hex::encode(mac.finalize().into_bytes());

        let log_entry = AuditLogEntry {
            record,
            chain_hash: chain_hash.clone(),
        };

        inner.last_hash = chain_hash;
        inner.event_count += 1;

        // Build JSONL line for disk persistence. Throughput fix: reuses
        // `record_json` (already serialized above, once, for the HMAC input)
        // as the nested "record" value instead of re-serializing an
        // identical Value tree a second time via another `json!` macro call
        // — this was measured (see `benches/benchmarks.rs`'s
        // `T14_WAL_Sustained_Throughput`) to roughly halve the per-event
        // JSON-serialization cost, since building a `serde_json::Value` via
        // the `json!` macro allocates a full tree (one `String`/`Value` per
        // field) before `to_string()` even runs. Safe because `record_json`
        // is already valid, compact, properly-escaped JSON text, and
        // `chain_hash` is a hex string (`hex::encode` output — pure
        // lowercase ASCII hex digits, never containing `"` or a control
        // character), so no escaping is needed to embed it directly.
        let entry_json = format!(r#"{{"record":{record_json},"chain_hash":"{}"}}"#, log_entry.chain_hash);

        // Enqueue for WAL worker (non-blocking — drop if full, per spec §15.2).
        if let Some(ref tx) = self.wal_tx {
            let msg = WalMessage {
                entry_json,
                event_count: inner.event_count,
            };
            if tx.try_send(msg).is_ok() {
                self.queue_len.fetch_add(1, Ordering::Relaxed);
            } else {
                // FIX 3: rate-limited signal via an atomic counter — never an
                // inline eprintln! on this hot path. (A slow consumer forcing
                // this branch hundreds of thousands of times, each printing,
                // was the actual root cause of the original latency spike.)
                self.dropped_audits.fetch_add(1, Ordering::Relaxed);
                crate::telemetry::global_telemetry().record_gate_rejection("gate_6_0_audit");
            }

            // FIX 4: recompute health from live queue pressure. `fetch_update`
            // refuses to overwrite a sticky `Fatal` — only the WAL worker sets
            // that (on an actual I/O failure), and only a fresh
            // `ImmutableAuditLog` clears it.
            let pct = self.queue_len.load(Ordering::Relaxed) as f64
                / AUDIT_WAL_QUEUE_CAPACITY as f64;
            let level = if pct > AUDIT_HEALTH_SATURATED_PCT {
                AuditHealth::Saturated
            } else if pct > AUDIT_HEALTH_DEGRADED_PCT {
                AuditHealth::Degraded
            } else {
                AuditHealth::Healthy
            };
            let _ = self.health.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                if cur == AuditHealth::Fatal as u8 { None } else { Some(level as u8) }
            });
        }

        // Keep in-memory for fast verify_chain().
        let record_for_subscribers = log_entry.record.clone();
        inner.entries.push(log_entry);

        // Release the hash-chain lock BEFORE invoking subscriber callbacks —
        // never hold `inner` across a callback (same rule `trust_decay.rs`'s
        // `emit` follows for its own, separate subscriber-list mutex).
        drop(inner);
        for cb in self.subscribers.lock().expect("lock poisoned").iter() {
            cb(&record_for_subscribers);
        }
    }

    /// Verify the integrity of the in-memory audit chain.
    ///
    /// Also validates the sentinel file count if it exists (spec §15.3):
    /// the event count on disk must be >= the sentinel value.
    ///
    /// Returns `false` on any tampering detection.
    pub fn verify_chain(&self, issuer_secret: &[u8]) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");

        if inner.entries.is_empty() {
            // Empty chain — valid iff event_count is also 0.
            if inner.event_count != 0 {
                return false;
            }
            // Check sentinel: if sentinel file exists and shows count > 0, tamper detected.
            if let Ok(sentinel_str) = fs::read_to_string(&inner.count_file) {
                if let Ok(sentinel_count) = sentinel_str.trim().parse::<u64>() {
                    if sentinel_count > 0 {
                        return false;
                    }
                }
            }
            return true;
        }

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for entry in &inner.entries {
            if entry.record.prev_hash != expected_prev_hash {
                return false; // Chain broken
            }

            // Recompute HMAC over the same canonical record JSON.
            let record_json = serde_json::to_string(&serde_json::json!({
                "intent": entry.record.intent,
                "prev_hash": entry.record.prev_hash,
                "seq": entry.record.seq,
                "source": entry.record.source,
                "target": entry.record.target,
                "timestamp": entry.record.timestamp,
                "token_signature": entry.record.token_signature,
                "traceparent": entry.record.traceparent,
            })).unwrap_or_default();

            let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
            mac.update(record_json.as_bytes());
            let expected_sig = hex::encode(mac.finalize().into_bytes());

            // SECURITY: use constant-time hex comparison to prevent timing oracle.
            if !constant_time_eq_hex(&expected_sig, &entry.chain_hash) {
                return false; // Tampering detected
            }

            expected_prev_hash = entry.chain_hash.clone();
        }

        // Spec §15.3: Total disk count MUST be >= sentinel count.
        // The sentinel records how many events were accepted in-memory.
        // If the sentinel exists and shows a count HIGHER than in-memory, something was erased.
        if Path::new(&inner.count_file).exists() {
            if let Ok(sentinel_str) = fs::read_to_string(&inner.count_file) {
                if let Ok(sentinel_count) = sentinel_str.trim().parse::<u64>() {
                    if inner.event_count < sentinel_count {
                        return false; // Events were lost/erased
                    }
                }
            }
        }

        true
    }

    /// Full disk-based chain verification (spec §15.3 complete implementation).
    ///
    /// Re-reads the log file entry by entry, recomputes HMACs, and checks:
    /// 1. prev_hash of each entry matches chain_hash of previous entry.
    /// 2. chain_hash matches recomputed HMAC.
    /// 3. Total entry count on disk >= sentinel in SAACP_COUNT_FILE.
    ///
    /// NOTE: This requires the WAL thread to have flushed pending writes to disk.
    /// Use `verify_chain()` for in-process verification without disk I/O.
    pub fn verify_chain_disk(&self, issuer_secret: &[u8]) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        let log_file = &inner.log_file;
        let count_file = &inner.count_file;

        // Read all log entries from disk.
        let content = match fs::read_to_string(log_file) {
            Ok(c) => c,
            Err(_) => {
                // File missing — valid only if in-memory count is 0.
                return inner.event_count == 0;
            }
        };

        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();
        let disk_count = lines.len() as u64;

        // Check sentinel: disk count must be >= sentinel count.
        if Path::new(count_file).exists() {
            if let Ok(s) = fs::read_to_string(count_file) {
                if let Ok(sentinel) = s.trim().parse::<u64>() {
                    if disk_count < sentinel {
                        return false;
                    }
                }
            }
        }

        if lines.is_empty() {
            return true;
        }

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for line in &lines {
            let entry: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => return false,
            };
            let rec = &entry["record"];
            let chain_hash = match entry["chain_hash"].as_str() {
                Some(h) => h,
                None => return false,
            };
            let prev_hash = rec["prev_hash"].as_str().unwrap_or("");

            if prev_hash != expected_prev_hash {
                return false;
            }

            let record_json = serde_json::to_string(&serde_json::json!({
                "intent":          rec["intent"],
                "prev_hash":       rec["prev_hash"],
                "seq":             rec["seq"],
                "source":          rec["source"],
                "target":          rec["target"],
                "timestamp":       rec["timestamp"],
                "token_signature": rec["token_signature"],
                "traceparent":     rec["traceparent"],
            })).unwrap_or_default();

            let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
            mac.update(record_json.as_bytes());
            let expected_sig = hex::encode(mac.finalize().into_bytes());

            // SECURITY: constant-time hex comparison to prevent timing oracle.
            if !constant_time_eq_hex(&expected_sig, chain_hash) {
                return false;
            }

            expected_prev_hash = chain_hash.to_string();
        }

        true
    }

    /// Return the number of events in the chain.
    pub fn event_count(&self) -> u64 {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.event_count
    }

    /// Current Gate 6.0 backpressure health (see `AuditHealth`). Read by
    /// `handler::gate_2_5_kinetic_firewall` to decide whether IRREVERSIBLE_ACTION
    /// packets should be rejected while the audit trail is degraded or blind.
    pub fn health(&self) -> AuditHealth {
        AuditHealth::from_u8(self.health.load(Ordering::Relaxed))
    }

    /// Count of audit events dropped because the WAL queue was full (or the
    /// worker thread had already exited after a fatal open failure).
    pub fn dropped_audit_count(&self) -> u64 {
        self.dropped_audits.load(Ordering::Relaxed)
    }

    /// Count of WAL write failures — distinct from queue-full drops: the
    /// worker actually attempted a disk write and the OS returned an error.
    pub fn wal_write_failure_count(&self) -> u64 {
        self.wal_write_failures.load(Ordering::Relaxed)
    }

    /// Approximate current WAL queue depth (best-effort; maintained by hand
    /// since `mpsc::SyncSender` exposes no introspection API).
    pub fn queue_len(&self) -> usize {
        self.queue_len.load(Ordering::Relaxed)
    }

    /// Reset the audit log completely (for test isolation).
    pub fn reset(&self) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        let log_file = inner.log_file.clone();
        let count_file = inner.count_file.clone();
        inner.last_hash = GENESIS_HASH.to_string();
        inner.event_count = 0;
        inner.entries.clear();
        let _ = fs::remove_file(&log_file);
        let _ = fs::remove_file(&count_file);
    }

    /// Alias for `event_count()` used by audit facades.
    pub fn entry_count(&self) -> usize {
        self.event_count() as usize
    }

    /// Convenience: append a simple text message as an audit event.
    ///
    /// # Security Warning
    /// This method signs the audit entry with the hardcoded key `AUDIT_SENTINEL`.
    /// Because the key is publicly known, any caller can forge matching entries and
    /// the chain hash will still verify.  Use `append_event()` with a real secret key
    /// for any security-critical log entries.  This method is kept only for non-security
    /// diagnostic messages (e.g. daemon startup banners).
    #[deprecated(
        note = "Uses a publicly-known sentinel key. \
                Call append_event() with a real secret for security-critical entries."
    )]
    pub fn append(&self, message: String) {
        self.append_event(
            b"SAACP-AUDIT-DIAGNOSTIC-ONLY-NOT-SECRET",
            "system",
            "system",
            "",
            &message,
            &"0".repeat(48),
        );
    }

    /// Append an audit event with the `intent` field encrypted at rest
    /// (AES-256-GCM; see the "Audit-intent confidentiality" module docs and
    /// `encrypt_intent`). Opt-in — choose this instead of `append_event` when
    /// the deployment's threat model includes an attacker with filesystem
    /// read access to the log but not `issuer_secret`. Chain integrity is
    /// identical either way: `verify_chain`/`verify_chain_disk` need no
    /// changes, since the HMAC covers whatever string is in `intent`.
    /// Decrypt with `decrypt_intent`.
    pub fn append_event_confidential(
        &self,
        issuer_secret: &[u8],
        source_agent: &str,
        target_agent: &str,
        token_signature: &str,
        evaluated_intent: &str,
        traceparent: &str,
    ) {
        let encrypted = encrypt_intent(issuer_secret, evaluated_intent);
        self.append_event(
            issuer_secret, source_agent, target_agent, token_signature, &encrypted, traceparent,
        );
    }

    /// Convenience: append a signed audit event (alias for `append_event`).
    pub fn append_signed(
        &self,
        issuer_secret: &[u8],
        source_agent: &str,
        target_agent: &str,
        token_signature: &str,
        evaluated_intent: &str,
        traceparent: &str,
    ) {
        self.append_event(
            issuer_secret,
            source_agent,
            target_agent,
            token_signature,
            evaluated_intent,
            traceparent,
        );
    }
}

impl Default for ImmutableAuditLog {
    fn default() -> Self {
        Self::with_default_path()
    }
}

// ---------------------------------------------------------------------------
// WalWriter — persistent buffered file handle for the WAL worker (Fix 1)
// ---------------------------------------------------------------------------

/// Owns a persistent, buffered file handle across the lifetime of the WAL
/// worker thread so it never pays an open()+close() cost per event — the
/// original root cause of the Gate 6.0 latency spike: on Windows that cost is
/// dominated by kernel filter-driver / AV real-time-scan overhead per
/// syscall, not the syscall itself, and it forced the mpsc queue to
/// saturate under load.
///
/// See `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES` for the flush/durability contract.
struct WalWriter {
    path: String,
    /// `None` only for the instant between dropping the old handle and
    /// opening the new one during rotation — never observable from outside
    /// `maybe_rotate`.
    writer: Option<BufWriter<File>>,
    size: u64,
    entries_since_flush: u64,
    last_flush: Instant,
    /// Most recent event_count seen — written to the sentinel file at the
    /// same flush cadence as the WAL entries. Previously the sentinel was
    /// rewritten via a fresh open()+write()+close() on *every* event — an
    /// unnoticed second instance of the exact same root-cause bug. Batching
    /// it here means the sentinel can never claim a higher durable count
    /// than the entries it describes.
    pending_event_count: u64,
}

impl WalWriter {
    fn open(path: &str) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_string(),
            writer: Some(BufWriter::with_capacity(64 * 1024, file)),
            size,
            entries_since_flush: 0,
            last_flush: Instant::now(),
            pending_event_count: 0,
        })
    }

    /// Rotate BEFORE writing the next entry if the file is already oversized
    /// — same pre-write check order as the pre-Fix-1 code. Flushes + syncs +
    /// drops the handle first: required on Windows, where a file can't be
    /// renamed while a handle to it is open.
    fn maybe_rotate(&mut self) -> io::Result<()> {
        if self.size <= AUDIT_MAX_LOG_SIZE {
            return Ok(());
        }
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
            w.get_ref().sync_data()?;
        }
        self.writer = None;
        let rotated = format!("{}.{}.bak", self.path, now_secs() as u64);
        let _ = fs::rename(&self.path, &rotated);
        let file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.writer = Some(BufWriter::with_capacity(64 * 1024, file));
        self.size = 0;
        Ok(())
    }

    /// Write one entry. Errors propagate to the caller (Fix 2) instead of
    /// being silently swallowed.
    fn write_entry(&mut self, entry_json: &str, event_count: u64, count_file: &str) -> io::Result<()> {
        self.maybe_rotate()?;
        {
            let w = self.writer.as_mut().expect("writer present after maybe_rotate");
            writeln!(w, "{entry_json}")?;
        }
        self.size += entry_json.len() as u64 + 1;
        self.entries_since_flush += 1;
        self.pending_event_count = event_count;

        // Fix 3: durability window — flush + sync at most every
        // AUDIT_WAL_FLUSH_EVERY_N_ENTRIES entries or AUDIT_WAL_FLUSH_INTERVAL,
        // whichever comes first. `flush()` only moves bytes from the Rust
        // buffer into the OS page cache; `sync_data()` is what actually makes
        // them survive a power loss / kill -9, which is not optional for an
        // audit log making non-repudiation claims.
        let should_flush = self.entries_since_flush >= AUDIT_WAL_FLUSH_EVERY_N_ENTRIES
            || self.last_flush.elapsed() >= AUDIT_WAL_FLUSH_INTERVAL;
        if should_flush {
            let w = self.writer.as_mut().expect("writer present after maybe_rotate");
            w.flush()?;
            w.get_ref().sync_data()?;
            // Sentinel batched into the same flush boundary — see the
            // `pending_event_count` field doc.
            fs::write(count_file, self.pending_event_count.to_string())?;
            self.entries_since_flush = 0;
            self.last_flush = Instant::now();
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WAL worker thread body
// ---------------------------------------------------------------------------

/// Runs for the lifetime of the `ImmutableAuditLog` instance that spawned it
/// — exits when `wal_tx` is dropped (closing the channel and ending
/// `wal_rx.iter()`), or immediately if the log file can't be opened (Fix 2).
fn run_wal_worker(
    wal_rx: mpsc::Receiver<WalMessage>,
    log_file: &str,
    count_file: &str,
    health: &AtomicU8,
    wal_write_failures: &AtomicU64,
    queue_len: &AtomicUsize,
) {
    // In-memory-only mode (`ImmutableAuditLog::new("")`): drain without any
    // disk I/O. This is a deliberate no-persistence mode, not a failure —
    // health stays HEALTHY for the life of the instance.
    if log_file.is_empty() {
        for _msg in wal_rx.iter() {
            queue_len.fetch_sub(1, Ordering::Relaxed);
        }
        return;
    }

    let mut wal = match WalWriter::open(log_file) {
        Ok(w) => w,
        Err(e) => {
            // Fix 2: a WAL worker that can't open its log file is not
            // "degraded" — it is completely blind. This must be visible, and
            // it must halt here rather than silently no-op forever. The
            // channel disconnects when this thread returns, so every
            // subsequent `append_event` sees its `try_send` fail and counts
            // it as a dropped audit (never a silent no-op).
            health.store(AuditHealth::Fatal as u8, Ordering::SeqCst);
            eprintln!(
                "[SAACP audit] FATAL: WAL worker cannot open log file '{log_file}': {e} — \
                 audit subsystem is BLIND. No further events from this instance will reach \
                 disk. Restart the process (or construct a fresh ImmutableAuditLog) after \
                 fixing the underlying disk/permission issue."
            );
            return;
        }
    };

    for msg in wal_rx.iter() {
        queue_len.fetch_sub(1, Ordering::Relaxed);
        if let Err(e) = wal.write_entry(&msg.entry_json, msg.event_count, count_file) {
            // Fix 3: an atomic counter, not an inline eprintln! on this loop
            // — a sustained disk fault must not reintroduce the original
            // per-event-print hot-path bug.
            wal_write_failures.fetch_add(1, Ordering::Relaxed);
            // Fix 4: sticky FATAL. Log only on the transition into FATAL so a
            // sustained fault logs once, not once per failed write.
            let already_fatal =
                health.swap(AuditHealth::Fatal as u8, Ordering::SeqCst) == AuditHealth::Fatal as u8;
            if !already_fatal {
                eprintln!(
                    "[SAACP audit] FATAL: WAL write failed for '{log_file}': {e} — audit \
                     subsystem degraded. Gate 2.5 will now reject IRREVERSIBLE_ACTION packets \
                     referencing this log until a fresh ImmutableAuditLog is constructed."
                );
            }
        }
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- NonceTracker tests --

    #[test]
    fn test_nonce_track_unique() {
        let tracker = NonceTracker::new();
        assert!(tracker.track(1).is_ok());
        assert!(tracker.track(2).is_ok());
        assert!(tracker.track(3).is_ok());
        assert_eq!(tracker.count(), 3);
    }

    #[test]
    fn test_nonce_replay_detected() {
        let tracker = NonceTracker::new();
        tracker.track(42).unwrap();
        let err = tracker.track(42).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::InvalidSignature);
    }

    #[test]
    fn test_nonce_clear() {
        let tracker = NonceTracker::new();
        tracker.track(1).unwrap();
        tracker.clear();
        assert_eq!(tracker.count(), 0);
        // Can reuse nonce after clear
        assert!(tracker.track(1).is_ok());
    }

    #[test]
    fn test_nonce_custom_limits() {
        let tracker = NonceTracker::with_limits(0.001, 2);
        tracker.track(1).unwrap();
        tracker.track(2).unwrap();
        // Third should trigger eviction attempt; but they're too fresh
        // This depends on timing - if the test runs fast enough they'll still be within TTL
        let result = tracker.track(3);
        // Either succeeds (if eviction worked) or fails with CircuitBreakerOpen
        match result {
            Ok(()) => {}
            Err(e) => assert_eq!(e.bytecode, SAACPBytecodes::CircuitBreakerOpen),
        }
    }

    // -- ImmutableAuditLog tests --

    fn test_audit_log(name: &str) -> ImmutableAuditLog {
        let log_file = format!("test_audit_{}.log", name);
        let count_file = format!("test_audit_{}.sentinel", name);
        let log = ImmutableAuditLog::with_paths(&log_file, &count_file);
        log.reset(); // Clean slate
        log
    }

    #[test]
    fn test_audit_append_and_verify() {
        let log = test_audit_log("append_verify");
        let secret = b"audit_secret_key";

        log.append_event(secret, "agent-a", "agent-b", "sig-001", "read:data", "trace-001");
        log.append_event(secret, "agent-b", "agent-c", "sig-002", "write:data", "trace-002");

        assert_eq!(log.event_count(), 2);
        assert!(log.verify_chain(secret));
        log.reset();
    }

    #[test]
    fn test_subscribe_notified_on_append_with_correct_record() {
        let log = test_audit_log("subscribe_basic");
        let secret = b"audit_secret_key";

        let received: Arc<Mutex<Vec<AuditRecord>>> = Arc::new(Mutex::new(Vec::new()));
        let received2 = Arc::clone(&received);
        log.subscribe(Arc::new(move |record: &AuditRecord| {
            received2.lock().unwrap().push(record.clone());
        }));

        log.append_event(secret, "agent-a", "agent-b", "sig-001", "read:data", "trace-001");

        let recs = received.lock().unwrap();
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].source, "agent-a");
        assert_eq!(recs[0].target, "agent-b");
        assert_eq!(recs[0].intent, "read:data");
        log.reset();
    }

    #[test]
    fn test_subscribe_does_not_affect_chain_verification() {
        // Adding a subscriber must not change AuditRecord's HMAC input
        // (that's driven entirely by the separate CanonicalAuditRecord) —
        // confirm the chain still verifies correctly with a subscriber attached.
        let log = test_audit_log("subscribe_chain_integrity");
        let secret = b"audit_secret_key";
        log.subscribe(Arc::new(|_record: &AuditRecord| {}));

        log.append_event(secret, "agent-a", "agent-b", "sig-001", "read:data", "trace-001");
        log.append_event(secret, "agent-b", "agent-c", "sig-002", "write:data", "trace-002");

        assert!(log.verify_chain(secret));
        log.reset();
    }

    #[test]
    fn test_multiple_subscribers_all_notified() {
        let log = test_audit_log("subscribe_multi");
        let secret = b"audit_secret_key";

        let count_a = Arc::new(Mutex::new(0u32));
        let count_b = Arc::new(Mutex::new(0u32));
        let ca = Arc::clone(&count_a);
        let cb = Arc::clone(&count_b);
        log.subscribe(Arc::new(move |_record: &AuditRecord| { *ca.lock().unwrap() += 1; }));
        log.subscribe(Arc::new(move |_record: &AuditRecord| { *cb.lock().unwrap() += 1; }));

        log.append_event(secret, "agent-a", "agent-b", "sig-001", "read:data", "trace-001");

        assert_eq!(*count_a.lock().unwrap(), 1);
        assert_eq!(*count_b.lock().unwrap(), 1);
        log.reset();
    }

    #[test]
    fn test_audit_empty_chain_valid() {
        let log = test_audit_log("empty");
        assert!(log.verify_chain(b"secret"));
        log.reset();
    }

    #[test]
    fn test_audit_wrong_secret_fails() {
        let log = test_audit_log("wrong_secret");
        log.append_event(b"correct_secret", "a", "b", "sig", "intent", "trace");
        // Verifying with wrong secret should fail
        assert!(!log.verify_chain(b"wrong_secret"));
        log.reset();
    }

    #[test]
    fn test_audit_chain_integrity() {
        let log = test_audit_log("integrity");
        let secret = b"integrity_key";

        for i in 0..5 {
            log.append_event(
                secret,
                &format!("agent-{}", i),
                &format!("agent-{}", i + 1),
                &format!("sig-{}", i),
                &format!("intent-{}", i),
                &format!("trace-{}", i),
            );
        }

        assert_eq!(log.event_count(), 5);
        assert!(log.verify_chain(secret));
        log.reset();
    }

    #[test]
    fn test_audit_reset() {
        let log = test_audit_log("reset");
        let secret = b"secret";
        log.append_event(secret, "a", "b", "sig", "intent", "trace");
        assert_eq!(log.event_count(), 1);
        log.reset();
        assert_eq!(log.event_count(), 0);
        assert!(log.verify_chain(secret));
    }

    /// Guarantees every event appended so far is actually flushed+synced to
    /// disk: sleeps past `AUDIT_WAL_FLUSH_INTERVAL_MS` (so the elapsed-time
    /// flush condition is armed on the WAL worker thread), then appends one
    /// more throwaway event — whose `write_entry()` call observes the
    /// elapsed time and flushes the `BufWriter`, which is cumulative and
    /// therefore also flushes every entry buffered before it.
    ///
    /// Rather than trusting a fixed sleep for the flush itself to land
    /// (unreliable under parallel-test scheduler load), this polls the
    /// actual log file on disk for `expected_lines` with a bounded timeout.
    fn force_wal_flush_and_drain(
        log: &ImmutableAuditLog,
        secret: &[u8],
        log_file: &str,
        expected_lines: usize,
    ) {
        thread::sleep(Duration::from_millis(AUDIT_WAL_FLUSH_INTERVAL_MS + 20));
        log.append_event(secret, "__flush__", "__flush__", "__flush__", "__flush__", "__flush__");
        for _ in 0..500 {
            if let Ok(content) = fs::read_to_string(log_file) {
                if content.lines().filter(|l| !l.is_empty()).count() >= expected_lines {
                    return;
                }
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!("WAL flush did not land on disk within timeout");
    }

    /// H-6 regression: `initialize_chain` must verify disk state, not blindly
    /// trust it. A valid, untampered log file is accepted.
    #[test]
    fn test_initialize_chain_accepts_valid_disk_state() {
        let log = test_audit_log("init_chain_valid");
        let log_file = "test_audit_init_chain_valid.log";
        let secret = b"init_chain_secret";
        log.append_event(secret, "a", "b", "sig-1", "intent-1", "trace-1");
        log.append_event(secret, "b", "c", "sig-2", "intent-2", "trace-2");
        // 2 real events + 1 flush-forcing event.
        force_wal_flush_and_drain(&log, secret, log_file, 3);

        assert!(log.initialize_chain(secret).is_ok());
        assert_eq!(log.event_count(), 3);
        log.reset();
    }

    /// H-6 regression: a tampered on-disk chain_hash must be rejected, not
    /// silently adopted as the new chain head — this was the core vulnerability
    /// (chain integrity bypass via untrusted disk data).
    #[test]
    fn test_initialize_chain_rejects_tampered_disk_state() {
        let log = test_audit_log("init_chain_tampered");
        let log_file = "test_audit_init_chain_tampered.log";
        let secret = b"init_chain_secret_2";
        log.append_event(secret, "a", "b", "sig-1", "intent-1", "trace-1");
        // 1 real event + 1 flush-forcing event.
        force_wal_flush_and_drain(&log, secret, log_file, 2);

        // Tamper with the on-disk chain_hash of the first entry.
        let content = fs::read_to_string(log_file).expect("log file must exist");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 2, "expected both entries flushed to disk");
        let mut entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        entry["chain_hash"] = serde_json::Value::String("deadbeef".repeat(8));
        lines[0] = entry.to_string();
        fs::write(log_file, format!("{}\n{}\n", lines[0], lines[1])).unwrap();

        let result = log.initialize_chain(secret);
        assert!(result.is_err());
        // Fail-closed: in-memory state must be reset to genesis, not left
        // trusting the tampered tail hash.
        assert_eq!(log.event_count(), 0);
        log.reset();
    }

    /// H-6 regression: a missing log file is valid empty state (matches
    /// `verify_chain_disk`'s existing missing-file semantics).
    #[test]
    fn test_initialize_chain_missing_file_is_valid_empty() {
        let log = test_audit_log("init_chain_missing");
        // test_audit_log() -> reset() already deletes any existing files.
        assert!(log.initialize_chain(b"any_secret").is_ok());
        assert_eq!(log.event_count(), 0);
    }

    #[test]
    fn test_audit_single_event() {
        let log = test_audit_log("single");
        let secret = b"single_key";
        log.append_event(secret, "src", "dst", "abc123", "execute", "tp-001");
        assert!(log.verify_chain(secret));
        log.reset();
    }

    #[test]
    fn test_audit_wal_constants() {
        assert_eq!(AUDIT_WAL_QUEUE_CAPACITY, 100_000);
        assert_eq!(AUDIT_MAX_LOG_SIZE, 50_000_000);
        assert_eq!(AUDIT_LOG_FILE, "saacp_audit.log");
        assert_eq!(AUDIT_COUNT_FILE, "saacp_event_count.sentinel");
        assert_eq!(ENV_AUDIT_LOG, "SAACP_AUDIT_LOG");
        assert_eq!(ENV_COUNT_FILE, "SAACP_COUNT_FILE");
        // Gate 6.0 backpressure repair: durability window must be a stated,
        // testable number — not just "we flush periodically".
        assert_eq!(AUDIT_WAL_FLUSH_EVERY_N_ENTRIES, 200);
        assert_eq!(AUDIT_WAL_FLUSH_INTERVAL_MS, 50);
    }

    #[test]
    fn test_audit_health_ordering_and_default() {
        // Fix 4 contract: Healthy < Degraded < Saturated < Fatal, and a
        // freshly constructed log starts Healthy with zero drop/failure counts.
        assert!(AuditHealth::Healthy < AuditHealth::Degraded);
        assert!(AuditHealth::Degraded < AuditHealth::Saturated);
        assert!(AuditHealth::Saturated < AuditHealth::Fatal);

        let log = test_audit_log("health_default");
        assert_eq!(log.health(), AuditHealth::Healthy);
        assert_eq!(log.dropped_audit_count(), 0);
        assert_eq!(log.wal_write_failure_count(), 0);
        log.reset();
    }

    #[test]
    fn test_audit_env_var_constants_exported() {
        // Verify env var names match Appendix A of spec.
        assert_eq!(ENV_AUDIT_LOG, "SAACP_AUDIT_LOG");
        assert_eq!(ENV_COUNT_FILE, "SAACP_COUNT_FILE");
    }

    // -- Audit-intent confidentiality (STRIDE Information Disclosure fix) --

    #[test]
    fn test_encrypt_intent_roundtrip() {
        let secret = b"audit-intent-secret-32-bytes!!!";
        let plaintext = "transfer $5000 from acct-A to acct-B";
        let encrypted = encrypt_intent(secret, plaintext);
        // Ciphertext must not leak the plaintext as a substring.
        assert!(!encrypted.contains("transfer"));
        assert!(!encrypted.contains("acct-A"));
        let decrypted = decrypt_intent(secret, &encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypt_intent_wrong_key_fails() {
        let secret = b"audit-intent-secret-32-bytes!!!";
        let wrong = b"a-completely-different-secret!!";
        let encrypted = encrypt_intent(secret, "sensitive task detail");
        assert!(decrypt_intent(wrong, &encrypted).is_err());
    }

    #[test]
    fn test_encrypt_intent_nonce_uniqueness() {
        // Same plaintext, same key — different nonces must produce different
        // ciphertexts (no keystream/nonce reuse).
        let secret = b"audit-intent-secret-32-bytes!!!";
        let a = encrypt_intent(secret, "same task text");
        let b = encrypt_intent(secret, "same task text");
        assert_ne!(a, b);
        assert_eq!(decrypt_intent(secret, &a).unwrap(), "same task text");
        assert_eq!(decrypt_intent(secret, &b).unwrap(), "same task text");
    }

    #[test]
    fn test_decrypt_intent_rejects_corrupt_input() {
        let secret = b"audit-intent-secret-32-bytes!!!";
        assert!(decrypt_intent(secret, "not-valid-hex").is_err());
        assert!(decrypt_intent(secret, "aabb").is_err()); // too short
    }

    #[test]
    fn test_append_event_confidential_preserves_chain_integrity() {
        let log = test_audit_log("confidential");
        let secret = b"confidential_audit_secret_key!!!";
        let plaintext_intent = "delete all records matching filter X";

        log.append_event_confidential(secret, "agent-a", "agent-b", "sig-001", plaintext_intent, "trace-001");
        log.append_event(secret, "agent-b", "agent-c", "sig-002", "ordinary plaintext intent", "trace-002");

        // Chain integrity (HMAC over whatever string is in `intent`) is
        // completely unaffected by whether that string is ciphertext or
        // plaintext.
        assert_eq!(log.event_count(), 2);
        assert!(log.verify_chain(secret));

        // The stored intent for the first entry is ciphertext, not plaintext,
        // and decrypts back to the original.
        // Scoped so the MutexGuard drops before `log.reset()` below re-locks
        // `inner` — holding a reference derived from it across that call
        // would deadlock (the lock is not reentrant).
        let stored_intent = {
            let inner = log.inner.lock().unwrap();
            inner.entries[0].record.intent.clone()
        };
        assert_ne!(stored_intent, plaintext_intent);
        assert_eq!(decrypt_intent(secret, &stored_intent).unwrap(), plaintext_intent);

        log.reset();
    }
}
