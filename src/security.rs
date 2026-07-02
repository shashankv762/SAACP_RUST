//! security.rs — Nonce Tracking + Immutable Audit Log
//!
//! Implements:
//! - `NonceTracker`: Tracks nonces to defeat Replay Attacks
//! - `ImmutableAuditLog`: Append-only cryptographic hash chain with WAL worker thread

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock, mpsc};
use std::thread;
use std::time::SystemTime;
use std::fs;
use std::path::Path;

use sha2::Sha256;
use hmac::{Hmac, Mac};

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

/// Genesis hash for the audit chain.
const GENESIS_HASH: &str = "47454e455349535f424c4f434b"; // hex of b"GENESIS_BLOCK"

/// An audit log entry record.
#[derive(Debug, Clone)]
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

// ---------------------------------------------------------------------------
// WAL worker message
// ---------------------------------------------------------------------------

struct WalMessage {
    entry_json: String,
    log_file: String,
    count_file: String,
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
/// Disk I/O is handled by a background WAL worker thread (spec §15.2).
/// If the WAL queue is full, the event is dropped and logged to stderr —
/// dropping is preferred over blocking or rejecting the packet.
pub struct ImmutableAuditLog {
    inner: Mutex<AuditInner>,
    /// WAL worker sender. Always `Some` — even a "" log_file spawns the worker,
    /// but `wal_write_entry` silently no-ops on an empty path (see `new()`).
    wal_tx: Option<mpsc::SyncSender<WalMessage>>,
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
    /// count_file too, so `wal_write_entry`'s sentinel write silently no-ops and
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

        // Spawn WAL worker daemon thread.
        thread::Builder::new()
            .name("saacp-wal-worker".into())
            .spawn(move || {
                while let Ok(msg) = wal_rx.recv() {
                    wal_write_entry(&msg.entry_json, &msg.log_file, msg.event_count, &msg.count_file);
                }
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
        }
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
    pub fn initialize_chain(&self) {
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
    }

    /// Append one audit event to the in-memory chain and enqueue for WAL persistence.
    ///
    /// The chain hash is computed inline (synchronous) so the in-memory chain is
    /// always coherent. Disk I/O is offloaded to the WAL worker thread.
    /// If the WAL queue is full, the event is dropped to stderr — the packet is
    /// NOT rejected (spec §15.2: "Dropping an event is preferred over rejecting the packet").
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

        // Serialize deterministically with sort_keys (canonical JSON).
        let record_json = serde_json::to_string(&serde_json::json!({
            "intent": record.intent,
            "prev_hash": record.prev_hash,
            "seq": record.seq,
            "source": record.source,
            "target": record.target,
            "timestamp": record.timestamp,
            "token_signature": record.token_signature,
            "traceparent": record.traceparent,
        })).unwrap_or_default();

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

        // Build JSONL line for disk persistence.
        let entry_json = serde_json::to_string(&serde_json::json!({
            "record": {
                "intent": log_entry.record.intent,
                "prev_hash": log_entry.record.prev_hash,
                "seq": log_entry.record.seq,
                "source": log_entry.record.source,
                "target": log_entry.record.target,
                "timestamp": log_entry.record.timestamp,
                "token_signature": log_entry.record.token_signature,
                "traceparent": log_entry.record.traceparent,
            },
            "chain_hash": log_entry.chain_hash,
        })).unwrap_or_default();

        // Enqueue for WAL worker (non-blocking — drop if full, per spec §15.2).
        if let Some(ref tx) = self.wal_tx {
            let msg = WalMessage {
                entry_json,
                log_file: inner.log_file.clone(),
                count_file: inner.count_file.clone(),
                event_count: inner.event_count,
            };
            if tx.try_send(msg).is_err() {
                eprintln!(
                    "[SAACP AUDIT] WAL queue full — event seq={} dropped to stderr",
                    inner.event_count - 1
                );
            }
        }

        // Keep in-memory for fast verify_chain().
        inner.entries.push(log_entry);
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
// WAL worker helper — called from the background thread
// ---------------------------------------------------------------------------

fn wal_write_entry(entry_json: &str, log_file: &str, event_count: u64, count_file: &str) {
    // Rotate if file exceeds 50 MB.
    if let Ok(metadata) = fs::metadata(log_file) {
        if metadata.len() > AUDIT_MAX_LOG_SIZE {
            let rotated = format!("{}.{}.bak", log_file, now_secs() as u64);
            let _ = fs::rename(log_file, rotated);
        }
    }

    // Append JSONL entry to log file.
    let _ = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_file)
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(f, "{}", entry_json)
        });

    // Update sentinel file with current event count.
    let _ = fs::write(count_file, format!("{}", event_count));
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
    }

    #[test]
    fn test_audit_env_var_constants_exported() {
        // Verify env var names match Appendix A of spec.
        assert_eq!(ENV_AUDIT_LOG, "SAACP_AUDIT_LOG");
        assert_eq!(ENV_COUNT_FILE, "SAACP_COUNT_FILE");
    }
}
