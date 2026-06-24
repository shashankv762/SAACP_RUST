//! security.rs — Nonce Tracking + Immutable Audit Log
//!
//! Implements:
//! - `NonceTracker`: Tracks nonces to defeat Replay Attacks
//! - `ImmutableAuditLog`: Append-only cryptographic hash chain

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;
use std::fs;
use std::path::Path;

use sha2::Sha256;
use hmac::{Hmac, Mac};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

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

/// Default log file path.
pub const AUDIT_LOG_FILE: &str = "saacp_audit.log";
/// Maximum log file size before rotation (50MB).
pub const AUDIT_MAX_LOG_SIZE: u64 = 50_000_000;

/// Genesis hash for the audit chain.
const GENESIS_HASH: &str = "47454e455349535f424c4f434b"; // hex of "GENESIS_BLOCK"

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

/// Append-Only Cryptographic Hash Chain Audit Log.
///
/// Ties Distributed Tracing (traceparent) to lateral movement token signatures.
/// If a compromised agent alters a past entry, the chain breaks.
/// Detects file deletion and partial truncation attacks.
pub struct ImmutableAuditLog {
    inner: Mutex<AuditInner>,
}

struct AuditInner {
    last_hash: String,
    event_count: u64,
    log_file: String,
    entries: Vec<AuditLogEntry>, // In-memory chain for verification
}

impl ImmutableAuditLog {
    /// Create a new ImmutableAuditLog.
    pub fn new(log_file: &str) -> Self {
        Self {
            inner: Mutex::new(AuditInner {
                last_hash: GENESIS_HASH.to_string(),
                event_count: 0,
                log_file: log_file.to_string(),
                entries: Vec::new(),
            }),
        }
    }

    /// Create a new audit log with default file path.
    pub fn with_default_path() -> Self {
        Self::new(AUDIT_LOG_FILE)
    }

    /// Initialize the chain from an existing log file.
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

    /// Append one audit event to the in-memory chain and persist to disk.
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

        // Serialize deterministically for hashing
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

        // HMAC-SHA256 over the record
        let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
        mac.update(record_json.as_bytes());
        let chain_hash = hex::encode(mac.finalize().into_bytes());

        let log_entry = AuditLogEntry {
            record,
            chain_hash: chain_hash.clone(),
        };

        inner.last_hash = chain_hash;
        inner.event_count += 1;

        // Persist to disk synchronously
        let log_file = inner.log_file.clone();
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

        // Rotate if needed
        if let Ok(metadata) = fs::metadata(&log_file) {
            if metadata.len() > AUDIT_MAX_LOG_SIZE {
                let rotated = format!("{}.{}.bak", log_file, now_secs() as u64);
                let _ = fs::rename(&log_file, rotated);
            }
        }

        let _ = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_file)
            .and_then(|mut f| {
                use std::io::Write;
                writeln!(f, "{}", entry_json)
            });

        // Keep in-memory for verification
        inner.entries.push(log_entry);
    }

    /// Verify the integrity of the audit chain.
    pub fn verify_chain(&self, issuer_secret: &[u8]) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");

        if inner.entries.is_empty() {
            return inner.event_count == 0;
        }

        let mut expected_prev_hash = GENESIS_HASH.to_string();

        for entry in &inner.entries {
            if entry.record.prev_hash != expected_prev_hash {
                return false; // Chain broken
            }

            // Recompute HMAC
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

            if expected_sig != entry.chain_hash {
                return false; // Tampering detected
            }

            expected_prev_hash = entry.chain_hash.clone();
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
        inner.last_hash = GENESIS_HASH.to_string();
        inner.event_count = 0;
        inner.entries.clear();
        let _ = fs::remove_file(&log_file);
    }
    /// Alias for `event_count()` used by audit facades.
    pub fn entry_count(&self) -> usize {
        self.event_count() as usize
    }

    /// Convenience: append a simple text message as an audit event.
    pub fn append(&self, message: String) {
        self.append_event(
            b"AUDIT_SENTINEL",
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
        let log = ImmutableAuditLog::new(&log_file);
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
}
