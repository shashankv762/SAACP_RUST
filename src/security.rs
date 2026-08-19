//! security.rs — Nonce Tracking + Immutable Audit Log
//!
//! Implements:
//! - `NonceTracker`: Tracks nonces to defeat Replay Attacks
//! - `ImmutableAuditLog`: Append-only cryptographic hash chain with WAL worker thread
//!
//! C-4: rotated audit logs (`<path>.<timestamp>.bak`, written by `WalWriter::maybe_rotate`
//! once the active log exceeds `AUDIT_MAX_LOG_SIZE`) are gzip-compressed to `.bak.gz` on a
//! dedicated `saacp-audit-archival` background thread — never the `saacp-wal-worker` thread
//! that services live writes, so compression never adds latency to audit-log appends. What
//! happens to the compressed file afterward is pluggable via the [`ArchivalSink`] trait —
//! see its doc comment, [`NoopArchivalSink`] (default), and [`FilesystemArchivalSink`]
//! (opt in via [`ENV_AUDIT_ARCHIVE_DIR`] or [`ImmutableAuditLog::with_paths_and_archival_sink`]).

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, mpsc};
use std::sync::atomic::{AtomicU8, AtomicU64, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;

use sha2::{Sha256, Digest};
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
///
/// M-1 fix: this is the SINGLE canonical implementation for the whole crate.
/// `gateway.rs`, `command_center.rs`, and `identity_binding.rs` previously each
/// carried a byte-identical private copy of this function (and of
/// `constant_time_eq_hex` below) — harmless on its own, but a maintenance trap:
/// a future correctness fix applied to one copy silently would not propagate to
/// the other three. `pub(crate)` so every module in this crate can call this one
/// instead of redefining it.
/// L-5 fix: delegates to `subtle::ConstantTimeEq` (already a declared dependency,
/// already used elsewhere in this crate — nothing new pulled in) instead of a
/// hand-rolled `diff |= x ^ y` loop. LLVM is legally permitted to prove `diff == 0`
/// early and short-circuit a hand-written loop like the old one under aggressive
/// inlining/optimization, defeating the constant-time intent; `subtle::ConstantTimeEq`
/// is specifically engineered to resist that. The `a.len() != b.len()` short-circuit is
/// kept as-is — length isn't secret, so comparing it in variable time is fine; only the
/// byte-content comparison needs the constant-time guarantee.
pub(crate) fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

/// Constant-time comparison of two hex-encoded HMAC digests (as strings).
/// Decodes both to raw bytes before comparing so no timing information
/// about the first differing hex character leaks.
///
/// M-1 fix: canonical implementation — see `constant_time_eq`'s doc comment.
pub(crate) fn constant_time_eq_hex(a: &str, b: &str) -> bool {
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

/// L-1 fix: HKDF-Extract salt for audit-intent key derivation. `AUDIT_INTENT_HKDF_INFO`
/// (above) already domain-separates the *expand* step, but a `None` salt at the
/// *extract* step falls back to a zero-filled salt per RFC 5869 — fine per-spec, but it
/// gives up free domain separation between this extraction and any other unsalted HKDF
/// extraction elsewhere that might reuse the same `issuer_secret` as IKM. A fixed,
/// purpose-specific salt closes that gap even though no such collision is known today.
const AUDIT_INTENT_HKDF_SALT: &[u8] = b"SAACP-audit-intent-hkdf-salt-v1";

/// Derive a 32-byte AES-256-GCM key for audit-intent encryption from the same
/// `issuer_secret` already used for chain-hash HMACs, via HKDF-SHA256.
fn derive_intent_key(issuer_secret: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(AUDIT_INTENT_HKDF_SALT), issuer_secret);
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
/// C-4: optional directory that rotated-and-gzip-compressed audit logs are moved into
/// after compression. Unset (the default) leaves compressed `.bak.gz` files beside the
/// live WAL — see [`FilesystemArchivalSink`] / [`ArchivalSink`].
pub const ENV_AUDIT_ARCHIVE_DIR: &str = "SAACP_AUDIT_ARCHIVE_DIR";

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
        self.track_key(nonce)
    }

    /// M-4 fix: track a nonce scoped to `session_id`, so the same raw nonce
    /// value reused by two different sessions is not treated as a replay of
    /// itself. `NonceTracker` as originally written has no per-session
    /// scoping baked into `track()` — every caller shares one flat `u64`
    /// keyspace. That is a real hazard for any *future* caller that tracks
    /// nonces across multiple concurrent sessions from one shared
    /// `NonceTracker` (today, `NonceTracker` is only exercised by this
    /// module's own unit tests; production replay protection for MEASC
    /// traffic is `ReplayWindow`/`PacketSequencer` in `measc.rs`, which is
    /// already correctly scoped per `SessionEpochManager` entry). Composes
    /// `(session_id, nonce)` into a single derived key via SHA-256 (truncated
    /// to the first 8 bytes) before delegating to the same atomic
    /// check-and-insert logic `track()` uses — a different `session_id` with
    /// the same `nonce` value hashes to a different key, so no cross-session
    /// collision is possible.
    pub fn track_scoped(&self, session_id: &str, nonce: u64) -> Result<(), SAACPHardDrop> {
        self.track_key(Self::composite_key(session_id, nonce))
    }

    /// Derive a session-scoped `u64` key from `(session_id, nonce)` via
    /// SHA-256 truncated to its first 8 bytes (big-endian). Collision
    /// probability is cryptographically negligible for any realistic number
    /// of tracked (session, nonce) pairs.
    fn composite_key(session_id: &str, nonce: u64) -> u64 {
        let mut hasher = Sha256::new();
        hasher.update(session_id.as_bytes());
        hasher.update(nonce.to_be_bytes());
        let digest = hasher.finalize();
        u64::from_be_bytes(digest[0..8].try_into().expect("SHA-256 digest is >= 8 bytes"))
    }

    /// Shared atomic check-and-insert-with-pruning logic backing both
    /// `track()` (raw nonce as key) and `track_scoped()` (session-composited
    /// key) — the only difference between the two public entry points is
    /// which `u64` they pass in here.
    fn track_key(&self, key: u64) -> Result<(), SAACPHardDrop> {
        let current_time = now_secs();
        let mut inner = self.inner.lock().expect("lock poisoned");

        // Atomic check-and-insert (fixes TOCTOU race condition)
        if inner.seen_nonces.contains_key(&key) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "REPLAY ATTACK DETECTED: Nonce already used.",
            ));
        }

        inner.seen_nonces.insert(key, current_time);

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

/// L-10 fix: default timeout for [`ImmutableAuditLog::flush`]'s ack wait — used by
/// every graceful-shutdown call site (`daemon.rs`, `transport/ws.rs`,
/// `transport/tls.rs`, `sidecar.rs`) as the bound on how long shutdown waits for the
/// WAL worker to confirm a final flush+sync before the process exits.
pub const AUDIT_FLUSH_ON_SHUTDOWN_TIMEOUT_SECS: u64 = 5;

/// S-6 fix: cap on the number of `AuditLogEntry` records retained in the
/// in-memory `AuditInner::entries` vector. This vector exists to serve the fast
/// in-process `verify_chain()`; every appended event was previously kept for the
/// entire process lifetime, so a long-running daemon accumulated hundreds of MB
/// (a memory leak, not a bypass). Once the vector exceeds this cap, `append_event`
/// drains the oldest 20% — the full, authoritative history remains on disk and is
/// checked by `verify_chain_disk()`. `event_count` (the running total, used by the
/// sentinel check) is deliberately NOT reset by the drain, so tamper detection
/// against the on-disk sentinel is unaffected. `verify_chain()` seeds its expected
/// hash from the first retained entry's `prev_hash`, so a drained window still
/// verifies internal continuity.
pub const AUDIT_MAX_IN_MEMORY_ENTRIES: usize = 100_000;

const AUDIT_WAL_FLUSH_INTERVAL: Duration = Duration::from_millis(AUDIT_WAL_FLUSH_INTERVAL_MS);

/// WAL queue-depth ratio above which `AuditHealth` becomes `Degraded`.
const AUDIT_HEALTH_DEGRADED_PCT: f64 = 0.70;
/// WAL queue-depth ratio above which `AuditHealth` becomes `Saturated`.
const AUDIT_HEALTH_SATURATED_PCT: f64 = 0.95;

/// Genesis hash for the audit chain.
const GENESIS_HASH: &str = "47454e455349535f424c4f434b"; // hex of b"GENESIS_BLOCK"

// ---------------------------------------------------------------------------
// Phase 6 — sharded hash chains + Merkle anchoring
// ---------------------------------------------------------------------------

/// Number of independent hash chains the audit log is split across.
///
/// The single `Mutex<AuditInner>` held across HMAC-SHA256 + `serde_json` +
/// `try_send` was the measured throughput ceiling (~250-360k events/sec, see
/// `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES`'s neighbours and `T14`/`T20`). Splitting it
/// into N independently-chained shards removes the serialization point without
/// weakening any per-record guarantee: each shard is a complete, HMAC-covered
/// prev_hash chain in its own right, and the periodic Merkle anchor ties all N
/// heads together so no shard can be rewritten, reordered, or dropped wholesale.
///
/// **The WAL channel is deliberately NOT sharded** — one `wal_tx`, one worker
/// thread, one queue capacity. The worker was never the bottleneck (362k
/// events/sec of pure I/O), so `health`, `health_floor`, `dropped_audits`,
/// `wal_write_failures`, `queue_len`, the sticky-`Fatal` `fetch_update`, and the
/// `gate_2_5_kinetic_firewall` saturation contract all carry over completely
/// unmodified.
pub const AUDIT_SHARDS: usize = 16;

/// A power of two makes the Merkle tree over `AUDIT_SHARDS` leaves perfectly
/// complete: every internal node has exactly two children, so there is no
/// odd-node promotion/duplication rule. That absence is what makes
/// CVE-2012-2459-style tree malleability (two distinct leaf sets hashing to the
/// same root by duplicating a lone trailing node) structurally impossible here
/// rather than merely guarded against. Enforced at compile time so a future
/// edit to `AUDIT_SHARDS` cannot silently reintroduce the hazard.
const _: () = assert!(
    AUDIT_SHARDS.is_power_of_two(),
    "AUDIT_SHARDS must be a power of two so the Merkle tree is complete and \
     has no odd-node duplication rule (CVE-2012-2459 class malleability)",
);

/// Per-shard cap on retained in-memory entries.
///
/// The aggregate bound stays [`AUDIT_MAX_IN_MEMORY_ENTRIES`] — sharding must not
/// silently multiply the memory this vector can consume, the same split
/// `RATE_LIMITER_PER_SHARD_MAX_ENTRIES` and `TOKEN_CACHE_PER_SHARD_MAX` use.
///
/// The drain MUST be per-shard rather than global: `verify_chain` seeds each
/// shard's expected hash from that shard's first *retained* entry (the S-6
/// rule), so a drain that removed a prefix of one shard's entries while leaving
/// another's intact would still leave every shard internally continuous. A
/// global drain across a merged list would cut shards at arbitrary points and
/// break that seeding invariant, failing verification spuriously.
const AUDIT_PER_SHARD_MAX_IN_MEMORY: usize = AUDIT_MAX_IN_MEMORY_ENTRIES / AUDIT_SHARDS;

/// Domain-separation tag for per-shard genesis hashes. Each shard `i` starts
/// from `SHA256(tag || u16BE(i))` rather than a shared constant, so a record
/// cannot be relocated from shard `i` to shard `j` and still chain — the first
/// record of every shard commits to that shard's unique genesis.
const AUDIT_SHARD_GENESIS_TAG: &[u8] = b"SAACP-audit-shard-genesis-v1";

/// Records written by the sharded (v2) code path carry `v: 2`.
///
/// A v1 line has **no** `v` field at all, and that absence is the entire
/// migration discriminator — `verify_chain_disk` branches on it per line, so a
/// file may contain a v1 prefix followed by a v2 suffix and still verify end to
/// end. Never emit `v: 1`; doing so would make old and new logs
/// indistinguishable from each other by structure.
const AUDIT_RECORD_VERSION_V2: u8 = 2;

/// Merkle anchor cadence: emit an anchor line after this many events...
const AUDIT_ANCHOR_EVERY_N_EVENTS: u64 = 4096;
/// ...or after this much wall-clock time, whichever comes first.
const AUDIT_ANCHOR_INTERVAL: Duration = Duration::from_secs(1);

/// RFC 6962 §2.1 domain separation: leaf hashes are `SHA256(0x00 || leaf)`,
/// interior nodes `SHA256(0x01 || left || right)`. Without the distinct
/// prefixes an attacker could present an interior node as a leaf (second
/// preimage across tree levels).
const MERKLE_LEAF_PREFIX: u8 = 0x00;
/// See [`MERKLE_LEAF_PREFIX`].
const MERKLE_NODE_PREFIX: u8 = 0x01;

/// Marker distinguishing an anchor line from a record line on disk.
const ANCHOR_LINE_KEY: &str = "anchor";

/// Genesis value for the anchor chain's `prev_root`, so the very first anchor
/// is still bound to a fixed starting point and an attacker cannot delete the
/// whole first epoch and present the second as the beginning.
const ANCHOR_GENESIS_ROOT: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";

/// Per-shard genesis hash: `SHA256(AUDIT_SHARD_GENESIS_TAG || u16BE(shard_id))`.
fn shard_genesis_hash(shard_id: u16) -> String {
    let mut h = Sha256::new();
    h.update(AUDIT_SHARD_GENESIS_TAG);
    h.update(shard_id.to_be_bytes());
    hex::encode(h.finalize())
}

/// RFC 6962 leaf hash over a shard head (`SHA256(0x00 || shard_id_be || head)`).
///
/// The shard id is inside the leaf, so two shards holding the same head hash
/// produce different leaves and cannot be transposed within the tree.
fn merkle_leaf(shard_id: u16, head_hash: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update([MERKLE_LEAF_PREFIX]);
    h.update(shard_id.to_be_bytes());
    h.update(head_hash.as_bytes());
    h.finalize().into()
}

/// Merkle root over exactly [`AUDIT_SHARDS`] leaves.
///
/// `AUDIT_SHARDS` is a power of two (statically asserted above), so every level
/// halves cleanly and the odd-node case simply never arises — no duplication
/// rule, hence no CVE-2012-2459-class ambiguity.
fn merkle_root(leaves: &[[u8; 32]]) -> String {
    debug_assert_eq!(leaves.len(), AUDIT_SHARDS);
    let mut level: Vec<[u8; 32]> = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks(2) {
            let mut h = Sha256::new();
            h.update([MERKLE_NODE_PREFIX]);
            h.update(pair[0]);
            h.update(pair[1]);
            next.push(h.finalize().into());
        }
        level = next;
    }
    hex::encode(level[0])
}

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
///
///   **Sticky on drop.** A queue-full drop is not transient pressure — it is a
///   permanently missing audit record. Recomputing health purely from live
///   queue depth would return to `Healthy` the moment the backlog drained,
///   re-authorizing IRREVERSIBLE_ACTION under an audit chain that already has
///   a hole in it. So the first drop raises a floor that pins health at
///   `Saturated` until an operator explicitly calls
///   [`ImmutableAuditLog::acknowledge_dropped_audits`]. Gate 2.5 therefore
///   keeps rejecting irreversible actions for as long as the gap is
///   unacknowledged, rather than for as long as the queue happens to be deep.
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
    /// Phase 6: which of the [`AUDIT_SHARDS`] hash chains this record belongs
    /// to. `None` for a v1 record read back from an older log.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard_id: Option<u16>,
    /// Phase 6: position within `shard_id`'s chain. Distinct from `seq`, which
    /// stays a globally-monotonic (and HMAC-covered) ordering hint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shard_seq: Option<u64>,
    /// Phase 6: the Merkle anchor epoch in force when this record was appended.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub anchor_epoch: Option<u64>,
}

impl AuditRecord {
    /// Phase 6: shard-chain fields as the canonical HMAC sees them.
    ///
    /// A v1 record (no shard fields) yields `None` for all three, which is
    /// exactly how [`CanonicalAuditRecord`] reproduces byte-identical v1 output.
    fn v2_fields(&self) -> (Option<u16>, Option<u64>, Option<u64>, Option<u8>) {
        match (self.shard_id, self.shard_seq, self.anchor_epoch) {
            (Some(sid), Some(sseq), Some(ep)) => {
                (Some(sid), Some(sseq), Some(ep), Some(AUDIT_RECORD_VERSION_V2))
            }
            _ => (None, None, None, None),
        }
    }
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
///
/// ## Phase 6 — the v1/v2 discriminator lives here
///
/// The four sharding fields are `Option`s with `skip_serializing_if`, so when
/// they are all `None` this struct serializes to **exactly** the eight-field v1
/// JSON, byte for byte. That is what lets `verify_chain_disk` recompute the
/// HMAC of a record written by a pre-Phase-6 build using this same struct, and
/// it is verified against a checked-in pinned fixture
/// (`tests/test_audit_v1_fixture_rs.rs`) rather than by inspection.
///
/// Field order remains alphabetical **including** the new fields
/// (`anchor_epoch` first, `v` last) — do not group the v2 fields together for
/// readability, that would change the canonical bytes.
#[derive(serde::Serialize)]
struct CanonicalAuditRecord<'a> {
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor_epoch: Option<u64>,
    intent: &'a str,
    prev_hash: &'a str,
    seq: u64,
    /// Inside the HMAC input deliberately: combined with the per-shard genesis
    /// (`shard_genesis_hash`), this is the second of two independent defenses
    /// against relocating a record from one shard's chain into another's.
    #[serde(skip_serializing_if = "Option::is_none")]
    shard_id: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    shard_seq: Option<u64>,
    source: &'a str,
    target: &'a str,
    timestamp: f64,
    token_signature: &'a str,
    traceparent: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    v: Option<u8>,
}

impl<'a> CanonicalAuditRecord<'a> {
    /// Build the canonical form of an in-memory [`AuditRecord`].
    fn from_record(r: &'a AuditRecord) -> Self {
        let (shard_id, shard_seq, anchor_epoch, v) = r.v2_fields();
        Self {
            anchor_epoch,
            intent: &r.intent,
            prev_hash: &r.prev_hash,
            seq: r.seq,
            shard_id,
            shard_seq,
            source: &r.source,
            target: &r.target,
            timestamp: r.timestamp,
            token_signature: &r.token_signature,
            traceparent: &r.traceparent,
            v,
        }
    }

    /// Serialize and HMAC in one step — the single definition of "the chain
    /// hash of this record", shared by `append_event`, `verify_chain`, and
    /// `verify_chain_disk` so the three can never drift apart (the M-40 fix,
    /// preserved and extended to the v2 fields).
    fn chain_hash(&self, issuer_secret: &[u8]) -> String {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
        mac.update(json.as_bytes());
        hex::encode(mac.finalize().into_bytes())
    }

    /// As [`Self::chain_hash`], but also returns the canonical JSON so
    /// `append_event` can reuse it for the on-disk line instead of serializing
    /// the identical bytes a second time.
    fn serialize_and_hash(&self, issuer_secret: &[u8]) -> (String, String) {
        let json = serde_json::to_string(self).unwrap_or_default();
        let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
        mac.update(json.as_bytes());
        (json, hex::encode(mac.finalize().into_bytes()))
    }
}

// ---------------------------------------------------------------------------
// WAL worker message
// ---------------------------------------------------------------------------

enum WalMessage {
    Entry {
        entry_json: String,
        event_count: u64,
    },
    /// L-10 fix: sent by [`ImmutableAuditLog::flush`]; the worker acks on the enclosed
    /// `Sender<()>` only after performing a real flush+`sync_data()` (and sentinel
    /// write) at this exact point in the FIFO queue — i.e. after every `Entry` message
    /// enqueued before it, so a caller that observes the ack knows every
    /// happened-before `append_event` is durable.
    Flush(std::sync::mpsc::Sender<()>),
}

// ---------------------------------------------------------------------------
// Phase 6 — shard state
// ---------------------------------------------------------------------------

/// One shard's independently-chained state. Exactly the fields the old single
/// `AuditInner` carried per chain, minus the process-wide ones (`log_file`,
/// `count_file`, total event count) which stay global.
struct ShardInner {
    last_hash: String,
    /// Number of records appended to THIS shard — the record's `shard_seq`.
    shard_seq: u64,
    entries: Vec<AuditLogEntry>,
}

/// The value each shard publishes for the Merkle anchor to read.
///
/// Published into an `ArcSwap` **after** the shard's own mutex is released, so
/// building an anchor never has to acquire all [`AUDIT_SHARDS`] locks at once —
/// which would be both a contention point and a lock-ordering hazard against
/// the appenders it is supposed to stay out of the way of.
struct ShardHead {
    hash: String,
}

/// A Merkle anchor line: a commitment to all [`AUDIT_SHARDS`] chain heads at a
/// point in time, chained to the previous anchor via `prev_root`.
///
/// The anchor is what makes the shards a single tamper-evident structure rather
/// than 16 independent logs. Without it an attacker could delete or rewrite one
/// entire shard's records and the remaining 15 chains would still verify. With
/// it, any such edit changes that shard's head, hence the root, and the root is
/// recomputed from the file's own records during `verify_chain_disk`.
///
/// `prev_root` chains anchors to each other so a whole epoch cannot be excised.
#[derive(serde::Serialize, serde::Deserialize)]
struct MerkleAnchor {
    epoch: u64,
    /// Chain heads at anchor time, indexed by shard id.
    heads: Vec<String>,
    root: String,
    prev_root: String,
    /// Global event count at anchor time.
    event_count: u64,
    timestamp: f64,
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
    /// Phase 6: [`AUDIT_SHARDS`] independent hash chains, replacing the single
    /// `Mutex<AuditInner>` that serialized every appender across HMAC +
    /// serialization + enqueue.
    shards: Vec<Mutex<ShardInner>>,
    /// Lock-free published head of each shard, for the Merkle anchor. Written
    /// after the corresponding shard mutex is released — see [`ShardHead`].
    /// Shared with the WAL worker, which builds the anchors.
    shard_heads: Arc<Vec<arc_swap::ArcSwap<ShardHead>>>,
    /// Global lifetime event count. Lock-free, so `event_count()` no longer
    /// takes any mutex while returning the same value it always did.
    global_seq: AtomicU64,
    /// Paths are immutable after construction (no setter exists), so they need
    /// no lock — they were only inside `AuditInner` because everything was.
    log_file: String,
    count_file: String,
    /// Current Merkle anchor epoch, stamped into every appended record and
    /// advanced by the WAL worker each time it emits an anchor.
    anchor_epoch: Arc<AtomicU64>,
    /// WAL worker sender. Always `Some` — even a "" log_file spawns the worker,
    /// but the worker thread no-ops on disk I/O for an empty path (see `new()`).
    wal_tx: Option<mpsc::SyncSender<WalMessage>>,
    /// Backpressure health shared with the WAL worker thread — see `AuditHealth`.
    health: Arc<AtomicU8>,
    /// Count of events dropped because the WAL queue was full (or the worker
    /// thread had already exited after a fatal open failure).
    dropped_audits: Arc<AtomicU64>,
    /// Sticky floor under the health level, raised to `Saturated` the first
    /// time an event is dropped and only lowered by
    /// `acknowledge_dropped_audits`. A drop means a permanently missing audit
    /// record, so health must not drift back to `Healthy` (re-authorizing
    /// IRREVERSIBLE_ACTION at Gate 2.5) just because the queue later drained
    /// — see `AuditHealth`'s "Sticky on drop" note.
    health_floor: Arc<AtomicU8>,
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

thread_local! {
    /// Phase 6: this thread's shard slot, assigned round-robin on first use.
    ///
    /// **Deliberately a thread-local slot, not a hash of the record content.**
    /// Hashing `source_agent` (or any other field) would let anyone who controls
    /// agent ids steer every event onto one shard — a free DoS lever created by
    /// the optimization itself — and would give zero speedup in the
    /// single-dominant-agent case that a real load test actually looks like,
    /// since all of that agent's events would hash to the same lock.
    ///
    /// A thread slot has neither problem: the gate pipeline runs under
    /// `spawn_blocking`, so a given pool thread always touches the same mutex —
    /// an uncontended fast path plus cache locality — and the assignment is
    /// completely outside any attacker's influence.
    static AUDIT_SHARD_SLOT: usize = {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        NEXT.fetch_add(1, Ordering::Relaxed) % AUDIT_SHARDS
    };
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

    /// Create with both log file and sentinel file paths. Rotated audit logs are
    /// gzip-compressed in the background (C-4) but the compressed `.bak.gz` file is
    /// left in place (`NoopArchivalSink`) — use
    /// [`with_paths_and_archival_sink`](Self::with_paths_and_archival_sink) to plug in
    /// a real archival destination.
    pub fn with_paths(log_file: &str, count_file: &str) -> Self {
        Self::with_paths_and_archival_sink(log_file, count_file, Arc::new(NoopArchivalSink))
    }

    /// Create with both log file and sentinel file paths, plus a pluggable
    /// [`ArchivalSink`] (C-4) that receives every rotated-and-gzip-compressed audit
    /// log (`<log_file>.<timestamp>.bak.gz`). Compression itself always happens (on a
    /// dedicated background thread, never delaying the WAL worker) — the sink only
    /// decides what happens to the compressed file afterward.
    pub fn with_paths_and_archival_sink(
        log_file: &str,
        count_file: &str,
        archival_sink: Arc<dyn ArchivalSink>,
    ) -> Self {
        let resolved_log_file = if log_file.is_empty() {
            String::new()
        } else if let Ok(test_log_dir) = std::env::var("SAACP_TEST_LOG_DIR") {
            let path = Path::new(&log_file);
            if path.is_relative() {
                Path::new(&test_log_dir).join(path).to_string_lossy().to_string()
            } else {
                log_file.to_string()
            }
        } else {
            log_file.to_string()
        };

        let resolved_count_file = if count_file.is_empty() {
            String::new()
        } else if let Ok(test_log_dir) = std::env::var("SAACP_TEST_LOG_DIR") {
            let path = Path::new(&count_file);
            if path.is_relative() {
                Path::new(&test_log_dir).join(path).to_string_lossy().to_string()
            } else {
                count_file.to_string()
            }
        } else {
            count_file.to_string()
        };

        let (wal_tx, wal_rx) = mpsc::sync_channel::<WalMessage>(AUDIT_WAL_QUEUE_CAPACITY);

        let health: Arc<AtomicU8> = Arc::new(AtomicU8::new(AuditHealth::Healthy as u8));
        let dropped_audits: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let health_floor: Arc<AtomicU8> = Arc::new(AtomicU8::new(AuditHealth::Healthy as u8));
        let wal_write_failures: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
        let queue_len: Arc<AtomicUsize> = Arc::new(AtomicUsize::new(0));

        // Phase 6: the published shard heads and the anchor epoch are shared
        // with the WAL worker, which is the thread that builds Merkle anchors —
        // it is already the single I/O serialization point, so anchoring needs
        // no new thread and no new lock.
        let shard_heads: Arc<Vec<arc_swap::ArcSwap<ShardHead>>> = Arc::new(
            (0..AUDIT_SHARDS)
                .map(|i| {
                    arc_swap::ArcSwap::from_pointee(ShardHead {
                        hash: shard_genesis_hash(i as u16),
                    })
                })
                .collect(),
        );
        let anchor_epoch: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));

        // Spawn WAL worker daemon thread. `log_file`/`count_file` never change
        // after construction (no setter exists), so the worker captures its own
        // copies once instead of receiving them on every message.
        let worker_health = Arc::clone(&health);
        let worker_wal_write_failures = Arc::clone(&wal_write_failures);
        let worker_queue_len = Arc::clone(&queue_len);
        let worker_log_file = resolved_log_file.clone();
        let worker_count_file = resolved_count_file.clone();
        let worker_shard_heads = Arc::clone(&shard_heads);
        let worker_anchor_epoch = Arc::clone(&anchor_epoch);
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
                    archival_sink,
                    &worker_shard_heads,
                    &worker_anchor_epoch,
                );
            })
            .expect("WAL worker thread spawn failed");

        Self {
            shards: (0..AUDIT_SHARDS)
                .map(|i| {
                    Mutex::new(ShardInner {
                        last_hash: shard_genesis_hash(i as u16),
                        shard_seq: 0,
                        entries: Vec::new(),
                    })
                })
                .collect(),
            shard_heads,
            global_seq: AtomicU64::new(0),
            log_file: resolved_log_file,
            count_file: resolved_count_file,
            anchor_epoch,
            wal_tx: Some(wal_tx),
            health,
            dropped_audits,
            health_floor,
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
    /// M-38 fix: every `self.inner.lock()`/`self.subscribers.lock()` in this
    /// impl block recovers via `into_inner()` on poison rather than panicking
    /// — `ImmutableAuditLog::global()` is a process-wide singleton, so one
    /// poisoning panic must not cascade into every other in-flight packet
    /// losing the ability to append/verify the audit chain.
    pub fn subscribe(&self, cb: Arc<dyn Fn(&AuditRecord) + Send + Sync>) {
        self.subscribers.lock().unwrap_or_else(|e| e.into_inner()).push(cb);
    }

    /// Create a new audit log with default file path (reads from env vars). C-4: also
    /// honors [`ENV_AUDIT_ARCHIVE_DIR`] — when set, rotated-and-compressed audit logs
    /// are moved into that directory via [`FilesystemArchivalSink`]; when unset, the
    /// compressed `.bak.gz` is simply left beside the live WAL ([`NoopArchivalSink`]).
    pub fn with_default_path() -> Self {
        let log_file = std::env::var(ENV_AUDIT_LOG)
            .unwrap_or_else(|_| AUDIT_LOG_FILE.to_string());
        let count_file = std::env::var(ENV_COUNT_FILE)
            .unwrap_or_else(|_| AUDIT_COUNT_FILE.to_string());
        let archival_sink: Arc<dyn ArchivalSink> = match std::env::var(ENV_AUDIT_ARCHIVE_DIR) {
            Ok(dir) if !dir.is_empty() => Arc::new(FilesystemArchivalSink::new(dir)),
            _ => Arc::new(NoopArchivalSink),
        };
        Self::with_paths_and_archival_sink(&log_file, &count_file, archival_sink)
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
    /// ## Phase 6 — reconstructing per-shard state, and the migration boundary
    ///
    /// The file may be pure v1, pure v2, or a v1 prefix followed by a v2 suffix
    /// (a log an older build wrote and this build is now appending to). Each
    /// shard's head is restored from the last v2 record carrying that
    /// `shard_id`.
    ///
    /// A shard with no v2 record yet is seeded to
    /// `SHA256(genesis_tag || u16BE(i) || final_v1_hash)` rather than to its
    /// bare genesis. This is what anchors the v2 region to the *end* of the v1
    /// region: without it, every shard would restart from a value an attacker
    /// can compute offline, making the upgrade point a free "truncate the
    /// entire v1 history here" edit that still verifies.
    pub fn initialize_chain(&self, issuer_secret: &[u8]) -> Result<(), String> {
        // Verify BEFORE adopting any on-disk state — the file is untrusted
        // input, and `verify_chain_disk` reads the file itself rather than the
        // in-memory shards, so it needs no state loaded first.
        if !self.verify_chain_disk(issuer_secret) {
            self.reset_chain_state_to_genesis();
            return Err(
                "audit chain integrity verification failed on load — chain reset to genesis"
                    .to_string(),
            );
        }

        if !Path::new(&self.log_file).exists() {
            return Ok(());
        }
        let Ok(content) = fs::read_to_string(&self.log_file) else {
            return Ok(());
        };

        // Walk the file once, tracking the last v1 hash and each shard's last
        // v2 head. Anchor lines are skipped — they commit to heads, they are
        // not themselves part of any shard's chain.
        let mut record_count: u64 = 0;
        let mut final_v1_hash: Option<String> = None;
        let mut heads: Vec<Option<(String, u64)>> = vec![None; AUDIT_SHARDS];
        let mut max_anchor_epoch: u64 = 0;

        for line in content.lines().filter(|l| !l.is_empty()) {
            let Ok(entry) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            if let Some(anchor) = entry.get(ANCHOR_LINE_KEY) {
                max_anchor_epoch =
                    max_anchor_epoch.max(anchor.get("epoch").and_then(|v| v.as_u64()).unwrap_or(0));
                continue;
            }
            let Some(chain_hash) = entry["chain_hash"].as_str() else {
                continue;
            };
            record_count += 1;
            let rec = &entry["record"];
            match (
                rec.get("shard_id").and_then(|v| v.as_u64()),
                rec.get("shard_seq").and_then(|v| v.as_u64()),
            ) {
                (Some(sid), Some(sseq)) if (sid as usize) < AUDIT_SHARDS => {
                    heads[sid as usize] = Some((chain_hash.to_string(), sseq + 1));
                }
                // A v1 record (no shard fields). Its hash is a candidate for
                // the migration seed; the last one wins.
                _ => final_v1_hash = Some(chain_hash.to_string()),
            }
        }

        self.global_seq.store(record_count, Ordering::SeqCst);
        self.anchor_epoch.store(max_anchor_epoch, Ordering::SeqCst);

        for i in 0..AUDIT_SHARDS {
            let (hash, shard_seq) = match &heads[i] {
                Some((h, s)) => (h.clone(), *s),
                None => (self.migration_seed_hash(i as u16, final_v1_hash.as_deref()), 0),
            };
            {
                let mut shard = self.shards[i].lock().unwrap_or_else(|e| e.into_inner());
                shard.last_hash = hash.clone();
                shard.shard_seq = shard_seq;
                shard.entries.clear();
            }
            self.shard_heads[i].store(Arc::new(ShardHead { hash }));
        }

        Ok(())
    }

    /// Seed for a shard that has no v2 record yet.
    ///
    /// With no preceding v1 history this is the plain per-shard genesis. When
    /// the file *does* have a v1 region, the seed folds in that region's final
    /// hash, binding the start of every v2 chain to the end of the v1 chain —
    /// see [`Self::initialize_chain`] for why that binding is load-bearing.
    fn migration_seed_hash(&self, shard_id: u16, final_v1_hash: Option<&str>) -> String {
        match final_v1_hash {
            None => shard_genesis_hash(shard_id),
            Some(v1) => {
                let mut h = Sha256::new();
                h.update(AUDIT_SHARD_GENESIS_TAG);
                h.update(shard_id.to_be_bytes());
                h.update(v1.as_bytes());
                hex::encode(h.finalize())
            }
        }
    }

    /// Reset every shard chain to its per-shard genesis and zero the counters.
    fn reset_chain_state_to_genesis(&self) {
        self.global_seq.store(0, Ordering::SeqCst);
        self.anchor_epoch.store(0, Ordering::SeqCst);
        for i in 0..AUDIT_SHARDS {
            let genesis = shard_genesis_hash(i as u16);
            {
                let mut shard = self.shards[i].lock().unwrap_or_else(|e| e.into_inner());
                shard.last_hash = genesis.clone();
                shard.shard_seq = 0;
                shard.entries.clear();
            }
            self.shard_heads[i].store(Arc::new(ShardHead { hash: genesis }));
        }
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
    ///
    /// ## Phase 6 — what the lock still covers, and why
    ///
    /// P-2 identified the single global mutex held across HMAC + JSON +
    /// `try_send` as the measured throughput ceiling. The chain is genuinely
    /// sequential — each record's `prev_hash` is the previous record's
    /// `chain_hash`, and the HMAC covers `prev_hash`, so two records in the same
    /// chain cannot have their hashes computed concurrently without breaking the
    /// linkage that `verify_chain` walks.
    ///
    /// The fix is therefore not to shorten the critical section but to have
    /// [`AUDIT_SHARDS`] of them: each shard is a complete, independently-linked
    /// chain, so appenders on different shards never wait on each other while
    /// every record keeps exactly the tamper-evidence it had before. Only the
    /// read-modify-write of `last_hash`/`shard_seq` plus the HMAC over them is
    /// inside the lock; serialization of the WAL line, the enqueue, health
    /// bookkeeping, and subscriber callbacks all happen after it is released.
    pub fn append_event(
        &self,
        issuer_secret: &[u8],
        source_agent: &str,
        target_agent: &str,
        token_signature: &str,
        evaluated_intent: &str,
        traceparent: &str,
    ) {
        let shard_idx = AUDIT_SHARD_SLOT.with(|s| *s);
        let anchor_epoch = self.anchor_epoch.load(Ordering::Relaxed);
        // Reserve this record's global sequence number outside the shard lock.
        // `seq` stays globally monotonic and HMAC-covered as an unforgeable
        // ordering hint; cross-shard *ordering* is deliberately relaxed (no
        // consumer depends on it — see the module docs and `verify_chain`).
        let seq = self.global_seq.fetch_add(1, Ordering::Relaxed);
        let timestamp = now_secs();

        // O-6: non-blocking probe first — on contention, record the observation
        // then fall through to the normal blocking lock() below.
        let mut shard = match self.shards[shard_idx].try_lock() {
            Ok(guard) => guard,
            Err(std::sync::TryLockError::WouldBlock) => {
                crate::telemetry::global_telemetry().record_mutex_contention("wal_append");
                self.shards[shard_idx].lock().unwrap_or_else(|e| e.into_inner())
            }
            Err(std::sync::TryLockError::Poisoned(e)) => e.into_inner(),
        };

        let record = AuditRecord {
            timestamp,
            source: source_agent.to_string(),
            target: target_agent.to_string(),
            intent: evaluated_intent.to_string(),
            token_signature: token_signature.to_string(),
            traceparent: traceparent.to_string(),
            prev_hash: shard.last_hash.clone(),
            seq,
            shard_id: Some(shard_idx as u16),
            shard_seq: Some(shard.shard_seq),
            anchor_epoch: Some(anchor_epoch),
        };

        // Canonical (alphabetical) JSON + HMAC-SHA256 over it, in one place —
        // `verify_chain`/`verify_chain_disk` call the same helper, so the three
        // can never drift apart (M-40).
        let (record_json, chain_hash) =
            CanonicalAuditRecord::from_record(&record).serialize_and_hash(issuer_secret);

        let log_entry = AuditLogEntry {
            record,
            chain_hash: chain_hash.clone(),
        };

        // Build the JSONL line for disk persistence, reusing `record_json`
        // (already serialized once, for the HMAC input) as the nested "record"
        // value instead of re-serializing an identical tree. Safe because
        // `record_json` is already valid, compact, properly-escaped JSON text
        // and `chain_hash` is `hex::encode` output — pure lowercase ASCII hex,
        // never containing `"` or a control character. Formatting is cheap and
        // touches no shared state, but the actual enqueue happens after the
        // lock is dropped.
        let entry_json = format!(r#"{{"record":{record_json},"chain_hash":"{chain_hash}"}}"#);

        shard.last_hash = chain_hash.clone();
        shard.shard_seq += 1;

        // Keep in-memory for fast verify_chain().
        let record_for_subscribers = log_entry.record.clone();
        shard.entries.push(log_entry);

        // S-6 fix, per-shard: bound the in-memory retention window. The on-disk
        // WAL keeps the full history (verified by `verify_chain_disk`); this
        // vector only backs the fast in-process `verify_chain`, so dropping the
        // oldest slice caps memory without losing any auditable record. The
        // drain MUST be per-shard: `verify_chain` seeds each shard from that
        // shard's first retained entry, and a global drain would cut shards at
        // arbitrary points and break that invariant. `global_seq` is untouched,
        // so the sentinel/tamper check still sees the true total.
        if shard.entries.len() > AUDIT_PER_SHARD_MAX_IN_MEMORY {
            let drop_n = AUDIT_PER_SHARD_MAX_IN_MEMORY / 5;
            shard.entries.drain(0..drop_n);
        }

        // Release the shard lock before enqueueing, touching health, or invoking
        // subscriber callbacks — none of those participate in the chain linkage,
        // and a callback must never run while a chain lock is held (same rule
        // `trust_decay.rs::emit` follows).
        drop(shard);

        // Publish this shard's head for the Merkle anchor. Done after the mutex
        // is released so building an anchor never needs to take all 16 locks.
        self.shard_heads[shard_idx].store(Arc::new(ShardHead { hash: chain_hash }));

        self.enqueue_wal_line(entry_json);

        for cb in self.subscribers.lock().unwrap_or_else(|e| e.into_inner()).iter() {
            cb(&record_for_subscribers);
        }
    }

    /// Enqueue one already-serialized JSONL line for the WAL worker, applying
    /// the full backpressure contract (drop-on-full, sticky floor, health
    /// recompute). Unchanged from the pre-Phase-6 inline version — factored out
    /// only so `append_event` can call it after releasing its shard lock.
    fn enqueue_wal_line(&self, entry_json: String) {
        let Some(ref tx) = self.wal_tx else { return };
        let event_count = self.global_seq.load(Ordering::Relaxed);
        let msg = WalMessage::Entry {
            entry_json,
            event_count,
        };
        if tx.try_send(msg).is_ok() {
            self.queue_len.fetch_add(1, Ordering::Relaxed);
        } else {
            // FIX 3: rate-limited signal via an atomic counter — never an
            // inline eprintln! on this hot path.
            self.dropped_audits.fetch_add(1, Ordering::Relaxed);
            // This event is now permanently absent from the audit trail — not
            // merely late. Raise the sticky floor so health cannot fall back to
            // Healthy when the queue drains, keeping Gate 2.5 fail-closed on
            // IRREVERSIBLE_ACTION until an operator calls
            // `acknowledge_dropped_audits`. See `AuditHealth`'s "Sticky on
            // drop" note.
            self.health_floor
                .fetch_max(AuditHealth::Saturated as u8, Ordering::Relaxed);
            crate::telemetry::global_telemetry().record_gate_rejection("gate_6_0_audit");
        }

        // FIX 4: recompute health from live queue pressure. `fetch_update`
        // refuses to overwrite a sticky `Fatal` — only the WAL worker sets that
        // (on an actual I/O failure), and only a fresh `ImmutableAuditLog`
        // clears it.
        //
        // The sticky drop floor is deliberately NOT folded into this stored
        // value: `health()` applies it on read instead. Baking it in here would
        // leave the floor's level latched in `health` even after
        // `acknowledge_dropped_audits` cleared the floor itself.
        let pct = self.queue_len.load(Ordering::Relaxed) as f64 / AUDIT_WAL_QUEUE_CAPACITY as f64;
        let level = if pct > AUDIT_HEALTH_SATURATED_PCT {
            AuditHealth::Saturated
        } else if pct > AUDIT_HEALTH_DEGRADED_PCT {
            AuditHealth::Degraded
        } else {
            AuditHealth::Healthy
        };
        let _ = self
            .health
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |cur| {
                if cur == AuditHealth::Fatal as u8 { None } else { Some(level as u8) }
            });
    }

    /// Verify the integrity of the in-memory audit chain.
    ///
    /// Also validates the sentinel file count if it exists (spec §15.3):
    /// the event count on disk must be >= the sentinel value.
    ///
    /// Phase 6: each of the [`AUDIT_SHARDS`] chains is walked independently
    /// with the same loop body, seeded by the same S-6 rule (first *retained*
    /// entry's `prev_hash`), plus a check that every entry's `shard_id` actually
    /// matches the shard it was found in — a record moved between shards would
    /// otherwise only be caught by the HMAC, and this makes the binding explicit.
    ///
    /// Returns `false` on any tampering detection.
    pub fn verify_chain(&self, issuer_secret: &[u8]) -> bool {
        let event_count = self.global_seq.load(Ordering::Relaxed);
        let mut total_retained = 0usize;

        for (idx, shard_lock) in self.shards.iter().enumerate() {
            let shard = shard_lock.lock().unwrap_or_else(|e| e.into_inner());
            total_retained += shard.entries.len();
            if shard.entries.is_empty() {
                continue;
            }

            // S-6 fix: seed the expected hash from the FIRST RETAINED entry's
            // `prev_hash` rather than a hard-coded genesis. When this shard's
            // window has never been drained that first `prev_hash` IS the
            // shard's genesis, so this is identical to a genesis-anchored walk
            // for the common case. After a drain (see
            // `append_event`/`AUDIT_PER_SHARD_MAX_IN_MEMORY`) the window no
            // longer begins at genesis, and this still confirms the internal
            // continuity + HMAC integrity of what is retained. Full-history
            // (genesis-anchored) verification is `verify_chain_disk`'s job.
            let mut expected_prev_hash = shard.entries[0].record.prev_hash.clone();

            for entry in &shard.entries {
                // Phase 6: the record must claim the shard it is stored in.
                if entry.record.shard_id != Some(idx as u16) {
                    return false;
                }
                if entry.record.prev_hash != expected_prev_hash {
                    return false; // Chain broken
                }

                // M-40 fix: recompute the HMAC via the SAME `CanonicalAuditRecord`
                // helper `append_event` uses, instead of an independently
                // hand-listed field set — any future field added to one but not
                // the other would otherwise silently break verification (or
                // worse, silently stop covering a field with the HMAC).
                let expected_sig =
                    CanonicalAuditRecord::from_record(&entry.record).chain_hash(issuer_secret);

                // SECURITY: use constant-time hex comparison to prevent timing oracle.
                if !constant_time_eq_hex(&expected_sig, &entry.chain_hash) {
                    return false; // Tampering detected
                }

                expected_prev_hash = entry.chain_hash.clone();
            }
        }

        if total_retained == 0 {
            // Empty chain — valid iff event_count is also 0.
            if event_count != 0 {
                return false;
            }
            // Check sentinel: if it exists and shows count > 0, tamper detected.
            if let Ok(sentinel_str) = fs::read_to_string(&self.count_file) {
                if let Ok(sentinel_count) = sentinel_str.trim().parse::<u64>() {
                    if sentinel_count > 0 {
                        return false;
                    }
                }
            }
            return true;
        }

        // Spec §15.3: Total disk count MUST be >= sentinel count.
        // The sentinel records how many events were accepted in-memory.
        // If the sentinel exists and shows a count HIGHER than in-memory, something was erased.
        if Path::new(&self.count_file).exists() {
            if let Ok(sentinel_str) = fs::read_to_string(&self.count_file) {
                if let Ok(sentinel_count) = sentinel_str.trim().parse::<u64>() {
                    if event_count < sentinel_count {
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
    ///
    /// ## Phase 6 — one pass, three branches
    ///
    /// A line is an **anchor**, a **v2 record**, or a **v1 record**, decided per
    /// line by structure alone (an anchor has an `"anchor"` key; a v2 record has
    /// `shard_id`/`shard_seq`; a v1 record has neither). A file may therefore be
    /// pure v1, pure v2, or a v1 prefix followed by a v2 suffix, and all three
    /// verify through this single walk. For a pure-v1 log only the v1 branch
    /// ever executes, doing character-for-character what it did before Phase 6 —
    /// which is what the pinned fixture in `tests/test_audit_v1_fixture_rs.rs`
    /// exists to prove.
    ///
    /// At the migration boundary each shard's expected hash is re-seeded to
    /// `SHA256(genesis_tag || u16BE(i) || final_v1_hash)`, binding the v2 region
    /// to the end of the v1 region — see [`Self::initialize_chain`].
    pub fn verify_chain_disk(&self, issuer_secret: &[u8]) -> bool {
        let log_file = &self.log_file;
        let count_file = &self.count_file;

        // Read all log entries from disk.
        let content = match fs::read_to_string(log_file) {
            Ok(c) => c,
            Err(_) => {
                // File missing — valid only if in-memory count is 0.
                return self.global_seq.load(Ordering::Relaxed) == 0;
            }
        };

        let lines: Vec<&str> = content.lines().filter(|l| !l.is_empty()).collect();

        // Anchor lines are metadata, not events — they must not inflate the
        // count the sentinel is compared against.
        let mut record_lines = 0u64;
        for line in &lines {
            if !line.contains(r#""anchor""#) {
                record_lines += 1;
            } else if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v.get(ANCHOR_LINE_KEY).is_none() {
                    record_lines += 1;
                }
            }
        }

        // Check sentinel: disk count must be >= sentinel count.
        if Path::new(count_file).exists() {
            if let Ok(s) = fs::read_to_string(count_file) {
                if let Ok(sentinel) = s.trim().parse::<u64>() {
                    if record_lines < sentinel {
                        return false;
                    }
                }
            }
        }

        if lines.is_empty() {
            return true;
        }

        // v1 walk state: one linear chain seeded at the global genesis.
        let mut expected_v1_hash = GENESIS_HASH.to_string();
        let mut final_v1_hash: Option<String> = None;
        // v2 walk state: one expected hash per shard, lazily seeded on that
        // shard's first v2 record (so the seed can incorporate `final_v1_hash`).
        let mut expected_v2: Vec<Option<String>> = vec![None; AUDIT_SHARDS];
        // Anchor chain state.
        let mut expected_prev_root = ANCHOR_GENESIS_ROOT.to_string();

        for line in &lines {
            let entry: serde_json::Value = match serde_json::from_str(line) {
                Ok(v) => v,
                Err(_) => return false,
            };

            // ---- Branch 1: Merkle anchor ----
            if let Some(anchor_val) = entry.get(ANCHOR_LINE_KEY) {
                let anchor: MerkleAnchor = match serde_json::from_value(anchor_val.clone()) {
                    Ok(a) => a,
                    Err(_) => return false,
                };
                if anchor.heads.len() != AUDIT_SHARDS {
                    return false;
                }
                // The anchor must chain to the previous anchor, so a whole
                // epoch cannot be excised from the middle of the file.
                if anchor.prev_root != expected_prev_root {
                    return false;
                }
                // The committed root must actually be the root of the committed
                // heads — otherwise the root is a free-form string.
                let leaves: Vec<[u8; 32]> = anchor
                    .heads
                    .iter()
                    .enumerate()
                    .map(|(i, h)| merkle_leaf(i as u16, h))
                    .collect();
                if merkle_root(&leaves) != anchor.root {
                    return false;
                }
                // Every committed head must match the chain state the records
                // seen so far actually produced. This is the check that makes
                // dropping or rewriting a shard's records detectable: the shard
                // head would no longer match what the anchor committed to.
                for (i, head) in anchor.heads.iter().enumerate() {
                    let actual = expected_v2[i]
                        .clone()
                        .unwrap_or_else(|| self.migration_seed_hash(i as u16, final_v1_hash.as_deref()));
                    if &actual != head {
                        return false;
                    }
                }
                expected_prev_root = anchor.root.clone();
                continue;
            }

            let rec = &entry["record"];
            let chain_hash = match entry["chain_hash"].as_str() {
                Some(h) => h,
                None => return false,
            };
            let prev_hash = rec["prev_hash"].as_str().unwrap_or("");

            // M-40 fix: the same `CanonicalAuditRecord` helper `append_event` and
            // `verify_chain` use, rather than a third independently hand-listed
            // field set built from untyped `Value`s. Extracting each field with
            // its expected type (rather than embedding the raw `Value`) means a
            // malformed/missing field fails the parse explicitly (fail-closed)
            // instead of silently serializing as `null` and merely producing a
            // mismatching HMAC.
            let intent = match rec["intent"].as_str() { Some(v) => v, None => return false };
            let seq = match rec["seq"].as_u64() { Some(v) => v, None => return false };
            let source = match rec["source"].as_str() { Some(v) => v, None => return false };
            let target = match rec["target"].as_str() { Some(v) => v, None => return false };
            let timestamp = match rec["timestamp"].as_f64() { Some(v) => v, None => return false };
            let token_signature = match rec["token_signature"].as_str() { Some(v) => v, None => return false };
            let traceparent = match rec["traceparent"].as_str() { Some(v) => v, None => return false };

            // ---- Branch 2: v2 (sharded) record ----
            if let Some(shard_id_raw) = rec.get("shard_id").and_then(|v| v.as_u64()) {
                if shard_id_raw as usize >= AUDIT_SHARDS {
                    return false;
                }
                let shard_id = shard_id_raw as u16;
                let shard_seq = match rec.get("shard_seq").and_then(|v| v.as_u64()) {
                    Some(v) => v,
                    None => return false,
                };
                let anchor_epoch = match rec.get("anchor_epoch").and_then(|v| v.as_u64()) {
                    Some(v) => v,
                    None => return false,
                };
                // The version marker must be present and exact on a v2 record —
                // an unknown version is rejected rather than guessed at.
                match rec.get("v").and_then(|v| v.as_u64()) {
                    Some(v) if v == AUDIT_RECORD_VERSION_V2 as u64 => {}
                    _ => return false,
                }

                // Seed this shard on first sight, folding in the final v1 hash
                // if the file has a v1 region — this is the migration boundary.
                let expected = expected_v2[shard_id as usize]
                    .get_or_insert_with(|| self.migration_seed_hash(shard_id, final_v1_hash.as_deref()));
                if prev_hash != expected.as_str() {
                    return false;
                }

                let record_json = serde_json::to_string(&CanonicalAuditRecord {
                    anchor_epoch: Some(anchor_epoch),
                    intent,
                    prev_hash,
                    seq,
                    shard_id: Some(shard_id),
                    shard_seq: Some(shard_seq),
                    source,
                    target,
                    timestamp,
                    token_signature,
                    traceparent,
                    v: Some(AUDIT_RECORD_VERSION_V2),
                }).unwrap_or_default();

                let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
                mac.update(record_json.as_bytes());
                let expected_sig = hex::encode(mac.finalize().into_bytes());

                // SECURITY: constant-time hex comparison to prevent timing oracle.
                if !constant_time_eq_hex(&expected_sig, chain_hash) {
                    return false;
                }

                expected_v2[shard_id as usize] = Some(chain_hash.to_string());
                continue;
            }

            // ---- Branch 3: v1 record (pre-Phase-6) ----
            //
            // A v1 record must not appear after the v2 region has begun: the
            // upgrade is one-way, and accepting an interleaved v1 line would let
            // an attacker append records that skip the shard binding entirely.
            if expected_v2.iter().any(|e| e.is_some()) {
                return false;
            }
            if prev_hash != expected_v1_hash {
                return false;
            }

            let record_json = serde_json::to_string(&CanonicalAuditRecord {
                anchor_epoch: None,
                intent,
                prev_hash,
                seq,
                shard_id: None,
                shard_seq: None,
                source,
                target,
                timestamp,
                token_signature,
                traceparent,
                v: None,
            }).unwrap_or_default();

            let mut mac = <HmacSha256 as Mac>::new_from_slice(issuer_secret).expect("HMAC key");
            mac.update(record_json.as_bytes());
            let expected_sig = hex::encode(mac.finalize().into_bytes());

            // SECURITY: constant-time hex comparison to prevent timing oracle.
            if !constant_time_eq_hex(&expected_sig, chain_hash) {
                return false;
            }

            expected_v1_hash = chain_hash.to_string();
            final_v1_hash = Some(chain_hash.to_string());
        }

        true
    }

    /// Return the number of events in the chain.
    ///
    /// Phase 6: lock-free (`global_seq`), returning the same value the old
    /// mutex-guarded `event_count` field did.
    pub fn event_count(&self) -> u64 {
        self.global_seq.load(Ordering::Relaxed)
    }

    /// S-6 fix: number of entries currently retained in the in-memory window
    /// (bounded by `AUDIT_MAX_IN_MEMORY_ENTRIES`). Distinct from `event_count`,
    /// which is the lifetime total (never decremented by the retention drain).
    /// Exposed for monitoring and for verifying the retention bound in tests.
    ///
    /// Phase 6: the sum across all [`AUDIT_SHARDS`] windows. The aggregate bound
    /// is unchanged — each shard is capped at
    /// `AUDIT_MAX_IN_MEMORY_ENTRIES / AUDIT_SHARDS`, so sharding cannot silently
    /// multiply the memory this retains.
    pub fn in_memory_entries_len(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).entries.len())
            .sum()
    }

    /// Current Gate 6.0 backpressure health (see `AuditHealth`). Read by
    /// `handler::gate_2_5_kinetic_firewall` to decide whether IRREVERSIBLE_ACTION
    /// packets should be rejected while the audit trail is degraded or blind.
    ///
    /// Never reports below the sticky drop floor: once an event has been dropped
    /// the trail has a permanent hole, so this stays at least `Saturated` until
    /// [`Self::acknowledge_dropped_audits`] is called, regardless of how far the
    /// WAL queue has since drained.
    pub fn health(&self) -> AuditHealth {
        let live = self.health.load(Ordering::Relaxed);
        AuditHealth::from_u8(live.max(self.health_floor.load(Ordering::Relaxed)))
    }

    /// Clear the sticky drop floor raised by a queue-full audit drop, returning
    /// the `dropped_audit_count()` at the moment of acknowledgement.
    ///
    /// This is an explicit operator action, deliberately not automatic: a drop
    /// means audit records were permanently lost, and Gate 2.5 keeps rejecting
    /// IRREVERSIBLE_ACTION until someone has actually reconciled that gap. Call
    /// this only after the loss has been recorded out-of-band. Does not clear a
    /// `Fatal` health state (a failed *write* is a different, non-recoverable
    /// condition — only constructing a fresh `ImmutableAuditLog` clears that),
    /// and does not reset the `dropped_audit_count()` lifetime total.
    pub fn acknowledge_dropped_audits(&self) -> u64 {
        self.health_floor
            .store(AuditHealth::Healthy as u8, Ordering::Relaxed);
        self.dropped_audits.load(Ordering::Relaxed)
    }

    /// Count of audit events dropped because the WAL queue was full (or the
    /// worker thread had already exited after a fatal open failure).
    ///
    /// Lifetime total — never reset. A non-zero value means the audit chain has
    /// a permanent hole, which pins `health()` at `Saturated` until
    /// [`Self::acknowledge_dropped_audits`] is called.
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

    /// L-10 fix: block the calling (native) thread until every `append_event` that
    /// happened-before this call has been written and `sync_data()`'d to disk, or
    /// `timeout` elapses. Used as the terminal "flush WAL" step of graceful shutdown
    /// (`daemon.rs`, `transport/ws.rs`, `transport/tls.rs`, `sidecar.rs`).
    ///
    /// This is a **std blocking channel `recv`, not a tokio await point** — the WAL
    /// worker is a plain OS thread (see `run_wal_worker`'s doc comment), not a tokio
    /// task, so there is nothing to `.await` here. Callers in an async context MUST
    /// run this via `tokio::task::spawn_blocking` rather than calling it directly on
    /// an async task, or they will block that task's executor thread for up to
    /// `timeout`.
    ///
    /// Sends via `SyncSender::send` (blocking, not `try_send`) deliberately — unlike
    /// `append_event`'s drop-on-full policy (spec §15.2, an event that can't be
    /// enqueued instantly is dropped rather than blocking the packet path), a
    /// deliberate shutdown flush should wait for queue room rather than silently
    /// no-op, since by the time shutdown calls this the caller has already stopped
    /// accepting new work and genuinely wants to wait.
    ///
    /// Returns `false` if the WAL worker is unreachable (e.g. it already exited after
    /// a fatal open failure) or didn't ack within `timeout`. This is a WEAKER
    /// guarantee than "confirmed lost" — entries already covered by the periodic
    /// flush cadence (`AUDIT_WAL_FLUSH_EVERY_N_ENTRIES`/`AUDIT_WAL_FLUSH_INTERVAL_MS`)
    /// are not lost just because this call couldn't confirm the very latest ones in
    /// time. Callers should log a warning on `false`, not treat it as fatal.
    pub fn flush(&self, timeout: Duration) -> bool {
        let Some(ref tx) = self.wal_tx else { return false };
        let (ack_tx, ack_rx) = std::sync::mpsc::channel::<()>();
        if tx.send(WalMessage::Flush(ack_tx)).is_err() {
            return false; // worker thread gone (channel disconnected)
        }
        self.queue_len.fetch_add(1, Ordering::Relaxed);
        ack_rx.recv_timeout(timeout).is_ok()
    }

    /// Reset the audit log completely (for test isolation).
    pub fn reset(&self) {
        self.reset_chain_state_to_genesis();
        self.health_floor
            .store(AuditHealth::Healthy as u8, Ordering::Relaxed);
        let _ = fs::remove_file(&self.log_file);
        let _ = fs::remove_file(&self.count_file);
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
// C-4: rotated audit log archival
// ---------------------------------------------------------------------------

/// Hand-off point for a rotated, gzip-compressed audit log (`<path>.<ts>.bak.gz`).
/// `maybe_rotate` always compresses; this trait only decides what happens to the
/// compressed file *after* that — deliberately not a concrete S3/GCS/Azure client
/// baked into this crate (see [`ImmutableAuditLog`]'s module doc for why: a
/// cloud-vendor-specific dependency in this security-critical audit path is
/// disproportionate to what "Must-Have" compliance requires generically). A
/// deployment that wants real object-storage hand-off implements this trait with
/// its own client and passes it to [`ImmutableAuditLog::with_paths_and_archival_sink`].
///
/// Invoked on a dedicated background thread (`saacp-audit-archival`, spawned by
/// `maybe_rotate`) — never the `saacp-wal-worker` thread that services live audit
/// writes — so blocking I/O here (a network upload, say) never delays the next
/// audit-log entry.
pub trait ArchivalSink: Send + Sync {
    /// Called with the path of a `.bak.gz` file once gzip compression has
    /// completed and been `fsync`'d, and the uncompressed `.bak` has already
    /// been removed.
    fn archive(&self, path: &Path) -> io::Result<()>;
}

/// Default sink: does nothing, leaving the compressed `.bak.gz` file exactly where
/// `maybe_rotate` wrote it (beside the live WAL). Correct, safe default for any
/// deployment that hasn't configured real off-box archival.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopArchivalSink;

impl ArchivalSink for NoopArchivalSink {
    fn archive(&self, _path: &Path) -> io::Result<()> {
        Ok(())
    }
}

/// Moves the compressed file into `target_dir` (e.g. a mounted backup volume, or a
/// directory a separate off-box sync process watches) instead of leaving it beside
/// the live WAL. Configured via [`ENV_AUDIT_ARCHIVE_DIR`] for `with_default_path`/
/// `global`. Still no cloud-vendor SDK dependency — real object-storage hand-off is
/// a deployment's own process watching this directory, or a custom [`ArchivalSink`].
#[derive(Debug, Clone)]
pub struct FilesystemArchivalSink {
    target_dir: std::path::PathBuf,
}

impl FilesystemArchivalSink {
    pub fn new(target_dir: impl Into<std::path::PathBuf>) -> Self {
        Self { target_dir: target_dir.into() }
    }
}

impl ArchivalSink for FilesystemArchivalSink {
    fn archive(&self, path: &Path) -> io::Result<()> {
        fs::create_dir_all(&self.target_dir)?;
        let file_name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "archival source path has no file name")
        })?;
        fs::rename(path, self.target_dir.join(file_name))
    }
}

/// Gzip-compresses `src` to `<src>.gz` (via `flate2`, already a project dependency —
/// see `framing.rs`'s zlib usage for the sibling precedent), `fsync`s the compressed
/// output, then removes `src` — only once the compressed copy is confirmed durable,
/// never delete-then-fail-to-compress. Hands the result to `sink`. Errors are logged,
/// not propagated: this runs detached on a background thread with no caller to
/// return a `Result` to, matching `run_wal_worker`'s own error-handling idiom for
/// this module (log + leave the uncompressed artifact in place, never panic).
fn compress_and_archive_rotated_log(rotated_path: String, sink: Arc<dyn ArchivalSink>) {
    let gz_path = format!("{rotated_path}.gz");
    if let Err(e) = compress_file_to_gzip(&rotated_path, &gz_path) {
        eprintln!(
            "[SAACP audit] gzip compression failed for rotated audit log '{rotated_path}': {e} \
             — uncompressed .bak left in place, not archived."
        );
        return;
    }
    if let Err(e) = fs::remove_file(&rotated_path) {
        eprintln!(
            "[SAACP audit] failed to remove uncompressed '{rotated_path}' after successful \
             compression to '{gz_path}': {e} — both copies left on disk."
        );
    }
    if let Err(e) = sink.archive(Path::new(&gz_path)) {
        eprintln!(
            "[SAACP audit] archival sink failed for '{gz_path}': {e} — compressed file left \
             in place at that path."
        );
    }
}

fn compress_file_to_gzip(src: &str, dst: &str) -> io::Result<()> {
    let mut input = File::open(src)?;
    let output = File::create(dst)?;
    let mut encoder = flate2::write::GzEncoder::new(output, flate2::Compression::default());
    io::copy(&mut input, &mut encoder)?;
    let output = encoder.finish()?;
    output.sync_all()
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
    /// C-4: where a rotated `.bak` file's compressed copy gets handed off once
    /// `maybe_rotate`'s background compression thread finishes. Defaults to
    /// [`NoopArchivalSink`] — see [`run_wal_worker`]/[`ImmutableAuditLog::with_paths_and_archival_sink`]
    /// for how a real sink gets plumbed in.
    archival_sink: Arc<dyn ArchivalSink>,
}

impl WalWriter {
    fn open(path: &str, archival_sink: Arc<dyn ArchivalSink>) -> io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);
        Ok(Self {
            path: path.to_string(),
            writer: Some(BufWriter::with_capacity(64 * 1024, file)),
            size,
            entries_since_flush: 0,
            last_flush: Instant::now(),
            pending_event_count: 0,
            archival_sink,
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
        // C-4: only kick off background compression/archival if the rename actually
        // succeeded — a failed rename means `rotated` doesn't exist, and spawning a
        // thread to compress a nonexistent file would just be a spurious error log.
        if fs::rename(&self.path, &rotated).is_ok() {
            let sink = Arc::clone(&self.archival_sink);
            let spawn_result = thread::Builder::new()
                .name("saacp-audit-archival".into())
                .spawn(move || compress_and_archive_rotated_log(rotated, sink));
            if let Err(e) = spawn_result {
                eprintln!(
                    "[SAACP audit] failed to spawn background archival thread: {e} — rotated \
                     .bak file left uncompressed."
                );
            }
        }
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
            self.flush_and_sync(count_file)?;
        }
        Ok(())
    }

    /// L-10 fix: unconditional flush+`sync_data()`+sentinel-write, factored out of
    /// `write_entry`'s periodic `should_flush` branch so [`ImmutableAuditLog::flush`]
    /// (driven by `WalMessage::Flush`) can force the same durability guarantee
    /// on-demand, not just at the periodic cadence.
    fn flush_and_sync(&mut self, count_file: &str) -> io::Result<()> {
        if let Some(w) = self.writer.as_mut() {
            w.flush()?;
            w.get_ref().sync_data()?;
        }
        // Sentinel batched into the same flush boundary — see the
        // `pending_event_count` field doc.
        //
        // C-5: atomic write. A direct `fs::write` overwrites the sentinel
        // in place, which can leave a truncated/corrupt count file if the
        // process is killed mid-write (power loss, `kill -9`). Instead write
        // to a sibling temp file, fsync its contents so they're durable,
        // then `rename` it over the real sentinel — a rename is atomic on
        // both POSIX (same-filesystem rename) and Windows (`fs::rename` is
        // backed by `MoveFileExW` with the replace-existing flag).
        let tmp_path = format!("{count_file}.tmp-{}", std::process::id());
        {
            let mut tmp = File::create(&tmp_path)?;
            tmp.write_all(self.pending_event_count.to_string().as_bytes())?;
            tmp.sync_all()?;
        }
        // Windows can transiently fail a rename with ERROR_ACCESS_DENIED if
        // the destination is momentarily opened elsewhere (e.g. a concurrent
        // reader of the sentinel); retry once after a short backoff before
        // propagating the error. On a second failure the temp file is left
        // in place deliberately — that's a diagnostic artifact, not silent
        // data loss, and the real sentinel is guaranteed untouched either way.
        if let Err(first_err) = fs::rename(&tmp_path, count_file) {
            thread::sleep(Duration::from_millis(20));
            fs::rename(&tmp_path, count_file).map_err(|_| first_err)?;
        }
        self.entries_since_flush = 0;
        self.last_flush = Instant::now();
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// WAL worker thread body
// ---------------------------------------------------------------------------

/// A built anchor line plus the root it committed to, so the caller can chain
/// the next anchor to it only if the write actually succeeded.
struct AnchorLine {
    json: String,
    root: String,
}

/// Build one Merkle anchor over the currently-published shard heads.
///
/// Reads each head from its `ArcSwap` — never takes a shard mutex, so anchoring
/// cannot contend with or block appenders. The heads are therefore a slightly
/// skewed snapshot (shard 3 may have advanced while shard 0 was read), which is
/// intentional and harmless: the anchor commits to a set of heads that each
/// genuinely existed, and `verify_chain_disk` replays the file's own records to
/// check the commitment. A skewed-but-real snapshot cannot make a tampered log
/// verify; it can only cause an anchor to commit to a slightly older head than
/// the newest one on disk, which the replay handles because it checks each
/// anchor against the chain state *at the point the anchor appears in the file*.
///
/// Returns `None` if the anchor cannot be serialized (never expected — the
/// struct is plain data).
fn build_anchor_line(
    shard_heads: &[arc_swap::ArcSwap<ShardHead>],
    anchor_epoch: &AtomicU64,
    prev_root: &str,
    event_count: u64,
) -> Option<AnchorLine> {
    let heads: Vec<String> = shard_heads
        .iter()
        .map(|h| h.load().hash.clone())
        .collect();
    let leaves: Vec<[u8; 32]> = heads
        .iter()
        .enumerate()
        .map(|(i, h)| merkle_leaf(i as u16, h))
        .collect();
    let root = merkle_root(&leaves);
    // Advance the epoch so records appended after this anchor carry the new
    // value — `fetch_add` returns the previous, which is the epoch this anchor
    // closes.
    let epoch = anchor_epoch.fetch_add(1, Ordering::Relaxed);

    let anchor = MerkleAnchor {
        epoch,
        heads,
        root: root.clone(),
        prev_root: prev_root.to_string(),
        event_count,
        timestamp: now_secs(),
    };
    let json = serde_json::to_string(&serde_json::json!({ ANCHOR_LINE_KEY: anchor })).ok()?;
    Some(AnchorLine { json, root })
}

/// Runs for the lifetime of the `ImmutableAuditLog` instance that spawned it
/// — exits when `wal_tx` is dropped (closing the channel and ending
/// `wal_rx.iter()`), or immediately if the log file can't be opened (Fix 2).
///
/// Phase 6: also emits the periodic Merkle anchor. This thread is already the
/// single I/O serialization point, so anchoring here needs no new thread and no
/// new lock — it reads each shard's head from the lock-free `ArcSwap` the
/// appenders publish into, never taking a shard mutex.
#[allow(clippy::too_many_arguments)]
fn run_wal_worker(
    wal_rx: mpsc::Receiver<WalMessage>,
    log_file: &str,
    count_file: &str,
    health: &AtomicU8,
    wal_write_failures: &AtomicU64,
    queue_len: &AtomicUsize,
    archival_sink: Arc<dyn ArchivalSink>,
    shard_heads: &[arc_swap::ArcSwap<ShardHead>],
    anchor_epoch: &AtomicU64,
) {
    // In-memory-only mode (`ImmutableAuditLog::new("")`): drain without any
    // disk I/O. This is a deliberate no-persistence mode, not a failure —
    // health stays HEALTHY for the life of the instance. L-10 fix: a `Flush`
    // message must still be acked immediately here — there's nothing to sync,
    // but a caller blocking on `flush()`'s ack must not hang forever just
    // because this instance never persists anything.
    if log_file.is_empty() {
        for msg in wal_rx.iter() {
            queue_len.fetch_sub(1, Ordering::Relaxed);
            if let WalMessage::Flush(ack_tx) = msg {
                let _ = ack_tx.send(());
            }
        }
        return;
    }

    let mut wal = match WalWriter::open(log_file, archival_sink) {
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

    // Phase 6 anchor state, owned entirely by this thread.
    let mut events_since_anchor: u64 = 0;
    let mut last_anchor = Instant::now();
    let mut prev_root = ANCHOR_GENESIS_ROOT.to_string();

    for msg in wal_rx.iter() {
        queue_len.fetch_sub(1, Ordering::Relaxed);
        match msg {
            WalMessage::Entry { entry_json, event_count } => {
                if let Err(e) = wal.write_entry(&entry_json, event_count, count_file) {
                    // Fix 3: an atomic counter, not an inline eprintln! on this loop
                    // — a sustained disk fault must not reintroduce the original
                    // per-event-print hot-path bug.
                    wal_write_failures.fetch_add(1, Ordering::Relaxed);
                    // Fix 4: sticky FATAL. Log only on the transition into FATAL so a
                    // sustained fault logs once, not once per failed write.
                    let already_fatal = health.swap(AuditHealth::Fatal as u8, Ordering::SeqCst)
                        == AuditHealth::Fatal as u8;
                    if !already_fatal {
                        eprintln!(
                            "[SAACP audit] FATAL: WAL write failed for '{log_file}': {e} — audit \
                             subsystem degraded. Gate 2.5 will now reject IRREVERSIBLE_ACTION packets \
                             referencing this log until a fresh ImmutableAuditLog is constructed."
                        );
                    }
                }

                // Phase 6: emit a Merkle anchor every N events or T seconds,
                // whichever comes first. Failure to write an anchor is counted
                // like any other WAL write failure but does not abort the loop —
                // the per-shard chains remain individually verifiable, and the
                // next anchor re-commits to the same heads.
                events_since_anchor += 1;
                if events_since_anchor >= AUDIT_ANCHOR_EVERY_N_EVENTS
                    || last_anchor.elapsed() >= AUDIT_ANCHOR_INTERVAL
                {
                    if let Some(line) = build_anchor_line(
                        shard_heads,
                        anchor_epoch,
                        &prev_root,
                        event_count,
                    ) {
                        if wal.write_entry(&line.json, event_count, count_file).is_err() {
                            wal_write_failures.fetch_add(1, Ordering::Relaxed);
                        } else {
                            prev_root = line.root;
                        }
                    }
                    events_since_anchor = 0;
                    last_anchor = Instant::now();
                }
            }
            WalMessage::Flush(ack_tx) => {
                // L-10 fix: force a flush+sync outside the periodic cadence, then ack
                // regardless of outcome — a failed flush here is already covered by
                // the same FATAL/wal_write_failures signal path as a failed
                // `write_entry`, and the caller's `flush()` returning `false` on a
                // missing/late ack is the documented (non-fatal) failure mode.
                if let Err(e) = wal.flush_and_sync(count_file) {
                    wal_write_failures.fetch_add(1, Ordering::Relaxed);
                    let already_fatal = health.swap(AuditHealth::Fatal as u8, Ordering::SeqCst)
                        == AuditHealth::Fatal as u8;
                    if !already_fatal {
                        eprintln!(
                            "[SAACP audit] FATAL: WAL flush failed for '{log_file}': {e} — audit \
                             subsystem degraded. Gate 2.5 will now reject IRREVERSIBLE_ACTION packets \
                             referencing this log until a fresh ImmutableAuditLog is constructed."
                        );
                    }
                }
                let _ = ack_tx.send(()); // best-effort; caller may have already timed out
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

    // -- M-4: NonceTracker::track_scoped session isolation --

    #[test]
    fn test_nonce_scoped_same_nonce_different_sessions_both_accepted() {
        let tracker = NonceTracker::new();
        // The SAME raw nonce value used by two DIFFERENT sessions must not
        // collide — each session has its own independent nonce space.
        assert!(tracker.track_scoped("session-A", 42).is_ok());
        assert!(tracker.track_scoped("session-B", 42).is_ok());
        assert_eq!(tracker.count(), 2);
    }

    #[test]
    fn test_nonce_scoped_replay_within_same_session_detected() {
        let tracker = NonceTracker::new();
        tracker.track_scoped("session-A", 42).unwrap();
        let err = tracker.track_scoped("session-A", 42).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::InvalidSignature);
    }

    #[test]
    fn test_nonce_scoped_and_unscoped_share_no_special_relationship() {
        // track() and track_scoped() both ultimately write into the same
        // underlying keyspace via different key-derivation functions; this
        // just documents that calling both with logically related inputs
        // does not error out unexpectedly (they operate on distinct derived
        // keys with overwhelming probability).
        let tracker = NonceTracker::new();
        assert!(tracker.track(42).is_ok());
        assert!(tracker.track_scoped("session-A", 42).is_ok());
        assert_eq!(tracker.count(), 2);
    }

    // -- ImmutableAuditLog tests --

    fn test_audit_log(name: &str) -> ImmutableAuditLog {
        let log_file = format!("test_audit_{}.log", name);
        let count_file = format!("test_audit_{}.sentinel", name);
        let log = ImmutableAuditLog::with_paths(&log_file, &count_file);
        log.reset(); // Clean slate
        log
    }

    /// Resolve a relative audit fixture path the same way `with_paths` does, so
    /// test read-backs hit the actual file the WAL worker wrote — under
    /// `SAACP_TEST_LOG_DIR` (the RAM disk) when set, else CWD. Without this a
    /// test that writes through the env var but reads a bare relative path looks
    /// on the SSD/repo-root for a file that only exists on R:.
    fn resolve_test_log_path(relative: &str) -> String {
        match std::env::var("SAACP_TEST_LOG_DIR") {
            Ok(dir) if !dir.is_empty() => {
                let p = Path::new(relative);
                if p.is_relative() {
                    Path::new(&dir).join(p).to_string_lossy().to_string()
                } else {
                    relative.to_string()
                }
            }
            _ => relative.to_string(),
        }
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

    /// S-6 fix: the in-memory entry vector is bounded by
    /// `AUDIT_MAX_IN_MEMORY_ENTRIES`; appending past the cap drains the oldest
    /// slice, `event_count` keeps the true lifetime total, and `verify_chain`
    /// still succeeds on the drained (non-genesis-anchored) window.
    #[test]
    fn test_audit_in_memory_retention_bounded_and_verifiable() {
        // In-memory-only mode (no disk sentinel) keeps this fast and hermetic.
        let log = ImmutableAuditLog::new("");
        let secret = b"audit_secret_key";

        let target = AUDIT_MAX_IN_MEMORY_ENTRIES + (AUDIT_MAX_IN_MEMORY_ENTRIES / 5) + 25;
        for i in 0..target {
            log.append_event(secret, "agent-a", "agent-b", "sig", "read:data", &format!("t{i}"));
        }

        // Retention bound: never exceeds the cap.
        assert!(
            log.in_memory_entries_len() <= AUDIT_MAX_IN_MEMORY_ENTRIES,
            "in-memory window ({}) must stay within AUDIT_MAX_IN_MEMORY_ENTRIES ({})",
            log.in_memory_entries_len(),
            AUDIT_MAX_IN_MEMORY_ENTRIES
        );
        // Lifetime counter is NOT decremented by the drain.
        assert_eq!(log.event_count(), target as u64);
        // A drain must actually have happened for this test to be meaningful.
        assert!(log.in_memory_entries_len() < target);
        // The retained (drained) window still verifies internal continuity.
        assert!(
            log.verify_chain(secret),
            "verify_chain must hold on a drained in-memory window (seeded from first retained entry)"
        );
    }

    // -- L-10: WAL flush() tests --

    #[test]
    fn test_flush_confirms_and_persists_pending_entries() {
        let log = test_audit_log("flush_confirms");
        let secret = b"audit_secret_key";

        for i in 0..5 {
            log.append_event(
                secret, "agent-a", "agent-b", &format!("sig-{i}"), "read:data", &format!("trace-{i}"),
            );
        }

        // Before an explicit flush, the periodic cadence (200 entries / 50ms) may not
        // have fired yet — `flush()` forces it and blocks until acked.
        assert!(log.flush(Duration::from_secs(2)), "flush() should confirm within 2s");
        assert_eq!(log.queue_len(), 0);

        // On-disk line count must match the appended event count once flush() has
        // returned true.
        let log_file = resolve_test_log_path(&format!("test_audit_{}.log", "flush_confirms"));
        let contents = fs::read_to_string(&log_file).expect("log file should exist after flush");
        assert_eq!(contents.lines().count(), 5);

        log.reset();
    }

    #[test]
    fn test_flush_on_in_memory_only_log_does_not_hang() {
        // `ImmutableAuditLog::new("")` is the deliberate no-persistence mode (see
        // `run_wal_worker`'s doc comment) — `flush()` must still return promptly
        // (acked with nothing to sync) rather than blocking until `timeout`.
        let log = ImmutableAuditLog::new("");
        let secret = b"audit_secret_key";
        log.append_event(secret, "agent-a", "agent-b", "sig-001", "read:data", "trace-001");

        let start = Instant::now();
        assert!(log.flush(Duration::from_secs(2)));
        assert!(
            start.elapsed() < Duration::from_secs(1),
            "in-memory flush() should ack near-instantly, not wait out the timeout"
        );
    }

    #[test]
    fn test_sentinel_write_is_atomic_and_leaves_no_temp_file() {
        // C-5: flush_and_sync must swap the sentinel in with a rename, not an
        // in-place overwrite. Observable from a unit test as: (a) the final
        // sentinel content is correct, (b) no `.tmp-<pid>` artifact survives
        // a successful flush.
        let log = test_audit_log("sentinel_atomic");
        let secret = b"audit_secret_key";

        for i in 0..3 {
            log.append_event(
                secret, "agent-a", "agent-b", &format!("sig-{i}"), "read:data", &format!("trace-{i}"),
            );
        }
        assert!(log.flush(Duration::from_secs(2)));

        let count_file = resolve_test_log_path(&format!("test_audit_{}.sentinel", "sentinel_atomic"));
        let sentinel = fs::read_to_string(&count_file).expect("sentinel file should exist after flush");
        assert_eq!(sentinel.trim().parse::<u64>().unwrap(), 3);

        let tmp_leftover = format!("{count_file}.tmp-{}", std::process::id());
        assert!(
            !Path::new(&tmp_leftover).exists(),
            "temp sentinel file must not survive a successful flush"
        );

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
        let log_file = resolve_test_log_path("test_audit_init_chain_valid.log");
        let secret = b"init_chain_secret";
        log.append_event(secret, "a", "b", "sig-1", "intent-1", "trace-1");
        log.append_event(secret, "b", "c", "sig-2", "intent-2", "trace-2");
        // 2 real events + 1 flush-forcing event.
        force_wal_flush_and_drain(&log, secret, &log_file, 3);

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
        let log_file = resolve_test_log_path("test_audit_init_chain_tampered.log");
        let secret = b"init_chain_secret_2";
        log.append_event(secret, "a", "b", "sig-1", "intent-1", "trace-1");
        // 1 real event + 1 flush-forcing event.
        force_wal_flush_and_drain(&log, secret, &log_file, 2);

        // Tamper with the on-disk chain_hash of the first entry.
        let content = fs::read_to_string(&log_file).expect("log file must exist");
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        assert_eq!(lines.len(), 2, "expected both entries flushed to disk");
        let mut entry: serde_json::Value = serde_json::from_str(&lines[0]).unwrap();
        entry["chain_hash"] = serde_json::Value::String("deadbeef".repeat(8));
        lines[0] = entry.to_string();
        fs::write(&log_file, format!("{}\n{}\n", lines[0], lines[1])).unwrap();

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

    /// SC-4 (white-box): the sticky drop floor must survive a fully drained WAL
    /// queue. The integration test in `tests/test_gate6_backpressure_rs.rs` can
    /// only reach the drop path via a *Fatal* worker (which is sticky on its own
    /// account), so this test raises the floor directly on an otherwise perfectly
    /// healthy log — isolating the exact behavior the fix adds.
    ///
    /// Pre-fix, `health()` returned `AuditHealth::from_u8(self.health.load(..))`,
    /// which a drained queue had already recomputed back to `Healthy`, letting
    /// `gate_2_5_kinetic_firewall` re-authorize IRREVERSIBLE_ACTION against an
    /// audit chain with a permanent hole in it.
    #[test]
    fn test_dropped_audit_floor_survives_drained_queue() {
        let log = test_audit_log("sticky_drop_floor");
        let secret = b"sticky_floor_key";

        log.append_event(secret, "src", "dst", "sig", "execute", "tp-sticky");
        assert!(log.flush(Duration::from_secs(2)), "flush should confirm");
        assert_eq!(log.queue_len(), 0, "queue drained");
        assert_eq!(log.health(), AuditHealth::Healthy);

        // Simulate what `append_event`'s queue-full branch does on a drop.
        log.health_floor
            .fetch_max(AuditHealth::Saturated as u8, Ordering::Relaxed);

        // Appending again recomputes health from a (still empty) queue — the
        // precise condition that used to reset it to Healthy.
        log.append_event(secret, "src", "dst", "sig2", "execute", "tp-sticky2");
        assert!(log.flush(Duration::from_secs(2)));
        assert_eq!(log.queue_len(), 0);
        assert_eq!(
            log.health(), AuditHealth::Saturated,
            "a dropped audit record must pin health at Saturated even with an empty \
             queue, so Gate 2.5 stays fail-closed on IRREVERSIBLE_ACTION"
        );

        // Only an explicit operator acknowledgement clears it.
        log.acknowledge_dropped_audits();
        assert_eq!(
            log.health(), AuditHealth::Healthy,
            "acknowledge_dropped_audits must release the floor on a log with no \
             underlying Fatal condition"
        );
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
        //
        // Phase 6: both appends came from THIS thread, so they are both on this
        // thread's shard (`AUDIT_SHARD_SLOT`) and in order — the first entry of
        // that shard is the confidential one. Scoped so the guard drops before
        // `log.reset()` below re-locks the shard (the lock is not reentrant).
        let stored_intent = {
            let idx = AUDIT_SHARD_SLOT.with(|s| *s);
            let shard = log.shards[idx].lock().unwrap();
            shard.entries[0].record.intent.clone()
        };
        assert_ne!(stored_intent, plaintext_intent);
        assert_eq!(decrypt_intent(secret, &stored_intent).unwrap(), plaintext_intent);

        log.reset();
    }

    // -- C-4: rotated audit log archival --

    #[test]
    fn test_compress_file_to_gzip_roundtrip() {
        use std::io::Read;

        let src = "test_c4_compress_src.txt";
        let dst = "test_c4_compress_src.txt.gz";
        let _ = fs::remove_file(src);
        let _ = fs::remove_file(dst);

        let content = b"the quick brown fox jumps over the lazy dog\n".repeat(100);
        fs::write(src, &content).unwrap();

        compress_file_to_gzip(src, dst).expect("compression must succeed");
        assert!(Path::new(dst).exists(), "compressed .gz file must exist");

        let compressed = fs::read(dst).unwrap();
        assert!(compressed.len() < content.len(), "gzip output should be smaller than repetitive input");
        let mut decoder = flate2::read::GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();
        assert_eq!(decompressed, content);

        fs::remove_file(src).unwrap();
        fs::remove_file(dst).unwrap();
    }

    #[test]
    fn test_noop_archival_sink_is_ok_and_side_effect_free() {
        let sink = NoopArchivalSink;
        // Deliberately a path that doesn't exist — Noop must never touch the
        // filesystem, so a missing file must not surface as an error either.
        let path = Path::new("test_c4_noop_target_need_not_exist.gz");
        assert!(sink.archive(path).is_ok());
        assert!(!path.exists());
    }

    #[test]
    fn test_filesystem_archival_sink_moves_file_into_target_dir() {
        let target_dir = "test_c4_archive_dir";
        let _ = fs::remove_dir_all(target_dir);
        let src_path = "test_c4_archival_source.bak.gz";
        fs::write(src_path, b"compressed-ish content").unwrap();

        let sink = FilesystemArchivalSink::new(target_dir);
        sink.archive(Path::new(src_path)).expect("archive must succeed");

        assert!(!Path::new(src_path).exists(), "source must be moved, not copied");
        let dest = Path::new(target_dir).join(src_path);
        assert!(dest.exists(), "compressed file must land in target_dir");
        assert_eq!(fs::read(&dest).unwrap(), b"compressed-ish content");

        fs::remove_dir_all(target_dir).unwrap();
    }

    #[test]
    fn test_maybe_rotate_compresses_bak_and_removes_uncompressed_copy() {
        let log_file = "test_c4_rotate_wal.log";
        let cleanup = || {
            let _ = fs::remove_file(log_file);
            if let Ok(dir) = fs::read_dir(".") {
                for entry in dir.flatten() {
                    let name = entry.file_name().to_string_lossy().to_string();
                    if name.starts_with("test_c4_rotate_wal.log.") {
                        let _ = fs::remove_file(entry.path());
                    }
                }
            }
        };
        cleanup();

        let mut wal = WalWriter::open(log_file, Arc::new(NoopArchivalSink)).unwrap();
        // Force rotation on the next call without needing to actually write
        // AUDIT_MAX_LOG_SIZE (50MB) worth of entries first.
        wal.size = AUDIT_MAX_LOG_SIZE + 1;
        wal.maybe_rotate().expect("maybe_rotate must succeed");

        // The rename to `.bak` happens synchronously inside `maybe_rotate` — only
        // compression happens on the detached `saacp-audit-archival` background
        // thread — so the `.bak` file is already on disk with a known name the
        // instant `maybe_rotate()` returns, before compression has necessarily
        // finished (`GzEncoder`'s `File::create` for the `.gz` destination happens
        // near-instantly, well before the compressed bytes are fully written and
        // fsync'd — polling for the `.gz` path to merely *appear* would race).
        let bak_path = fs::read_dir(".")
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .find(|p| {
                let name = p.file_name().unwrap().to_string_lossy();
                name.starts_with("test_c4_rotate_wal.log.") && name.ends_with(".bak")
            })
            .expect("expected a *.bak file to exist immediately after maybe_rotate()");

        // Poll for that exact `.bak` file's removal — the background thread only
        // deletes it after the compressed copy is confirmed written+fsync'd.
        let deadline = Instant::now() + Duration::from_secs(5);
        while bak_path.exists() && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(20));
        }
        assert!(
            !bak_path.exists(),
            "uncompressed .bak must be removed after successful compression (timed out waiting)"
        );

        let gz_path = format!("{}.gz", bak_path.to_string_lossy());
        assert!(
            Path::new(&gz_path).exists(),
            "expected a compressed .bak.gz file to exist once the uncompressed .bak was removed"
        );

        cleanup();
    }
}
