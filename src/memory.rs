//! memory.rs — Federated Memory + Secure Context Store
//!
//! Implements:
//! - `CheckpointedSession`: Stateful Asynchrony Model for Flaky Infrastructure
//! - `FederatedMemory`: Decentralized, shared local memory buffer
//! - `SecureContextStore`: Secure Context References (SCR) with AES-256-GCM

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use std::collections::BTreeMap;

use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{AeadInPlace, KeyInit};
use rand::RngCore;
use subtle::ConstantTimeEq;
use serde::{Serialize, Deserialize};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::state_backend::StateBackend;

type HmacSha256 = Hmac<Sha256>;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ===========================================================================
// CheckpointedSession
// ===========================================================================

/// Stateful Asynchrony Model for Flaky Infrastructure.
/// Preserves multi-step agent reasoning chains if a TCP connection blips.
pub struct CheckpointedSession {
    inner: Mutex<CheckpointInner>,
}

struct CheckpointInner {
    checkpoints: HashMap<Vec<u8>, CheckpointEntry>,
}

struct CheckpointEntry {
    stage: String,
    data: serde_json::Value,
    timestamp: f64,
}

/// Maximum entries before eviction.
pub const CHECKPOINT_MAX_ENTRIES: usize = 10_000;
/// 30 minutes — hard abort threshold.
pub const CHECKPOINT_TTL_SECONDS: f64 = 1800.0;
/// 2 minutes — log warning.
pub const STALL_WARN_SECONDS: f64 = 120.0;
/// 10 minutes — force checkpoint.
pub const STALL_CHECKPOINT_SECONDS: f64 = 600.0;
/// 30 minutes — hard abort.
pub const STALL_ABORT_SECONDS: f64 = 1800.0;

/// Pipeline stall detection result.
pub struct StallReport {
    pub warn: Vec<Vec<u8>>,
    pub checkpoint: Vec<Vec<u8>>,
    pub abort: Vec<Vec<u8>>,
}

impl CheckpointedSession {
    /// Create a new CheckpointedSession.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(CheckpointInner {
                checkpoints: HashMap::new(),
            }),
        }
    }

    /// Saves the exact pipeline stage linked to the 32-byte Context-State-ID.
    pub fn save_checkpoint(&self, context_state_id: &[u8], execution_stage: &str, intermediate_data: serde_json::Value) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.checkpoints.insert(context_state_id.to_vec(), CheckpointEntry {
            stage: execution_stage.to_string(),
            data: intermediate_data,
            timestamp: now_secs(),
        });
        // Evict expired entries if over capacity
        if inner.checkpoints.len() > CHECKPOINT_MAX_ENTRIES {
            let now = now_secs();
            inner.checkpoints.retain(|_, v| (now - v.timestamp) < CHECKPOINT_TTL_SECONDS);
        }
    }

    /// Restores the exact state if the agent reconnects after a drop.
    pub fn resume_checkpoint(&self, context_state_id: &[u8]) -> Option<(String, serde_json::Value)> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        if let Some(cp) = inner.checkpoints.get(context_state_id) {
            if (now_secs() - cp.timestamp) > CHECKPOINT_TTL_SECONDS {
                inner.checkpoints.remove(context_state_id);
                return None;
            }
            return Some((cp.stage.clone(), cp.data.clone()));
        }
        None
    }

    /// Scans all active checkpoints for pipeline stalls.
    /// Aborted sessions are automatically evicted.
    pub fn check_pipeline_stalls(&self) -> StallReport {
        let mut result = StallReport {
            warn: Vec::new(),
            checkpoint: Vec::new(),
            abort: Vec::new(),
        };
        let now = now_secs();
        let mut to_delete = Vec::new();

        let mut inner = self.inner.lock().expect("lock poisoned");
        for (cid, cp) in inner.checkpoints.iter() {
            let age = now - cp.timestamp;
            if age >= STALL_ABORT_SECONDS {
                result.abort.push(cid.clone());
                to_delete.push(cid.clone());
            } else if age >= STALL_CHECKPOINT_SECONDS {
                result.checkpoint.push(cid.clone());
            } else if age >= STALL_WARN_SECONDS {
                result.warn.push(cid.clone());
            }
        }
        for cid in to_delete {
            inner.checkpoints.remove(&cid);
        }
        result
    }

    /// Return number of active checkpoints.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.checkpoints.len()
    }
}

impl Default for CheckpointedSession {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// FederatedMemory
// ===========================================================================

/// TTL for stored context (5 minutes).
pub const FEDERATED_TTL_SECONDS: f64 = 300.0;
/// Max entries before eviction.
pub const FEDERATED_MAX_ENTRIES: usize = 10_000;
/// 24 hours max even for intent envelopes.
pub const INTENT_MAX_LIFETIME: f64 = 86400.0;

/// Decentralized, shared local memory buffer.
/// Prevents Context Window Exhaustion by allowing agents to pass data by reference
/// using a 32-byte Context-State-ID hash and enforcing TTLs.
///
/// Backed by a process-local `HashMap` by default (`::new()` / `::global()`).
/// [`FederatedMemory::with_backend`] instead routes every record through a
/// shared [`StateBackend`] (e.g. Redis) so multiple SAACP gateway nodes can
/// see the same context store — see `state_backend.rs` for the rationale and
/// which other subsystems this is (and isn't) safe to do for.
pub struct FederatedMemory {
    inner: Mutex<FederatedInner>,
    backend: Option<Arc<dyn StateBackend>>,
}

struct FederatedRecord {
    data: String,
    version: u32,
    expires_at: f64,
}

/// Wire format for a `FederatedRecord` stored in a `StateBackend`. `store_context`,
/// `save_context`, and the intent-envelope methods all share this one record
/// shape and one flat key space, mirroring the single `HashMap` used locally.
#[derive(Serialize, Deserialize)]
struct FederatedRecordWire {
    data: String,
    version: u32,
    expires_at: f64,
}

struct FederatedInner {
    store: HashMap<Vec<u8>, FederatedRecord>,
}

/// Backing store for [`FederatedMemory::global`] / [`FederatedMemory::set_global_backend`] (H-29).
static FEDERATED_MEMORY_GLOBAL: std::sync::OnceLock<FederatedMemory> = std::sync::OnceLock::new();

impl FederatedMemory {
    /// Create a new, process-local FederatedMemory store.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(FederatedInner {
                store: HashMap::new(),
            }),
            backend: None,
        }
    }

    /// Create a FederatedMemory store backed by a shared [`StateBackend`]
    /// (e.g. Redis) instead of a process-local `HashMap`. Every method below
    /// consults the backend exclusively when one is configured — the two
    /// storage modes are never mixed within one instance.
    pub fn with_backend(backend: Arc<dyn StateBackend>) -> Self {
        Self {
            inner: Mutex::new(FederatedInner { store: HashMap::new() }),
            backend: Some(backend),
        }
    }

    /// Stores the massive history/context and returns a 32-byte SHA-256 hash (Context-State-ID).
    ///
    /// `agent_id` is folded into the hash so two agents that happen to submit
    /// byte-identical content never collide on the same Context-State-ID and
    /// silently alias each other's storage slot (H-25). The agent_id is
    /// length-prefixed before the content rather than plainly concatenated —
    /// otherwise `("ab", "cdef")` and `("abcd", "ef")` would hash identically,
    /// the same boundary-ambiguity class already fixed elsewhere in this
    /// crate for `NegotiationTranscript` suite lists (H-9).
    pub fn store_context(&self, agent_id: &str, massive_context_string: &str, version: u32) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update((agent_id.len() as u64).to_le_bytes());
        hasher.update(agent_id.as_bytes());
        hasher.update(massive_context_string.as_bytes());
        let state_id = hasher.finalize().to_vec();
        self.put_record(&state_id, massive_context_string.to_string(), version, FEDERATED_TTL_SECONDS);
        state_id
    }

    /// Fetches context by 32-byte state ID. Checks expiration and version.
    pub fn fetch_context(&self, state_id: &[u8], expected_version: u32) -> Result<String, String> {
        if state_id.len() != 32 {
            return Err("Context-State-ID must be exactly 32 bytes.".into());
        }
        let (data, version, expires_at) = self.get_record(state_id)
            .ok_or("Context-State-ID not found in Federated Memory.")?;
        if now_secs() > expires_at {
            self.remove_record(state_id);
            return Err("Context-State-ID has expired (TTL).".into());
        }
        if version != expected_version {
            return Err(format!("StaleStateError: Expected version {}, got {}", expected_version, version));
        }
        Ok(data)
    }

    /// Directly saves a context by its 32-byte ID.
    pub fn save_context(&self, state_id: &[u8], data: &str, version: u32) -> Result<(), String> {
        if state_id.len() != 32 {
            return Err("Context-State-ID must be exactly 32 bytes.".into());
        }
        self.put_record(state_id, data.to_string(), version, FEDERATED_TTL_SECONDS);
        Ok(())
    }

    /// Provenance-tracking sibling of [`Self::save_context`]. `save_context`
    /// itself is left unchanged (no signature/behavior change, no blast
    /// radius on its existing callers/tests) — this is a purely additive,
    /// opt-in API for callers that want to record *who* wrote a context
    /// entry, so a reader can later check provenance before trusting shared
    /// content instead of treating the store as write-by-anyone,
    /// trust-unconditionally. Defense-in-depth against cross-agent context
    /// poisoning — `save_context`/`fetch_context` currently have no caller
    /// anywhere in this crate outside their own unit tests, so this hardens
    /// the primitive ahead of any future live wiring rather than closing an
    /// actively-exploited gap.
    pub fn save_context_with_provenance(
        &self,
        state_id: &[u8],
        data: &str,
        version: u32,
        writer_agent: &str,
    ) -> Result<(), String> {
        if state_id.len() != 32 {
            return Err("Context-State-ID must be exactly 32 bytes.".into());
        }
        let tagged = serde_json::json!({
            "_saacp_provenance_v1": true,
            "writer_agent": writer_agent,
            "data": data,
        }).to_string();
        self.put_record(state_id, tagged, version, FEDERATED_TTL_SECONDS);
        Ok(())
    }

    /// Fetches context by 32-byte state ID, returning the recorded
    /// `writer_agent` if the entry was written via
    /// [`Self::save_context_with_provenance`]. Entries written via the plain
    /// `save_context`/`store_context` (or any pre-existing data with no
    /// provenance tag) return `writer_agent: None` — provenance is strictly
    /// opt-in and never retroactive, so this never breaks reads of
    /// non-provenance-tagged entries. Internally delegates to the unchanged
    /// `fetch_context` for the actual lookup/expiry/version checks.
    pub fn fetch_context_with_provenance(
        &self,
        state_id: &[u8],
        expected_version: u32,
    ) -> Result<(String, Option<String>), String> {
        let raw = self.fetch_context(state_id, expected_version)?;
        match serde_json::from_str::<serde_json::Value>(&raw) {
            Ok(v) if v.get("_saacp_provenance_v1") == Some(&serde_json::Value::Bool(true)) => {
                let writer = v.get("writer_agent").and_then(|w| w.as_str()).map(String::from);
                let data = v.get("data").and_then(|d| d.as_str()).unwrap_or("").to_string();
                Ok((data, writer))
            }
            _ => Ok((raw, None)),
        }
    }

    // ── Local/backend storage primitives ────────────────────────────────────
    // Every public method above (and the intent-envelope methods below) goes
    // through these three helpers, matching the single flat key space the
    // original in-process HashMap always had (context records and intent
    // envelopes are both just "a blob behind a hash, with a TTL").

    fn put_record(&self, id: &[u8], data: String, version: u32, ttl_secs: f64) {
        match &self.backend {
            Some(backend) => {
                let record = FederatedRecordWire { data, version, expires_at: now_secs() + ttl_secs };
                if let Ok(bytes) = serde_json::to_vec(&record) {
                    let _ = backend.set(
                        &Self::backend_key(id),
                        &bytes,
                        Some(Duration::from_secs_f64(ttl_secs.max(0.0))),
                    );
                }
            }
            None => {
                let mut inner = self.inner.lock().expect("lock poisoned");
                inner.store.insert(id.to_vec(), FederatedRecord {
                    data, version, expires_at: now_secs() + ttl_secs,
                });
                // Evict expired entries if over capacity (in-process mode only —
                // the backend mode relies on the backend's own TTL expiry).
                if inner.store.len() > FEDERATED_MAX_ENTRIES {
                    let now = now_secs();
                    inner.store.retain(|_, v| v.expires_at > now);
                }
            }
        }
    }

    fn get_record(&self, id: &[u8]) -> Option<(String, u32, f64)> {
        match &self.backend {
            Some(backend) => {
                let bytes = backend.get(&Self::backend_key(id)).ok().flatten()?;
                let record: FederatedRecordWire = serde_json::from_slice(&bytes).ok()?;
                Some((record.data, record.version, record.expires_at))
            }
            None => {
                let inner = self.inner.lock().expect("lock poisoned");
                inner.store.get(id).map(|r| (r.data.clone(), r.version, r.expires_at))
            }
        }
    }

    fn remove_record(&self, id: &[u8]) {
        match &self.backend {
            Some(backend) => { let _ = backend.delete(&Self::backend_key(id)); }
            None => { self.inner.lock().expect("lock poisoned").store.remove(id); }
        }
    }

    /// `state_backend::StateBackend` keys are namespaced under a common
    /// prefix so a shared Redis instance can host multiple SAACP subsystems
    /// (and future FederatedMemory-adjacent tooling) without key collisions.
    fn backend_key(id: &[u8]) -> String {
        format!("fedmem:{}", hex::encode(id))
    }

    /// Creates an immutable intent envelope, signs it with HMAC-SHA256, and stores it.
    /// Returns the 32-byte hex hash of the envelope.
    ///
    /// SECURITY: The HMAC covers a BTreeMap-sorted canonical JSON of ONLY the three
    /// payload fields (root_intent, root_issuer, timestamp). This guarantees that the
    /// byte string passed to HMAC at creation exactly matches the byte string reconstructed
    /// at verification, regardless of serde_json's map iteration order. Separately stored
    /// metadata (root_signature) is never part of the signed payload.
    pub fn create_intent_envelope(
        &self,
        root_intent: &str,
        root_issuer: &str,
        secret_key: &[u8],
    ) -> String {
        // f64→u64: epoch seconds are positive and fractional part is not needed.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let ts_u64 = now_secs() as u64;

        // Canonical signed payload: BTreeMap ensures deterministic key ordering.
        let mut signed_fields: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        signed_fields.insert("root_intent", serde_json::Value::String(root_intent.to_string()));
        signed_fields.insert("root_issuer", serde_json::Value::String(root_issuer.to_string()));
        signed_fields.insert("timestamp", serde_json::json!(ts_u64));
        let canonical_json = serde_json::to_string(&signed_fields).unwrap_or_default();

        // HMAC-SHA256 over the canonical payload
        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret_key).expect("HMAC accepts any key size");
        mac.update(canonical_json.as_bytes());
        let root_signature = hex::encode(mac.finalize().into_bytes());

        // Store the full envelope (canonical payload + signature) as JSON
        let mut final_fields: BTreeMap<&str, serde_json::Value> = signed_fields.into_iter().collect();
        final_fields.insert("root_signature", serde_json::Value::String(root_signature));
        let final_json = serde_json::to_string(&final_fields).unwrap_or_default();
        let envelope_hash = Sha256::digest(final_json.as_bytes()).to_vec();

        self.put_record(&envelope_hash, final_json, 1, INTENT_MAX_LIFETIME);

        hex::encode(&envelope_hash)
    }

    /// Deletes an intent envelope by hex hash. Returns true if found and deleted.
    pub fn delete_intent_envelope(&self, intent_hash_hex: &str) -> bool {
        let intent_hash = match hex::decode(intent_hash_hex) {
            Ok(h) => h,
            Err(_) => return false,
        };
        match &self.backend {
            Some(backend) => backend.delete(&Self::backend_key(&intent_hash)).unwrap_or(false),
            None => self.inner.lock().expect("lock poisoned").store.remove(&intent_hash).is_some(),
        }
    }

    /// Evicts all expired entries. Returns count evicted.
    ///
    /// In backend mode this is a no-op that always returns 0 — the backend
    /// (e.g. Redis `EX`) enforces TTL expiry itself; there's no generically
    /// safe way to enumerate every key across the shared keyspace to sweep
    /// them client-side without a full scan on every call.
    pub fn evict_expired(&self) -> usize {
        match &self.backend {
            Some(_) => 0,
            None => {
                let now = now_secs();
                let mut inner = self.inner.lock().expect("lock poisoned");
                let before = inner.store.len();
                inner.store.retain(|_, v| v.expires_at > now);
                before - inner.store.len()
            }
        }
    }

    /// Fetches the intent envelope, validates HMAC signature, returns root_intent.
    pub fn fetch_intent_envelope(
        &self,
        intent_hash_hex: &str,
        secret_key: &[u8],
    ) -> Result<String, SAACPHardDrop> {
        let intent_hash = hex::decode(intent_hash_hex).map_err(|_| {
            SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "Invalid intent hash format.")
        })?;

        let raw_data = {
            let (data, _version, expires_at) = self.get_record(&intent_hash).ok_or_else(|| {
                SAACPHardDrop::new(SAACPBytecodes::StateExpiredOrStale,
                    "Intent Envelope missing from Federated Memory.")
            })?;
            if now_secs() > expires_at {
                self.remove_record(&intent_hash);
                return Err(SAACPHardDrop::new(SAACPBytecodes::StateExpiredOrStale,
                    "Intent Envelope has expired (TTL)."));
            }
            data
        };

        // Parse and verify signature outside lock
        let envelope: serde_json::Value = serde_json::from_str(&raw_data)
            .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "Envelope parse error."))?;
        let obj = envelope.as_object().ok_or_else(|| {
            SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "Envelope not an object.")
        })?;
        let provided_sig = obj.get("root_signature")
            .and_then(|v| v.as_str())
            .unwrap_or_default();

        // Reconstruct the EXACT canonical JSON that was signed at creation:
        // BTreeMap-sorted, only the three payload fields, no root_signature.
        // This is the only valid signed payload — no field stripping needed.
        let root_intent_str = obj.get("root_intent").and_then(|v| v.as_str()).unwrap_or_default();
        let root_issuer_str = obj.get("root_issuer").and_then(|v| v.as_str()).unwrap_or_default();
        let timestamp_val = obj.get("timestamp").cloned().unwrap_or(serde_json::Value::Null);
        let mut signed_fields: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
        signed_fields.insert("root_intent", serde_json::Value::String(root_intent_str.to_string()));
        signed_fields.insert("root_issuer", serde_json::Value::String(root_issuer_str.to_string()));
        signed_fields.insert("timestamp", timestamp_val);
        let canonical_json = serde_json::to_string(&signed_fields).unwrap_or_default();

        let mut mac = <HmacSha256 as Mac>::new_from_slice(secret_key).expect("HMAC key");
        mac.update(canonical_json.as_bytes());
        let expected_sig = hex::encode(mac.finalize().into_bytes());

        // Constant-time comparison prevents timing oracle on the HMAC tag.
        if expected_sig.as_bytes().ct_ne(provided_sig.as_bytes()).into() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Intent Envelope signature verification failed.",
            ));
        }

        Ok(root_intent_str.to_string())
    }

    /// Return number of stored entries.
    ///
    /// In backend mode this performs a `scan_prefix` over the whole `fedmem:`
    /// namespace — an O(n) diagnostic operation (matching Redis `SCAN`
    /// semantics), not something to call on a hot path.
    pub fn count(&self) -> usize {
        match &self.backend {
            Some(backend) => backend.scan_prefix("fedmem:").map(|k| k.len()).unwrap_or(0),
            None => self.inner.lock().expect("lock poisoned").store.len(),
        }
    }

    /// Process-wide singleton FederatedMemory. Defaults to process-local
    /// storage unless [`FederatedMemory::set_global_backend`] was called
    /// first (see H-29).
    pub fn global() -> &'static FederatedMemory {
        FEDERATED_MEMORY_GLOBAL.get_or_init(FederatedMemory::new)
    }

    /// (H-29) Configure the process-wide [`FederatedMemory::global`]
    /// singleton to use a shared [`StateBackend`] (e.g. Redis) instead of
    /// the process-local `HashMap` default, so multi-node deployments get
    /// cross-node visibility from the singleton every gate actually calls
    /// (`handler.rs`), not just from manually-constructed instances.
    ///
    /// Must be called before the first call to [`FederatedMemory::global`]
    /// — typically once at process startup, before the gateway starts
    /// accepting connections. Returns `Err` if the singleton was already
    /// initialized (by a prior call to this function, or by an earlier
    /// `global()` call defaulting to process-local storage) rather than
    /// silently discarding the caller's intent — a misordered startup
    /// sequence should be observable, not a silent correctness gap.
    pub fn set_global_backend(backend: Arc<dyn StateBackend>) -> Result<(), String> {
        FEDERATED_MEMORY_GLOBAL
            .set(FederatedMemory::with_backend(backend))
            .map_err(|_| {
                "FederatedMemory::global() singleton already initialized; \
                 set_global_backend() must be called before the first use of global()."
                    .to_string()
            })
    }

    /// Fetch context by hex-encoded context state ID.
    pub fn fetch_context_by_hex(&self, hex_id: &str, version: u64) -> Result<String, String> {
        let bytes = hex::decode(hex_id)
            .map_err(|e| format!("Invalid hex context ID: {}", e))?;
        // context_version in the wire format is u32; reject values that don't fit.
        let version_u32 = u32::try_from(version)
            .map_err(|_| format!("context_version {version} exceeds u32 range"))?;
        self.fetch_context(&bytes, version_u32)
    }
}

impl Default for FederatedMemory {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// SecureContextStore (SCR)
// ===========================================================================

const SCR_INFO: &[u8] = b"SAACP-SCR-v1";
const SCR_IV_INFO: &[u8] = b"SAACP-SCR-iv-v1";
const SCR_MAX_ENTRIES: usize = 50_000;

/// Derive a 32-byte SCR from a master key and a fresh random salt.
fn derive_scr(master_key: &[u8], salt: &[u8]) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(salt), master_key);
    let mut okm = vec![0u8; 32];
    hkdf.expand(SCR_INFO, &mut okm).expect("HKDF expand");
    okm
}

/// Derive a deterministic 12-byte IV for AES-GCM from the SCR.
fn derive_iv(master_key: &[u8], scr: &[u8]) -> Vec<u8> {
    let hkdf = Hkdf::<Sha256>::new(Some(scr), master_key);
    let mut okm = vec![0u8; 12];
    hkdf.expand(SCR_IV_INFO, &mut okm).expect("HKDF expand");
    okm
}

/// Build AAD from ownership metadata.
fn build_aad(owner_id: &str, audience: &[String], expiry: f64) -> Vec<u8> {
    let mut map = serde_json::Map::new();
    map.insert("audience".into(), serde_json::json!(audience));
    map.insert("expiry".into(), serde_json::json!(expiry));
    map.insert("owner".into(), serde_json::Value::String(owner_id.to_string()));
    serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_default().into_bytes()
}

#[allow(dead_code)]
struct ScrRecord {
    ciphertext: Vec<u8>,
    salt: Vec<u8>,
    aad: Vec<u8>,
    expiry: f64,
    owner: String,
    audience: Vec<String>,
    revoked: bool,
    classification: String,
}

/// Secure Context References (SCR) — AEGF replacement for content-derived
/// context_state_id.
///
/// Security model:
/// - SCR = HKDF-SHA256(master_key, fresh_salt) — crypto-random, not content-derived.
/// - Stored content encrypted with AES-256-GCM before indexing.
/// - Ownership, audience, expiry metadata bound as AEAD AAD.
/// - Two identical context objects produce different SCRs (different salt each time).
pub struct SecureContextStore {
    inner: Mutex<ScrInner>,
}

struct ScrInner {
    store: HashMap<String, ScrRecord>,
}

impl SecureContextStore {
    /// Create a new SecureContextStore.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(ScrInner {
                store: HashMap::new(),
            }),
        }
    }

    /// Encrypt and store content. Returns SCR hex string (64 chars).
    pub fn store(
        &self,
        content: &str,
        owner_id: &str,
        audience: &[String],
        ttl_seconds: f64,
        master_key: &[u8],
        classification: &str,
    ) -> Result<String, String> {
        if master_key.len() < 32 {
            return Err("master_key must be at least 32 bytes.".into());
        }

        let expiry = now_secs() + ttl_seconds;
        let mut salt = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt);

        let scr = derive_scr(master_key, &salt);
        let iv = derive_iv(master_key, &scr);
        let aad = build_aad(owner_id, audience, expiry);

        // AES-256-GCM encryption
        let key = Key::<Aes256Gcm>::from_slice(&master_key[..32]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&iv);

        let plaintext = content.as_bytes();
        let mut buffer = plaintext.to_vec();
        cipher.encrypt_in_place(nonce, &aad, &mut buffer)
            .map_err(|e| format!("AES-GCM encrypt error: {e}"))?;

        let scr_hex = hex::encode(&scr);
        let mut inner = self.inner.lock().expect("lock poisoned");
        Self::evict_if_needed(&mut inner);
        inner.store.insert(scr_hex.clone(), ScrRecord {
            ciphertext: buffer,
            salt,
            aad,
            expiry,
            owner: owner_id.to_string(),
            audience: audience.to_vec(),
            revoked: false,
            classification: classification.to_string(),
        });
        Ok(scr_hex)
    }

    /// Retrieve and decrypt content.
    ///
    /// Authorization checks:
    /// 1. SCR must exist and not be expired or revoked.
    /// 2. requester_id must be the owner OR in the audience list.
    /// 3. AES-GCM tag must verify (detects tampering).
    ///
    /// (H-27) The existence/expiry/revoked/authorization checks and the
    /// AES-GCM decrypt all run inside a single lock acquisition. Splitting
    /// these across two critical sections (checks under the lock, decrypt
    /// after releasing it) opened a TOCTOU window: a concurrent `revoke()`
    /// between lock release and decrypt completion would still let this call
    /// return plaintext for a context that is, by the time the caller sees
    /// it, already revoked. Holding the lock across the (microsecond-scale,
    /// in-memory) decrypt closes that window entirely — `revoke()` takes the
    /// same `Mutex<ScrInner>`, so the two can never interleave.
    pub fn retrieve(
        &self,
        scr_hex: &str,
        requester_id: &str,
        master_key: &[u8],
    ) -> Result<String, SAACPHardDrop> {
        if master_key.len() < 32 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScrUnauthorized,
                "master_key must be at least 32 bytes.",
            ));
        }
        let scr = hex::decode(scr_hex).map_err(|_| {
            SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "Invalid SCR hex.")
        })?;

        let buffer = {
            let mut inner = self.inner.lock().expect("lock poisoned");
            let record = inner.store.get(scr_hex).ok_or_else(|| {
                SAACPHardDrop::new(SAACPBytecodes::ScrNotFound,
                    "Secure Context Reference not found or expired.")
            })?;
            if now_secs() > record.expiry {
                inner.store.remove(scr_hex);
                return Err(SAACPHardDrop::new(SAACPBytecodes::ScrNotFound,
                    "Secure Context Reference not found or expired."));
            }
            if record.revoked {
                return Err(SAACPHardDrop::new(SAACPBytecodes::ScrNotFound,
                    "Secure Context Reference not found or expired."));
            }
            if requester_id != record.owner && !record.audience.contains(&requester_id.to_string()) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::ScrUnauthorized,
                    "Access denied: requester not authorized for this Secure Context Reference.",
                ));
            }

            // AES-GCM decryption — still inside the lock (see doc comment above).
            let iv = derive_iv(master_key, &scr);
            let key = Key::<Aes256Gcm>::from_slice(&master_key[..32]);
            let cipher = Aes256Gcm::new(key);
            let nonce = Nonce::from_slice(&iv);

            let mut buffer = record.ciphertext.clone();
            cipher.decrypt_in_place(nonce, &record.aad, &mut buffer)
                .map_err(|_| SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Secure Context Reference authentication failed — tampering detected.",
                ))?;
            buffer
        };

        String::from_utf8(buffer).map_err(|_| {
            SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "Decrypted content is not valid UTF-8.")
        })
    }

    /// Revoke an SCR. Only the owner may revoke.
    pub fn revoke(&self, scr_hex: &str, revoker_id: &str) -> Result<bool, SAACPHardDrop> {
        let mut inner = self.inner.lock().expect("lock poisoned");
        let record = match inner.store.get_mut(scr_hex) {
            Some(r) => r,
            None => return Ok(false),
        };
        if record.owner != revoker_id {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScrUnauthorized,
                "Only the owner may revoke a Secure Context Reference.",
            ));
        }
        record.revoked = true;
        Ok(true)
    }

    /// Remove expired and revoked entries. Returns eviction count.
    pub fn evict_expired(&self) -> usize {
        let now = now_secs();
        let mut inner = self.inner.lock().expect("lock poisoned");
        let before = inner.store.len();
        inner.store.retain(|_, v| v.expiry > now && !v.revoked);
        before - inner.store.len()
    }

    /// Return number of stored entries.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.store.len()
    }

    fn evict_if_needed(inner: &mut ScrInner) {
        // High-water mark: trigger eviction before the store is completely full so
        // there is always room for incoming entries. The old approach only evicted
        // at exactly SCR_MAX_ENTRIES and silently dropped new entries if all existing
        // ones were still valid — enabling a DoS by pre-filling with long-TTL SCRs.
        const HIGH_WATER: usize = SCR_MAX_ENTRIES - SCR_MAX_ENTRIES / 5; // 40,000
        if inner.store.len() < HIGH_WATER {
            return;
        }
        let now = now_secs();
        inner.store.retain(|_, v| v.expiry > now && !v.revoked);
        // If expiry eviction wasn't enough (all entries still valid), forcibly remove
        // the oldest half by key order to keep memory bounded.
        if inner.store.len() >= SCR_MAX_ENTRIES {
            let target = SCR_MAX_ENTRIES / 2;
            let excess = inner.store.len().saturating_sub(target);
            let to_remove: Vec<_> = inner.store.keys().take(excess).cloned().collect();
            for k in to_remove { inner.store.remove(&k); }
        }
    }
}

impl Default for SecureContextStore {
    fn default() -> Self {
        Self::new()
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // -- CheckpointedSession tests --

    #[test]
    fn test_checkpoint_save_and_resume() {
        let cs = CheckpointedSession::new();
        let state_id = vec![0xAB; 32];
        cs.save_checkpoint(&state_id, "stage_1", serde_json::json!({"key": "value"}));
        let result = cs.resume_checkpoint(&state_id);
        assert!(result.is_some());
        let (stage, data) = result.unwrap();
        assert_eq!(stage, "stage_1");
        assert_eq!(data["key"], "value");
    }

    #[test]
    fn test_checkpoint_not_found() {
        let cs = CheckpointedSession::new();
        assert!(cs.resume_checkpoint(&[0u8; 32]).is_none());
    }

    #[test]
    fn test_checkpoint_count() {
        let cs = CheckpointedSession::new();
        assert_eq!(cs.count(), 0);
        cs.save_checkpoint(&[1u8; 32], "s1", serde_json::json!(null));
        assert_eq!(cs.count(), 1);
    }

    #[test]
    fn test_pipeline_stall_detection() {
        let cs = CheckpointedSession::new();
        // These will have fresh timestamps so won't be in any stall category
        cs.save_checkpoint(&[1u8; 32], "s1", serde_json::json!(null));
        let report = cs.check_pipeline_stalls();
        assert!(report.warn.is_empty());
        assert!(report.checkpoint.is_empty());
        assert!(report.abort.is_empty());
    }

    // -- FederatedMemory tests --

    #[test]
    fn test_store_and_fetch_context() {
        let fm = FederatedMemory::new();
        let data = "Hello, SAACP world!";
        let state_id = fm.store_context("agent-alpha", data, 1);
        assert_eq!(state_id.len(), 32);
        let fetched = fm.fetch_context(&state_id, 1).unwrap();
        assert_eq!(fetched, data);
    }

    #[test]
    fn test_fetch_wrong_version() {
        let fm = FederatedMemory::new();
        let state_id = fm.store_context("agent-alpha", "data", 1);
        assert!(fm.fetch_context(&state_id, 2).is_err());
    }

    #[test]
    fn test_fetch_not_found() {
        let fm = FederatedMemory::new();
        assert!(fm.fetch_context(&[0u8; 32], 1).is_err());
    }

    #[test]
    fn test_fetch_invalid_state_id_length() {
        let fm = FederatedMemory::new();
        assert!(fm.fetch_context(&[0u8; 16], 1).is_err());
    }

    #[test]
    fn test_save_context_direct() {
        let fm = FederatedMemory::new();
        let state_id = vec![0xCC; 32];
        fm.save_context(&state_id, "direct_data", 5).unwrap();
        let fetched = fm.fetch_context(&state_id, 5).unwrap();
        assert_eq!(fetched, "direct_data");
    }

    #[test]
    fn test_intent_envelope_create_and_fetch() {
        let fm = FederatedMemory::new();
        let secret = b"my_secret_key_for_hmac";
        let hash_hex = fm.create_intent_envelope("do_something", "agent-001", secret);
        assert_eq!(hash_hex.len(), 64); // 32 bytes hex
        let intent = fm.fetch_intent_envelope(&hash_hex, secret).unwrap();
        assert_eq!(intent, "do_something");
    }

    #[test]
    fn test_intent_envelope_wrong_secret() {
        let fm = FederatedMemory::new();
        let hash_hex = fm.create_intent_envelope("intent", "issuer", b"secret1");
        let err = fm.fetch_intent_envelope(&hash_hex, b"secret2").unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::InvalidSignature);
    }

    #[test]
    fn test_intent_envelope_delete() {
        let fm = FederatedMemory::new();
        let hash_hex = fm.create_intent_envelope("intent", "issuer", b"secret");
        assert!(fm.delete_intent_envelope(&hash_hex));
        assert!(!fm.delete_intent_envelope(&hash_hex)); // already gone
    }

    #[test]
    fn test_evict_expired() {
        let fm = FederatedMemory::new();
        fm.store_context("agent-alpha", "data", 1);
        assert_eq!(fm.count(), 1);
        // Nothing expired yet
        assert_eq!(fm.evict_expired(), 0);
    }

    // -- FederatedMemory::global() / set_global_backend() (H-29) --
    //
    // `FEDERATED_MEMORY_GLOBAL` is a genuine process-wide static shared by
    // every test in this binary (and by `handler.rs` in a real process), so
    // these tests only assert invariants that hold regardless of which test
    // happens to touch the singleton first — they must not assume they win
    // the initialization race.

    #[test]
    fn h29_global_returns_same_instance_across_calls() {
        let a = FederatedMemory::global() as *const FederatedMemory;
        let b = FederatedMemory::global() as *const FederatedMemory;
        assert_eq!(a, b, "global() must return the same singleton instance across calls");
    }

    #[test]
    fn h29_set_global_backend_rejects_double_init() {
        use crate::state_backend::InMemoryBackend;
        // Whether this call wins the race to initialize the process-wide
        // singleton or loses it to another test/call site, the singleton is
        // guaranteed initialized by the time it returns.
        let _ = FederatedMemory::set_global_backend(Arc::new(InMemoryBackend::new()));
        let second = FederatedMemory::set_global_backend(Arc::new(InMemoryBackend::new()));
        assert!(
            second.is_err(),
            "set_global_backend must reject re-initialization instead of silently discarding it"
        );
    }

    // -- FederatedMemory::with_backend tests (state_backend.rs wiring) --

    fn backend_fm() -> FederatedMemory {
        use crate::state_backend::InMemoryBackend;
        FederatedMemory::with_backend(Arc::new(InMemoryBackend::new()))
    }

    #[test]
    fn test_backend_store_and_fetch_context() {
        let fm = backend_fm();
        let data = "Hello, backend-mode SAACP world!";
        let state_id = fm.store_context("agent-alpha", data, 1);
        assert_eq!(state_id.len(), 32);
        let fetched = fm.fetch_context(&state_id, 1).unwrap();
        assert_eq!(fetched, data);
    }

    #[test]
    fn test_backend_fetch_wrong_version() {
        let fm = backend_fm();
        let state_id = fm.store_context("agent-alpha", "data", 1);
        assert!(fm.fetch_context(&state_id, 2).is_err());
    }

    #[test]
    fn test_backend_fetch_not_found() {
        let fm = backend_fm();
        assert!(fm.fetch_context(&[0u8; 32], 1).is_err());
    }

    #[test]
    fn test_backend_save_context_direct() {
        let fm = backend_fm();
        let state_id = vec![0xCCu8; 32];
        fm.save_context(&state_id, "direct_backend_data", 5).unwrap();
        let fetched = fm.fetch_context(&state_id, 5).unwrap();
        assert_eq!(fetched, "direct_backend_data");
    }

    #[test]
    fn test_backend_intent_envelope_create_and_fetch() {
        let fm = backend_fm();
        let secret = b"my_secret_key_for_hmac";
        let hash_hex = fm.create_intent_envelope("do_something", "agent-001", secret);
        assert_eq!(hash_hex.len(), 64);
        let intent = fm.fetch_intent_envelope(&hash_hex, secret).unwrap();
        assert_eq!(intent, "do_something");
    }

    #[test]
    fn test_backend_intent_envelope_wrong_secret() {
        let fm = backend_fm();
        let hash_hex = fm.create_intent_envelope("intent", "issuer", b"secret1");
        let err = fm.fetch_intent_envelope(&hash_hex, b"secret2").unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::InvalidSignature);
    }

    #[test]
    fn test_backend_intent_envelope_delete() {
        let fm = backend_fm();
        let hash_hex = fm.create_intent_envelope("intent", "issuer", b"secret");
        assert!(fm.delete_intent_envelope(&hash_hex));
        assert!(!fm.delete_intent_envelope(&hash_hex)); // already gone
    }

    #[test]
    fn test_backend_count_reflects_scan_prefix() {
        let fm = backend_fm();
        assert_eq!(fm.count(), 0);
        fm.store_context("agent-alpha", "a", 1);
        fm.store_context("agent-alpha", "b", 1);
        assert_eq!(fm.count(), 2);
    }

    #[test]
    fn test_backend_and_local_instances_are_independent() {
        let local = FederatedMemory::new();
        let backend = backend_fm();
        let state_id = local.store_context("agent-alpha", "only-local", 1);
        // The backend-mode instance has an entirely separate store — it must
        // not see data written to the local, process-only instance.
        assert!(backend.fetch_context(&state_id, 1).is_err());
    }

    /// H-25: two different agents storing byte-identical content must land on
    /// different Context-State-IDs — the state_id must not be a pure content
    /// hash an attacker can collide across identities.
    #[test]
    fn test_store_context_cross_agent_no_collision() {
        let fm = FederatedMemory::new();
        let payload = "identical payload submitted by two different agents";
        let id_a = fm.store_context("agent-alpha", payload, 1);
        let id_b = fm.store_context("agent-beta", payload, 1);
        assert_ne!(id_a, id_b);
        assert_eq!(fm.fetch_context(&id_a, 1).unwrap(), payload);
        assert_eq!(fm.fetch_context(&id_b, 1).unwrap(), payload);
    }

    /// H-25: the hash input must be unambiguous about the agent_id/content
    /// boundary — a naive concatenation would let ("ab","cdef") collide with
    /// ("abcd","ef"). The length-prefixed hash must not.
    #[test]
    fn test_store_context_boundary_ambiguity_no_collision() {
        let fm = FederatedMemory::new();
        let id_1 = fm.store_context("ab", "cdef", 1);
        let id_2 = fm.store_context("abcd", "ef", 1);
        assert_ne!(id_1, id_2);
    }

    // -- SecureContextStore tests --

    fn test_master_key() -> Vec<u8> {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    #[test]
    fn test_scr_store_and_retrieve() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience = vec!["agent-b".to_string()];

        let scr_hex = scs.store("secret data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        assert_eq!(scr_hex.len(), 64);

        let content = scs.retrieve(&scr_hex, "agent-a", &key).unwrap();
        assert_eq!(content, "secret data");
    }

    #[test]
    fn test_scr_retrieve_by_audience() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience = vec!["agent-b".to_string()];

        let scr_hex = scs.store("shared data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        let content = scs.retrieve(&scr_hex, "agent-b", &key).unwrap();
        assert_eq!(content, "shared data");
    }

    #[test]
    fn test_scr_unauthorized_requester() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience = vec!["agent-b".to_string()];

        let scr_hex = scs.store("secret", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        let err = scs.retrieve(&scr_hex, "agent-c", &key).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::ScrUnauthorized);
    }

    #[test]
    fn test_scr_not_found() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let err = scs.retrieve(&"ab".repeat(32), "agent-a", &key).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::ScrNotFound);
    }

    #[test]
    fn test_scr_revoke() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience: Vec<String> = vec![];

        let scr_hex = scs.store("data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        assert!(scs.revoke(&scr_hex, "agent-a").unwrap());

        let err = scs.retrieve(&scr_hex, "agent-a", &key).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::ScrNotFound);
    }

    #[test]
    fn h27_retrieve_cannot_return_plaintext_after_concurrent_revoke() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let scs = Arc::new(SecureContextStore::new());
        let key = test_master_key();
        let audience: Vec<String> = vec![];
        let scr_hex = scs.store("top secret", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();

        let revoked = Arc::new(AtomicBool::new(false));
        let revoker_store = Arc::clone(&scs);
        let revoker_flag = Arc::clone(&revoked);
        let revoker_scr = scr_hex.clone();
        let revoker = std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_micros(200));
            revoker_store.revoke(&revoker_scr, "agent-a").unwrap();
            // Release ordering: everything revoke() did (including releasing
            // the store's internal lock) happens-before this store is
            // observed by any thread that then loads it with Acquire below.
            revoker_flag.store(true, Ordering::Release);
        });

        let mut post_revoke_calls = 0usize;
        let mut violations = 0usize;
        for _ in 0..5000 {
            // Check the flag BEFORE calling retrieve(): if it's already true,
            // revoke() has fully completed (Acquire pairs with the Release
            // above), so this retrieve() call is guaranteed to start after
            // the revocation — under the H-27 fix it must therefore fail.
            let already_revoked = revoked.load(Ordering::Acquire);
            let res = scs.retrieve(&scr_hex, "agent-a", &key);
            if already_revoked {
                post_revoke_calls += 1;
                if res.is_ok() {
                    violations += 1;
                }
            }
        }
        revoker.join().unwrap();

        assert_eq!(
            violations, 0,
            "retrieve() returned plaintext for an already-revoked SCR — H-27 TOCTOU regression"
        );
        assert!(
            post_revoke_calls > 0,
            "test did not exercise any post-revoke retrieve() calls; increase loop iterations"
        );
    }

    #[test]
    fn test_scr_revoke_by_non_owner() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience: Vec<String> = vec![];

        let scr_hex = scs.store("data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        let err = scs.revoke(&scr_hex, "agent-b").unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::ScrUnauthorized);
    }

    #[test]
    fn test_scr_different_content_different_scr() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience: Vec<String> = vec![];

        let scr1 = scs.store("data_a", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        let scr2 = scs.store("data_b", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        assert_ne!(scr1, scr2);
    }

    #[test]
    fn test_scr_same_content_different_scr() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience: Vec<String> = vec![];

        let scr1 = scs.store("same_data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        let scr2 = scs.store("same_data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        // Different salt each time → different SCR
        assert_ne!(scr1, scr2);
    }

    #[test]
    fn test_scr_evict_expired() {
        let scs = SecureContextStore::new();
        let key = test_master_key();
        let audience: Vec<String> = vec![];

        scs.store("data", "agent-a", &audience, 300.0, &key, "INTERNAL").unwrap();
        assert_eq!(scs.count(), 1);
        assert_eq!(scs.evict_expired(), 0);
    }

    #[test]
    fn test_scr_short_master_key_rejected() {
        let scs = SecureContextStore::new();
        let short_key = vec![0u8; 16];
        let audience: Vec<String> = vec![];
        assert!(scs.store("data", "a", &audience, 300.0, &short_key, "INTERNAL").is_err());
    }
}
