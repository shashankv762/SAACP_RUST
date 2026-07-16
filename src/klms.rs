//! klms.rs — Key Lifecycle Management System (KLMS) for SAACP
//!
//! Provides the full lifecycle of cryptographic keys used throughout the
//! SAACP protocol:
//!   * Key registration and versioned storage (KeyRegistry)
//!   * Policy-driven rotation and overlap periods (KeyLifecycleManager)
//!   * Revocation, emergency revocation, and propagation to federation peers
//!   * Audit trail per key identifier

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ---------------------------------------------------------------------------
// Enumerations
// ---------------------------------------------------------------------------

/// Lifecycle state of a KeyDescriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyStatus {
    /// The key is the current, valid material for its key-id.
    Active,
    /// The key has been superseded by a newer version (may still be in overlap window).
    Rotated,
    /// The key has been administratively revoked and MUST NOT be used.
    Revoked,
    /// The key material is believed to have been leaked; treat as revoked.
    Compromised,
}

impl KeyStatus {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Active => "ACTIVE",
            Self::Rotated => "ROTATED",
            Self::Revoked => "REVOKED",
            Self::Compromised => "COMPROMISED",
        }
    }
}

/// Cryptographic algorithm family associated with a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyAlgorithm {
    /// 256-bit AES in Galois/Counter Mode — authenticated encryption.
    Aes256Gcm,
    /// Edwards-curve Digital Signature Algorithm over Curve25519.
    Ed25519,
    /// Hash-based Message Authentication Code using SHA-256.
    HmacSha256,
    /// HMAC-based Key Derivation Function using SHA-256 (key material only).
    HkdfSha256,
}

impl KeyAlgorithm {
    pub fn value(&self) -> &'static str {
        match self {
            Self::Aes256Gcm => "AES-256-GCM",
            Self::Ed25519 => "Ed25519",
            Self::HmacSha256 => "HMAC-SHA-256",
            Self::HkdfSha256 => "HKDF-SHA-256",
        }
    }

    /// L-4 fix: the exact key-material length this algorithm requires, in bytes. Single
    /// source of truth shared by [`KeyDescriptor::new`]'s validation and
    /// [`default_key_generator`], so the two can never silently drift out of sync with
    /// each other.
    pub fn key_len(&self) -> usize {
        match self {
            Self::Aes256Gcm => 32,
            Self::Ed25519 => 32,
            Self::HmacSha256 => 32,
            Self::HkdfSha256 => 32,
        }
    }
}

/// Semantic role of a key within the SAACP security architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCategory {
    /// Pre-Shared Key — established out-of-band between two parties.
    Psk,
    /// Agent or service identity key (typically Ed25519 signing key).
    Identity,
    /// Key used to sign SAACP capability tokens (RRBC / FAITF).
    TokenSigning,
    /// Key used to encrypt/decrypt entries in the shared memory subsystem.
    MemoryProtection,
    /// Root-of-trust key whose public component is distributed out-of-band.
    TrustAnchor,
    /// Ephemeral key derived during delegated authentication exchanges.
    DelegatedAuth,
    /// Per-epoch traffic encryption key for MEASC-protected channels.
    EpochTraffic,
}

impl KeyCategory {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Psk => "PSK",
            Self::Identity => "IDENTITY",
            Self::TokenSigning => "TOKEN_SIGNING",
            Self::MemoryProtection => "MEMORY_PROTECTION",
            Self::TrustAnchor => "TRUST_ANCHOR",
            Self::DelegatedAuth => "DELEGATED_AUTH",
            Self::EpochTraffic => "EPOCH_TRAFFIC",
        }
    }

    pub fn tag(&self) -> &'static str {
        match self {
            Self::Psk => "psk",
            Self::Identity => "identity",
            Self::TokenSigning => "token_signing",
            Self::MemoryProtection => "memory_protection",
            Self::TrustAnchor => "trust_anchor",
            Self::DelegatedAuth => "delegated_auth",
            Self::EpochTraffic => "epoch_traffic",
        }
    }
}

// ---------------------------------------------------------------------------
// Data structures
// ---------------------------------------------------------------------------

/// Full descriptor for a single version of a managed cryptographic key.
///
/// SECURITY FIX (FINDING-2): `key_material` is wiped on drop, matching the
/// pattern already used by `KeyEvolutionEngine`/`SessionMeta` in measc.rs.
///
/// SECURITY FIX (H-11): `key_material` is `Arc<Zeroizing<Vec<u8>>>` rather
/// than a bare `Vec<u8>`. `KeyDescriptor` is cloned by `KeyRegistry`/
/// `KeyLifecycleManager` on every read (`get_active`, `get_version`,
/// `all_for_kid`, `rotate_key`); with a bare `Vec<u8>` each such clone was a
/// full byte-for-byte copy of the raw secret key onto the heap, so a single
/// "read the active key" call could leave 2+ simultaneous unprotected
/// plaintext copies of the same key material alive in process memory at
/// once. Wrapping it in `Arc` makes `.clone()` a refcount bump instead of a
/// copy: there is exactly one heap allocation of any given key version's
/// bytes, shared by reference across every live `KeyDescriptor` clone, and
/// it is zeroized exactly once — via `Zeroizing<Vec<u8>>`'s own unconditional
/// `Drop` impl — at the moment the last referencing `Arc` is dropped. Because
/// `Arc<T>` does not itself implement `Zeroize`, `key_material` is marked
/// `#[zeroize(skip)]` here; that's not a gap, zeroization is guaranteed by
/// the `Zeroizing` wrapper regardless of this struct's own derive.
#[derive(Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct KeyDescriptor {
    /// Key identifier — a 32-character hexadecimal UUID4 string (no hyphens).
    #[zeroize(skip)]
    pub kid: String,
    /// Monotonically increasing integer; version 1 is the first registered version.
    #[zeroize(skip)]
    pub version: u64,
    /// The KeyAlgorithm this key material is intended for.
    #[zeroize(skip)]
    pub algorithm: KeyAlgorithm,
    /// The KeyCategory denoting the key's role in SAACP.
    #[zeroize(skip)]
    pub category: KeyCategory,
    /// Raw key bytes, shared by reference across clones (see H-11 note above).
    #[zeroize(skip)]
    pub key_material: Arc<Zeroizing<Vec<u8>>>,
    /// Unix epoch timestamp (seconds) at which this descriptor was created.
    #[zeroize(skip)]
    pub created_at: f64,
    /// Unix epoch timestamp (seconds) after which the key SHOULD be rotated.
    #[zeroize(skip)]
    pub expires_at: f64,
    /// Unix epoch timestamp at which rotate_key was called, or None if not yet rotated.
    #[zeroize(skip)]
    pub rotated_at: Option<f64>,
    /// Current KeyStatus of this key version.
    #[zeroize(skip)]
    pub status: KeyStatus,
    /// Arbitrary key-value pairs for audit or application-level annotation.
    #[zeroize(skip)]
    pub metadata: HashMap<String, String>,
}

impl KeyDescriptor {
    /// Create a new KeyDescriptor with validation.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        kid: String,
        version: u64,
        algorithm: KeyAlgorithm,
        category: KeyCategory,
        key_material: Vec<u8>,
        created_at: f64,
        expires_at: f64,
        rotated_at: Option<f64>,
        status: KeyStatus,
        metadata: HashMap<String, String>,
    ) -> Result<Self, String> {
        if kid.len() != 32 || !kid.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)) {
            return Err(format!(
                "kid must be a 32-character lowercase hex string; got {:?}",
                kid
            ));
        }
        if version < 1 {
            return Err(format!("version must be >= 1; got {}", version));
        }
        if expires_at <= created_at {
            return Err("expires_at must be strictly after created_at".into());
        }
        // L-4 fix: reject key material whose length doesn't match what `algorithm`
        // requires — previously any length was silently accepted, so a truncated or
        // malformed key (e.g. a 16-byte value where AES-256-GCM needs 32) would only
        // surface as a confusing failure much later, at first actual use.
        let expected_len = algorithm.key_len();
        if key_material.len() != expected_len {
            return Err(format!(
                "key_material length {} does not match {} bytes required by {}",
                key_material.len(),
                expected_len,
                algorithm.value()
            ));
        }
        Ok(Self {
            kid,
            version,
            algorithm,
            category,
            key_material: Arc::new(Zeroizing::new(key_material)),
            created_at,
            expires_at,
            rotated_at,
            status,
            metadata,
        })
    }
}

/// Policy governing automated key rotation behaviour.
#[derive(Debug, Clone)]
pub struct KeyRotationPolicy {
    /// Maximum age of an ACTIVE key before it should be rotated. Default: 86400s (24h).
    pub max_age_seconds: f64,
    /// Duration for which the old key version remains usable after rotation. Default: 3600s (1h).
    pub overlap_seconds: f64,
    /// When true, the manager may rotate keys automatically.
    pub auto_rotate: bool,
    /// Propagation deadline (seconds) for emergency revocations. 0.0 = immediate.
    pub emergency_revocation_ttl: f64,
    /// Pre-expiry renewal window (seconds): a key becomes eligible for automatic rotation
    /// once `expires_at - now <= renewal_lead_seconds`, i.e. rotation happens ahead of
    /// expiry rather than exactly at it. Defaults to 10% of `max_age_seconds` (a 24h-TTL
    /// key rotates ~2.4h before expiry) via [`Self::default`].
    pub renewal_lead_seconds: f64,
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        let max_age_seconds = 86_400.0;
        Self {
            max_age_seconds,
            overlap_seconds: 3_600.0,
            auto_rotate: true,
            emergency_revocation_ttl: 0.0,
            renewal_lead_seconds: max_age_seconds * 0.1,
        }
    }
}

/// Immutable audit record for a single key revocation event.
#[derive(Debug, Clone)]
pub struct KeyRevocationRecord {
    /// Key identifier of the revoked key.
    pub kid: String,
    /// Version of the revoked key (-1 as i64 means all versions).
    pub version: i64,
    /// Unix epoch timestamp at which revocation was recorded.
    pub revoked_at: f64,
    /// Human-readable reason code: 'expired', 'compromised', 'superseded', 'emergency'.
    pub reason: String,
    /// True once propagate_revocations has delivered this record to all federation peers.
    pub propagated: bool,
}

/// Audit trail entry for a key version.
#[derive(Debug, Clone)]
pub struct KeyAuditEntry {
    pub kid: String,
    pub version: u64,
    pub status: String,
    pub created_at: f64,
    pub expires_at: f64,
    pub rotated_at: Option<f64>,
    pub category: String,
    pub algorithm: String,
}

// ---------------------------------------------------------------------------
// KeyRegistry
// ---------------------------------------------------------------------------

/// Thread-safe store for all KeyDescriptor versions.
///
/// The registry is keyed internally by (kid, version) tuples.
pub struct KeyRegistry {
    registry: Mutex<HashMap<(String, u64), KeyDescriptor>>,
}

impl KeyRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            registry: Mutex::new(HashMap::new()),
        }
    }

    /// Register a KeyDescriptor in the store.
    ///
    /// Returns Err if a descriptor with the same (kid, version) already exists.
    ///
    /// M-38 fix: every `self.registry.lock()` in this impl block recovers via
    /// `into_inner()` on poison rather than panicking — `klms::DEFAULT_REGISTRY`
    /// is a process-wide singleton, so one poisoning panic must not cascade
    /// into every other caller losing the ability to look up/rotate keys.
    pub fn register(&self, descriptor: KeyDescriptor) -> Result<(), String> {
        let key = (descriptor.kid.clone(), descriptor.version);
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        if reg.contains_key(&key) {
            return Err(format!(
                "Key (kid={:?}, version={}) is already registered. Use rotate_key to create a new version.",
                descriptor.kid, descriptor.version
            ));
        }
        reg.insert(key, descriptor);
        Ok(())
    }

    /// Return the highest-version ACTIVE descriptor for kid.
    ///
    /// Returns SAACPHardDrop with KEY_REVOKED if all versions are revoked/compromised.
    pub fn get_active(&self, kid: &str) -> Result<KeyDescriptor, SAACPHardDrop> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let versions: Vec<&KeyDescriptor> = reg
            .iter()
            .filter(|((k, _), _)| k == kid)
            .map(|(_, desc)| desc)
            .collect();

        if versions.is_empty() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::KeyRevoked,
                format!("Unknown kid: {:?}", kid),
            ));
        }

        let active: Vec<&KeyDescriptor> = versions
            .iter()
            .filter(|d| d.status == KeyStatus::Active)
            .copied()
            .collect();

        if active.is_empty() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::KeyRevoked,
                format!("All versions of kid={:?} are REVOKED or COMPROMISED", kid),
            ));
        }

        // Return the highest version
        let best = active.iter().max_by_key(|d| d.version).unwrap();
        Ok((*best).clone())
    }

    /// Return the exact (kid, version) descriptor.
    pub fn get_version(&self, kid: &str, version: u64) -> Result<KeyDescriptor, String> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let key = (kid.to_string(), version);
        reg.get(&key)
            .cloned()
            .ok_or_else(|| format!("No descriptor for (kid={:?}, version={})", kid, version))
    }

    /// Return a deduplicated sorted list of key ids with at least one ACTIVE version.
    pub fn list_active_kids(&self) -> Vec<String> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let mut kids: Vec<String> = reg
            .iter()
            .filter(|(_, desc)| desc.status == KeyStatus::Active)
            .map(|((kid, _), _)| kid.clone())
            .collect();
        kids.sort();
        kids.dedup();
        kids
    }

    /// Return all descriptors for kid, sorted by version ascending.
    pub fn all_for_kid(&self, kid: &str) -> Vec<KeyDescriptor> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let mut descriptors: Vec<KeyDescriptor> = reg
            .iter()
            .filter(|((k, _), _)| k == kid)
            .map(|(_, desc)| desc.clone())
            .collect();
        descriptors.sort_by_key(|d| d.version);
        descriptors
    }

    /// Return `(kid, version)` pairs for every `Active` descriptor whose
    /// `expires_at - now <= within_seconds` — a "pre-expiry renewal window" query used by
    /// [`KeyLifecycleManager::sweep_and_rotate`] (Phase 5, item 4: automatic key rotation).
    /// Only `Active` descriptors are ever considered (never `Rotated`/`Revoked`/
    /// `Compromised`) — Monotonic Security: automatic rotation must never touch a key that
    /// isn't currently the live version.
    pub fn list_expiring(&self, within_seconds: f64, now: f64) -> Vec<(String, u64)> {
        let reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        reg.iter()
            .filter(|(_, desc)| {
                desc.status == KeyStatus::Active && desc.expires_at - now <= within_seconds
            })
            .map(|((kid, version), _)| (kid.clone(), *version))
            .collect()
    }

    /// Internal: update a descriptor's status and rotated_at in-place.
    fn update_status(&self, kid: &str, version: u64, status: KeyStatus, rotated_at: Option<f64>) {
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let key = (kid.to_string(), version);
        if let Some(desc) = reg.get_mut(&key) {
            desc.status = status;
            desc.rotated_at = rotated_at;
        }
    }

    /// Atomically rotate `kid`'s current ACTIVE version to a freshly-built next version,
    /// entirely under one lock acquisition.
    ///
    /// This exists to close a TOCTOU race that a naive "get_active, then update_status,
    /// then register" sequence (three separate lock acquisitions) leaves open: two
    /// concurrent callers can both read the same ACTIVE descriptor before either writes
    /// back, both compute the same `version + 1`, and — worse — a caller acting on a stale
    /// "this kid is due for rotation" snapshot can still successfully rotate a kid that a
    /// *different* concurrent caller already rotated moments earlier, since a plain
    /// `get_active` check only confirms *some* version is Active, not that it's still the
    /// specific version the caller believed was due. Holding the registry lock across the
    /// read-current, build-new, and write-both steps makes the whole operation atomic: at
    /// most one concurrent caller can ever observe and act on a given ACTIVE version.
    ///
    /// `build_new` receives the current ACTIVE descriptor (lock held) and must return its
    /// replacement; whatever `version` it sets is overwritten with `current.version + 1`
    /// before insertion, so a caller cannot target the wrong slot even by mistake.
    fn atomic_rotate<F>(
        &self,
        kid: &str,
        rotated_at: f64,
        build_new: F,
    ) -> Result<KeyDescriptor, KlmsRotateError>
    where
        F: FnOnce(&KeyDescriptor) -> Result<KeyDescriptor, String>,
    {
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());

        let current_version = reg
            .iter()
            .filter(|((k, _), d)| k == kid && d.status == KeyStatus::Active)
            .map(|((_, v), _)| *v)
            .max()
            .ok_or_else(|| KlmsRotateError::NoActiveVersion(format!("Unknown kid: {:?}", kid)))?;

        let current = reg
            .get(&(kid.to_string(), current_version))
            .expect("current_version was just derived from this same map")
            .clone();

        let mut new_descriptor = build_new(&current).map_err(KlmsRotateError::Invalid)?;
        new_descriptor.version = current_version + 1;

        let new_key = (kid.to_string(), new_descriptor.version);
        if reg.contains_key(&new_key) {
            return Err(KlmsRotateError::Conflict(format!(
                "Key (kid={:?}, version={}) is already registered. Use rotate_key to create a new version.",
                kid, new_descriptor.version
            )));
        }

        if let Some(desc) = reg.get_mut(&(kid.to_string(), current_version)) {
            desc.status = KeyStatus::Rotated;
            desc.rotated_at = Some(rotated_at);
        }
        reg.insert(new_key, new_descriptor.clone());
        Ok(new_descriptor)
    }

    /// Same single-lock atomicity as [`Self::atomic_rotate`], but conditional: rotates only
    /// if `kid`'s current ACTIVE version is still exactly `expected_version`, returning
    /// `Ok(None)` as a no-op otherwise.
    ///
    /// [`Self::atomic_rotate`] alone is not sufficient for
    /// [`KeyLifecycleManager::sweep_and_rotate`]'s concurrent use: it always rotates
    /// *whatever* is currently ACTIVE, so if two threads both believe (from their own
    /// `list_expiring` snapshot) that `kid` is due for rotation, the first thread's
    /// atomic_rotate call succeeds, and the second thread's call would then happily rotate
    /// the *first thread's brand-new, nowhere-near-expiry* replacement — silently
    /// double-rotating a key far ahead of schedule. Gating on `expected_version` means the
    /// second thread's call sees the active version has already moved past what it
    /// snapshotted as due and skips, exactly once per genuinely-due version.
    fn atomic_rotate_if_current<F>(
        &self,
        kid: &str,
        expected_version: u64,
        rotated_at: f64,
        build_new: F,
    ) -> Result<Option<KeyDescriptor>, KlmsRotateError>
    where
        F: FnOnce(&KeyDescriptor) -> Result<KeyDescriptor, String>,
    {
        let mut reg = self.registry.lock().unwrap_or_else(|e| e.into_inner());
        let key = (kid.to_string(), expected_version);

        let current = match reg.get(&key) {
            Some(d) if d.status == KeyStatus::Active => d.clone(),
            // Either never existed, or exists but is no longer Active (already rotated,
            // revoked, or expired by a concurrent caller) — both are a safe no-op, not an
            // error, since "someone else already handled this due key" is the expected
            // outcome of losing the race, not a failure.
            _ => return Ok(None),
        };

        let mut new_descriptor = build_new(&current).map_err(KlmsRotateError::Invalid)?;
        new_descriptor.version = current.version + 1;

        let new_key = (kid.to_string(), new_descriptor.version);
        if reg.contains_key(&new_key) {
            return Err(KlmsRotateError::Conflict(format!(
                "Key (kid={:?}, version={}) is already registered. Use rotate_key to create a new version.",
                kid, new_descriptor.version
            )));
        }

        if let Some(desc) = reg.get_mut(&key) {
            desc.status = KeyStatus::Rotated;
            desc.rotated_at = Some(rotated_at);
        }
        reg.insert(new_key, new_descriptor.clone());
        Ok(Some(new_descriptor))
    }
}

/// Error from [`KeyRegistry::atomic_rotate`] — kept distinct from a bare `String` so
/// [`KeyLifecycleManager::rotate_key`] can map each variant to the right
/// [`SAACPBytecodes`] instead of guessing from message text.
enum KlmsRotateError {
    /// `kid` has no ACTIVE version at all (already fully revoked/rotated away).
    NoActiveVersion(String),
    /// The computed next-version slot is already occupied (should be unreachable given the
    /// single-lock atomicity above, but kept as a defensive check rather than an `unwrap`).
    Conflict(String),
    /// `build_new` itself rejected the new descriptor (e.g. `KeyDescriptor::new` validation).
    Invalid(String),
}

impl KlmsRotateError {
    fn into_message(self) -> String {
        match self {
            Self::NoActiveVersion(m) | Self::Conflict(m) | Self::Invalid(m) => m,
        }
    }
}

impl Default for KeyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// KeyLifecycleManager
// ---------------------------------------------------------------------------

/// Orchestrates rotation, revocation, expiry, and audit of managed keys.
pub struct KeyLifecycleManager {
    registry: KeyRegistry,
    policy: KeyRotationPolicy,
    revocation_log: Mutex<Vec<KeyRevocationRecord>>,
}

impl KeyLifecycleManager {
    /// Create a new KeyLifecycleManager with the given registry and policy.
    pub fn new(registry: KeyRegistry, policy: Option<KeyRotationPolicy>) -> Self {
        Self {
            registry,
            policy: policy.unwrap_or_default(),
            revocation_log: Mutex::new(Vec::new()),
        }
    }

    /// Rotate an existing key, producing a new version.
    ///
    /// The old ACTIVE descriptor has its status changed to ROTATED and rotated_at stamped.
    /// A new descriptor with version+1 and status=ACTIVE is created and registered.
    pub fn rotate_key(
        &self,
        kid: &str,
        new_key_material: Vec<u8>,
        algorithm: KeyAlgorithm,
    ) -> Result<KeyDescriptor, SAACPHardDrop> {
        let now = now_epoch_secs();
        let policy = &self.policy;

        // Read-current, build-new, and write-both all happen under one lock inside
        // atomic_rotate — see its doc comment for the concurrent-rotation race this closes.
        let result = self.registry.atomic_rotate(kid, now, move |current| {
            let mut metadata = HashMap::new();
            metadata.insert("rotated_from_version".into(), current.version.to_string());
            metadata.insert("overlap_expires_at".into(), (now + policy.overlap_seconds).to_string());

            KeyDescriptor::new(
                kid.to_string(),
                current.version + 1,
                algorithm,
                current.category,
                new_key_material,
                now,
                now + policy.max_age_seconds,
                None,
                KeyStatus::Active,
                metadata,
            )
        });

        let new_descriptor = match result {
            Ok(desc) => desc,
            Err(e @ KlmsRotateError::NoActiveVersion(_)) => {
                return Err(SAACPHardDrop::new(SAACPBytecodes::KeyRevoked, e.into_message()));
            }
            Err(e) => {
                return Err(SAACPHardDrop::new(SAACPBytecodes::KeyVersionMismatch, e.into_message()));
            }
        };

        crate::telemetry::global_telemetry().record_key_rotation();

        Ok(new_descriptor)
    }

    /// Revoke ALL versions of a key immediately.
    ///
    /// If reason is "compromised", status is set to Compromised; otherwise Revoked.
    pub fn revoke_key(
        &self,
        kid: &str,
        reason: &str,
    ) -> Result<KeyRevocationRecord, String> {
        let now = now_epoch_secs();
        let new_status = if reason == "compromised" {
            KeyStatus::Compromised
        } else {
            KeyStatus::Revoked
        };

        let all_versions = self.registry.all_for_kid(kid);
        if all_versions.is_empty() {
            return Err(format!("Cannot revoke unknown kid: {:?}", kid));
        }

        for desc in &all_versions {
            self.registry
                .update_status(kid, desc.version, new_status, None);
        }

        let record = KeyRevocationRecord {
            kid: kid.to_string(),
            version: -1, // -1 signals "all versions"
            revoked_at: now,
            reason: reason.to_string(),
            propagated: false,
        };

        self.revocation_log.lock().unwrap_or_else(|e| e.into_inner()).push(record.clone());
        Ok(record)
    }

    /// Mark ACTIVE keys that have passed their expires_at as ROTATED.
    ///
    /// This is a soft expiry — the key status becomes ROTATED (not REVOKED).
    /// Returns the number of key versions transitioned to ROTATED.
    pub fn expire_stale_keys(&self, now: Option<f64>) -> usize {
        let now = now.unwrap_or_else(now_epoch_secs);
        let mut count = 0;

        // Get all registered keys via the registry's internal map. Matches the
        // M-38 idiom already used by every other `self.registry.lock()` call
        // in `KeyRegistry`'s own impl block (see its doc comment): this is the
        // same process-wide-singleton-backing Mutex, so recovering on poison
        // here keeps this direct field access consistent with its siblings.
        let reg = self.registry.registry.lock().unwrap_or_else(|e| e.into_inner());
        let stale: Vec<(String, u64)> = reg
            .iter()
            .filter(|(_, desc)| desc.status == KeyStatus::Active && desc.expires_at < now)
            .map(|((kid, ver), _)| (kid.clone(), *ver))
            .collect();
        drop(reg);

        for (kid, ver) in stale {
            self.registry
                .update_status(&kid, ver, KeyStatus::Rotated, Some(now));
            count += 1;
        }

        count
    }

    /// Automatically rotate every key within its pre-expiry renewal window (Phase 5, item
    /// 4: automatic key rotation). A no-op if `self.policy.auto_rotate` is `false`.
    ///
    /// `generate_key` supplies fresh CSPRNG key material per algorithm — `klms.rs` itself
    /// never hard-codes or duplicates an RNG choice for every [`KeyAlgorithm`] variant; see
    /// [`default_key_generator`] for a sane default. Returns the `kid`s that were
    /// successfully rotated (a `kid` whose current version has since become non-`Active`,
    /// e.g. concurrently revoked, is silently skipped rather than erroring — Monotonic
    /// Security: automatic rotation must never resurrect a `Revoked`/`Compromised` key, and
    /// [`KeyRegistry::get_active`] — which only [`KeyRegistry::list_expiring`] feeds —
    /// already filters to `Active`, so a skip here means the key changed state between the
    /// `list_expiring` snapshot and this call, not that rotation logic is unsound).
    pub fn sweep_and_rotate<F>(&self, now: f64, generate_key: F) -> Vec<String>
    where
        F: Fn(KeyAlgorithm) -> Vec<u8>,
    {
        if !self.policy.auto_rotate {
            return Vec::new();
        }

        let due = self.registry.list_expiring(self.policy.renewal_lead_seconds, now);
        let mut rotated = Vec::new();
        for (kid, version) in due {
            // `version` is the exact snapshotted descriptor `list_expiring` found due —
            // versions are retained (never deleted) on rotation, so `get_version` still
            // resolves it even if a concurrent sweep already rotated `kid` past it.
            let algorithm = match self.registry.get_version(&kid, version) {
                Ok(desc) => desc.algorithm,
                Err(_) => continue,
            };
            let policy = &self.policy;
            // `atomic_rotate_if_current` only performs the rotation if `version` is still
            // the live ACTIVE version at the moment the lock is acquired — see its doc
            // comment for the concurrent double-rotation race this closes. A concurrent
            // sweep that already rotated `kid` past `version` makes this call a safe no-op
            // (`Ok(None)`) rather than a second, spurious rotation.
            let result = self.registry.atomic_rotate_if_current(&kid, version, now, |current| {
                let mut metadata = HashMap::new();
                metadata.insert("rotated_from_version".into(), current.version.to_string());
                metadata.insert(
                    "overlap_expires_at".into(),
                    (now + policy.overlap_seconds).to_string(),
                );
                KeyDescriptor::new(
                    kid.clone(),
                    current.version + 1,
                    algorithm,
                    current.category,
                    generate_key(algorithm),
                    now,
                    now + policy.max_age_seconds,
                    None,
                    KeyStatus::Active,
                    metadata,
                )
            });
            if matches!(result, Ok(Some(_))) {
                rotated.push(kid);
            }
        }
        rotated
    }

    /// Spawn a background OS thread (matching `security.rs`'s WAL-worker idiom, and the
    /// Phase-7 "background maintenance sweep" 60s cadence used elsewhere) that calls
    /// [`Self::sweep_and_rotate`] every 60 seconds using `generate_key` for fresh key
    /// material. Returns the thread's `JoinHandle` — the thread runs for the lifetime of
    /// the process (or until the handle is dropped and the process exits); there is no
    /// explicit stop signal since `KeyLifecycleManager` instances are expected to live for
    /// the daemon's lifetime, matching `TrustDecayEngine`/other global background workers.
    pub fn start_auto_rotation(
        self: std::sync::Arc<Self>,
        generate_key: impl Fn(KeyAlgorithm) -> Vec<u8> + Send + Sync + 'static,
    ) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("klms-auto-rotation".to_string())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                let now = now_epoch_secs();
                self.sweep_and_rotate(now, &generate_key);
            })
            .expect("failed to spawn klms-auto-rotation thread")
    }

    /// Return an ordered audit trail for all versions of kid.
    pub fn audit_key_lifecycle(&self, kid: &str) -> Vec<KeyAuditEntry> {
        let all_versions = self.registry.all_for_kid(kid);
        all_versions
            .iter()
            .map(|desc| KeyAuditEntry {
                kid: desc.kid.clone(),
                version: desc.version,
                status: desc.status.name().into(),
                created_at: desc.created_at,
                expires_at: desc.expires_at,
                rotated_at: desc.rotated_at,
                category: desc.category.name().into(),
                algorithm: desc.algorithm.value().into(),
            })
            .collect()
    }

    /// Return a copy of the internal revocation log.
    pub fn get_revocation_log(&self) -> Vec<KeyRevocationRecord> {
        self.revocation_log.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Propagate all un-propagated revocation records to federation peers.
    ///
    /// The optional callback receives each un-propagated record.
    /// Returns the number of records newly marked as propagated.
    pub fn propagate_revocations<F>(&self, mut federation_callback: Option<F>) -> usize
    where
        F: FnMut(&KeyRevocationRecord),
    {
        let unpropagated: Vec<usize> = {
            let log = self.revocation_log.lock().unwrap_or_else(|e| e.into_inner());
            log.iter()
                .enumerate()
                .filter(|(_, r)| !r.propagated)
                .map(|(i, _)| i)
                .collect()
        };

        let mut count = 0;
        for idx in unpropagated {
            let record = {
                let log = self.revocation_log.lock().unwrap_or_else(|e| e.into_inner());
                log[idx].clone()
            };

            if let Some(ref mut cb) = federation_callback {
                // Call outside the lock to avoid deadlock
                cb(&record);
            }

            let mut log = self.revocation_log.lock().unwrap_or_else(|e| e.into_inner());
            log[idx].propagated = true;
            count += 1;
        }

        count
    }
}

// ---------------------------------------------------------------------------
// Convenience helpers
// ---------------------------------------------------------------------------

/// Generate a fresh 32-character lowercase hex key identifier (UUID4).
pub fn make_kid() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

/// Construct a new KeyDescriptor with sensible defaults.
pub fn make_descriptor(
    kid: &str,
    algorithm: KeyAlgorithm,
    category: KeyCategory,
    key_material: Vec<u8>,
    max_age_seconds: Option<f64>,
    version: Option<u64>,
    metadata: Option<HashMap<String, String>>,
) -> Result<KeyDescriptor, String> {
    let now = now_epoch_secs();
    let max_age = max_age_seconds.unwrap_or(86_400.0);
    KeyDescriptor::new(
        kid.to_string(),
        version.unwrap_or(1),
        algorithm,
        category,
        key_material,
        now,
        now + max_age,
        None,
        KeyStatus::Active,
        metadata.unwrap_or_default(),
    )
}

/// Current wall-clock time as seconds since UNIX epoch.
fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Sane default CSPRNG-backed key-material generator for
/// [`KeyLifecycleManager::sweep_and_rotate`]/[`KeyLifecycleManager::start_auto_rotation`],
/// using `rand::rngs::OsRng` (already available via `ed25519-dalek`'s `rand_core` feature /
/// the plain `rand = "0.8"` dependency). Sized correctly per algorithm — 32 bytes
/// (256 bits) for every current [`KeyAlgorithm`] variant (AES-256-GCM, Ed25519,
/// HMAC-SHA-256, HKDF-SHA-256). Most deployments can pass this directly and need zero
/// extra wiring; a deployment with its own HSM-backed key generation should supply its own
/// `generate_key` closure instead.
pub fn default_key_generator(alg: KeyAlgorithm) -> Vec<u8> {
    use rand::RngCore;
    let mut buf = vec![0u8; alg.key_len()];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    buf
}

// ---------------------------------------------------------------------------
// Module-level defaults
// ---------------------------------------------------------------------------

/// Default KeyRotationPolicy used when no policy is explicitly supplied.
pub fn default_policy() -> KeyRotationPolicy {
    KeyRotationPolicy::default()
}

/// Process-wide default [`KeyRegistry`] singleton.
/// Matches Python's `DEFAULT_REGISTRY as KLMS_DEFAULT_REGISTRY` export.
pub static DEFAULT_REGISTRY: std::sync::LazyLock<KeyRegistry> =
    std::sync::LazyLock::new(KeyRegistry::new);

/// Process-wide default [`KeyRotationPolicy`] singleton.
/// Matches Python's `DEFAULT_POLICY as KLMS_DEFAULT_POLICY` export.
pub static DEFAULT_POLICY: std::sync::LazyLock<KeyRotationPolicy> =
    std::sync::LazyLock::new(KeyRotationPolicy::default);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_kid() -> String {
        "a".repeat(32)
    }

    fn test_descriptor(kid: &str) -> KeyDescriptor {
        make_descriptor(
            kid,
            KeyAlgorithm::Aes256Gcm,
            KeyCategory::Psk,
            vec![0u8; 32],
            Some(86_400.0),
            Some(1),
            None,
        )
        .unwrap()
    }

    #[test]
    fn test_kid_validation() {
        // Valid
        let kid = "0123456789abcdef0123456789abcdef";
        assert!(make_descriptor(kid, KeyAlgorithm::Aes256Gcm, KeyCategory::Psk, vec![0; 32], None, None, None).is_ok());

        // Invalid: uppercase
        let bad_kid = "A".repeat(32);
        assert!(make_descriptor(&bad_kid, KeyAlgorithm::Aes256Gcm, KeyCategory::Psk, vec![0; 32], None, None, None).is_err());

        // Invalid: wrong length
        assert!(make_descriptor("abc", KeyAlgorithm::Aes256Gcm, KeyCategory::Psk, vec![0; 32], None, None, None).is_err());
    }

    #[test]
    fn test_registry_register_and_get() {
        let reg = KeyRegistry::new();
        let desc = test_descriptor(&test_kid());
        reg.register(desc).unwrap();

        let active = reg.get_active(&test_kid()).unwrap();
        assert_eq!(active.version, 1);
        assert_eq!(active.status, KeyStatus::Active);
    }

    /// H-11 regression: `KeyDescriptor::clone()` must share the underlying
    /// key material allocation (an `Arc` refcount bump) rather than
    /// deep-copying the raw secret bytes onto the heap a second time.
    #[test]
    fn test_key_descriptor_clone_shares_key_material_allocation() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        reg.register(test_descriptor(&kid)).unwrap();

        let first = reg.get_active(&kid).unwrap();
        let second = reg.get_active(&kid).unwrap();

        assert!(
            Arc::ptr_eq(&first.key_material, &second.key_material),
            "two independent reads of the same key version must share one \
             key_material allocation, not duplicate it"
        );
        assert!(Arc::strong_count(&first.key_material) >= 2);

        let cloned = first.clone();
        assert!(Arc::ptr_eq(&first.key_material, &cloned.key_material));
    }

    #[test]
    fn test_registry_duplicate_rejected() {
        let reg = KeyRegistry::new();
        let desc = test_descriptor(&test_kid());
        reg.register(desc.clone()).unwrap();
        assert!(reg.register(desc).is_err());
    }

    #[test]
    fn test_registry_unknown_kid() {
        let reg = KeyRegistry::new();
        assert!(reg.get_active("0".repeat(32).as_str()).is_err());
    }

    #[test]
    fn test_registry_list_active_kids() {
        let reg = KeyRegistry::new();
        let kid1 = "a".repeat(32);
        let kid2 = "b".repeat(32);
        reg.register(test_descriptor(&kid1)).unwrap();
        reg.register(test_descriptor(&kid2)).unwrap();
        let kids = reg.list_active_kids();
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&kid1));
        assert!(kids.contains(&kid2));
    }

    #[test]
    fn test_lifecycle_rotate_key() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        reg.register(test_descriptor(&kid)).unwrap();

        let mgr = KeyLifecycleManager::new(reg, None);
        let new_desc = mgr.rotate_key(&kid, vec![1u8; 32], KeyAlgorithm::Aes256Gcm).unwrap();
        assert_eq!(new_desc.version, 2);
        assert_eq!(new_desc.status, KeyStatus::Active);
    }

    #[test]
    fn test_lifecycle_revoke_key() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        reg.register(test_descriptor(&kid)).unwrap();

        let mgr = KeyLifecycleManager::new(reg, None);
        let record = mgr.revoke_key(&kid, "compromised").unwrap();
        assert_eq!(record.reason, "compromised");
        assert_eq!(record.version, -1);

        // All versions should now be compromised
        let versions = mgr.registry.all_for_kid(&kid);
        assert!(versions.iter().all(|d| d.status == KeyStatus::Compromised));
    }

    #[test]
    fn test_lifecycle_expire_stale_keys() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        let now = now_epoch_secs();
        // Create a key that's already expired
        let desc = KeyDescriptor::new(
            kid.clone(),
            1,
            KeyAlgorithm::Aes256Gcm,
            KeyCategory::Psk,
            vec![0u8; 32],
            now - 200_000.0,
            now - 100_000.0,
            None,
            KeyStatus::Active,
            HashMap::new(),
        )
        .unwrap();
        reg.register(desc).unwrap();

        let mgr = KeyLifecycleManager::new(reg, None);
        let count = mgr.expire_stale_keys(None);
        assert_eq!(count, 1);
    }

    #[test]
    fn test_lifecycle_audit() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        reg.register(test_descriptor(&kid)).unwrap();

        let mgr = KeyLifecycleManager::new(reg, None);
        let audit = mgr.audit_key_lifecycle(&kid);
        assert_eq!(audit.len(), 1);
        assert_eq!(audit[0].status, "ACTIVE");
    }

    #[test]
    fn test_lifecycle_propagate_revocations() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        reg.register(test_descriptor(&kid)).unwrap();

        let mgr = KeyLifecycleManager::new(reg, None);
        mgr.revoke_key(&kid, "expired").unwrap();

        let mut propagated = Vec::new();
        let count = mgr.propagate_revocations(Some(|r: &KeyRevocationRecord| {
            propagated.push(r.kid.clone());
        }));
        assert_eq!(count, 1);
        assert_eq!(propagated.len(), 1);
    }

    #[test]
    fn test_make_kid() {
        let kid = make_kid();
        assert_eq!(kid.len(), 32);
        assert!(kid.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_key_status_names() {
        assert_eq!(KeyStatus::Active.name(), "ACTIVE");
        assert_eq!(KeyStatus::Rotated.name(), "ROTATED");
        assert_eq!(KeyStatus::Revoked.name(), "REVOKED");
        assert_eq!(KeyStatus::Compromised.name(), "COMPROMISED");
    }

    #[test]
    fn test_key_algorithm_values() {
        assert_eq!(KeyAlgorithm::Aes256Gcm.value(), "AES-256-GCM");
        assert_eq!(KeyAlgorithm::Ed25519.value(), "Ed25519");
        assert_eq!(KeyAlgorithm::HmacSha256.value(), "HMAC-SHA-256");
        assert_eq!(KeyAlgorithm::HkdfSha256.value(), "HKDF-SHA-256");
    }

    #[test]
    fn test_revocation_log() {
        let reg = KeyRegistry::new();
        let kid = test_kid();
        reg.register(test_descriptor(&kid)).unwrap();

        let mgr = KeyLifecycleManager::new(reg, None);
        assert_eq!(mgr.get_revocation_log().len(), 0);

        mgr.revoke_key(&kid, "superseded").unwrap();
        assert_eq!(mgr.get_revocation_log().len(), 1);
    }
}
