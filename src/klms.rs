//! klms.rs — Key Lifecycle Management System (KLMS) for SAACP
//!
//! Provides the full lifecycle of cryptographic keys used throughout the
//! SAACP protocol:
//!   * Key registration and versioned storage (KeyRegistry)
//!   * Policy-driven rotation and overlap periods (KeyLifecycleManager)
//!   * Revocation, emergency revocation, and propagation to federation peers
//!   * Audit trail per key identifier

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

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
#[derive(Debug, Clone)]
pub struct KeyDescriptor {
    /// Key identifier — a 32-character hexadecimal UUID4 string (no hyphens).
    pub kid: String,
    /// Monotonically increasing integer; version 1 is the first registered version.
    pub version: u64,
    /// The KeyAlgorithm this key material is intended for.
    pub algorithm: KeyAlgorithm,
    /// The KeyCategory denoting the key's role in SAACP.
    pub category: KeyCategory,
    /// Raw key bytes.
    pub key_material: Vec<u8>,
    /// Unix epoch timestamp (seconds) at which this descriptor was created.
    pub created_at: f64,
    /// Unix epoch timestamp (seconds) after which the key SHOULD be rotated.
    pub expires_at: f64,
    /// Unix epoch timestamp at which rotate_key was called, or None if not yet rotated.
    pub rotated_at: Option<f64>,
    /// Current KeyStatus of this key version.
    pub status: KeyStatus,
    /// Arbitrary key-value pairs for audit or application-level annotation.
    pub metadata: HashMap<String, String>,
}

impl KeyDescriptor {
    /// Create a new KeyDescriptor with validation.
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
        Ok(Self {
            kid,
            version,
            algorithm,
            category,
            key_material,
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
}

impl Default for KeyRotationPolicy {
    fn default() -> Self {
        Self {
            max_age_seconds: 86_400.0,
            overlap_seconds: 3_600.0,
            auto_rotate: true,
            emergency_revocation_ttl: 0.0,
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
    pub fn register(&self, descriptor: KeyDescriptor) -> Result<(), String> {
        let key = (descriptor.kid.clone(), descriptor.version);
        let mut reg = self.registry.lock().unwrap();
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
        let reg = self.registry.lock().unwrap();
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
        let reg = self.registry.lock().unwrap();
        let key = (kid.to_string(), version);
        reg.get(&key)
            .cloned()
            .ok_or_else(|| format!("No descriptor for (kid={:?}, version={})", kid, version))
    }

    /// Return a deduplicated sorted list of key ids with at least one ACTIVE version.
    pub fn list_active_kids(&self) -> Vec<String> {
        let reg = self.registry.lock().unwrap();
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
        let reg = self.registry.lock().unwrap();
        let mut descriptors: Vec<KeyDescriptor> = reg
            .iter()
            .filter(|((k, _), _)| k == kid)
            .map(|(_, desc)| desc.clone())
            .collect();
        descriptors.sort_by_key(|d| d.version);
        descriptors
    }

    /// Internal: update a descriptor's status and rotated_at in-place.
    fn update_status(&self, kid: &str, version: u64, status: KeyStatus, rotated_at: Option<f64>) {
        let mut reg = self.registry.lock().unwrap();
        let key = (kid.to_string(), version);
        if let Some(desc) = reg.get_mut(&key) {
            desc.status = status;
            desc.rotated_at = rotated_at;
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

        // Fetch the current active descriptor (may raise SAACPHardDrop)
        let current = self.registry.get_active(kid)?;

        // Stamp the old descriptor as ROTATED
        self.registry.update_status(
            kid,
            current.version,
            KeyStatus::Rotated,
            Some(now),
        );

        // Build the new descriptor
        let mut metadata = HashMap::new();
        metadata.insert("rotated_from_version".into(), current.version.to_string());
        metadata.insert("overlap_expires_at".into(), (now + self.policy.overlap_seconds).to_string());

        let new_descriptor = KeyDescriptor::new(
            kid.to_string(),
            current.version + 1,
            algorithm,
            current.category,
            new_key_material,
            now,
            now + self.policy.max_age_seconds,
            None,
            KeyStatus::Active,
            metadata,
        )
        .map_err(|e| SAACPHardDrop::new(SAACPBytecodes::KeyVersionMismatch, e))?;

        self.registry
            .register(new_descriptor.clone())
            .map_err(|e| SAACPHardDrop::new(SAACPBytecodes::KeyVersionMismatch, e))?;

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

        self.revocation_log.lock().unwrap().push(record.clone());
        Ok(record)
    }

    /// Mark ACTIVE keys that have passed their expires_at as ROTATED.
    ///
    /// This is a soft expiry — the key status becomes ROTATED (not REVOKED).
    /// Returns the number of key versions transitioned to ROTATED.
    pub fn expire_stale_keys(&self, now: Option<f64>) -> usize {
        let now = now.unwrap_or_else(now_epoch_secs);
        let mut count = 0;

        // Get all registered keys via the registry's internal map
        let reg = self.registry.registry.lock().unwrap();
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
        self.revocation_log.lock().unwrap().clone()
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
            let log = self.revocation_log.lock().unwrap();
            log.iter()
                .enumerate()
                .filter(|(_, r)| !r.propagated)
                .map(|(i, _)| i)
                .collect()
        };

        let mut count = 0;
        for idx in unpropagated {
            let record = {
                let log = self.revocation_log.lock().unwrap();
                log[idx].clone()
            };

            if let Some(ref mut cb) = federation_callback {
                // Call outside the lock to avoid deadlock
                cb(&record);
            }

            let mut log = self.revocation_log.lock().unwrap();
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

// ---------------------------------------------------------------------------
// Module-level defaults
// ---------------------------------------------------------------------------

/// Default KeyRotationPolicy used when no policy is explicitly supplied.
pub fn default_policy() -> KeyRotationPolicy {
    KeyRotationPolicy::default()
}

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
