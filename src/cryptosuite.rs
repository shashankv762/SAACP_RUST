//! cryptosuite.rs — Cryptographic Agility Layer for SAACP ACSVAF
//!
//! Provides an algorithm-agnostic signing and verification interface.
//! Ed25519 is the mandatory default trust primitive (SAACP v6.0).

use ed25519_dalek::{SigningKey, VerifyingKey, Signer, Verifier};
use sha2::{Sha256, Digest};

use crate::crypto_governance::{
    CryptoLedgerEntry, CryptoTransparencyLedger, SuiteStatus,
    get_active_policy,
};

fn now_epoch_secs() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// CryptoSuite trait
// ---------------------------------------------------------------------------

/// Algorithm-agnostic signing / verification interface.
pub trait CryptoSuite: Send + Sync {
    /// Canonical algorithm name, e.g. "ed25519".
    fn algorithm(&self) -> &str;
    /// Fixed byte-length of a signature produced by this suite.
    fn signature_length(&self) -> usize;
    /// Fixed byte-length of a public key for this suite.
    fn public_key_length(&self) -> usize;
    /// Generate a new keypair. Returns (private_key_bytes, public_key_bytes).
    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>);
    /// Sign message with private key bytes. Returns raw signature bytes.
    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String>;
    /// Verify signature over message with public key bytes.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
    /// SHA-256 hex fingerprint of the public key bytes (64 chars).
    fn fingerprint(&self, public_key: &[u8]) -> String {
        sha256_hex(public_key)
    }
}

// ---------------------------------------------------------------------------
// Ed25519Suite
// ---------------------------------------------------------------------------

/// Ed25519 (RFC 8032) signing suite — the mandatory default for SAACP v6.0.
pub struct Ed25519Suite;

impl Ed25519Suite {
    pub fn new() -> Self {
        Self
    }
}

impl Default for Ed25519Suite {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoSuite for Ed25519Suite {
    fn algorithm(&self) -> &str {
        "ed25519"
    }

    fn signature_length(&self) -> usize {
        64
    }

    fn public_key_length(&self) -> usize {
        32
    }

    fn generate_keypair(&self) -> (Vec<u8>, Vec<u8>) {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        (signing_key.to_bytes().to_vec(), verifying_key.to_bytes().to_vec())
    }

    fn sign(&self, private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
        if private_key.len() != 32 {
            return Err(format!("Ed25519 private key must be 32 bytes, got {}", private_key.len()));
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(private_key);
        let signing_key = SigningKey::from_bytes(&key_bytes);
        let signature = signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if public_key.len() != 32 || signature.len() != 64 {
            return false;
        }
        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);
        let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_bytes) else {
            return false;
        };
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify(message, &sig).is_ok()
    }
}

// ---------------------------------------------------------------------------
// Suite Registry
// ---------------------------------------------------------------------------

/// Default algorithm name.
pub const DEFAULT_ALGORITHM: &str = "ed25519";

/// Get the Ed25519 suite (the mandatory default).
pub fn get_ed25519_suite() -> Ed25519Suite {
    Ed25519Suite::new()
}

/// Get a suite by algorithm name with governance enforcement.
///
/// In PRODUCTION, only approved algorithms may be requested.
pub fn get_suite(
    algorithm: &str,
    deployment_profile: &str,
    ledger: &CryptoTransparencyLedger,
) -> Result<Ed25519Suite, String> {
    if algorithm != "ed25519" {
        return Err(format!(
            "Unknown cryptographic algorithm '{}'. Registered: [ed25519]",
            algorithm
        ));
    }

    let policy = get_active_policy(deployment_profile);
    let status = policy.get_status(algorithm);

    if status == SuiteStatus::Forbidden {
        return Err(format!(
            "Algorithm '{}' is FORBIDDEN and may never be used.",
            algorithm
        ));
    }

    if status == SuiteStatus::Deprecated {
        ledger.append(CryptoLedgerEntry {
            timestamp: now_epoch_secs(),
            event_type: "DEPRECATION".into(),
            suite_name: algorithm.into(),
            session_id: String::new(),
            outcome: if deployment_profile == "PRODUCTION" { "BLOCKED" } else { "APPROVED" }.into(),
            transcript_hash: String::new(),
            details: format!(
                "get_suite('{}') called; suite is DEPRECATED in {}.",
                algorithm, deployment_profile
            ),
            entry_hash: String::new(),
        });
        if deployment_profile == "PRODUCTION" {
            return Err(format!(
                "Algorithm '{}' is DEPRECATED and rejected in PRODUCTION.",
                algorithm
            ));
        }
    }

    if !policy.is_approved(algorithm) {
        ledger.append(CryptoLedgerEntry {
            timestamp: now_epoch_secs(),
            event_type: "POLICY_VIOLATION".into(),
            suite_name: algorithm.into(),
            session_id: String::new(),
            outcome: "BLOCKED".into(),
            transcript_hash: String::new(),
            details: format!(
                "get_suite('{}') rejected: not on approved allowlist.",
                algorithm
            ),
            entry_hash: String::new(),
        });
        return Err(format!(
            "Algorithm '{}' is not approved for use in {} deployments.",
            algorithm, deployment_profile
        ));
    }

    Ok(Ed25519Suite::new())
}

// ---------------------------------------------------------------------------
// Convenience sign/verify functions
// ---------------------------------------------------------------------------

/// Sign a message using Ed25519.
pub fn ed25519_sign(private_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    Ed25519Suite::new().sign(private_key, message)
}

/// Verify an Ed25519 signature.
pub fn ed25519_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    Ed25519Suite::new().verify(public_key, message, signature)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto_governance::CryptoTransparencyLedger;

    #[test]
    fn test_ed25519_keypair_generation() {
        let suite = Ed25519Suite::new();
        let (priv_key, pub_key) = suite.generate_keypair();
        assert_eq!(priv_key.len(), 32);
        assert_eq!(pub_key.len(), 32);
    }

    #[test]
    fn test_ed25519_sign_and_verify() {
        let suite = Ed25519Suite::new();
        let (priv_key, pub_key) = suite.generate_keypair();
        let message = b"Hello, SAACP!";
        let signature = suite.sign(&priv_key, message).unwrap();
        assert_eq!(signature.len(), 64);
        assert!(suite.verify(&pub_key, message, &signature));
    }

    #[test]
    fn test_ed25519_verify_wrong_message() {
        let suite = Ed25519Suite::new();
        let (priv_key, pub_key) = suite.generate_keypair();
        let signature = suite.sign(&priv_key, b"correct message").unwrap();
        assert!(!suite.verify(&pub_key, b"wrong message", &signature));
    }

    #[test]
    fn test_ed25519_verify_wrong_key() {
        let suite = Ed25519Suite::new();
        let (priv_key, _) = suite.generate_keypair();
        let (_, other_pub) = suite.generate_keypair();
        let signature = suite.sign(&priv_key, b"test").unwrap();
        assert!(!suite.verify(&other_pub, b"test", &signature));
    }

    #[test]
    fn test_fingerprint() {
        let suite = Ed25519Suite::new();
        let (_, pub_key) = suite.generate_keypair();
        let fp = suite.fingerprint(&pub_key);
        assert_eq!(fp.len(), 64);
    }

    #[test]
    fn test_get_suite_ed25519() {
        let ledger = CryptoTransparencyLedger::new();
        let result = get_suite("ed25519", "PRODUCTION", &ledger);
        assert!(result.is_ok());
    }

    #[test]
    fn test_get_suite_unknown() {
        let ledger = CryptoTransparencyLedger::new();
        let result = get_suite("rsa-2048", "PRODUCTION", &ledger);
        assert!(result.is_err());
    }

    #[test]
    fn test_ed25519_convenience_functions() {
        let suite = Ed25519Suite::new();
        let (priv_key, pub_key) = suite.generate_keypair();
        let msg = b"test message";
        let sig = ed25519_sign(&priv_key, msg).unwrap();
        assert!(ed25519_verify(&pub_key, msg, &sig));
    }

    #[test]
    fn test_ed25519_invalid_key_length() {
        let suite = Ed25519Suite::new();
        assert!(suite.sign(&[0u8; 16], b"msg").is_err());
        assert!(!suite.verify(&[0u8; 16], b"msg", &[0u8; 64]));
    }

    #[test]
    fn test_suite_properties() {
        let suite = Ed25519Suite::new();
        assert_eq!(suite.algorithm(), "ed25519");
        assert_eq!(suite.signature_length(), 64);
        assert_eq!(suite.public_key_length(), 32);
    }
}
