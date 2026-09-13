//! Post-Quantum Cryptography (PQC) Module
//!
//! Implements NIST FIPS-standardized post-quantum cryptographic primitives
//! for quantum-resistant security in SAACP.
//!
//! # Standards
//! - ML-DSA (FIPS 204, Dilithium) — lattice-based digital signatures
//! - ML-KEM (FIPS 203, Kyber) — lattice-based key encapsulation
//! - SLH-DSA (FIPS 205, SPHINCS+) — hash-based digital signatures (backstop)
//!
//! # Hybrid Approach
//! All PQC primitives are deployed in HYBRID mode, combining classical
//! (Ed25519/X25519) and PQC algorithms. This ensures security if EITHER
//! primitive remains unbroken, providing defense-in-depth against both
//! classical and quantum adversaries.

pub mod kem;
pub mod signature;

pub use kem::{HybridKem, Kem, KemAlgorithm, MlKem768, X25519Kem};
pub use signature::{HybridEd25519MlDsa65, SignatureAlgorithm, SignatureSuite, SigningContext};

use saacp_primitives::errors::SAACPHardDrop;

/// Errors specific to PQC operations.
#[derive(Debug, Clone)]
pub enum PqcError {
    /// Key generation failed
    KeyGeneration(String),
    /// Encapsulation failed
    Encapsulation(String),
    /// Decapsulation failed
    Decapsulation(String),
    /// Signing failed
    Signing(String),
    /// Verification failed
    Verification(String),
    /// Invalid key or ciphertext length
    InvalidLength(String),
    /// Algorithm not supported
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for PqcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyGeneration(msg) => write!(f, "PQC key generation failed: {}", msg),
            Self::Encapsulation(msg) => write!(f, "PQC encapsulation failed: {}", msg),
            Self::Decapsulation(msg) => write!(f, "PQC decapsulation failed: {}", msg),
            Self::Signing(msg) => write!(f, "PQC signing failed: {}", msg),
            Self::Verification(msg) => write!(f, "PQC verification failed: {}", msg),
            Self::InvalidLength(msg) => write!(f, "PQC invalid length: {}", msg),
            Self::UnsupportedAlgorithm(msg) => write!(f, "PQC unsupported algorithm: {}", msg),
        }
    }
}

impl std::error::Error for PqcError {}

impl From<PqcError> for SAACPHardDrop {
    fn from(err: PqcError) -> Self {
        SAACPHardDrop::new(
            saacp_primitives::errors::SAACPBytecodes::InvalidSignature,
            format!("PQC operation failed: {}", err),
        )
    }
}

/// Domain separation strings for HKDF operations.
/// These ensure that keys derived for different purposes cannot collide.
pub mod domain_separation {
    /// Hybrid KEM shared secret derivation.
    pub const HYBRID_KEM_SS: &[u8] = b"SAACP-PQC-hybrid-kem-ss-v1";
    /// Hybrid signature context binding.
    pub const HYBRID_SIG_CONTEXT: &[u8] = b"SAACP-PQC-hybrid-sig-context-v1";
    /// Session key derivation from hybrid shared secret.
    pub const SESSION_KEY_DERIVATION: &[u8] = b"SAACP-PQC-session-key-v1";
    /// Attestation challenge binding.
    pub const ATTESTATION_CHALLENGE: &[u8] = b"SAACP-PQC-attestation-challenge-v1";
    /// Channel binding token derivation.
    pub const CHANNEL_BINDING: &[u8] = b"SAACP-PQC-channel-binding-v1";
}

/// Maximum sizes for PQC messages (bytes).
/// These bounds prevent DoS via oversized PQC payloads.
pub mod max_sizes {
    /// ML-KEM-768 public key size.
    pub const ML_KEM_768_PK: usize = 1184;
    /// ML-KEM-768 ciphertext size.
    pub const ML_KEM_768_CT: usize = 1088;
    /// ML-KEM-1024 public key size.
    pub const ML_KEM_1024_PK: usize = 1568;
    /// ML-KEM-1024 ciphertext size.
    pub const ML_KEM_1024_CT: usize = 1568;
    /// ML-DSA-65 public key size.
    pub const ML_DSA_65_PK: usize = 1952;
    /// ML-DSA-65 signature size.
    pub const ML_DSA_65_SIG: usize = 3293;
    /// Maximum hybrid handshake message size (classical + PQC shares).
    pub const MAX_HYBRID_HANDSHAKE: usize = 8192;
    /// Maximum attestation quote size.
    pub const MAX_ATTESTATION_QUOTE: usize = 4096;
}
