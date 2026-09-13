//! Key Encapsulation Mechanism (KEM) Module
//!
//! Implements hybrid key exchange combining classical X25519 ECDH with
//! post-quantum ML-KEM (FIPS 203) for quantum-resistant forward secrecy.
//!
//! # Hybrid Construction
//! The hybrid KEM combines shared secrets from both X25519 and ML-KEM
//! via concatenation, then derives the final session key using HKDF-SHA384.
//! Security is maintained if EITHER primitive remains unbroken.

use hkdf::Hkdf;
use sha2::Sha384;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::pqc::domain_separation;
use crate::pqc::max_sizes;
use crate::pqc::PqcError;

/// Key Encapsulation Mechanism trait.
///
/// Implementations provide quantum-safe or classical key agreement.
pub trait Kem: Send + Sync {
    /// Algorithm identifier for this KEM.
    fn algorithm(&self) -> KemAlgorithm;

    /// Generate a new keypair. Returns (public_key, secret_key).
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError>;

    /// Encapsulate a shared secret for the given public key.
    /// Returns (ciphertext, shared_secret).
    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError>;

    /// Decapsulate a shared secret from the given ciphertext and secret key.
    /// Returns the shared secret.
    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Public key size in bytes.
    fn public_key_size(&self) -> usize;

    /// Ciphertext size in bytes.
    fn ciphertext_size(&self) -> usize;

    /// Shared secret size in bytes.
    fn shared_secret_size(&self) -> usize;
}

/// Supported KEM algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KemAlgorithm {
    /// X25519 ECDH (classical, quantum-vulnerable alone).
    X25519,
    /// ML-KEM-768 (NIST FIPS 203, Category 3 security).
    MlKem768,
    /// ML-KEM-1024 (NIST FIPS 203, Category 5 security).
    MlKem1024,
    /// Hybrid X25519 + ML-KEM-768 (recommended default).
    HybridX25519MlKem768,
    /// Hybrid P-384 + ML-KEM-1024 (high-security tier).
    HybridP384MlKem1024,
}

impl KemAlgorithm {
    /// String representation for wire format and governance.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::X25519 => "x25519",
            Self::MlKem768 => "ml-kem-768",
            Self::MlKem1024 => "ml-kem-1024",
            Self::HybridX25519MlKem768 => "hybrid-x25519-ml-kem-768",
            Self::HybridP384MlKem1024 => "hybrid-p384-ml-kem-1024",
        }
    }

    /// Parse from string.
    ///
    /// Deliberately an inherent method (Python-parity shape), not a `FromStr`
    /// impl — see `cluster.rs`'s matching `#[allow]` for the rationale.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "x25519" => Some(Self::X25519),
            "ml-kem-768" => Some(Self::MlKem768),
            "ml-kem-1024" => Some(Self::MlKem1024),
            "hybrid-x25519-ml-kem-768" => Some(Self::HybridX25519MlKem768),
            "hybrid-p384-ml-kem-1024" => Some(Self::HybridP384MlKem1024),
            _ => None,
        }
    }

    /// Whether this is a hybrid (classical + PQC) construction.
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Self::HybridX25519MlKem768 | Self::HybridP384MlKem1024)
    }

    /// Whether this KEM provides quantum resistance.
    pub fn is_quantum_resistant(&self) -> bool {
        !matches!(self, Self::X25519)
    }
}

/// X25519 ECDH KEM (classical).
///
/// This is the existing key exchange mechanism, retained for backward
/// compatibility and as the classical component of hybrid constructions.
pub struct X25519Kem;

impl X25519Kem {
    pub fn new() -> Self {
        Self
    }
}

impl Kem for X25519Kem {
    fn algorithm(&self) -> KemAlgorithm {
        KemAlgorithm::X25519
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        let secret_bytes = secret.to_bytes().to_vec();
        let public_bytes = public.as_bytes().to_vec();
        Ok((public_bytes, secret_bytes))
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        use rand::rngs::OsRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        if public_key.len() != 32 {
            return Err(PqcError::InvalidLength(format!(
                "X25519 public key must be 32 bytes, got {}",
                public_key.len()
            )));
        }

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(public_key);
        let peer_public = PublicKey::from(pk_bytes);

        // Generate ephemeral static secret for encapsulation
        let ephemeral_secret = StaticSecret::random_from_rng(OsRng);
        let ephemeral_public = PublicKey::from(&ephemeral_secret);
        let shared = ephemeral_secret.diffie_hellman(&peer_public);

        let ciphertext = ephemeral_public.as_bytes().to_vec();
        let shared_secret = shared.as_bytes().to_vec();

        Ok((ciphertext, shared_secret))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PqcError> {
        use x25519_dalek::{PublicKey, StaticSecret};

        if secret_key.len() != 32 {
            return Err(PqcError::InvalidLength(format!(
                "X25519 secret key must be 32 bytes, got {}",
                secret_key.len()
            )));
        }
        if ciphertext.len() != 32 {
            return Err(PqcError::InvalidLength(format!(
                "X25519 ciphertext (ephemeral public) must be 32 bytes, got {}",
                ciphertext.len()
            )));
        }

        let mut sk_bytes = [0u8; 32];
        sk_bytes.copy_from_slice(secret_key);
        let secret = StaticSecret::from(sk_bytes);

        let mut pk_bytes = [0u8; 32];
        pk_bytes.copy_from_slice(ciphertext);
        let ephemeral_public = PublicKey::from(pk_bytes);

        let shared = secret.diffie_hellman(&ephemeral_public);
        Ok(shared.as_bytes().to_vec())
    }

    fn public_key_size(&self) -> usize {
        32
    }

    fn ciphertext_size(&self) -> usize {
        32
    }

    fn shared_secret_size(&self) -> usize {
        32
    }
}

/// ML-KEM-768 KEM (NIST FIPS 203, post-quantum).
///
/// Lattice-based key encapsulation providing Category 3 quantum resistance.
pub struct MlKem768;

impl MlKem768 {
    pub fn new() -> Self {
        Self
    }
}

impl Kem for MlKem768 {
    fn algorithm(&self) -> KemAlgorithm {
        KemAlgorithm::MlKem768
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        use ml_kem::{kem::Kem, KeyExport, MlKem768 as MlKem768Impl};

        let (dk, ek) = MlKem768Impl::generate_keypair();
        let pk: Vec<u8> = ek.to_bytes().into();
        let sk: Vec<u8> = dk.to_bytes().into();

        Ok((pk, sk))
    }

    fn encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        use ml_kem::{kem::Encapsulate, EncapsulationKey, MlKem768 as MlKem768Impl};

        if public_key.len() != max_sizes::ML_KEM_768_PK {
            return Err(PqcError::InvalidLength(format!(
                "ML-KEM-768 public key must be {} bytes, got {}",
                max_sizes::ML_KEM_768_PK,
                public_key.len()
            )));
        }

        // Convert slice to Key type
        let key = <ml_kem::Key<EncapsulationKey<MlKem768Impl>>>::try_from(public_key)
            .map_err(|_| PqcError::Encapsulation("Invalid public key length".into()))?;

        let ek = EncapsulationKey::<MlKem768Impl>::new(&key)
            .map_err(|_| PqcError::Encapsulation("Invalid public key".into()))?;

        let (ct, ss) = ek.encapsulate();

        let ct_bytes: Vec<u8> = ct.into();
        let ss_bytes: Vec<u8> = ss.into();

        Ok((ct_bytes, ss_bytes))
    }

    fn decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, PqcError> {
        use ml_kem::{kem::Decapsulate, DecapsulationKey, MlKem768 as MlKem768Impl, Seed};

        if ciphertext.len() != max_sizes::ML_KEM_768_CT {
            return Err(PqcError::InvalidLength(format!(
                "ML-KEM-768 ciphertext must be {} bytes, got {}",
                max_sizes::ML_KEM_768_CT,
                ciphertext.len()
            )));
        }

        if secret_key.len() != 64 {
            return Err(PqcError::InvalidLength(format!(
                "ML-KEM-768 seed must be 64 bytes, got {}",
                secret_key.len()
            )));
        }

        let seed = Seed::try_from(secret_key)
            .map_err(|_| PqcError::Decapsulation("Invalid seed length".into()))?;
        let dk = DecapsulationKey::<MlKem768Impl>::from_seed(seed);
        let ct = ml_kem::Ciphertext::<MlKem768Impl>::try_from(ciphertext)
            .map_err(|_| PqcError::Decapsulation("Invalid ciphertext length".into()))?;

        let ss = dk.decapsulate(&ct);
        let ss_bytes: Vec<u8> = ss.into();
        Ok(ss_bytes)
    }

    fn public_key_size(&self) -> usize {
        max_sizes::ML_KEM_768_PK
    }

    fn ciphertext_size(&self) -> usize {
        max_sizes::ML_KEM_768_CT
    }

    fn shared_secret_size(&self) -> usize {
        32
    }
}

/// Hybrid KEM combining X25519 ECDH + ML-KEM-768.
///
/// This is the recommended default for quantum-resistant key exchange.
/// The shared secrets from both primitives are concatenated and derived
/// via HKDF-SHA384 to produce the final session key.
///
/// # Security Properties
/// - **Hybrid security**: Session remains secure if EITHER X25519 OR ML-KEM-768 is unbroken
/// - **Forward secrecy**: Ephemeral keypairs ensure past sessions cannot be decrypted
/// - **Quantum resistance**: ML-KEM-768 provides post-quantum security
pub struct HybridKem {
    classical: X25519Kem,
    pqc: MlKem768,
}

/// Result of a hybrid KEM operation.
///
/// #7 FIX: Implements ZeroizeOnDrop to ensure secrets are cleared from memory
/// when the struct is dropped, preventing secret material from lingering in memory.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridSharedSecret {
    /// Classical shared secret (X25519). Zeroized on drop.
    pub classical: Vec<u8>,
    /// Post-quantum shared secret (ML-KEM). Zeroized on drop.
    pub pqc: Vec<u8>,
    /// Derived session key (HKDF-SHA384 of classical || pqc). Zeroized on drop.
    pub session_key: Vec<u8>,
}

/// Hybrid KEM handshake message.
#[derive(Debug, Clone)]
pub struct HybridHandshakeMessage {
    /// Ephemeral X25519 public key (32 bytes).
    pub x25519_public: Vec<u8>,
    /// ML-KEM-768 public key (1184 bytes).
    pub mlkem_public: Vec<u8>,
    /// ML-KEM-768 ciphertext (1088 bytes).
    pub mlkem_ciphertext: Vec<u8>,
    /// Signature over the handshake (hybrid Ed25519+ML-DSA).
    pub transcript_signature: Vec<u8>,
}

impl HybridKem {
    pub fn new() -> Self {
        Self {
            classical: X25519Kem::new(),
            pqc: MlKem768::new(),
        }
    }

    /// Generate a hybrid keypair (both X25519 and ML-KEM).
    pub fn generate_keypair(&self) -> Result<HybridKeypair, PqcError> {
        let (x25519_pk, x25519_sk) = self.classical.generate_keypair()?;
        let (mlkem_pk, mlkem_sk) = self.pqc.generate_keypair()?;

        Ok(HybridKeypair {
            x25519_public: x25519_pk,
            x25519_secret: x25519_sk,
            mlkem_public: mlkem_pk,
            mlkem_secret: mlkem_sk,
        })
    }

    /// Encapsulate a shared secret using the peer's hybrid public key.
    pub fn encapsulate(
        &self,
        peer_x25519_pk: &[u8],
        peer_mlkem_pk: &[u8],
    ) -> Result<(HybridHandshakeMessage, HybridSharedSecret), PqcError> {
        // Classical X25519 encapsulation
        // Note: encapsulate() generates an ephemeral keypair internally and returns
        // (ephemeral_public_key, shared_secret). The ephemeral_public_key is the ciphertext.
        let (x25519_ct, ss_classical) = self.classical.encapsulate(peer_x25519_pk)?;

        // Post-quantum ML-KEM encapsulation
        let (mlkem_ct, ss_pqc) = self.pqc.encapsulate(peer_mlkem_pk)?;

        // Derive session key via HKDF-SHA384
        // #1 FIX: Pass both shared secrets AND ciphertexts to bind them into the KDF.
        let session_key =
            derive_hybrid_session_key(&ss_classical, &ss_pqc, &x25519_ct, &mlkem_ct, None)?;

        let msg = HybridHandshakeMessage {
            x25519_public: x25519_ct, // Use the same ephemeral public key from encapsulation
            mlkem_public: vec![],     // Not needed in encapsulation response
            mlkem_ciphertext: mlkem_ct,
            transcript_signature: vec![], // Added after signing
        };

        let secret = HybridSharedSecret {
            classical: ss_classical,
            pqc: ss_pqc,
            session_key,
        };

        Ok((msg, secret))
    }

    /// Decapsulate a shared secret from the peer's handshake message.
    pub fn decapsulate(
        &self,
        keypair: &HybridKeypair,
        peer_x25519_public: &[u8],
        peer_mlkem_ciphertext: &[u8],
    ) -> Result<HybridSharedSecret, PqcError> {
        // Classical X25519 decapsulation
        let ss_classical = self
            .classical
            .decapsulate(&keypair.x25519_secret, peer_x25519_public)?;

        // Post-quantum ML-KEM decapsulation
        let ss_pqc = self
            .pqc
            .decapsulate(&keypair.mlkem_secret, peer_mlkem_ciphertext)?;

        // Derive session key via HKDF-SHA384
        // #1 FIX: Pass both shared secrets AND ciphertexts to bind them into the KDF.
        // The ciphertexts are peer_x25519_public (X25519) and peer_mlkem_ciphertext (ML-KEM).
        let session_key = derive_hybrid_session_key(
            &ss_classical,
            &ss_pqc,
            peer_x25519_public,
            peer_mlkem_ciphertext,
            None,
        )?;

        Ok(HybridSharedSecret {
            classical: ss_classical,
            pqc: ss_pqc,
            session_key,
        })
    }
}

/// Hybrid keypair containing both classical and PQC keys.
///
/// #7 FIX: Implements ZeroizeOnDrop to ensure secret keys are cleared from memory
/// when the struct is dropped. Public keys are marked with #[zeroize(skip)] since
/// they are not secret.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct HybridKeypair {
    /// Public key — not secret, skipped during zeroization.
    #[zeroize(skip)]
    pub x25519_public: Vec<u8>,
    /// Secret key — zeroized on drop.
    pub x25519_secret: Vec<u8>,
    /// Public key — not secret, skipped during zeroization.
    #[zeroize(skip)]
    pub mlkem_public: Vec<u8>,
    /// Secret key — zeroized on drop.
    pub mlkem_secret: Vec<u8>,
}

/// Derive a session key from hybrid shared secrets using HKDF-SHA384.
///
/// #1 FIX: Binds BOTH shared secrets AND ciphertexts into the KDF input.
/// This gives IND-CCA robustness against a chosen-ciphertext attack on the
/// weaker component. Without binding ciphertexts, an attacker could potentially
/// manipulate the ciphertext to weaken the derived key.
///
/// The correct KEM-combiner construction is:
///   ss = HKDF(label || ss_classical || ss_pqc || ct_classical || ct_pqc)
///
/// # Arguments
/// * `classical_ss` - Classical shared secret (X25519)
/// * `pqc_ss` - Post-quantum shared secret (ML-KEM)
/// * `classical_ct` - Classical ciphertext (X25519 ephemeral public key)
/// * `pqc_ct` - Post-quantum ciphertext (ML-KEM ciphertext)
/// * `salt` - Optional salt (defaults to zeros)
///
/// # Returns
/// 32-byte session key derived from both shared secrets and ciphertexts.
pub fn derive_hybrid_session_key(
    classical_ss: &[u8],
    pqc_ss: &[u8],
    classical_ct: &[u8],
    pqc_ct: &[u8],
    salt: Option<&[u8]>,
) -> Result<Vec<u8>, PqcError> {
    // #1 FIX: Concatenate shared secrets AND ciphertexts: classical_ss || pqc_ss || classical_ct || pqc_ct
    // Binding ciphertexts prevents chosen-ciphertext attacks on the weaker component.
    let mut ikm =
        Vec::with_capacity(classical_ss.len() + pqc_ss.len() + classical_ct.len() + pqc_ct.len());
    ikm.extend_from_slice(classical_ss);
    ikm.extend_from_slice(pqc_ss);
    ikm.extend_from_slice(classical_ct);
    ikm.extend_from_slice(pqc_ct);

    // #4 FIX: Use length-framing to prevent cross-context collision.
    // Prepend the domain separation label length and the IKM length.
    let mut framed_input = Vec::new();
    framed_input.extend_from_slice(&(domain_separation::HYBRID_KEM_SS.len() as u32).to_be_bytes());
    framed_input.extend_from_slice(domain_separation::HYBRID_KEM_SS);
    framed_input.extend_from_slice(&(ikm.len() as u32).to_be_bytes());
    framed_input.extend_from_slice(&ikm);

    // HKDF-SHA384 extract + expand
    let hk = Hkdf::<Sha384>::new(salt, &framed_input);
    let mut okm = [0u8; 32];
    hk.expand(domain_separation::SESSION_KEY_DERIVATION, &mut okm)
        .map_err(|e| PqcError::KeyGeneration(format!("HKDF expand failed: {}", e)))?;

    Ok(okm.to_vec())
}

impl Default for HybridKem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for X25519Kem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MlKem768 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_x25519_keypair_generation() {
        let kem = X25519Kem::new();
        let (pk, sk) = kem.generate_keypair().unwrap();
        assert_eq!(pk.len(), 32);
        assert_eq!(sk.len(), 32);
    }

    #[test]
    fn test_x25519_encapsulate_decapsulate() {
        let kem = X25519Kem::new();
        let (pk, sk) = kem.generate_keypair().unwrap();
        let (ct, ss_enc) = kem.encapsulate(&pk).unwrap();
        let ss_dec = kem.decapsulate(&sk, &ct).unwrap();
        assert_eq!(ss_enc, ss_dec);
    }

    #[test]
    fn test_hybrid_kem_keypair_generation() {
        let kem = HybridKem::new();
        let kp = kem.generate_keypair().unwrap();
        assert_eq!(kp.x25519_public.len(), 32);
        assert_eq!(kp.x25519_secret.len(), 32);
        assert_eq!(kp.mlkem_public.len(), max_sizes::ML_KEM_768_PK);
        assert!(!kp.mlkem_secret.is_empty());
    }

    #[test]
    fn test_hybrid_kem_encapsulate_decapsulate() {
        let kem = HybridKem::new();
        let _alice_kp = kem.generate_keypair().unwrap();
        let bob_kp = kem.generate_keypair().unwrap();

        // Alice encapsulates to Bob
        let (msg, ss_alice) = kem
            .encapsulate(&bob_kp.x25519_public, &bob_kp.mlkem_public)
            .unwrap();

        // Bob decapsulates from Alice
        let ss_bob = kem
            .decapsulate(&bob_kp, &msg.x25519_public, &msg.mlkem_ciphertext)
            .unwrap();

        assert_eq!(ss_alice.session_key, ss_bob.session_key);
    }

    #[test]
    fn test_hybrid_session_key_derivation() {
        let ss1 = vec![1u8; 32];
        let ss2 = vec![2u8; 32];
        let ct1 = vec![3u8; 32];
        let ct2 = vec![4u8; 32];
        let key = derive_hybrid_session_key(&ss1, &ss2, &ct1, &ct2, None).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_kem_algorithm_strings() {
        assert_eq!(KemAlgorithm::X25519.as_str(), "x25519");
        assert_eq!(
            KemAlgorithm::from_str("hybrid-x25519-ml-kem-768"),
            Some(KemAlgorithm::HybridX25519MlKem768)
        );
        assert!(KemAlgorithm::HybridX25519MlKem768.is_hybrid());
        assert!(KemAlgorithm::MlKem768.is_quantum_resistant());
        assert!(!KemAlgorithm::X25519.is_quantum_resistant());
    }
}

// ---------------------------------------------------------------------------
// #7 FIX: Key Lifecycle State Machine
// ---------------------------------------------------------------------------

/// Key lifecycle states for forward secrecy management.
///
/// #7 FIX: Explicit state machine ensures keys are properly managed from creation
/// through retirement, with zeroization guaranteed on transition to the Zeroized state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyLifecycleState {
    /// Key has been generated but not yet used.
    Generated,
    /// Key is currently in use for an active session.
    InUse,
    /// Key has been retired (session ended) and is awaiting zeroization.
    Retired,
    /// Key material has been zeroized and the key is no longer usable.
    Zeroized,
}

/// Session key metadata for forward secrecy management.
///
/// #7 FIX: Tracks the age and lifecycle state of session keys to enforce
/// re-handshake before the key age cap is exceeded.
#[derive(Debug, Clone)]
pub struct SessionKeyMetadata {
    /// The session key itself (zeroized on drop).
    pub key: Vec<u8>,
    /// Current lifecycle state of this key.
    pub state: KeyLifecycleState,
    /// Timestamp when the key was created (epoch seconds).
    pub created_at: f64,
    /// Maximum age of this key in seconds before re-handshake is required.
    pub max_age_secs: f64,
}

impl SessionKeyMetadata {
    /// Default maximum session key age: 1 hour.
    pub const DEFAULT_MAX_AGE_SECS: f64 = 3600.0;

    /// Create a new session key metadata with the default max age.
    pub fn new(key: Vec<u8>) -> Self {
        Self {
            key,
            state: KeyLifecycleState::Generated,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            max_age_secs: Self::DEFAULT_MAX_AGE_SECS,
        }
    }

    /// Create with a custom max age.
    pub fn with_max_age(key: Vec<u8>, max_age_secs: f64) -> Self {
        Self {
            key,
            state: KeyLifecycleState::Generated,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs_f64(),
            max_age_secs,
        }
    }

    /// Check if the key has exceeded its maximum age.
    pub fn is_expired(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        (now - self.created_at) > self.max_age_secs
    }

    /// Transition to InUse state.
    pub fn mark_in_use(&mut self) {
        if self.state == KeyLifecycleState::Generated {
            self.state = KeyLifecycleState::InUse;
        }
    }

    /// Transition to Retired state.
    pub fn mark_retired(&mut self) {
        if self.state == KeyLifecycleState::InUse {
            self.state = KeyLifecycleState::Retired;
        }
    }

    /// Transition to Zeroized state and zeroize the key material.
    pub fn zeroize(&mut self) {
        self.key.zeroize();
        self.state = KeyLifecycleState::Zeroized;
    }
}

impl Drop for SessionKeyMetadata {
    fn drop(&mut self) {
        // #7 FIX: Ensure key material is zeroized on drop, regardless of state.
        // This covers the error and abort paths that are often forgotten.
        if self.state != KeyLifecycleState::Zeroized {
            self.key.zeroize();
        }
    }
}
