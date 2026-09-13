//! Signature Module
//!
//! Implements hybrid digital signatures combining classical Ed25519 with
//! post-quantum ML-DSA (FIPS 204, Dilithium) for quantum-resistant non-repudiation.
//!
//! # Hybrid Construction
//! A hybrid signature consists of both an Ed25519 signature AND an ML-DSA signature
//! over the same message. Verification requires BOTH signatures to be valid.
//! This ensures non-repudiation survives the breaking of EITHER algorithm.

use core::convert::Infallible;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use zeroize::Zeroizing;

use crate::pqc::domain_separation;
use crate::pqc::PqcError;

/// Wrapper to bridge rand 0.8's OsRng (rand_core 0.6) to rand_core 0.10.
/// Uses UnwrapErr to convert TryRng to Rng (infallible).
struct OsRngWrapper {
    inner: rand::rngs::OsRng,
}

impl OsRngWrapper {
    fn new() -> Self {
        Self {
            inner: rand::rngs::OsRng,
        }
    }
}

impl rand_core::TryRng for OsRngWrapper {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        use rand::RngCore;
        Ok(self.inner.next_u32())
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        use rand::RngCore;
        Ok(self.inner.next_u64())
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        use rand::RngCore;
        self.inner.fill_bytes(dest);
        Ok(())
    }
}

// Note: `rand_core::Rng` and `rand_core::CryptoRng` are automatically implemented
// for types that implement `TryRng<Error = Infallible>` and `TryCryptoRng` respectively.

/// Convert OsRngWrapper to a type that implements TryCryptoRng for rand_core 0.10.
/// We use a newtype to avoid conflicting impls.
struct PqcRng(OsRngWrapper);

impl rand_core::TryRng for PqcRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        self.0.try_fill_bytes(dest)
    }
}

impl rand_core::TryCryptoRng for PqcRng {}

// `rand_core::CryptoRng` is automatically implemented for PqcRng because it implements
// `TryRng<Error = Infallible>` and `TryCryptoRng`.

/// Supported signature algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SignatureAlgorithm {
    /// Ed25519 (RFC 8032) — classical, quantum-vulnerable alone.
    Ed25519,
    /// ML-DSA-65 (NIST FIPS 204, Dilithium) — lattice-based, Category 3.
    MlDsa65,
    /// SLH-DSA (NIST FIPS 205, SPHINCS+) — hash-based, conservative backstop.
    SlhDsa,
    /// Hybrid Ed25519 + ML-DSA-65 (recommended default).
    HybridEd25519MlDsa65,
}

impl SignatureAlgorithm {
    /// String representation for wire format and governance.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ed25519 => "ed25519",
            Self::MlDsa65 => "ml-dsa-65",
            Self::SlhDsa => "slh-dsa",
            Self::HybridEd25519MlDsa65 => "hybrid-ed25519-ml-dsa-65",
        }
    }

    /// Parse from string.
    ///
    /// Deliberately an inherent method (Python-parity shape), not a `FromStr`
    /// impl — see `cluster.rs`'s matching `#[allow]` for the rationale.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "ed25519" => Some(Self::Ed25519),
            "ml-dsa-65" => Some(Self::MlDsa65),
            "slh-dsa" => Some(Self::SlhDsa),
            "hybrid-ed25519-ml-dsa-65" => Some(Self::HybridEd25519MlDsa65),
            _ => None,
        }
    }

    /// Whether this is a hybrid (classical + PQC) construction.
    pub fn is_hybrid(&self) -> bool {
        matches!(self, Self::HybridEd25519MlDsa65)
    }

    /// Whether this signature provides quantum resistance.
    pub fn is_quantum_resistant(&self) -> bool {
        !matches!(self, Self::Ed25519)
    }

    /// Expected signature size in bytes.
    pub fn signature_size(&self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::MlDsa65 => 3293, // ML-DSA-65 signature size
            Self::SlhDsa => 49856, // SLH-DSA-128s signature size (conservative)
            Self::HybridEd25519MlDsa65 => 64 + 3293 + 8, // classical + pqc + length prefix
        }
    }

    /// #3 FIX: IANA-style code point for wire format.
    /// Never infer algorithm from signature length — use the code point.
    pub fn code_point(&self) -> u16 {
        match self {
            Self::Ed25519 => 0x0801, // Reserved private-use range
            Self::MlDsa65 => 0x0802,
            Self::SlhDsa => 0x0803,
            Self::HybridEd25519MlDsa65 => 0x0901,
        }
    }

    /// Parse from IANA-style code point.
    pub fn from_code_point(code: u16) -> Option<Self> {
        match code {
            0x0801 => Some(Self::Ed25519),
            0x0802 => Some(Self::MlDsa65),
            0x0803 => Some(Self::SlhDsa),
            0x0901 => Some(Self::HybridEd25519MlDsa65),
            _ => None,
        }
    }

    /// Whether this algorithm is a classical (non-PQC) algorithm.
    pub fn is_classical(&self) -> bool {
        matches!(self, Self::Ed25519)
    }
}

/// Signature suite trait for algorithm-agnostic signing/verification.
pub trait SignatureSuite: Send + Sync {
    /// Algorithm identifier.
    fn algorithm(&self) -> SignatureAlgorithm;

    /// Generate a new keypair. Returns (public_key, secret_key).
    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError>;

    /// Sign a message. Returns raw signature bytes.
    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, PqcError>;

    /// Verify a signature over a message.
    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;

    /// Public key size in bytes.
    fn public_key_size(&self) -> usize;

    /// Secret key size in bytes.
    fn secret_key_size(&self) -> usize;

    /// Signature size in bytes.
    fn signature_size(&self) -> usize;
}

/// Ed25519 signature suite (classical).
pub struct Ed25519SignatureSuite;

impl Ed25519SignatureSuite {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureSuite for Ed25519SignatureSuite {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::Ed25519
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        let mut csprng = rand::thread_rng();
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Ok((
            verifying_key.to_bytes().to_vec(),
            signing_key.to_bytes().to_vec(),
        ))
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, PqcError> {
        if secret_key.len() != 32 {
            return Err(PqcError::InvalidLength(format!(
                "Ed25519 secret key must be 32 bytes, got {}",
                secret_key.len()
            )));
        }
        let mut key_bytes = Zeroizing::new([0u8; 32]);
        key_bytes.copy_from_slice(secret_key);
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

    fn public_key_size(&self) -> usize {
        32
    }

    fn secret_key_size(&self) -> usize {
        32
    }

    fn signature_size(&self) -> usize {
        64
    }
}

/// ML-DSA-65 signature suite (NIST FIPS 204, post-quantum).
pub struct MlDsa65Suite;

impl MlDsa65Suite {
    pub fn new() -> Self {
        Self
    }
}

impl SignatureSuite for MlDsa65Suite {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::MlDsa65
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, SigningKey};

        let mut rng = PqcRng(OsRngWrapper::new());
        let sk = SigningKey::<MlDsa65>::try_generate_from_rng(&mut rng)
            .map_err(|e| PqcError::KeyGeneration(format!("Key generation failed: {:?}", e)))?;
        let vk = sk.verifying_key();

        // Serialize keys to bytes
        let pk_bytes: Vec<u8> = vk.to_bytes().into();
        let sk_bytes: Vec<u8> = sk.to_bytes().into();

        Ok((pk_bytes, sk_bytes))
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, PqcError> {
        use ml_dsa::{MlDsa65, SignatureEncoding, Signer, SigningKey};

        let sk = SigningKey::<MlDsa65>::from_seed(
            &ml_dsa::Seed::try_from(secret_key)
                .map_err(|_| PqcError::Signing("Invalid seed length".into()))?,
        );

        let signature = sk.sign(message);
        let sig_bytes: Vec<u8> = signature.to_bytes().into();
        Ok(sig_bytes)
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        use ml_dsa::{KeyInit, MlDsa65, Verifier, VerifyingKey};

        let key = match ml_dsa::common::Key::<VerifyingKey<MlDsa65>>::try_from(public_key) {
            Ok(k) => k,
            Err(_) => return false,
        };
        let vk = VerifyingKey::<MlDsa65>::new(&key);
        let Ok(sig) = ml_dsa::Signature::<MlDsa65>::try_from(signature) else {
            return false;
        };
        vk.verify(message, &sig).is_ok()
    }

    fn public_key_size(&self) -> usize {
        1952 // ML-DSA-65 public key size
    }

    fn secret_key_size(&self) -> usize {
        4032 // ML-DSA-65 secret key size
    }

    fn signature_size(&self) -> usize {
        3293 // ML-DSA-65 signature size
    }
}

/// Hybrid Ed25519 + ML-DSA-65 signature suite.
///
/// Combines classical Ed25519 with post-quantum ML-DSA-65 for
/// quantum-resistant non-repudiation.
///
/// # Signature Format
/// ```text
/// [4 bytes: classical_sig_len] [64 bytes: Ed25519 sig] [4 bytes: pqc_sig_len] [3293 bytes: ML-DSA sig]
/// ```
///
/// # Security
/// Both signatures must verify for the hybrid signature to be valid.
/// This ensures non-repudiation even if one algorithm is broken.
pub struct HybridEd25519MlDsa65 {
    classical: Ed25519SignatureSuite,
    pqc: MlDsa65Suite,
}

/// A hybrid signature containing both classical and PQC components.
#[derive(Debug, Clone)]
pub struct HybridSignature {
    /// Ed25519 signature (64 bytes).
    pub classical_sig: Vec<u8>,
    /// ML-DSA-65 signature (~3293 bytes).
    pub pqc_sig: Vec<u8>,
}

impl HybridSignature {
    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.classical_sig.len() + self.pqc_sig.len());
        // Length-prefixed classical signature
        out.extend_from_slice(&(self.classical_sig.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.classical_sig);
        // Length-prefixed PQC signature
        out.extend_from_slice(&(self.pqc_sig.len() as u32).to_be_bytes());
        out.extend_from_slice(&self.pqc_sig);
        out
    }

    /// Deserialize from wire format.
    ///
    /// #6 FIX: Bounded composite parsing — enforce maximum sizes BEFORE allocation.
    /// This prevents memory-amplification attacks where an attacker sends a small
    /// message claiming many large components, forcing large allocations before verification.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 8 {
            return Err(PqcError::InvalidLength("Hybrid signature too short".into()));
        }
        let classical_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;

        // #6 FIX: Enforce maximum classical signature size BEFORE allocation.
        // Ed25519 signatures are always 64 bytes; allow a small margin for future algorithms.
        const MAX_CLASSICAL_SIG_SIZE: usize = 128;
        if classical_len > MAX_CLASSICAL_SIG_SIZE {
            return Err(PqcError::InvalidLength(format!(
                "Classical signature length {} exceeds maximum {}",
                classical_len, MAX_CLASSICAL_SIG_SIZE
            )));
        }

        if bytes.len() < 8 + classical_len {
            return Err(PqcError::InvalidLength(
                "Hybrid signature truncated (classical)".into(),
            ));
        }
        // #6 FIX: Only allocate after bounds check passes
        let classical_sig = bytes[4..4 + classical_len].to_vec();

        let pqc_len_offset = 4 + classical_len;
        let pqc_len = u32::from_be_bytes([
            bytes[pqc_len_offset],
            bytes[pqc_len_offset + 1],
            bytes[pqc_len_offset + 2],
            bytes[pqc_len_offset + 3],
        ]) as usize;

        // #6 FIX: Enforce maximum PQC signature size BEFORE allocation.
        // ML-DSA-65 signatures are ~3293 bytes; SLH-DSA can be larger. Set a generous bound.
        const MAX_PQC_SIG_SIZE: usize = 65_536; // 64 KB max for any PQC signature
        if pqc_len > MAX_PQC_SIG_SIZE {
            return Err(PqcError::InvalidLength(format!(
                "PQC signature length {} exceeds maximum {}",
                pqc_len, MAX_PQC_SIG_SIZE
            )));
        }

        if bytes.len() < pqc_len_offset + 4 + pqc_len {
            return Err(PqcError::InvalidLength(
                "Hybrid signature truncated (pqc)".into(),
            ));
        }
        // #6 FIX: Only allocate after bounds check passes
        let pqc_sig = bytes[pqc_len_offset + 4..pqc_len_offset + 4 + pqc_len].to_vec();

        Ok(Self {
            classical_sig,
            pqc_sig,
        })
    }
}

// ---------------------------------------------------------------------------
// #3 FIX: Composite Signature Envelope — supports multiple algorithms
// ---------------------------------------------------------------------------

/// A single component in a composite signature, identified by IANA-style code point.
#[derive(Debug, Clone)]
pub struct SignatureComponent {
    /// IANA-style code point identifying the algorithm.
    pub algorithm: u16,
    /// Signature bytes.
    pub signature: Vec<u8>,
}

/// #3 FIX: Composite signature envelope supporting multiple algorithms.
/// Format: [count][(code_point, length, bytes)...]
///
/// This allows the protocol to evolve — add SLH-DSA as a third signer,
/// retire any component, or change the verification policy without a wire break.
#[derive(Debug, Clone)]
pub struct CompositeSignature {
    /// Ordered list of signature components.
    pub components: Vec<SignatureComponent>,
}

impl CompositeSignature {
    /// Maximum number of components allowed in a composite signature.
    const MAX_COMPONENTS: usize = 8;

    /// Create a new composite signature from components.
    pub fn new(components: Vec<SignatureComponent>) -> Self {
        Self { components }
    }

    /// Serialize to wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Component count
        out.extend_from_slice(&(self.components.len() as u16).to_be_bytes());
        for component in &self.components {
            // IANA-style code point
            out.extend_from_slice(&component.algorithm.to_be_bytes());
            // Length-prefixed signature
            out.extend_from_slice(&(component.signature.len() as u32).to_be_bytes());
            out.extend_from_slice(&component.signature);
        }
        out
    }

    /// Deserialize from wire format.
    ///
    /// #6 FIX: Bounded parsing — enforce maximum component count BEFORE allocation.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PqcError> {
        if bytes.len() < 2 {
            return Err(PqcError::InvalidLength(
                "Composite signature too short".into(),
            ));
        }
        let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;

        // #6 FIX: Enforce maximum component count BEFORE allocation
        if count > Self::MAX_COMPONENTS {
            return Err(PqcError::InvalidLength(format!(
                "Component count {} exceeds maximum {}",
                count,
                Self::MAX_COMPONENTS
            )));
        }

        let mut components = Vec::with_capacity(count);
        let mut offset = 2;

        for _ in 0..count {
            // Read code point
            if offset + 2 > bytes.len() {
                return Err(PqcError::InvalidLength(
                    "Composite signature truncated (code point)".into(),
                ));
            }
            let algorithm = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
            offset += 2;

            // Read length
            if offset + 4 > bytes.len() {
                return Err(PqcError::InvalidLength(
                    "Composite signature truncated (length)".into(),
                ));
            }
            let sig_len = u32::from_be_bytes([
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            ]) as usize;
            offset += 4;

            // #6 FIX: Enforce maximum signature size BEFORE allocation
            const MAX_COMPONENT_SIG_SIZE: usize = 65_536; // 64 KB
            if sig_len > MAX_COMPONENT_SIG_SIZE {
                return Err(PqcError::InvalidLength(format!(
                    "Component signature length {} exceeds maximum {}",
                    sig_len, MAX_COMPONENT_SIG_SIZE
                )));
            }

            // Read signature
            if offset + sig_len > bytes.len() {
                return Err(PqcError::InvalidLength(
                    "Composite signature truncated (signature)".into(),
                ));
            }
            let signature = bytes[offset..offset + sig_len].to_vec();
            offset += sig_len;

            components.push(SignatureComponent {
                algorithm,
                signature,
            });
        }

        Ok(Self { components })
    }

    /// Get the component for a specific algorithm code point.
    pub fn get_component(&self, code_point: u16) -> Option<&SignatureComponent> {
        self.components.iter().find(|c| c.algorithm == code_point)
    }

    /// Check if the composite signature contains at least one classical algorithm.
    pub fn has_classical(&self) -> bool {
        self.components.iter().any(|c| {
            SignatureAlgorithm::from_code_point(c.algorithm).is_some_and(|a| a.is_classical())
        })
    }

    /// Check if the composite signature contains at least one PQC algorithm.
    pub fn has_pqc(&self) -> bool {
        self.components.iter().any(|c| {
            SignatureAlgorithm::from_code_point(c.algorithm)
                .is_some_and(|a| a.is_quantum_resistant())
        })
    }
}

/// Signing context for domain separation.
#[derive(Debug, Clone)]
pub struct SigningContext {
    /// Domain separation string.
    pub domain: &'static [u8],
    /// Protocol version.
    pub protocol_version: &'static str,
}

impl Default for SigningContext {
    fn default() -> Self {
        Self {
            domain: domain_separation::HYBRID_SIG_CONTEXT,
            protocol_version: "SAACP/0.3",
        }
    }
}

impl HybridEd25519MlDsa65 {
    pub fn new() -> Self {
        Self {
            classical: Ed25519SignatureSuite::new(),
            pqc: MlDsa65Suite::new(),
        }
    }

    /// Generate a hybrid keypair (both Ed25519 and ML-DSA).
    pub fn generate_keypair(&self) -> Result<HybridKeypair, PqcError> {
        let (ed25519_pk, ed25519_sk) = self.classical.generate_keypair()?;
        let (ml_dsa_pk, ml_dsa_sk) = self.pqc.generate_keypair()?;

        Ok(HybridKeypair {
            ed25519_public: ed25519_pk,
            ed25519_secret: ed25519_sk,
            ml_dsa_public: ml_dsa_pk,
            ml_dsa_secret: ml_dsa_sk,
        })
    }

    /// Alias for generate_keypair for backward compatibility.
    pub fn generate_hybrid_keypair(&self) -> Result<HybridKeypair, PqcError> {
        self.generate_keypair()
    }

    /// Sign a message with both Ed25519 and ML-DSA.
    pub fn sign_hybrid(
        &self,
        keypair: &HybridKeypair,
        message: &[u8],
        ctx: Option<&SigningContext>,
    ) -> Result<HybridSignature, PqcError> {
        // Apply domain separation if context provided
        let message_to_sign = if let Some(c) = ctx {
            let mut m = Vec::with_capacity(c.domain.len() + message.len());
            m.extend_from_slice(c.domain);
            m.extend_from_slice(message);
            m
        } else {
            message.to_vec()
        };

        // Classical Ed25519 signature
        let classical_sig = self
            .classical
            .sign(&keypair.ed25519_secret, &message_to_sign)?;

        // Post-quantum ML-DSA signature
        let pqc_sig = self.pqc.sign(&keypair.ml_dsa_secret, &message_to_sign)?;

        Ok(HybridSignature {
            classical_sig,
            pqc_sig,
        })
    }

    /// Verify a hybrid signature.
    pub fn verify_hybrid(
        &self,
        keypair: &HybridKeypair,
        message: &[u8],
        signature: &HybridSignature,
        ctx: Option<&SigningContext>,
    ) -> bool {
        // Apply domain separation if context provided
        let message_to_verify = if let Some(c) = ctx {
            let mut m = Vec::with_capacity(c.domain.len() + message.len());
            m.extend_from_slice(c.domain);
            m.extend_from_slice(message);
            m
        } else {
            message.to_vec()
        };

        // BOTH signatures must verify
        let classical_valid = self.classical.verify(
            &keypair.ed25519_public,
            &message_to_verify,
            &signature.classical_sig,
        );
        let pqc_valid = self.pqc.verify(
            &keypair.ml_dsa_public,
            &message_to_verify,
            &signature.pqc_sig,
        );

        classical_valid && pqc_valid
    }
}

/// Hybrid keypair containing both Ed25519 and ML-DSA keys.
pub struct HybridKeypair {
    pub ed25519_public: Vec<u8>,
    pub ed25519_secret: Vec<u8>,
    pub ml_dsa_public: Vec<u8>,
    pub ml_dsa_secret: Vec<u8>,
}

impl SignatureSuite for HybridEd25519MlDsa65 {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::HybridEd25519MlDsa65
    }

    fn generate_keypair(&self) -> Result<(Vec<u8>, Vec<u8>), PqcError> {
        let kp = self.generate_keypair()?;
        // Serialize: [ed25519_pk][ed25519_sk][ml_dsa_pk][ml_dsa_sk] with length prefixes
        let mut pk_bytes = Vec::new();
        pk_bytes.extend_from_slice(&(kp.ed25519_public.len() as u32).to_be_bytes());
        pk_bytes.extend_from_slice(&kp.ed25519_public);
        pk_bytes.extend_from_slice(&(kp.ml_dsa_public.len() as u32).to_be_bytes());
        pk_bytes.extend_from_slice(&kp.ml_dsa_public);

        let mut sk_bytes = Vec::new();
        sk_bytes.extend_from_slice(&(kp.ed25519_secret.len() as u32).to_be_bytes());
        sk_bytes.extend_from_slice(&kp.ed25519_secret);
        sk_bytes.extend_from_slice(&(kp.ml_dsa_secret.len() as u32).to_be_bytes());
        sk_bytes.extend_from_slice(&kp.ml_dsa_secret);

        Ok((pk_bytes, sk_bytes))
    }

    fn sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>, PqcError> {
        let keypair = self.deserialize_keypair_sk(secret_key)?;
        let sig = self.sign_hybrid(&keypair, message, None)?;
        Ok(sig.to_bytes())
    }

    fn verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        let Ok(keypair) = self.deserialize_keypair_pk(public_key) else {
            return false;
        };
        let Ok(sig) = HybridSignature::from_bytes(signature) else {
            return false;
        };
        self.verify_hybrid(&keypair, message, &sig, None)
    }

    fn public_key_size(&self) -> usize {
        8 + 32 + 1952 // length-prefixed Ed25519 + ML-DSA public keys
    }

    fn secret_key_size(&self) -> usize {
        8 + 32 + 4032 // length-prefixed Ed25519 + ML-DSA secret keys
    }

    fn signature_size(&self) -> usize {
        8 + 64 + 3293 // length-prefixed Ed25519 + ML-DSA signatures
    }
}

impl HybridEd25519MlDsa65 {
    /// Deserialize a public key from wire format.
    fn deserialize_keypair_pk(&self, bytes: &[u8]) -> Result<HybridKeypair, PqcError> {
        if bytes.len() < 8 {
            return Err(PqcError::InvalidLength("Public key too short".into()));
        }
        let ed25519_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 8 + ed25519_len {
            return Err(PqcError::InvalidLength("Public key truncated".into()));
        }
        let ed25519_public = bytes[4..4 + ed25519_len].to_vec();

        let ml_dsa_offset = 4 + ed25519_len;
        let ml_dsa_len = u32::from_be_bytes([
            bytes[ml_dsa_offset],
            bytes[ml_dsa_offset + 1],
            bytes[ml_dsa_offset + 2],
            bytes[ml_dsa_offset + 3],
        ]) as usize;
        if bytes.len() < ml_dsa_offset + 4 + ml_dsa_len {
            return Err(PqcError::InvalidLength("Public key truncated".into()));
        }
        let ml_dsa_public = bytes[ml_dsa_offset + 4..ml_dsa_offset + 4 + ml_dsa_len].to_vec();

        Ok(HybridKeypair {
            ed25519_public,
            ed25519_secret: vec![],
            ml_dsa_public,
            ml_dsa_secret: vec![],
        })
    }

    /// Deserialize a secret key from wire format.
    fn deserialize_keypair_sk(&self, bytes: &[u8]) -> Result<HybridKeypair, PqcError> {
        if bytes.len() < 8 {
            return Err(PqcError::InvalidLength("Secret key too short".into()));
        }
        let ed25519_len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        if bytes.len() < 8 + ed25519_len {
            return Err(PqcError::InvalidLength("Secret key truncated".into()));
        }
        let ed25519_secret = bytes[4..4 + ed25519_len].to_vec();

        let ml_dsa_offset = 4 + ed25519_len;
        let ml_dsa_len = u32::from_be_bytes([
            bytes[ml_dsa_offset],
            bytes[ml_dsa_offset + 1],
            bytes[ml_dsa_offset + 2],
            bytes[ml_dsa_offset + 3],
        ]) as usize;
        if bytes.len() < ml_dsa_offset + 4 + ml_dsa_len {
            return Err(PqcError::InvalidLength("Secret key truncated".into()));
        }
        let ml_dsa_secret = bytes[ml_dsa_offset + 4..ml_dsa_offset + 4 + ml_dsa_len].to_vec();

        Ok(HybridKeypair {
            ed25519_public: vec![],
            ed25519_secret,
            ml_dsa_public: vec![],
            ml_dsa_secret,
        })
    }
}

impl Default for Ed25519SignatureSuite {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for MlDsa65Suite {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for HybridEd25519MlDsa65 {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_signature_suite() {
        let suite = Ed25519SignatureSuite::new();
        let (pk, sk) = suite.generate_keypair().unwrap();
        let msg = b"test message";
        let sig = suite.sign(&sk, msg).unwrap();
        assert!(suite.verify(&pk, msg, &sig));
        assert!(!suite.verify(&pk, b"wrong message", &sig));
    }

    #[test]
    fn test_hybrid_signature_serialize_deserialize() {
        let sig = HybridSignature {
            classical_sig: vec![1u8; 64],
            pqc_sig: vec![2u8; 100],
        };
        let bytes = sig.to_bytes();
        let deserialized = HybridSignature::from_bytes(&bytes).unwrap();
        assert_eq!(sig.classical_sig, deserialized.classical_sig);
        assert_eq!(sig.pqc_sig, deserialized.pqc_sig);
    }

    #[test]
    fn test_hybrid_ed25519_ml_dsa() {
        let suite = HybridEd25519MlDsa65::new();
        let keypair = suite.generate_hybrid_keypair().unwrap();
        let msg = b"test message for hybrid signature";

        let sig = suite.sign_hybrid(&keypair, msg, None).unwrap();
        assert!(suite.verify_hybrid(&keypair, msg, &sig, None));
        assert!(!suite.verify_hybrid(&keypair, b"wrong message", &sig, None));
    }

    #[test]
    fn test_signature_algorithm_strings() {
        assert_eq!(SignatureAlgorithm::Ed25519.as_str(), "ed25519");
        assert_eq!(
            SignatureAlgorithm::from_str("hybrid-ed25519-ml-dsa-65"),
            Some(SignatureAlgorithm::HybridEd25519MlDsa65)
        );
        assert!(SignatureAlgorithm::HybridEd25519MlDsa65.is_hybrid());
        assert!(SignatureAlgorithm::MlDsa65.is_quantum_resistant());
        assert!(!SignatureAlgorithm::Ed25519.is_quantum_resistant());
    }
}
