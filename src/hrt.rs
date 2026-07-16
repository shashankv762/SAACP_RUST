//! hrt.rs — Hardware Root of Trust trait abstraction (Phase 6 / item 8 / Part 8.8).
//!
//! Every signing operation in this codebase today reaches directly into raw Ed25519 key
//! material (`klms::KeyDescriptor::key_material`, an identity certificate's signing key,
//! etc.) and calls `ed25519_dalek::SigningKey::sign` in-process. That is a real exposure:
//! any process that can read the running program's memory (a debugger, a core dump, an
//! unrelated memory-disclosure bug elsewhere) can exfiltrate a long-lived signing key
//! wholesale, forever. A hardware security module — a TPM, an SGX enclave, a PKCS#11
//! token — never releases the private key at all; it accepts a message and returns a
//! signature, keeping the key material sealed inside hardware for the device's lifetime.
//!
//! [`HardwareKeyStore`] is the seam that makes swapping in that stronger guarantee a
//! matter of implementing one trait, not rewriting every call site that signs something.
//! [`SoftwareKeyStore`] is the default, always-available implementation — it delegates key
//! *lifecycle* (rotation, expiry, revocation) entirely to [`crate::klms::KeyRegistry`]
//! (no duplicated bookkeeping) and only adds the one operation `klms.rs` itself doesn't
//! provide: turning a `KeyRegistry` entry's raw material into an actual Ed25519 signature.
//!
//! Per Phase 6 item 8's own scope note ("(trait abstraction)"), this module ships the
//! trait and the software default only. `TpmKeyStore`/`SgxKeyStore`/`Pkcs11KeyStore` are
//! feature-gated compile-only placeholders (`hrt-tpm`/`hrt-sgx`/`hrt-pkcs11`, all off by
//! default and absent from the default build) that return
//! [`HrtError::NotImplemented`] — real hardware integration for each is a distinct,
//! multi-week project outside what this pass specifies concretely enough to build
//! correctly. Existing signing call sites (`klms.rs`, `identity_binding.rs`, `factf.rs`'s
//! threshold-signing paths, `hth.rs`) are NOT rewired onto `Arc<dyn HardwareKeyStore>` in
//! this pass — that migration touches four crypto-critical modules and is deliberately
//! deferred to its own explicitly-scoped change, per Part A.2's phased-rollout intent.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};

use crate::klms::{KeyAlgorithm, KeyRegistry};

/// Errors a [`HardwareKeyStore`] implementation can return. Deliberately does not
/// implement `std::error::Error` (matching this codebase's existing lightweight
/// string/enum error style, e.g. `faitf::DRIError`) — callers needing interop with
/// `std::error::Error`-based code can wrap this at their boundary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HrtError {
    /// No key is registered under this key_id (or none of its versions are `Active`).
    UnknownKey(String),
    /// The key exists but is not usable for signing (e.g. an AES-256-GCM or HKDF key
    /// asked to produce an Ed25519 signature).
    WrongAlgorithm { key_id: String, algorithm: &'static str },
    /// Key material was the wrong length for the expected algorithm — should be
    /// unreachable given `klms::KeyDescriptor::new`'s own construction-time validation,
    /// but checked explicitly here rather than panicking on a slice-to-array conversion.
    MalformedKeyMaterial(String),
    /// Signature verification failed.
    VerificationFailed,
    /// A feature-gated hardware backend compiled in but not yet wired to real hardware —
    /// see the module doc comment.
    NotImplemented(&'static str),
}

impl std::fmt::Display for HrtError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownKey(id) => write!(f, "HRT: unknown or inactive key_id '{id}'"),
            Self::WrongAlgorithm { key_id, algorithm } =>
                write!(f, "HRT: key_id '{key_id}' is a {algorithm} key, not usable for this operation"),
            Self::MalformedKeyMaterial(id) => write!(f, "HRT: key_id '{id}' has malformed key material"),
            Self::VerificationFailed => write!(f, "HRT: signature verification failed"),
            Self::NotImplemented(backend) => write!(f, "HRT: {backend} backend is not implemented"),
        }
    }
}

/// Seam between "something signs a message with a named key" and the actual place that
/// key material lives. A named `key_id` (not raw key bytes) is the entire interface —
/// exactly what a real HSM API looks like (you ask the device to sign with slot N; you
/// never get the private key back), so [`SoftwareKeyStore`] and a genuine hardware-backed
/// implementation are interchangeable behind this trait with no caller-visible difference
/// beyond where the key material actually lives.
pub trait HardwareKeyStore: Send + Sync {
    /// Sign `message` with the key named `key_id`. Returns the raw signature bytes (64
    /// bytes for Ed25519).
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError>;
    /// Return the public key bytes (32 bytes for Ed25519) corresponding to `key_id`, so a
    /// caller can verify a signature (or distribute the public key) without ever handling
    /// private key material.
    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HrtError>;
}

/// Default, always-available [`HardwareKeyStore`]: signs using Ed25519 key material held
/// by a [`KeyRegistry`] in-process. See the module doc comment for the exact division of
/// responsibility with `klms.rs`.
pub struct SoftwareKeyStore {
    registry: Arc<KeyRegistry>,
}

impl SoftwareKeyStore {
    /// Wrap an existing `KeyRegistry` — typically the same one a `klms::KeyLifecycleManager`
    /// is already managing rotation/expiry for, so signing always uses whatever version is
    /// currently `Active`.
    pub fn new(registry: Arc<KeyRegistry>) -> Self {
        Self { registry }
    }

    fn active_ed25519_signing_key(&self, key_id: &str) -> Result<SigningKey, HrtError> {
        let desc = self.registry.get_active(key_id)
            .map_err(|_| HrtError::UnknownKey(key_id.to_string()))?;
        if desc.algorithm != KeyAlgorithm::Ed25519 {
            return Err(HrtError::WrongAlgorithm { key_id: key_id.to_string(), algorithm: desc.algorithm.value() });
        }
        let bytes: [u8; 32] = desc.key_material.as_slice().try_into()
            .map_err(|_| HrtError::MalformedKeyMaterial(key_id.to_string()))?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

impl HardwareKeyStore for SoftwareKeyStore {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError> {
        let signing_key = self.active_ed25519_signing_key(key_id)?;
        Ok(signing_key.sign(message).to_bytes().to_vec())
    }

    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HrtError> {
        let signing_key = self.active_ed25519_signing_key(key_id)?;
        Ok(signing_key.verifying_key().to_bytes().to_vec())
    }
}

/// Verify a `signature` (64 bytes) over `message` against a `public_key` (32 bytes)
/// returned by [`HardwareKeyStore::public_key`] — the read-only counterpart every caller
/// of `sign` eventually needs, kept as a free function since verification never touches
/// private key material and so has no reason to go through the trait.
pub fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<(), HrtError> {
    let pk_bytes: [u8; 32] = public_key.try_into()
        .map_err(|_| HrtError::MalformedKeyMaterial("<verify: public_key argument>".to_string()))?;
    let sig_bytes: [u8; 64] = signature.try_into()
        .map_err(|_| HrtError::MalformedKeyMaterial("<verify: signature argument>".to_string()))?;
    let vk = VerifyingKey::from_bytes(&pk_bytes)
        .map_err(|_| HrtError::MalformedKeyMaterial("<verify: public_key argument>".to_string()))?;
    let sig = Signature::from_bytes(&sig_bytes);
    vk.verify(message, &sig).map_err(|_| HrtError::VerificationFailed)
}

// ---------------------------------------------------------------------------
// Feature-gated hardware backend placeholders — see the module doc comment.
// ---------------------------------------------------------------------------

/// Compile-only placeholder for a TPM 2.0-backed [`HardwareKeyStore`]. Every operation
/// returns [`HrtError::NotImplemented`] — see the module doc comment for why real TPM
/// integration is out of scope for this pass.
#[cfg(feature = "hrt-tpm")]
pub struct TpmKeyStore;

#[cfg(feature = "hrt-tpm")]
impl HardwareKeyStore for TpmKeyStore {
    fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::NotImplemented("TPM"))
    }
    fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::NotImplemented("TPM"))
    }
}

/// Compile-only placeholder for an Intel SGX enclave-backed [`HardwareKeyStore`]. See
/// [`TpmKeyStore`]'s doc comment — identical rationale.
#[cfg(feature = "hrt-sgx")]
pub struct SgxKeyStore;

#[cfg(feature = "hrt-sgx")]
impl HardwareKeyStore for SgxKeyStore {
    fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::NotImplemented("SGX"))
    }
    fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::NotImplemented("SGX"))
    }
}

/// Compile-only placeholder for a PKCS#11-token-backed [`HardwareKeyStore`]. See
/// [`TpmKeyStore`]'s doc comment — identical rationale.
#[cfg(feature = "hrt-pkcs11")]
pub struct Pkcs11KeyStore;

#[cfg(feature = "hrt-pkcs11")]
impl HardwareKeyStore for Pkcs11KeyStore {
    fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::NotImplemented("PKCS#11"))
    }
    fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::NotImplemented("PKCS#11"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::klms::{make_descriptor, make_kid, KeyCategory};

    fn registry_with_ed25519_key() -> (Arc<KeyRegistry>, String) {
        use rand::RngCore;
        let mut material = vec![0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut material);
        let kid = make_kid();
        let reg = KeyRegistry::new();
        reg.register(
            make_descriptor(&kid, KeyAlgorithm::Ed25519, KeyCategory::Identity, material, None, None, None)
                .expect("valid descriptor")
        ).expect("register");
        (Arc::new(reg), kid)
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let (registry, kid) = registry_with_ed25519_key();
        let store = SoftwareKeyStore::new(registry);
        let pk = store.public_key(&kid).expect("public_key");
        let sig = store.sign(&kid, b"hello hrt").expect("sign");
        assert_eq!(sig.len(), 64);
        assert_eq!(pk.len(), 32);
        verify(&pk, b"hello hrt", &sig).expect("verify must succeed for a genuine signature");
    }

    #[test]
    fn verify_rejects_tampered_message() {
        let (registry, kid) = registry_with_ed25519_key();
        let store = SoftwareKeyStore::new(registry);
        let pk = store.public_key(&kid).expect("public_key");
        let sig = store.sign(&kid, b"original").expect("sign");
        assert!(verify(&pk, b"tampered", &sig).is_err());
    }

    #[test]
    fn unknown_key_id_is_rejected() {
        let store = SoftwareKeyStore::new(Arc::new(KeyRegistry::new()));
        assert_eq!(store.sign("does-not-exist", b"x"), Err(HrtError::UnknownKey("does-not-exist".to_string())));
        assert_eq!(store.public_key("does-not-exist"), Err(HrtError::UnknownKey("does-not-exist".to_string())));
    }

    #[test]
    fn wrong_algorithm_key_is_rejected() {
        let kid = make_kid();
        let reg = KeyRegistry::new();
        reg.register(
            make_descriptor(&kid, KeyAlgorithm::Aes256Gcm, KeyCategory::EpochTraffic, vec![0u8; 32], None, None, None)
                .expect("valid descriptor")
        ).expect("register");
        let store = SoftwareKeyStore::new(Arc::new(reg));
        assert_eq!(
            store.sign(&kid, b"x"),
            Err(HrtError::WrongAlgorithm { key_id: kid.clone(), algorithm: KeyAlgorithm::Aes256Gcm.value() })
        );
    }

    #[test]
    fn two_key_ids_produce_independent_signatures() {
        let (registry, kid_a) = registry_with_ed25519_key();
        // Register a second, independent key in the SAME registry.
        let kid_b = make_kid();
        {
            use rand::RngCore;
            let mut material = vec![0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut material);
            registry.register(
                make_descriptor(&kid_b, KeyAlgorithm::Ed25519, KeyCategory::Identity, material, None, None, None)
                    .expect("valid descriptor")
            ).expect("register");
        }
        let store = SoftwareKeyStore::new(registry);
        let pk_a = store.public_key(&kid_a).expect("pk a");
        let pk_b = store.public_key(&kid_b).expect("pk b");
        assert_ne!(pk_a, pk_b, "distinct key_ids must have distinct key material");

        let sig_a = store.sign(&kid_a, b"same message").expect("sign a");
        // A signature made with key A's private key must not verify against key B's
        // public key — proves `sign` genuinely used the named key_id's own material,
        // not e.g. a single process-wide default key.
        assert!(verify(&pk_b, b"same message", &sig_a).is_err());
        assert!(verify(&pk_a, b"same message", &sig_a).is_ok());
    }
}
