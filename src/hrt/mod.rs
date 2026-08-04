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
//! Per Phase 6 item 8's original "(trait abstraction)" scope note, this module once
//! shipped the trait and a software default only. It no longer does: [`pkcs11`],
//! [`aws_kms`], and [`gcp_kms`] are real, working backends, each behind its own Cargo
//! feature and off by default. `TpmKeyStore`/`SgxKeyStore` remain feature-gated
//! compile-only placeholders (`hrt-tpm`/`hrt-sgx`) that return
//! [`HrtError::NotImplemented`] — unlike PKCS#11 and the cloud KMSes, neither has a
//! maintained integration path that can be implemented *and tested* here.
//!
//! ## Which call sites use this
//!
//! The credential-issuance paths — the long-lived keys whose compromise is permanent and
//! silent — can now be hardware-backed, each through an additive constructor that leaves
//! the original software API untouched:
//!
//! - [`crate::identity_binding::AgentIdentityCertificate::issue_with_keystore`] — the CA
//!   key, the root of the identity hierarchy and the highest-value key in the crate.
//! - [`crate::acsvaf::CapabilityIssuanceAuthority::with_keystore`] — the key that
//!   authorizes every action any agent may take.
//! - [`crate::faitf::AgentCredential::issue_with_keystore`] — the issuer key (and only
//!   the issuer key; see that method's doc for why an agent's own key is not a
//!   candidate).
//! - [`crate::aca::AttestationAuthority::with_keystore`] — the operator attestation key.
//!
//! Deliberately *not* migrated: per-session ephemeral keys and the two `daemon.rs`
//! handshake paths. Those are per-connection operations on the data plane, where a
//! network KMS round-trip per handshake would be a self-inflicted latency and
//! availability problem; the keys involved are also short-lived, which is most of what
//! hardware storage is protecting against in the first place.

use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, Signature};

use crate::klms::{KeyAlgorithm, KeyRegistry};

// ---------------------------------------------------------------------------
// Backend submodules
// ---------------------------------------------------------------------------

/// Synchronous-to-asynchronous bridge shared by the cloud KMS backends. Compiled
/// whenever either cloud backend is enabled; PKCS#11 does not need it (`cryptoki`
/// is natively synchronous).
#[cfg(any(feature = "hrt-aws-kms", feature = "hrt-gcp-kms"))]
pub mod remote;

/// PKCS#11 (Cryptoki) hardware token / network HSM backend.
#[cfg(feature = "hrt-pkcs11")]
pub mod pkcs11;

/// AWS KMS backend.
#[cfg(feature = "hrt-aws-kms")]
pub mod aws_kms;

/// Google Cloud KMS backend.
#[cfg(feature = "hrt-gcp-kms")]
pub mod gcp_kms;


/// Errors a [`HardwareKeyStore`] implementation can return.
///
/// Implements `std::error::Error` (unlike the lighter `faitf::DRIError` style used
/// elsewhere in this crate) because the real hardware backends interoperate with
/// third-party SDK error types that expect it. `Backend`/`Configuration` carry an
/// owned `String` rather than a `&'static str` for the same reason: the detail comes
/// from a vendor SDK at runtime.
///
/// These strings are for operator logs only. Nothing here reaches a protocol peer
/// directly — a signing failure surfaces on the wire through `pecf.rs`'s
/// error-confidentiality filter like every other internal fault, so a KMS IAM message
/// can never leak to a remote agent.
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
    /// The backend was reachable but the operation failed (PKCS#11 `CKR_*` error, a KMS
    /// API error, a denied IAM policy). `detail` is the backend's own message, kept for
    /// operator logs — it is never surfaced to a protocol peer, since `hrt.rs` sits
    /// behind the `pecf.rs` error-confidentiality filter like every other subsystem.
    Backend { backend: &'static str, detail: String },
    /// The backend did not answer within the configured timeout. Distinct from
    /// [`Self::Backend`] because it is the one failure a caller may sensibly retry:
    /// a network KMS can be transiently slow, whereas a `CKR_KEY_HANDLE_INVALID`
    /// will fail identically forever.
    Timeout { backend: &'static str },
    /// The keystore could not be constructed from the supplied configuration (missing
    /// module path, unreadable PIN file, malformed key identifier). Always fatal at
    /// startup — a misconfigured HSM must never silently degrade to software keys.
    Configuration(String),
    /// The backend returned a signature or public key that was not the size Ed25519
    /// requires. Treated as a hard failure rather than passed through: a truncated
    /// signature would fail verification much later, somewhere far less diagnosable.
    MalformedResponse { backend: &'static str, expected: usize, got: usize },
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
            Self::Backend { backend, detail } => write!(f, "HRT: {backend} backend error: {detail}"),
            Self::Timeout { backend } => write!(f, "HRT: {backend} backend timed out"),
            Self::Configuration(detail) => write!(f, "HRT: misconfigured key store: {detail}"),
            Self::MalformedResponse { backend, expected, got } => write!(
                f,
                "HRT: {backend} backend returned {got} bytes where Ed25519 requires {expected}"
            ),
        }
    }
}

impl std::error::Error for HrtError {}

/// Raw Ed25519 signature length. Every backend must return exactly this.
pub const ED25519_SIGNATURE_LEN: usize = 64;
/// Raw Ed25519 public key length.
pub const ED25519_PUBLIC_KEY_LEN: usize = 32;

/// DER prefix of an Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4).
///
/// Both AWS KMS `GetPublicKey` and GCP KMS `GetPublicKey` hand back an SPKI
/// structure rather than the bare 32-byte point, so both backends need to strip
/// this exact 12-byte header. Spelled out byte-by-byte because an off-by-one here
/// yields a public key that silently fails every verification:
///
/// ```text
/// 30 2A                          SEQUENCE (42 bytes)
///   30 05                        SEQUENCE (5 bytes)  -- AlgorithmIdentifier
///     06 03 2B 65 70             OID 1.3.101.112     -- id-Ed25519
///   03 21 00                     BIT STRING (33 bytes, 0 unused bits)
///     <32 bytes of public key>
/// ```
pub const ED25519_SPKI_PREFIX: [u8; 12] =
    [0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00];

/// Extract the raw 32-byte Ed25519 public key from a DER `SubjectPublicKeyInfo`.
///
/// Shared by the AWS and GCP KMS backends. Validates the full prefix rather than
/// blindly slicing the last 32 bytes: if a provider ever returns a key for a
/// *different* algorithm (an operator pointing at an ECDSA P-256 key by mistake is
/// the realistic case), that must be a loud configuration error, not a 32-byte
/// tail that looks plausible and fails verification much later.
pub fn ed25519_public_key_from_spki(der: &[u8], backend: &'static str) -> Result<Vec<u8>, HrtError> {
    let expected = ED25519_SPKI_PREFIX.len() + ED25519_PUBLIC_KEY_LEN;
    if der.len() != expected {
        return Err(HrtError::MalformedResponse { backend, expected, got: der.len() });
    }
    if der[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(HrtError::Backend {
            backend,
            detail: "GetPublicKey returned a SubjectPublicKeyInfo that is not id-Ed25519 \
                     (1.3.101.112) — the configured key is not an Ed25519 signing key"
                .to_string(),
        });
    }
    Ok(der[ED25519_SPKI_PREFIX.len()..].to_vec())
}

/// Check a backend's signature is exactly 64 bytes before handing it upward.
///
/// Only referenced by the feature-gated backends, so it is unused in a default build.
#[cfg(any(feature = "hrt-pkcs11", feature = "hrt-aws-kms", feature = "hrt-gcp-kms"))]
fn check_signature_len(sig: Vec<u8>, backend: &'static str) -> Result<Vec<u8>, HrtError> {
    if sig.len() != ED25519_SIGNATURE_LEN {
        return Err(HrtError::MalformedResponse {
            backend,
            expected: ED25519_SIGNATURE_LEN,
            got: sig.len(),
        });
    }
    Ok(sig)
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

// NOTE: there is no `Pkcs11KeyStore` placeholder here. The real implementation lives in
// [`pkcs11`] and is re-exported from `lib.rs` under the same name — a stub alongside it
// would be a name collision that resolves to whichever the caller imported, and a
// deployment that accidentally got the stub would see every signature fail at runtime
// with NotImplemented.

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
