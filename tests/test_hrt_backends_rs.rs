//! Integration coverage for hardware-backed signing (`src/hrt/`).
//!
//! These tests assert the properties that unit tests inside the modules cannot: that a
//! credential signed through the `HardwareKeyStore` seam is **byte-for-byte
//! interchangeable** with one signed by an in-process key, and verifies through each
//! subsystem's own real verification path.
//!
//! That interchangeability is the whole premise of the migration. If a hardware-issued
//! certificate did not verify identically, every deployment that switched to an HSM
//! would silently lock itself out of its own trust hierarchy — and the failure would
//! appear at the verifier, far from the signing change that caused it.
//!
//! No real HSM is needed. A `RecordingKeyStore` implements `HardwareKeyStore` over an
//! ordinary in-memory Ed25519 key, which is exactly what a correct PKCS#11/KMS backend
//! is indistinguishable from at this seam: the trait's entire contract is "given a
//! key_id and a message, return a valid 64-byte Ed25519 signature".

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use saacp::hrt::{HardwareKeyStore, HrtError};

/// A `HardwareKeyStore` over an in-process key, standing in for a real token.
///
/// Also counts calls, so tests can assert the caching behavior the real backends rely on
/// to avoid a network round-trip per issuance.
struct RecordingKeyStore {
    key: SigningKey,
    expected_key_id: String,
    sign_calls: AtomicUsize,
    public_key_calls: AtomicUsize,
}

impl RecordingKeyStore {
    fn new(key_id: &str) -> Self {
        Self {
            key: SigningKey::generate(&mut rand::rngs::OsRng),
            expected_key_id: key_id.to_string(),
            sign_calls: AtomicUsize::new(0),
            public_key_calls: AtomicUsize::new(0),
        }
    }

    fn verifying_key(&self) -> VerifyingKey {
        self.key.verifying_key()
    }
}

impl HardwareKeyStore for RecordingKeyStore {
    fn sign(&self, key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError> {
        self.sign_calls.fetch_add(1, Ordering::SeqCst);
        // A real token resolves by label/ARN and fails on an unknown one; model that, so
        // a call site passing the wrong id is caught here rather than silently signing.
        if key_id != self.expected_key_id {
            return Err(HrtError::UnknownKey(key_id.to_string()));
        }
        Ok(self.key.sign(message).to_bytes().to_vec())
    }

    fn public_key(&self, key_id: &str) -> Result<Vec<u8>, HrtError> {
        self.public_key_calls.fetch_add(1, Ordering::SeqCst);
        if key_id != self.expected_key_id {
            return Err(HrtError::UnknownKey(key_id.to_string()));
        }
        Ok(self.key.verifying_key().to_bytes().to_vec())
    }
}

/// A store whose signing always fails, modelling an HSM that is unreachable, whose IAM
/// policy denies `kms:Sign`, or whose token has been physically removed.
struct FailingKeyStore;

impl HardwareKeyStore for FailingKeyStore {
    fn sign(&self, _key_id: &str, _message: &[u8]) -> Result<Vec<u8>, HrtError> {
        Err(HrtError::Backend { backend: "test", detail: "HSM unreachable".to_string() })
    }
    fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, HrtError> {
        Ok(SigningKey::generate(&mut rand::rngs::OsRng).verifying_key().to_bytes().to_vec())
    }
}

// ---------------------------------------------------------------------------
// identity_binding — the CA path
// ---------------------------------------------------------------------------

#[test]
fn a_hardware_signed_certificate_verifies_through_the_real_identity_verifier() {
    use saacp::identity_binding::{AgentIdentityCertificate, IdentityVerifier};

    let store = Arc::new(RecordingKeyStore::new("ca-key"));
    let agent_key = SigningKey::generate(&mut rand::rngs::OsRng);
    let agent_pub_hex = hex::encode(agent_key.verifying_key().to_bytes());

    let cert = AgentIdentityCertificate::issue_with_keystore(
        "agent-alpha",
        &agent_pub_hex,
        store.as_ref(),
        "ca-key",
        "ca-kid-1",
        "issuer-1",
        3600.0,
        "ed25519",
    )
    .expect("hardware-backed CA issuance must succeed");

    // The load-bearing assertion: verification goes through the ordinary path, with no
    // knowledge that the key was hardware-held.
    let verifier = IdentityVerifier::new();
    verifier.register_ca_key("ca-kid-1", store.verifying_key());
    assert!(
        verifier.verify_certificate(&cert).is_ok(),
        "a certificate signed via HardwareKeyStore must verify exactly like a \
         software-signed one — otherwise adopting an HSM breaks the trust hierarchy"
    );
    assert_eq!(cert.cert_signature.len(), 64);
}

#[test]
fn a_certificate_signed_by_the_wrong_hardware_key_is_rejected() {
    use saacp::identity_binding::{AgentIdentityCertificate, IdentityVerifier};

    let store = Arc::new(RecordingKeyStore::new("ca-key"));
    let agent_key = SigningKey::generate(&mut rand::rngs::OsRng);

    let cert = AgentIdentityCertificate::issue_with_keystore(
        "agent-alpha",
        &hex::encode(agent_key.verifying_key().to_bytes()),
        store.as_ref(),
        "ca-key",
        "ca-kid-1",
        "issuer-1",
        3600.0,
        "ed25519",
    )
    .unwrap();

    // Register a DIFFERENT CA public key: proves the signature is genuinely bound to the
    // store's key and the verifier is not accepting it structurally.
    let verifier = IdentityVerifier::new();
    let unrelated = SigningKey::generate(&mut rand::rngs::OsRng).verifying_key();
    verifier.register_ca_key("ca-kid-1", unrelated);
    assert!(verifier.verify_certificate(&cert).is_err());
}

#[test]
fn an_unknown_hardware_key_id_fails_issuance_instead_of_producing_an_unsigned_cert() {
    use saacp::identity_binding::AgentIdentityCertificate;

    let store = RecordingKeyStore::new("ca-key");
    let result = AgentIdentityCertificate::issue_with_keystore(
        "agent-alpha",
        &hex::encode([0u8; 32]),
        &store,
        "a-key-that-does-not-exist",
        "ca-kid-1",
        "issuer-1",
        3600.0,
        "ed25519",
    );
    assert!(
        matches!(result, Err(HrtError::UnknownKey(_))),
        "a bad key id must fail loudly, never yield a certificate with an empty signature"
    );
}

// ---------------------------------------------------------------------------
// acsvaf — capability issuance
// ---------------------------------------------------------------------------

#[test]
fn hardware_issued_capability_tokens_verify_and_match_the_software_path() {
    use saacp::acsvaf::CapabilityIssuanceAuthority;
    use serde_json::{Map, Value};

    let store = Arc::new(RecordingKeyStore::new("cap-key"));
    let authority = CapabilityIssuanceAuthority::with_keystore(
        store.clone(),
        "cap-key",
        "ed25519-v1-test",
        "issuer-hsm",
    )
    .expect("construction must succeed and fetch the public key once");

    // The public key is fetched exactly once, at construction — not per issuance. On a
    // real KMS this is the difference between one round-trip and one per token.
    assert_eq!(store.public_key_calls.load(Ordering::SeqCst), 1);

    let mut claims = Map::new();
    claims.insert("sub".to_string(), Value::String("agent-beta".to_string()));
    claims.insert("scope".to_string(), Value::String("read".to_string()));

    let token = authority.issue(claims.clone()).expect("issuance must succeed");
    assert_eq!(store.sign_calls.load(Ordering::SeqCst), 1);
    assert_eq!(authority.kid(), "ed25519-v1-test");
    assert_eq!(authority.issuer_id(), "issuer-hsm");
    assert_eq!(*authority.public_key(), store.verifying_key());

    // Issuing more tokens must not re-fetch the public key.
    let _ = authority.issue(claims).expect("second issuance");
    assert_eq!(
        store.public_key_calls.load(Ordering::SeqCst),
        1,
        "the public key is immutable and must be cached, not re-fetched per token"
    );

    // The signature verifies against the authority's advertised public key.
    use ed25519_dalek::{Signature, Verifier};
    let signed_bytes = {
        // Same canonical form the authority signs: sorted-key JSON.
        let sorted: std::collections::BTreeMap<_, _> = token.claims.iter().collect();
        serde_json::to_vec(&sorted).unwrap()
    };
    assert!(
        store
            .verifying_key()
            .verify(&signed_bytes, &Signature::from_bytes(&token.signature))
            .is_ok(),
        "a hardware-issued capability token must verify against the issuer public key"
    );
}

#[test]
fn an_unreachable_hsm_blocks_capability_issuance_rather_than_failing_open() {
    use saacp::acsvaf::CapabilityIssuanceAuthority;
    use serde_json::Map;

    let authority = CapabilityIssuanceAuthority::with_keystore(
        Arc::new(FailingKeyStore),
        "any",
        "kid",
        "issuer",
    )
    .expect("construction succeeds; this store only fails on sign");

    let result = authority.issue(Map::new());
    assert!(
        result.is_err(),
        "if the HSM cannot sign, issuance must fail closed — never emit an unsigned or \
         differently-keyed token"
    );
}

// ---------------------------------------------------------------------------
// faitf — issuer credentials
// ---------------------------------------------------------------------------

#[test]
fn a_hardware_issued_credential_is_identical_to_a_software_issued_one() {
    use saacp::faitf::{AgentCredential, AgentIdentity, AttestationType};

    let identity = AgentIdentity::generate(
        "agent-gamma",
        "issuer-1",
        3600,
        None,
        None,
        "none",
        AttestationType::None,
    );
    let issuer = SigningKey::generate(&mut rand::rngs::OsRng);
    let issuer_vk = issuer.verifying_key();

    // A store holding the *same* key as the software path, so the two must agree byte
    // for byte. This is the strongest available statement of interchangeability: the
    // hardware seam changes where the key lives, and nothing else.
    struct FixedKeyStore(SigningKey);
    impl HardwareKeyStore for FixedKeyStore {
        fn sign(&self, _key_id: &str, message: &[u8]) -> Result<Vec<u8>, HrtError> {
            Ok(self.0.sign(message).to_bytes().to_vec())
        }
        fn public_key(&self, _key_id: &str) -> Result<Vec<u8>, HrtError> {
            Ok(self.0.verifying_key().to_bytes().to_vec())
        }
    }

    let software = AgentCredential::issue(&identity, &issuer, &issuer_vk);
    let hardware = AgentCredential::issue_with_keystore(
        &identity,
        &FixedKeyStore(issuer.clone()),
        "issuer-key",
        &issuer_vk,
    )
    .expect("hardware issuance must succeed");

    assert_eq!(
        software.signature, hardware.signature,
        "the same key must produce the same signature regardless of which path signed — \
         any difference means the two paths canonicalize the payload differently"
    );
    assert_eq!(software.issuer_public_key_id, hardware.issuer_public_key_id);
    assert_eq!(software.payload, hardware.payload);
}

// ---------------------------------------------------------------------------
// aca — attestation
// ---------------------------------------------------------------------------

#[test]
fn hardware_backed_attestation_claims_verify() {
    use saacp::aca::{AttestationAuthority, AttestationRegistry, SafetyLevel};

    let store = Arc::new(RecordingKeyStore::new("attest-key"));
    let authority = AttestationAuthority::with_keystore(store.clone(), "attest-key")
        .expect("construction must fetch the public key");

    assert_eq!(
        authority.verifying_key(),
        store.verifying_key(),
        "the authority must advertise the hardware key's real public key"
    );

    let claim = authority
        .try_issue("agent-delta", SafetyLevel::AlignedModel, "prod-enclave", 600)
        .expect("hardware-backed attestation issuance must succeed");
    assert_eq!(claim.operator_signature.len(), 64);

    // Verified through the production path — `install_claim` re-derives the canonical
    // body and checks the Ed25519 signature against the trusted operator key.
    let registry = AttestationRegistry::new();
    registry.trust_operator(store.verifying_key());
    assert!(
        registry.install_claim(claim).is_ok(),
        "a hardware-signed attestation claim must be accepted by the real registry"
    );
}

#[test]
fn a_failing_hsm_surfaces_an_error_from_try_issue() {
    use saacp::aca::{AttestationAuthority, SafetyLevel};

    let authority = AttestationAuthority::with_keystore(Arc::new(FailingKeyStore), "k").unwrap();
    assert!(
        authority
            .try_issue("agent", SafetyLevel::AlignedModel, "env", 60)
            .is_err(),
        "try_issue must report a backend failure rather than panicking or forging a claim"
    );
}
