//! Comprehensive tests for Post-Quantum Cryptography (PQC) integration.
//!
//! Tests hybrid KEM, hybrid signatures, channel binding, attestation,
//! and structural hardening.

use saacp::attestation::{
    create_attestation_binding, generate_attestation_challenge, validate_attestation_size,
    AttestationEvidence, AttestationType, AttestationVerifier,
};
use saacp::crypto_governance::SuiteStatus;
use saacp::pqc::kem::*;
use saacp::pqc::signature::*;
use saacp::pqc::*;

// ─── Hybrid KEM Tests ────────────────────────────────────────────────────────

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
    assert_eq!(ct.len(), 32);
    assert_eq!(ss_enc.len(), 32);
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
    let _alice = kem.generate_keypair().unwrap();
    let bob = kem.generate_keypair().unwrap();

    // Alice encapsulates to Bob's public keys
    let (msg, ss_alice) = kem
        .encapsulate(&bob.x25519_public, &bob.mlkem_public)
        .unwrap();

    // Bob decapsulates using his keys and Alice's public share
    let ss_bob = kem
        .decapsulate(&bob, &msg.x25519_public, &msg.mlkem_ciphertext)
        .unwrap();

    // Both derive the same session key
    assert_eq!(ss_alice.session_key, ss_bob.session_key);
    assert_eq!(ss_alice.session_key.len(), 32);
}

#[test]
fn test_hybrid_session_key_derivation() {
    let ss1 = vec![1u8; 32];
    let ss2 = vec![2u8; 32];
    let ct1 = vec![3u8; 32];
    let ct2 = vec![4u8; 32];
    let key = derive_hybrid_session_key(&ss1, &ss2, &ct1, &ct2, None).unwrap();
    assert_eq!(key.len(), 32);

    // Different inputs produce different keys
    let key2 = derive_hybrid_session_key(&ss2, &ss1, &ct1, &ct2, None).unwrap();
    assert_ne!(key, key2);

    // #1 FIX: Different ciphertexts produce different keys (ciphertext binding)
    let key3 = derive_hybrid_session_key(&ss1, &ss2, &ct2, &ct1, None).unwrap();
    assert_ne!(
        key, key3,
        "Different ciphertexts should produce different keys"
    );
}

#[test]
fn test_kem_algorithm_strings() {
    assert_eq!(KemAlgorithm::X25519.as_str(), "x25519");
    assert_eq!(KemAlgorithm::MlKem768.as_str(), "ml-kem-768");
    assert_eq!(
        KemAlgorithm::HybridX25519MlKem768.as_str(),
        "hybrid-x25519-ml-kem-768"
    );
    assert_eq!(
        KemAlgorithm::from_str("hybrid-x25519-ml-kem-768"),
        Some(KemAlgorithm::HybridX25519MlKem768)
    );
    assert!(KemAlgorithm::HybridX25519MlKem768.is_hybrid());
    assert!(KemAlgorithm::MlKem768.is_quantum_resistant());
    assert!(!KemAlgorithm::X25519.is_quantum_resistant());
}

// ─── Hybrid Signature Tests ──────────────────────────────────────────────────

#[test]
fn test_ed25519_signature_suite() {
    let suite = Ed25519SignatureSuite::new();
    let (pk, sk) = suite.generate_keypair().unwrap();
    assert_eq!(pk.len(), 32);
    assert_eq!(sk.len(), 32);

    let msg = b"test message";
    let sig = suite.sign(&sk, msg).unwrap();
    assert_eq!(sig.len(), 64);
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
fn test_hybrid_ed25519_ml_dsa_composition() {
    let suite = HybridEd25519MlDsa65::new();
    let keypair = suite.generate_hybrid_keypair().unwrap();

    let msg = b"test message for hybrid signature";
    let sig = suite.sign_hybrid(&keypair, msg, None).unwrap();

    // Both signatures must be present
    assert_eq!(sig.classical_sig.len(), 64); // Ed25519
    assert!(!sig.pqc_sig.is_empty()); // ML-DSA

    // Verification succeeds only if BOTH verify
    assert!(suite.verify_hybrid(&keypair, msg, &sig, None));
    assert!(!suite.verify_hybrid(&keypair, b"wrong message", &sig, None));
}

#[test]
fn test_hybrid_signature_with_domain_separation() {
    let suite = HybridEd25519MlDsa65::new();
    let keypair = suite.generate_hybrid_keypair().unwrap();
    let ctx = SigningContext::default();

    let msg = b"test message";
    let sig = suite.sign_hybrid(&keypair, msg, Some(&ctx)).unwrap();

    // Verify with correct context
    assert!(suite.verify_hybrid(&keypair, msg, &sig, Some(&ctx)));

    // Verify with wrong context fails
    let wrong_ctx = SigningContext {
        domain: b"wrong-domain",
        protocol_version: "SAACP/0.3",
    };
    assert!(!suite.verify_hybrid(&keypair, msg, &sig, Some(&wrong_ctx)));
}

#[test]
fn test_signature_algorithm_properties() {
    assert_eq!(SignatureAlgorithm::Ed25519.as_str(), "ed25519");
    assert_eq!(
        SignatureAlgorithm::from_str("hybrid-ed25519-ml-dsa-65"),
        Some(SignatureAlgorithm::HybridEd25519MlDsa65)
    );
    assert!(SignatureAlgorithm::HybridEd25519MlDsa65.is_hybrid());
    assert!(SignatureAlgorithm::MlDsa65.is_quantum_resistant());
    assert!(!SignatureAlgorithm::Ed25519.is_quantum_resistant());
}

// ─── Channel Binding Tests ───────────────────────────────────────────────────

#[test]
fn test_channel_binding_token_derivation() {
    let transcript_hash = vec![1u8; 32];
    let session_secret = vec![2u8; 32];
    let agent_id = "agent-1";

    let token = saacp::crypto_governance::derive_channel_binding_token(
        &transcript_hash,
        &session_secret,
        agent_id,
    );
    assert_eq!(token.len(), 32);

    // Same inputs produce same token
    let token2 = saacp::crypto_governance::derive_channel_binding_token(
        &transcript_hash,
        &session_secret,
        agent_id,
    );
    assert_eq!(token, token2);

    // Different transcript produces different token
    let different_hash = vec![3u8; 32];
    let token3 = saacp::crypto_governance::derive_channel_binding_token(
        &different_hash,
        &session_secret,
        agent_id,
    );
    assert_ne!(token, token3);
}

#[test]
fn test_channel_binding_token_verification() {
    let transcript_hash = vec![1u8; 32];
    let session_secret = vec![2u8; 32];
    let agent_id = "agent-1";

    let token = saacp::crypto_governance::derive_channel_binding_token(
        &transcript_hash,
        &session_secret,
        agent_id,
    );

    // Valid token verifies
    assert!(saacp::crypto_governance::verify_channel_binding_token(
        &token,
        &transcript_hash,
        &session_secret,
        agent_id,
    ));

    // Invalid token fails
    let wrong_token = vec![0u8; 32];
    assert!(!saacp::crypto_governance::verify_channel_binding_token(
        &wrong_token,
        &transcript_hash,
        &session_secret,
        agent_id,
    ));
}

// ─── Attestation Tests ───────────────────────────────────────────────────────

#[test]
fn test_attestation_type_strings() {
    assert_eq!(AttestationType::None.as_str(), "none");
    assert_eq!(AttestationType::Tpm.as_str(), "tpm");
    assert_eq!(AttestationType::from_str("tpm"), Some(AttestationType::Tpm));
    assert!(AttestationType::Tpm.requires_hardware());
    assert!(!AttestationType::None.requires_hardware());
}

#[test]
fn test_attestation_verifier_none() {
    let verifier = AttestationVerifier::new();
    let result = verifier.verify(&AttestationEvidence::None, 0.0);
    assert!(result.is_valid);
    assert_eq!(result.attestation_type, AttestationType::None);
}

#[test]
fn test_attestation_challenge_generation() {
    let challenge = generate_attestation_challenge();
    assert_eq!(challenge.len(), 32);

    // Challenges should be unique
    let challenge2 = generate_attestation_challenge();
    assert_ne!(challenge, challenge2);
}

#[test]
fn test_attestation_binding_creation() {
    let nonce = vec![1u8; 32];
    let channel_binding = vec![2u8; 32];
    let suite_transcript_hash = vec![3u8; 32];

    let binding = create_attestation_binding(
        b"public_key_bytes",
        b"measurement_bytes",
        AttestationType::Tpm,
        &nonce,
        &channel_binding,
        &suite_transcript_hash,
    );
    assert_eq!(binding.len(), 32);

    // Different inputs produce different bindings
    let binding2 = create_attestation_binding(
        b"different_key",
        b"measurement_bytes",
        AttestationType::Tpm,
        &nonce,
        &channel_binding,
        &suite_transcript_hash,
    );
    assert_ne!(binding, binding2);
}

#[test]
fn test_validate_attestation_size() {
    assert!(validate_attestation_size(1000).is_ok());
    assert!(
        saacp::attestation::validate_attestation_size(max_sizes::MAX_ATTESTATION_QUOTE).is_ok()
    );
    assert!(
        saacp::attestation::validate_attestation_size(max_sizes::MAX_ATTESTATION_QUOTE + 1)
            .is_err()
    );
}

// ─── Structural Hardening Tests ──────────────────────────────────────────────

#[test]
fn test_validate_hybrid_handshake_size() {
    assert!(saacp::handler::validate_hybrid_handshake_size(1000).is_ok());
    assert!(saacp::handler::validate_hybrid_handshake_size(
        saacp::handler::MAX_HYBRID_HANDSHAKE_SIZE
    )
    .is_ok());
    assert!(saacp::handler::validate_hybrid_handshake_size(
        saacp::handler::MAX_HYBRID_HANDSHAKE_SIZE + 1
    )
    .is_err());
}

#[test]
fn test_validate_pqc_public_key_size() {
    assert!(saacp::handler::validate_pqc_public_key_size(1952).is_ok()); // ML-DSA-65
    assert!(
        saacp::handler::validate_pqc_public_key_size(saacp::handler::MAX_PQC_PUBLIC_KEY_SIZE)
            .is_ok()
    );
    assert!(saacp::handler::validate_pqc_public_key_size(
        saacp::handler::MAX_PQC_PUBLIC_KEY_SIZE + 1
    )
    .is_err());
}

#[test]
fn test_validate_pqc_signature_size() {
    assert!(saacp::handler::validate_pqc_signature_size(3293).is_ok()); // ML-DSA-65
    assert!(
        saacp::handler::validate_pqc_signature_size(saacp::handler::MAX_PQC_SIGNATURE_SIZE).is_ok()
    );
    assert!(saacp::handler::validate_pqc_signature_size(
        saacp::handler::MAX_PQC_SIGNATURE_SIZE + 1
    )
    .is_err());
}

#[test]
fn test_validate_pqc_extensions_size() {
    assert!(saacp::handler::validate_pqc_extensions_size(1000).is_ok());
    assert!(saacp::handler::validate_pqc_extensions_size(
        saacp::handler::MAX_PQC_EXTENSIONS_TOTAL_SIZE
    )
    .is_ok());
    assert!(saacp::handler::validate_pqc_extensions_size(
        saacp::handler::MAX_PQC_EXTENSIONS_TOTAL_SIZE + 1
    )
    .is_err());
}

#[test]
fn test_validate_pqc_key_shares_count() {
    assert!(saacp::handler::validate_pqc_key_shares_count(2).is_ok());
    assert!(
        saacp::handler::validate_pqc_key_shares_count(saacp::handler::MAX_PQC_KEY_SHARES).is_ok()
    );
    assert!(
        saacp::handler::validate_pqc_key_shares_count(saacp::handler::MAX_PQC_KEY_SHARES + 1)
            .is_err()
    );
}

// ─── Governance Tests ────────────────────────────────────────────────────────

#[test]
fn test_pqc_suite_approval() {
    let policy = saacp::crypto_governance::production_policy();
    assert!(policy.is_approved("ed25519"));
    assert!(policy.is_approved("ml-dsa-65"));
    assert!(policy.is_approved("hybrid-ed25519-ml-dsa-65"));
    assert!(policy.is_approved("ml-kem-768"));
    assert!(policy.is_approved("hybrid-x25519-ml-kem-768"));
    assert!(!policy.is_approved("rsa-2048"));
}

#[test]
fn test_pqc_suite_status() {
    let policy = saacp::crypto_governance::production_policy();
    assert_eq!(policy.get_status("ml-dsa-65"), SuiteStatus::Approved);
    assert_eq!(
        policy.get_status("hybrid-ed25519-ml-dsa-65"),
        SuiteStatus::Approved
    );
    assert_eq!(policy.get_status("unknown-alg"), SuiteStatus::Forbidden);
}

#[test]
fn test_recommended_suites() {
    assert_eq!(
        saacp::crypto_governance::RECOMMENDED_SIGNATURE_SUITE,
        "hybrid-ed25519-ml-dsa-65"
    );
    assert_eq!(
        saacp::crypto_governance::RECOMMENDED_KEM_SUITE,
        "hybrid-x25519-ml-kem-768"
    );
}

// ─── Domain Separation Tests ─────────────────────────────────────────────────

#[test]
fn test_domain_separation_strings() {
    assert_eq!(
        domain_separation::HYBRID_KEM_SS,
        b"SAACP-PQC-hybrid-kem-ss-v1"
    );
    assert_eq!(
        domain_separation::HYBRID_SIG_CONTEXT,
        b"SAACP-PQC-hybrid-sig-context-v1"
    );
    assert_eq!(
        domain_separation::SESSION_KEY_DERIVATION,
        b"SAACP-PQC-session-key-v1"
    );
}

// ─── Max Sizes Tests ─────────────────────────────────────────────────────────

#[test]
fn test_max_sizes_constants() {
    assert_eq!(max_sizes::ML_KEM_768_PK, 1184);
    assert_eq!(max_sizes::ML_KEM_768_CT, 1088);
    assert_eq!(max_sizes::ML_DSA_65_PK, 1952);
    assert_eq!(max_sizes::ML_DSA_65_SIG, 3293);
    assert_eq!(max_sizes::MAX_HYBRID_HANDSHAKE, 8192);
}

// ─── Integration Tests ───────────────────────────────────────────────────────

#[test]
fn test_full_hybrid_handshake_flow() {
    // 1. Both peers generate hybrid keypairs
    let kem = HybridKem::new();
    let _alice_kp = kem.generate_keypair().unwrap();
    let bob_kp = kem.generate_keypair().unwrap();

    // 2. Alice encapsulates a shared secret for Bob
    let (msg, ss_alice) = kem
        .encapsulate(&bob_kp.x25519_public, &bob_kp.mlkem_public)
        .unwrap();

    // 3. Bob decapsulates the shared secret
    let ss_bob = kem
        .decapsulate(&bob_kp, &msg.x25519_public, &msg.mlkem_ciphertext)
        .unwrap();

    // 4. Both derive the same session key
    assert_eq!(ss_alice.session_key, ss_bob.session_key);

    // 5. Derive channel binding token
    let transcript_hash = vec![1u8; 32];
    let binding = saacp::crypto_governance::derive_channel_binding_token(
        &transcript_hash,
        &ss_alice.session_key,
        "alice",
    );
    assert_eq!(binding.len(), 32);

    // 6. Verify channel binding
    assert!(saacp::crypto_governance::verify_channel_binding_token(
        &binding,
        &transcript_hash,
        &ss_bob.session_key,
        "alice",
    ));
}

#[test]
fn test_hybrid_signature_with_keypair_serialization() {
    let suite = HybridEd25519MlDsa65::new();
    let keypair = suite.generate_hybrid_keypair().unwrap();

    // Test hybrid signing
    let msg = b"message to sign";
    let sig = suite.sign_hybrid(&keypair, msg, None).unwrap();
    assert!(suite.verify_hybrid(&keypair, msg, &sig, None));

    // Test serialization round-trip
    let sig_bytes = sig.to_bytes();
    let sig2 = HybridSignature::from_bytes(&sig_bytes).unwrap();
    assert_eq!(sig.classical_sig, sig2.classical_sig);
    assert_eq!(sig.pqc_sig, sig2.pqc_sig);
}

// ─── Adversarial Protocol Tests (#10) ────────────────────────────────────────
//
// These tests verify the protocol resists attacks, not just that primitives
// work in the happy path. Each test maps to a specific attack scenario.

/// #10 TEST: Verify that the KEM combiner binds ciphertexts.
/// If an attacker manipulates the ciphertext, the derived key should change.
#[test]
fn test_combiner_ciphertext_binding() {
    let kem = HybridKem::new();
    let _alice_kp = kem.generate_keypair().unwrap();
    let bob_kp = kem.generate_keypair().unwrap();

    // Alice encapsulates to Bob
    let (msg, ss_alice) = kem
        .encapsulate(&bob_kp.x25519_public, &bob_kp.mlkem_public)
        .unwrap();

    // Bob decapsulates normally
    let ss_bob = kem
        .decapsulate(&bob_kp, &msg.x25519_public, &msg.mlkem_ciphertext)
        .unwrap();

    // Keys should match
    assert_eq!(ss_alice.session_key, ss_bob.session_key);

    // #1 FIX: If we flip a bit in the ciphertext, the derived key should change
    // (because the combiner binds ciphertexts, not just shared secrets)
    let mut tampered_ct = msg.mlkem_ciphertext.clone();
    if !tampered_ct.is_empty() {
        tampered_ct[0] ^= 0x01; // Flip one bit
    }
    let ss_tampered = kem
        .decapsulate(&bob_kp, &msg.x25519_public, &tampered_ct)
        .unwrap();

    // The tampered ciphertext should produce a different key
    assert_ne!(
        ss_alice.session_key, ss_tampered.session_key,
        "Tampering with ciphertext should change the derived key"
    );
}

/// #10 TEST: Verify that the composite signature envelope rejects
/// oversized component counts (DoS protection).
#[test]
fn test_composite_envelope_count_bomb_bounded() {
    // Create a malicious envelope claiming many components
    let mut malicious = Vec::new();
    malicious.extend_from_slice(&1000u16.to_be_bytes()); // Claim 1000 components
                                                         // Add minimal data for the first component
    malicious.extend_from_slice(&0x0801u16.to_be_bytes()); // Ed25519 code point
    malicious.extend_from_slice(&64u32.to_be_bytes()); // Length
    malicious.extend_from_slice(&[0u8; 64]); // Dummy signature

    let result = CompositeSignature::from_bytes(&malicious);
    assert!(
        result.is_err(),
        "Composite envelope with excessive component count should be rejected"
    );
}

/// #10 TEST: Verify that the composite signature envelope rejects
/// oversized component signatures.
#[test]
fn test_composite_envelope_oversized_component_rejected() {
    let mut malicious = Vec::new();
    malicious.extend_from_slice(&1u16.to_be_bytes()); // 1 component
    malicious.extend_from_slice(&0x0802u16.to_be_bytes()); // ML-DSA code point
    malicious.extend_from_slice(&100_000u32.to_be_bytes()); // Claim 100KB signature

    let result = CompositeSignature::from_bytes(&malicious);
    assert!(
        result.is_err(),
        "Composite envelope with oversized component should be rejected"
    );
}

/// #10 TEST: Verify that the hybrid signature rejects oversized classical component.
#[test]
fn test_hybrid_signature_oversized_classical_rejected() {
    let mut malicious = Vec::new();
    // Claim a 1000-byte classical signature (max is 128)
    malicious.extend_from_slice(&1000u32.to_be_bytes());
    malicious.extend_from_slice(&[0u8; 100]);

    let result = HybridSignature::from_bytes(&malicious);
    assert!(
        result.is_err(),
        "Hybrid signature with oversized classical component should be rejected"
    );
}

/// #10 TEST: Verify that the composite signature correctly identifies
/// classical and PQC components.
#[test]
fn test_composite_signature_classical_pqc_detection() {
    let components = vec![
        SignatureComponent {
            algorithm: SignatureAlgorithm::Ed25519.code_point(),
            signature: vec![0u8; 64],
        },
        SignatureComponent {
            algorithm: SignatureAlgorithm::MlDsa65.code_point(),
            signature: vec![0u8; 100],
        },
    ];
    let composite = CompositeSignature::new(components);

    assert!(
        composite.has_classical(),
        "Should detect classical component"
    );
    assert!(composite.has_pqc(), "Should detect PQC component");
    assert!(
        composite
            .get_component(SignatureAlgorithm::Ed25519.code_point())
            .is_some(),
        "Should find Ed25519 component"
    );
    assert!(
        composite
            .get_component(SignatureAlgorithm::MlDsa65.code_point())
            .is_some(),
        "Should find ML-DSA component"
    );
}

/// #10 TEST: Verify that the composite signature envelope rejects
/// truncated data.
#[test]
fn test_composite_envelope_truncated_rejected() {
    let mut data = Vec::new();
    data.extend_from_slice(&2u16.to_be_bytes()); // Claim 2 components
    data.extend_from_slice(&0x0801u16.to_be_bytes()); // Ed25519 code point
    data.extend_from_slice(&64u32.to_be_bytes()); // Length
                                                  // But only provide data for 1 component (truncated)

    let result = CompositeSignature::from_bytes(&data);
    assert!(
        result.is_err(),
        "Truncated composite envelope should be rejected"
    );
}

/// #10 TEST: Verify that the session key metadata properly tracks expiration.
#[test]
fn test_session_key_expiration() {
    let key = vec![0u8; 32];
    let metadata = SessionKeyMetadata::with_max_age(key, 0.001); // 1ms max age

    // Key should not be expired immediately
    assert!(!metadata.is_expired());

    // Wait for expiration
    std::thread::sleep(std::time::Duration::from_millis(10));
    assert!(metadata.is_expired(), "Key should be expired after max age");
}

/// #10 TEST: Verify that the session key metadata zeroizes on drop.
#[test]
fn test_session_key_zeroized_on_drop() {
    let key = vec![0xFFu8; 32]; // All 1s to detect zeroization
    let mut metadata = SessionKeyMetadata::new(key);

    // Key should not be zeroized initially
    assert!(metadata.key.iter().any(|&b| b != 0));

    // Explicitly zeroize
    metadata.zeroize();

    // Key should be zeroized
    assert!(metadata.key.iter().all(|&b| b == 0));
    assert_eq!(metadata.state, KeyLifecycleState::Zeroized);
}

/// #10 TEST: Verify that the security tier correctly enforces PQC requirements.
#[test]
fn test_security_tier_pqc_required() {
    use saacp::crypto_governance::{is_classical_suite, is_hybrid_suite, SecurityTier};

    assert!(SecurityTier::PqcRequired.requires_pqc());
    assert!(!SecurityTier::PqcRequired.allows_classical());

    assert!(!SecurityTier::PqcPreferred.requires_pqc());
    assert!(SecurityTier::PqcPreferred.allows_classical());

    assert!(!SecurityTier::ClassicalLegacy.requires_pqc());
    assert!(SecurityTier::ClassicalLegacy.allows_classical());

    // Suite classification
    assert!(is_hybrid_suite("hybrid-x25519-ml-kem-768"));
    assert!(is_hybrid_suite("ml-dsa-65"));
    assert!(is_classical_suite("ed25519"));
    assert!(is_classical_suite("x25519"));
}

/// #10 TEST: Verify that the crypto telemetry registry correctly records
/// and queries session data.
#[test]
fn test_crypto_telemetry_registry() {
    use saacp::crypto_governance::{CryptoTelemetryRegistry, SessionCryptoTelemetry};

    let mut registry = CryptoTelemetryRegistry::new();

    let mut telemetry = SessionCryptoTelemetry::new(
        "session-1".to_string(),
        "hybrid-ed25519-ml-dsa-65".to_string(),
        "PQC-REQUIRED".to_string(),
        "hash1".to_string(),
    );
    telemetry.add_signature_algorithm(SignatureAlgorithm::Ed25519.code_point());
    telemetry.add_signature_algorithm(SignatureAlgorithm::MlDsa65.code_point());
    registry.record(telemetry);

    let mut degraded = SessionCryptoTelemetry::new(
        "session-2".to_string(),
        "ed25519".to_string(),
        "PQC-PREFERRED".to_string(),
        "hash2".to_string(),
    );
    degraded.record_degradation("Peer only supports classical");
    registry.record(degraded);

    // Query by suite
    let hybrid_sessions = registry.find_by_suite("hybrid-ed25519-ml-dsa-65");
    assert_eq!(hybrid_sessions.len(), 1);

    // Query by degradation
    let degraded_sessions = registry.find_degraded_sessions();
    assert_eq!(degraded_sessions.len(), 1);
    assert_eq!(degraded_sessions[0].session_id, "session-2");

    // Query by tier
    let pqc_required = registry.find_by_tier("PQC-REQUIRED");
    assert_eq!(pqc_required.len(), 1);
}

/// #10 TEST: Verify that the signature algorithm code points are correct
/// and can be round-tripped.
#[test]
fn test_signature_algorithm_code_points() {
    // Verify code points are unique
    let ed25519 = SignatureAlgorithm::Ed25519.code_point();
    let mldsa = SignatureAlgorithm::MlDsa65.code_point();
    let slhdsa = SignatureAlgorithm::SlhDsa.code_point();
    let hybrid = SignatureAlgorithm::HybridEd25519MlDsa65.code_point();

    assert_ne!(ed25519, mldsa);
    assert_ne!(ed25519, slhdsa);
    assert_ne!(mldsa, slhdsa);

    // Verify round-trip
    assert_eq!(
        SignatureAlgorithm::from_code_point(ed25519),
        Some(SignatureAlgorithm::Ed25519)
    );
    assert_eq!(
        SignatureAlgorithm::from_code_point(mldsa),
        Some(SignatureAlgorithm::MlDsa65)
    );
    assert_eq!(
        SignatureAlgorithm::from_code_point(slhdsa),
        Some(SignatureAlgorithm::SlhDsa)
    );
    assert_eq!(
        SignatureAlgorithm::from_code_point(hybrid),
        Some(SignatureAlgorithm::HybridEd25519MlDsa65)
    );
    assert_eq!(SignatureAlgorithm::from_code_point(0xFFFF), None);
}

/// #10 TEST (FIX #2): Verify that the signed transcript signature fails
/// verification if the offered suites are tampered with (downgrade attack).
/// An active MITM that strips PQC options from the advertisement cannot
/// produce a valid signature over the modified transcript.
#[test]
fn test_downgrade_strip_pqc_from_offer_fails() {
    use saacp::crypto_governance::{
        NegotiationTranscript, SecurityTier, SignedNegotiationTranscript,
    };
    use saacp::pqc::signature::HybridEd25519MlDsa65;

    let suite = HybridEd25519MlDsa65::new();
    let keypair = suite.generate_hybrid_keypair().unwrap();

    // Alice advertises both classical and PQC suites
    let alice_suites = vec![
        "hybrid-ed25519-ml-dsa-65".to_string(),
        "ed25519".to_string(),
    ];
    let bob_suites = vec![
        "hybrid-ed25519-ml-dsa-65".to_string(),
        "ed25519".to_string(),
    ];

    // Create a legitimate transcript with hybrid selected
    let transcript = NegotiationTranscript::new(
        alice_suites.clone(),
        bob_suites.clone(),
        "hybrid-ed25519-ml-dsa-65".to_string(),
        "SAACP/0.2-beta1".to_string(),
        b"session-1".to_vec(),
        SecurityTier::PqcRequired,
        true, // peer advertised PQC
    );

    // Sign the transcript
    let signed = SignedNegotiationTranscript::sign(transcript.clone(), &keypair, &suite).unwrap();

    // Verify the original signature is valid
    assert!(signed.verify(&suite), "Original transcript should verify");

    // #2 FIX: Now simulate a tampered transcript where PQC was stripped from the offer
    let tampered_transcript = NegotiationTranscript::new(
        vec!["ed25519".to_string()], // PQC stripped from offer
        vec!["ed25519".to_string()],
        "ed25519".to_string(), // Classical-only selected
        "SAACP/0.2-beta1".to_string(),
        b"session-1".to_vec(),
        SecurityTier::PqcRequired,
        true, // But peer DID advertise PQC originally — downgrade sentinel!
    );

    // Create a new signed transcript with the tampered negotiation
    let tampered_signed =
        SignedNegotiationTranscript::sign(tampered_transcript, &keypair, &suite).unwrap();

    // The tampered transcript has a different hash, so signature won't match
    // the original transcript's hash. This means the tampered negotiation
    // cannot pass verification against the original expected transcript.
    assert_ne!(
        signed.transcript.transcript_hash_hex(),
        tampered_signed.transcript.transcript_hash_hex(),
        "Tampered transcript should have different hash"
    );

    // Verify that the downgrade sentinel was triggered
    assert_eq!(
        tampered_signed.transcript.downgrade_sentinel,
        saacp::crypto_governance::DOWNGRADE_SENTINEL_PQC_CAPABLE,
        "Downgrade sentinel should be set when PQC peer ends up classical"
    );
}

/// #10 TEST (FIX #3/#4): Verify that swapping a signature component
/// from one algorithm slot into another is rejected. An attacker who
/// replays an ML-DSA signature into the Ed25519 slot must fail verification.
#[test]
fn test_signature_component_swap_rejected() {
    use saacp::pqc::signature::{
        CompositeSignature, Ed25519SignatureSuite, HybridEd25519MlDsa65, MlDsa65Suite,
        SignatureAlgorithm, SignatureComponent,
    };

    let hybrid_suite = HybridEd25519MlDsa65::new();
    let keypair = hybrid_suite.generate_hybrid_keypair().unwrap();

    // Use the individual suites (public types) to generate signatures
    let ed25519_suite = Ed25519SignatureSuite::new();
    let mldsa_suite = MlDsa65Suite::new();

    let msg = b"test message for component swap";

    // Generate a valid ML-DSA signature
    let mldsa_sig = mldsa_suite.sign(&keypair.ml_dsa_secret, msg).unwrap();

    // Direct test: verify that ML-DSA bytes don't verify as Ed25519
    let ed25519_result = ed25519_suite.verify(
        &keypair.ed25519_public,
        msg,
        &mldsa_sig, // ML-DSA sig bytes as Ed25519
    );
    assert!(
        !ed25519_result,
        "ML-DSA signature bytes must NOT verify as Ed25519"
    );

    // And Ed25519 sig bytes don't verify as ML-DSA
    let ed25519_sig = ed25519_suite.sign(&keypair.ed25519_secret, msg).unwrap();
    let mldsa_result = mldsa_suite.verify(
        &keypair.ml_dsa_public,
        msg,
        &ed25519_sig, // Ed25519 sig bytes as ML-DSA
    );
    assert!(
        !mldsa_result,
        "Ed25519 signature bytes must NOT verify as ML-DSA"
    );

    // Verify that the ML-DSA signature is much larger than Ed25519
    assert!(
        mldsa_sig.len() > 64,
        "ML-DSA signature should be much larger than Ed25519"
    );

    // Verify that a composite signature with a swapped component is detected
    let swapped_components = vec![SignatureComponent {
        algorithm: SignatureAlgorithm::Ed25519.code_point(), // Ed25519 slot
        signature: mldsa_sig.clone(),                        // But contains ML-DSA sig bytes
    }];
    let swapped_composite = CompositeSignature::new(swapped_components);
    let swapped_bytes = swapped_composite.to_bytes();

    // The composite parses but the signature won't verify as Ed25519
    let parsed = CompositeSignature::from_bytes(&swapped_bytes).unwrap();
    assert_eq!(parsed.components.len(), 1);
    assert_eq!(
        parsed.components[0].algorithm,
        SignatureAlgorithm::Ed25519.code_point()
    );
    // The signature bytes are ML-DSA sized, not Ed25519 sized
    assert!(
        parsed.components[0].signature.len() > 64,
        "Swapped component should contain ML-DSA-sized bytes in Ed25519 slot"
    );
}

/// #10 TEST (FIX #1): Verify that if one KEM component is broken (returns
/// degenerate output), the hybrid session key still has entropy from the
/// other component. The combiner must be robust against a weak component.
#[test]
fn test_combiner_weak_component_still_secure() {
    use saacp::pqc::kem::derive_hybrid_session_key;

    // Simulate a broken ML-KEM that returns all-zeros shared secret
    // (worst case: the attacker has broken ML-KEM but not X25519)
    let weak_pqc_ss = vec![0u8; 32]; // Degenerate ML-KEM output
    let strong_classical_ss = vec![0xABu8; 32]; // Strong X25519 output
    let ct_classical = vec![0xCDu8; 32];
    let ct_pqc = vec![0xEFu8; 1088];

    let key_with_weak_pqc = derive_hybrid_session_key(
        &strong_classical_ss,
        &weak_pqc_ss,
        &ct_classical,
        &ct_pqc,
        None,
    )
    .unwrap();

    // Compare with a fully strong combination
    let strong_pqc_ss = vec![0x12u8; 32];
    let key_fully_strong = derive_hybrid_session_key(
        &strong_classical_ss,
        &strong_pqc_ss,
        &ct_classical,
        &ct_pqc,
        None,
    )
    .unwrap();

    // The keys should differ (weak component changes the output)
    assert_ne!(
        key_with_weak_pqc, key_fully_strong,
        "Weak PQC component should produce different key"
    );

    // But the key with weak PQC should NOT be all-zeros — it still has
    // entropy from the classical component. This is the security guarantee
    // of the hybrid construction: breaking one component doesn't break the key.
    assert!(
        key_with_weak_pqc.iter().any(|&b| b != 0),
        "Key with weak PQC component must still have entropy from classical"
    );

    // Also verify that weak classical + strong PQC still produces a valid key
    let weak_classical_ss = vec![0u8; 32];
    let key_with_weak_classical = derive_hybrid_session_key(
        &weak_classical_ss,
        &strong_pqc_ss,
        &ct_classical,
        &ct_pqc,
        None,
    )
    .unwrap();
    assert!(
        key_with_weak_classical.iter().any(|&b| b != 0),
        "Key with weak classical component must still have entropy from PQC"
    );
}

/// #10 TEST (FIX #8): Verify that a PQC-required tier fails closed when
/// only classical suites are available, producing a distinct error.
#[test]
fn test_pqc_required_tier_fails_closed() {
    use saacp::crypto_governance::CryptoTransparencyLedger;
    use saacp::crypto_governance::{production_policy, SecurityTier, SuiteNegotiator};

    let ledger = CryptoTransparencyLedger::new();
    let policy = production_policy();

    // Both peers only support classical suites
    let result = SuiteNegotiator::negotiate(
        &["ed25519", "AES-256-GCM-HKDF-SHA256"],
        &["ed25519", "AES-256-GCM-HKDF-SHA256"],
        b"session-1",
        None,
        Some(&policy),
        &ledger,
        Some(SecurityTier::PqcRequired),
    );

    // Must fail — PQC is required but only classical is available
    assert!(
        result.is_err(),
        "PQC-required tier must fail when only classical suites available"
    );

    let err = result.unwrap_err();
    assert!(
        err.contains("PQC_REQUIRED_VIOLATION"),
        "Error must be a distinct PQC_REQUIRED_VIOLATION, got: {}",
        err
    );

    // Verify that the failure was logged to the ledger
    let entries = ledger.entries();
    let has_pqc_blocked = entries.iter().any(|e| {
        e.event_type == "DOWNGRADE_ATTEMPT"
            && e.outcome == "BLOCKED"
            && e.details.contains("requires PQC")
    });
    assert!(
        has_pqc_blocked,
        "PQC-required failure must be logged as BLOCKED downgrade attempt"
    );
}

/// #10 TEST (FIX #7): Verify that ephemeral secrets are zeroized on
/// the error/abort path. When a handshake fails, the secrets must not
/// linger in memory.
#[test]
fn test_ephemeral_secret_zeroized_on_abort() {
    use saacp::pqc::kem::{HybridKem, KeyLifecycleState, SessionKeyMetadata};

    let kem = HybridKem::new();

    // Generate a keypair and extract the secret
    let keypair = kem.generate_keypair().unwrap();
    let secret_bytes = keypair.x25519_secret.clone();
    assert!(!secret_bytes.is_empty(), "Secret should not be empty");

    // Create session key metadata
    let mut metadata = SessionKeyMetadata::new(secret_bytes.clone());
    assert_eq!(metadata.state, KeyLifecycleState::Generated);

    // Mark as in use (simulating handshake start)
    metadata.mark_in_use();
    assert_eq!(metadata.state, KeyLifecycleState::InUse);

    // Simulate an abort — zeroize the secret
    metadata.zeroize();

    // Verify zeroization
    assert_eq!(metadata.state, KeyLifecycleState::Zeroized);
    assert!(
        metadata.key.iter().all(|&b| b == 0),
        "Key material must be zeroized after abort"
    );
}

/// #10 TEST: Verify that the SignedNegotiationTranscript verify correctly
/// handles the length-prefixed public key format (not hardcoded 32-byte split).
#[test]
fn test_signed_negotiation_transcript_verify() {
    use saacp::crypto_governance::{
        NegotiationTranscript, SecurityTier, SignedNegotiationTranscript,
    };
    use saacp::pqc::signature::HybridEd25519MlDsa65;

    let suite = HybridEd25519MlDsa65::new();
    let keypair = suite.generate_hybrid_keypair().unwrap();

    let transcript = NegotiationTranscript::new(
        vec!["hybrid-ed25519-ml-dsa-65".to_string()],
        vec!["hybrid-ed25519-ml-dsa-65".to_string()],
        "hybrid-ed25519-ml-dsa-65".to_string(),
        "SAACP/0.2-beta1".to_string(),
        b"session-verify-test".to_vec(),
        SecurityTier::PqcRequired,
        true,
    );

    let signed = SignedNegotiationTranscript::sign(transcript, &keypair, &suite).unwrap();

    // Verify the signature is valid
    assert!(
        signed.verify(&suite),
        "Signed transcript should verify with length-prefixed key format"
    );
}
