//! aca.rs — Agent Capability Attestation (ACA, Phase 6 / Part 8.4)
//!
//! *New in Rust* — no Python-reference analog.
//!
//! # Why this exists
//!
//! A capability token (`gateway.rs`/`acsvaf.rs`) answers "is this agent
//! *authorized* to perform this action class?" — a policy question, purely
//! about scope. It says nothing about whether the agent's underlying model or
//! execution environment has actually been vetted to be *safe enough* to
//! exercise that authorization responsibly. ACA adds a second, independent,
//! operator-signed claim — [`AttestationClaim`] — that answers exactly that:
//! "has this agent's deployment been attested to a given safety level?" The
//! two checks are deliberately orthogonal: a capability token grants scope, an
//! attestation claim vouches for the executor. Neither can substitute for the
//! other.
//!
//! # Architecture — additive, gate-adjacent, NOT a new gate
//!
//! [`enforce_attestation`] is called from `handler.rs` immediately after Gate
//! 2.5 (kinetic firewall) succeeds — the point where `parsed.action_class` is
//! already resolved against the validated token's ceiling — rather than
//! becoming a 13th numbered gate. Deliberately additive: nothing about the
//! existing gate pipeline's control flow, numbering, or behavior changes when
//! ACA is disabled (the documented default — see [`is_required`]'s doc
//! comment), consistent with Part 12 principle 3 ("fail-closed only applies
//! once a feature is actually enabled").
//!
//! # Safety level hierarchy and default policy
//!
//! ```text
//! Unattested(0) < BasicFiltering(1) < AlignedModel(2) < AuditedAligned(3) < HardwareAttested(4)
//! ```
//!
//! [`minimum_safety_level_for`] encodes the documented default policy:
//! READ_ONLY requires only `Unattested` (i.e. no attestation needed at all),
//! REVERSIBLE requires `BasicFiltering`, IRREVERSIBLE requires `AlignedModel`.
//!
//! # Signature scheme
//!
//! An [`AttestationAuthority`] (the deployment's attestation-issuing operator)
//! signs [`AttestationClaim`]'s canonical, length-prefixed field encoding — the
//! same idiom `identity_binding.rs`'s transcript hash, `faitf.rs`'s
//! `AgentCredential`/`SignedRevocationRecord` body bytes, and `ievl.rs`'s
//! `ExecutionReceipt` signing already use, so two fields can never be
//! concatenation-ambiguous. [`AttestationRegistry::install_claim`] verifies
//! that signature against a registry of explicitly-trusted operator keys
//! before a claim can ever affect [`AttestationRegistry::current_safety_level`]
//! — an untrusted or forged claim is never installed, matching the same
//! trust-anchor idiom `factf.rs`'s threshold-token verification and
//! `identity_binding.rs`'s CA-key verification already use.
//!
//! # Bounded memory
//!
//! [`AttestationRegistry`]'s claim map is capped at [`ACA_MAX_CLAIMS`] with
//! oldest-issued-first eviction on overflow (see
//! [`AttestationRegistry::install_claim`]) — the same "Bounded Everything"
//! principle (Part 12 principle 5) every other tracked map in this codebase
//! already follows.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn key_id_for(verifying_key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(verifying_key.as_bytes()))
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum distinct agent_ids tracked in [`AttestationRegistry`]'s claim map.
pub const ACA_MAX_CLAIMS: usize = 10_000;

// ---------------------------------------------------------------------------
// SafetyLevel
// ---------------------------------------------------------------------------

/// Attested safety tier, ascending in the exact order the `Ord` derive below
/// relies on — see the module docs' "Safety level hierarchy" section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum SafetyLevel {
    Unattested = 0,
    BasicFiltering = 1,
    AlignedModel = 2,
    AuditedAligned = 3,
    HardwareAttested = 4,
}

impl SafetyLevel {
    pub fn value(self) -> u8 {
        self as u8
    }
}

/// The default policy's minimum required [`SafetyLevel`] for a given
/// `action_class` — see the module docs' "Safety level hierarchy" section.
pub fn minimum_safety_level_for(action_class: u8) -> SafetyLevel {
    match action_class {
        0 => SafetyLevel::Unattested,
        1 => SafetyLevel::BasicFiltering,
        _ => SafetyLevel::AlignedModel,
    }
}

// ---------------------------------------------------------------------------
// AttestationClaim
// ---------------------------------------------------------------------------

/// An operator-signed vouch for one agent's execution environment, riding
/// alongside (never replacing) that agent's own capability token — see the
/// module docs' "Why this exists" section.
#[derive(Debug, Clone)]
pub struct AttestationClaim {
    pub agent_id: String,
    pub safety_level: SafetyLevel,
    /// Free-text sandbox/network-policy declaration (e.g.
    /// `"docker: no-network, read-only-fs"`) — informational, not itself
    /// verified beyond being part of the signed body.
    pub execution_environment: String,
    pub issued_at: f64,
    pub expires_at: f64,
    /// Fingerprint (`key_id_for`) of the [`AttestationAuthority`] verifying
    /// key that signed this claim.
    pub operator_key_id: String,
    pub operator_signature: Vec<u8>,
}

impl AttestationClaim {
    /// Canonical length-prefixed encoding of a claim's signed fields — see
    /// the module docs' "Signature scheme" section.
    fn canonical_bytes(
        agent_id: &str,
        safety_level: SafetyLevel,
        execution_environment: &str,
        issued_at: f64,
        expires_at: f64,
    ) -> Vec<u8> {
        fn encode_field(buf: &mut Vec<u8>, data: &[u8]) {
            buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
            buf.extend_from_slice(data);
        }
        let mut buf = Vec::new();
        buf.extend_from_slice(b"saacp-aca-claim-v1");
        encode_field(&mut buf, agent_id.as_bytes());
        buf.push(safety_level.value());
        encode_field(&mut buf, execution_environment.as_bytes());
        buf.extend_from_slice(&issued_at.to_be_bytes());
        buf.extend_from_slice(&expires_at.to_be_bytes());
        buf
    }

    pub fn is_expired(&self) -> bool {
        now_secs() > self.expires_at
    }
}

// ---------------------------------------------------------------------------
// AttestationAuthority — the operator's issuing keypair
// ---------------------------------------------------------------------------

/// Where an [`AttestationAuthority`]'s signing key actually lives.
///
/// `Local` is the original behavior: a `SigningKey` value held in this process's memory.
/// `Hardware` routes signing through an [`crate::hrt::HardwareKeyStore`] — a PKCS#11
/// token, AWS KMS, or GCP KMS — so the private key is never present in the address space
/// and cannot be exfiltrated by a memory-disclosure bug or a core dump.
enum AttestationKeySource {
    Local(SigningKey),
    Hardware {
        store: std::sync::Arc<dyn crate::hrt::HardwareKeyStore>,
        key_id: String,
    },
}

/// The deployment's attestation-issuing operator. Distinct from any agent's
/// own identity — mirrors how `faitf.rs`'s `AgentCredential::issue` is signed
/// by a separate issuer keypair, not the agent's own.
pub struct AttestationAuthority {
    source: AttestationKeySource,
    /// Cached in both modes. For a hardware store this is fetched exactly once, at
    /// construction: `key_id()` is called on every `issue`, and a KMS round-trip per
    /// issuance to re-fetch an immutable value would make an HSM-backed authority
    /// pointlessly slower than a software one.
    verifying_key: VerifyingKey,
}

impl AttestationAuthority {
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        Self { source: AttestationKeySource::Local(signing_key), verifying_key }
    }

    /// Build an authority whose signing key lives in hardware.
    ///
    /// `key_id` is resolved by the backend: a PKCS#11 `CKA_LABEL`, a KMS key id / ARN /
    /// alias, or a Cloud KMS CryptoKeyVersion resource name. The public key is fetched
    /// once here, which also serves as an eager health check — a misconfigured key id or
    /// an unreachable HSM fails at construction rather than at the first attempt to issue
    /// an attestation, when it would be far more disruptive.
    pub fn with_keystore(
        store: std::sync::Arc<dyn crate::hrt::HardwareKeyStore>,
        key_id: impl Into<String>,
    ) -> Result<Self, crate::hrt::HrtError> {
        let key_id = key_id.into();
        let public_key = store.public_key(&key_id)?;
        let bytes: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
            crate::hrt::HrtError::MalformedResponse {
                backend: "attestation authority",
                expected: 32,
                got: public_key.len(),
            }
        })?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| crate::hrt::HrtError::MalformedKeyMaterial(key_id.clone()))?;
        Ok(Self { source: AttestationKeySource::Hardware { store, key_id }, verifying_key })
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.verifying_key
    }

    pub fn key_id(&self) -> String {
        key_id_for(&self.verifying_key)
    }

    /// Issue a freshly-signed claim for `agent_id`, valid for `ttl_seconds`
    /// from now.
    ///
    /// # Panics
    ///
    /// Panics if a hardware-backed signing call fails. Use [`Self::try_issue`] on any
    /// authority built with [`Self::with_keystore`] — a network KMS can fail
    /// transiently, and this signature (kept for backward compatibility with the
    /// software path, where signing is infallible) has no way to report that.
    pub fn issue(
        &self,
        agent_id: &str,
        safety_level: SafetyLevel,
        execution_environment: &str,
        ttl_seconds: u64,
    ) -> AttestationClaim {
        self.try_issue(agent_id, safety_level, execution_environment, ttl_seconds)
            .expect("attestation signing failed — use try_issue() with a hardware key store")
    }

    /// Fallible form of [`Self::issue`]. Always succeeds for a software key; may return
    /// a backend error for a hardware-backed one.
    pub fn try_issue(
        &self,
        agent_id: &str,
        safety_level: SafetyLevel,
        execution_environment: &str,
        ttl_seconds: u64,
    ) -> Result<AttestationClaim, crate::hrt::HrtError> {
        let issued_at = now_secs();
        let expires_at = issued_at + ttl_seconds as f64;
        let body = AttestationClaim::canonical_bytes(agent_id, safety_level, execution_environment, issued_at, expires_at);
        let operator_signature = match &self.source {
            AttestationKeySource::Local(sk) => sk.sign(&body).to_bytes().to_vec(),
            AttestationKeySource::Hardware { store, key_id } => store.sign(key_id, &body)?,
        };
        Ok(AttestationClaim {
            agent_id: agent_id.to_string(),
            safety_level,
            execution_environment: execution_environment.to_string(),
            issued_at,
            expires_at,
            operator_key_id: self.key_id(),
            operator_signature,
        })
    }
}

// ---------------------------------------------------------------------------
// AttestationRegistry
// ---------------------------------------------------------------------------

/// Why an [`AttestationClaim`] was rejected by [`AttestationRegistry::install_claim`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcaError {
    /// `operator_key_id` is not a key this registry has been told to trust
    /// via [`AttestationRegistry::trust_operator`].
    UntrustedOperator,
    /// The signature does not verify against the claimed operator's key, or
    /// is not a well-formed 64-byte Ed25519 signature.
    SignatureInvalid,
    /// `expires_at` is already in the past.
    Expired,
}

impl std::fmt::Display for AcaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AcaError::UntrustedOperator => write!(f, "attestation claim's operator key is not trusted by this registry"),
            AcaError::SignatureInvalid => write!(f, "attestation claim signature is invalid"),
            AcaError::Expired => write!(f, "attestation claim is already expired"),
        }
    }
}

impl std::error::Error for AcaError {}

/// Process-wide (or per-instance, for tests) store of currently-active
/// attestation claims, keyed by `agent_id`, plus the set of operator keys
/// this registry trusts to sign them.
pub struct AttestationRegistry {
    trusted_operators: Mutex<HashMap<String, VerifyingKey>>,
    claims: Mutex<HashMap<String, AttestationClaim>>,
}

impl Default for AttestationRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationRegistry {
    pub fn new() -> Self {
        Self {
            trusted_operators: Mutex::new(HashMap::new()),
            claims: Mutex::new(HashMap::new()),
        }
    }

    /// Process-wide singleton, matching `TrustDecayEngine::global()`'s
    /// established pattern.
    pub fn global() -> &'static AttestationRegistry {
        static GLOBAL: OnceLock<AttestationRegistry> = OnceLock::new();
        GLOBAL.get_or_init(AttestationRegistry::new)
    }

    /// Trust `verifying_key` as a valid attestation-issuing operator. Claims
    /// signed by any other key are rejected by [`Self::install_claim`] with
    /// [`AcaError::UntrustedOperator`] — an ACA deployment must call this at
    /// least once before any claim can ever be installed.
    pub fn trust_operator(&self, verifying_key: VerifyingKey) {
        let key_id = key_id_for(&verifying_key);
        self.trusted_operators.lock().unwrap_or_else(|e| e.into_inner()).insert(key_id, verifying_key);
    }

    /// Verify `claim`'s signature against a trusted operator key and, if
    /// valid and not expired, install it as `claim.agent_id`'s current claim
    /// (replacing any prior claim for that agent). Bounded: on overflow,
    /// evicts the currently-tracked claim with the oldest `issued_at` —
    /// mirroring `faitf.rs::DistributedRevocationInfrastructure`'s own
    /// capacity-eviction precedent, just without a high-severity exemption
    /// (an attestation claim has no analogous "this one must never be
    /// evicted" tier).
    pub fn install_claim(&self, claim: AttestationClaim) -> Result<(), AcaError> {
        {
            let operators = self.trusted_operators.lock().unwrap_or_else(|e| e.into_inner());
            let Some(operator_key) = operators.get(&claim.operator_key_id) else {
                return Err(AcaError::UntrustedOperator);
            };
            if claim.operator_signature.len() != 64 {
                return Err(AcaError::SignatureInvalid);
            }
            let mut sig_bytes = [0u8; 64];
            sig_bytes.copy_from_slice(&claim.operator_signature);
            let sig = Signature::from_bytes(&sig_bytes);
            let body = AttestationClaim::canonical_bytes(
                &claim.agent_id, claim.safety_level, &claim.execution_environment,
                claim.issued_at, claim.expires_at,
            );
            if operator_key.verify(&body, &sig).is_err() {
                return Err(AcaError::SignatureInvalid);
            }
        }

        if claim.is_expired() {
            return Err(AcaError::Expired);
        }

        let mut claims = self.claims.lock().unwrap_or_else(|e| e.into_inner());
        if claims.len() >= ACA_MAX_CLAIMS && !claims.contains_key(&claim.agent_id) {
            if let Some(oldest) = claims.iter()
                .min_by(|(_, a), (_, b)| a.issued_at.partial_cmp(&b.issued_at).unwrap_or(std::cmp::Ordering::Equal))
                .map(|(k, _)| k.clone())
            {
                claims.remove(&oldest);
            }
        }
        claims.insert(claim.agent_id.clone(), claim);
        Ok(())
    }

    /// `agent_id`'s currently-active safety level — [`SafetyLevel::Unattested`]
    /// if no claim is on record, or the on-record claim has expired.
    pub fn current_safety_level(&self, agent_id: &str) -> SafetyLevel {
        let claims = self.claims.lock().unwrap_or_else(|e| e.into_inner());
        match claims.get(agent_id) {
            Some(c) if !c.is_expired() => c.safety_level,
            _ => SafetyLevel::Unattested,
        }
    }

    /// Number of claims currently tracked (for observability/tests).
    pub fn tracked_count(&self) -> usize {
        self.claims.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

// ---------------------------------------------------------------------------
// Deployment on/off switch + enforcement
// ---------------------------------------------------------------------------

static ACA_REQUIRED: AtomicBool = AtomicBool::new(false);

/// Enable or disable ACA enforcement process-wide. Defaults to `false` (off)
/// — deployments that never provision attestation-issuing infrastructure are
/// completely unaffected: [`enforce_attestation`] is an unconditional no-op
/// while this is `false`, matching Part 12 principle 3 ("fail-closed only
/// applies once a feature is actually enabled").
pub fn set_required(required: bool) {
    ACA_REQUIRED.store(required, Ordering::SeqCst);
}

/// Whether ACA enforcement is currently active for this process. See
/// [`set_required`]'s doc comment.
pub fn is_required() -> bool {
    ACA_REQUIRED.load(Ordering::SeqCst)
}

/// Gate-2.5-adjacent enforcement (`handler.rs`, called immediately after Gate
/// 2.5 succeeds — see the module docs' "Architecture" section). A pure no-op
/// (returns `Ok(())` without even touching [`AttestationRegistry`]) unless
/// [`is_required`] is `true`.
pub fn enforce_attestation(agent_id: &str, action_class: u8) -> Result<(), SAACPHardDrop> {
    if !is_required() {
        return Ok(());
    }
    let required = minimum_safety_level_for(action_class);
    let actual = AttestationRegistry::global().current_safety_level(agent_id);
    if actual < required {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InsufficientAttestation,
            format!(
                "ACA: agent '{agent_id}' attestation safety level {actual:?} is below the \
                 minimum {required:?} required for action_class {action_class}."
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;

    // ── SafetyLevel ordering ────────────────────────────────────────────

    #[test]
    fn safety_level_ordering_is_ascending() {
        assert!(SafetyLevel::Unattested < SafetyLevel::BasicFiltering);
        assert!(SafetyLevel::BasicFiltering < SafetyLevel::AlignedModel);
        assert!(SafetyLevel::AlignedModel < SafetyLevel::AuditedAligned);
        assert!(SafetyLevel::AuditedAligned < SafetyLevel::HardwareAttested);
    }

    #[test]
    fn minimum_safety_level_matches_documented_default_policy() {
        assert_eq!(minimum_safety_level_for(0x00), SafetyLevel::Unattested);
        assert_eq!(minimum_safety_level_for(0x01), SafetyLevel::BasicFiltering);
        assert_eq!(minimum_safety_level_for(0x02), SafetyLevel::AlignedModel);
    }

    // ── AttestationAuthority / signing ──────────────────────────────────

    #[test]
    fn issued_claim_carries_requested_fields() {
        let authority = AttestationAuthority::generate();
        let claim = authority.issue("agent-a", SafetyLevel::AlignedModel, "docker: no-network", 3600);
        assert_eq!(claim.agent_id, "agent-a");
        assert_eq!(claim.safety_level, SafetyLevel::AlignedModel);
        assert_eq!(claim.operator_key_id, authority.key_id());
        assert!(!claim.is_expired());
    }

    #[test]
    fn zero_ttl_claim_is_immediately_expired() {
        let authority = AttestationAuthority::generate();
        let claim = authority.issue("agent-a", SafetyLevel::AlignedModel, "env", 0);
        assert!(claim.is_expired());
    }

    // ── AttestationRegistry::install_claim ──────────────────────────────

    #[test]
    fn install_claim_from_trusted_operator_succeeds() {
        let registry = AttestationRegistry::new();
        let authority = AttestationAuthority::generate();
        registry.trust_operator(authority.verifying_key());
        let claim = authority.issue("agent-a", SafetyLevel::AlignedModel, "env", 3600);
        assert!(registry.install_claim(claim).is_ok());
        assert_eq!(registry.current_safety_level("agent-a"), SafetyLevel::AlignedModel);
    }

    #[test]
    fn install_claim_from_untrusted_operator_rejected() {
        let registry = AttestationRegistry::new();
        let authority = AttestationAuthority::generate();
        // Deliberately never call registry.trust_operator(...).
        let claim = authority.issue("agent-a", SafetyLevel::AlignedModel, "env", 3600);
        assert_eq!(registry.install_claim(claim), Err(AcaError::UntrustedOperator));
        assert_eq!(registry.current_safety_level("agent-a"), SafetyLevel::Unattested);
    }

    #[test]
    fn install_claim_with_tampered_field_rejected() {
        let registry = AttestationRegistry::new();
        let authority = AttestationAuthority::generate();
        registry.trust_operator(authority.verifying_key());
        let mut claim = authority.issue("agent-a", SafetyLevel::AlignedModel, "env", 3600);
        // Tamper with the safety level after signing.
        claim.safety_level = SafetyLevel::HardwareAttested;
        assert_eq!(registry.install_claim(claim), Err(AcaError::SignatureInvalid));
    }

    #[test]
    fn install_claim_forged_by_different_key_rejected() {
        let registry = AttestationRegistry::new();
        let real_authority = AttestationAuthority::generate();
        let attacker_authority = AttestationAuthority::generate();
        registry.trust_operator(real_authority.verifying_key());
        // Attacker signs a claim, then relabels it as if the trusted operator issued it.
        let mut forged = attacker_authority.issue("agent-a", SafetyLevel::HardwareAttested, "env", 3600);
        forged.operator_key_id = real_authority.key_id();
        assert_eq!(registry.install_claim(forged), Err(AcaError::SignatureInvalid));
    }

    #[test]
    fn install_expired_claim_rejected() {
        let registry = AttestationRegistry::new();
        let authority = AttestationAuthority::generate();
        registry.trust_operator(authority.verifying_key());
        let claim = authority.issue("agent-a", SafetyLevel::AlignedModel, "env", 0);
        assert_eq!(registry.install_claim(claim), Err(AcaError::Expired));
    }

    #[test]
    fn current_safety_level_defaults_to_unattested_when_no_claim() {
        let registry = AttestationRegistry::new();
        assert_eq!(registry.current_safety_level("never-attested-agent"), SafetyLevel::Unattested);
    }

    #[test]
    fn later_claim_replaces_earlier_claim_for_same_agent() {
        let registry = AttestationRegistry::new();
        let authority = AttestationAuthority::generate();
        registry.trust_operator(authority.verifying_key());
        registry.install_claim(authority.issue("agent-a", SafetyLevel::BasicFiltering, "env", 3600)).unwrap();
        assert_eq!(registry.current_safety_level("agent-a"), SafetyLevel::BasicFiltering);
        registry.install_claim(authority.issue("agent-a", SafetyLevel::AuditedAligned, "env", 3600)).unwrap();
        assert_eq!(registry.current_safety_level("agent-a"), SafetyLevel::AuditedAligned);
        assert_eq!(registry.tracked_count(), 1);
    }

    #[test]
    fn tracked_count_reflects_installed_claims() {
        let registry = AttestationRegistry::new();
        let authority = AttestationAuthority::generate();
        registry.trust_operator(authority.verifying_key());
        assert_eq!(registry.tracked_count(), 0);
        registry.install_claim(authority.issue("agent-a", SafetyLevel::AlignedModel, "env", 3600)).unwrap();
        registry.install_claim(authority.issue("agent-b", SafetyLevel::AlignedModel, "env", 3600)).unwrap();
        assert_eq!(registry.tracked_count(), 2);
    }

    // ── enforce_attestation / is_required ───────────────────────────────

    #[test]
    #[serial]
    fn enforce_attestation_is_a_noop_when_not_required() {
        set_required(false);
        assert!(enforce_attestation("any-unattested-agent", 0x02).is_ok());
    }

    #[test]
    #[serial]
    fn enforce_attestation_rejects_insufficient_level_when_required() {
        AttestationRegistry::global().trust_operator(AttestationAuthority::generate().verifying_key());
        set_required(true);
        let result = enforce_attestation("unattested-agent-under-enforcement", 0x02);
        set_required(false);
        let err = result.unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::InsufficientAttestation);
    }

    #[test]
    #[serial]
    fn enforce_attestation_allows_sufficient_level_when_required() {
        let authority = AttestationAuthority::generate();
        AttestationRegistry::global().trust_operator(authority.verifying_key());
        AttestationRegistry::global().install_claim(
            authority.issue("sufficiently-attested-agent", SafetyLevel::AlignedModel, "env", 3600)
        ).unwrap();
        set_required(true);
        let result = enforce_attestation("sufficiently-attested-agent", 0x02);
        set_required(false);
        assert!(result.is_ok());
    }

    #[test]
    #[serial]
    fn enforce_attestation_read_only_never_needs_attestation_even_when_required() {
        set_required(true);
        let result = enforce_attestation("never-attested-read-only-agent", 0x00);
        set_required(false);
        assert!(result.is_ok(), "READ_ONLY's minimum SafetyLevel is Unattested — every agent already meets it");
    }
}
