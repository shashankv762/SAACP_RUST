//! identity_binding.rs — Authenticated Identity Binding and Transcript Integrity (C-3)
//!
//! Cryptographically binds agent identity to the authenticated handshake transcript.
//!
//! ## C-3 Invariants
//! 1. Agent identifiers are only trusted when included in the transcript hash.
//! 2. The canonical TranscriptHash (thash) is the cryptographic foundation for
//!    session auth, capability binding, PoP, replay protection, and audit.
//! 3. Every agent must prove both (a) possession of credentials AND (b) ownership
//!    of the claimed identity via a signed identity assertion.
//! 4. Identity verification must occur BEFORE authorization, capability validation,
//!    memory access, delegation, or application execution.
//! 5. Identity substitution, relabeling, misbinding, session-splicing, and
//!    key-swapping are all rejected automatically.

use std::collections::{HashMap, HashSet};
use std::sync::{LazyLock, Mutex};
use std::time::SystemTime;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Sha256, Digest};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ---------------------------------------------------------------------------
// AgentIdentityCertificate
// ---------------------------------------------------------------------------

/// Signed assertion linking an Agent Identifier to a long-term public key.
///
/// The certificate body is signed by an authority whose public key is
/// trusted by the verifier (certificate_authority_kid).
pub struct AgentIdentityCertificate {
    /// Unique certificate UUID (hex).
    pub cert_id: String,
    /// The agent identifier being certified.
    pub agent_id: String,
    /// Hex-encoded Ed25519 long-term public key (32 bytes = 64 hex chars).
    pub public_key_hex: String,
    /// Cryptographic algorithm (default: "ed25519").
    pub algorithm: String,
    /// Unix timestamp of issuance.
    pub issued_at: f64,
    /// Unix timestamp of expiry.
    pub expires_at: f64,
    /// Key ID of the certificate authority's signing key.
    pub ca_kid: String,
    /// Issuer identifier of the certificate authority.
    pub issuer_id: String,
    /// 64-byte Ed25519 signature over body_bytes().
    pub cert_signature: Vec<u8>,
}

impl AgentIdentityCertificate {
    /// Issue an identity certificate for `agent_id` linked to `public_key_hex`.
    /// The certificate is signed by the provided `signing_key`.
    pub fn issue(
        agent_id: &str,
        public_key_hex: &str,
        signing_key: &SigningKey,
        ca_kid: &str,
        issuer_id: &str,
        ttl_seconds: f64,
        algorithm: &str,
    ) -> Self {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        let cert_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let mut cert = Self {
            cert_id,
            agent_id: agent_id.to_string(),
            public_key_hex: public_key_hex.to_string(),
            algorithm: algorithm.to_string(),
            issued_at: now,
            expires_at: now + ttl_seconds,
            ca_kid: ca_kid.to_string(),
            issuer_id: issuer_id.to_string(),
            cert_signature: Vec::new(),
        };
        let body = cert.body_bytes();
        let sig = signing_key.sign(&body);
        cert.cert_signature = sig.to_bytes().to_vec();
        cert
    }

    /// Canonical bytes over which cert_signature is computed (no signature field).
    /// Returns deterministic JSON with sorted keys.
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut map = serde_json::Map::new();
        map.insert("agent_id".into(), serde_json::Value::String(self.agent_id.clone()));
        map.insert("algorithm".into(), serde_json::Value::String(self.algorithm.clone()));
        map.insert("ca_kid".into(), serde_json::Value::String(self.ca_kid.clone()));
        map.insert("cert_id".into(), serde_json::Value::String(self.cert_id.clone()));
        map.insert("expires_at".into(), serde_json::json!(self.expires_at));
        map.insert("issued_at".into(), serde_json::json!(self.issued_at));
        map.insert("issuer_id".into(), serde_json::Value::String(self.issuer_id.clone()));
        map.insert("public_key_hex".into(), serde_json::Value::String(self.public_key_hex.clone()));
        let body = serde_json::Value::Object(map);
        serde_json::to_string(&body).unwrap_or_default().into_bytes()
    }

    /// Serialize to JSON string.
    pub fn to_json(&self) -> String {
        let mut map = serde_json::Map::new();
        map.insert("agent_id".into(), serde_json::Value::String(self.agent_id.clone()));
        map.insert("algorithm".into(), serde_json::Value::String(self.algorithm.clone()));
        map.insert("ca_kid".into(), serde_json::Value::String(self.ca_kid.clone()));
        map.insert("cert_id".into(), serde_json::Value::String(self.cert_id.clone()));
        map.insert("cert_signature".into(), serde_json::Value::String(hex::encode(&self.cert_signature)));
        map.insert("expires_at".into(), serde_json::json!(self.expires_at));
        map.insert("issued_at".into(), serde_json::json!(self.issued_at));
        map.insert("issuer_id".into(), serde_json::Value::String(self.issuer_id.clone()));
        map.insert("public_key_hex".into(), serde_json::Value::String(self.public_key_hex.clone()));
        serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_default()
    }

    /// Deserialize from JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, String> {
        let d: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("JSON parse error: {e}"))?;
        let obj = d.as_object().ok_or("expected JSON object")?;
        Ok(Self {
            cert_id: obj["cert_id"].as_str().unwrap_or_default().to_string(),
            agent_id: obj["agent_id"].as_str().unwrap_or_default().to_string(),
            public_key_hex: obj["public_key_hex"].as_str().unwrap_or_default().to_string(),
            algorithm: obj["algorithm"].as_str().unwrap_or_default().to_string(),
            issued_at: obj["issued_at"].as_f64().unwrap_or(0.0),
            expires_at: obj["expires_at"].as_f64().unwrap_or(0.0),
            ca_kid: obj["ca_kid"].as_str().unwrap_or_default().to_string(),
            issuer_id: obj["issuer_id"].as_str().unwrap_or_default().to_string(),
            cert_signature: hex::decode(
                obj["cert_signature"].as_str().unwrap_or_default()
            ).map_err(|e| format!("hex decode error: {e}"))?,
        })
    }

    /// Check if the certificate has expired.
    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        now > self.expires_at
    }

    /// SHA-256 fingerprint of the certified public key (hex).
    pub fn fingerprint(&self) -> String {
        let pk_bytes = hex::decode(&self.public_key_hex).unwrap_or_default();
        hex::encode(Sha256::digest(&pk_bytes))
    }
}

// ---------------------------------------------------------------------------
// TranscriptBoundSession (C-3 session record)
// ---------------------------------------------------------------------------

/// Full C-3-compliant session record.
///
/// Every field listed in C-3 is stored and hashed into the transcript.
/// The final `thash` hex string is the canonical trust anchor for all
/// downstream operations in this session.
pub struct TranscriptBoundSession {
    /// 16-byte opaque session ID.
    pub session_id: Vec<u8>,
    /// Client agent identifier.
    pub client_agent_id: String,
    /// Server agent identifier.
    pub server_agent_id: String,
    /// Hex-encoded 32-byte Ed25519 client public key.
    pub client_public_key_hex: String,
    /// Hex-encoded 32-byte Ed25519 server public key.
    pub server_public_key_hex: String,
    /// Hex-encoded random client nonce.
    pub client_nonce_hex: String,
    /// Hex-encoded random server nonce.
    pub server_nonce_hex: String,
    /// Protocol version string (e.g. "SAACP/0.1-beta2").
    pub protocol_version: String,
    /// Cipher suite string (e.g. "Ed25519-AES256GCM").
    pub cipher_suite: String,
    /// Final 64-char hex transcript hash.
    pub thash: String,
    /// Wall-clock time (seconds since UNIX epoch) at establishment.
    pub established_at: f64,
    /// True after both certs verified.
    pub identity_verified: bool,
    /// Additional security-relevant session parameters.
    pub extra_params: serde_json::Value,
}

impl TranscriptBoundSession {
    /// Hex-encoded session ID.
    pub fn session_id_hex(&self) -> String {
        hex::encode(&self.session_id)
    }

    /// Establish a C-3-compliant session: compute the canonical thash over
    /// all mandatory transcript fields in deterministic order.
    #[allow(clippy::too_many_arguments)]
    pub fn establish(
        session_id: Vec<u8>,
        client_agent_id: &str,
        server_agent_id: &str,
        client_public_key_hex: &str,
        server_public_key_hex: &str,
        client_nonce_hex: &str,
        server_nonce_hex: &str,
        protocol_version: &str,
        cipher_suite: &str,
        extra_params: Option<serde_json::Value>,
    ) -> Self {
        let extra = extra_params.unwrap_or(serde_json::Value::Object(serde_json::Map::new()));
        let thash = Self::compute_thash(
            &session_id,
            client_agent_id,
            server_agent_id,
            client_public_key_hex,
            server_public_key_hex,
            client_nonce_hex,
            server_nonce_hex,
            protocol_version,
            cipher_suite,
            &extra,
        );
        let established_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            session_id,
            client_agent_id: client_agent_id.to_string(),
            server_agent_id: server_agent_id.to_string(),
            client_public_key_hex: client_public_key_hex.to_string(),
            server_public_key_hex: server_public_key_hex.to_string(),
            client_nonce_hex: client_nonce_hex.to_string(),
            server_nonce_hex: server_nonce_hex.to_string(),
            protocol_version: protocol_version.to_string(),
            cipher_suite: cipher_suite.to_string(),
            thash,
            established_at,
            identity_verified: false,
            extra_params: extra,
        }
    }

    /// Canonical transcript hash (thash) computation.
    ///
    /// Layout (length-prefixed, in fixed order):
    /// ```text
    ///   TAG "saacp-transcript-v1"          (19 bytes literal)
    ///   session_id                         (16 bytes)
    ///   client_agent_id                    (utf-8)
    ///   server_agent_id                    (utf-8)
    ///   client_public_key_hex              (utf-8)
    ///   server_public_key_hex              (utf-8)
    ///   client_nonce_hex                   (utf-8)
    ///   server_nonce_hex                   (utf-8)
    ///   protocol_version                   (utf-8)
    ///   cipher_suite                       (utf-8)
    ///   canonical_json(extra_params)       (utf-8, sort_keys)
    /// ```
    /// Each field is prefixed with its 4-byte LE length.
    #[allow(clippy::too_many_arguments)]
    pub fn compute_thash(
        session_id: &[u8],
        client_agent_id: &str,
        server_agent_id: &str,
        client_public_key_hex: &str,
        server_public_key_hex: &str,
        client_nonce_hex: &str,
        server_nonce_hex: &str,
        protocol_version: &str,
        cipher_suite: &str,
        extra_params: &serde_json::Value,
    ) -> String {
        fn encode_field(data: &[u8]) -> Vec<u8> {
            let mut buf = Vec::with_capacity(4 + data.len());
            buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
            buf.extend_from_slice(data);
            buf
        }

        let mut buf: Vec<u8> = Vec::new();
        buf.extend_from_slice(b"saacp-transcript-v1");
        buf.extend_from_slice(&encode_field(session_id));
        buf.extend_from_slice(&encode_field(client_agent_id.as_bytes()));
        buf.extend_from_slice(&encode_field(server_agent_id.as_bytes()));
        buf.extend_from_slice(&encode_field(client_public_key_hex.as_bytes()));
        buf.extend_from_slice(&encode_field(server_public_key_hex.as_bytes()));
        buf.extend_from_slice(&encode_field(client_nonce_hex.as_bytes()));
        buf.extend_from_slice(&encode_field(server_nonce_hex.as_bytes()));
        buf.extend_from_slice(&encode_field(protocol_version.as_bytes()));
        buf.extend_from_slice(&encode_field(cipher_suite.as_bytes()));

        // Canonical JSON for extra_params (sorted keys)
        let extra_json = serde_json::to_string(extra_params).unwrap_or_else(|_| "{}".to_string());
        buf.extend_from_slice(&encode_field(extra_json.as_bytes()));

        hex::encode(Sha256::digest(&buf))
    }

    /// Re-derive the thash from stored fields. Must equal self.thash (tamper detection).
    pub fn recompute_thash(&self) -> String {
        Self::compute_thash(
            &self.session_id,
            &self.client_agent_id,
            &self.server_agent_id,
            &self.client_public_key_hex,
            &self.server_public_key_hex,
            &self.client_nonce_hex,
            &self.server_nonce_hex,
            &self.protocol_version,
            &self.cipher_suite,
            &self.extra_params,
        )
    }

    /// Return true if the stored thash matches recomputed value.
    pub fn verify_thash_integrity(&self) -> bool {
        self.thash == self.recompute_thash()
    }

    /// Call after IdentityVerifier successfully validates both agent certs.
    pub fn mark_identity_verified(&mut self) {
        self.identity_verified = true;
    }
}

// ---------------------------------------------------------------------------
// IdentityVerifier
// ---------------------------------------------------------------------------

/// CA public key record for verification.
struct CAKeyRecord {
    verifying_key: VerifyingKey,
    _kid: String,
}

/// Validates AgentIdentityCertificates and enforces transcript binding.
///
/// All methods raise SAACPHardDrop on any C-3 violation.
pub struct IdentityVerifier {
    inner: Mutex<VerifierInner>,
}

struct VerifierInner {
    /// Trusted CA public keys: ca_kid → VerifyingKey
    ca_keys: HashMap<String, CAKeyRecord>,
    /// Revoked cert_ids
    revoked_certs: HashSet<String>,
    /// Verified agent_id → cert_id (last verified cert per agent)
    verified: HashMap<String, String>,
}

impl IdentityVerifier {
    /// Create a new IdentityVerifier.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(VerifierInner {
                ca_keys: HashMap::new(),
                revoked_certs: HashSet::new(),
                verified: HashMap::new(),
            }),
        }
    }

    /// Register a CA public key for verification.
    pub fn register_ca_key(&self, ca_kid: &str, verifying_key: VerifyingKey) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.ca_keys.insert(ca_kid.to_string(), CAKeyRecord {
            verifying_key,
            _kid: ca_kid.to_string(),
        });
    }

    /// Mark a certificate as revoked.
    pub fn revoke_certificate(&self, cert_id: &str) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.revoked_certs.insert(cert_id.to_string());
    }

    /// Verify an AgentIdentityCertificate.
    ///
    /// Checks:
    /// 1. cert_id not revoked
    /// 2. Not expired
    /// 3. CA key known
    /// 4. Signature valid over body_bytes()
    pub fn verify_certificate(&self, cert: &AgentIdentityCertificate) -> Result<(), SAACPHardDrop> {
        let (revoked, ca_verifying_key) = {
            let inner = self.inner.lock().expect("lock poisoned");
            let revoked = inner.revoked_certs.contains(&cert.cert_id);
            let ca_key = inner.ca_keys.get(&cert.ca_kid).map(|r| r.verifying_key);
            (revoked, ca_key)
        };

        if revoked {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::KeyRevoked,
                format!("C-3: Identity certificate '{}' for agent '{}' has been revoked.",
                    cert.cert_id, cert.agent_id),
            ));
        }
        if cert.is_expired() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                format!("C-3: Identity certificate for agent '{}' has expired.", cert.agent_id),
            ));
        }
        let ca_pub = ca_verifying_key.ok_or_else(|| SAACPHardDrop::new(
            SAACPBytecodes::IdentityBindingMissing,
            format!("C-3: CA key '{}' not registered in IdentityVerifier.", cert.ca_kid),
        ))?;

        // Verify signature
        if cert.cert_signature.len() != 64 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                format!("C-3: Identity certificate signature invalid length for agent '{}'.", cert.agent_id),
            ));
        }
        let sig_bytes: [u8; 64] = cert.cert_signature[..].try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        let body = cert.body_bytes();
        if ca_pub.verify(&body, &sig).is_err() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                format!("C-3: Identity certificate signature invalid for agent '{}'.", cert.agent_id),
            ));
        }

        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.verified.insert(cert.agent_id.clone(), cert.cert_id.clone());
        Ok(())
    }

    /// Verify that agent_id's claimed_public_key_hex matches the key in the
    /// session transcript for the given role ("client" or "server").
    pub fn verify_transcript_binding(
        &self,
        session: &TranscriptBoundSession,
        agent_id: &str,
        claimed_public_key_hex: &str,
        role: &str,
    ) -> Result<(), SAACPHardDrop> {
        let (transcript_key, transcript_agent) = if role == "client" {
            (&session.client_public_key_hex, &session.client_agent_id)
        } else {
            (&session.server_public_key_hex, &session.server_agent_id)
        };

        // Key mismatch → key-swap attack
        if claimed_public_key_hex != transcript_key {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                format!("C-3: Public key presented by '{}' does not match the {} key \
                    committed in the session transcript. Key-swap or session-splice attack detected.",
                    agent_id, role),
            ));
        }

        // Agent ID mismatch → identity relabeling attack
        if agent_id != transcript_agent {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SessionSpliceDetected,
                format!("C-3: Agent identity '{}' does not match transcript {} agent '{}'. \
                    Identity substitution or session-splice detected.",
                    agent_id, role, transcript_agent),
            ));
        }

        Ok(())
    }

    /// Verify that a capability token's thash field matches the session transcript.
    pub fn verify_thash_matches_capability(
        &self,
        session: &TranscriptBoundSession,
        capability_thash: &str,
    ) -> Result<(), SAACPHardDrop> {
        if capability_thash != session.thash {
            let cap_prefix: String = capability_thash.chars().take(16).collect();
            let thash_prefix: String = session.thash.chars().take(16).collect();
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TranscriptHashMismatch,
                format!("C-3: Capability token thash '{}'…' does not match \
                    session transcript thash '{}'…'. Cross-session replay or transcript \
                    tampering detected.", cap_prefix, thash_prefix),
            ));
        }
        Ok(())
    }

    /// Check if an agent's identity has been verified.
    pub fn is_identity_verified(&self, agent_id: &str) -> bool {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.verified.contains_key(agent_id)
    }

    /// Gate: raise SAACPHardDrop if agent_id has not completed identity verification.
    pub fn require_identity_verified(&self, agent_id: &str, operation: &str) -> Result<(), SAACPHardDrop> {
        if !self.is_identity_verified(agent_id) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityNotVerified,
                format!("C-3: Identity verification for agent '{}' must be completed before {}.",
                    agent_id, operation),
            ));
        }
        Ok(())
    }
}

impl Default for IdentityVerifier {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// IdentityGate — Pre-authorization ordering guard
// ---------------------------------------------------------------------------

/// C-3 ordering phases.
pub const IDENTITY_GATE_PHASES: &[&str] = &[
    "IDENTITY_VERIFIED",
    "AUTHORIZED",
    "CAPABILITY_VALIDATED",
    "MEMORY_ACCESSED",
    "DELEGATION_PROCESSED",
    "EXECUTION_ALLOWED",
];

/// Enforces the C-3 ordering invariant:
///
/// Identity verification → Authorization → Capability validation →
/// Memory access → Delegation processed → Application execution
///
/// The gate maintains a per-agent, per-session set of completed phases.
pub struct IdentityGate {
    inner: Mutex<GateInner>,
}

struct GateInner {
    /// (agent_id, sid) → set of completed phases
    progress: HashMap<(String, String), HashSet<String>>,
}

impl IdentityGate {
    /// Create a new IdentityGate.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(GateInner {
                progress: HashMap::new(),
            }),
        }
    }

    fn phase_index(phase: &str) -> Option<usize> {
        IDENTITY_GATE_PHASES.iter().position(|&p| p == phase)
    }

    /// Mark a phase as complete for (agent_id, sid).
    pub fn advance(&self, agent_id: &str, sid: &str, phase: &str) -> Result<(), String> {
        if Self::phase_index(phase).is_none() {
            return Err(format!("Unknown IdentityGate phase: '{phase}'"));
        }
        let mut inner = self.inner.lock().expect("lock poisoned");
        let key = (agent_id.to_string(), sid.to_string());
        inner.progress.entry(key).or_default().insert(phase.to_string());
        Ok(())
    }

    /// Require that all phases up to and including `phase` have been completed.
    pub fn require_phase(&self, agent_id: &str, sid: &str, phase: &str) -> Result<(), SAACPHardDrop> {
        let idx = Self::phase_index(phase).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityNotVerified,
                format!("Unknown IdentityGate phase: '{phase}'"),
            )
        })?;
        let key = (agent_id.to_string(), sid.to_string());
        let completed = {
            let inner = self.inner.lock().expect("lock poisoned");
            inner.progress.get(&key).cloned().unwrap_or_default()
        };

        // Every phase with index <= idx must be completed
        for (i, &p) in IDENTITY_GATE_PHASES.iter().enumerate() {
            if i <= idx && !completed.contains(p) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::IdentityNotVerified,
                    format!("C-3: Phase '{}' must be completed before '{}' for agent '{}' in session '{}'.",
                        p, phase, agent_id, sid),
                ));
            }
        }
        Ok(())
    }

    /// Clear phase state for a session (e.g. on teardown).
    pub fn clear(&self, agent_id: &str, sid: &str) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        let key = (agent_id.to_string(), sid.to_string());
        inner.progress.remove(&key);
    }
}

impl Default for IdentityGate {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SessionIdentityRegistry
// ---------------------------------------------------------------------------

/// Thread-safe registry: thash → TranscriptBoundSession.
pub struct SessionIdentityRegistry {
    inner: Mutex<RegistryInner>,
}

struct RegistryInner {
    sessions: HashMap<String, TranscriptBoundSession>,
}

impl SessionIdentityRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(RegistryInner {
                sessions: HashMap::new(),
            }),
        }
    }

    /// Register a session (keyed by thash).
    pub fn register(&self, session: TranscriptBoundSession) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.sessions.insert(session.thash.clone(), session);
    }

    /// Look up a session by its transcript hash.
    pub fn get_by_thash<F, R>(&self, thash: &str, f: F) -> Option<R>
    where
        F: FnOnce(&TranscriptBoundSession) -> R,
    {
        let inner = self.inner.lock().ok()?;
        inner.sessions.get(thash).map(f)
    }

    /// Look up a session by its session ID hex string.
    pub fn get_by_session_id<F, R>(&self, session_id_hex: &str, f: F) -> Option<R>
    where
        F: FnOnce(&TranscriptBoundSession) -> R,
    {
        let inner = self.inner.lock().ok()?;
        for s in inner.sessions.values() {
            if s.session_id_hex() == session_id_hex {
                return Some(f(s));
            }
        }
        None
    }

    /// Remove a session by thash.
    pub fn remove(&self, thash: &str) {
        let mut inner = self.inner.lock().expect("lock poisoned");
        inner.sessions.remove(thash);
    }

    /// Return the number of registered sessions.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().expect("lock poisoned");
        inner.sessions.len()
    }
}

impl Default for SessionIdentityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Process-wide default identity verifier.
pub static DEFAULT_IDENTITY_VERIFIER: LazyLock<IdentityVerifier> = LazyLock::new(IdentityVerifier::new);

/// Process-wide default identity gate.
pub static DEFAULT_IDENTITY_GATE: LazyLock<IdentityGate> = LazyLock::new(IdentityGate::new);

/// Process-wide default session identity registry.
pub static DEFAULT_IDENTITY_REGISTRY: LazyLock<SessionIdentityRegistry> = LazyLock::new(SessionIdentityRegistry::new);

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn make_ca_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    fn make_agent_keypair() -> (SigningKey, VerifyingKey) {
        let sk = SigningKey::generate(&mut OsRng);
        let vk = sk.verifying_key();
        (sk, vk)
    }

    #[test]
    fn test_certificate_issue_and_verify() {
        let (ca_sk, ca_vk) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-001",
            &agent_pk_hex,
            &ca_sk,
            "ca-kid-01",
            "root-ca",
            86400.0,
            "ed25519",
        );
        assert_eq!(cert.agent_id, "agent-001");
        assert!(!cert.is_expired());
        assert_eq!(cert.cert_signature.len(), 64);

        // Verify signature manually
        let body = cert.body_bytes();
        let sig_bytes: [u8; 64] = cert.cert_signature[..].try_into().unwrap();
        let sig = Signature::from_bytes(&sig_bytes);
        assert!(ca_vk.verify(&body, &sig).is_ok());
    }

    #[test]
    fn test_certificate_serialization() {
        let (ca_sk, _) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-002",
            &agent_pk_hex,
            &ca_sk,
            "ca-kid-01",
            "root-ca",
            86400.0,
            "ed25519",
        );
        let json = cert.to_json();
        let cert2 = AgentIdentityCertificate::from_json(&json).unwrap();
        assert_eq!(cert2.agent_id, "agent-002");
        assert_eq!(cert2.cert_signature, cert.cert_signature);
    }

    #[test]
    fn test_certificate_fingerprint() {
        let (ca_sk, _) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-003",
            &agent_pk_hex,
            &ca_sk,
            "ca-kid-01",
            "root-ca",
            86400.0,
            "ed25519",
        );
        let fp = cert.fingerprint();
        assert_eq!(fp.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_transcript_bound_session_establish() {
        let sid = vec![0xAB; 16];
        let session = TranscriptBoundSession::establish(
            sid.clone(),
            "client-agent",
            "server-agent",
            &"aa".repeat(32),
            &"bb".repeat(32),
            &"cc".repeat(16),
            &"dd".repeat(16),
            "SAACP/0.1-beta2",
            "Ed25519-AES256GCM",
            None,
        );
        assert_eq!(session.thash.len(), 64);
        assert!(session.verify_thash_integrity());
        assert!(!session.identity_verified);
    }

    #[test]
    fn test_thash_deterministic() {
        let sid = vec![0xAB; 16];
        let s1 = TranscriptBoundSession::establish(
            sid.clone(), "c", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        let s2 = TranscriptBoundSession::establish(
            sid, "c", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        assert_eq!(s1.thash, s2.thash);
    }

    #[test]
    fn test_thash_different_params() {
        let sid = vec![0xAB; 16];
        let s1 = TranscriptBoundSession::establish(
            sid.clone(), "c1", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        let s2 = TranscriptBoundSession::establish(
            sid, "c2", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        assert_ne!(s1.thash, s2.thash);
    }

    #[test]
    fn test_identity_verifier_certificate_valid() {
        let (ca_sk, ca_vk) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-ok", &agent_pk_hex, &ca_sk, "ca-01", "root", 86400.0, "ed25519",
        );

        let verifier = IdentityVerifier::new();
        verifier.register_ca_key("ca-01", ca_vk);
        assert!(verifier.verify_certificate(&cert).is_ok());
        assert!(verifier.is_identity_verified("agent-ok"));
    }

    #[test]
    fn test_identity_verifier_revoked_cert() {
        let (ca_sk, ca_vk) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-rev", &agent_pk_hex, &ca_sk, "ca-01", "root", 86400.0, "ed25519",
        );

        let verifier = IdentityVerifier::new();
        verifier.register_ca_key("ca-01", ca_vk);
        verifier.revoke_certificate(&cert.cert_id);
        let err = verifier.verify_certificate(&cert).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::KeyRevoked);
    }

    #[test]
    fn test_identity_verifier_unknown_ca() {
        let (ca_sk, _) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-x", &agent_pk_hex, &ca_sk, "ca-unknown", "root", 86400.0, "ed25519",
        );

        let verifier = IdentityVerifier::new();
        let err = verifier.verify_certificate(&cert).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::IdentityBindingMissing);
    }

    #[test]
    fn test_verify_transcript_binding_ok() {
        let sid = vec![0xAB; 16];
        let client_pk = "aa".repeat(32);
        let server_pk = "bb".repeat(32);
        let session = TranscriptBoundSession::establish(
            sid, "client-a", "server-b",
            &client_pk, &server_pk,
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let verifier = IdentityVerifier::new();
        assert!(verifier.verify_transcript_binding(&session, "client-a", &client_pk, "client").is_ok());
        assert!(verifier.verify_transcript_binding(&session, "server-b", &server_pk, "server").is_ok());
    }

    #[test]
    fn test_verify_transcript_binding_key_swap() {
        let sid = vec![0xAB; 16];
        let session = TranscriptBoundSession::establish(
            sid, "client-a", "server-b",
            &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let verifier = IdentityVerifier::new();
        let err = verifier.verify_transcript_binding(&session, "client-a", &"ff".repeat(32), "client").unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::IdentityMisbinding);
    }

    #[test]
    fn test_verify_thash_matches_capability() {
        let sid = vec![0xAB; 16];
        let session = TranscriptBoundSession::establish(
            sid, "c", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        let verifier = IdentityVerifier::new();
        assert!(verifier.verify_thash_matches_capability(&session, &session.thash).is_ok());
        let err = verifier.verify_thash_matches_capability(&session, "wrong_hash").unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::TranscriptHashMismatch);
    }

    #[test]
    fn test_identity_gate_ordering() {
        let gate = IdentityGate::new();
        let agent = "agent-1";
        let sid = "session-1";

        // No phases completed - should fail
        assert!(gate.require_phase(agent, sid, "IDENTITY_VERIFIED").is_err());

        // Advance through phases in order
        gate.advance(agent, sid, "IDENTITY_VERIFIED").unwrap();
        assert!(gate.require_phase(agent, sid, "IDENTITY_VERIFIED").is_ok());
        assert!(gate.require_phase(agent, sid, "AUTHORIZED").is_err());

        gate.advance(agent, sid, "AUTHORIZED").unwrap();
        assert!(gate.require_phase(agent, sid, "AUTHORIZED").is_ok());

        gate.advance(agent, sid, "CAPABILITY_VALIDATED").unwrap();
        gate.advance(agent, sid, "MEMORY_ACCESSED").unwrap();
        gate.advance(agent, sid, "DELEGATION_PROCESSED").unwrap();
        gate.advance(agent, sid, "EXECUTION_ALLOWED").unwrap();
        assert!(gate.require_phase(agent, sid, "EXECUTION_ALLOWED").is_ok());
    }

    #[test]
    fn test_identity_gate_clear() {
        let gate = IdentityGate::new();
        gate.advance("a1", "s1", "IDENTITY_VERIFIED").unwrap();
        gate.clear("a1", "s1");
        assert!(gate.require_phase("a1", "s1", "IDENTITY_VERIFIED").is_err());
    }

    #[test]
    fn test_session_identity_registry() {
        let reg = SessionIdentityRegistry::new();
        assert_eq!(reg.count(), 0);

        let sid = vec![0xAB; 16];
        let session = TranscriptBoundSession::establish(
            sid, "c", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        let thash = session.thash.clone();
        let sid_hex = session.session_id_hex();

        reg.register(session);
        assert_eq!(reg.count(), 1);
        assert!(reg.get_by_thash(&thash, |s| s.client_agent_id.clone()).is_some());
        assert!(reg.get_by_session_id(&sid_hex, |s| s.server_agent_id.clone()).is_some());

        reg.remove(&thash);
        assert_eq!(reg.count(), 0);
    }

    #[test]
    fn test_default_statics() {
        assert!(DEFAULT_IDENTITY_VERIFIER.is_identity_verified("nobody") == false);
        assert!(DEFAULT_IDENTITY_GATE.require_phase("a", "s", "IDENTITY_VERIFIED").is_err());
        assert_eq!(DEFAULT_IDENTITY_REGISTRY.count(), 0);
    }
}
