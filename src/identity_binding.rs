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
        // L-3 fix: `.expect(...)` (loud, unreachable-in-practice panic) instead of the
        // old `body_bytes()`'s internal `.unwrap_or_default()` (silent empty-Vec
        // fallback) — signing over an accidentally-empty body would produce a
        // signature that "verifies" but certifies nothing, a fail-open substitution
        // bug in exactly the kind of thing a signature scheme exists to prevent. See
        // `body_bytes`'s own doc comment for why this specific composition cannot
        // actually fail.
        let body = cert.body_bytes()
            .expect("AgentIdentityCertificate::body_bytes: see its doc comment — cannot fail for this struct");
        let sig = signing_key.sign(&body);
        cert.cert_signature = sig.to_bytes().to_vec();
        cert
    }

    /// Canonical bytes over which cert_signature is computed (no signature field).
    /// Returns deterministic JSON with sorted keys.
    ///
    /// L-3 fix: returns `Result` instead of silently falling back to an empty `Vec` on
    /// serialization failure. In practice this exact composition — a `serde_json::Map`
    /// built purely from `String` fields and finite `f64` timestamps — cannot fail
    /// `serde_json::to_string`: `String`s are always valid UTF-8 and none of these
    /// fields can hold a non-finite float. But "cannot fail today" is exactly the kind
    /// of invariant that should be enforced, not assumed silently: the old
    /// `.unwrap_or_default()` meant that IF it ever did fail, `issue()`/
    /// `verify_certificate` would sign/verify an empty byte string instead of the real
    /// certificate body — a fail-open bug, not a fail-closed one.
    pub fn body_bytes(&self) -> Result<Vec<u8>, String> {
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
        serde_json::to_string(&body)
            .map(|s| s.into_bytes())
            .map_err(|e| format!("failed to canonicalize certificate body: {e}"))
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

/// M-1 fix: use the crate's single canonical constant-time comparison
/// (`security::constant_time_eq`/`constant_time_eq_hex`) instead of local
/// byte-identical copies — see `security::constant_time_eq`'s doc comment.
use crate::security::constant_time_eq_hex;

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
    ///
    /// M-38 fix: every `self.inner.lock()` across `IdentityVerifier`,
    /// `IdentityGate`, and `SessionIdentityRegistry` in this file recovers via
    /// `into_inner()` on poison rather than panicking — each backs a
    /// process-wide singleton (`DEFAULT_IDENTITY_VERIFIER`,
    /// `DEFAULT_IDENTITY_GATE`/`GLOBAL_IDENTITY_GATE`,
    /// `DEFAULT_IDENTITY_REGISTRY`), so one poisoning panic must not cascade
    /// into every other in-flight session's identity-binding checks.
    pub fn register_ca_key(&self, ca_kid: &str, verifying_key: VerifyingKey) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.ca_keys.insert(ca_kid.to_string(), CAKeyRecord {
            verifying_key,
            _kid: ca_kid.to_string(),
        });
    }

    /// Mark a certificate as revoked.
    ///
    /// CRIT-8 fix: also purges any `verified` cache entries pinned to this cert_id.
    /// Without this, an agent that completed identity verification before revocation
    /// would keep passing `is_identity_verified`/`require_identity_verified` forever —
    /// revocation had no effect on the cached "verified" status.
    pub fn revoke_certificate(&self, cert_id: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.revoked_certs.insert(cert_id.to_string());
        inner.verified.retain(|_, verified_cert_id| verified_cert_id != cert_id);
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
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
        // L-3 fix: propagate a hypothetical canonicalization failure as a rejected
        // certificate (fail closed) instead of silently verifying against an empty
        // body (fail open).
        let body = cert.body_bytes().map_err(|e| SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding,
            format!("C-3: failed to canonicalize identity certificate body for agent '{}': {e}", cert.agent_id),
        ))?;
        if ca_pub.verify(&body, &sig).is_err() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                format!("C-3: Identity certificate signature invalid for agent '{}'.", cert.agent_id),
            ));
        }

        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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

        // Key mismatch → key-swap attack.
        // H-3 fix: constant-time comparison. `claimed_public_key_hex` is
        // attacker-controlled (a claimed field presented by the connecting
        // party); a naive `!=` on `&str` short-circuits on the first
        // differing byte, leaking timing information about how many leading
        // hex characters of a guess are correct — the same class of bug
        // fixed for `verify_thash_matches_capability` under H-4. Decoding to
        // bytes and comparing in constant time removes that side channel.
        if !constant_time_eq_hex(claimed_public_key_hex, transcript_key) {
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
        // H-4 fix: constant-time comparison. capability_thash is attacker-controlled
        // (a claimed field on a presented capability token); a naive `!=` on &str
        // short-circuits on the first differing byte, leaking timing information about
        // how many leading hex characters of a guess are correct. Decoding to bytes and
        // comparing in constant time removes that side channel.
        if !constant_time_eq_hex(capability_thash, &session.thash) {
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
    ///
    /// CRIT-8 fix: re-checks `revoked_certs` against the agent's cached cert_id on every
    /// call, rather than trusting bare presence in `verified`. `revoke_certificate` already
    /// evicts the cache eagerly, but this defends in depth against any code path that could
    /// otherwise leave a stale, revoked cert_id in `verified`.
    pub fn is_identity_verified(&self, agent_id: &str) -> bool {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        match inner.verified.get(agent_id) {
            Some(cert_id) => !inner.revoked_certs.contains(cert_id),
            None => false,
        }
    }

    /// Gate: raise SAACPHardDrop if agent_id has not completed identity verification, or if
    /// the certificate it was verified against has since been revoked.
    pub fn require_identity_verified(&self, agent_id: &str, operation: &str) -> Result<(), SAACPHardDrop> {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let cert_id = inner.verified.get(agent_id).ok_or_else(|| SAACPHardDrop::new(
            SAACPBytecodes::IdentityNotVerified,
            format!("C-3: Identity verification for agent '{}' must be completed before {}.",
                agent_id, operation),
        ))?;
        if inner.revoked_certs.contains(cert_id) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::KeyRevoked,
                format!("C-3: Identity certificate for agent '{}' has been revoked; \
                    re-verification is required before {}.", agent_id, operation),
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

/// M-31 fix: maximum tracked (agent_id, sid) progress entries before
/// oldest-first eviction runs. Matches the order of magnitude of this
/// codebase's other bounded per-session/per-agent stores (e.g.
/// `memory::CHECKPOINT_MAX_ENTRIES`, `trust_decay::TRUST_MAX_ENTRIES`).
pub const IDENTITY_GATE_MAX_ENTRIES: usize = 10_000;

/// M-31 fix: maximum tracked transcript-bound sessions before oldest-first
/// eviction runs.
pub const SESSION_IDENTITY_REGISTRY_MAX_ENTRIES: usize = 10_000;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

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
    /// (agent_id, sid) → progress record
    progress: HashMap<(String, String), GateProgress>,
}

/// M-31 fix: completed-phase set plus a `last_touched` timestamp, so
/// capacity-forced eviction can remove the oldest entries first instead of
/// relying on arbitrary `HashMap` iteration order.
struct GateProgress {
    phases: HashSet<String>,
    last_touched: f64,
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

    /// M-31 fix: forcibly remove the oldest `evict_count` entries by
    /// `last_touched`, ascending. Called only once `progress` is at or over
    /// `IDENTITY_GATE_MAX_ENTRIES` and the incoming key is new — an
    /// evicted (agent_id, sid) pair simply has to redo the C-3 handshake
    /// from the start (`require_phase` already fails closed with no
    /// progress entry present), which is the correct fail-closed outcome:
    /// eviction can only ever DEGRADE a pair back to "must re-authenticate",
    /// never advance it to implicitly-authenticated.
    fn evict_oldest(progress: &mut HashMap<(String, String), GateProgress>, evict_count: usize) {
        let mut by_age: Vec<((String, String), f64)> = progress
            .iter()
            .map(|(k, v)| (k.clone(), v.last_touched))
            .collect();
        by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
        for (k, _) in by_age.into_iter().take(evict_count) {
            progress.remove(&k);
        }
    }

    /// Mark a phase as complete for (agent_id, sid).
    pub fn advance(&self, agent_id: &str, sid: &str, phase: &str) -> Result<(), String> {
        if Self::phase_index(phase).is_none() {
            return Err(format!("Unknown IdentityGate phase: '{phase}'"));
        }
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        let key = (agent_id.to_string(), sid.to_string());
        let now = now_secs();

        if inner.progress.len() >= IDENTITY_GATE_MAX_ENTRIES && !inner.progress.contains_key(&key) {
            let evict_count = inner.progress.len() + 1 - IDENTITY_GATE_MAX_ENTRIES;
            Self::evict_oldest(&mut inner.progress, evict_count);
        }

        let entry = inner.progress.entry(key).or_insert_with(|| GateProgress {
            phases: HashSet::new(),
            last_touched: now,
        });
        entry.phases.insert(phase.to_string());
        entry.last_touched = now;
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
            let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
            inner.progress.get(&key).map(|p| p.phases.clone()).unwrap_or_default()
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
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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
    ///
    /// M-31 fix: forces oldest-`established_at`-first eviction once the
    /// registry is at `SESSION_IDENTITY_REGISTRY_MAX_ENTRIES` and the
    /// incoming thash is new. An evicted session simply requires the client
    /// to re-establish (its Gate C-3/identity-binding handshake must run
    /// again) — fail-closed, matching `IdentityGate::evict_oldest`'s same
    /// posture on the sibling structure this finding also targets.
    pub fn register(&self, session: TranscriptBoundSession) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        if inner.sessions.len() >= SESSION_IDENTITY_REGISTRY_MAX_ENTRIES
            && !inner.sessions.contains_key(&session.thash)
        {
            let evict_count = inner.sessions.len() + 1 - SESSION_IDENTITY_REGISTRY_MAX_ENTRIES;
            let mut by_age: Vec<(String, f64)> = inner.sessions.iter()
                .map(|(k, v)| (k.clone(), v.established_at))
                .collect();
            by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (k, _) in by_age.into_iter().take(evict_count) {
                inner.sessions.remove(&k);
            }
        }
        inner.sessions.insert(session.thash.clone(), session);
    }

    /// Look up a session by its transcript hash.
    ///
    /// M-38 fix: recovers via `into_inner()` on poison instead of `.ok()?`-mapping
    /// poison to `None` (indistinguishable from "no session with this thash") —
    /// `DEFAULT_IDENTITY_REGISTRY` is a process-wide singleton.
    pub fn get_by_thash<F, R>(&self, thash: &str, f: F) -> Option<R>
    where
        F: FnOnce(&TranscriptBoundSession) -> R,
    {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.sessions.get(thash).map(f)
    }

    /// Look up a session by its session ID hex string.
    ///
    /// M-38 fix: see `get_by_thash`'s doc comment — same poison-recovery fix.
    pub fn get_by_session_id<F, R>(&self, session_id_hex: &str, f: F) -> Option<R>
    where
        F: FnOnce(&TranscriptBoundSession) -> R,
    {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        for s in inner.sessions.values() {
            if s.session_id_hex() == session_id_hex {
                return Some(f(s));
            }
        }
        None
    }

    /// Remove a session by thash.
    pub fn remove(&self, thash: &str) {
        let mut inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
        inner.sessions.remove(thash);
    }

    /// Return the number of registered sessions.
    pub fn count(&self) -> usize {
        let inner = self.inner.lock().unwrap_or_else(|e| e.into_inner());
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

pub static GLOBAL_IDENTITY_GATE: LazyLock<IdentityGate> = LazyLock::new(IdentityGate::new);

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
        let body = cert.body_bytes().unwrap();
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

    /// CRIT-8 regression test: revoking a certificate AFTER the agent has already
    /// completed identity verification must immediately invalidate the cached
    /// "verified" status — not leave it valid until some unrelated re-verification.
    #[test]
    fn test_crit8_revocation_invalidates_verified_cache() {
        let (ca_sk, ca_vk) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-cached", &agent_pk_hex, &ca_sk, "ca-01", "root", 86400.0, "ed25519",
        );

        let verifier = IdentityVerifier::new();
        verifier.register_ca_key("ca-01", ca_vk);

        // Agent completes identity verification — cached as verified.
        assert!(verifier.verify_certificate(&cert).is_ok());
        assert!(verifier.is_identity_verified("agent-cached"));
        assert!(verifier.require_identity_verified("agent-cached", "test op").is_ok());

        // Certificate is revoked (e.g. compromise detected) AFTER caching.
        verifier.revoke_certificate(&cert.cert_id);

        // The cached "verified" status must no longer be trusted. `revoke_certificate`
        // eagerly purges the `verified` entry, so the subsequent read sees no cached
        // entry at all (IdentityNotVerified) rather than a revoked one (KeyRevoked) —
        // either way it fails closed, which is what matters here.
        assert!(
            !verifier.is_identity_verified("agent-cached"),
            "CRIT-8: revocation must invalidate the cached verified status"
        );
        let err = verifier.require_identity_verified("agent-cached", "test op").unwrap_err();
        assert_eq!(
            err.bytecode, SAACPBytecodes::IdentityNotVerified,
            "CRIT-8: eager purge removes the cache entry entirely, so re-verification is required"
        );
    }

    /// CRIT-8: even if a stale `verified` entry somehow survives `revoke_certificate`'s
    /// eager purge, `is_identity_verified`/`require_identity_verified` must independently
    /// re-check `revoked_certs` at read time (defense in depth).
    #[test]
    fn test_crit8_defensive_recheck_on_read() {
        let (ca_sk, ca_vk) = make_ca_keypair();
        let (_, agent_vk) = make_agent_keypair();
        let agent_pk_hex = hex::encode(agent_vk.as_bytes());

        let cert = AgentIdentityCertificate::issue(
            "agent-defense", &agent_pk_hex, &ca_sk, "ca-01", "root", 86400.0, "ed25519",
        );

        let verifier = IdentityVerifier::new();
        verifier.register_ca_key("ca-01", ca_vk);
        assert!(verifier.verify_certificate(&cert).is_ok());

        // Simulate a stale cache entry bypassing revoke_certificate's purge by
        // revoking the cert_id directly in the inner revoked set.
        {
            let mut inner = verifier.inner.lock().unwrap();
            inner.revoked_certs.insert(cert.cert_id.clone());
            // `verified` intentionally left untouched here.
        }

        assert!(
            !verifier.is_identity_verified("agent-defense"),
            "CRIT-8: read-time recheck must catch a revoked cert_id even without eager purge"
        );
        let err = verifier.require_identity_verified("agent-defense", "test op").unwrap_err();
        assert_eq!(
            err.bytecode, SAACPBytecodes::KeyRevoked,
            "CRIT-8: require_identity_verified must report KeyRevoked when the cached \
                cert_id is present in revoked_certs"
        );
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

    /// H-3 regression: `verify_transcript_binding`'s public-key comparison must
    /// use `constant_time_eq_hex` rather than a short-circuiting `&str` `!=`
    /// (mirrors the H-4 fix for `verify_thash_matches_capability`). Exercises
    /// exact match, well-formed-but-wrong hex differing only in the last byte,
    /// and malformed non-hex input — all must produce the same pass/fail
    /// outcome as before the fix, without the timing side-channel.
    #[test]
    fn test_verify_transcript_binding_constant_time() {
        let sid = vec![0xAB; 16];
        let client_pk = "aa".repeat(32);
        let session = TranscriptBoundSession::establish(
            sid, "client-a", "server-b",
            &client_pk, &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let verifier = IdentityVerifier::new();

        // Exact match still succeeds.
        assert!(verifier.verify_transcript_binding(&session, "client-a", &client_pk, "client").is_ok());

        // Well-formed hex, same length, differing only in the final byte.
        let mut tampered = client_pk.clone();
        let last = tampered.pop().unwrap();
        let flipped = if last == 'a' { 'b' } else { 'a' };
        tampered.push(flipped);
        let err = verifier.verify_transcript_binding(&session, "client-a", &tampered, "client").unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::IdentityMisbinding);

        // Malformed non-hex input must be rejected (fail-closed), not panic.
        let err = verifier.verify_transcript_binding(&session, "client-a", "not-valid-hex!!", "client").unwrap_err();
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

    /// H-4 regression: `verify_thash_matches_capability` must now compare via
    /// `constant_time_eq_hex` rather than a short-circuiting `&str` `!=`. This test
    /// exercises the three cases the fix must preserve correctness for: exact match,
    /// well-formed-but-wrong-content hex (differs only in the last byte, so a
    /// short-circuiting compare would previously have leaked the most timing signal
    /// here), and malformed non-hex input — all with the same pass/fail outcome as
    /// before the fix, just without the timing side-channel.
    #[test]
    fn test_verify_thash_matches_capability_constant_time() {
        let sid = vec![0xAB; 16];
        let session = TranscriptBoundSession::establish(
            sid, "c", "s", &"aa".repeat(32), &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16), "v1", "cs1", None,
        );
        let verifier = IdentityVerifier::new();

        // Exact match still succeeds.
        assert!(verifier.verify_thash_matches_capability(&session, &session.thash).is_ok());

        // Well-formed hex, same length, differing only in the final byte.
        let mut tampered = session.thash.clone();
        let last = tampered.pop().unwrap();
        let flipped = if last == '0' { '1' } else { '0' };
        tampered.push(flipped);
        let err = verifier.verify_thash_matches_capability(&session, &tampered).unwrap_err();
        assert_eq!(err.bytecode, SAACPBytecodes::TranscriptHashMismatch);

        // Malformed non-hex input must be rejected (fail-closed), not panic.
        let err = verifier.verify_thash_matches_capability(&session, "not-valid-hex!!").unwrap_err();
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

    // -- M-31: IdentityGate bounded growth, oldest-first eviction --

    #[test]
    fn test_identity_gate_evicts_oldest_first_at_capacity() {
        let gate = IdentityGate::new();
        {
            let mut inner = gate.inner.lock().unwrap();
            // Fill to exactly capacity with DESCENDING last_touched (so
            // HashMap iteration/key order is the exact opposite of age
            // order) — proves eviction sorts by actual age, not by
            // arbitrary map order.
            for i in 0..IDENTITY_GATE_MAX_ENTRIES {
                let last_touched = (IDENTITY_GATE_MAX_ENTRIES - i) as f64;
                inner.progress.insert(
                    (format!("agent-{i:06}"), "sess".to_string()),
                    GateProgress { phases: HashSet::new(), last_touched },
                );
            }
        }
        assert_eq!(gate.inner.lock().unwrap().progress.len(), IDENTITY_GATE_MAX_ENTRIES);

        // One more distinct key must trigger eviction, not grow past the cap.
        gate.advance("brand-new-agent", "sess", "IDENTITY_VERIFIED").unwrap();
        let inner = gate.inner.lock().unwrap();
        assert!(
            inner.progress.len() <= IDENTITY_GATE_MAX_ENTRIES,
            "M-31: IdentityGate must not grow past IDENTITY_GATE_MAX_ENTRIES"
        );

        // The newly-advanced entry (freshest last_touched) must survive.
        assert!(
            inner.progress.contains_key(&("brand-new-agent".to_string(), "sess".to_string())),
            "the just-advanced entry must not be evicted"
        );
        // Every surviving pre-existing entry must have a last_touched
        // STRICTLY GREATER than the smallest possible value (1.0) — i.e.
        // the genuinely oldest entries (last_touched near 1..few) were
        // evicted first, not entries chosen by key/hash order.
        let min_surviving_prefilled = inner.progress.iter()
            .filter(|(k, _)| k.0 != "brand-new-agent")
            .map(|(_, v)| v.last_touched)
            .fold(f64::INFINITY, f64::min);
        assert!(
            min_surviving_prefilled > 1.0,
            "M-31: the oldest pre-filled entries must be evicted first, but found \
             a surviving entry with last_touched={min_surviving_prefilled}"
        );
    }

    #[test]
    fn test_identity_gate_evicted_pair_fails_closed_not_open() {
        // An evicted (agent_id, sid) pair must degrade to "must
        // re-authenticate" (require_phase fails), never be silently treated
        // as already-authorized.
        let gate = IdentityGate::new();
        {
            let mut inner = gate.inner.lock().unwrap();
            for i in 0..IDENTITY_GATE_MAX_ENTRIES {
                let mut phases = HashSet::new();
                phases.insert("IDENTITY_VERIFIED".to_string());
                inner.progress.insert(
                    (format!("agent-{i:06}"), "sess".to_string()),
                    GateProgress { phases, last_touched: i as f64 },
                );
            }
        }
        // Before eviction: agent-000000 already completed IDENTITY_VERIFIED,
        // so requiring exactly that phase must currently succeed.
        assert!(
            gate.require_phase("agent-000000", "sess", "IDENTITY_VERIFIED").is_ok(),
            "test setup: agent-000000 must start with IDENTITY_VERIFIED completed"
        );

        // Force eviction of the very oldest entry (last_touched == 0.0, i.e.
        // agent-000000 specifically).
        gate.advance("forcing-eviction-agent", "sess", "IDENTITY_VERIFIED").unwrap();

        // agent-000000 had the smallest last_touched (0.0) and must now have
        // been evicted — requiring the SAME phase it had already completed
        // must now fail (no progress entry at all), proving eviction
        // actually removed real, previously-satisfied progress rather than
        // just failing to complete a phase it never had.
        let result = gate.require_phase("agent-000000", "sess", "IDENTITY_VERIFIED");
        assert!(
            result.is_err(),
            "M-31: an evicted pair must fail closed (require re-auth for a phase \
             it had already completed), not silently keep passing"
        );
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

    // -- M-31: SessionIdentityRegistry bounded growth, oldest-first eviction --

    fn test_session_at(thash_seed: u32, established_at: f64) -> TranscriptBoundSession {
        let sid = format!("{thash_seed:032x}").into_bytes();
        let mut session = TranscriptBoundSession::establish(
            sid.clone(),
            &format!("client-{thash_seed}"),
            "server",
            &"aa".repeat(32),
            &"bb".repeat(32),
            &format!("{thash_seed:032x}"),
            &format!("{thash_seed:032x}"),
            "v1",
            "cs1",
            None,
        );
        // establish() sets established_at to the real now_secs(); overwrite
        // it directly (established_at is a `pub` field) for deterministic,
        // non-flaky age control instead of relying on real wall-clock deltas
        // in a tight loop.
        session.established_at = established_at;
        session
    }

    #[test]
    fn test_session_identity_registry_evicts_oldest_first_at_capacity() {
        let reg = SessionIdentityRegistry::new();
        {
            let mut inner = reg.inner.lock().unwrap();
            for i in 0..SESSION_IDENTITY_REGISTRY_MAX_ENTRIES {
                // Descending established_at (opposite of insertion/key order)
                // so eviction-by-key-order would evict the WRONG entries.
                let established_at = (SESSION_IDENTITY_REGISTRY_MAX_ENTRIES - i) as f64;
                let session = test_session_at(i as u32, established_at);
                inner.sessions.insert(session.thash.clone(), session);
            }
        }
        assert_eq!(reg.count(), SESSION_IDENTITY_REGISTRY_MAX_ENTRIES);

        let newest = test_session_at(u32::MAX, 999_999.0);
        let newest_thash = newest.thash.clone();
        reg.register(newest);

        assert!(
            reg.count() <= SESSION_IDENTITY_REGISTRY_MAX_ENTRIES,
            "M-31: SessionIdentityRegistry must not grow past its cap"
        );
        assert!(
            reg.get_by_thash(&newest_thash, |_| ()).is_some(),
            "the just-registered newest session must survive"
        );

        let inner = reg.inner.lock().unwrap();
        let min_surviving_established_at = inner.sessions.values()
            .map(|s| s.established_at)
            .filter(|&t| t < 999_999.0)
            .fold(f64::INFINITY, f64::min);
        assert!(
            min_surviving_established_at > 1.0,
            "M-31: the oldest pre-filled session must be evicted first, but found \
             a surviving session with established_at={min_surviving_established_at}"
        );
    }

    #[test]
    fn test_default_statics() {
        assert!(!DEFAULT_IDENTITY_VERIFIER.is_identity_verified("nobody"));
        assert!(DEFAULT_IDENTITY_GATE.require_phase("a", "s", "IDENTITY_VERIFIED").is_err());
        assert_eq!(DEFAULT_IDENTITY_REGISTRY.count(), 0);
    }
}
