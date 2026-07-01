//! Federated Agent Identity and Trust Framework (FAITF)
//!
//! Implements the complete FAITF specification:
//! 1. `AgentIdentity` — Unique long-term Ed25519 keypair per agent.
//! 2. `AgentCredential` — Serializable, signed credential (wire-transmittable).
//! 3. `TrustAnchor` — A trusted root or federation authority.
//! 4. `TrustStore` — Thread-safe registry of trust anchors.
//! 5. `DistributedRevocationInfrastructure` (DRI) — Signed revocation records.
//! 6. `TrustMeshFederation` — Multi-org trust mesh without shared secrets.
//! 7. `IdentityProver` — Challenge-response proof of Ed25519 key possession.
//! 8. `DelegationChain` — Depth-limited, privilege-downward delegation.
//! 9. `CredentialRenewal` — Key rotation with overlap periods.
//! 10. `HardwareAttestationStub` — Interface for TPM/HSM/TEE integration.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde_json;
use sha2::{Digest, Sha256};

// ─── Constants ──────────────────────────────────────────────────────────────────

pub const FAITF_VERSION: &str = "1.0";
pub const FAITF_MAX_DELEGATION_DEPTH: usize = 3;
pub const IDENTITY_PROOF_TTL: f64 = 30.0;
pub const MAX_CLOCK_SKEW: f64 = 5.0;
pub const CREDENTIAL_SIG_MARKER: &str = "ed25519";
pub const PSK_SIG_MARKER: &str = "hmac-sha256";

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn pub_key_fingerprint(key: &VerifyingKey) -> String {
    hex::encode(Sha256::digest(key.as_bytes()))
}

fn sign_data(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    signing_key.sign(message).to_bytes().to_vec()
}

fn verify_data(verifying_key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message, &sig).is_ok()
}

fn sorted_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    // serde_json with BTreeMap produces sorted keys by default
    serde_json::to_vec(value).unwrap_or_default()
}

// ─── Enumerations ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustModel {
    /// Direct trust: agent trusts issuer directly (self-signed / bilateral).
    /// Matches Python `TrustModel.DIRECT`.
    Direct,
    CentralizedCa,
    DecentralizedAnchors,
    FederatedDomains,
    Organizational,
    ManuallyPinned,
    OfflineBundle,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AttestationType {
    None,
    Tpm,
    Hsm,
    Tee,
    Enclave,
}

impl AttestationType {
    pub fn value(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Tpm => "tpm",
            Self::Hsm => "hsm",
            Self::Tee => "tee",
            Self::Enclave => "secure_enclave",
        }
    }

    pub fn is_implemented(&self) -> bool {
        matches!(self, Self::None)
    }

    pub fn requires_hardware_provider(&self) -> bool {
        !self.is_implemented()
    }
}

// ─── AgentIdentity ──────────────────────────────────────────────────────────────

/// A provisioned cryptographic identity for a single agent.
pub struct AgentIdentity {
    pub agent_id: String,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub issuer_id: String,
    pub credential_version: u32,
    pub not_before: f64,
    pub not_after: f64,
    pub trust_policy: serde_json::Value,
    pub revocation_info: String,
    pub supported_protocols: Vec<String>,
    pub capability_constraints: serde_json::Value,
    pub attestation_type: AttestationType,
}

impl AgentIdentity {
    /// Generate a fresh Ed25519 identity for an agent.
    pub fn generate(
        agent_id: &str,
        issuer_id: &str,
        ttl_seconds: u64,
        trust_policy: Option<serde_json::Value>,
        capability_constraints: Option<serde_json::Value>,
        revocation_info: &str,
        attestation_type: AttestationType,
    ) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        let now = now_f64();
        Self {
            agent_id: agent_id.to_string(),
            signing_key,
            verifying_key,
            issuer_id: issuer_id.to_string(),
            credential_version: 1,
            not_before: now,
            not_after: now + ttl_seconds as f64,
            trust_policy: trust_policy.unwrap_or(serde_json::Value::Object(Default::default())),
            revocation_info: revocation_info.to_string(),
            supported_protocols: vec!["SAACP/0.1-beta2".to_string()],
            capability_constraints: capability_constraints
                .unwrap_or(serde_json::Value::Object(Default::default())),
            attestation_type,
        }
    }

    pub fn is_valid_now(&self) -> bool {
        let now = now_f64();
        self.not_before <= now && now <= self.not_after
    }

    pub fn fingerprint(&self) -> String {
        pub_key_fingerprint(&self.verifying_key)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        *self.verifying_key.as_bytes()
    }
}

// ─── AgentCredential ────────────────────────────────────────────────────────────

/// A wire-transmittable, signed credential for one agent.
#[derive(Debug, Clone)]
pub struct AgentCredential {
    pub payload: serde_json::Value,
    pub signature: Vec<u8>,
    pub issuer_public_key_id: String,
}

impl AgentCredential {
    /// Issuer signs the public fields of an AgentIdentity to create a credential.
    pub fn issue(
        identity: &AgentIdentity,
        issuer_signing_key: &SigningKey,
        issuer_verifying_key: &VerifyingKey,
    ) -> Self {
        let payload = serde_json::json!({
            "faitf_version": FAITF_VERSION,
            "agent_id": identity.agent_id,
            "public_key_b64": B64.encode(identity.public_key_bytes()),
            "issuer_id": identity.issuer_id,
            "credential_version": identity.credential_version,
            "not_before": identity.not_before,
            "not_after": identity.not_after,
            "trust_policy": identity.trust_policy,
            "revocation_info": identity.revocation_info,
            "supported_protocols": identity.supported_protocols,
            "capability_constraints": identity.capability_constraints,
            "attestation_type": identity.attestation_type.value(),
        });
        let payload_bytes = sorted_json_bytes(&payload);
        let sig = sign_data(issuer_signing_key, &payload_bytes);
        Self {
            payload,
            signature: sig,
            issuer_public_key_id: pub_key_fingerprint(issuer_verifying_key),
        }
    }

    /// Serialize to wire format: base64(4-byte-BE-json-len || json || sig || issuer_key_id).
    pub fn to_wire(&self) -> Vec<u8> {
        let payload_bytes = sorted_json_bytes(&self.payload);
        let mut packed = Vec::new();
        packed.extend_from_slice(&(payload_bytes.len() as u32).to_be_bytes());
        packed.extend_from_slice(&payload_bytes);
        packed.extend_from_slice(&self.signature);
        packed.extend_from_slice(self.issuer_public_key_id.as_bytes());
        B64.encode(&packed).into_bytes()
    }

    /// Deserialize from wire format.
    pub fn from_wire(wire: &[u8]) -> Result<Self, String> {
        let raw = B64
            .decode(wire)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        if raw.len() < 4 {
            return Err("Credential too short".to_string());
        }
        let payload_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if payload_len == 0 || payload_len + 4 + 64 > raw.len() {
            return Err("Invalid payload length".to_string());
        }
        let payload_bytes = &raw[4..4 + payload_len];
        let sig = raw[4 + payload_len..4 + payload_len + 64].to_vec();
        let issuer_key_id = String::from_utf8_lossy(&raw[4 + payload_len + 64..]).to_string();
        let payload: serde_json::Value = serde_json::from_slice(payload_bytes)
            .map_err(|e| format!("Malformed AgentCredential wire format: {e}"))?;
        Ok(Self {
            payload,
            signature: sig,
            issuer_public_key_id: issuer_key_id,
        })
    }

    /// Recover the agent's Ed25519 public key from the credential payload.
    pub fn agent_public_key(&self) -> Result<VerifyingKey, String> {
        let pk_b64 = self
            .payload
            .get("public_key_b64")
            .and_then(|v| v.as_str())
            .ok_or("Missing public_key_b64")?;
        let pk_bytes = B64
            .decode(pk_b64)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        if pk_bytes.len() != 32 {
            return Err("Invalid public key length".to_string());
        }
        let mut key_bytes = [0u8; 32];
        key_bytes.copy_from_slice(&pk_bytes);
        VerifyingKey::from_bytes(&key_bytes).map_err(|e| format!("Invalid Ed25519 key: {e}"))
    }

    pub fn agent_id(&self) -> String {
        self.payload
            .get("agent_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    pub fn is_expired(&self) -> bool {
        now_f64() > self.payload.get("not_after").and_then(|v| v.as_f64()).unwrap_or(0.0)
    }

    pub fn is_active(&self) -> bool {
        let now = now_f64();
        let nb = self.payload.get("not_before").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let na = self.payload.get("not_after").and_then(|v| v.as_f64()).unwrap_or(0.0);
        nb <= now && now <= na
    }

    pub fn credential_version(&self) -> u32 {
        self.payload
            .get("credential_version")
            .and_then(|v| v.as_u64())
            .unwrap_or(1) as u32
    }

    /// SHA-256 fingerprint of this credential's payload (unique ID).
    pub fn fingerprint(&self) -> String {
        let payload_bytes = sorted_json_bytes(&self.payload);
        let mut hasher = Sha256::new();
        hasher.update(&payload_bytes);
        hasher.update(&self.signature);
        hex::encode(hasher.finalize())
    }
}

// ─── TrustAnchor ────────────────────────────────────────────────────────────────

/// A trust root that can issue and verify AgentCredentials.
pub struct TrustAnchor {
    pub anchor_id: String,
    pub verifying_key: VerifyingKey,
    pub trust_domains: Vec<String>,
    pub max_delegation_depth: usize,
    pub valid_until: f64,
    pub trust_model: TrustModel,
    pub metadata: serde_json::Value,
}

impl TrustAnchor {
    pub fn new(anchor_id: &str, verifying_key: VerifyingKey) -> Self {
        Self {
            anchor_id: anchor_id.to_string(),
            verifying_key,
            trust_domains: Vec::new(),
            max_delegation_depth: FAITF_MAX_DELEGATION_DEPTH,
            valid_until: now_f64() + 365.0 * 86400.0,
            trust_model: TrustModel::CentralizedCa,
            metadata: serde_json::Value::Object(Default::default()),
        }
    }

    pub fn is_valid(&self) -> bool {
        now_f64() <= self.valid_until
    }

    pub fn fingerprint(&self) -> String {
        pub_key_fingerprint(&self.verifying_key)
    }

    pub fn covers_domain(&self, domain: &str) -> bool {
        if self.trust_domains.is_empty() {
            return true;
        }
        self.trust_domains.iter().any(|d| d == domain)
    }

    pub fn verify_credential(&self, cred: &AgentCredential) -> bool {
        if !self.is_valid() {
            return false;
        }
        if self.fingerprint() != cred.issuer_public_key_id {
            return false;
        }
        let payload_bytes = sorted_json_bytes(&cred.payload);
        verify_data(&self.verifying_key, &payload_bytes, &cred.signature)
    }
}

// ─── TrustStore ─────────────────────────────────────────────────────────────────

/// Thread-safe registry of TrustAnchors and manually pinned identities.
pub struct TrustStore {
    anchors: Mutex<HashMap<String, TrustAnchor>>,
    pinned_keys: Mutex<HashMap<String, VerifyingKey>>,
    keys_by_fp: Mutex<HashMap<String, VerifyingKey>>,
    verification_epoch: Mutex<u64>,
}

impl TrustStore {
    pub fn new() -> Self {
        Self {
            anchors: Mutex::new(HashMap::new()),
            pinned_keys: Mutex::new(HashMap::new()),
            keys_by_fp: Mutex::new(HashMap::new()),
            verification_epoch: Mutex::new(0),
        }
    }

    pub fn register_anchor(&self, anchor: TrustAnchor) {
        let mut anchors = self.anchors.lock().unwrap();
        let mut epoch = self.verification_epoch.lock().unwrap();
        anchors.insert(anchor.anchor_id.clone(), anchor);
        *epoch += 1;
    }

    pub fn remove_anchor(&self, anchor_id: &str) -> bool {
        let mut anchors = self.anchors.lock().unwrap();
        let existed = anchors.remove(anchor_id).is_some();
        if existed {
            *self.verification_epoch.lock().unwrap() += 1;
        }
        existed
    }

    pub fn get_anchor(&self, anchor_id: &str) -> Option<TrustAnchorEntry> {
        let anchors = self.anchors.lock().unwrap();
        anchors.get(anchor_id).map(|a| TrustAnchorEntry {
            anchor_id: a.anchor_id.clone(),
            fingerprint: a.fingerprint(),
            verifying_key: a.verifying_key,
            trust_domains: a.trust_domains.clone(),
            max_delegation_depth: a.max_delegation_depth,
            valid_until: a.valid_until,
            trust_model: a.trust_model,
        })
    }

    pub fn list_anchors(&self) -> Vec<String> {
        self.anchors.lock().unwrap().keys().cloned().collect()
    }

    pub fn pin_identity(&self, agent_id: &str, public_key: VerifyingKey) {
        let mut pinned = self.pinned_keys.lock().unwrap();
        let mut by_fp = self.keys_by_fp.lock().unwrap();
        let fp = pub_key_fingerprint(&public_key);
        pinned.insert(agent_id.to_string(), public_key);
        by_fp.insert(fp, public_key);
        *self.verification_epoch.lock().unwrap() += 1;
    }

    pub fn register_key_by_fingerprint(&self, fingerprint: &str, public_key: VerifyingKey) {
        let mut by_fp = self.keys_by_fp.lock().unwrap();
        by_fp.insert(fingerprint.to_string(), public_key);
        *self.verification_epoch.lock().unwrap() += 1;
    }

    pub fn get_pinned_key(&self, agent_id: &str) -> Option<VerifyingKey> {
        self.pinned_keys.lock().unwrap().get(agent_id).copied()
    }

    pub fn get_key_by_fingerprint(&self, fingerprint: &str) -> Option<VerifyingKey> {
        self.keys_by_fp.lock().unwrap().get(fingerprint).copied()
    }

    /// Verify a credential against all registered anchors.
    /// Returns (success, reason) — reason only populated on failure.
    pub fn verify_credential(&self, cred: &AgentCredential, trust_domain: &str) -> (bool, String) {
        if cred.is_expired() {
            return (false, "credential_expired".to_string());
        }
        if !cred.is_active() {
            return (false, "credential_not_yet_active".to_string());
        }

        let anchors_snapshot: Vec<(String, TrustAnchorSnapshot)> = {
            let anchors = self.anchors.lock().unwrap();
            anchors
                .iter()
                .map(|(k, v)| {
                    (
                        k.clone(),
                        TrustAnchorSnapshot {
                            verifying_key: v.verifying_key,
                            fingerprint: v.fingerprint(),
                            trust_domains: v.trust_domains.clone(),
                            valid_until: v.valid_until,
                        },
                    )
                })
                .collect()
        };
        let pinned_snapshot: HashMap<String, VerifyingKey> = {
            self.pinned_keys.lock().unwrap().clone()
        };

        // 1. Manually pinned identity check
        let agent_id = cred.agent_id();
        if let Some(pinned_pub) = pinned_snapshot.get(&agent_id) {
            let payload_b = sorted_json_bytes(&cred.payload);
            if verify_data(pinned_pub, &payload_b, &cred.signature) {
                return (true, String::new());
            }
        }

        // 2. Trust anchor verification
        for (_, anchor) in &anchors_snapshot {
            if !trust_domain.is_empty() && !anchor.covers_domain(trust_domain) {
                continue;
            }
            if anchor.verify_credential_fast(cred) {
                return (true, String::new());
            }
        }

        if anchors_snapshot.is_empty() && pinned_snapshot.is_empty() {
            return (false, "no_trust_anchors_registered".to_string());
        }
        (false, "no_anchor_verified_credential".to_string())
    }

    pub fn epoch(&self) -> u64 {
        *self.verification_epoch.lock().unwrap()
    }
}

impl Default for TrustStore {
    fn default() -> Self {
        Self::new()
    }
}

/// Snapshot of anchor data for verification without holding the lock.
struct TrustAnchorSnapshot {
    verifying_key: VerifyingKey,
    fingerprint: String,
    trust_domains: Vec<String>,
    valid_until: f64,
}

impl TrustAnchorSnapshot {
    fn covers_domain(&self, domain: &str) -> bool {
        if self.trust_domains.is_empty() {
            return true;
        }
        self.trust_domains.iter().any(|d| d == domain)
    }

    fn verify_credential_fast(&self, cred: &AgentCredential) -> bool {
        if now_f64() > self.valid_until {
            return false;
        }
        if self.fingerprint != cred.issuer_public_key_id {
            return false;
        }
        let payload_bytes = sorted_json_bytes(&cred.payload);
        verify_data(&self.verifying_key, &payload_bytes, &cred.signature)
    }
}

/// Read-only snapshot of a TrustAnchor returned by TrustStore.
pub struct TrustAnchorEntry {
    pub anchor_id: String,
    pub fingerprint: String,
    pub verifying_key: VerifyingKey,
    pub trust_domains: Vec<String>,
    pub max_delegation_depth: usize,
    pub valid_until: f64,
    pub trust_model: TrustModel,
}

// ─── Distributed Revocation Infrastructure (DRI) ───────────────────────────────

/// A cryptographically signed revocation notice for one agent or credential.
#[derive(Debug, Clone)]
pub struct SignedRevocationRecord {
    pub agent_id: String,
    pub credential_fingerprint: String,
    pub reason: String,
    pub revoked_at: f64,
    pub revoker_id: String,
    pub revoker_signature: Vec<u8>,
    pub revoker_key_id: String,
}

impl SignedRevocationRecord {
    /// Deterministic serialization of the fields that are signed.
    pub fn body_bytes(&self) -> Vec<u8> {
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "credential_fingerprint": self.credential_fingerprint,
            "reason": self.reason,
            "revoked_at": self.revoked_at,
            "revoker_id": self.revoker_id,
        });
        sorted_json_bytes(&body)
    }

    /// Compact wire format for propagation to federation members.
    pub fn to_wire(&self) -> Vec<u8> {
        let body = self.body_bytes();
        let mut packed = Vec::new();
        packed.extend_from_slice(&(body.len() as u32).to_be_bytes());
        packed.extend_from_slice(&body);
        packed.extend_from_slice(&self.revoker_signature);
        packed.extend_from_slice(self.revoker_key_id.as_bytes());
        B64.encode(&packed).into_bytes()
    }

    /// Deserialize from wire format.
    pub fn from_wire(wire: &[u8]) -> Result<Self, String> {
        let raw = B64
            .decode(wire)
            .map_err(|e| format!("Base64 decode error: {e}"))?;
        if raw.len() < 4 {
            return Err("Too short".to_string());
        }
        let body_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if 4 + body_len + 64 > raw.len() {
            return Err("Invalid body length".to_string());
        }
        let body_bytes = &raw[4..4 + body_len];
        let sig = raw[4 + body_len..4 + body_len + 64].to_vec();
        let revoker_key_id = String::from_utf8_lossy(&raw[4 + body_len + 64..]).to_string();
        let body: serde_json::Value = serde_json::from_slice(body_bytes)
            .map_err(|e| format!("Malformed SignedRevocationRecord: {e}"))?;
        Ok(Self {
            agent_id: body["agent_id"].as_str().unwrap_or("").to_string(),
            credential_fingerprint: body["credential_fingerprint"]
                .as_str()
                .unwrap_or("")
                .to_string(),
            reason: body["reason"].as_str().unwrap_or("").to_string(),
            revoked_at: body["revoked_at"].as_f64().unwrap_or(0.0),
            revoker_id: body["revoker_id"].as_str().unwrap_or("").to_string(),
            revoker_signature: sig,
            revoker_key_id,
        })
    }

    /// Verify this record's signature against a trust anchor's verifying key.
    /// Used by `TrustMeshFederation::propagate_revocation()` to filter eligible members.
    pub fn is_valid_for_anchor(&self, anchor_key: &ed25519_dalek::VerifyingKey) -> bool {
        let body = self.body_bytes();
        verify_data(anchor_key, &body, &self.revoker_signature)
    }
}

/// Thread-safe, in-memory DRI with signed revocation records.
pub struct DistributedRevocationInfrastructure {
    revoked_agents: Mutex<HashMap<String, SignedRevocationRecord>>,
    revoked_credentials: Mutex<HashMap<String, SignedRevocationRecord>>,
    revocation_epoch: Mutex<u64>,
}

const DRI_MAX_RECORDS: usize = 100_000;

impl DistributedRevocationInfrastructure {
    pub fn new() -> Self {
        Self {
            revoked_agents: Mutex::new(HashMap::new()),
            revoked_credentials: Mutex::new(HashMap::new()),
            revocation_epoch: Mutex::new(0),
        }
    }

    /// Revoke an agent or a specific credential. Returns the signed record.
    pub fn revoke(
        &self,
        agent_id: &str,
        reason: &str,
        revoker_identity: &AgentIdentity,
        credential_fingerprint: &str,
    ) -> SignedRevocationRecord {
        let mut record = SignedRevocationRecord {
            agent_id: agent_id.to_string(),
            credential_fingerprint: credential_fingerprint.to_string(),
            reason: reason.to_string(),
            revoked_at: now_f64(),
            revoker_id: revoker_identity.agent_id.clone(),
            revoker_signature: Vec::new(),
            revoker_key_id: revoker_identity.fingerprint(),
        };
        record.revoker_signature = sign_data(&revoker_identity.signing_key, &record.body_bytes());
        self.store_record(record.clone());
        record
    }

    /// Accept a signed revocation from a federation peer.
    /// Only stores if the revoker's key is trusted by the TrustStore.
    pub fn propagate(&self, wire_record: &[u8], trust_store: &TrustStore) -> bool {
        let record = match SignedRevocationRecord::from_wire(wire_record) {
            Ok(r) => r,
            Err(_) => return false,
        };

        let mut verified = false;
        let anchor_ids = trust_store.list_anchors();
        for aid in anchor_ids {
            if let Some(entry) = trust_store.get_anchor(&aid) {
                if entry.fingerprint == record.revoker_key_id {
                    verified = verify_data(
                        &entry.verifying_key,
                        &record.body_bytes(),
                        &record.revoker_signature,
                    );
                    if verified {
                        break;
                    }
                }
            }
        }

        if !verified {
            return false;
        }

        self.store_record(record);
        true
    }

    fn store_record(&self, record: SignedRevocationRecord) {
        let mut agents = self.revoked_agents.lock().unwrap();
        let mut creds = self.revoked_credentials.lock().unwrap();
        let mut epoch = self.revocation_epoch.lock().unwrap();

        if agents.len() + creds.len() >= DRI_MAX_RECORDS {
            if let Some(oldest_key) = agents
                .iter()
                .min_by(|a, b| a.1.revoked_at.partial_cmp(&b.1.revoked_at).unwrap())
                .map(|(k, _)| k.clone())
            {
                agents.remove(&oldest_key);
            }
        }

        if !record.credential_fingerprint.is_empty() {
            creds.insert(record.credential_fingerprint.clone(), record);
        } else {
            agents.insert(record.agent_id.clone(), record);
        }
        *epoch += 1;
    }

    /// Check if an agent or specific credential is revoked.
    pub fn is_revoked(&self, agent_id: &str, credential_fingerprint: &str) -> bool {
        let agents = self.revoked_agents.lock().unwrap();
        if agents.contains_key(agent_id) {
            return true;
        }
        if !credential_fingerprint.is_empty() {
            let creds = self.revoked_credentials.lock().unwrap();
            if creds.contains_key(credential_fingerprint) {
                return true;
            }
        }
        false
    }

    pub fn get_revocation_record(&self, agent_id: &str) -> Option<SignedRevocationRecord> {
        self.revoked_agents.lock().unwrap().get(agent_id).cloned()
    }

    pub fn epoch(&self) -> u64 {
        *self.revocation_epoch.lock().unwrap()
    }

    pub fn clear(&self) {
        self.revoked_agents.lock().unwrap().clear();
        self.revoked_credentials.lock().unwrap().clear();
        *self.revocation_epoch.lock().unwrap() = 0;
    }
}

impl Default for DistributedRevocationInfrastructure {
    fn default() -> Self {
        Self::new()
    }
}

// ─── TrustMeshFederation ────────────────────────────────────────────────────────

/// A bilateral or multilateral trust agreement between organisations.
#[derive(Debug, Clone)]
pub struct SignedFederationAgreement {
    pub agreement_id: String,
    pub members: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub valid_until: f64,
    pub issuer_id: String,
    pub signature: Vec<u8>,
    pub issuer_key_id: String,
}

impl SignedFederationAgreement {
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut sorted_members = self.members.clone();
        sorted_members.sort();
        let mut sorted_scopes = self.allowed_scopes.clone();
        sorted_scopes.sort();
        let body = serde_json::json!({
            "agreement_id": self.agreement_id,
            "members": sorted_members,
            "allowed_scopes": sorted_scopes,
            "valid_until": self.valid_until,
            "issuer_id": self.issuer_id,
        });
        sorted_json_bytes(&body)
    }

    pub fn is_expired(&self) -> bool {
        now_f64() > self.valid_until
    }
}

/// Multi-organization federated trust without shared secrets.
pub struct TrustMeshFederation {
    members: Mutex<HashMap<String, TrustAnchorMember>>,
    agreements: Mutex<HashMap<String, SignedFederationAgreement>>,
}

#[allow(dead_code)]
struct TrustAnchorMember {
    verifying_key: VerifyingKey,
    fingerprint: String,
    trust_domains: Vec<String>,
    valid_until: f64,
}

impl TrustAnchorMember {
    fn verify_credential(&self, cred: &AgentCredential) -> bool {
        if now_f64() > self.valid_until {
            return false;
        }
        if self.fingerprint != cred.issuer_public_key_id {
            return false;
        }
        let payload_bytes = sorted_json_bytes(&cred.payload);
        verify_data(&self.verifying_key, &payload_bytes, &cred.signature)
    }
}

impl TrustMeshFederation {
    pub fn new() -> Self {
        Self {
            members: Mutex::new(HashMap::new()),
            agreements: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_member(&self, domain: &str, anchor: &TrustAnchor) {
        let mut members = self.members.lock().unwrap();
        members.insert(
            domain.to_string(),
            TrustAnchorMember {
                verifying_key: anchor.verifying_key,
                fingerprint: anchor.fingerprint(),
                trust_domains: anchor.trust_domains.clone(),
                valid_until: anchor.valid_until,
            },
        );
    }

    pub fn register_agreement(
        &self,
        agreement: SignedFederationAgreement,
        issuer_anchor: &TrustAnchor,
    ) -> bool {
        if agreement.is_expired() {
            return false;
        }
        let body = agreement.body_bytes();
        if !verify_data(&issuer_anchor.verifying_key, &body, &agreement.signature) {
            return false;
        }
        let mut agreements = self.agreements.lock().unwrap();
        agreements.insert(agreement.agreement_id.clone(), agreement);
        true
    }

    /// Validate a cross-domain credential access attempt.
    /// Returns (success, reason).
    pub fn validate_cross_domain(
        &self,
        source_cred: &AgentCredential,
        source_domain: &str,
        target_domain: &str,
        requested_scope: &str,
    ) -> (bool, String) {
        let members = self.members.lock().unwrap();
        let agreements = self.agreements.lock().unwrap();

        let source_anchor = match members.get(source_domain) {
            Some(a) => a,
            None => return (false, format!("unknown_source_domain:{source_domain}")),
        };

        if !source_anchor.verify_credential(source_cred) {
            return (false, "credential_not_verified_by_source_anchor".to_string());
        }

        for ag in agreements.values() {
            if ag.is_expired() {
                continue;
            }
            if ag.members.iter().any(|m| m == source_domain)
                && ag.members.iter().any(|m| m == target_domain)
                && ag.allowed_scopes.iter().any(|s| s == requested_scope || s == "*") {
                    return (true, String::new());
                }
        }

        (false, "no_valid_federation_agreement".to_string())
    }

    pub fn list_members(&self) -> Vec<String> {
        self.members.lock().unwrap().keys().cloned().collect()
    }

    /// Propagate a revocation record to all federation members.
    /// Python parity: `TrustMeshFederation.propagate_revocation()`.
    ///
    /// In production this sends the record over the network to each member.
    /// Here we validate the record signature and return the set of domains notified.
    /// The caller is responsible for actual network delivery.
    pub fn propagate_revocation(
        &self,
        record: &crate::faitf::SignedRevocationRecord,
    ) -> Vec<String> {
        let members = self.members.lock().unwrap();
        let mut notified = Vec::new();
        for (domain, member) in members.iter() {
            // Only propagate to members who can verify the record issuer
            if record.is_valid_for_anchor(&member.verifying_key) {
                notified.push(domain.clone());
            }
        }
        notified
    }
}

impl Default for TrustMeshFederation {
    fn default() -> Self {
        Self::new()
    }
}

// ─── IdentityProver ─────────────────────────────────────────────────────────────

/// Proves that an agent possesses the private key corresponding to its credential.
pub struct IdentityProver {
    used_challenges: Mutex<HashMap<Vec<u8>, f64>>,
}

impl IdentityProver {
    pub fn new() -> Self {
        Self {
            used_challenges: Mutex::new(HashMap::new()),
        }
    }

    /// Generate a cryptographically random 32-byte challenge.
    pub fn generate_challenge() -> Vec<u8> {
        let mut buf = vec![0u8; 32];
        rand::RngCore::fill_bytes(&mut OsRng, &mut buf);
        buf
    }

    /// Sign the challenge with the agent's private key.
    /// Returns (signature, timestamp).
    pub fn generate_proof(identity: &AgentIdentity, challenge: &[u8]) -> (Vec<u8>, f64) {
        let timestamp = now_f64();
        let message = Self::proof_message(challenge, &identity.agent_id, timestamp);
        let sig = sign_data(&identity.signing_key, &message);
        (sig, timestamp)
    }

    /// Verify an identity proof.
    /// Returns (success, reason).
    pub fn verify_proof(
        &self,
        proof: &[u8],
        credential: &AgentCredential,
        challenge: &[u8],
        timestamp: f64,
        max_clock_skew: f64,
    ) -> (bool, String) {
        let now = now_f64();

        // 1. Timestamp freshness
        if (now - timestamp).abs() > IDENTITY_PROOF_TTL + max_clock_skew {
            return (false, "proof_timestamp_expired".to_string());
        }

        // 2. Challenge replay prevention
        {
            let mut challenges = self.used_challenges.lock().unwrap();
            Self::evict_expired_challenges(&mut challenges);
            if challenges.contains_key(challenge) {
                return (false, "challenge_already_used".to_string());
            }
            challenges.insert(challenge.to_vec(), now + IDENTITY_PROOF_TTL);
        }

        // 3. Signature verification
        let agent_id = credential.agent_id();
        let message = Self::proof_message(challenge, &agent_id, timestamp);
        let pub_key = match credential.agent_public_key() {
            Ok(k) => k,
            Err(_) => return (false, "malformed_credential_public_key".to_string()),
        };

        if verify_data(&pub_key, &message, proof) {
            (true, String::new())
        } else {
            (false, "invalid_proof_signature".to_string())
        }
    }

    fn proof_message(challenge: &[u8], agent_id: &str, timestamp: f64) -> Vec<u8> {
        let ts_bytes = format!("{:.6}", timestamp);
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(agent_id.as_bytes());
        hasher.update(ts_bytes.as_bytes());
        hasher.finalize().to_vec()
    }

    fn evict_expired_challenges(challenges: &mut HashMap<Vec<u8>, f64>) {
        let now = now_f64();
        challenges.retain(|_, exp| *exp >= now);
    }

    pub fn clear(&self) {
        self.used_challenges.lock().unwrap().clear();
    }
}

impl Default for IdentityProver {
    fn default() -> Self {
        Self::new()
    }
}

// ─── DelegationChain ────────────────────────────────────────────────────────────

/// A credential delegated from a parent credential to a sub-agent.
#[derive(Debug, Clone)]
pub struct DelegatedCredential {
    pub credential: AgentCredential,
    pub parent_agent_id: String,
    pub depth: usize,
    pub constraints: serde_json::Value,
    pub parent_fingerprint: String,
}

/// Verifies and issues delegated credentials.
pub struct DelegationChain;

impl DelegationChain {
    /// Issue a delegated credential from a parent to a child agent.
    pub fn issue_delegated(
        parent_identity: &AgentIdentity,
        parent_credential: &AgentCredential,
        child_agent_id: &str,
        child_public_key: &VerifyingKey,
        child_constraints: serde_json::Value,
        child_ttl_seconds: u64,
        current_depth: usize,
    ) -> Result<DelegatedCredential, String> {
        if current_depth >= FAITF_MAX_DELEGATION_DEPTH {
            return Err(format!(
                "Delegation depth {} would exceed maximum of {}.",
                current_depth, FAITF_MAX_DELEGATION_DEPTH
            ));
        }

        // Privilege amplification check
        let parent_constraints = parent_credential
            .payload
            .get("capability_constraints")
            .cloned()
            .unwrap_or(serde_json::json!({}));
        Self::check_no_amplification(&parent_constraints, &child_constraints)?;

        let now = now_f64();
        let parent_not_after = parent_credential
            .payload
            .get("not_after")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let child_not_after = (now + child_ttl_seconds as f64).min(parent_not_after);

        let child_payload = serde_json::json!({
            "faitf_version": FAITF_VERSION,
            "agent_id": child_agent_id,
            "public_key_b64": B64.encode(child_public_key.as_bytes()),
            "issuer_id": parent_identity.agent_id,
            "credential_version": 1,
            "not_before": now,
            "not_after": child_not_after,
            "trust_policy": parent_credential.payload.get("trust_policy").cloned().unwrap_or(serde_json::json!({})),
            "revocation_info": parent_credential.payload.get("revocation_info").and_then(|v| v.as_str()).unwrap_or(""),
            "supported_protocols": parent_credential.payload.get("supported_protocols").cloned().unwrap_or(serde_json::json!(["SAACP/0.1-beta2"])),
            "capability_constraints": child_constraints,
            "attestation_type": AttestationType::None.value(),
            "_delegation_depth": current_depth,
            "_parent_fingerprint": parent_credential.fingerprint(),
        });

        let payload_bytes = sorted_json_bytes(&child_payload);
        let sig = sign_data(&parent_identity.signing_key, &payload_bytes);

        let child_cred = AgentCredential {
            payload: child_payload.clone(),
            signature: sig,
            issuer_public_key_id: parent_identity.fingerprint(),
        };

        Ok(DelegatedCredential {
            credential: child_cred,
            parent_agent_id: parent_identity.agent_id.clone(),
            depth: current_depth,
            constraints: child_constraints,
            parent_fingerprint: parent_credential.fingerprint(),
        })
    }

    /// Verify a full delegation chain.
    /// chain[0] must be verifiable by a trust anchor.
    pub fn verify_chain(
        chain: &[AgentCredential],
        trust_store: &TrustStore,
    ) -> (bool, String) {
        if chain.is_empty() {
            return (false, "empty_delegation_chain".to_string());
        }
        if chain.len() > FAITF_MAX_DELEGATION_DEPTH + 1 {
            return (false, "delegation_chain_exceeds_max_depth".to_string());
        }

        // Check for circular delegation
        let mut seen_ids = std::collections::HashSet::new();
        for cred in chain {
            let aid = cred.agent_id();
            if !seen_ids.insert(aid) {
                return (false, format!("circular_delegation_detected:{}", cred.agent_id()));
            }
        }

        // Verify root credential against trust store
        let (ok, reason) = trust_store.verify_credential(&chain[0], "");
        if !ok {
            return (false, format!("root_credential_invalid:{reason}"));
        }

        // Verify each subsequent credential
        for i in 1..chain.len() {
            let parent_cred = &chain[i - 1];
            let child_cred = &chain[i];

            let depth = child_cred
                .payload
                .get("_delegation_depth")
                .and_then(|v| v.as_u64())
                .unwrap_or(0) as usize;
            if depth > FAITF_MAX_DELEGATION_DEPTH {
                return (
                    false,
                    format!("delegation_depth_{depth}_exceeds_max"),
                );
            }

            let parent_pub = match parent_cred.agent_public_key() {
                Ok(k) => k,
                Err(_) => {
                    return (
                        false,
                        format!("malformed_parent_credential_at_index_{}", i - 1),
                    )
                }
            };

            let payload_b = sorted_json_bytes(&child_cred.payload);
            if !verify_data(&parent_pub, &payload_b, &child_cred.signature) {
                return (false, format!("invalid_signature_at_chain_index_{i}"));
            }

            let parent_constraints = parent_cred
                .payload
                .get("capability_constraints")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            let child_constraints = child_cred
                .payload
                .get("capability_constraints")
                .cloned()
                .unwrap_or(serde_json::json!({}));
            if let Err(e) = Self::check_no_amplification(&parent_constraints, &child_constraints) {
                return (false, e);
            }
        }

        (true, String::new())
    }

    fn check_no_amplification(
        parent_constraints: &serde_json::Value,
        child_constraints: &serde_json::Value,
    ) -> Result<(), String> {
        let parent_max = parent_constraints
            .get("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0xFF);
        let child_max = child_constraints
            .get("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0xFF);
        if child_max > parent_max {
            return Err(format!(
                "Privilege amplification detected: child max_action_class ({child_max}) > parent ({parent_max})."
            ));
        }

        let parent_domains: std::collections::HashSet<String> = parent_constraints
            .get("allowed_domains")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let child_domains: std::collections::HashSet<String> = child_constraints
            .get("allowed_domains")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        if !parent_domains.is_empty() {
            let excess: std::collections::HashSet<_> =
                child_domains.difference(&parent_domains).collect();
            if !excess.is_empty() {
                return Err(format!(
                    "Privilege amplification: child claims domains not in parent: {:?}",
                    excess
                ));
            }
        }

        Ok(())
    }
}

// ─── CredentialRenewal ──────────────────────────────────────────────────────────

/// Documents a key rotation event for audit and continuity verification.
#[derive(Debug, Clone)]
pub struct CredentialRenewalRecord {
    pub agent_id: String,
    pub old_key_fingerprint: String,
    pub new_key_fingerprint: String,
    pub old_credential_version: u32,
    pub new_credential_version: u32,
    pub renewed_at: f64,
    pub issuer_id: String,
    pub issuer_signature: Vec<u8>,
    pub issuer_key_id: String,
}

impl CredentialRenewalRecord {
    pub fn body_bytes(&self) -> Vec<u8> {
        let body = serde_json::json!({
            "agent_id": self.agent_id,
            "old_key_fingerprint": self.old_key_fingerprint,
            "new_key_fingerprint": self.new_key_fingerprint,
            "old_credential_version": self.old_credential_version,
            "new_credential_version": self.new_credential_version,
            "renewed_at": self.renewed_at,
            "issuer_id": self.issuer_id,
        });
        sorted_json_bytes(&body)
    }
}

/// Manages key rotation and credential renewal with overlap periods.
pub struct CredentialRenewal;

impl CredentialRenewal {
    /// Renew an agent's identity and credential.
    /// Returns (new_identity, new_credential, renewal_record).
    pub fn renew(
        old_identity: &AgentIdentity,
        issuer_signing_key: &SigningKey,
        issuer_verifying_key: &VerifyingKey,
        issuer_id: &str,
        new_ttl_seconds: u64,
    ) -> (AgentIdentity, AgentCredential, CredentialRenewalRecord) {
        let mut new_identity = AgentIdentity::generate(
            &old_identity.agent_id,
            issuer_id,
            new_ttl_seconds,
            Some(old_identity.trust_policy.clone()),
            Some(old_identity.capability_constraints.clone()),
            &old_identity.revocation_info,
            old_identity.attestation_type,
        );
        new_identity.credential_version = old_identity.credential_version + 1;

        let new_credential =
            AgentCredential::issue(&new_identity, issuer_signing_key, issuer_verifying_key);

        let issuer_pub_fp = pub_key_fingerprint(issuer_verifying_key);
        let mut record = CredentialRenewalRecord {
            agent_id: old_identity.agent_id.clone(),
            old_key_fingerprint: old_identity.fingerprint(),
            new_key_fingerprint: new_identity.fingerprint(),
            old_credential_version: old_identity.credential_version,
            new_credential_version: new_identity.credential_version,
            renewed_at: now_f64(),
            issuer_id: issuer_id.to_string(),
            issuer_signature: Vec::new(),
            issuer_key_id: issuer_pub_fp,
        };
        record.issuer_signature = sign_data(issuer_signing_key, &record.body_bytes());

        (new_identity, new_credential, record)
    }
}

// ─── HardwareAttestationStub ────────────────────────────────────────────────────

/// Stub interface for hardware-backed identity attestation.
///
/// Only `AttestationType::None` (software Ed25519) is implemented.
/// Hardware types (TPM/HSM/TEE/Enclave) require registering a real provider.
pub struct HardwareAttestationStub;

impl HardwareAttestationStub {
    /// Software-only attestation quote using the agent's Ed25519 private key.
    pub fn software_attest(
        identity: &AgentIdentity,
        challenge: &[u8],
        protocol_version: &str,
        security_posture: Option<&serde_json::Value>,
    ) -> Vec<u8> {
        let posture_bytes = serde_json::to_vec(
            security_posture.unwrap_or(&serde_json::Value::Object(Default::default())),
        )
        .unwrap_or_default();
        let posture_hash = Sha256::digest(&posture_bytes);
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(identity.agent_id.as_bytes());
        hasher.update(protocol_version.as_bytes());
        hasher.update(posture_hash);
        let message = hasher.finalize();
        sign_data(&identity.signing_key, &message)
    }

    /// Verify a software attestation quote.
    pub fn software_verify(
        quote: &[u8],
        public_key: &VerifyingKey,
        challenge: &[u8],
        agent_id: &str,
        protocol_version: &str,
        security_posture: Option<&serde_json::Value>,
    ) -> bool {
        let posture_bytes = serde_json::to_vec(
            security_posture.unwrap_or(&serde_json::Value::Object(Default::default())),
        )
        .unwrap_or_default();
        let posture_hash = Sha256::digest(&posture_bytes);
        let mut hasher = Sha256::new();
        hasher.update(challenge);
        hasher.update(agent_id.as_bytes());
        hasher.update(protocol_version.as_bytes());
        hasher.update(posture_hash);
        let message = hasher.finalize();
        verify_data(public_key, &message, quote)
    }
}

// ─── Convenience: provision an issuer ───────────────────────────────────────────

/// Generate a fresh issuer keypair and construct a TrustAnchor.
/// Returns (issuer_signing_key, trust_anchor).
pub fn provision_issuer(
    issuer_id: &str,
    trust_domains: &[&str],
    max_delegation_depth: usize,
    valid_for_days: u64,
    trust_model: TrustModel,
) -> (SigningKey, TrustAnchor) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    let mut anchor = TrustAnchor::new(issuer_id, verifying_key);
    anchor.trust_domains = trust_domains.iter().map(|s| s.to_string()).collect();
    anchor.max_delegation_depth = max_delegation_depth;
    anchor.valid_until = now_f64() + valid_for_days as f64 * 86400.0;
    anchor.trust_model = trust_model;
    (signing_key, anchor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: create issuer (AgentIdentity + signed AgentCredential + TrustAnchor).
    fn make_issuer(id: &str) -> (AgentIdentity, AgentCredential, TrustAnchor) {
        let (sk, anchor) = provision_issuer(
            id, &[id], FAITF_MAX_DELEGATION_DEPTH, 1, TrustModel::Direct,
        );
        let identity = AgentIdentity::generate(
            id,           // agent_id
            id,           // issuer_id (self-issued)
            3600,         // ttl_seconds
            None,         // trust_policy
            None,         // capability_constraints
            "",           // revocation_info
            AttestationType::None,
        );
        let cred = AgentCredential::issue(&identity, &sk, &anchor.verifying_key);
        (identity, cred, anchor)
    }

    /// Task: delegation_chain_depth_4_rejected
    /// FAITF_MAX_DELEGATION_DEPTH = 3. Delegating to depth >= 3 must fail.
    #[test]
    fn delegation_chain_depth_4_rejected() {
        let (issuer_id, issuer_cred, anchor) = make_issuer("issuer-depth");
        let store = TrustStore::new();
        store.register_anchor(anchor);
        store.pin_identity(&issuer_id.agent_id, issuer_id.verifying_key);

        let mut parent_identity = issuer_id;
        let mut parent_cred = issuer_cred;
        let constraints = serde_json::json!({"max_action_class": 0});

        for depth in 1..=4usize {
            let child_identity = AgentIdentity::generate(
                &format!("agent-{depth}"),
                &parent_identity.agent_id,
                3600, None, None, "", AttestationType::None,
            );
            let result = DelegationChain::issue_delegated(
                &parent_identity,
                &parent_cred,
                &child_identity.agent_id,
                &child_identity.verifying_key,
                constraints.clone(),
                3600,
                depth,
            );
            if depth >= FAITF_MAX_DELEGATION_DEPTH {
                assert!(
                    result.is_err(),
                    "depth {depth} >= max ({FAITF_MAX_DELEGATION_DEPTH}) must be rejected"
                );
                return; // Depth limit correctly enforced
            }
            let delegated = result.expect("depth below max must succeed");
            parent_cred = delegated.credential;
            parent_identity = child_identity;
        }
        // verify_chain fallback: the chain itself must be rejected
        unreachable!("loop should have returned early when depth limit was hit");
    }

    /// Task: delegation_chain_scope_amplification_rejected
    /// A child cannot claim a higher max_action_class than its parent.
    #[test]
    fn delegation_chain_scope_amplification_rejected() {
        let (parent_identity, parent_cred_base, _anchor) = make_issuer("parent-amp");

        // Craft a parent cred that restricts max_action_class to 1
        let mut patched_parent = parent_cred_base.clone();
        if let Some(obj) = patched_parent.payload.as_object_mut() {
            obj.insert(
                "capability_constraints".to_string(),
                serde_json::json!({"max_action_class": 1}),
            );
        }

        let child_identity = AgentIdentity::generate(
            "child-amp", &parent_identity.agent_id,
            3600, None, None, "", AttestationType::None,
        );

        // Child claims max_action_class=2 — more than parent's 1
        let amplified_constraints = serde_json::json!({"max_action_class": 2});
        let result = DelegationChain::issue_delegated(
            &parent_identity,
            &patched_parent,
            &child_identity.agent_id,
            &child_identity.verifying_key,
            amplified_constraints,
            3600,
            1,
        );
        assert!(result.is_err(), "privilege amplification must be rejected");
        let err = result.unwrap_err();
        assert!(
            err.contains("amplification") || err.contains("Privilege") || err.contains("max_action_class"),
            "error must mention privilege amplification: got '{err}'"
        );
    }

    /// Verify circular delegation detection in DelegationChain::verify_chain().
    #[test]
    fn delegation_chain_circular_detection() {
        let (_issuer_identity, issuer_cred, anchor) = make_issuer("issuer-circ");
        let store = TrustStore::new();
        store.register_anchor(anchor);

        // Craft a chain where the same credential appears twice → circular.
        let chain = vec![issuer_cred.clone(), issuer_cred.clone()];
        let (ok, reason) = DelegationChain::verify_chain(&chain, &store);
        assert!(!ok, "chain with repeated credential must be rejected");
        // The reason must indicate the circular/duplicate issue
        assert!(
            reason.contains("circular")
                || reason.contains("duplicate")
                || reason.contains("cycle")
                || reason.contains("already"),
            "reason must indicate circular detection: got '{reason}'"
        );
    }
}
