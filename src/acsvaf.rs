use crate::errors::{SAACPBytecodes, SAACPHardDrop};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::RwLock;
use std::time::{SystemTime, UNIX_EPOCH};

pub const ACSVAF_MAX_DELEGATION_DEPTH: u32 = 8;
pub const WIRE_JSON_LEN_SIZE: usize = 4;

// ---------------------------------------------------------------------------
// KeyStatus
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyStatus {
    Active,
    Rotated,
    Revoked,
    Compromised,
}

// ---------------------------------------------------------------------------
// CapabilitySigningKey
// ---------------------------------------------------------------------------

pub struct CapabilitySigningKey {
    pub kid: String,
    pub issuer_id: String,
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
    pub version: u32,
    pub created_at: f64,
    pub expires_at: f64,
    pub status: KeyStatus,
}

impl CapabilitySigningKey {
    /// Generate a fresh Ed25519 keypair.
    pub fn generate(issuer_id: &str, ttl_seconds: u64) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();

        // Fingerprint = hex(sha256(verifying_key.as_bytes()))[..16]
        let mut hasher = Sha256::new();
        hasher.update(verifying_key.as_bytes());
        let hash = hasher.finalize();
        let fingerprint = hex::encode(&hash[..8]); // 8 bytes = 16 hex chars

        let kid = format!("ed25519-v1-{}", fingerprint);

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        Self {
            kid,
            issuer_id: issuer_id.to_string(),
            signing_key,
            verifying_key,
            version: 1,
            created_at: now,
            expires_at: now + ttl_seconds as f64,
            status: KeyStatus::Active,
        }
    }

    /// Sign arbitrary data.
    pub fn sign(&self, data: &[u8]) -> Signature {
        self.signing_key.sign(data)
    }

    /// Get public key bytes.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }
}

// ---------------------------------------------------------------------------
// SignedCapabilityToken
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SignedCapabilityToken {
    pub claims: Map<String, Value>,
    pub signature: [u8; 64],
}

impl SignedCapabilityToken {
    /// Serialize to wire format: base64(4-byte-BE-json-len || sorted-claims-json || 64-byte-sig)
    pub fn to_wire(&self) -> Vec<u8> {
        let json_bytes = serialize_sorted_json(&self.claims);
        let json_len = json_bytes.len() as u32;

        let mut payload = Vec::with_capacity(4 + json_bytes.len() + 64);
        payload.extend_from_slice(&json_len.to_be_bytes());
        payload.extend_from_slice(&json_bytes);
        payload.extend_from_slice(&self.signature);

        BASE64.encode(&payload).into_bytes()
    }

    /// Deserialize from wire format.
    pub fn from_wire(data: &[u8]) -> Result<Self, SAACPHardDrop> {
        let decoded = BASE64.decode(data).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Invalid base64 in wire token",
            )
        })?;

        if decoded.len() < WIRE_JSON_LEN_SIZE + 64 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Wire token too short",
            ));
        }

        let json_len =
            u32::from_be_bytes([decoded[0], decoded[1], decoded[2], decoded[3]]) as usize;

        if decoded.len() < WIRE_JSON_LEN_SIZE + json_len + 64 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Wire token length mismatch",
            ));
        }

        let json_bytes = &decoded[WIRE_JSON_LEN_SIZE..WIRE_JSON_LEN_SIZE + json_len];
        let sig_bytes =
            &decoded[WIRE_JSON_LEN_SIZE + json_len..WIRE_JSON_LEN_SIZE + json_len + 64];

        let claims: Map<String, Value> = serde_json::from_slice(json_bytes).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Invalid JSON in wire token",
            )
        })?;

        let mut signature = [0u8; 64];
        signature.copy_from_slice(sig_bytes);

        Ok(Self { claims, signature })
    }

    /// Get a specific claim value.
    pub fn get_claim(&self, key: &str) -> Option<&Value> {
        self.claims.get(key)
    }

    /// Deterministic JSON bytes of the claims (for signature verification).
    pub fn claims_bytes(&self) -> Vec<u8> {
        serialize_sorted_json(&self.claims)
    }

    // ── Convenience accessors for common claims ──────────────────────────

    pub fn jti(&self) -> String {
        self.get_claim("jti").and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    pub fn kid(&self) -> String {
        self.get_claim("kid").and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    pub fn iss(&self) -> String {
        self.get_claim("iss").and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    pub fn sub(&self) -> String {
        self.get_claim("sub").and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    pub fn sid(&self) -> String {
        self.get_claim("sid").and_then(|v| v.as_str()).unwrap_or("").to_string()
    }

    pub fn actions(&self) -> Vec<String> {
        extract_string_array(self.get_claim("actions"))
    }

    pub fn max_action_class(&self) -> u8 {
        self.get_claim("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8
    }

    pub fn delegation_depth(&self) -> usize {
        self.get_claim("delegation_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as usize
    }

    pub fn parent_jti(&self) -> Option<String> {
        self.get_claim("parent_jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
    }
}

// ---------------------------------------------------------------------------
// CapabilityIssuanceAuthority
// ---------------------------------------------------------------------------

pub struct CapabilityIssuanceAuthority {
    signing_key: CapabilitySigningKey,
}

impl CapabilityIssuanceAuthority {
    pub fn new(signing_key: CapabilitySigningKey) -> Self {
        Self { signing_key }
    }

    /// Issue a signed capability token.
    pub fn issue(
        &self,
        claims: Map<String, Value>,
    ) -> Result<SignedCapabilityToken, SAACPHardDrop> {
        let json_bytes = serialize_sorted_json(&claims);
        let sig = self.signing_key.sign(&json_bytes);
        Ok(SignedCapabilityToken {
            claims,
            signature: sig.to_bytes(),
        })
    }

    /// Get the public key for distribution.
    pub fn public_key(&self) -> &VerifyingKey {
        &self.signing_key.verifying_key
    }

    /// Get the key ID.
    pub fn kid(&self) -> &str {
        &self.signing_key.kid
    }

    /// Get issuer ID.
    pub fn issuer_id(&self) -> &str {
        &self.signing_key.issuer_id
    }
}

// ---------------------------------------------------------------------------
// CapabilityVerificationResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct CapabilityVerificationResult {
    pub jti: String,
    pub issuer_id: String,
    pub sub: String,
    pub allowed_agents: Vec<String>,
    pub forbidden_agents: Vec<String>,
    pub actions: Vec<String>,
    pub audience: Vec<String>,
    pub sid: String,
    pub thash: String,
    pub remaining_uses: Option<u64>,
    pub max_action_class: u8,
    pub delegation_depth: u32,
    pub parent_jti: Option<String>,
}

// ---------------------------------------------------------------------------
// CapabilityVerificationAuthority
// ---------------------------------------------------------------------------

pub struct CapabilityVerificationAuthority {
    keys: RwLock<HashMap<String, VerifyingKey>>,
    revoked_tokens: RwLock<HashSet<String>>,
}

impl CapabilityVerificationAuthority {
    pub fn new() -> Self {
        Self {
            keys: RwLock::new(HashMap::new()),
            revoked_tokens: RwLock::new(HashSet::new()),
        }
    }

    /// Register a verification key.
    pub fn register_key(&self, kid: &str, key: VerifyingKey) {
        self.keys
            .write()
            .unwrap()
            .insert(kid.to_string(), key);
    }

    /// Get a verification key by kid.
    pub fn get_verification_key(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys.read().unwrap().get(kid).copied()
    }

    /// Revoke a token by JTI.
    pub fn revoke_token(&self, jti: &str) {
        self.revoked_tokens
            .write()
            .unwrap()
            .insert(jti.to_string());
    }

    /// Remove a trusted key (e.g. on compromise).
    pub fn revoke_trusted_key(&self, kid: &str) {
        self.keys.write().unwrap().remove(kid);
    }

    /// Verify a token: signature + temporal bounds + revocation check.
    pub fn verify(
        &self,
        token: &SignedCapabilityToken,
    ) -> Result<CapabilityVerificationResult, SAACPHardDrop> {
        // 1. Extract kid from claims
        let kid = token
            .get_claim("kid")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Missing kid claim",
                )
            })?
            .to_string();

        // 2. Look up verification key
        let vk = self.get_verification_key(&kid).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::AcsvafKeyNotTrusted,
                format!("Key not trusted: {}", kid),
            )
        })?;

        // 3. Reconstruct the signed payload (sorted JSON bytes)
        let json_bytes = serialize_sorted_json(&token.claims);

        // 4. Verify Ed25519 signature
        let signature = Signature::from_bytes(&token.signature);
        vk.verify(&json_bytes, &signature).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Ed25519 signature verification failed",
            )
        })?;

        // 5. Extract jti, check revocation
        let jti = token
            .get_claim("jti")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if self.revoked_tokens.read().unwrap().contains(&jti) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "Token has been revoked",
            ));
        }

        // 6. Check temporal bounds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs_f64();

        let nbf = token
            .get_claim("nbf")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let exp = token
            .get_claim("exp")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        if now < nbf {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "Token not yet valid (nbf)",
            ));
        }
        if now > exp {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "Token has expired (exp)",
            ));
        }

        // 7. Check delegation depth
        let delegation_depth = token
            .get_claim("delegation_depth")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u32;

        if delegation_depth > ACSVAF_MAX_DELEGATION_DEPTH {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AcsvafDelegationDepthExceeded,
                format!(
                    "Delegation depth {} exceeds max {}",
                    delegation_depth, ACSVAF_MAX_DELEGATION_DEPTH
                ),
            ));
        }

        // 8. Build result
        let issuer_id = token
            .get_claim("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let sub = token
            .get_claim("sub")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let allowed_agents = extract_string_array(token.get_claim("allow"));
        let forbidden_agents = extract_string_array(token.get_claim("forbid"));
        let actions = extract_string_array(token.get_claim("actions"));
        let audience = extract_string_array(token.get_claim("aud"));

        let sid = token
            .get_claim("sid")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let thash = token
            .get_claim("thash")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let remaining_uses = token
            .get_claim("max_use")
            .and_then(|v| v.as_u64());

        let max_action_class = token
            .get_claim("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        let parent_jti = token
            .get_claim("parent_jti")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        Ok(CapabilityVerificationResult {
            jti,
            issuer_id,
            sub,
            allowed_agents,
            forbidden_agents,
            actions,
            audience,
            sid,
            thash,
            remaining_uses,
            max_action_class,
            delegation_depth,
            parent_jti,
        })
    }
}

// ---------------------------------------------------------------------------
// KeyManifest
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct KeyManifestEntry {
    pub kid: String,
    pub public_key: [u8; 32],
    pub algorithm: String,
    pub created_at: f64,
    pub expires_at: f64,
}

#[derive(Debug, Clone)]
pub struct KeyManifest {
    pub issuer_id: String,
    pub keys: Vec<KeyManifestEntry>,
    pub valid_from: f64,
    pub valid_until: f64,
    pub signature: [u8; 64],
}

impl KeyManifest {
    /// Create and sign a manifest.
    pub fn create(
        issuer_id: &str,
        keys: Vec<KeyManifestEntry>,
        valid_from: f64,
        valid_until: f64,
        signing_key: &SigningKey,
    ) -> Self {
        let content = Self::manifest_content(issuer_id, &keys, valid_from, valid_until);
        let sig: Signature = signing_key.sign(&content);

        Self {
            issuer_id: issuer_id.to_string(),
            keys,
            valid_from,
            valid_until,
            signature: sig.to_bytes(),
        }
    }

    /// Verify manifest signature.
    pub fn verify(&self, verifying_key: &VerifyingKey) -> Result<(), SAACPHardDrop> {
        let content =
            Self::manifest_content(&self.issuer_id, &self.keys, self.valid_from, self.valid_until);
        let signature = Signature::from_bytes(&self.signature);
        verifying_key.verify(&content, &signature).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::AcsvafManifestInvalid,
                "Manifest signature verification failed",
            )
        })
    }

    /// Build the canonical content bytes for signing/verifying.
    fn manifest_content(
        issuer_id: &str,
        keys: &[KeyManifestEntry],
        valid_from: f64,
        valid_until: f64,
    ) -> Vec<u8> {
        let mut map = serde_json::Map::new();
        map.insert("issuer_id".to_string(), Value::String(issuer_id.to_string()));
        map.insert(
            "valid_from".to_string(),
            Value::Number(serde_json::Number::from_f64(valid_from).unwrap()),
        );
        map.insert(
            "valid_until".to_string(),
            Value::Number(serde_json::Number::from_f64(valid_until).unwrap()),
        );

        let keys_json: Vec<Value> = keys
            .iter()
            .map(|k| {
                let mut km = serde_json::Map::new();
                km.insert("kid".to_string(), Value::String(k.kid.clone()));
                km.insert(
                    "public_key".to_string(),
                    Value::String(hex::encode(k.public_key)),
                );
                km.insert("algorithm".to_string(), Value::String(k.algorithm.clone()));
                km.insert(
                    "created_at".to_string(),
                    Value::Number(serde_json::Number::from_f64(k.created_at).unwrap()),
                );
                km.insert(
                    "expires_at".to_string(),
                    Value::Number(serde_json::Number::from_f64(k.expires_at).unwrap()),
                );
                Value::Object(km)
            })
            .collect();

        map.insert("keys".to_string(), Value::Array(keys_json));

        serialize_sorted_json(&map)
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic JSON serialization with sorted keys.
fn serialize_sorted_json(claims: &Map<String, Value>) -> Vec<u8> {
    let sorted: BTreeMap<&String, &Value> = claims.iter().collect();
    serde_json::to_vec(&sorted).expect("JSON serialization failed")
}

/// Extract a Vec<String> from a JSON array value.
fn extract_string_array(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(arr)) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}
