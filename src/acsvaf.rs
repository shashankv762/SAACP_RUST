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
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Maximum ACSVAF capability delegation chain depth (spec §5.7).
/// Chains longer than 3 raise `ACSVAF_DELEGATION_DEPTH_EXCEEDED`.
pub const ACSVAF_MAX_DELEGATION_DEPTH: u32 = 3;
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

// ed25519-dalek 2.x SigningKey has its own ZeroizeOnDrop that zeroes the secret scalar.
// We zero the String fields (key IDs) and numerics to prevent correlation via heap inspection.
impl Zeroize for CapabilitySigningKey {
    fn zeroize(&mut self) {
        self.kid.zeroize();
        self.issuer_id.zeroize();
        self.version.zeroize();
        self.created_at.zeroize();
        self.expires_at.zeroize();
    }
}

impl ZeroizeOnDrop for CapabilitySigningKey {}

impl Drop for CapabilitySigningKey {
    fn drop(&mut self) {
        self.zeroize();
        // signing_key's own Drop zeroes the 32-byte secret scalar (ed25519-dalek internals).
    }
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
            .unwrap_or_default()
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

        // Guard against integer overflow in the addition and against DoS via a
        // giant json_len field. 10 MB is the protocol MTU; legitimate tokens are
        // measured in hundreds of bytes.
        //
        // M-12 fix: exact-length check (`!=`, not `<`). `to_wire()` always
        // produces exactly `WIRE_JSON_LEN_SIZE + json_len + 64` bytes with no
        // trailing padding, so any extra bytes beyond that are either
        // corruption or an attacker-appended payload smuggled past whatever
        // validated the token's length — previously silently ignored (`< `
        // let `decoded.len() > required` through), now rejected fail-closed.
        let required = WIRE_JSON_LEN_SIZE.saturating_add(json_len).saturating_add(64);
        if json_len > 10_000_000 || decoded.len() != required {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Wire token length invalid, exceeds protocol MTU, or has trailing data",
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

/// Where a [`CapabilityIssuanceAuthority`]'s signing key lives.
///
/// Note this wraps the *authority*, not [`CapabilitySigningKey`] itself. That type
/// exposes `signing_key`/`verifying_key` as public fields and offers an infallible
/// `sign(&self) -> Signature`; giving it a hardware mode would mean either storing a
/// dummy `SigningKey` in the public field — which callers reading it directly would use
/// to produce signatures that fail verification — or making a public field optional,
/// a breaking change. Wrapping one level up avoids both.
///
/// `clippy::large_enum_variant` is allowed deliberately: boxing `Local` would put the
/// signing key behind an extra allocation and, more importantly, move it out of the
/// `CapabilitySigningKey` value whose `Zeroize`/`Drop` impl is what wipes the secret
/// scalar. A 488-vs-280-byte spread on a struct held one-per-authority (not per token)
/// is not worth weakening that.
#[allow(clippy::large_enum_variant)]
enum IssuerKeySource {
    Local(CapabilitySigningKey),
    Hardware {
        store: std::sync::Arc<dyn crate::hrt::HardwareKeyStore>,
        key_id: String,
        /// All three are cached at construction because the accessors below return
        /// borrows, and because each would otherwise cost an HSM round-trip on a path
        /// that issues tokens continuously.
        verifying_key: VerifyingKey,
        kid: String,
        issuer_id: String,
    },
}

pub struct CapabilityIssuanceAuthority {
    signing_key: IssuerKeySource,
}

impl CapabilityIssuanceAuthority {
    pub fn new(signing_key: CapabilitySigningKey) -> Self {
        Self { signing_key: IssuerKeySource::Local(signing_key) }
    }

    /// Build an authority that signs capability tokens with a hardware-held key.
    ///
    /// The capability signing key authorizes every action any agent is permitted to
    /// take, so holding it in an HSM means a compromise of this process cannot yield a
    /// key capable of minting arbitrary capabilities offline and indefinitely.
    ///
    /// The public key is fetched once here — an eager health check that surfaces a bad
    /// key id or an unreachable HSM at construction rather than on the first token
    /// issuance.
    pub fn with_keystore(
        store: std::sync::Arc<dyn crate::hrt::HardwareKeyStore>,
        key_id: impl Into<String>,
        kid: impl Into<String>,
        issuer_id: impl Into<String>,
    ) -> Result<Self, crate::hrt::HrtError> {
        let key_id = key_id.into();
        let public_key = store.public_key(&key_id)?;
        let bytes: [u8; 32] = public_key.as_slice().try_into().map_err(|_| {
            crate::hrt::HrtError::MalformedResponse {
                backend: "capability issuance authority",
                expected: 32,
                got: public_key.len(),
            }
        })?;
        let verifying_key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| crate::hrt::HrtError::MalformedKeyMaterial(key_id.clone()))?;
        Ok(Self {
            signing_key: IssuerKeySource::Hardware {
                store,
                key_id,
                verifying_key,
                kid: kid.into(),
                issuer_id: issuer_id.into(),
            },
        })
    }

    /// Issue a signed capability token.
    pub fn issue(
        &self,
        claims: Map<String, Value>,
    ) -> Result<SignedCapabilityToken, SAACPHardDrop> {
        let json_bytes = serialize_sorted_json(&claims);
        let signature: [u8; 64] = match &self.signing_key {
            IssuerKeySource::Local(sk) => sk.sign(&json_bytes).to_bytes(),
            IssuerKeySource::Hardware { store, key_id, .. } => {
                let sig = store.sign(key_id, &json_bytes).map_err(|e| {
                    // Fail closed: an HSM that cannot sign must block issuance, never
                    // fall back to some other key. The operator-facing detail goes in
                    // the message; `pecf.rs` strips it before anything reaches a peer.
                    SAACPHardDrop::new(
                        SAACPBytecodes::AcsvafKeyNotTrusted,
                        format!("capability signing key is unavailable: {e}"),
                    )
                })?;
                sig.as_slice().try_into().map_err(|_| {
                    SAACPHardDrop::new(
                        SAACPBytecodes::AcsvafKeyNotTrusted,
                        format!(
                            "hardware key store returned a {}-byte signature; Ed25519 requires 64",
                            sig.len()
                        ),
                    )
                })?
            }
        };
        Ok(SignedCapabilityToken { claims, signature })
    }

    /// Get the public key for distribution.
    pub fn public_key(&self) -> &VerifyingKey {
        match &self.signing_key {
            IssuerKeySource::Local(sk) => &sk.verifying_key,
            IssuerKeySource::Hardware { verifying_key, .. } => verifying_key,
        }
    }

    /// Get the key ID.
    pub fn kid(&self) -> &str {
        match &self.signing_key {
            IssuerKeySource::Local(sk) => &sk.kid,
            IssuerKeySource::Hardware { kid, .. } => kid,
        }
    }

    /// Get issuer ID.
    pub fn issuer_id(&self) -> &str {
        match &self.signing_key {
            IssuerKeySource::Local(sk) => &sk.issuer_id,
            IssuerKeySource::Hardware { issuer_id, .. } => issuer_id,
        }
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

impl Default for CapabilityVerificationAuthority {
    fn default() -> Self { Self::new() }
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

    /// Return a list of all registered key IDs.
    /// Python parity: `CapabilityVerificationAuthority.list_kids()`.
    pub fn list_kids(&self) -> Vec<String> {
        self.keys.read().unwrap().keys().cloned().collect()
    }

    /// Clear the JTI revocation registry. Returns the number of entries cleared.
    /// Python parity: `CapabilityVerificationAuthority.clear_replay_registry() -> int`.
    pub fn clear_replay_registry(&self) -> usize {
        let mut revoked = self.revoked_tokens.write().unwrap();
        let count = revoked.len();
        revoked.clear();
        count
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
            .unwrap_or_default()
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

        // 7. Check delegation depth — claim is mandatory and must be a non-negative integer.
        // unwrap_or(0) would allow an attacker to omit the claim and bypass depth limits
        // by having the missing field treated as depth 0, enabling unlimited sub-delegation.
        let delegation_depth = match token.get_claim("delegation_depth").and_then(|v| v.as_u64()) {
            Some(d) => {
                if d > u32::MAX as u64 {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::AcsvafDelegationDepthExceeded,
                        "delegation_depth value out of u32 range",
                    ));
                }
                d as u32
            }
            None => return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "delegation_depth claim is mandatory and must be a non-negative integer",
            )),
        };

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
        map.insert("valid_from".to_string(), json_f64(valid_from));
        map.insert("valid_until".to_string(), json_f64(valid_until));

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
                km.insert("created_at".to_string(), json_f64(k.created_at));
                km.insert("expires_at".to_string(), json_f64(k.expires_at));
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
/// Convert f64 to a serde_json Number, falling back to 0 for NaN/Infinity.
///
/// SECURITY FIX (C-3): `Number::from_f64()` returns None for NaN/Infinity;
/// `.unwrap()` would panic. Timestamps of 0 → immediately expired, the safe default.
fn json_f64(v: f64) -> Value {
    Value::Number(
        serde_json::Number::from_f64(if v.is_finite() { v } else { 0.0 })
            .unwrap_or_else(|| serde_json::Number::from(0u64))
    )
}

fn serialize_sorted_json(claims: &Map<String, Value>) -> Vec<u8> {
    let sorted: BTreeMap<&String, &Value> = claims.iter().collect();
    // serde_json::to_vec on a BTreeMap<&String, &Value> where all values are valid
    // JSON cannot fail in practice. If it does (e.g., OOM), return empty bytes so
    // downstream signature verification fails closed rather than panicking.
    serde_json::to_vec(&sorted).unwrap_or_default()
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

#[cfg(test)]
mod tests {
    use super::*;

    fn make_authority_pair(issuer_id: &str) -> (CapabilityIssuanceAuthority, CapabilityVerificationAuthority) {
        let csk = CapabilitySigningKey::generate(issuer_id, 3600);
        let cva = CapabilityVerificationAuthority::new();
        cva.register_key(&csk.kid, csk.verifying_key);
        let cia = CapabilityIssuanceAuthority::new(csk);
        (cia, cva)
    }

    fn make_token_claims(
        kid: &str,
        issuer_id: &str,
        sub: &str,
        delegation_depth: u32,
        exp: f64,
    ) -> Map<String, Value> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let mut claims = Map::new();
        claims.insert("kid".into(), Value::String(kid.to_string()));
        claims.insert("iss".into(), Value::String(issuer_id.to_string()));
        claims.insert("sub".into(), Value::String(sub.to_string()));
        claims.insert("jti".into(), Value::String(uuid_hex()));
        claims.insert("nbf".into(), json_f64(now));
        claims.insert("exp".into(), json_f64(exp));
        claims.insert("delegation_depth".into(), Value::Number(delegation_depth.into()));
        claims.insert("actions".into(), Value::Array(vec![Value::String("read".into())]));
        claims.insert("aud".into(), Value::Array(vec![]));
        claims
    }

    fn uuid_hex() -> String {
        use sha2::{Sha256, Digest};
        let mut h = Sha256::new();
        let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_nanos().to_le_bytes();
        h.update(t);
        hex::encode(h.finalize()[..16].as_ref())
    }


    #[test]
    fn test_clear_replay_registry_returns_count() {
        let cva = CapabilityVerificationAuthority::new();
        cva.revoke_token("jti-aaa");
        cva.revoke_token("jti-bbb");
        cva.revoke_token("jti-ccc");
        // clear_replay_registry must return 3 and drain the set
        let cleared = cva.clear_replay_registry();
        assert_eq!(cleared, 3, "must return count of cleared JTIs");
        // After clearing, revoking again returns 1
        cva.revoke_token("jti-new");
        assert_eq!(cva.clear_replay_registry(), 1);
    }

    #[test]
    fn test_list_kids() {
        let cva = CapabilityVerificationAuthority::new();
        let sk1 = CapabilitySigningKey::generate("iss1", 3600);
        let sk2 = CapabilitySigningKey::generate("iss2", 3600);
        cva.register_key("kid-alpha", sk1.verifying_key);
        cva.register_key("kid-beta", sk2.verifying_key);
        let kids = cva.list_kids();
        assert_eq!(kids.len(), 2);
        assert!(kids.contains(&"kid-alpha".to_string()));
        assert!(kids.contains(&"kid-beta".to_string()));
    }

    #[test]
    fn test_acsvaf_delegation_depth_rejected() {
        let (cia, cva) = make_authority_pair("issuer-test");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        // depth=4 > ACSVAF_MAX_DELEGATION_DEPTH (3) — must be rejected on verify
        let claims = make_token_claims(cia.kid(), cia.issuer_id(), "agent-x", 4, now + 300.0);
        let token = cia.issue(claims).expect("issue must succeed");
        let result = cva.verify(&token);
        assert!(result.is_err(), "depth=9 must be rejected by verify()");
    }

    #[test]
    fn test_acsvaf_delegation_depth_at_max_allowed() {
        let (cia, cva) = make_authority_pair("issuer-test");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        // depth=ACSVAF_MAX_DELEGATION_DEPTH (3) — exactly at max, must pass
        let claims = make_token_claims(
            cia.kid(), cia.issuer_id(), "agent-y",
            ACSVAF_MAX_DELEGATION_DEPTH, now + 300.0,
        );
        let token = cia.issue(claims).expect("issue must succeed");
        assert!(cva.verify(&token).is_ok(), "depth=max must be accepted");
    }

    // -- M-12: SignedCapabilityToken::from_wire trailing-data rejection --

    #[test]
    fn test_wire_roundtrip_succeeds() {
        let (cia, _cva) = make_authority_pair("issuer-wire");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let claims = make_token_claims(cia.kid(), cia.issuer_id(), "agent-wire", 0, now + 300.0);
        let token = cia.issue(claims).expect("issue must succeed");

        let wire = token.to_wire();
        let recovered = SignedCapabilityToken::from_wire(&wire).expect("exact wire bytes must roundtrip");
        assert_eq!(recovered.claims, token.claims);
        assert_eq!(recovered.signature, token.signature);
    }

    #[test]
    fn test_from_wire_rejects_trailing_data() {
        let (cia, _cva) = make_authority_pair("issuer-wire-trailer");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let claims = make_token_claims(cia.kid(), cia.issuer_id(), "agent-wire-2", 0, now + 300.0);
        let token = cia.issue(claims).expect("issue must succeed");

        // Decode the legitimate wire bytes, append attacker-controlled trailing
        // bytes to the pre-base64 payload, then re-encode — simulating a
        // smuggled payload appended after a valid signature.
        let wire = token.to_wire();
        let mut decoded = BASE64.decode(&wire).expect("valid base64");
        decoded.extend_from_slice(b"SMUGGLED-TRAILING-BYTES");
        let tampered = BASE64.encode(&decoded).into_bytes();

        let result = SignedCapabilityToken::from_wire(&tampered);
        assert!(result.is_err(), "M-12: trailing bytes after a valid signature must be rejected, not silently ignored");
    }

    #[test]
    fn test_from_wire_rejects_truncated_data() {
        let (cia, _cva) = make_authority_pair("issuer-wire-trunc");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let claims = make_token_claims(cia.kid(), cia.issuer_id(), "agent-wire-3", 0, now + 300.0);
        let token = cia.issue(claims).expect("issue must succeed");

        let wire = token.to_wire();
        let mut decoded = BASE64.decode(&wire).expect("valid base64");
        decoded.truncate(decoded.len() - 1); // drop the last byte of the signature
        let tampered = BASE64.encode(&decoded).into_bytes();

        let result = SignedCapabilityToken::from_wire(&tampered);
        assert!(result.is_err(), "truncated wire data (short by 1 byte) must be rejected");
    }

    #[test]
    fn test_revoke_token_blocks_verification() {
        let (cia, cva) = make_authority_pair("issuer-revo");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64();
        let claims = make_token_claims(cia.kid(), cia.issuer_id(), "agent-z", 0, now + 300.0);
        let token = cia.issue(claims).expect("issue must succeed");
        // Initially valid
        let result = cva.verify(&token);
        assert!(result.is_ok(), "token must be valid initially");
        // Revoke then verify again
        let jti = token.get_claim("jti").and_then(|v| v.as_str()).unwrap_or("").to_string();
        cva.revoke_token(&jti);
        let result2 = cva.verify(&token);
        assert!(result2.is_err(), "revoked token must be rejected");
    }
}
