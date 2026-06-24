//! gateway.rs — Zero-Trust Gateway
//!
//! Zero-Trust Tokenized Micro-Gateway.
//! Prevents prompt-injected agents from lateral movement using
//! cryptographically signed capability tokens.
//! Uses length-prefix format to prevent token delimiter injection.

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Circuit breaker threshold for legitimate packet errors.
pub const RATE_LIMITER_THRESHOLD: usize = 5;
/// Circuit breaker window in seconds.
pub const RATE_LIMITER_WINDOW_SECONDS: f64 = 10.0;
/// Circuit breaker lockout duration in seconds.
pub const RATE_LIMITER_LOCKOUT_SECONDS: f64 = 30.0;
/// Cover traffic rate limit per window.
pub const COVER_TRAFFIC_THRESHOLD: usize = 50;
/// Cover traffic window in seconds.
pub const COVER_TRAFFIC_WINDOW_SECONDS: f64 = 1.0;
/// Maximum token cache entries before eviction.
pub const TOKEN_CACHE_MAX: usize = 10_000;
/// Token cache TTL cap (seconds).
pub const TOKEN_CACHE_TTL: f64 = 30.0;

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).unwrap();
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

fn serialize_sorted_json(data: &HashMap<String, serde_json::Value>) -> Vec<u8> {
    use std::collections::BTreeMap;
    let sorted: BTreeMap<&String, &serde_json::Value> = data.iter().collect();
    serde_json::to_vec(&sorted).unwrap_or_default()
}

fn parse_token_wire(token_b64: &[u8]) -> Result<(Vec<u8>, Vec<u8>), SAACPHardDrop> {
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, token_b64)
        .map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Missing or malformed Capability Token.",
        ))?;
    if raw.len() < 4 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Token too short.",
        ));
    }
    let json_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if json_len == 0 || json_len > raw.len() - 4 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Invalid token JSON length.",
        ));
    }
    let token_json = raw[4..4 + json_len].to_vec();
    let signature = raw[4 + json_len..].to_vec();
    if signature.len() != 32 && signature.len() != 64 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "Invalid signature length.",
        ));
    }
    Ok((token_json, signature))
}

// ---------------------------------------------------------------------------
// Token validation result
// ---------------------------------------------------------------------------

/// Result of token validation.
#[derive(Debug, Clone)]
pub struct TokenValidationResult {
    pub is_valid: bool,
    pub source_agent: String,
    pub root_intent_hash: Option<String>,
    pub max_action_class: u8,
}

// ---------------------------------------------------------------------------
// AgentRateLimiter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct RateRecord {
    errors: usize,
    window_start: f64,
    locked_until: f64,
}

#[derive(Debug, Clone)]
struct CoverRecord {
    count: usize,
    window_start: f64,
}

/// Per-agent-identity circuit breaker with separate cover traffic budget.
pub struct AgentRateLimiter {
    records: Mutex<HashMap<String, RateRecord>>,
    cover_records: Mutex<HashMap<String, CoverRecord>>,
}

impl AgentRateLimiter {
    pub fn new() -> Self {
        Self {
            records: Mutex::new(HashMap::new()),
            cover_records: Mutex::new(HashMap::new()),
        }
    }

    /// Record one error. Raises CIRCUIT_BREAKER_OPEN if threshold exceeded.
    pub fn record_error(&self, agent_id: &str) -> Result<(), SAACPHardDrop> {
        let mut records = self.records.lock().unwrap();
        let now = now_epoch_secs();
        let rec = records.entry(agent_id.to_string()).or_insert(RateRecord {
            errors: 0,
            window_start: now,
            locked_until: 0.0,
        });

        if now < rec.locked_until {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!("Agent '{}' is locked out for malformed packet flooding.", agent_id),
            ));
        }

        if (now - rec.window_start) > RATE_LIMITER_WINDOW_SECONDS {
            rec.errors = 0;
            rec.window_start = now;
        }

        rec.errors += 1;
        if rec.errors >= RATE_LIMITER_THRESHOLD {
            rec.locked_until = now + RATE_LIMITER_LOCKOUT_SECONDS;
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!(
                    "Circuit breaker OPEN for '{}': {} errors in {}s.",
                    agent_id, rec.errors, RATE_LIMITER_WINDOW_SECONDS
                ),
            ));
        }
        Ok(())
    }

    /// Record one cover traffic packet (M-8 fix).
    pub fn record_cover_traffic(&self, agent_id: &str) -> Result<(), SAACPHardDrop> {
        let mut records = self.cover_records.lock().unwrap();
        let now = now_epoch_secs();
        let rec = records.entry(agent_id.to_string()).or_insert(CoverRecord {
            count: 0,
            window_start: now,
        });

        if (now - rec.window_start) > COVER_TRAFFIC_WINDOW_SECONDS {
            rec.count = 0;
            rec.window_start = now;
        }

        rec.count += 1;
        if rec.count > COVER_TRAFFIC_THRESHOLD {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                format!(
                    "Cover traffic rate limit exceeded for '{}': {} cover packets in {}s (limit: {}).",
                    agent_id, rec.count, COVER_TRAFFIC_WINDOW_SECONDS, COVER_TRAFFIC_THRESHOLD
                ),
            ));
        }
        Ok(())
    }

    /// Returns true if the agent is currently under circuit-breaker lockout.
    pub fn is_locked(&self, agent_id: &str) -> bool {
        let records = self.records.lock().unwrap();
        if let Some(rec) = records.get(agent_id) {
            return now_epoch_secs() < rec.locked_until;
        }
        false
    }

    /// Reset records for an agent (or all agents if None).
    pub fn reset(&self, agent_id: Option<&str>) {
        if let Some(id) = agent_id {
            self.records.lock().unwrap().remove(id);
            self.cover_records.lock().unwrap().remove(id);
        } else {
            self.records.lock().unwrap().clear();
            self.cover_records.lock().unwrap().clear();
        }
    }
}

impl Default for AgentRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ZeroTrustGateway
// ---------------------------------------------------------------------------

/// Token cache entry.
#[derive(Clone)]
struct CacheEntry {
    expiry: f64,
    result: TokenValidationResult,
}

/// Zero-Trust Tokenized Micro-Gateway.
pub struct ZeroTrustGateway {
    revoked_tokens: Mutex<HashSet<String>>,
    token_cache: Mutex<HashMap<String, CacheEntry>>,
    trusted_issuer_keys: Mutex<HashMap<String, Vec<u8>>>,
    strict_asymmetric_mode: Mutex<bool>,
    revocation_epoch: Mutex<u64>,
    issuer_registry_epoch: Mutex<u64>,
}

impl ZeroTrustGateway {
    pub fn new() -> Self {
        Self {
            revoked_tokens: Mutex::new(HashSet::new()),
            token_cache: Mutex::new(HashMap::new()),
            trusted_issuer_keys: Mutex::new(HashMap::new()),
            strict_asymmetric_mode: Mutex::new(false),
            revocation_epoch: Mutex::new(0),
            issuer_registry_epoch: Mutex::new(0),
        }
    }

    /// When true, HMAC-PSK tokens are rejected outright.
    pub fn set_strict_asymmetric_mode(&self, enabled: bool) {
        *self.strict_asymmetric_mode.lock().unwrap() = enabled;
        self.token_cache.lock().unwrap().clear();
    }

    /// Register the canonical token-signing key for a trusted issuer.
    pub fn register_issuer_key(&self, issuer_agent: &str, issuer_secret: &[u8]) {
        self.trusted_issuer_keys
            .lock()
            .unwrap()
            .insert(issuer_agent.to_string(), issuer_secret.to_vec());
        self.token_cache.lock().unwrap().clear();
        *self.issuer_registry_epoch.lock().unwrap() += 1;
    }

    /// Clear trusted issuer registry.
    pub fn clear_trusted_issuers(&self) {
        self.trusted_issuer_keys.lock().unwrap().clear();
        self.token_cache.lock().unwrap().clear();
        *self.issuer_registry_epoch.lock().unwrap() += 1;
    }

    /// Issue a capability token (HMAC-SHA256 path).
    pub fn issue_capability_token(
        &self,
        issuer_secret: &[u8],
        issuer_agent: &str,
        allowed_agents: &[&str],
        forbidden_agents: &[&str],
        ttl_seconds: u64,
        root_intent_hash: Option<&str>,
        max_action_class: u8,
    ) -> Vec<u8> {
        let expiry = now_epoch_secs() as u64 + ttl_seconds;

        let mut token_data = HashMap::new();
        token_data.insert("iss".into(), serde_json::Value::String(issuer_agent.into()));
        token_data.insert("exp".into(), serde_json::Value::Number(expiry.into()));
        token_data.insert(
            "allow".into(),
            serde_json::Value::Array(allowed_agents.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert(
            "forbid".into(),
            serde_json::Value::Array(forbidden_agents.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert("max_action_class".into(), serde_json::Value::Number(max_action_class.into()));
        if let Some(rih) = root_intent_hash {
            token_data.insert("root_intent_hash".into(), serde_json::Value::String(rih.into()));
        }

        let token_json = serialize_sorted_json(&token_data);
        let signature = hmac_sha256(issuer_secret, &token_json);

        // Length-prefix format: 4-byte big-endian json length + json + signature
        let json_len = token_json.len() as u32;
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&json_len.to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);

        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
    }

    /// Revoke a token by adding its signature hash to the revocation set.
    pub fn revoke_token(&self, token_b64: &[u8]) -> Result<(), String> {
        let (token_json, signature) = parse_token_wire(token_b64)
            .map_err(|e| format!("Token revocation failed: {}", e))?;
        if signature.is_empty() {
            return Err("Token has no signature to revoke.".into());
        }
        let sig_hash = sha256_hex(&signature);
        self.revoked_tokens.lock().unwrap().insert(sig_hash);
        self.token_cache.lock().unwrap().clear();
        *self.revocation_epoch.lock().unwrap() += 1;
        Ok(())
    }

    /// Returns the current revocation epoch.
    pub fn get_revocation_epoch(&self) -> u64 {
        *self.revocation_epoch.lock().unwrap()
    }

    /// Check if a token signature hash is in the revocation set.
    pub fn is_token_revoked(&self, token_sig_hash: &str) -> bool {
        self.revoked_tokens.lock().unwrap().contains(token_sig_hash)
    }

    /// PSK Compromise Recovery: revoke ALL tokens, flush ALL caches (M-6 fix).
    pub fn revoke_all_tokens(&self) -> u64 {
        self.revoked_tokens.lock().unwrap().clear();
        self.token_cache.lock().unwrap().clear();
        self.trusted_issuer_keys.lock().unwrap().clear();
        let mut rev_epoch = self.revocation_epoch.lock().unwrap();
        *rev_epoch += 1;
        let mut iss_epoch = self.issuer_registry_epoch.lock().unwrap();
        *iss_epoch += 1;
        *rev_epoch
    }

    /// Evaluate the token before allowing lateral movement.
    ///
    /// HMAC-PSK path: verifies signature, checks expiry, allow/forbid lists.
    pub fn validate_lateral_movement(
        &self,
        target_agent: &str,
        token_b64: &[u8],
        issuer_secret: &[u8],
    ) -> Result<TokenValidationResult, SAACPHardDrop> {
        let now = now_epoch_secs();
        let fallback_key_hash = sha256_hex(issuer_secret);
        let registry_epoch = *self.issuer_registry_epoch.lock().unwrap();
        let revocation_epoch = *self.revocation_epoch.lock().unwrap();

        let cache_key = format!(
            "{}:{}:{}:{}:{}",
            target_agent,
            String::from_utf8_lossy(token_b64),
            fallback_key_hash,
            registry_epoch,
            revocation_epoch,
        );

        // Check cache
        {
            let cache = self.token_cache.lock().unwrap();
            if let Some(entry) = cache.get(&cache_key) {
                if now < entry.expiry {
                    return Ok(entry.result.clone());
                }
            }
        }

        // Parse token
        let (token_json, signature) = parse_token_wire(token_b64)?;

        // Parse JSON
        let data: serde_json::Value = serde_json::from_slice(&token_json).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "Missing or malformed Capability Token.",
            )
        })?;
        let obj = data.as_object().ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "Token payload must be a JSON object.",
            )
        })?;

        // Check revocation
        let sig_hash = sha256_hex(&signature);
        if self.revoked_tokens.lock().unwrap().contains(&sig_hash) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "Capability Token has been REVOKED.",
            ));
        }

        let source_agent = obj
            .get("iss")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown_Issuer")
            .to_string();

        let sig_alg = obj
            .get("_sig_alg")
            .and_then(|v| v.as_str())
            .unwrap_or("hmac-sha256");

        // Reject HMAC in strict mode
        if *self.strict_asymmetric_mode.lock().unwrap() && sig_alg != "ed25519" {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "HMAC-PSK tokens are rejected in strict asymmetric mode.",
            ));
        }

        // HMAC-SHA256 verification
        if sig_alg != "ed25519" {
            let trusted_keys = self.trusted_issuer_keys.lock().unwrap();
            let has_registry = !trusted_keys.is_empty();
            let trusted_secret = trusted_keys.get(&source_agent).cloned();
            drop(trusted_keys);

            if has_registry && trusted_secret.is_none() {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Capability Token issuer is not trusted.",
                ));
            }

            let verification_secret = trusted_secret.unwrap_or_else(|| issuer_secret.to_vec());
            let expected_sig = hmac_sha256(&verification_secret, &token_json);
            if !constant_time_eq(&expected_sig, &signature) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "Capability Token has been tampered with!",
                ));
            }
        }

        // Check expiry
        let exp = obj.get("exp").and_then(|v| v.as_u64()).unwrap_or(0) as f64;
        if now_epoch_secs() > exp {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "Capability Token EXPIRED.",
            ));
        }

        // Check forbidden list
        let forbid: Vec<&str> = obj
            .get("forbid")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if forbid.contains(&target_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                format!("Strictly forbidden from calling {}.", target_agent),
            ));
        }

        // Check allowed list
        let allow: Vec<&str> = obj
            .get("allow")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !allow.contains(&target_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScopeViolation,
                format!("Scope violation: '{}' is not in the allowed scope list.", target_agent),
            ));
        }

        let root_intent_hash = obj
            .get("root_intent_hash")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let max_action_class = obj
            .get("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;

        let result = TokenValidationResult {
            is_valid: true,
            source_agent,
            root_intent_hash,
            max_action_class,
        };

        // Cache the result
        let cache_expiry = (now_epoch_secs() + TOKEN_CACHE_TTL).min(exp);
        let mut cache = self.token_cache.lock().unwrap();
        if cache.len() > TOKEN_CACHE_MAX {
            let current_time = now_epoch_secs();
            cache.retain(|_, v| v.expiry > current_time);
        }
        cache.insert(cache_key, CacheEntry {
            expiry: cache_expiry,
            result: result.clone(),
        });

        Ok(result)
    }
}

impl Default for ZeroTrustGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// DelegationGuard
// ---------------------------------------------------------------------------

/// Prevents cascading token delegation.
pub struct DelegationGuard;

impl DelegationGuard {
    /// Validates the token is signed by the root orchestrator key.
    pub fn validate_not_self_signed(
        token_b64: &[u8],
        root_secret: &[u8],
    ) -> Result<(), SAACPHardDrop> {
        let (token_json, signature) = {
            let raw = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                token_b64,
            )
            .map_err(|_| SAACPHardDrop::new(
                SAACPBytecodes::DelegationRejected,
                "Delegation attempt with malformed token structure.",
            ))?;
            if raw.len() < 4 {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::DelegationRejected,
                    "Delegation attempt with malformed token structure.",
                ));
            }
            let json_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
            let tj = raw[4..4 + json_len].to_vec();
            let sig = raw[4 + json_len..].to_vec();
            (tj, sig)
        };

        let expected_sig = hmac_sha256(root_secret, &token_json);
        if !constant_time_eq(&expected_sig, &signature) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::DelegationRejected,
                "DELEGATION REJECTED: Token is not signed by the root orchestrator key.",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// RRBC (Replay-Resistant Bound Capabilities)
// ---------------------------------------------------------------------------

/// Result of a successful RRBC token redemption.
#[derive(Debug, Clone)]
pub struct RRBCRedemptionResult {
    pub jti: String,
    pub issuer_agent: String,
    pub allowed_agents: Vec<String>,
    pub forbidden_agents: Vec<String>,
    pub actions: Vec<String>,
    pub audience: Vec<String>,
    pub sid: String,
    pub cid: String,
    pub oaid: String,
    pub remaining_uses: i64,
    pub max_action_class: u8,
}

struct RRBCTokenRecord {
    data: serde_json::Value,
    remaining: i64,
    revoked: bool,
}

/// Replay-Resistant Bound Capabilities gateway.
pub struct RRBCGateway {
    replay_registry: Mutex<HashMap<(String, String, String), i64>>,
    tokens: Mutex<HashMap<String, RRBCTokenRecord>>,
    revoked_jtis: Mutex<HashSet<String>>,
}

impl RRBCGateway {
    pub fn new() -> Self {
        Self {
            replay_registry: Mutex::new(HashMap::new()),
            tokens: Mutex::new(HashMap::new()),
            revoked_jtis: Mutex::new(HashSet::new()),
        }
    }

    /// Issue an RRBC token (HMAC-SHA256 path).
    pub fn issue_token(
        &self,
        issuer_secret: &[u8],
        issuer_agent: &str,
        allowed_agents: &[&str],
        forbidden_agents: &[&str],
        actions: &[&str],
        audience: &[&str],
        sid: &str,
        cid: &str,
        oaid: &str,
        max_use: i64,
        ttl_seconds: u64,
        max_action_class: u8,
    ) -> Vec<u8> {
        let now = now_epoch_secs();
        let jti = uuid::Uuid::new_v4().to_string().replace('-', "");
        let iat = now as u64;
        let exp = iat + ttl_seconds;

        let mut token_data = serde_json::Map::new();
        token_data.insert("jti".into(), serde_json::Value::String(jti.clone()));
        token_data.insert("iat".into(), serde_json::json!(iat));
        token_data.insert("nbf".into(), serde_json::json!(iat));
        token_data.insert("exp".into(), serde_json::json!(exp));
        token_data.insert("iss".into(), serde_json::Value::String(issuer_agent.into()));
        token_data.insert(
            "aud".into(),
            serde_json::Value::Array(audience.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert("sid".into(), serde_json::Value::String(sid.into()));
        token_data.insert("cid".into(), serde_json::Value::String(cid.into()));
        token_data.insert("oaid".into(), serde_json::Value::String(oaid.into()));
        token_data.insert(
            "actions".into(),
            serde_json::Value::Array(actions.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert(
            "allow".into(),
            serde_json::Value::Array(allowed_agents.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert(
            "forbid".into(),
            serde_json::Value::Array(forbidden_agents.iter().map(|a| serde_json::Value::String(a.to_string())).collect()),
        );
        token_data.insert("max_use".into(), serde_json::json!(max_use));
        token_data.insert("max_action_class".into(), serde_json::json!(max_action_class));

        let token_json = serde_json::to_vec(&serde_json::Value::Object(token_data)).unwrap_or_default();
        let signature = hmac_sha256(issuer_secret, &token_json);

        let json_len = token_json.len() as u32;
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&json_len.to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);

        // Register token
        let data: serde_json::Value = serde_json::from_slice(&token_json).unwrap_or(serde_json::Value::Null);
        self.tokens.lock().unwrap().insert(jti, RRBCTokenRecord {
            data,
            remaining: max_use,
            revoked: false,
        });

        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
    }

    /// Redeem a single use of an RRBC token.
    pub fn redeem_token(
        &self,
        token_b64: &[u8],
        rnonce: &str,
        presenting_agent: &str,
        presenting_sid: &str,
        presenting_cid: &str,
        presenting_oaid: &str,
        issuer_secret: &[u8],
    ) -> Result<RRBCRedemptionResult, SAACPHardDrop> {
        // Parse token
        let (token_json, signature) = parse_token_wire(token_b64).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Missing or malformed capability token.",
            )
        })?;

        // Verify HMAC
        let expected_sig = hmac_sha256(issuer_secret, &token_json);
        if !constant_time_eq(&expected_sig, &signature[..expected_sig.len().min(signature.len())]) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "RRBC: Capability token signature verification failed.",
            ));
        }

        // Parse JSON
        let data: serde_json::Value = serde_json::from_slice(&token_json).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Malformed token payload.",
            )
        })?;
        let obj = data.as_object().ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Token payload must be a JSON object.",
            )
        })?;

        let jti = obj.get("jti").and_then(|v| v.as_str()).unwrap_or("").to_string();

        // Revocation check
        if self.revoked_jtis.lock().unwrap().contains(&jti) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Token has been revoked.",
            ));
        }

        // Temporal validity
        let now = now_epoch_secs();
        let nbf = obj.get("nbf").and_then(|v| v.as_f64()).unwrap_or(0.0);
        let exp = obj.get("exp").and_then(|v| v.as_f64()).unwrap_or(0.0);
        if now < nbf {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "RRBC: Token not yet valid (nbf constraint).",
            ));
        }
        if now > exp {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::TokenExpired,
                "RRBC: Capability token has expired.",
            ));
        }

        // Binding checks
        let token_sid = obj.get("sid").and_then(|v| v.as_str()).unwrap_or("");
        let token_cid = obj.get("cid").and_then(|v| v.as_str()).unwrap_or("");
        let token_oaid = obj.get("oaid").and_then(|v| v.as_str()).unwrap_or("");

        if presenting_sid != token_sid
            || presenting_cid != token_cid
            || presenting_oaid != token_oaid
        {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RrbcBindingMismatch,
                "RRBC: Token binding mismatch (sid/cid/oaid).",
            ));
        }

        // Audience check
        let aud: Vec<&str> = obj
            .get("aud")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !aud.contains(&presenting_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScopeViolation,
                format!("RRBC: Agent '{}' not in token audience.", presenting_agent),
            ));
        }

        // Replay protection
        let replay_key = (jti.clone(), rnonce.to_string(), presenting_sid.to_string());
        {
            let mut registry = self.replay_registry.lock().unwrap();
            if registry.contains_key(&replay_key) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::RrbcReplayDetected,
                    "RRBC: Replay detected — (jti, rnonce, sid) already consumed.",
                ));
            }
            registry.insert(replay_key, 1);
        }

        // Usage counter
        let remaining = {
            let mut tokens = self.tokens.lock().unwrap();
            if let Some(rec) = tokens.get_mut(&jti) {
                if rec.remaining <= 0 {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::RrbcUsageExhausted,
                        "RRBC: Token usage limit exhausted.",
                    ));
                }
                rec.remaining -= 1;
                rec.remaining
            } else {
                let max_use = obj.get("max_use").and_then(|v| v.as_i64()).unwrap_or(1);
                max_use - 1
            }
        };

        let extract_strings = |key: &str| -> Vec<String> {
            obj.get(key)
                .and_then(|v| v.as_array())
                .map(|arr| arr.iter().filter_map(|v| v.as_str().map(String::from)).collect())
                .unwrap_or_default()
        };

        Ok(RRBCRedemptionResult {
            jti,
            issuer_agent: obj.get("iss").and_then(|v| v.as_str()).unwrap_or("").into(),
            allowed_agents: extract_strings("allow"),
            forbidden_agents: extract_strings("forbid"),
            actions: extract_strings("actions"),
            audience: extract_strings("aud"),
            sid: token_sid.into(),
            cid: token_cid.into(),
            oaid: token_oaid.into(),
            remaining_uses: remaining,
            max_action_class: obj.get("max_action_class").and_then(|v| v.as_u64()).unwrap_or(0) as u8,
        })
    }

    /// Revoke a token by JTI.
    pub fn revoke_token(&self, jti: &str) {
        let mut revoked = self.revoked_jtis.lock().unwrap();
        revoked.insert(jti.to_string());
        let mut tokens = self.tokens.lock().unwrap();
        if let Some(rec) = tokens.get_mut(jti) {
            rec.revoked = true;
            rec.remaining = 0;
        }
    }

    /// Check if a JTI has been revoked.
    pub fn is_jti_revoked(&self, jti: &str) -> bool {
        self.revoked_jtis.lock().unwrap().contains(jti)
    }

    /// Return remaining uses for a JTI, or None if not in registry.
    pub fn get_remaining_uses(&self, jti: &str) -> Option<i64> {
        let tokens = self.tokens.lock().unwrap();
        tokens.get(jti).map(|rec| rec.remaining)
    }

    /// Clear all replay state. Returns count of cleared entries.
    pub fn clear_replay_registry(&self) -> usize {
        let mut registry = self.replay_registry.lock().unwrap();
        let n = registry.len();
        registry.clear();
        n
    }
}

impl Default for RRBCGateway {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rate_limiter_basic() {
        let rl = AgentRateLimiter::new();
        for _ in 0..4 {
            assert!(rl.record_error("agent1").is_ok());
        }
        // 5th error should trigger circuit breaker
        assert!(rl.record_error("agent1").is_err());
        assert!(rl.is_locked("agent1"));
    }

    #[test]
    fn test_rate_limiter_reset() {
        let rl = AgentRateLimiter::new();
        for _ in 0..5 {
            let _ = rl.record_error("agent1");
        }
        assert!(rl.is_locked("agent1"));
        rl.reset(Some("agent1"));
        assert!(!rl.is_locked("agent1"));
    }

    #[test]
    fn test_cover_traffic() {
        let rl = AgentRateLimiter::new();
        for _ in 0..50 {
            assert!(rl.record_cover_traffic("agent1").is_ok());
        }
        // 51st should exceed threshold
        assert!(rl.record_cover_traffic("agent1").is_err());
    }

    #[test]
    fn test_issue_and_validate_token() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x01,
        );
        let result = gw.validate_lateral_movement("agent-b", &token, secret);
        assert!(result.is_ok());
        let r = result.unwrap();
        assert!(r.is_valid);
        assert_eq!(r.source_agent, "agent-a");
        assert_eq!(r.max_action_class, 0x01);
    }

    #[test]
    fn test_token_scope_violation() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x00,
        );
        let result = gw.validate_lateral_movement("agent-c", &token, secret);
        assert!(result.is_err());
    }

    #[test]
    fn test_token_revocation() {
        let gw = ZeroTrustGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = gw.issue_capability_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            3600,
            None,
            0x00,
        );
        gw.revoke_token(&token).unwrap();
        assert_eq!(gw.get_revocation_epoch(), 1);
    }

    #[test]
    fn test_revoke_all_tokens() {
        let gw = ZeroTrustGateway::new();
        gw.register_issuer_key("agent-a", b"secret");
        let epoch = gw.revoke_all_tokens();
        assert_eq!(epoch, 1);
    }

    #[test]
    fn test_delegation_guard() {
        let secret = b"root-orchestrator-key-32-bytes!!";
        let gw = ZeroTrustGateway::new();
        let token = gw.issue_capability_token(
            secret,
            "root",
            &["agent-b"],
            &[],
            3600,
            None,
            0x00,
        );
        assert!(DelegationGuard::validate_not_self_signed(&token, secret).is_ok());
        assert!(DelegationGuard::validate_not_self_signed(&token, b"wrong-key-32-bytes-long!!!!!!!!!").is_err());
    }

    #[test]
    fn test_rrbc_issue_and_redeem() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = rbc.issue_token(
            secret,
            "agent-a",
            &["agent-b"],
            &[],
            &["read"],
            &["agent-b"],
            "session-1",
            "conv-1",
            "agent-b",
            1,
            3600,
            0x00,
        );
        let result = rbc.redeem_token(
            &token,
            "rnonce-1",
            "agent-b",
            "session-1",
            "conv-1",
            "agent-b",
            secret,
        );
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.issuer_agent, "agent-a");
        assert_eq!(r.remaining_uses, 0);
    }

    #[test]
    fn test_rrbc_replay_detection() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = rbc.issue_token(
            secret, "a", &["b"], &[], &["read"], &["b"],
            "s1", "c1", "b", 1, 3600, 0x00,
        );
        assert!(rbc.redeem_token(&token, "rn", "b", "s1", "c1", "b", secret).is_ok());
        // Second redemption with same rnonce should fail
        assert!(rbc.redeem_token(&token, "rn", "b", "s1", "c1", "b", secret).is_err());
    }

    #[test]
    fn test_rrbc_binding_mismatch() {
        let rbc = RRBCGateway::new();
        let secret = b"test-secret-key-32-bytes-long!!!";
        let token = rbc.issue_token(
            secret, "a", &["b"], &[], &["read"], &["b"],
            "s1", "c1", "b", 1, 3600, 0x00,
        );
        assert!(rbc.redeem_token(&token, "rn", "b", "wrong-sid", "c1", "b", secret).is_err());
    }

    #[test]
    fn test_rrbc_revocation() {
        let rbc = RRBCGateway::new();
        rbc.revoke_token("jti-1");
        assert!(rbc.is_jti_revoked("jti-1"));
        assert!(!rbc.is_jti_revoked("jti-2"));
    }
}
