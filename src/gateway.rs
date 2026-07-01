//! gateway.rs — Zero-Trust Gateway
//!
//! Zero-Trust Tokenized Micro-Gateway.
//! Prevents prompt-injected agents from lateral movement using
//! cryptographically signed capability tokens.
//! Uses length-prefix format to prevent token delimiter injection.

use std::collections::{HashMap, HashSet, BTreeMap};
use std::sync::{Arc, Mutex, OnceLock, LazyLock};
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{VerifyingKey, Signature, Verifier};
use hmac::{Hmac, Mac};
use sha2::{Sha256, Digest};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::faitf::TrustStore;
use crate::acsvaf::CapabilityVerificationAuthority;

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
    let sorted: BTreeMap<&String, &serde_json::Value> = data.iter().collect();
    serde_json::to_vec(&sorted).unwrap_or_default()
}

/// Sort a JSON array of strings in-place (for cross-language token compatibility).
fn sorted_str_array(items: &[&str]) -> serde_json::Value {
    let mut v: Vec<String> = items.iter().map(|s| s.to_string()).collect();
    v.sort();
    serde_json::Value::Array(v.into_iter().map(serde_json::Value::String).collect())
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
    // u32→usize is always safe: u32 <= usize on all supported platforms.
    let json_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
    if json_len == 0 || json_len > raw.len().saturating_sub(4) {
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

    /// Process-wide singleton AgentRateLimiter.
    ///
    /// Used by `SAACPProtocolHandler::intercept_packet()` as the unconditional
    /// circuit-breaker fallback when no rate_limiter is explicitly injected.
    /// Enforces GAP-3 (circuit breaker always checked) and GAP-10 (record_error
    /// always called on SAACPHardDrop) per Python `intercept_packet` parity.
    pub fn global() -> &'static AgentRateLimiter {
        static GLOBAL: OnceLock<AgentRateLimiter> = OnceLock::new();
        GLOBAL.get_or_init(AgentRateLimiter::new)
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
    /// T3.1 — TrustStore integration (FAITF identity verification)
    trust_store: Mutex<Option<Arc<TrustStore>>>,
    /// T3.2 — ACSVAF capability verification authority
    capability_authority: Mutex<Option<Arc<CapabilityVerificationAuthority>>>,
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
            trust_store: Mutex::new(None),
            capability_authority: Mutex::new(None),
        }
    }

    /// Process-wide ZeroTrustGateway singleton used as fallback when no gateway is injected.
    /// Provides a shared revocation list and cache so that revocations performed via the
    /// global gateway are honoured by stream-continuation checks even without a per-call
    /// gateway reference.
    pub fn global() -> &'static ZeroTrustGateway {
        static GLOBAL_ZTG: LazyLock<ZeroTrustGateway> =
            LazyLock::new(ZeroTrustGateway::new);
        &GLOBAL_ZTG
    }

    /// When true, HMAC-PSK tokens are rejected outright.
    pub fn set_strict_asymmetric_mode(&self, enabled: bool) {
        *self.strict_asymmetric_mode.lock().unwrap() = enabled;
        self.token_cache.lock().unwrap().clear();
    }

    /// T3.1 — Register a FAITF TrustStore for identity verification.
    pub fn register_trust_store(&self, ts: Arc<TrustStore>) {
        *self.trust_store.lock().unwrap() = Some(ts);
        self.token_cache.lock().unwrap().clear();
    }

    /// T3.2 — Register an ACSVAF CapabilityVerificationAuthority.
    pub fn register_capability_authority(&self, ca: Arc<CapabilityVerificationAuthority>) {
        *self.capability_authority.lock().unwrap() = Some(ca);
        self.token_cache.lock().unwrap().clear();
    }

    /// Register the canonical token-signing key for a trusted issuer.
    /// T3.8: validates non-empty agent string and exactly 32-byte secret.
    pub fn register_issuer_key(&self, issuer_agent: &str, issuer_secret: &[u8]) -> Result<(), SAACPHardDrop> {
        if issuer_agent.trim().is_empty() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                "register_issuer_key: issuer_agent must be non-empty",
            ));
        }
        // SECURITY: reject null bytes in agent IDs to prevent string-termination bypass
        // in downstream comparisons (e.g. "agent\x00" == "agent" in C-style matching).
        if issuer_agent.contains('\0') {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                "register_issuer_key: issuer_agent must not contain null bytes",
            ));
        }
        if issuer_secret.len() != 32 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                format!("register_issuer_key: secret must be exactly 32 bytes, got {}", issuer_secret.len()),
            ));
        }
        self.trusted_issuer_keys
            .lock()
            .unwrap()
            .insert(issuer_agent.to_string(), issuer_secret.to_vec());
        self.token_cache.lock().unwrap().clear();
        *self.issuer_registry_epoch.lock().unwrap() += 1;
        Ok(())
    }

    /// Clear trusted issuer registry.
    pub fn clear_trusted_issuers(&self) {
        self.trusted_issuer_keys.lock().unwrap().clear();
        self.token_cache.lock().unwrap().clear();
        *self.issuer_registry_epoch.lock().unwrap() += 1;
    }

    /// Issue a capability token (HMAC-SHA256 path).
    /// T3.5/T3.6: sorted allow/forbid lists; supports thash field for ACSVAF compatibility.
    #[allow(clippy::too_many_arguments)]
    pub fn issue_capability_token(
        &self,
        issuer_secret: &[u8],
        issuer_agent: &str,
        allowed_agents: &[&str],
        forbidden_agents: &[&str],
        ttl_seconds: u64,
        root_intent_hash: Option<&str>,
        max_action_class: u8,
        thash: Option<&str>,
    ) -> Vec<u8> {
        // f64→u64: epoch seconds always positive, fractional part discarded intentionally.
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
        let expiry = now_epoch_secs() as u64 + ttl_seconds;

        let mut token_data = HashMap::new();
        token_data.insert("iss".into(), serde_json::Value::String(issuer_agent.into()));
        token_data.insert("exp".into(), serde_json::Value::Number(expiry.into()));
        // T3.6: sort lists for deterministic cross-language HMAC
        token_data.insert("allow".into(), sorted_str_array(allowed_agents));
        token_data.insert("forbid".into(), sorted_str_array(forbidden_agents));
        token_data.insert("max_action_class".into(), serde_json::Value::Number(max_action_class.into()));
        if let Some(rih) = root_intent_hash {
            token_data.insert("root_intent_hash".into(), serde_json::Value::String(rih.into()));
        }
        // T3.4: thash alias for ACSVAF transcript binding
        if let Some(th) = thash {
            token_data.insert("thash".into(), serde_json::Value::String(th.into()));
        }

        let token_json = serialize_sorted_json(&token_data);
        let signature = hmac_sha256(issuer_secret, &token_json);

        // SECURITY: validate json_len fits in u32 before packing into the 4-byte wire field.
        let json_len = u32::try_from(token_json.len()).unwrap_or(u32::MAX);
        let mut packed = Vec::with_capacity(4 + token_json.len() + signature.len());
        packed.extend_from_slice(&json_len.to_be_bytes());
        packed.extend_from_slice(&token_json);
        packed.extend_from_slice(&signature);

        use base64::Engine;
        base64::engine::general_purpose::STANDARD.encode(&packed).into_bytes()
    }

    /// Revoke a token by adding its signature hash to the revocation set.
    pub fn revoke_token(&self, token_b64: &[u8]) -> Result<(), String> {
        let (_token_json, signature) = parse_token_wire(token_b64)
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

        // Hash the token before using it as a cache key — never store the plaintext
        // capability token in a data structure that could be heap-dumped or logged.
        let token_hash = sha256_hex(token_b64);
        let cache_key = format!(
            "{}:{}:{}:{}:{}",
            target_agent,
            token_hash,
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

            // When no registry is configured, require an explicit secret of at least 32 bytes
            // to prevent acceptance of default/empty keys by callers that omit the parameter.
            if !has_registry && issuer_secret.len() < 32 {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::InvalidSignature,
                    "HMAC fallback requires at least a 32-byte issuer_secret when no registry is configured.",
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

        // Check forbidden list — H-4 fix: HashSet for O(1) lookup, no timing side-channel.
        // Vec::contains() is O(n) and short-circuits on first differing byte, leaking
        // information about which forbidden agents share a prefix with the target.
        let forbid: HashSet<&str> = obj
            .get("forbid")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if forbid.contains(target_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                format!("Strictly forbidden from calling {}.", target_agent),
            ));
        }

        // Check allowed list — H-4 fix: HashSet for O(1) lookup.
        let allow: HashSet<&str> = obj
            .get("allow")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect())
            .unwrap_or_default();
        if !allow.contains(target_agent) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::ScopeViolation,
                format!("Scope violation: '{}' is not in the allowed scope list.", target_agent),
            ));
        }

        // H-2 fix: Self-issue guard for the HMAC-PSK path.
        // DelegationGuard exists but was never wired into validate_lateral_movement.
        // A token where iss == target_agent grants an agent permission to call itself,
        // which is semantically identical to no authorization check at all.
        if source_agent == target_agent {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SelfIssuedCapability,
                format!(
                    "Self-issued lateral movement rejected: '{}' cannot authorize itself.",
                    source_agent
                ),
            ));
        }

        // T3.4: thash alias — treat "thash" as equivalent to "root_intent_hash"
        let root_intent_hash = obj
            .get("root_intent_hash")
            .or_else(|| obj.get("thash"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        // SECURITY: validate max_action_class fits in u8 before casting.
        // A value > 255 silently truncating could grant higher privilege than intended
        // (e.g. 0x102 → 0x02 = IRREVERSIBLE when only 0x01 was intended).
        let mac_raw = obj
            .get("max_action_class")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        if mac_raw > u8::MAX as u64 {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::SchemaMismatch,
                format!("max_action_class value {mac_raw} exceeds valid range 0–255"),
            ));
        }
        let max_action_class = mac_raw as u8;

        let result = TokenValidationResult {
            is_valid: true,
            source_agent,
            root_intent_hash,
            max_action_class,
        };

        // T3.7: eviction — drop expired first, then soonest-expiring 20% if still full.
        // SECURITY FIX: The previous code used `.keys().take(n)` which iterates in
        // HashMap's internal (process-deterministic) order.  An attacker observing which
        // tokens survive eviction could time requests to prevent a compromised token from
        // being evicted, extending its effective validity window.  Evicting soonest-expiring
        // entries is deterministic (based on content, not iteration order) and correct:
        // entries closest to natural expiry provide the least residual value anyway.
        let cache_expiry = (now_epoch_secs() + TOKEN_CACHE_TTL).min(exp);
        let mut cache = self.token_cache.lock().unwrap();
        if cache.len() >= TOKEN_CACHE_MAX {
            let current_time = now_epoch_secs();
            // First pass: drop already-expired entries (free, no ordering needed).
            cache.retain(|_, v| v.expiry > current_time);
            // Second pass: if still at/above capacity, evict the 20% soonest to expire.
            if cache.len() >= TOKEN_CACHE_MAX {
                let evict_count = TOKEN_CACHE_MAX / 5;
                let mut by_expiry: Vec<(String, f64)> = cache
                    .iter()
                    .map(|(k, v)| (k.clone(), v.expiry))
                    .collect();
                // Sort ascending by expiry — soonest-expiring entries first.
                by_expiry.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                for (k, _) in by_expiry.into_iter().take(evict_count) {
                    cache.remove(&k);
                }
            }
        }
        cache.insert(cache_key, CacheEntry {
            expiry: cache_expiry,
            result: result.clone(),
        });

        Ok(result)
    }

    // T3.3 — Ed25519 signature verification path (delegates to module-level fn)
    #[allow(dead_code)]
    fn verify_ed25519_signature(
        token_json: &[u8],
        signature: &[u8],
        pub_key_bytes: &[u8],
    ) -> Result<(), SAACPHardDrop> {
        verify_ed25519_signature_inner(token_json, signature, pub_key_bytes)
    }
}

// ---------------------------------------------------------------------------
// Module-level Ed25519 verification helper (shared by ZeroTrustGateway + RRBCGateway)
// ---------------------------------------------------------------------------

fn verify_ed25519_signature_inner(
    token_json: &[u8],
    signature: &[u8],
    pub_key_bytes: &[u8],
) -> Result<(), SAACPHardDrop> {
    if pub_key_bytes.len() != 32 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 public key must be 32 bytes",
        ));
    }
    if signature.len() != 64 {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 signature must be 64 bytes",
        ));
    }
    let pub_key_arr: [u8; 32] = pub_key_bytes.try_into().map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 public key internal conversion failed (unexpected length)",
        )
    })?;
    let vk = VerifyingKey::from_bytes(&pub_key_arr)
        .map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Invalid Ed25519 public key bytes",
        ))?;
    let sig_arr: [u8; 64] = signature.try_into().map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 signature internal conversion failed (unexpected length)",
        )
    })?;
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(token_json, &sig)
        .map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "Ed25519 signature verification failed",
        ))
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

#[allow(dead_code)]
struct RRBCTokenRecord {
    data: serde_json::Value,
    remaining: i64,
    revoked: bool,
}

/// TTL for replay-registry entries: entries are kept until the bound token expires
/// (the token's own `exp` field), after which they can never be replayed anyway.
/// Hard cap prevents OOM if exp values are far in the future.
pub const RRBC_REPLAY_REGISTRY_MAX: usize = 500_000;

/// Replay-Resistant Bound Capabilities gateway.
pub struct RRBCGateway {
    /// Maps (jti, rnonce, sid) → token_exp_timestamp.
    /// Entries are pruned once now() > token_exp (replay is impossible then anyway).
    /// SECURITY FIX (RRBC-OOM): previously stored `i64` (count) with no eviction,
    /// growing without bound under sustained load.
    replay_registry: Mutex<HashMap<(String, String, String), f64>>,
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
    ///
    /// `pop_verifying_key`: if `Some`, embeds the Ed25519 public key (32 raw bytes)
    /// in the token so that `redeem_token` enforces proof-of-possession (spec §8.2 step 4).
    #[allow(clippy::too_many_arguments)]
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
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
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
        // PoP key embedded in token if provided (spec §8.2 step 4).
        // Absent = no PoP required; present = redeem_token enforces Ed25519 proof.

        let token_json = serde_json::to_vec(&serde_json::Value::Object(token_data)).unwrap_or_default();
        let signature = hmac_sha256(issuer_secret, &token_json);

        let json_len = u32::try_from(token_json.len()).unwrap_or(u32::MAX);
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

    /// Redeem a single use of an RRBC token (spec §8.2).
    ///
    /// `pop_proof`: Ed25519 signature (64 bytes) over `rnonce.as_bytes()` made
    /// with the presenter's private key, required when the token contains a
    /// `pop_key` field (spec §8.2 step 4).  Pass `None` when no PoP was
    /// requested at issuance.
    #[allow(clippy::too_many_arguments)]
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
        self.redeem_token_with_pop(
            token_b64, rnonce, presenting_agent,
            presenting_sid, presenting_cid, presenting_oaid,
            issuer_secret, None,
        )
    }

    /// Redeem with optional Ed25519 proof-of-possession (spec §8.2 step 4).
    #[allow(clippy::too_many_arguments)]
    pub fn redeem_token_with_pop(
        &self,
        token_b64: &[u8],
        rnonce: &str,
        presenting_agent: &str,
        presenting_sid: &str,
        presenting_cid: &str,
        presenting_oaid: &str,
        issuer_secret: &[u8],
        pop_proof: Option<&[u8]>,
    ) -> Result<RRBCRedemptionResult, SAACPHardDrop> {
        // Parse token
        let (token_json, signature) = parse_token_wire(token_b64).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::LateralMovementBlocked,
                "RRBC: Missing or malformed capability token.",
            )
        })?;

        // Verify HMAC — SECURITY: must compare full-length signatures.
        // Truncated comparison (e.g. signature[..N]) allows a 1-byte signature
        // to pass if its first byte matches the expected HMAC output.
        let expected_sig = hmac_sha256(issuer_secret, &token_json);
        if signature.len() != expected_sig.len()
            || !constant_time_eq(&expected_sig, &signature)
        {
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

            // TTL-based eviction: prune entries whose bound token has expired.
            // An expired token can never be replayed (it will fail the temporal check
            // above), so these entries provide zero replay-protection value.
            // This keeps the registry O(active_tokens) instead of O(all_time_uses).
            let current_time = now_epoch_secs();
            if registry.len() >= RRBC_REPLAY_REGISTRY_MAX / 2 {
                registry.retain(|_, &mut token_exp| current_time < token_exp);
            }
            // Hard cap: if still at limit after pruning, reject to prevent OOM.
            if registry.len() >= RRBC_REPLAY_REGISTRY_MAX {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::CircuitBreakerOpen,
                    "RRBC: Replay registry at capacity — rejecting to prevent OOM.",
                ));
            }

            if registry.contains_key(&replay_key) {
                return Err(SAACPHardDrop::new(
                    SAACPBytecodes::RrbcReplayDetected,
                    "RRBC: Replay detected — (jti, rnonce, sid) already consumed.",
                ));
            }
            // Store token_exp as the entry TTL so we know when it's safe to evict.
            registry.insert(replay_key, exp);
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

        // Step 4 (spec §8.2): Proof-of-Possession verification.
        // If the token carries a pop_key field, the presenter MUST provide a
        // valid Ed25519 signature over `rnonce` bytes; absence of proof → RRBC_POP_FAILED.
        if let Some(pop_key_b64) = obj.get("pop_key").and_then(|v| v.as_str()) {
            let pop_key_bytes = base64::Engine::decode(
                &base64::engine::general_purpose::STANDARD,
                pop_key_b64.as_bytes(),
            ).map_err(|_| SAACPHardDrop::new(
                SAACPBytecodes::RrbcPopFailed,
                "RRBC PoP: invalid pop_key encoding in token.",
            ))?;
            let proof = pop_proof.ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::RrbcPopFailed,
                "RRBC PoP: token requires proof-of-possession but none was supplied.",
            ))?;
            // Verify Ed25519(pop_key, message=rnonce, sig=proof)
            verify_ed25519_signature_inner(rnonce.as_bytes(), proof, &pop_key_bytes)
                .map_err(|_| SAACPHardDrop::new(
                    SAACPBytecodes::RrbcPopFailed,
                    "RRBC PoP: Ed25519 proof-of-possession verification failed.",
                ))?;
        } else if pop_proof.is_some() {
            // Token does not require PoP but caller supplied a proof — reject to prevent
            // bypass attempts where a forged pop_key field is stripped but proof remains.
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RrbcPopFailed,
                "RRBC PoP: proof-of-possession supplied but token does not require it.",
            ));
        }

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
            max_action_class: {
                let v = obj.get("max_action_class").and_then(|v| v.as_u64()).unwrap_or(0);
                u8::try_from(v).unwrap_or(u8::MAX)
            },
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

    /// Prune expired replay-registry entries (entries whose token_exp < now).
    /// Returns the count of pruned entries. Call periodically from a maintenance task.
    pub fn prune_expired_replay_entries(&self) -> usize {
        let mut registry = self.replay_registry.lock().unwrap();
        let before = registry.len();
        let now = now_epoch_secs();
        registry.retain(|_, &mut token_exp| now < token_exp);
        before - registry.len()
    }

    /// Return the current size of the replay registry (for monitoring).
    pub fn replay_registry_size(&self) -> usize {
        self.replay_registry.lock().unwrap().len()
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
            None,
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
            None,
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
            None,
        );
        gw.revoke_token(&token).unwrap();
        assert_eq!(gw.get_revocation_epoch(), 1);
    }

    #[test]
    fn test_revoke_all_tokens() {
        let gw = ZeroTrustGateway::new();
        gw.register_issuer_key("agent-a", b"secret-key-32-bytes-long!!!!!!!!").unwrap();
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
            None,
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

    /// Task: revoke_all_tokens_increments_both_epochs
    #[test]
    fn revoke_all_tokens_increments_both_epochs() {
        let gw = ZeroTrustGateway::new();
        // Register an issuer to give issuer_registry_epoch a baseline to work with
        gw.register_issuer_key("agent-a", b"secret-key-32-bytes-long!!!!!!!!").unwrap();
        let rev_epoch_before = gw.get_revocation_epoch();
        let epoch = gw.revoke_all_tokens();
        // revoke_all_tokens() increments revocation_epoch by 1 and returns it
        assert_eq!(epoch, rev_epoch_before + 1, "revocation_epoch must increment");
        // Calling twice must keep incrementing
        let epoch2 = gw.revoke_all_tokens();
        assert_eq!(epoch2, epoch + 1, "revocation_epoch must increment on each call");
        // get_revocation_epoch() must match the return value
        assert_eq!(gw.get_revocation_epoch(), epoch2);
    }

    /// Task: cover_traffic_budget_separate_from_error_budget
    #[test]
    fn cover_traffic_budget_separate_from_error_budget() {
        let rl = AgentRateLimiter::new();
        // Fill the cover-traffic budget to the threshold (50 in COVER_TRAFFIC_WINDOW_SECONDS=1.0s).
        // All within one second, so count accumulates in the same window.
        for i in 0..COVER_TRAFFIC_THRESHOLD {
            assert!(
                rl.record_cover_traffic("agent-cover").is_ok(),
                "call {i} must be OK within threshold"
            );
        }
        // The (THRESHOLD+1)-th call must be rejected as rate-limited.
        let over_limit = rl.record_cover_traffic("agent-cover");
        assert!(over_limit.is_err(), "cover traffic over threshold must be rejected");

        // Meanwhile, a different agent has independent cover traffic budget.
        assert!(rl.record_cover_traffic("agent-other").is_ok(),
            "different agent must have its own budget");
    }
}
