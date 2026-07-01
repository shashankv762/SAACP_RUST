//! Federated Authorization and Cryptographic Trust Framework (FACTF)
//!
//! Layers advanced trust infrastructure on top of ACSVAF:
//! - `DelegationChainValidator` — anti-amplification, depth-limit, cycle/orphan detection
//! - `ThresholdAuthorityIssuer` — M-of-N independent-signature capability issuance
//! - `CapabilityTransparencyLog` — hash-chained append-only audit ledger
//! - `RiskAwareAuthorizationEvaluator` — configurable-policy risk scoring
//! - `PostCompromiseRecovery` — structured key-compromise handling

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::acsvaf::{
    CapabilityVerificationAuthority,
    SignedCapabilityToken, ACSVAF_MAX_DELEGATION_DEPTH,
};
use crate::errors::{SAACPBytecodes, SAACPHardDrop};

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn new_uuid_hex() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

// ─── DelegationChainValidator ───────────────────────────────────────────────────

/// Result of validating a delegation chain.
#[derive(Debug, Clone)]
pub struct DelegationChainResult {
    pub valid: bool,
    pub depth: usize,
    pub root_jti: String,
    pub final_jti: String,
    pub effective_actions: Vec<String>,
    pub effective_max_action_class: u8,
    pub violations: Vec<String>,
}

/// Validates a complete delegation chain from root issuer to final token.
pub struct DelegationChainValidator;

impl DelegationChainValidator {
    pub fn validate_chain(
        tokens: &[SignedCapabilityToken],
        verification_authority: &CapabilityVerificationAuthority,
    ) -> DelegationChainResult {
        let mut violations: Vec<String> = Vec::new();

        if tokens.is_empty() {
            violations.push("Empty delegation chain.".to_string());
            return DelegationChainResult {
                valid: false,
                depth: 0,
                root_jti: String::new(),
                final_jti: String::new(),
                effective_actions: Vec::new(),
                effective_max_action_class: 0,
                violations,
            };
        }

        let jti_set: HashSet<String> = tokens.iter().map(|t| t.jti()).collect();
        let mut seen_jtis: HashSet<String> = HashSet::new();
        let root_sid = tokens[0].sid();
        let mut effective_actions: HashSet<String> =
            tokens[0].actions().into_iter().collect();
        let mut effective_mac: u8 = tokens[0].max_action_class();
        let root_jti = tokens[0].jti();

        for (i, token) in tokens.iter().enumerate() {
            // Signature verification
            if let Some(vk) = verification_authority.get_verification_key(&token.kid()) {
                let claims_bytes = token.claims_bytes();
                if !Self::verify_ed25519(&vk, &claims_bytes, &token.signature) {
                    let j = token.jti();
                    violations.push(format!(
                        "[{}] Signature invalid for jti '{}'.",
                        i,
                        &j[..8.min(j.len())]
                    ));
                }
            } else {
                violations.push(format!("[{}] kid '{}' not trusted.", i, token.kid()));
            }

            // Depth
            if token.delegation_depth() != i {
                violations.push(format!(
                    "[{}] delegation_depth={} expected {}.",
                    i, token.delegation_depth(), i
                ));
            }
            if i > ACSVAF_MAX_DELEGATION_DEPTH as usize {
                violations.push(format!(
                    "[{}] Chain depth {} exceeds MAX_DELEGATION_DEPTH={}."
                , i, i, ACSVAF_MAX_DELEGATION_DEPTH));
            }

            // Circular reference
            let token_jti = token.jti();
            if !seen_jtis.insert(token_jti.clone()) {
                violations.push(format!(
                    "[{}] Circular jti reference: '{}'.",
                    i,
                    &token_jti[..8.min(token_jti.len())]
                ));
            }

            // Orphan check
            if i > 0 {
                let pjti = token.parent_jti();
                let parent_jti_str = pjti.as_deref().unwrap_or("");
                if !parent_jti_str.is_empty() && !jti_set.contains(parent_jti_str) {
                    violations.push(format!(
                        "[{}] parent_jti '{}' not in chain (orphan).",
                        i,
                        &parent_jti_str[..8.min(parent_jti_str.len())]
                    ));
                }
            }

            // Anti-amplification
            if i > 0 {
                let parent = &tokens[i - 1];
                let parent_actions: HashSet<String> =
                    parent.actions().into_iter().collect();
                let child_actions: HashSet<String> =
                    token.actions().into_iter().collect();
                let extra: HashSet<_> =
                    child_actions.difference(&parent_actions).collect();
                if !extra.is_empty() {
                    violations.push(format!(
                        "[{}] Privilege amplification: actions {:?} exceed parent.",
                        i, extra
                    ));
                }
                let token_mac = token.max_action_class();
                let parent_mac = parent.max_action_class();
                if token_mac > parent_mac {
                    violations.push(format!(
                        "[{}] max_action_class {} > parent {} (escalation).",
                        i, token_mac, parent_mac
                    ));
                }
                effective_actions = effective_actions
                    .intersection(&child_actions)
                    .cloned()
                    .collect();
                effective_mac = effective_mac.min(token_mac);
            }

            // Cross-session binding
            let token_sid = token.sid();
            if token_sid != root_sid {
                violations.push(format!(
                    "[{}] sid '{}' != root sid '{}' (cross-session).",
                    i, token_sid, root_sid
                ));
            }
        }

        let valid = violations.is_empty();
        let mut sorted_actions: Vec<String> = effective_actions.into_iter().collect();
        sorted_actions.sort();

        DelegationChainResult {
            valid,
            depth: tokens.len() - 1,
            root_jti,
            final_jti: tokens.last().unwrap().jti(),
            effective_actions: sorted_actions,
            effective_max_action_class: effective_mac,
            violations,
        }
    }

    fn verify_ed25519(
        verifying_key: &VerifyingKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        if signature.len() != 64 {
            return false;
        }
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(signature);
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        verifying_key.verify(message, &sig).is_ok()
    }
}

// ─── ThresholdAuthorityIssuer ───────────────────────────────────────────────────

/// Approval state for a threshold request.
#[derive(Debug, Clone)]
pub struct ThresholdApprovalState {
    pub request_id: String,
    pub approvals_received: usize,
    pub threshold_m: usize,
    pub is_ready: bool,
}

/// M-of-N independently signed capability token.
#[derive(Debug, Clone)]
pub struct ThresholdCapabilityToken {
    pub request_id: String,
    pub base_claims: serde_json::Value,
    pub signatures: Vec<ThresholdSignatureEntry>,
    pub threshold_m: usize,
    pub participating_authorities: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ThresholdSignatureEntry {
    pub kid: String,
    pub issuer_id: String,
    pub signature_hex: String,
    pub claims_bytes_hex: String,
}

impl ThresholdCapabilityToken {
    pub fn to_wire(&self) -> String {
        serde_json::to_string(&serde_json::json!({
            "request_id": self.request_id,
            "base_claims": self.base_claims,
            "signatures": self.signatures.iter().map(|s| serde_json::json!({
                "kid": s.kid,
                "issuer_id": s.issuer_id,
                "signature_hex": s.signature_hex,
                "claims_bytes_hex": s.claims_bytes_hex,
            })).collect::<Vec<_>>(),
            "threshold_m": self.threshold_m,
            "participants": self.participating_authorities,
        }))
        .unwrap_or_default()
    }
}

#[allow(dead_code)]
struct ProposalState {
    base_claims: serde_json::Value,
    approvals: HashMap<String, ThresholdSignatureEntry>,
    created_at: f64,
    expires_at: f64,
}

/// Orchestrates M-of-N multi-authority capability issuance.
pub struct ThresholdAuthorityIssuer {
    m: usize,
    authorities: HashSet<String>,
    proposal_ttl: f64,
    requests: Mutex<HashMap<String, ProposalState>>,
}

impl ThresholdAuthorityIssuer {
    pub const DEFAULT_PROPOSAL_TTL_SECONDS: f64 = 300.0;

    pub fn new(
        threshold_m: usize,
        authority_issuer_ids: Vec<String>,
        proposal_ttl_seconds: f64,
    ) -> Result<Self, String> {
        if threshold_m < 1 {
            return Err("threshold_m must be >= 1".to_string());
        }
        if threshold_m > authority_issuer_ids.len() {
            return Err("threshold_m cannot exceed the number of authorities".to_string());
        }
        if proposal_ttl_seconds <= 0.0 {
            return Err("proposal_ttl_seconds must be positive".to_string());
        }
        Ok(Self {
            m: threshold_m,
            authorities: authority_issuer_ids.into_iter().collect(),
            proposal_ttl: proposal_ttl_seconds,
            requests: Mutex::new(HashMap::new()),
        })
    }

    /// Register a new threshold request. Returns request_id.
    pub fn create_request(&self, base_claims: serde_json::Value) -> String {
        let request_id = new_uuid_hex();
        let now = now_f64();
        let state = ProposalState {
            base_claims,
            approvals: HashMap::new(),
            created_at: now,
            expires_at: now + self.proposal_ttl,
        };
        self.requests
            .lock()
            .unwrap()
            .insert(request_id.clone(), state);
        request_id
    }

    /// Submit one authority's signed approval for request_id.
    pub fn submit_partial_approval(
        &self,
        request_id: &str,
        issuer_id: &str,
        token: &SignedCapabilityToken,
    ) -> Result<ThresholdApprovalState, SAACPHardDrop> {
        if !self.authorities.contains(issuer_id) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AcsvafKeyNotTrusted,
                format!(
                    "FACTF: Authority '{}' is not in the threshold authority list.",
                    issuer_id
                ),
            ));
        }
        if token.signature.iter().all(|&b| b == 0) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "Token must be signed before submitting as approval.".to_string(),
            ));
        }

        // N-6 fix: auto-clean expired proposals on every submission (matches Python behavior)
        self.gc_expired_proposals();

        let mut requests = self.requests.lock().unwrap();
        let state = requests.get_mut(request_id).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::AcsvafThresholdNotReached,
                format!("FACTF: Unknown request_id '{}'.", request_id),
            )
        })?;

        // Reject expired proposals
        if now_f64() > state.expires_at {
            drop(requests);
            self.requests.lock().unwrap().remove(request_id);
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AcsvafThresholdNotReached,
                format!(
                    "FACTF: Proposal '{}' has expired (TTL exceeded).",
                    request_id
                ),
            ));
        }

        if state.approvals.contains_key(issuer_id) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AcsvafThresholdNotReached,
                format!("FACTF: Duplicate approval from '{}'.", issuer_id),
            ));
        }

        state.approvals.insert(
            issuer_id.to_string(),
            ThresholdSignatureEntry {
                kid: token.kid(),
                issuer_id: issuer_id.to_string(),
                signature_hex: hex::encode(token.signature),
                claims_bytes_hex: hex::encode(token.claims_bytes()),
            },
        );

        let count = state.approvals.len();
        Ok(ThresholdApprovalState {
            request_id: request_id.to_string(),
            approvals_received: count,
            threshold_m: self.m,
            is_ready: count >= self.m,
        })
    }

    /// Assemble a ThresholdCapabilityToken once >= M approvals are collected.
    pub fn assemble_threshold_token(
        &self,
        request_id: &str,
    ) -> Result<ThresholdCapabilityToken, String> {
        let requests = self.requests.lock().unwrap();
        let state = requests
            .get(request_id)
            .ok_or_else(|| format!("FACTF: Unknown request_id '{}'.", request_id))?;

        if now_f64() > state.expires_at {
            drop(requests);
            self.requests.lock().unwrap().remove(request_id);
            return Err(format!(
                "FACTF: Proposal '{}' has expired before reaching threshold.",
                request_id
            ));
        }

        if state.approvals.len() < self.m {
            return Err(format!(
                "FACTF: Only {}/{} approvals collected.",
                state.approvals.len(),
                self.m
            ));
        }

        Ok(ThresholdCapabilityToken {
            request_id: request_id.to_string(),
            base_claims: state.base_claims.clone(),
            signatures: state.approvals.values().cloned().collect(),
            threshold_m: self.m,
            participating_authorities: state.approvals.keys().cloned().collect(),
        })
    }

    /// Remove expired proposals. Returns purge count. (Python API: purge_expired_requests)
    pub fn purge_expired_requests(&self) -> usize {
        let now = now_f64();
        let mut requests = self.requests.lock().unwrap();
        let expired: Vec<String> = requests
            .iter()
            .filter(|(_, s)| now > s.expires_at)
            .map(|(k, _)| k.clone())
            .collect();
        let count = expired.len();
        for rid in expired {
            requests.remove(&rid);
        }
        count
    }

    /// N-6 fix: gc_expired_proposals() — Python-API-named cleanup.
    /// Removes all proposals where proposal_ttl has elapsed.
    /// Call explicitly or relies on auto-call inside submit_partial_approval().
    pub fn gc_expired_proposals(&self) -> usize {
        self.purge_expired_requests()
    }

    /// Return number of in-flight (non-expired) proposals.
    pub fn pending_request_count(&self) -> usize {
        let now = now_f64();
        self.requests
            .lock()
            .unwrap()
            .values()
            .filter(|s| now <= s.expires_at)
            .count()
    }

    /// Verify a threshold token — requires >= M distinct valid signatures.
    pub fn verify_threshold_token(
        &self,
        token: &ThresholdCapabilityToken,
        verification_authority: &CapabilityVerificationAuthority,
    ) -> bool {
        let claims_bytes = serde_json::to_vec(&token.base_claims).unwrap_or_default();

        let mut valid_count: usize = 0;
        let mut seen_issuers: HashSet<String> = HashSet::new();

        for entry in &token.signatures {
            if !seen_issuers.insert(entry.issuer_id.clone()) {
                continue;
            }

            let key = match verification_authority.get_verification_key(&entry.kid) {
                Some(k) => k,
                None => continue,
            };

            let sig = match hex::decode(&entry.signature_hex) {
                Ok(s) => s,
                Err(_) => continue,
            };

            let actual_claims = if !entry.claims_bytes_hex.is_empty() {
                hex::decode(&entry.claims_bytes_hex).unwrap_or_default()
            } else {
                claims_bytes.clone()
            };

            if DelegationChainValidator::verify_ed25519(
                &key,
                &actual_claims,
                &sig,
            ) {
                valid_count += 1;
            }
        }

        valid_count >= token.threshold_m
    }
}

// ─── Transparency Log ───────────────────────────────────────────────────────────

/// A single entry in the transparency log.
#[derive(Debug, Clone)]
pub struct TransparencyLogEntry {
    pub entry_id: String,
    pub event_type: String,
    pub jti: Option<String>,
    pub kid: Option<String>,
    pub issuer_id: String,
    pub sub_hash: String,
    pub aud_hash: String,
    pub actions_hash: String,
    pub timestamp: f64,
    pub delegation_depth: usize,
    pub parent_jti_hash: Option<String>,
    pub entry_hash: String,
    pub chain_hash: String,
    pub entry_signature: Vec<u8>,
}

fn compute_entry_hash(e: &TransparencyLogEntry) -> String {
    let blob = format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        e.entry_id,
        e.event_type,
        e.jti.as_deref().unwrap_or(""),
        e.kid.as_deref().unwrap_or(""),
        e.issuer_id,
        e.sub_hash,
        e.aud_hash,
        e.actions_hash,
        e.timestamp,
        e.delegation_depth,
        e.parent_jti_hash.as_deref().unwrap_or(""),
    );
    sha256_hex(blob.as_bytes())
}

/// Thread-safe in-memory transparency log backend.
pub struct InMemoryBackend {
    entries: Mutex<Vec<TransparencyLogEntry>>,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(Vec::new()),
        }
    }

    pub fn append(&self, entry: TransparencyLogEntry) {
        self.entries.lock().unwrap().push(entry);
    }

    pub fn get_all(&self) -> Vec<TransparencyLogEntry> {
        self.entries.lock().unwrap().clone()
    }

    pub fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.jti.as_deref() == Some(jti))
            .cloned()
            .collect()
    }

    pub fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

impl Default for InMemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

const GENESIS_CHAIN_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Append-only, cryptographically hash-chained capability transparency ledger.
pub struct CapabilityTransparencyLog {
    backend: InMemoryBackend,
    last_hash: Mutex<String>,
}

impl CapabilityTransparencyLog {
    pub fn new() -> Self {
        Self {
            backend: InMemoryBackend::new(),
            last_hash: Mutex::new(GENESIS_CHAIN_HASH.to_string()),
        }
    }

    /// Append an event. Returns the chain_hash of this entry.
    #[allow(clippy::too_many_arguments)]
    pub fn append(
        &self,
        event_type: &str,
        issuer_id: &str,
        jti: Option<&str>,
        kid: Option<&str>,
        sub: &str,
        aud: &[&str],
        actions: &[&str],
        delegation_depth: usize,
        parent_jti: Option<&str>,
        signing_key: Option<&SigningKey>,
    ) -> String {
        let sub_hash = sha256_hex(sub.as_bytes());
        let mut sorted_aud: Vec<&str> = aud.to_vec();
        sorted_aud.sort();
        let aud_hash = sha256_hex(
            &serde_json::to_vec(&sorted_aud).unwrap_or_default(),
        );
        let mut sorted_actions: Vec<&str> = actions.to_vec();
        sorted_actions.sort();
        let act_hash = sha256_hex(
            &serde_json::to_vec(&sorted_actions).unwrap_or_default(),
        );
        let pjh = parent_jti.map(|p| sha256_hex(p.as_bytes()));

        let mut entry = TransparencyLogEntry {
            entry_id: new_uuid_hex(),
            event_type: event_type.to_string(),
            jti: jti.map(|s| s.to_string()),
            kid: kid.map(|s| s.to_string()),
            issuer_id: issuer_id.to_string(),
            sub_hash,
            aud_hash,
            actions_hash: act_hash,
            timestamp: now_f64(),
            delegation_depth,
            parent_jti_hash: pjh,
            entry_hash: String::new(),
            chain_hash: String::new(),
            entry_signature: Vec::new(),
        };
        entry.entry_hash = compute_entry_hash(&entry);

        let mut last_hash = self.last_hash.lock().unwrap();
        let prev_hash = last_hash.clone();
        entry.chain_hash =
            sha256_hex(format!("{}{}", prev_hash, entry.entry_hash).as_bytes());

        if let Some(sk) = signing_key {
            entry.entry_signature = sk.sign(entry.chain_hash.as_bytes()).to_bytes().to_vec();
        }

        *last_hash = entry.chain_hash.clone();
        let chain_hash = entry.chain_hash.clone();
        self.backend.append(entry);
        chain_hash
    }

    /// Rehash all entries. Returns false if any has been tampered with.
    pub fn verify_chain_integrity(&self) -> bool {
        let entries = self.backend.get_all();
        let mut prev_hash = GENESIS_CHAIN_HASH.to_string();

        for entry in &entries {
            let recomputed = compute_entry_hash(entry);
            if recomputed != entry.entry_hash {
                return false;
            }
            let expected_chain =
                sha256_hex(format!("{}{}", prev_hash, entry.entry_hash).as_bytes());
            if expected_chain != entry.chain_hash {
                return false;
            }
            prev_hash = entry.chain_hash.clone();
        }
        true
    }

    pub fn get_entries_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry> {
        self.backend.get_by_jti(jti)
    }

    pub fn get_entries_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry> {
        self.backend.get_since(timestamp)
    }

    pub fn count(&self) -> usize {
        self.backend.count()
    }

    /// Return an audit bundle (no raw PII — only hashes).
    pub fn export_audit_bundle(&self, since: Option<f64>) -> serde_json::Value {
        let entries = match since {
            Some(ts) => self.backend.get_since(ts),
            None => self.backend.get_all(),
        };
        serde_json::json!({
            "generated_at": now_f64(),
            "entry_count": entries.len(),
            "chain_valid": self.verify_chain_integrity(),
            "entries": entries.iter().map(|e| serde_json::json!({
                "entry_id": e.entry_id,
                "event_type": e.event_type,
                "jti": e.jti,
                "kid": e.kid,
                "issuer_id": e.issuer_id,
                "timestamp": e.timestamp,
                "depth": e.delegation_depth,
                "entry_hash": e.entry_hash,
                "chain_hash": e.chain_hash,
            })).collect::<Vec<_>>(),
        })
    }
}

impl Default for CapabilityTransparencyLog {
    fn default() -> Self {
        Self::new()
    }
}

// ─── RiskAwareAuthorizationEvaluator ────────────────────────────────────────────

/// Context for risk evaluation.
#[derive(Debug, Clone)]
pub struct AuthorizationContext {
    pub requesting_agent: String,
    pub target_agent: String,
    pub session_trust_level: String,
    pub requested_action_class: u8,
    pub delegation_depth: usize,
    pub issuer_reputation_score: f64,
    pub capability_age_seconds: f64,
    pub behavioral_anomaly_flag: bool,
    pub prior_violation_count: u32,
    pub is_high_risk_operation: bool,
}

/// Result of a risk evaluation.
#[derive(Debug, Clone)]
pub struct RiskEvaluation {
    pub risk_score: f64,
    pub decision: String,
    pub factors: Vec<String>,
    pub requires_threshold: bool,
    pub requires_human_approval: bool,
}

/// Default risk policy with configurable thresholds.
pub struct DefaultPolicy {
    approve_threshold: f64,
    escalate_threshold: f64,
}

impl DefaultPolicy {
    pub fn new(approve_threshold: f64, escalate_threshold: f64) -> Self {
        Self {
            approve_threshold,
            escalate_threshold,
        }
    }

    pub fn evaluate(&self, ctx: &AuthorizationContext) -> RiskEvaluation {
        let mut score: f64 = 0.0;
        let mut factors: Vec<String> = Vec::new();

        if ctx.behavioral_anomaly_flag {
            score += 0.40;
            factors.push("Behavioral anomaly detected (+0.40)".to_string());
        }
        if ctx.session_trust_level == "minimal" {
            score += 0.20;
            factors.push("Minimal session trust level (+0.20)".to_string());
        } else if ctx.session_trust_level == "partial" {
            score += 0.10;
            factors.push("Partial session trust level (+0.10)".to_string());
        }
        if ctx.delegation_depth > 6 {
            score += 0.10;
            factors.push(format!(
                "Very high delegation depth {} (+0.10)",
                ctx.delegation_depth
            ));
        } else if ctx.delegation_depth > 3 {
            score += 0.15;
            factors.push(format!(
                "High delegation depth {} (+0.15)",
                ctx.delegation_depth
            ));
        }
        if ctx.capability_age_seconds > 240.0 {
            score += 0.10;
            factors.push(format!(
                "Old capability ({:.0}s) (+0.10)",
                ctx.capability_age_seconds
            ));
        }
        if ctx.requested_action_class == 2 {
            score += 0.15;
            factors.push("IRREVERSIBLE action class (+0.15)".to_string());
        }
        if ctx.prior_violation_count >= 3 {
            score += 0.20;
            factors.push(format!(
                "{} prior violations (+0.20)",
                ctx.prior_violation_count
            ));
        }
        if ctx.issuer_reputation_score < 0.5 {
            score += 0.15;
            factors.push(format!(
                "Low issuer reputation {:.2} (+0.15)",
                ctx.issuer_reputation_score
            ));
        }
        if ctx.is_high_risk_operation {
            score += 0.10;
            factors.push("High-risk operation flag (+0.10)".to_string());
        }

        score = score.min(1.0);

        let decision = if score >= self.escalate_threshold {
            "REJECT"
        } else if score >= self.approve_threshold {
            "ESCALATE"
        } else {
            "APPROVE"
        };

        let requires_threshold =
            decision == "ESCALATE" && ctx.is_high_risk_operation;
        let requires_human = score >= self.escalate_threshold;

        RiskEvaluation {
            risk_score: (score * 10000.0).round() / 10000.0,
            decision: decision.to_string(),
            factors,
            requires_threshold,
            requires_human_approval: requires_human,
        }
    }
}

impl Default for DefaultPolicy {
    fn default() -> Self {
        Self::new(0.30, 0.65)
    }
}

/// Computes risk score and authorization decision.
pub struct RiskAwareAuthorizationEvaluator {
    policy: Box<dyn Fn(&AuthorizationContext) -> RiskEvaluation + Send + Sync>,
}

impl RiskAwareAuthorizationEvaluator {
    pub fn new() -> Self {
        let default_policy = DefaultPolicy::default();
        Self {
            policy: Box::new(move |ctx| default_policy.evaluate(ctx)),
        }
    }

    pub fn with_policy(
        approve_threshold: f64,
        escalate_threshold: f64,
    ) -> Self {
        let policy = DefaultPolicy::new(approve_threshold, escalate_threshold);
        Self {
            policy: Box::new(move |ctx| policy.evaluate(ctx)),
        }
    }

    pub fn evaluate(&self, ctx: &AuthorizationContext) -> RiskEvaluation {
        (self.policy)(ctx)
    }
}

impl Default for RiskAwareAuthorizationEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

// ─── PostCompromiseRecovery ─────────────────────────────────────────────────────

/// Report from a key compromise recovery operation.
#[derive(Debug, Clone)]
pub struct CompromiseRecoveryReport {
    pub compromised_kid: String,
    pub replacement_kid: String,
    pub affected_token_count: usize,
    pub revoked_jti_list: Vec<String>,
    pub recovery_timestamp: f64,
    pub recovery_complete: bool,
}

/// Orchestrates key-compromise recovery.
pub struct PostCompromiseRecovery;

impl PostCompromiseRecovery {
    /// Return JTIs of all tokens issued by the given kid.
    pub fn get_affected_tokens(
        kid: &str,
        transparency_log: &CapabilityTransparencyLog,
    ) -> Vec<String> {
        transparency_log
            .backend
            .get_all()
            .into_iter()
            .filter(|e| {
                e.kid.as_deref() == Some(kid)
                    && e.jti.is_some()
                    && (e.event_type == "ISSUED" || e.event_type == "DELEGATED")
            })
            .filter_map(|e| e.jti)
            .collect()
    }

    /// Validate that a recovery report indicates complete recovery.
    pub fn validate_recovery_complete(report: &CompromiseRecoveryReport) -> bool {
        report.recovery_complete && report.replacement_kid != report.compromised_kid
    }

    /// Declare a key as compromised, revoke affected tokens, log events.
    pub fn declare_key_compromise(
        kid: &str,
        replacement_kid: &str,
        replacement_issuer_id: &str,
        verification_authority: &CapabilityVerificationAuthority,
        transparency_log: &CapabilityTransparencyLog,
    ) -> CompromiseRecoveryReport {
        // Step 1: Revoke the compromised key in verification authority
        verification_authority.revoke_trusted_key(kid);

        // Step 2: Find affected JTIs
        let affected_jtis = Self::get_affected_tokens(kid, transparency_log);

        // Step 3: Log compromise event
        transparency_log.append(
            "KEY_COMPROMISED",
            replacement_issuer_id,
            None,
            Some(kid),
            "",
            &[],
            &[],
            0,
            None,
            None,
        );

        // Step 4: Log key rotation
        transparency_log.append(
            "KEY_ROTATED",
            replacement_issuer_id,
            None,
            Some(replacement_kid),
            "",
            &[],
            &[],
            0,
            None,
            None,
        );

        CompromiseRecoveryReport {
            compromised_kid: kid.to_string(),
            replacement_kid: replacement_kid.to_string(),
            affected_token_count: affected_jtis.len(),
            revoked_jti_list: affected_jtis,
            recovery_timestamp: now_f64(),
            recovery_complete: true,
        }
    }
}

// ─── ThresholdNotReached ────────────────────────────────────────────────────────
// Python: class ThresholdNotReached(Exception): pass
// Raised by assemble_threshold_token() when M approvals have not been collected.

/// Error raised when fewer than M approvals exist in a threshold token.
#[derive(Debug, Clone)]
pub struct ThresholdNotReached {
    pub message: String,
}

impl ThresholdNotReached {
    pub fn new(msg: impl Into<String>) -> Self {
        Self { message: msg.into() }
    }
}

impl std::fmt::Display for ThresholdNotReached {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ThresholdNotReached: {}", self.message)
    }
}

impl std::error::Error for ThresholdNotReached {}

// ─── TransparencyLogBackend ─────────────────────────────────────────────────────
// Python: class TransparencyLogBackend(abc.ABC)  — persistence abstraction.

/// Persistence abstraction for the CapabilityTransparencyLog.
///
/// Implementations:
///   - [`InMemoryBackend`]  — default; development and testing.
///   - [`FilesystemBackend`] — JSONL file-based stub for production.
pub trait TransparencyLogBackend: Send + Sync {
    fn append(&self, entry: &TransparencyLogEntry);
    fn get_all(&self) -> Vec<TransparencyLogEntry>;
    fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry>;
    fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry>;
    fn count(&self) -> usize;
    fn clear(&self);
}

// ─── FilesystemBackend ──────────────────────────────────────────────────────────
// Python: class FilesystemBackend(TransparencyLogBackend) — JSONL stub.
// Full disk I/O is stubbed; uses InMemoryBackend as mirror (protocol v0.1-beta2).

/// File-based transparency log backend stub.
///
/// Writes one JSON line per entry to a log file (JSONL format).
/// Full implementation deferred to a future protocol version.
/// Uses an in-memory mirror for reads.
pub struct FilesystemBackend {
    path: String,
    mirror: InMemoryBackend,
}

impl FilesystemBackend {
    /// Create a new `FilesystemBackend` writing to `path`.
    pub fn new(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            mirror: InMemoryBackend::new(),
        }
    }

    /// Return the configured log file path.
    pub fn path(&self) -> &str {
        &self.path
    }
}

impl TransparencyLogBackend for FilesystemBackend {
    fn append(&self, entry: &TransparencyLogEntry) {
        // Clone so InMemoryBackend's owned-value append works
        let mut guard = self.mirror.entries.lock().unwrap();
        guard.push(entry.clone());
        // TODO: write to self.path as JSONL (future protocol version)
    }

    fn get_all(&self) -> Vec<TransparencyLogEntry> {
        self.mirror.get_all()
    }

    fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry> {
        self.mirror.get_by_jti(jti)
    }

    fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry> {
        self.mirror.get_since(timestamp)
    }

    fn count(&self) -> usize {
        self.mirror.count()
    }

    fn clear(&self) {
        self.mirror.clear();
    }
}

// Implement TransparencyLogBackend for InMemoryBackend too (for dyn dispatch)
impl TransparencyLogBackend for InMemoryBackend {
    fn append(&self, entry: &TransparencyLogEntry) {
        let mut entries = self.entries.lock().unwrap();
        entries.push(entry.clone());
    }

    fn get_all(&self) -> Vec<TransparencyLogEntry> {
        self.entries.lock().unwrap().clone()
    }

    fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.jti.as_deref() == Some(jti))
            .cloned()
            .collect()
    }

    fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .cloned()
            .collect()
    }

    fn count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }

    fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }
}

// ─── AuthorizationPolicy ────────────────────────────────────────────────────────
// Python: class AuthorizationPolicy(abc.ABC) — pluggable evaluation strategy.

/// Pluggable authorization policy evaluated by [`RiskAwareAuthorizationEvaluator`].
///
/// Implement this trait to define custom risk scoring and approval logic.
pub trait AuthorizationPolicy: Send + Sync {
    /// Evaluate the authorization context and return a risk score (0.0–1.0).
    /// A score >= the evaluator's threshold blocks the request.
    fn evaluate(&self, ctx: &AuthorizationContext) -> RiskEvaluation;
}

/// The default built-in authorization policy.
///
/// Uses action_class + delegation_depth as heuristic risk signals.
pub struct DefaultAuthorizationPolicy;

impl AuthorizationPolicy for DefaultAuthorizationPolicy {
    fn evaluate(&self, ctx: &AuthorizationContext) -> RiskEvaluation {
        // Mirror DefaultPolicy logic using correct Rust struct field names
        let mut score = 0.0_f64;
        let mut factors: Vec<String> = Vec::new();
        if ctx.requested_action_class > 1 {
            score += 0.3;
            factors.push(format!("action_class={}", ctx.requested_action_class));
        }
        if ctx.delegation_depth > 3 {
            score += 0.2;
            factors.push(format!("delegation_depth={}", ctx.delegation_depth));
        }
        if ctx.delegation_depth > 6 {
            score += 0.3;
            factors.push("deep_delegation_chain".to_string());
        }
        let score = score.min(1.0);
        let decision = if score >= 0.7 {
            "DENY".to_string()
        } else {
            "APPROVE".to_string()
        };
        RiskEvaluation {
            risk_score: score,
            decision,
            factors,
            requires_threshold: score >= 0.5,
            requires_human_approval: score >= 0.7,
        }
    }
}
