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

use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
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

/// Maximum tracked proposals before a stale-entry sweep runs. IoT /
/// low-resource fix: `create_request()` previously grew `requests` unbounded
/// if a caller never called `submit_partial_approval()`/
/// `purge_expired_requests()` — one permanent entry per request ever created.
/// Mirrors the sweep-on-overflow idiom already used in `cscs.rs`/`gateway.rs`/
/// `trust_decay.rs`: only sweeps once the cap is exceeded.
pub const FACTF_MAX_TRACKED_REQUESTS: usize = 10_000;

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
    /// Opt-in cryptographic verification of every submitted approval, matching
    /// this crate's `register_*` convention (e.g. `ZeroTrustGateway::
    /// register_capability_authority`). When `Some`, `submit_partial_approval`
    /// rejects any approval whose signature is not a valid Ed25519 signature by
    /// the submitting authority's key over the proposal's canonical
    /// `base_claims` bytes — the same bytes and rule `verify_threshold_token`
    /// enforces, so submit → assemble → verify compose. When `None` (default),
    /// only the structural non-zero-signature check runs, preserving the
    /// original behavior for callers that verify the assembled token themselves
    /// via `verify_threshold_token`.
    verification_authority: Mutex<Option<std::sync::Arc<CapabilityVerificationAuthority>>>,
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
            verification_authority: Mutex::new(None),
        })
    }

    /// Enable cryptographic verification of every submitted approval against the
    /// proposal's `base_claims` using `ca`'s registered per-`kid` verifying keys.
    /// Opt-in (see [`ThresholdAuthorityIssuer::verification_authority`]); once
    /// set, a forged or wrong-payload approval is rejected at
    /// [`ThresholdAuthorityIssuer::submit_partial_approval`] time rather than
    /// being allowed into the proposal to be caught only later by
    /// [`ThresholdAuthorityIssuer::verify_threshold_token`].
    pub fn register_verification_authority(&self, ca: std::sync::Arc<CapabilityVerificationAuthority>) {
        *self.verification_authority.lock().unwrap_or_else(|e| e.into_inner()) = Some(ca);
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

        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        // IoT / low-resource fix: sweep once the cap is exceeded — expired
        // proposals first, then oldest-created as a fallback if the map is
        // still full (mirrors the two-pass idiom in trust_decay.rs).
        if requests.len() >= FACTF_MAX_TRACKED_REQUESTS {
            requests.retain(|_, s| now <= s.expires_at);
            if requests.len() >= FACTF_MAX_TRACKED_REQUESTS {
                let evict_count = requests.len() + 1 - FACTF_MAX_TRACKED_REQUESTS;
                let mut by_age: Vec<(String, f64)> = requests.iter()
                    .map(|(k, s)| (k.clone(), s.created_at))
                    .collect();
                by_age.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
                for (k, _) in by_age.into_iter().take(evict_count) {
                    requests.remove(&k);
                }
            }
        }

        requests.insert(request_id.clone(), state);
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

        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let state = requests.get_mut(request_id).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::AcsvafThresholdNotReached,
                format!("FACTF: Unknown request_id '{}'.", request_id),
            )
        })?;

        // Reject expired proposals
        if now_f64() > state.expires_at {
            drop(requests);
            self.requests.lock().unwrap_or_else(|e| e.into_inner()).remove(request_id);
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

        // Opt-in cryptographic verification: when a CVA is registered, this
        // approval must carry a valid Ed25519 signature by the submitting
        // authority's key over the proposal's canonical `base_claims` bytes —
        // the exact bytes and rule `verify_threshold_token` enforces. Without
        // this, the only prior gate was "signature is not all-zero", so a
        // whitelisted authority could submit M structurally-non-zero but forged
        // (or wrong-payload) signatures and `assemble_threshold_token` would
        // package them into a token that a caller who forgot to call
        // `verify_threshold_token` would trust. Fail-closed: a registered CVA
        // that lacks this kid's key rejects the approval.
        {
            let ca_opt = self.verification_authority
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone();
            if let Some(ca) = ca_opt {
                let claims_bytes = serde_json::to_vec(&state.base_claims).unwrap_or_default();
                let kid = token.kid();
                let key = ca.get_verification_key(&kid).ok_or_else(|| {
                    SAACPHardDrop::new(
                        SAACPBytecodes::AcsvafKeyNotTrusted,
                        format!("FACTF: no verification key registered for kid '{}'.", kid),
                    )
                })?;
                if !DelegationChainValidator::verify_ed25519(&key, &claims_bytes, &token.signature) {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::InvalidSignature,
                        format!(
                            "FACTF: approval from '{}' is not a valid signature over the \
                             proposal's base_claims.",
                            issuer_id
                        ),
                    ));
                }
            }
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
        let requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
        let state = requests
            .get(request_id)
            .ok_or_else(|| format!("FACTF: Unknown request_id '{}'.", request_id))?;

        if now_f64() > state.expires_at {
            drop(requests);
            self.requests.lock().unwrap_or_else(|e| e.into_inner()).remove(request_id);
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
        let mut requests = self.requests.lock().unwrap_or_else(|e| e.into_inner());
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
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|s| now <= s.expires_at)
            .count()
    }

    /// Verify a threshold token — requires >= M distinct valid signatures,
    /// where M is *this issuer's own configured threshold* (`self.m`), and
    /// every signature MUST be over the token's shared `base_claims`.
    ///
    /// CRIT-3 fix: the pass/fail bar is `self.m`, never the token's
    /// self-declared `threshold_m` field. `threshold_m` on the wire is
    /// informational only — an attacker who controls the token cannot lower
    /// the effective threshold by setting `threshold_m` to a smaller value.
    ///
    /// CRIT-4 fix: every `ThresholdSignatureEntry` is verified against the
    /// single canonical `base_claims` bytes computed once up front.
    /// `entry.claims_bytes_hex` is never consulted for the verification
    /// decision (it remains on the wire struct for backward wire-format
    /// compatibility only) — this prevents an attacker from packaging M
    /// signatures that were each made over a *different* payload and passing
    /// them off as one M-of-N consensus over `base_claims`.
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

            // CRIT-4: always verify against the shared base_claims. Never
            // trust entry.claims_bytes_hex as an alternate signed payload.
            if DelegationChainValidator::verify_ed25519(
                &key,
                &claims_bytes,
                &sig,
            ) {
                valid_count += 1;
            }
        }

        // CRIT-3: compare against the issuer's own configured threshold,
        // never the token's self-declared threshold_m.
        valid_count >= self.m
    }
}

// ─── Transparency Log ───────────────────────────────────────────────────────────

/// A single entry in the transparency log.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    #[serde(with = "entry_signature_b64")]
    pub entry_signature: Vec<u8>,
}

/// Base64-armors `TransparencyLogEntry::entry_signature` for JSONL persistence
/// (mirroring the `B64` engine already used for wire encoding in `faitf.rs`)
/// so each on-disk line stays a compact, human-diffable JSON object rather
/// than a raw JSON byte-array.
mod entry_signature_b64 {
    use super::B64;
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        B64.encode(bytes).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(d)?;
        B64.decode(encoded.as_bytes()).map_err(serde::de::Error::custom)
    }
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

/// Maximum entries retained by [`InMemoryBackend`] before oldest-first
/// eviction kicks in (H-26). Without this the log — append-only, one entry
/// per capability issuance/delegation/revocation event — grows without
/// bound for the lifetime of the process, an unbounded-memory-growth DoS
/// surface on any long-lived gateway.
pub const TRANSPARENCY_LOG_MAX_ENTRIES: usize = 100_000;

/// Thread-safe in-memory transparency log backend.
///
/// Bounded at [`TRANSPARENCY_LOG_MAX_ENTRIES`]: once at capacity, the oldest
/// entry is evicted before the new one is appended (H-26). [`Self::append`]
/// returns the evicted entry, if any, so a hash-chained caller (see
/// [`CapabilityTransparencyLog`]) can re-anchor its integrity-verification
/// starting point instead of silently treating "the log rolled over" as "the
/// log was tampered with".
pub struct InMemoryBackend {
    entries: Mutex<std::collections::VecDeque<TransparencyLogEntry>>,
    max_entries: usize,
}

impl InMemoryBackend {
    pub fn new() -> Self {
        Self::with_capacity(TRANSPARENCY_LOG_MAX_ENTRIES)
    }

    /// Like [`Self::new`], with a custom capacity — primarily for tests that
    /// need to exercise the eviction path without appending 100K entries.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            entries: Mutex::new(std::collections::VecDeque::new()),
            max_entries,
        }
    }

    /// Appends `entry`, evicting the oldest entry first if already at
    /// capacity. Returns the evicted entry, if one was removed.
    pub fn append(&self, entry: TransparencyLogEntry) -> Option<TransparencyLogEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut entries = self.entries.lock().unwrap();
        let evicted = if entries.len() >= self.max_entries {
            entries.pop_front()
        } else {
            None
        };
        entries.push_back(entry);
        evicted
    }

    pub fn get_all(&self) -> Vec<TransparencyLogEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries.lock().unwrap().iter().cloned().collect()
    }

    pub fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.jti.as_deref() == Some(jti))
            .cloned()
            .collect()
    }

    pub fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .cloned()
            .collect()
    }

    pub fn count(&self) -> usize {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries.lock().unwrap().len()
    }

    pub fn clear(&self) {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
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
    backend: Box<dyn TransparencyLogBackend>,
    last_hash: Mutex<String>,
    /// Chain-hash to treat as the verification starting point, in place of
    /// `GENESIS_CHAIN_HASH`. Starts at `GENESIS_CHAIN_HASH` and advances to
    /// the `chain_hash` of the most recently evicted entry whenever the
    /// bounded `backend` prunes the oldest retained entry (H-26) — this
    /// keeps [`Self::verify_chain_integrity`] exact over the retained window
    /// instead of failing closed on every rollover.
    chain_floor_hash: Mutex<String>,
    /// Count of entries evicted over this log's lifetime, for audit-bundle
    /// honesty about how many events predate the currently retained window.
    pruned_count: std::sync::atomic::AtomicU64,
    /// M-30 fix: monotonically incremented by every `append()` call — the
    /// ONLY method that mutates chain-relevant state (`last_hash`,
    /// `chain_floor_hash`, and the backend's entry set). Paired with
    /// `cached_verification` below to avoid re-hashing every retained entry
    /// on every `verify_chain_integrity()` call when nothing has changed
    /// since the last one. Deliberately NOT `self.backend.count()` /
    /// `entries.len()`: once the backend is at capacity, every `append()`
    /// evicts exactly one entry while adding one, so entry COUNT stays
    /// constant across appends even though the chain's actual content
    /// (and `chain_floor_hash`) genuinely changes — count alone would be a
    /// silently-wrong staleness signal under sustained at-capacity load.
    generation: std::sync::atomic::AtomicU64,
    /// M-30 fix: `(generation, result)` from the most recent
    /// `verify_chain_integrity()` call. Invalidated (recomputed) whenever
    /// `generation` has advanced since this was cached.
    cached_verification: Mutex<Option<(u64, bool)>>,
}

impl CapabilityTransparencyLog {
    pub fn new() -> Self {
        Self::with_capacity(TRANSPARENCY_LOG_MAX_ENTRIES)
    }

    /// Like [`Self::new`], with a custom entry cap — primarily for tests that
    /// need to exercise the H-26 eviction/re-anchoring path without
    /// appending 100K entries.
    pub fn with_capacity(max_entries: usize) -> Self {
        Self {
            backend: Box::new(InMemoryBackend::with_capacity(max_entries)),
            last_hash: Mutex::new(GENESIS_CHAIN_HASH.to_string()),
            chain_floor_hash: Mutex::new(GENESIS_CHAIN_HASH.to_string()),
            pruned_count: std::sync::atomic::AtomicU64::new(0),
            generation: std::sync::atomic::AtomicU64::new(0),
            cached_verification: Mutex::new(None),
        }
    }

    /// Construct a `CapabilityTransparencyLog` backed by any
    /// [`TransparencyLogBackend`] implementation — e.g. a [`FilesystemBackend`]
    /// opened at startup for durable, disk-persisted transparency logging.
    /// `new()`/`with_capacity()` keep defaulting to `InMemoryBackend` so
    /// existing callers/tests are unaffected.
    ///
    /// If `backend` already holds replayed entries (e.g. a `FilesystemBackend`
    /// reopened against an existing JSONL file), `last_hash` is seeded from
    /// the most recent entry's `chain_hash` so subsequent appends continue
    /// the persisted chain rather than restarting it from genesis.
    /// `chain_floor_hash` stays at `GENESIS_CHAIN_HASH`: `FilesystemBackend::open`
    /// only accepts a file whose retained entries already verify unbroken
    /// from genesis (see its replay loop), so genesis is the correct floor
    /// for any backend constructed that way.
    pub fn with_backend(backend: Box<dyn TransparencyLogBackend>) -> Self {
        let seeded_last_hash = backend
            .get_all()
            .last()
            .map(|e| e.chain_hash.clone())
            .unwrap_or_else(|| GENESIS_CHAIN_HASH.to_string());
        Self {
            backend,
            last_hash: Mutex::new(seeded_last_hash),
            chain_floor_hash: Mutex::new(GENESIS_CHAIN_HASH.to_string()),
            pruned_count: std::sync::atomic::AtomicU64::new(0),
            generation: std::sync::atomic::AtomicU64::new(0),
            cached_verification: Mutex::new(None),
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

        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut last_hash = self.last_hash.lock().unwrap();
        let prev_hash = last_hash.clone();
        entry.chain_hash =
            sha256_hex(format!("{}{}", prev_hash, entry.entry_hash).as_bytes());

        if let Some(sk) = signing_key {
            entry.entry_signature = sk.sign(entry.chain_hash.as_bytes()).to_bytes().to_vec();
        }

        *last_hash = entry.chain_hash.clone();
        let chain_hash = entry.chain_hash.clone();
        drop(last_hash);

        // H-26: the backend is capacity-bounded and evicts oldest-first.
        // When it does, re-anchor the integrity-verification floor to the
        // evicted entry's own chain_hash so `verify_chain_integrity` keeps
        // verifying exactly the retained window rather than failing closed
        // against a genesis hash that no longer matches the oldest surviving
        // entry.
        if let Some(evicted) = self.backend.append(&entry) {
            // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
            *self.chain_floor_hash.lock().unwrap() = evicted.chain_hash;
            self.pruned_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        // M-30 fix: this is the only method that changes chain-relevant
        // state, so it is the only place `generation` needs to advance —
        // any `verify_chain_integrity()` cached against an earlier
        // generation is now correctly treated as stale.
        self.generation.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        chain_hash
    }

    /// Rehash all currently-retained entries. Returns false if any has been
    /// tampered with. Verification starts from [`Self::chain_floor_hash`]
    /// rather than the fixed genesis constant, so entries legitimately aged
    /// out by the bounded backend's oldest-first eviction (H-26) are not
    /// mistaken for tampering.
    ///
    /// M-30 fix: the O(n) rehash below only actually runs when `generation`
    /// (bumped by every `append()`) has advanced since the last call —
    /// otherwise this returns the cached result from that last call
    /// immediately. Safe because `append()` is the ONLY method that can
    /// change what this function would compute.
    ///
    /// The generation used as the cache key is captured BEFORE reading
    /// `backend`/`chain_floor_hash` below, not after computing the result.
    /// This matters under concurrent `append()` calls: if this method
    /// captured `generation` only after finishing its (potentially
    /// expensive) rehash, a concurrent `append()` landing mid-rehash could
    /// make this call observe a torn snapshot (some backend/floor state
    /// from before the append, read after `generation` had already
    /// advanced) and then cache that torn result keyed under the NEW
    /// (post-append) generation — a later call reading that same new
    /// generation would then wrongly trust a result that never actually
    /// corresponded to it. Keying under the PRE-computation generation
    /// avoids this: `generation` only ever increases, so once a concurrent
    /// `append()` has advanced it, no future call will ever match this
    /// (now-stale) cache entry again — it is naturally superseded rather
    /// than incorrectly trusted. The (rare, same as this method's
    /// pre-existing behavior with no cache at all) worst case under a
    /// genuinely concurrent append is a single torn read on the racing
    /// call itself, exactly as uncached `verify_chain_integrity` already
    /// tolerated — this fix does not make that pre-existing race any worse.
    pub fn verify_chain_integrity(&self) -> bool {
        let generation_at_start = self.generation.load(std::sync::atomic::Ordering::Relaxed);
        {
            // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
            let cached = self.cached_verification.lock().unwrap();
            if let Some((gen, result)) = *cached {
                if gen == generation_at_start {
                    return result;
                }
            }
        }

        let entries = self.backend.get_all();
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        let mut prev_hash = self.chain_floor_hash.lock().unwrap().clone();
        let mut result = true;

        for entry in &entries {
            let recomputed = compute_entry_hash(entry);
            if recomputed != entry.entry_hash {
                result = false;
                break;
            }
            let expected_chain =
                sha256_hex(format!("{}{}", prev_hash, entry.entry_hash).as_bytes());
            if expected_chain != entry.chain_hash {
                result = false;
                break;
            }
            prev_hash = entry.chain_hash.clone();
        }

        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        *self.cached_verification.lock().unwrap() = Some((generation_at_start, result));
        result
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

    /// Number of entries evicted over this log's lifetime by the bounded
    /// backend's oldest-first eviction (H-26). `count() + pruned_count()` is
    /// the total number of events ever appended.
    pub fn pruned_count(&self) -> u64 {
        self.pruned_count.load(std::sync::atomic::Ordering::Relaxed)
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
            "pruned_count": self.pruned_count(),
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

/// L-26 fix: per-factor scoring weights for [`DefaultPolicy::evaluate`]. Previously
/// every weight was a compile-time literal identical across every deployment of this
/// open-source crate — an adversary could precompute the exact score any crafted
/// `AuthorizationContext` produces and craft requests staying just under
/// `escalate_threshold`. Extracting them here lets an operator set deployment-specific,
/// externally-unknown values via [`DefaultPolicy::with_weights`] while `Default`
/// reproduces the exact prior literals, so `DefaultPolicy::default()`/`::new()` behave
/// identically to before this fix.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct PolicyWeights {
    pub behavioral_anomaly: f64,
    pub minimal_trust: f64,
    pub partial_trust: f64,
    pub very_high_delegation_depth: f64,
    pub high_delegation_depth: f64,
    pub old_capability: f64,
    pub irreversible_action: f64,
    pub prior_violations: f64,
    pub low_issuer_reputation: f64,
    pub high_risk_operation: f64,
}

impl Default for PolicyWeights {
    fn default() -> Self {
        Self {
            behavioral_anomaly: 0.40,
            minimal_trust: 0.20,
            partial_trust: 0.10,
            very_high_delegation_depth: 0.10,
            high_delegation_depth: 0.15,
            old_capability: 0.10,
            irreversible_action: 0.15,
            prior_violations: 0.20,
            low_issuer_reputation: 0.15,
            high_risk_operation: 0.10,
        }
    }
}

/// Default risk policy with configurable thresholds.
pub struct DefaultPolicy {
    approve_threshold: f64,
    escalate_threshold: f64,
    weights: PolicyWeights,
}

impl DefaultPolicy {
    pub fn new(approve_threshold: f64, escalate_threshold: f64) -> Self {
        Self::with_weights(approve_threshold, escalate_threshold, PolicyWeights::default())
    }

    /// L-26 fix: same as [`Self::new`] but with deployment-specific scoring weights
    /// instead of this policy's compiled-in defaults.
    pub fn with_weights(approve_threshold: f64, escalate_threshold: f64, weights: PolicyWeights) -> Self {
        Self {
            approve_threshold,
            escalate_threshold,
            weights,
        }
    }

    pub fn evaluate(&self, ctx: &AuthorizationContext) -> RiskEvaluation {
        let mut score: f64 = 0.0;
        let mut factors: Vec<String> = Vec::new();

        let w = &self.weights;
        if ctx.behavioral_anomaly_flag {
            score += w.behavioral_anomaly;
            factors.push(format!("Behavioral anomaly detected (+{:.2})", w.behavioral_anomaly));
        }
        if ctx.session_trust_level == "minimal" {
            score += w.minimal_trust;
            factors.push(format!("Minimal session trust level (+{:.2})", w.minimal_trust));
        } else if ctx.session_trust_level == "partial" {
            score += w.partial_trust;
            factors.push(format!("Partial session trust level (+{:.2})", w.partial_trust));
        }
        if ctx.delegation_depth > 6 {
            score += w.very_high_delegation_depth;
            factors.push(format!(
                "Very high delegation depth {} (+{:.2})",
                ctx.delegation_depth, w.very_high_delegation_depth
            ));
        } else if ctx.delegation_depth > 3 {
            score += w.high_delegation_depth;
            factors.push(format!(
                "High delegation depth {} (+{:.2})",
                ctx.delegation_depth, w.high_delegation_depth
            ));
        }
        if ctx.capability_age_seconds > 240.0 {
            score += w.old_capability;
            factors.push(format!(
                "Old capability ({:.0}s) (+{:.2})",
                ctx.capability_age_seconds, w.old_capability
            ));
        }
        if ctx.requested_action_class == 2 {
            score += w.irreversible_action;
            factors.push(format!("IRREVERSIBLE action class (+{:.2})", w.irreversible_action));
        }
        if ctx.prior_violation_count >= 3 {
            score += w.prior_violations;
            factors.push(format!(
                "{} prior violations (+{:.2})",
                ctx.prior_violation_count, w.prior_violations
            ));
        }
        if ctx.issuer_reputation_score < 0.5 {
            score += w.low_issuer_reputation;
            factors.push(format!(
                "Low issuer reputation {:.2} (+{:.2})",
                ctx.issuer_reputation_score, w.low_issuer_reputation
            ));
        }
        if ctx.is_high_risk_operation {
            score += w.high_risk_operation;
            factors.push(format!("High-risk operation flag (+{:.2})", w.high_risk_operation));
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
///   - [`FilesystemBackend`] — durable JSONL file-based backend for production.
pub trait TransparencyLogBackend: Send + Sync {
    /// Append `entry`, returning the evicted entry if the backend is bounded
    /// and already at capacity (mirrors `InMemoryBackend::append`'s H-26
    /// eviction contract) so a hash-chained caller can re-anchor its
    /// integrity-verification floor instead of treating a rollover as
    /// tampering.
    fn append(&self, entry: &TransparencyLogEntry) -> Option<TransparencyLogEntry>;
    fn get_all(&self) -> Vec<TransparencyLogEntry>;
    fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry>;
    fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry>;
    fn count(&self) -> usize;
    fn clear(&self);
}

// ─── FilesystemBackend ──────────────────────────────────────────────────────────
// Python: class FilesystemBackend(TransparencyLogBackend) — durable JSONL backend.

/// Maximum size, in bytes, a `FilesystemBackend`'s JSONL file may reach before
/// it is rotated to `{path}.{epoch}.bak` — mirrors `security::AUDIT_MAX_LOG_SIZE`'s
/// rotation contract so the transparency log can't grow the disk without bound
/// any more than the audit-log WAL can.
pub const TRANSPARENCY_LOG_MAX_FILE_SIZE: u64 = 50_000_000;

/// File-based transparency log backend.
///
/// Writes one JSON line per entry to a persistent, buffered file handle held
/// for the backend's lifetime (same idiom as `security::WalWriter` — avoids
/// paying an open()+close() syscall cost per event). An in-memory
/// `InMemoryBackend` mirror serves all reads so `get_all`/`get_by_jti`/
/// `get_since` never touch disk. [`Self::open`] replays and verifies the
/// on-disk hash chain at startup, failing closed (returning `Err`, never
/// silently starting from empty) if the file has been tampered with or
/// truncated — Architecture Principle #3, Fail-Closed by Default.
pub struct FilesystemBackend {
    path: String,
    writer: Mutex<FilesystemBackendWriter>,
    mirror: InMemoryBackend,
    max_file_size: u64,
}

struct FilesystemBackendWriter {
    file: std::io::BufWriter<std::fs::File>,
    size: u64,
    /// `chain_hash` of the most recently written entry — persisted to the
    /// `{path}.floor` sidecar on rotation so a subsequent [`FilesystemBackend::open`]
    /// knows the correct starting point to verify the new (post-rotation)
    /// file's chain against, instead of incorrectly expecting it to chain
    /// from `GENESIS_CHAIN_HASH`.
    last_chain_hash: String,
}

/// Sidecar file suffix holding the chain-hash floor for a rotated
/// `FilesystemBackend` log — see `FilesystemBackendWriter::last_chain_hash`.
const CHAIN_FLOOR_SUFFIX: &str = ".floor";

/// Error returned by [`FilesystemBackend::open`] when the on-disk JSONL file
/// exists but its hash chain does not verify — a truncated, corrupted, or
/// tampered file. The backend refuses to start in this state rather than
/// silently discarding the file and beginning from an empty log.
#[derive(Debug)]
pub struct FilesystemBackendIntegrityError {
    pub message: String,
}

impl std::fmt::Display for FilesystemBackendIntegrityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "FilesystemBackend integrity check failed: {}", self.message)
    }
}

impl std::error::Error for FilesystemBackendIntegrityError {}

impl FilesystemBackend {
    /// Create a new `FilesystemBackend` writing to `path`, replaying and
    /// verifying any existing on-disk JSONL file first.
    ///
    /// # Errors
    /// Returns `Err` if the file can't be opened/read, if a line fails to
    /// deserialize, or if the recomputed hash chain does not match the
    /// persisted `entry_hash`/`chain_hash` values for any entry — this is
    /// fail-closed by design (Architecture Principle #3): a tampered or
    /// truncated transparency log must never be silently treated as an
    /// empty one.
    pub fn open(path: impl Into<String>) -> Result<Self, FilesystemBackendIntegrityError> {
        Self::open_with_max_file_size(path, TRANSPARENCY_LOG_MAX_FILE_SIZE)
    }

    /// Like [`Self::open`], with a custom rotation threshold — primarily for
    /// tests that need to exercise the rotation path without writing 50MB of
    /// entries.
    pub fn open_with_max_file_size(
        path: impl Into<String>,
        max_file_size: u64,
    ) -> Result<Self, FilesystemBackendIntegrityError> {
        let path = path.into();
        let mirror = InMemoryBackend::new();

        // If a prior rotation happened, `{path}.floor` holds the chain_hash
        // that the *active* file's first entry must chain from — this file
        // has no entries of its own to verify from genesis, since they were
        // moved to a `.bak` sibling by `maybe_rotate`.
        let floor_path = format!("{path}{CHAIN_FLOOR_SUFFIX}");
        let mut prev_hash = std::fs::read_to_string(&floor_path)
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| GENESIS_CHAIN_HASH.to_string());

        if let Ok(contents) = std::fs::read_to_string(&path) {
            for (line_no, line) in contents.lines().enumerate() {
                if line.trim().is_empty() {
                    continue;
                }
                let entry: TransparencyLogEntry = serde_json::from_str(line).map_err(|e| {
                    FilesystemBackendIntegrityError {
                        message: format!("line {}: malformed JSON: {e}", line_no + 1),
                    }
                })?;

                let recomputed = compute_entry_hash(&entry);
                if recomputed != entry.entry_hash {
                    return Err(FilesystemBackendIntegrityError {
                        message: format!(
                            "line {}: entry_hash mismatch (entry_id={:?}) — tampering or corruption detected",
                            line_no + 1, entry.entry_id
                        ),
                    });
                }
                let expected_chain =
                    sha256_hex(format!("{}{}", prev_hash, entry.entry_hash).as_bytes());
                if expected_chain != entry.chain_hash {
                    return Err(FilesystemBackendIntegrityError {
                        message: format!(
                            "line {}: chain_hash mismatch (entry_id={:?}) — tampering, truncation, or reordering detected",
                            line_no + 1, entry.entry_id
                        ),
                    });
                }
                prev_hash = entry.chain_hash.clone();
                mirror.append(entry);
            }
        }

        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| FilesystemBackendIntegrityError {
                message: format!("failed to open {path:?} for append: {e}"),
            })?;
        let size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            path,
            writer: Mutex::new(FilesystemBackendWriter {
                file: std::io::BufWriter::with_capacity(64 * 1024, file),
                size,
                last_chain_hash: prev_hash,
            }),
            mirror,
            max_file_size,
        })
    }

    /// Create a new `FilesystemBackend` writing to `path` without replaying
    /// any existing file — panics if the file exists and fails the same
    /// integrity check [`Self::open`] would perform. Prefer [`Self::open`]
    /// in production; this is a convenience for tests/call sites that know
    /// the path is fresh.
    pub fn new(path: impl Into<String>) -> Self {
        let path = path.into();
        Self::open(&path).unwrap_or_else(|e| panic!("{e}"))
    }

    /// Return the configured log file path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Rotate the on-disk file if it has grown past `self.max_file_size` —
    /// same flush+sync+rename-before-reopen ordering as
    /// `security::WalWriter::maybe_rotate` (required on Windows, where a file
    /// can't be renamed while a handle to it is open). Before rotating,
    /// persists `w.last_chain_hash` to the `{path}.floor` sidecar so a
    /// subsequent [`FilesystemBackend::open`] knows the new (empty) active
    /// file's first entry must chain from this hash, not `GENESIS_CHAIN_HASH`
    /// — otherwise a legitimately-rotated log would be misdiagnosed as
    /// tampered on restart.
    fn maybe_rotate(w: &mut FilesystemBackendWriter, path: &str, max_file_size: u64) -> std::io::Result<()> {
        use std::io::Write;
        if w.size <= max_file_size {
            return Ok(());
        }
        w.file.flush()?;
        w.file.get_ref().sync_data()?;
        std::fs::write(format!("{path}{CHAIN_FLOOR_SUFFIX}"), &w.last_chain_hash)?;
        let rotated = format!("{path}.{}.bak", now_f64() as u64);
        let _ = std::fs::rename(path, &rotated);
        let file = std::fs::OpenOptions::new().create(true).append(true).open(path)?;
        w.file = std::io::BufWriter::with_capacity(64 * 1024, file);
        w.size = 0;
        Ok(())
    }
}

impl TransparencyLogBackend for FilesystemBackend {
    fn append(&self, entry: &TransparencyLogEntry) -> Option<TransparencyLogEntry> {
        use std::io::Write;

        let line = serde_json::to_string(entry).unwrap_or_default();
        {
            let mut w = self.writer.lock().unwrap_or_else(|e| e.into_inner());
            if Self::maybe_rotate(&mut w, &self.path, self.max_file_size).is_ok() {
                if writeln!(w.file, "{line}").is_ok() {
                    w.size += line.len() as u64 + 1;
                    w.last_chain_hash = entry.chain_hash.clone();
                }
                let _ = w.file.flush();
                let _ = w.file.get_ref().sync_data();
            }
        }

        // Routed through the mirror's own bounded, capacity-checked append
        // (H-26) rather than a raw push — this dyn-dispatch path must not
        // bypass the same eviction cap the direct `InMemoryBackend` API
        // enforces.
        self.mirror.append(entry.clone())
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
    fn append(&self, entry: &TransparencyLogEntry) -> Option<TransparencyLogEntry> {
        // Delegate to the bounded inherent append (H-26) so this dyn-dispatch
        // path enforces the same capacity cap as the direct API.
        Self::append(self, entry.clone())
    }

    fn get_all(&self) -> Vec<TransparencyLogEntry> {
        Self::get_all(self)
    }

    fn get_by_jti(&self, jti: &str) -> Vec<TransparencyLogEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.jti.as_deref() == Some(jti))
            .cloned()
            .collect()
    }

    fn get_since(&self, timestamp: f64) -> Vec<TransparencyLogEntry> {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.timestamp >= timestamp)
            .cloned()
            .collect()
    }

    fn count(&self) -> usize {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
        self.entries.lock().unwrap().len()
    }

    fn clear(&self) {
        // R-1: intentionally left as unwrap() — poisoned lock here means corrupted security invariant, fail-closed by panicking rather than serving stale/partial state
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
