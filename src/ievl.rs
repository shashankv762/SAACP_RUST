//! ievl.rs — Intent-Execution Verification Loop (Phase 6 / Part 8.1)
//!
//! *New in Rust* — no Python-reference analog.
//!
//! # Why this exists
//!
//! Gate 1.5 (`handler.rs`) already checks that a packet's *declared* task text is
//! consistent with the session's signed root intent — but that check is purely
//! prospective. Nothing in the pipeline ever asks "did the agent actually do what
//! it said it would?" after the fact. An agent (or a compromised one) can pass
//! every gate honestly while declaring an IRREVERSIBLE action, then execute
//! something materially different — a wider blast radius, a different target set,
//! or a more dangerous action class than it declared — with no protocol-level
//! consequence. IEVL closes that gap for the highest-stakes action class by asking
//! for a signed, after-the-fact `ExecutionReceipt` and comparing it against the
//! `IntentDeclaration` captured at Gate 1.5 time.
//!
//! # Architecture — NOT a gate
//!
//! Like [`crate::trust_decay::TrustDecayEngine`], IEVL is deliberately **not** a
//! 13th numbered gate. It is three additive pieces bolted onto the existing
//! pipeline without changing its control flow:
//!
//! 1. A **registration hook** at Gate 1.5 (`handler.rs`, inside the
//!    `root_intent_hash` branch, immediately after the existing intent checks
//!    succeed) — captures an [`IntentDeclaration`] for IRREVERSIBLE-class packets
//!    only (`RECEIPT_REQUIRED_ACTION_CLASS`). Every other action class is a no-op
//!    here: this hook never touches READ_ONLY/REVERSIBLE traffic.
//! 2. A **new inbound message handler** for schema_id=10 (`ExecutionReceipt`,
//!    `schemas.rs`), dispatched from `daemon.rs` *after* the full gate pipeline
//!    has already cleared the receipt packet — mirroring exactly how the
//!    schema_id=11 Gossip Envelope is dispatched post-pipeline in `daemon.rs`
//!    (see `decode_gossip_envelope`'s call site). [`handle_execution_receipt`] is
//!    that handler's entry point.
//! 3. A **background sweep** ([`IevlEngine::start_sweep`]) that turns a declared-
//!    but-never-fulfilled `IntentDeclaration` into a `ReceiptTimeout` penalty once
//!    its TTL elapses — opt-in, matching `gossip::GossipEngine::start_sweep`'s own
//!    "caller decides whether to spawn it" convention.
//!
//! # Enforcement
//!
//! [`VerificationVerdict`] is deliberately finer-grained than pass/fail because
//! the two things a receipt can misreport — *what* was targeted and *how* the
//! action was described — are independent axes, and only some of the ways they
//! can diverge warrant full revocation:
//!
//! - [`VerificationVerdict::ClassEscalation`] — the agent executed something
//!   *more* dangerous than it promised — is Monotonic-Security-critical and
//!   triggers immediate [`crate::faitf::DistributedRevocationInfrastructure::revoke`],
//!   not just a trust penalty (Part 12 principle 9). Detected two ways: (1) the
//!   receipt's own packet-level `action_class` exceeds what was declared —
//!   only reachable if a deployment lowers `RECEIPT_REQUIRED_ACTION_CLASS`
//!   below the protocol's ceiling, since at the documented default
//!   (IRREVERSIBLE only) a declaration already sits at the maximum class; or
//!   (2) `actual_action`'s text names a [`crate::handler::DANGEROUS_ACTION_TERMS`]
//!   verb absent from the declaration — the same denylist Gate 1.5c already
//!   applies prospectively, reused here retrospectively so escalation stays
//!   detectable even when every tracked declaration is already at the
//!   numeric ceiling.
//! - [`VerificationVerdict::TargetViolation`] (target-set Jaccard overlap collapses
//!   below [`TARGET_MINOR_DRIFT_THRESHOLD`]) and
//!   [`VerificationVerdict::MajorDivergence`] (the *described* action itself
//!   diverges that far from what was declared, reusing
//!   `SAACPProtocolHandler::intent_divergence`) both apply
//!   `PenaltyKind::TargetViolation` — real but recoverable evidence, not grounds
//!   for outright revocation.
//! - [`VerificationVerdict::MinorDrift`] (either axis sits between the minor and
//!   full overlap thresholds) is informational only — logged nowhere beyond the
//!   ordinary metrics a passing receipt produces, no trust action, since overlap
//!   this close is plausibly just paraphrasing rather than a real substitution.
//! - [`VerificationVerdict::Consistent`] rewards `RewardKind::ValidReceipt` —
//!   stronger positive evidence than a bare clean pipeline pass, since it proves
//!   post-execution reality matched the declaration (the "IEVL → Trust → Recovery"
//!   loop, Part A.10).
//! - [`VerificationVerdict::ReceiptMissing`] (no declaration matches the receipt's
//!   reference — already swept, or a bogus/forged reference) and
//!   [`VerificationVerdict::SignatureInvalid`] (the receipt's signature does not
//!   verify against the presenting session's bound public key) are both
//!   deliberately inert beyond telemetry: neither can be reliably attributed to
//!   the *declaring* agent's behavior, so neither penalizes trust.
//!
//! # Signature scheme
//!
//! A receipt is signed by the same Ed25519 key the presenting session bound at
//! handshake time (`identity_binding::DEFAULT_IDENTITY_REGISTRY`, exactly as
//! `trust_decay::trust_key_for` already looks it up) over a length-prefixed
//! canonical encoding of its own claimed fields
//! ([`verify_receipt_signature`]/`canonical_receipt_bytes`) — the same
//! length-prefixed-field idiom `identity_binding.rs`'s transcript hash and
//! `faitf.rs`'s `AgentCredential`/`SignedRevocationRecord` body bytes already use,
//! so two fields can never be concatenation-ambiguous with each other.
//!
//! # Declaration IDs need no extra round-trip
//!
//! An `IntentDeclaration` is keyed by [`declaration_id`], a pure function of the
//! declaring packet's own `(session_uuid, sequence_id)` — both values the
//! declaring agent already knows (it sent that packet), so the client can compute
//! the same ID independently when it later sends the matching receipt. No wire
//! message ever needs to hand a declaration ID back to the client.
//!
//! # Bounded memory
//!
//! Sharded (16-way) `Mutex<HashMap>`, same idiom as `trust_decay.rs`. Capacity
//! eviction never drops a declaration for an agent currently below
//! `TRUST_REAUTH_THRESHOLD` — mirroring `trust_decay.rs`'s H-24 protected-eviction
//! precedent, since that is exactly the agent IEVL should be watching most
//! closely. See [`IevlEngine::register_declaration`].

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::handler::{JsonValue, ParsedPacket, SAACPProtocolHandler};
use crate::telemetry::report_gate_rejection;
use crate::trust_decay::{trust_key_for, PenaltyKind, RewardKind, TrustDecayEngine};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// action_class threshold (inclusive) at/above which a declared intent requires
/// a follow-up `ExecutionReceipt`. Matches the IRREVERSIBLE action-class value
/// already used throughout `handler.rs` (e.g. the trust-reward call's
/// `parsed.action_class >= 0x02`).
pub const RECEIPT_REQUIRED_ACTION_CLASS: u8 = 0x02;

/// Wall-clock seconds an `IntentDeclaration` may remain unfulfilled before
/// [`IevlEngine::sweep_expired`] treats it as `ReceiptMissing` and penalizes
/// `PenaltyKind::ReceiptTimeout`.
pub const RECEIPT_TTL_SECONDS: f64 = 60.0;

/// Per-axis (targets / described-action) Jaccard-style overlap at/above which
/// that axis is considered fully consistent.
pub const TARGET_OVERLAP_THRESHOLD: f64 = 0.70;

/// Per-axis overlap below which that axis is a confirmed violation
/// (`TargetViolation`/`MajorDivergence`) rather than mere `MinorDrift`.
pub const TARGET_MINOR_DRIFT_THRESHOLD: f64 = 0.40;

const IEVL_SHARDS: usize = 16;
const IEVL_MAX_ENTRIES: usize = 10_000;
const IEVL_PER_SHARD_MAX_ENTRIES: usize = IEVL_MAX_ENTRIES / IEVL_SHARDS;

fn now_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn ievl_shard_index(key: &str) -> usize {
    (key.as_bytes().first().copied().unwrap_or(0) as usize) % IEVL_SHARDS
}

/// Deterministic declaration ID both the declaring agent and this engine can
/// compute independently — see the module docs' "Declaration IDs need no extra
/// round-trip" section.
pub fn declaration_id(session_uuid: &str, sequence_id: u64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(session_uuid.as_bytes());
    hasher.update(sequence_id.to_be_bytes());
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A declared, not-yet-fulfilled intent for an IRREVERSIBLE-class action,
/// captured at Gate 1.5 registration time. See module docs.
#[derive(Debug, Clone)]
pub struct IntentDeclaration {
    pub declared_action: String,
    pub action_class: u8,
    pub targets: Vec<String>,
    pub agent_id: String,
    pub session_uuid: String,
    pub declared_at: f64,
}

/// The outcome of comparing a submitted `ExecutionReceipt` against its matching
/// `IntentDeclaration`. See the module docs' "Enforcement" section for the
/// consequence each variant carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerificationVerdict {
    Consistent,
    MinorDrift,
    MajorDivergence,
    ClassEscalation,
    TargetViolation,
    ReceiptMissing,
    SignatureInvalid,
}

// ---------------------------------------------------------------------------
// IevlEngine
// ---------------------------------------------------------------------------

/// Process-wide (or per-instance, for tests) declaration tracker. See module
/// docs for the full model.
pub struct IevlEngine {
    shards: Vec<Mutex<HashMap<String, IntentDeclaration>>>,
}

impl Default for IevlEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl IevlEngine {
    pub fn new() -> Self {
        Self {
            shards: (0..IEVL_SHARDS).map(|_| Mutex::new(HashMap::new())).collect(),
        }
    }

    /// Process-wide singleton, matching `TrustDecayEngine::global()`'s
    /// established pattern.
    pub fn global() -> &'static IevlEngine {
        static GLOBAL: OnceLock<IevlEngine> = OnceLock::new();
        GLOBAL.get_or_init(IevlEngine::new)
    }

    fn shard(&self, key: &str) -> std::sync::MutexGuard<'_, HashMap<String, IntentDeclaration>> {
        self.shards[ievl_shard_index(key)].lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Registration hook — called from `handler.rs`'s Gate 1.5 block, only for
    /// packets whose resolved `action_class` meets `RECEIPT_REQUIRED_ACTION_CLASS`.
    /// Not a gate: never rejects, only records.
    pub fn register_declaration(
        &self,
        session_uuid: &str,
        sequence_id: u64,
        agent_id: &str,
        declared_action: String,
        action_class: u8,
        targets: Vec<String>,
    ) {
        let id = declaration_id(session_uuid, sequence_id);
        let now = now_secs();
        let mut to_penalize: Vec<IntentDeclaration> = Vec::new();

        {
            let mut shard = self.shard(&id);

            if shard.len() >= IEVL_PER_SHARD_MAX_ENTRIES && !shard.contains_key(&id) {
                // Pass 1: anything already past its own TTL is a safe capacity
                // victim — `ReceiptTimeout` is exactly the penalty it would have
                // earned via `sweep_expired` moments later anyway, so evicting it
                // here doesn't skip that consequence, just applies it slightly
                // early.
                let expired_keys: Vec<String> = shard.iter()
                    .filter(|(_, d)| now - d.declared_at > RECEIPT_TTL_SECONDS)
                    .map(|(k, _)| k.clone())
                    .collect();
                for k in expired_keys {
                    if let Some(d) = shard.remove(&k) {
                        to_penalize.push(d);
                    }
                }

                // Pass 2: still over cap — evict the oldest still-live
                // declaration whose owning agent is NOT currently reauth-locked
                // (H-24 precedent, `trust_decay.rs`: never forget a pending
                // declaration for an agent IEVL should be watching most
                // closely). If every remaining entry belongs to a locked agent,
                // let the shard sit over its soft cap rather than silently drop
                // that evidence.
                if shard.len() >= IEVL_PER_SHARD_MAX_ENTRIES {
                    let oldest_unlocked = shard.iter()
                        .filter(|(_, d)| !TrustDecayEngine::global()
                            .requires_reauth(&trust_key_for(&d.agent_id, &d.session_uuid)))
                        .min_by(|(_, a), (_, b)| {
                            a.declared_at.partial_cmp(&b.declared_at).unwrap_or(std::cmp::Ordering::Equal)
                        })
                        .map(|(k, _)| k.clone());
                    if let Some(k) = oldest_unlocked {
                        if let Some(d) = shard.remove(&k) {
                            to_penalize.push(d);
                        }
                    }
                }
            }

            shard.insert(id, IntentDeclaration {
                declared_action,
                action_class,
                targets,
                agent_id: agent_id.to_string(),
                session_uuid: session_uuid.to_string(),
                declared_at: now,
            });
        }

        for d in to_penalize {
            TrustDecayEngine::global().penalize(&trust_key_for(&d.agent_id, &d.session_uuid), PenaltyKind::ReceiptTimeout);
        }
    }

    /// Look up and consume (remove) the declaration matching `declaration_ref`,
    /// compare it against the reported receipt fields, and return the verdict.
    /// A declaration is consumed at most once — a replayed/duplicate receipt for
    /// the same reference always resolves `ReceiptMissing` on its second and
    /// later submissions.
    pub fn process_receipt(
        &self,
        declaration_ref: &str,
        actual_action: &str,
        actual_targets: &[String],
        actual_action_class: u8,
    ) -> VerificationVerdict {
        let decl = {
            let mut shard = self.shard(declaration_ref);
            shard.remove(declaration_ref)
        };
        let Some(decl) = decl else {
            return VerificationVerdict::ReceiptMissing;
        };

        if actual_action_class > decl.action_class {
            return VerificationVerdict::ClassEscalation;
        }

        // Numeric action_class alone can only ever signal escalation when a
        // deployment lowers `RECEIPT_REQUIRED_ACTION_CLASS` below the
        // protocol's ceiling — at the documented default (IRREVERSIBLE only,
        // already the maximum class), a declaration is always AT the ceiling,
        // so there is never a higher class left to escalate to and the check
        // above can never fire. Reuse the exact same dangerous-action-term
        // denylist Gate 1.5c already applies to the *declaration* itself
        // (`gate_1_5c_dangerous_action_consistency`, `DANGEROUS_ACTION_TERMS`)
        // as a textual proxy that stays meaningful regardless of the numeric
        // ceiling: a receipt whose `actual_action` names a high-risk verb
        // absent from what was declared is real evidence the agent did
        // something more dangerous than it promised.
        let declared_terms = SAACPProtocolHandler::intent_terms(&decl.declared_action);
        let actual_terms = SAACPProtocolHandler::intent_terms(actual_action);
        for term in crate::handler::DANGEROUS_ACTION_TERMS {
            if actual_terms.contains_key(*term) && !declared_terms.contains_key(*term) {
                return VerificationVerdict::ClassEscalation;
            }
        }

        let target_overlap = jaccard_overlap(&decl.targets, actual_targets);
        let action_overlap = 1.0 - SAACPProtocolHandler::intent_divergence(&decl.declared_action, actual_action);

        if target_overlap < TARGET_MINOR_DRIFT_THRESHOLD {
            VerificationVerdict::TargetViolation
        } else if action_overlap < TARGET_MINOR_DRIFT_THRESHOLD {
            VerificationVerdict::MajorDivergence
        } else if target_overlap < TARGET_OVERLAP_THRESHOLD || action_overlap < TARGET_OVERLAP_THRESHOLD {
            VerificationVerdict::MinorDrift
        } else {
            VerificationVerdict::Consistent
        }
    }

    /// Remove every declaration past `RECEIPT_TTL_SECONDS` and apply
    /// `PenaltyKind::ReceiptTimeout` for each. Returns the number swept.
    pub fn sweep_expired(&self) -> usize {
        let now = now_secs();
        let mut expired: Vec<IntentDeclaration> = Vec::new();

        for shard_lock in &self.shards {
            let mut shard = shard_lock.lock().unwrap_or_else(|e| e.into_inner());
            let expired_keys: Vec<String> = shard.iter()
                .filter(|(_, d)| now - d.declared_at > RECEIPT_TTL_SECONDS)
                .map(|(k, _)| k.clone())
                .collect();
            for k in expired_keys {
                if let Some(d) = shard.remove(&k) {
                    expired.push(d);
                }
            }
        }

        let count = expired.len();
        for d in expired {
            TrustDecayEngine::global().penalize(&trust_key_for(&d.agent_id, &d.session_uuid), PenaltyKind::ReceiptTimeout);
        }
        count
    }

    /// Number of declarations currently tracked (for observability/tests).
    pub fn tracked_count(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap_or_else(|e| e.into_inner()).len()).sum()
    }

    /// Spawn a background OS thread that calls [`Self::sweep_expired`] every 60
    /// seconds — matches `gossip::GossipEngine::start_sweep`'s and
    /// `klms::KeyLifecycleManager::start_auto_rotation`'s cadence and "caller
    /// decides whether to spawn it" opt-in convention. Returns the thread's
    /// `JoinHandle` — the thread runs for the lifetime of the process.
    pub fn start_sweep(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("ievl-sweep".to_string())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                self.sweep_expired();
            })
            .expect("failed to spawn ievl-sweep thread")
    }
}

/// Jaccard overlap between two target sets, case/whitespace-normalized.
/// Both empty ⇒ `1.0` (vacuously consistent — nothing was declared, nothing was
/// reported touched).
fn jaccard_overlap(declared: &[String], actual: &[String]) -> f64 {
    let normalize = |v: &[String]| -> HashSet<String> {
        v.iter().map(|s| s.trim().to_lowercase()).filter(|s| !s.is_empty()).collect()
    };
    let a = normalize(declared);
    let b = normalize(actual);
    if a.is_empty() && b.is_empty() {
        return 1.0;
    }
    let union = a.union(&b).count();
    if union == 0 {
        return 1.0;
    }
    a.intersection(&b).count() as f64 / union as f64
}

/// Extract a declaration's target list from a Gate-1.5-bound payload: prefers a
/// `targets` array, falls back to a single `target` string (schema 2 "Action"
/// shape), defaults to empty (an IRREVERSIBLE action with no identifiable
/// targets still gets a declaration — action-text/class comparison still
/// applies, just with `target_overlap` trivially `1.0` when both sides report
/// none).
pub fn extract_targets(payload_dict: &HashMap<String, JsonValue>) -> Vec<String> {
    match payload_dict.get("targets") {
        Some(JsonValue::Array(items)) => items.iter()
            .filter_map(|v| match v {
                JsonValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => match payload_dict.get("target") {
            Some(JsonValue::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        },
    }
}

// ---------------------------------------------------------------------------
// ExecutionReceipt wire decode + signature verification
// ---------------------------------------------------------------------------

/// Decode an already-schema-validated schema_id=10 `payload_dict` into its
/// four required fields. `PreCompiledSchemas::validate_payload` has already
/// confirmed all four keys are present by the time this runs (schema
/// validation happens inside `handler.rs`'s gate pipeline, before `Ok(parsed)`
/// is ever returned) — this only handles type coercion from loosely-typed
/// `JsonValue`s. Returns `None` on any type mismatch, mirroring
/// `daemon.rs::decode_gossip_envelope`'s "drop and log nothing further"
/// philosophy for malformed/adversarial peer traffic.
fn decode_execution_receipt(payload_dict: &HashMap<String, JsonValue>) -> Option<(String, String, Vec<String>, String)> {
    let declaration_ref = match payload_dict.get("declaration_ref") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };
    let actual_action = match payload_dict.get("actual_action") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };
    let actual_targets = match payload_dict.get("actual_targets") {
        Some(JsonValue::Array(items)) => items.iter()
            .filter_map(|v| match v {
                JsonValue::String(s) => Some(s.clone()),
                _ => None,
            })
            .collect(),
        _ => return None,
    };
    let receipt_signature = match payload_dict.get("receipt_signature") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };
    Some((declaration_ref, actual_action, actual_targets, receipt_signature))
}

/// Canonical length-prefixed encoding of a receipt's claimed fields — the same
/// idiom `identity_binding.rs`'s transcript hash and `faitf.rs`'s
/// `AgentCredential`/`SignedRevocationRecord` body bytes already use, so no two
/// fields can ever be concatenation-ambiguous with each other.
fn canonical_receipt_bytes(declaration_ref: &str, actual_action: &str, actual_targets: &[String]) -> Vec<u8> {
    fn encode_field(buf: &mut Vec<u8>, data: &[u8]) {
        buf.extend_from_slice(&(data.len() as u32).to_be_bytes());
        buf.extend_from_slice(data);
    }
    let mut buf = Vec::new();
    buf.extend_from_slice(b"saacp-ievl-receipt-v1");
    encode_field(&mut buf, declaration_ref.as_bytes());
    encode_field(&mut buf, actual_action.as_bytes());
    buf.extend_from_slice(&(actual_targets.len() as u32).to_be_bytes());
    for t in actual_targets {
        encode_field(&mut buf, t.as_bytes());
    }
    buf
}

/// Sign a receipt's claimed fields with the presenting session's private key,
/// producing the base64 `receipt_signature` a client attaches to its
/// `ExecutionReceipt` wire payload. The counterpart to
/// [`verify_receipt_signature`] — both sides must agree on
/// `canonical_receipt_bytes`'s exact encoding, so this reuses it directly
/// rather than duplicating the field layout.
pub fn sign_receipt(
    signing_key: &ed25519_dalek::SigningKey,
    declaration_ref: &str,
    actual_action: &str,
    actual_targets: &[String],
) -> String {
    use ed25519_dalek::Signer;
    let body = canonical_receipt_bytes(declaration_ref, actual_action, actual_targets);
    let sig = signing_key.sign(&body);
    base64::engine::general_purpose::STANDARD.encode(sig.to_bytes())
}

/// Verify a receipt's `receipt_signature` (base64 Ed25519 signature) against
/// the presenting session's bound public key
/// (`identity_binding::DEFAULT_IDENTITY_REGISTRY`, exactly as
/// `trust_decay::trust_key_for` already looks it up). `false` on any decode
/// failure or missing session binding — an unverifiable receipt must never be
/// treated as trusted.
pub fn verify_receipt_signature(
    session_uuid: &str,
    declaration_ref: &str,
    actual_action: &str,
    actual_targets: &[String],
    signature_b64: &str,
) -> bool {
    let Some(pk_hex) = crate::identity_binding::DEFAULT_IDENTITY_REGISTRY
        .get_by_session_id(session_uuid, |session| session.client_public_key_hex.clone())
        .filter(|pk_hex| !pk_hex.is_empty())
    else {
        return false;
    };
    let Ok(pk_bytes) = hex::decode(&pk_hex) else { return false; };
    let Ok(pk_arr) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else { return false; };
    let Ok(verifying_key) = VerifyingKey::from_bytes(&pk_arr) else { return false; };

    let Ok(sig_bytes) = base64::engine::general_purpose::STANDARD.decode(signature_b64) else { return false; };
    let Ok(sig_arr) = <[u8; 64]>::try_from(sig_bytes.as_slice()) else { return false; };
    let sig = Signature::from_bytes(&sig_arr);

    let body = canonical_receipt_bytes(declaration_ref, actual_action, actual_targets);
    verifying_key.verify(&body, &sig).is_ok()
}

// ---------------------------------------------------------------------------
// daemon.rs entry point
// ---------------------------------------------------------------------------

/// Handle a schema_id=10 `ExecutionReceipt` packet that has already cleared the
/// full gate pipeline (`daemon.rs` dispatches here exactly as it dispatches a
/// schema_id=11 Gossip Envelope to `gossip::GossipEngine::receive` — see that
/// call site). Decodes, verifies the signature, resolves the verdict against
/// [`IevlEngine::global`], and applies the enforcement the module docs'
/// "Enforcement" section describes. Never panics and never affects the wire
/// response for the receipt packet itself — enforcement here is a side effect
/// (trust penalty/reward or revocation), not a rejection of the
/// already-accepted receipt.
pub fn handle_execution_receipt(parsed: &ParsedPacket) {
    let Some((declaration_ref, actual_action, actual_targets, signature_b64)) =
        decode_execution_receipt(&parsed.payload_dict)
    else {
        return;
    };

    if !verify_receipt_signature(&parsed.session_uuid, &declaration_ref, &actual_action, &actual_targets, &signature_b64) {
        report_gate_rejection(
            "ievl_receipt",
            &parsed.source_agent,
            &SAACPHardDrop::new(
                SAACPBytecodes::InvalidSignature,
                "IEVL: ExecutionReceipt signature verification failed against the session's bound public key.",
            ),
        );
        return;
    }

    let trust_key = trust_key_for(&parsed.source_agent, &parsed.session_uuid);
    let verdict = IevlEngine::global().process_receipt(&declaration_ref, &actual_action, &actual_targets, parsed.action_class);

    match verdict {
        VerificationVerdict::Consistent => {
            TrustDecayEngine::global().reward(
                &trust_key,
                RewardKind::ValidReceipt,
                parsed.action_class >= RECEIPT_REQUIRED_ACTION_CLASS,
            );
        }
        VerificationVerdict::MinorDrift => {
            // Informational only — plausibly paraphrasing rather than a real
            // substitution; no trust action.
        }
        VerificationVerdict::TargetViolation | VerificationVerdict::MajorDivergence => {
            TrustDecayEngine::global().penalize(&trust_key, PenaltyKind::TargetViolation);
        }
        VerificationVerdict::ClassEscalation => {
            report_gate_rejection(
                "ievl_receipt",
                &parsed.source_agent,
                &SAACPHardDrop::new(
                    SAACPBytecodes::IntentClassEscalationDetected,
                    "IEVL: ExecutionReceipt reports an action_class exceeding its declared IntentDeclaration — revoking.",
                ),
            );
            let revoker = system_revoker_identity();
            let _ = crate::faitf::DistributedRevocationInfrastructure::global().revoke(
                &parsed.source_agent,
                "security-incident: IEVL detected action-class escalation between declared intent and execution receipt",
                revoker,
                "",
            );
        }
        VerificationVerdict::ReceiptMissing | VerificationVerdict::SignatureInvalid => {
            // No matching declaration (already swept, or a bogus/forged
            // reference) — nothing further to enforce against a receipt with
            // no corresponding declaration; cannot be reliably attributed to
            // the declaring agent's own behavior.
        }
    }
}

/// Lazily-generated protocol-internal identity used as the `revoker_identity`
/// for IEVL's own automated (non-human) `DistributedRevocationInfrastructure::revoke`
/// calls — distinct from any agent's own identity, matching how a real
/// automated security control has its own signing identity separate from human
/// operators. Generated once per process; the private key never leaves this
/// process's memory.
fn system_revoker_identity() -> &'static crate::faitf::AgentIdentity {
    static SYSTEM_IDENTITY: OnceLock<crate::faitf::AgentIdentity> = OnceLock::new();
    SYSTEM_IDENTITY.get_or_init(|| {
        crate::faitf::AgentIdentity::generate(
            "saacp-ievl-system",
            "saacp-protocol",
            u32::MAX as u64,
            None,
            None,
            "",
            crate::faitf::AttestationType::None,
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    // ── declaration_id ──────────────────────────────────────────────────

    #[test]
    fn declaration_id_is_deterministic() {
        let a = declaration_id("session-1", 42);
        let b = declaration_id("session-1", 42);
        assert_eq!(a, b);
    }

    #[test]
    fn declaration_id_differs_across_session_or_sequence() {
        let base = declaration_id("session-1", 42);
        assert_ne!(base, declaration_id("session-2", 42));
        assert_ne!(base, declaration_id("session-1", 43));
    }

    // ── jaccard_overlap ──────────────────────────────────────────────────

    #[test]
    fn jaccard_overlap_identical_sets_is_one() {
        let a = s(&["file-a", "file-b"]);
        assert_eq!(jaccard_overlap(&a, &a), 1.0);
    }

    #[test]
    fn jaccard_overlap_both_empty_is_one() {
        assert_eq!(jaccard_overlap(&[], &[]), 1.0);
    }

    #[test]
    fn jaccard_overlap_disjoint_sets_is_zero() {
        let a = s(&["file-a"]);
        let b = s(&["file-b"]);
        assert_eq!(jaccard_overlap(&a, &b), 0.0);
    }

    #[test]
    fn jaccard_overlap_case_and_whitespace_normalized() {
        let a = s(&["File-A"]);
        let b = s(&[" file-a "]);
        assert_eq!(jaccard_overlap(&a, &b), 1.0);
    }

    #[test]
    fn jaccard_overlap_partial() {
        let a = s(&["a", "b", "c"]);
        let b = s(&["a", "b", "d"]);
        // intersection {a,b} = 2, union {a,b,c,d} = 4
        assert_eq!(jaccard_overlap(&a, &b), 0.5);
    }

    // ── extract_targets ──────────────────────────────────────────────────

    #[test]
    fn extract_targets_prefers_array() {
        let mut payload = HashMap::new();
        payload.insert("targets".to_string(), JsonValue::Array(vec![
            JsonValue::String("a".to_string()),
            JsonValue::String("b".to_string()),
        ]));
        payload.insert("target".to_string(), JsonValue::String("ignored".to_string()));
        assert_eq!(extract_targets(&payload), s(&["a", "b"]));
    }

    #[test]
    fn extract_targets_falls_back_to_single_target() {
        let mut payload = HashMap::new();
        payload.insert("target".to_string(), JsonValue::String("solo".to_string()));
        assert_eq!(extract_targets(&payload), s(&["solo"]));
    }

    #[test]
    fn extract_targets_defaults_empty() {
        let payload = HashMap::new();
        assert!(extract_targets(&payload).is_empty());
    }

    // ── register_declaration / process_receipt ──────────────────────────

    #[test]
    fn consistent_receipt_verified() {
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-a", 1, "agent-a",
            "delete stale records".to_string(), 0x02, s(&["table-x"]),
        );
        let verdict = engine.process_receipt(
            &declaration_id("sess-a", 1),
            "delete stale records",
            &s(&["table-x"]),
            0x02,
        );
        assert_eq!(verdict, VerificationVerdict::Consistent);
    }

    #[test]
    fn receipt_consumes_declaration_exactly_once() {
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-b", 1, "agent-b",
            "delete stale records".to_string(), 0x02, s(&["table-x"]),
        );
        let id = declaration_id("sess-b", 1);
        let first = engine.process_receipt(&id, "delete stale records", &s(&["table-x"]), 0x02);
        assert_eq!(first, VerificationVerdict::Consistent);
        let second = engine.process_receipt(&id, "delete stale records", &s(&["table-x"]), 0x02);
        assert_eq!(second, VerificationVerdict::ReceiptMissing);
    }

    #[test]
    fn unknown_declaration_ref_is_receipt_missing() {
        let engine = IevlEngine::new();
        let verdict = engine.process_receipt("nonexistent-ref", "whatever", &[], 0x00);
        assert_eq!(verdict, VerificationVerdict::ReceiptMissing);
    }

    #[test]
    fn class_escalation_detected_via_numeric_action_class() {
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-c", 1, "agent-c",
            "read the report".to_string(), 0x01, s(&["report-1"]),
        );
        let verdict = engine.process_receipt(
            &declaration_id("sess-c", 1), "read the report", &s(&["report-1"]), 0x02,
        );
        assert_eq!(verdict, VerificationVerdict::ClassEscalation);
    }

    #[test]
    fn class_escalation_detected_via_dangerous_action_term_at_ceiling() {
        // Both declared and actual sit at the protocol's ceiling
        // (IRREVERSIBLE, 0x02) — the numeric check alone could never fire
        // here, since there is no higher class to escalate to. This is the
        // realistic production shape: `RECEIPT_REQUIRED_ACTION_CLASS`'s
        // documented default only ever registers IRREVERSIBLE declarations.
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-i", 1, "agent-i",
            "archive the quarterly ledger".to_string(), 0x02, s(&["ledger-1"]),
        );
        let verdict = engine.process_receipt(
            &declaration_id("sess-i", 1),
            "wipe the quarterly ledger",
            &s(&["ledger-1"]),
            0x02,
        );
        assert_eq!(verdict, VerificationVerdict::ClassEscalation);
    }

    #[test]
    fn dangerous_term_present_in_both_declared_and_actual_is_not_escalation() {
        // A root intent that legitimately declares a dangerous verb ("delete")
        // must not falsely flag a receipt that also (honestly) reports it —
        // mirrors `gate_1_5c_dangerous_action_consistency`'s own
        // "relative to the declaration's own vocabulary" false-positive guard.
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-j", 1, "agent-j",
            "delete stale test records".to_string(), 0x02, s(&["table-x"]),
        );
        let verdict = engine.process_receipt(
            &declaration_id("sess-j", 1), "delete stale test records", &s(&["table-x"]), 0x02,
        );
        assert_eq!(verdict, VerificationVerdict::Consistent);
    }

    #[test]
    fn target_violation_on_disjoint_targets() {
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-d", 1, "agent-d",
            "delete stale records".to_string(), 0x02, s(&["table-x"]),
        );
        let verdict = engine.process_receipt(
            &declaration_id("sess-d", 1), "delete stale records", &s(&["table-completely-different"]), 0x02,
        );
        assert_eq!(verdict, VerificationVerdict::TargetViolation);
    }

    #[test]
    fn major_divergence_on_unrelated_action_text_same_targets() {
        let engine = IevlEngine::new();
        engine.register_declaration(
            "sess-e", 1, "agent-e",
            "archive quarterly financial ledger entries".to_string(), 0x02, s(&["table-x"]),
        );
        let verdict = engine.process_receipt(
            &declaration_id("sess-e", 1),
            "send marketing email newsletter broadcast",
            &s(&["table-x"]),
            0x02,
        );
        assert_eq!(verdict, VerificationVerdict::MajorDivergence);
    }

    #[test]
    fn tracked_count_reflects_registration_and_consumption() {
        let engine = IevlEngine::new();
        assert_eq!(engine.tracked_count(), 0);
        engine.register_declaration("sess-f", 1, "agent-f", "task".to_string(), 0x02, vec![]);
        assert_eq!(engine.tracked_count(), 1);
        engine.process_receipt(&declaration_id("sess-f", 1), "task", &[], 0x02);
        assert_eq!(engine.tracked_count(), 0);
    }

    #[test]
    fn sweep_expired_removes_only_stale_entries_and_penalizes() {
        let engine = IevlEngine::new();
        // Directly inject an already-stale declaration to avoid a real sleep.
        {
            let mut shard = engine.shard(&declaration_id("sess-g", 1));
            shard.insert(declaration_id("sess-g", 1), IntentDeclaration {
                declared_action: "task".to_string(),
                action_class: 0x02,
                targets: vec![],
                agent_id: "agent-g".to_string(),
                session_uuid: "sess-g".to_string(),
                declared_at: now_secs() - RECEIPT_TTL_SECONDS - 1.0,
            });
        }
        engine.register_declaration("sess-h", 1, "agent-h", "fresh".to_string(), 0x02, vec![]);

        let swept = engine.sweep_expired();
        assert_eq!(swept, 1);
        assert_eq!(engine.tracked_count(), 1); // only the fresh one remains
    }

    // ── signature verification ──────────────────────────────────────────

    #[test]
    fn verify_receipt_signature_fails_with_no_bound_session() {
        assert!(!verify_receipt_signature("no-such-session", "ref", "action", &[], "not-base64!!"));
    }

    #[test]
    fn verify_receipt_signature_fails_on_garbage_signature() {
        assert!(!verify_receipt_signature("no-such-session", "ref", "action", &[], "AAAA"));
    }

    #[test]
    fn sign_and_verify_receipt_signature_round_trip() {
        use crate::identity_binding::{TranscriptBoundSession, DEFAULT_IDENTITY_REGISTRY};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let client_pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
        // Unique, test-local session_id so this can't collide with any other
        // test's use of the process-wide DEFAULT_IDENTITY_REGISTRY singleton.
        let sid = vec![0x1Eu8; 16];
        let session = TranscriptBoundSession::establish(
            sid, "receipt-signer", "server-x",
            &client_pk_hex, &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let session_id_hex = session.session_id_hex();
        let thash = session.thash.clone();
        DEFAULT_IDENTITY_REGISTRY.register(session);

        let targets = s(&["table-x"]);
        let sig_b64 = sign_receipt(&signing_key, "decl-ref-1", "delete stale records", &targets);
        let verified = verify_receipt_signature(&session_id_hex, "decl-ref-1", "delete stale records", &targets, &sig_b64);

        DEFAULT_IDENTITY_REGISTRY.remove(&thash);

        assert!(verified, "a correctly-signed receipt must verify against its session's bound public key");
    }

    #[test]
    fn verify_receipt_signature_rejects_tampered_field() {
        use crate::identity_binding::{TranscriptBoundSession, DEFAULT_IDENTITY_REGISTRY};
        use ed25519_dalek::SigningKey;
        use rand::rngs::OsRng;

        let signing_key = SigningKey::generate(&mut OsRng);
        let client_pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let sid = vec![0x1Fu8; 16];
        let session = TranscriptBoundSession::establish(
            sid, "receipt-signer-2", "server-x",
            &client_pk_hex, &"bb".repeat(32),
            &"cc".repeat(16), &"dd".repeat(16),
            "v1", "cs1", None,
        );
        let session_id_hex = session.session_id_hex();
        let thash = session.thash.clone();
        DEFAULT_IDENTITY_REGISTRY.register(session);

        let sig_b64 = sign_receipt(&signing_key, "decl-ref-1", "delete stale records", &s(&["table-x"]));
        // Verify against a DIFFERENT actual_action than what was signed.
        let verified = verify_receipt_signature(&session_id_hex, "decl-ref-1", "delete EVERYTHING", &s(&["table-x"]), &sig_b64);

        DEFAULT_IDENTITY_REGISTRY.remove(&thash);

        assert!(!verified, "a signature over one action must not verify against a tampered action string");
    }

    #[test]
    fn canonical_receipt_bytes_are_not_concatenation_ambiguous() {
        let a = canonical_receipt_bytes("ab", "c", &[]);
        let b = canonical_receipt_bytes("a", "bc", &[]);
        assert_ne!(a, b);
    }

    #[test]
    fn decode_execution_receipt_requires_all_fields() {
        let mut payload = HashMap::new();
        payload.insert("declaration_ref".to_string(), JsonValue::String("r".to_string()));
        assert!(decode_execution_receipt(&payload).is_none());
    }

    #[test]
    fn decode_execution_receipt_full_roundtrip() {
        let mut payload = HashMap::new();
        payload.insert("declaration_ref".to_string(), JsonValue::String("r".to_string()));
        payload.insert("actual_action".to_string(), JsonValue::String("a".to_string()));
        payload.insert("actual_targets".to_string(), JsonValue::Array(vec![JsonValue::String("t".to_string())]));
        payload.insert("receipt_signature".to_string(), JsonValue::String("sig".to_string()));
        let decoded = decode_execution_receipt(&payload);
        assert_eq!(decoded, Some(("r".to_string(), "a".to_string(), s(&["t"]), "sig".to_string())));
    }

    #[test]
    fn system_revoker_identity_is_stable_across_calls() {
        let a = system_revoker_identity().fingerprint();
        let b = system_revoker_identity().fingerprint();
        assert_eq!(a, b);
    }
}
