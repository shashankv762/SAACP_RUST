//! crypto_governance.rs — Cryptographic Suite Governance and Downgrade Resistance
//!
//! Implements ApprovedSuitePolicy, CryptoTransparencyLedger,
//! NegotiationTranscript, and SuiteNegotiator.

use std::collections::HashSet;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::security::constant_time_eq_hex;

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

// ---------------------------------------------------------------------------
// SuiteStatus
// ---------------------------------------------------------------------------

/// Classification of a cryptographic suite under the governance framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuiteStatus {
    Approved,
    Experimental,
    Deprecated,
    Forbidden,
}

impl SuiteStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Approved => "APPROVED",
            Self::Experimental => "EXPERIMENTAL",
            Self::Deprecated => "DEPRECATED",
            Self::Forbidden => "FORBIDDEN",
        }
    }

    /// Parse a SuiteStatus from a string. Unknown values default to Forbidden.
    pub fn parse(s: &str) -> Self {
        match s {
            "APPROVED" => Self::Approved,
            "EXPERIMENTAL" => Self::Experimental,
            "DEPRECATED" => Self::Deprecated,
            _ => Self::Forbidden,
        }
    }
}

impl std::str::FromStr for SuiteStatus {
    type Err = std::convert::Infallible;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self::parse(s))
    }
}

/// Signature algorithm baseline — Ed25519 governs ACSVAF/FAITF token signing.
pub const SIGNATURE_ALGO_BASELINE: &str = "ed25519";
/// Cipher suite baseline — AES-256-GCM with HKDF-SHA256 key derivation.
/// This is the AEAD session encryption baseline, NOT a signature algorithm.
/// (C-4 fix: was incorrectly set to "ed25519" — Ed25519 is a signature algo
///  used in ACSVAF token signing, completely separate from session encryption.)
pub const CIPHER_SUITE_BASELINE: &str = "AES-256-GCM-HKDF-SHA256";
/// Approved AEAD session cipher suites — only identifiers in this list may
/// be selected as the MEASC session encryption algorithm.
pub const APPROVED_SESSION_CIPHER_SUITES: &[&str] = &["AES-256-GCM-HKDF-SHA256"];
/// Approved signature suites — classical and post-quantum.
pub const APPROVED_SIGNATURE_SUITES: &[&str] = &[
    "ed25519",
    "ml-dsa-65",
    "slh-dsa",
    "hybrid-ed25519-ml-dsa-65",
];
/// Approved KEM suites — classical and post-quantum.
pub const APPROVED_KEM_SUITES: &[&str] = &[
    "x25519",
    "ml-kem-768",
    "ml-kem-1024",
    "hybrid-x25519-ml-kem-768",
    "hybrid-p384-ml-kem-1024",
];
// ---------------------------------------------------------------------------
// Security Tiers (#8 — PQC-required tier + fail-closed)
// ---------------------------------------------------------------------------

/// Security tiers for cryptographic negotiation.
///
/// #8 FIX: Introduces a hard PQC floor. A `PqcRequired` endpoint physically
/// cannot complete a classical handshake — it fails closed with a distinct
/// error rather than silently degrading. This is the single most important
/// architectural fix because without it, an active attacker can negotiate
/// down to classical and the PQC becomes decorative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecurityTier {
    /// PQC is mandatory. Any non-hybrid completion fails closed.
    /// Use for healthcare/banking channels carrying long-lived data.
    PqcRequired,
    /// PQC is preferred but classical is acceptable (logged as degraded).
    /// Use for general-purpose channels where backward compat matters.
    PqcPreferred,
    /// Classical-only, explicit opt-in, audit-flagged.
    /// Use only for legacy interoperability during migration windows.
    ClassicalLegacy,
}

impl SecurityTier {
    /// Parse from string.
    ///
    /// Deliberately an inherent method (Python-parity shape), not a `FromStr`
    /// impl — see `cluster.rs`'s matching `#[allow]` for the rationale.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_uppercase().as_str() {
            "PQC-REQUIRED" | "PQCREQUIRED" => Some(Self::PqcRequired),
            "PQC-PREFERRED" | "PQCPREFERRED" => Some(Self::PqcPreferred),
            "CLASSICAL-LEGACY" | "CLASSICALLEGACY" | "LEGACY" => Some(Self::ClassicalLegacy),
            _ => None,
        }
    }

    /// String representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::PqcRequired => "PQC-REQUIRED",
            Self::PqcPreferred => "PQC-PREFERRED",
            Self::ClassicalLegacy => "CLASSICAL-LEGACY",
        }
    }

    /// Whether this tier requires a hybrid (PQC) suite.
    pub fn requires_pqc(&self) -> bool {
        matches!(self, Self::PqcRequired)
    }

    /// Whether this tier allows classical-only suites.
    pub fn allows_classical(&self) -> bool {
        matches!(self, Self::PqcPreferred | Self::ClassicalLegacy)
    }
}

/// Recommended hybrid signature suite (quantum-resistant default).
pub const RECOMMENDED_SIGNATURE_SUITE: &str = "hybrid-ed25519-ml-dsa-65";
/// Recommended hybrid KEM suite (quantum-resistant default).
pub const RECOMMENDED_KEM_SUITE: &str = "hybrid-x25519-ml-kem-768";

// ---------------------------------------------------------------------------
// #9 FIX: Crypto-Telemetry per Session
// ---------------------------------------------------------------------------

/// Cryptographic telemetry for a single session.
///
/// #9 FIX: Records the exact cryptographic parameters used in each session
/// so that when a weakness is discovered (e.g., a Falcon side-channel or
/// an ML-KEM parameter revision), you can query which sessions are affected
/// within minutes, not days. This is also the compliance artifact for
/// regulated sectors — you must be able to *demonstrate* PQC was in force.
#[derive(Debug, Clone, Serialize)]
pub struct SessionCryptoTelemetry {
    /// Session identifier.
    pub session_id: String,
    /// Negotiated suite name.
    pub negotiated_suite: String,
    /// Security tier used during negotiation.
    pub security_tier: String,
    /// Algorithm code-points used (signature algorithms).
    pub signature_algorithms: Vec<u16>,
    /// KEM algorithm code-point used.
    pub kem_algorithm: String,
    /// Attestation verdict (if attestation was performed).
    pub attestation_verdict: Option<String>,
    /// Whether any degradation occurred during negotiation.
    pub degradation_occurred: bool,
    /// Reason for degradation (if any).
    pub degradation_reason: Option<String>,
    /// Timestamp when the session was established.
    pub established_at: f64,
    /// Negotiation transcript hash.
    pub transcript_hash: String,
}

impl SessionCryptoTelemetry {
    /// Create a new telemetry record for a session.
    pub fn new(
        session_id: String,
        negotiated_suite: String,
        security_tier: String,
        transcript_hash: String,
    ) -> Self {
        Self {
            session_id,
            negotiated_suite,
            security_tier,
            signature_algorithms: Vec::new(),
            kem_algorithm: String::new(),
            attestation_verdict: None,
            degradation_occurred: false,
            degradation_reason: None,
            established_at: now_epoch_secs(),
            transcript_hash,
        }
    }

    /// Record that a degradation occurred.
    pub fn record_degradation(&mut self, reason: &str) {
        self.degradation_occurred = true;
        self.degradation_reason = Some(reason.to_string());
    }

    /// Record the attestation verdict.
    pub fn record_attestation(&mut self, verdict: &str) {
        self.attestation_verdict = Some(verdict.to_string());
    }

    /// Add a signature algorithm code-point.
    pub fn add_signature_algorithm(&mut self, code_point: u16) {
        if !self.signature_algorithms.contains(&code_point) {
            self.signature_algorithms.push(code_point);
        }
    }
}

/// Registry of session crypto-telemetry records.
///
/// #9 FIX: Provides queryable storage for session cryptographic parameters.
/// When a weakness is discovered, query this registry to find affected sessions.
#[derive(Debug, Clone)]
pub struct CryptoTelemetryRegistry {
    records: Vec<SessionCryptoTelemetry>,
}

impl CryptoTelemetryRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Record telemetry for a session.
    pub fn record(&mut self, telemetry: SessionCryptoTelemetry) {
        self.records.push(telemetry);
    }

    /// Find all sessions that used a specific suite.
    pub fn find_by_suite(&self, suite: &str) -> Vec<&SessionCryptoTelemetry> {
        self.records
            .iter()
            .filter(|r| r.negotiated_suite == suite)
            .collect()
    }

    /// Find all sessions that used a specific signature algorithm code-point.
    pub fn find_by_signature_algorithm(&self, code_point: u16) -> Vec<&SessionCryptoTelemetry> {
        self.records
            .iter()
            .filter(|r| r.signature_algorithms.contains(&code_point))
            .collect()
    }

    /// Find all sessions where degradation occurred.
    pub fn find_degraded_sessions(&self) -> Vec<&SessionCryptoTelemetry> {
        self.records
            .iter()
            .filter(|r| r.degradation_occurred)
            .collect()
    }

    /// Find all sessions that used a specific security tier.
    pub fn find_by_tier(&self, tier: &str) -> Vec<&SessionCryptoTelemetry> {
        self.records
            .iter()
            .filter(|r| r.security_tier == tier)
            .collect()
    }

    /// Get all records.
    pub fn all_records(&self) -> &[SessionCryptoTelemetry] {
        &self.records
    }
}

impl Default for CryptoTelemetryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

/// Downgrade sentinel — a fixed value written into the transcript when a
/// PQC-capable endpoint ends up in a classical suite. A genuine classical-only
/// peer cannot produce the PQC-capable sentinel, so a stripped negotiation
/// fails signature verification.
///
/// #2 FIX: This is the TLS 1.3 server-random downgrade canary mechanism,
/// generalized to the SAACP suite registry.
pub const DOWNGRADE_SENTINEL_PQC_CAPABLE: &[u8] = b"SAACP-PQC-CAPABLE-v2";
pub const DOWNGRADE_SENTINEL_CLASSICAL_ONLY: &[u8] = b"SAACP-CLASSICAL-ONLY-v2";

/// Determine the downgrade sentinel based on peer capabilities and selected suite.
///
/// If the peer advertised PQC suites but the selected suite is classical,
/// returns the PQC-capable sentinel (indicating a potential downgrade attack).
/// Otherwise returns the classical-only sentinel.
pub fn compute_downgrade_sentinel(
    peer_advertised_pqc: bool,
    selected_suite: &str,
) -> &'static [u8] {
    let is_hybrid = selected_suite.contains("hybrid")
        || selected_suite.contains("ml-dsa")
        || selected_suite.contains("ml-kem");
    if peer_advertised_pqc && !is_hybrid {
        // Peer advertised PQC but we ended up classical — potential downgrade
        DOWNGRADE_SENTINEL_PQC_CAPABLE
    } else {
        DOWNGRADE_SENTINEL_CLASSICAL_ONLY
    }
}

/// Check if a suite name indicates a hybrid (PQC) construction.
pub fn is_hybrid_suite(suite: &str) -> bool {
    suite.contains("hybrid") || suite.contains("ml-dsa") || suite.contains("ml-kem")
}

/// Check if a suite name indicates a classical-only construction.
pub fn is_classical_suite(suite: &str) -> bool {
    !is_hybrid_suite(suite)
}

// ---------------------------------------------------------------------------
// CryptoLedgerEntry
// ---------------------------------------------------------------------------

/// One event in the Cryptographic Transparency Ledger.
#[derive(Debug, Clone)]
pub struct CryptoLedgerEntry {
    pub timestamp: f64,
    pub event_type: String,
    pub suite_name: String,
    pub session_id: String,
    pub outcome: String,
    pub transcript_hash: String,
    pub details: String,
    pub entry_hash: String,
}

// ---------------------------------------------------------------------------
// CryptoTransparencyLedger
// ---------------------------------------------------------------------------

/// Order-stable JSON view of a ledger entry used as the hash-chain input.
///
/// Excludes `entry_hash` itself (the value being computed from this
/// canonical form) and mirrors every other `CryptoLedgerEntry` field.
///
/// SECURITY (H-10): the previous hand-rolled `format!`-based canonicalization
/// escaped only `\` and `"`, leaving raw control characters (e.g. an embedded
/// newline) unescaped. That produced non-canonical, ambiguous string output
/// where two distinct `CryptoLedgerEntry` values could serialize to the same
/// bytes and therefore hash-collide, letting a forged entry pass
/// `verify_chain()`. `serde_json::to_string` performs complete, spec-correct
/// JSON string escaping.
#[derive(Serialize)]
struct CanonicalLedgerEntry<'a> {
    details: &'a str,
    event_type: &'a str,
    outcome: &'a str,
    session_id: &'a str,
    suite_name: &'a str,
    timestamp: f64,
    transcript_hash: &'a str,
}

impl<'a> From<&'a CryptoLedgerEntry> for CanonicalLedgerEntry<'a> {
    fn from(e: &'a CryptoLedgerEntry) -> Self {
        Self {
            details: &e.details,
            event_type: &e.event_type,
            outcome: &e.outcome,
            session_id: &e.session_id,
            suite_name: &e.suite_name,
            // JSON has no representation for non-finite floats; every real
            // caller sources `timestamp` from `now_epoch_secs()` (which
            // already falls back to 0.0 on clock error), so this clamp is a
            // defensive no-op in practice, not a behavior change.
            timestamp: if e.timestamp.is_finite() {
                e.timestamp
            } else {
                0.0
            },
            transcript_hash: &e.transcript_hash,
        }
    }
}

/// Canonical JSON encoding of `entry`, used as hash-chain input by both
/// `append` and `verify_chain` — a single shared implementation guarantees
/// they can never drift out of sync with each other.
fn canonical_json(entry: &CryptoLedgerEntry) -> String {
    serde_json::to_string(&CanonicalLedgerEntry::from(entry)).expect(
        "CanonicalLedgerEntry serialization is infallible: every field is a &str or a finite f64",
    )
}

/// Append-only, hash-chained ledger of all cryptographic governance events.
///
/// R-1: `log`/`last_hash` hold the *audit trail* of governance events, not the
/// governance decision state itself — suite accept/reject/deprecate decisions
/// are made by `ApprovedSuitePolicy` (no mutex, evaluated independently of
/// this ledger) before or alongside any `append()` call. A poisoned lock here
/// therefore cannot flip an accept/reject outcome; it would only risk this
/// audit log becoming unusable for every future caller (every `negotiate()`,
/// `get_suite()`, `register_suite()` call appends to a shared ledger), which
/// is a needless availability cascade, not a security bypass. So — matching
/// the established `CRYPTO_SUITES` idiom (see `cryptosuite.rs` M-38 fix) —
/// lock methods here recover from poisoning via `into_inner()` instead of
/// propagating the panic to every subsequent caller.
pub struct CryptoTransparencyLedger {
    log: Mutex<Vec<CryptoLedgerEntry>>,
    last_hash: Mutex<String>,
}

impl CryptoTransparencyLedger {
    pub fn new() -> Self {
        Self {
            log: Mutex::new(Vec::new()),
            last_hash: Mutex::new("0".repeat(64)),
        }
    }

    /// Append an entry with hash-chaining.
    pub fn append(&self, mut entry: CryptoLedgerEntry) {
        let canonical = canonical_json(&entry);
        let prev = self.last_hash.lock().clone();
        let chain_input = format!("{}{}", prev, canonical);
        let hash = sha256_hex(chain_input.as_bytes());
        entry.entry_hash = hash.clone();
        *self.last_hash.lock() = hash;
        self.log.lock().push(entry);
    }

    /// Return all entries.
    pub fn entries(&self) -> Vec<CryptoLedgerEntry> {
        self.log.lock().clone()
    }

    /// Verify the hash chain integrity.
    ///
    /// M-2 fix: compares `entry_hash` against the recomputed expected digest
    /// using a constant-time hex comparison (`constant_time_eq_hex`) instead
    /// of `!=`, so a local timing side-channel can't help an attacker narrow
    /// down a forged ledger entry's hash byte-by-byte.
    pub fn verify_chain(&self) -> bool {
        let log = self.log.lock();
        let mut prev_hash = "0".repeat(64);
        for entry in log.iter() {
            let canonical = canonical_json(entry);
            let chain_input = format!("{}{}", prev_hash, canonical);
            let expected = sha256_hex(chain_input.as_bytes());
            if !constant_time_eq_hex(&entry.entry_hash, &expected) {
                return false;
            }
            prev_hash = entry.entry_hash.clone();
        }
        true
    }

    /// Reset the ledger (for tests only).
    pub fn reset(&self) {
        self.log.lock().clear();
        *self.last_hash.lock() = "0".repeat(64);
    }
}

impl Default for CryptoTransparencyLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// ApprovedSuitePolicy
// ---------------------------------------------------------------------------

/// Production allowlist and minimum security thresholds.
#[derive(Debug, Clone)]
pub struct ApprovedSuitePolicy {
    pub approved_algorithms: HashSet<String>,
    pub minimum_signature_length: usize,
    pub minimum_public_key_length: usize,
    pub allow_experimental: bool,
    pub suite_status_map: Vec<(String, SuiteStatus)>,
    pub mandatory_baseline: String,
}

impl ApprovedSuitePolicy {
    pub fn is_approved(&self, algorithm: &str) -> bool {
        self.approved_algorithms.contains(algorithm)
    }

    pub fn get_status(&self, algorithm: &str) -> SuiteStatus {
        for (name, status) in &self.suite_status_map {
            if name == algorithm {
                return *status;
            }
        }
        SuiteStatus::Forbidden
    }

    /// Validate suite properties under this policy.
    pub fn validate_suite_properties(
        &self,
        algorithm: &str,
        sig_len: usize,
        pk_len: usize,
    ) -> Result<(), String> {
        let status = self.get_status(algorithm);

        if status == SuiteStatus::Forbidden {
            return Err(format!("Suite '{}' is FORBIDDEN.", algorithm));
        }
        if status == SuiteStatus::Deprecated {
            return Err(format!("Suite '{}' is DEPRECATED.", algorithm));
        }
        if status == SuiteStatus::Experimental && !self.allow_experimental {
            return Err(format!(
                "Suite '{}' is EXPERIMENTAL and allow_experimental=false.",
                algorithm
            ));
        }
        if !self.is_approved(algorithm) {
            return Err(format!(
                "Suite '{}' is not on the approved allowlist.",
                algorithm
            ));
        }
        if sig_len < self.minimum_signature_length {
            return Err(format!(
                "Suite '{}' signature length {}B is below minimum {}B.",
                algorithm, sig_len, self.minimum_signature_length
            ));
        }
        if pk_len < self.minimum_public_key_length {
            return Err(format!(
                "Suite '{}' public key length {}B is below minimum {}B.",
                algorithm, pk_len, self.minimum_public_key_length
            ));
        }
        Ok(())
    }

    /// Validate a runtime suite registration attempt.
    pub fn validate_registration(
        &self,
        algorithm: &str,
        sig_len: usize,
        pk_len: usize,
        deployment_profile: &str,
    ) -> Result<(), String> {
        if deployment_profile == "PRODUCTION" {
            return Err(format!(
                "Runtime registration of '{}' is prohibited in PRODUCTION.",
                algorithm
            ));
        }
        if !self.allow_experimental && !self.is_approved(algorithm) {
            return Err(format!(
                "Suite '{}' is not approved and allow_experimental=false.",
                algorithm
            ));
        }
        self.validate_suite_properties(algorithm, sig_len, pk_len)
    }
}

/// Production policy (C-4 fix: ed25519 governs signature algo baseline;
/// AES-256-GCM-HKDF-SHA256 governs AEAD session encryption — kept separate).
pub fn production_policy() -> ApprovedSuitePolicy {
    let mut approved = HashSet::new();
    approved.insert("ed25519".into());
    // Also mark the AEAD session cipher suite as approved for validate_suite_properties calls
    approved.insert("AES-256-GCM-HKDF-SHA256".into());
    // Post-quantum signature suites (NIST FIPS standardized)
    approved.insert("ml-dsa-65".into());
    approved.insert("slh-dsa".into());
    approved.insert("hybrid-ed25519-ml-dsa-65".into());
    // Post-quantum KEM suites
    approved.insert("ml-kem-768".into());
    approved.insert("ml-kem-1024".into());
    approved.insert("hybrid-x25519-ml-kem-768".into());
    approved.insert("hybrid-p384-ml-kem-1024".into());
    ApprovedSuitePolicy {
        approved_algorithms: approved,
        minimum_signature_length: 64,
        minimum_public_key_length: 32,
        allow_experimental: false,
        suite_status_map: vec![
            ("ed25519".into(), SuiteStatus::Approved),
            ("AES-256-GCM-HKDF-SHA256".into(), SuiteStatus::Approved),
            // Post-quantum signatures
            ("ml-dsa-65".into(), SuiteStatus::Approved),
            ("slh-dsa".into(), SuiteStatus::Approved),
            ("hybrid-ed25519-ml-dsa-65".into(), SuiteStatus::Approved),
            // Post-quantum KEMs
            ("ml-kem-768".into(), SuiteStatus::Approved),
            ("ml-kem-1024".into(), SuiteStatus::Approved),
            ("hybrid-x25519-ml-kem-768".into(), SuiteStatus::Approved),
            ("hybrid-p384-ml-kem-1024".into(), SuiteStatus::Approved),
        ],
        // mandatory_baseline here governs SIGNATURE algorithm (ACSVAF/FAITF signing).
        // Session encryption baseline is governed by CIPHER_SUITE_BASELINE separately.
        mandatory_baseline: "ed25519".into(),
    }
}

/// Lab/development policy.
pub fn lab_policy() -> ApprovedSuitePolicy {
    let mut approved = HashSet::new();
    approved.insert("ed25519".into());
    approved.insert("AES-256-GCM-HKDF-SHA256".into());
    // Post-quantum suites
    approved.insert("ml-dsa-65".into());
    approved.insert("slh-dsa".into());
    approved.insert("hybrid-ed25519-ml-dsa-65".into());
    approved.insert("ml-kem-768".into());
    approved.insert("ml-kem-1024".into());
    approved.insert("hybrid-x25519-ml-kem-768".into());
    approved.insert("hybrid-p384-ml-kem-1024".into());
    ApprovedSuitePolicy {
        approved_algorithms: approved,
        minimum_signature_length: 32,
        minimum_public_key_length: 16,
        allow_experimental: true,
        suite_status_map: vec![
            ("ed25519".into(), SuiteStatus::Approved),
            ("AES-256-GCM-HKDF-SHA256".into(), SuiteStatus::Approved),
            ("ml-dsa-65".into(), SuiteStatus::Approved),
            ("slh-dsa".into(), SuiteStatus::Approved),
            ("hybrid-ed25519-ml-dsa-65".into(), SuiteStatus::Approved),
            ("ml-kem-768".into(), SuiteStatus::Approved),
            ("ml-kem-1024".into(), SuiteStatus::Approved),
            ("hybrid-x25519-ml-kem-768".into(), SuiteStatus::Approved),
            ("hybrid-p384-ml-kem-1024".into(), SuiteStatus::Approved),
        ],
        mandatory_baseline: "ed25519".into(),
    }
}

/// Return the active policy based on deployment profile.
pub fn get_active_policy(deployment_profile: &str) -> ApprovedSuitePolicy {
    match deployment_profile {
        "STAGING" | "DEVELOPMENT" => lab_policy(),
        _ => production_policy(),
    }
}

// ---------------------------------------------------------------------------
// NegotiationTranscript
// ---------------------------------------------------------------------------

/// Immutable, cryptographically-bound record of a suite negotiation.
#[derive(Debug, Clone)]
pub struct NegotiationTranscript {
    pub peer_a_suites: Vec<String>,
    pub peer_b_suites: Vec<String>,
    pub selected_suite: String,
    pub protocol_version: String,
    pub session_id: Vec<u8>,
    pub transcript_hash: Vec<u8>,
    /// #2 FIX: Security tier used during negotiation (PqcRequired, PqcPreferred, ClassicalLegacy).
    /// This binds the negotiation mode into the transcript so a downgrade attempt
    /// that changes the tier is detectable.
    pub security_tier: String,
    /// #2 FIX: Downgrade sentinel value. When a PQC-capable peer ends up in a
    /// classical suite, this is set to DOWNGRADE_SENTINEL_PQC_CAPABLE. A genuine
    /// classical-only peer cannot produce this sentinel, so a stripped negotiation
    /// fails signature verification.
    pub downgrade_sentinel: Vec<u8>,
}

/// Appends a length-prefixed encoding of `items` to `out`: each element is
/// written as a 4-byte big-endian length followed by its raw UTF-8 bytes.
///
/// SECURITY (H-9): plain separator-joining (e.g. `items.join(",")`) is
/// ambiguous when elements may themselves contain the separator — the lists
/// `["a,b", "c"]` and `["a", "b,c"]` both join to `"a,b,c"`, so two different
/// suite negotiations could hash to an identical `transcript_hash`. Length
/// prefixing removes that ambiguity: no two distinct `Vec<String>` values
/// produce the same encoded byte sequence.
fn encode_length_prefixed(items: &[String], out: &mut Vec<u8>) {
    for item in items {
        let len = u32::try_from(item.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(item.as_bytes());
    }
}

impl NegotiationTranscript {
    pub fn new(
        peer_a_suites: Vec<String>,
        peer_b_suites: Vec<String>,
        selected_suite: String,
        protocol_version: String,
        session_id: Vec<u8>,
        security_tier: SecurityTier,
        peer_advertised_pqc: bool,
    ) -> Self {
        // #2 FIX: Compute the downgrade sentinel based on peer capabilities and selected suite.
        // If the peer advertised PQC suites but we ended up classical, this is a potential downgrade.
        let downgrade_sentinel =
            compute_downgrade_sentinel(peer_advertised_pqc, &selected_suite).to_vec();

        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"|A|");
        encode_length_prefixed(&peer_a_suites, &mut canonical);
        canonical.extend_from_slice(b"|B|");
        encode_length_prefixed(&peer_b_suites, &mut canonical);
        canonical.extend_from_slice(b"|S|");
        canonical.extend_from_slice(selected_suite.as_bytes());
        canonical.extend_from_slice(b"|V|");
        canonical.extend_from_slice(protocol_version.as_bytes());
        canonical.extend_from_slice(b"|ID|");
        canonical.extend_from_slice(&session_id);
        // #2 FIX: Include security tier and downgrade sentinel in transcript hash.
        // This binds the negotiation mode into the transcript so any tampering is detectable.
        canonical.extend_from_slice(b"|T|");
        canonical.extend_from_slice(security_tier.as_str().as_bytes());
        canonical.extend_from_slice(b"|D|");
        canonical.extend_from_slice(&downgrade_sentinel);

        let mut hasher = Sha256::new();
        hasher.update(&canonical);
        let transcript_hash = hasher.finalize().to_vec();

        Self {
            peer_a_suites,
            peer_b_suites,
            selected_suite,
            protocol_version,
            session_id,
            transcript_hash,
            security_tier: security_tier.as_str().to_string(),
            downgrade_sentinel,
        }
    }

    pub fn transcript_hash_hex(&self) -> String {
        hex::encode(&self.transcript_hash)
    }
}

// ---------------------------------------------------------------------------
// Signed Negotiation Transcript (Downgrade Prevention)
// ---------------------------------------------------------------------------

/// A negotiation transcript signed with a hybrid signature to prevent
/// downgrade attacks. An active MITM cannot strip PQC suites from the
/// advertisement without invalidating the signature.
#[derive(Debug, Clone)]
pub struct SignedNegotiationTranscript {
    /// The underlying unsigned transcript.
    pub transcript: NegotiationTranscript,
    /// Hybrid signature (Ed25519 + ML-DSA) over the transcript hash.
    pub signature: Vec<u8>,
    /// Public key of the signer (for verification).
    pub signer_public_key: Vec<u8>,
    /// Signature algorithm used.
    pub algorithm: String,
}

impl SignedNegotiationTranscript {
    /// Create a signed transcript from an existing transcript and signature suite.
    pub fn sign(
        transcript: NegotiationTranscript,
        signer_keypair: &crate::pqc::signature::HybridKeypair,
        suite: &crate::pqc::signature::HybridEd25519MlDsa65,
    ) -> Result<Self, crate::pqc::PqcError> {
        let sig = suite.sign_hybrid(signer_keypair, &transcript.transcript_hash, None)?;
        // Length-prefixed hybrid public key: [4-byte len][Ed25519 PK][4-byte len][ML-DSA PK]
        // This allows `verify` to correctly split the two keys regardless of their sizes.
        let mut signer_public_key = Vec::new();
        signer_public_key
            .extend_from_slice(&(signer_keypair.ed25519_public.len() as u32).to_be_bytes());
        signer_public_key.extend_from_slice(&signer_keypair.ed25519_public);
        signer_public_key
            .extend_from_slice(&(signer_keypair.ml_dsa_public.len() as u32).to_be_bytes());
        signer_public_key.extend_from_slice(&signer_keypair.ml_dsa_public);
        Ok(Self {
            transcript,
            signature: sig.to_bytes(),
            signer_public_key,
            algorithm: "hybrid-ed25519-ml-dsa-65".to_string(),
        })
    }

    /// Verify the signature over the transcript hash.
    ///
    /// Correctly deserializes the length-prefixed hybrid public key
    /// (Ed25519 PK is 32 bytes, ML-DSA PK is 1952 bytes — the two
    /// cannot be split at a hardcoded offset).
    pub fn verify(&self, suite: &crate::pqc::signature::HybridEd25519MlDsa65) -> bool {
        // Deserialize the hybrid public key using the same length-prefixed
        // format that `sign()` uses when concatenating the two public keys.
        let pk_bytes = &self.signer_public_key;
        if pk_bytes.len() < 8 {
            return false;
        }
        // Read length-prefixed Ed25519 public key
        let ed25519_len =
            u32::from_be_bytes([pk_bytes[0], pk_bytes[1], pk_bytes[2], pk_bytes[3]]) as usize;
        if ed25519_len != 32 || pk_bytes.len() < 4 + ed25519_len + 4 {
            return false;
        }
        let ed25519_public = pk_bytes[4..4 + ed25519_len].to_vec();
        // Read length-prefixed ML-DSA public key
        let ml_dsa_offset = 4 + ed25519_len;
        let ml_dsa_len = u32::from_be_bytes([
            pk_bytes[ml_dsa_offset],
            pk_bytes[ml_dsa_offset + 1],
            pk_bytes[ml_dsa_offset + 2],
            pk_bytes[ml_dsa_offset + 3],
        ]) as usize;
        if pk_bytes.len() < ml_dsa_offset + 4 + ml_dsa_len {
            return false;
        }
        let ml_dsa_public = pk_bytes[ml_dsa_offset + 4..ml_dsa_offset + 4 + ml_dsa_len].to_vec();

        let keypair = crate::pqc::signature::HybridKeypair {
            ed25519_public,
            ed25519_secret: vec![],
            ml_dsa_public,
            ml_dsa_secret: vec![],
        };
        let sig = match crate::pqc::signature::HybridSignature::from_bytes(&self.signature) {
            Ok(s) => s,
            Err(_) => return false,
        };
        suite.verify_hybrid(&keypair, &self.transcript.transcript_hash, &sig, None)
    }
}

// ---------------------------------------------------------------------------
// Channel Binding
// ---------------------------------------------------------------------------

/// Derive a channel-bound token that ties a session token to the exact
/// handshake transcript. This prevents session hijacking where a stolen
/// token is replayed on a different channel.
///
/// # Arguments
/// * `transcript_hash` - The handshake transcript hash
/// * `session_secret` - The session's shared secret
/// * `agent_id` - The agent identifier
///
/// # Returns
/// A 32-byte channel-bound token that is unique to this channel.
pub fn derive_channel_binding_token(
    transcript_hash: &[u8],
    session_secret: &[u8],
    agent_id: &str,
) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha384;

    let mut ikm = Vec::with_capacity(transcript_hash.len() + session_secret.len() + agent_id.len());
    ikm.extend_from_slice(session_secret);
    ikm.extend_from_slice(transcript_hash);
    ikm.extend_from_slice(agent_id.as_bytes());

    let hk = Hkdf::<Sha384>::new(Some(b"SAACP-channel-binding-salt-v1"), &ikm);
    let mut okm = [0u8; 32];
    hk.expand(crate::pqc::domain_separation::CHANNEL_BINDING, &mut okm)
        .expect("HKDF-SHA384 expand: output length 32 is always valid");
    okm.to_vec()
}

/// Verify a channel-bound token against the expected transcript.
pub fn verify_channel_binding_token(
    token: &[u8],
    transcript_hash: &[u8],
    session_secret: &[u8],
    agent_id: &str,
) -> bool {
    let expected = derive_channel_binding_token(transcript_hash, session_secret, agent_id);
    crate::security::constant_time_eq(token, &expected)
}

// ---------------------------------------------------------------------------
// SuiteNegotiator
// ---------------------------------------------------------------------------

/// Protocol version string.
pub const PROTOCOL_VERSION: &str = "SAACP/0.2-beta1";

/// Enforces cryptographic suite selection under the governance policy.
pub struct SuiteNegotiator;

impl SuiteNegotiator {
    /// Negotiate a cryptographic suite and return a bound NegotiationTranscript.
    ///
    /// #8 FIX: The `security_tier` parameter enforces a hard PQC floor.
    /// When `SecurityTier::PqcRequired` is specified, any non-hybrid suite
    /// selection fails closed with a distinct `PqcRequiredError` — the negotiation
    /// will never silently degrade to classical.
    pub fn negotiate(
        local_suites: &[&str],
        remote_suites: &[&str],
        session_id: &[u8],
        protocol_version: Option<&str>,
        policy: Option<&ApprovedSuitePolicy>,
        ledger: &CryptoTransparencyLedger,
        security_tier: Option<SecurityTier>,
    ) -> Result<NegotiationTranscript, String> {
        let default_policy = production_policy();
        let policy = policy.unwrap_or(&default_policy);
        let pv = protocol_version.unwrap_or(PROTOCOL_VERSION);
        let session_hex = hex::encode(session_id);
        let ts = now_epoch_secs();
        let tier = security_tier.unwrap_or(SecurityTier::PqcPreferred);

        // Log advertisement
        ledger.append(CryptoLedgerEntry {
            timestamp: ts,
            event_type: "NEGOTIATION".into(),
            suite_name: "(advertisement)".into(),
            session_id: session_hex.clone(),
            outcome: "PENDING".into(),
            transcript_hash: String::new(),
            details: format!(
                "Local advertised: {:?}; Remote advertised: {:?}; Tier: {}",
                local_suites,
                remote_suites,
                tier.as_str()
            ),
            entry_hash: String::new(),
        });

        // SECURITY FIX (FINDING-5): suite names were compared with exact byte
        // equality, so a MITM (or a differently-cased peer implementation) that
        // lowercases in-transit suite advertisement bytes causes two otherwise
        // fully-compatible peers to fail negotiation (protocol-level DoS). Suite
        // presence/matching is now case-insensitive; the canonical (as-configured)
        // casing from `local_suites` is still what gets selected and recorded.
        let remote_set_upper: HashSet<String> =
            remote_suites.iter().map(|s| s.to_uppercase()).collect();
        let local_set_upper: HashSet<String> =
            local_suites.iter().map(|s| s.to_uppercase()).collect();

        // Mandatory baseline enforcement
        let baseline = &policy.mandatory_baseline;
        let baseline_upper = baseline.to_uppercase();
        let local_has = local_set_upper.contains(&baseline_upper);
        let remote_has = remote_set_upper.contains(&baseline_upper);
        if !local_has || !remote_has {
            let missing = if !local_has { "local" } else { "remote" };
            ledger.append(CryptoLedgerEntry {
                timestamp: now_epoch_secs(),
                event_type: "DOWNGRADE_ATTEMPT".into(),
                suite_name: baseline.clone(),
                session_id: session_hex.clone(),
                outcome: "BLOCKED".into(),
                transcript_hash: String::new(),
                details: format!(
                    "Mandatory baseline suite '{}' absent from {} peer advertisement.",
                    baseline, missing
                ),
                entry_hash: String::new(),
            });
            return Err(format!(
                "Mandatory baseline suite '{}' is absent from the {} peer's advertisement list.",
                baseline, missing
            ));
        }

        // Select first approved common suite (preference order = local order)
        let mut selected: Option<&str> = None;
        for candidate in local_suites {
            if !remote_set_upper.contains(&candidate.to_uppercase()) {
                continue;
            }
            if !policy.is_approved(candidate) {
                ledger.append(CryptoLedgerEntry {
                    timestamp: now_epoch_secs(),
                    event_type: "DOWNGRADE_ATTEMPT".into(),
                    suite_name: candidate.to_string(),
                    session_id: session_hex.clone(),
                    outcome: "BLOCKED".into(),
                    transcript_hash: String::new(),
                    details: format!(
                        "Suite '{}' is common but not approved. Downgrade blocked.",
                        candidate
                    ),
                    entry_hash: String::new(),
                });
                continue;
            }
            selected = Some(candidate);
            break;
        }

        let selected = selected.ok_or_else(|| {
            ledger.append(CryptoLedgerEntry {
                timestamp: now_epoch_secs(),
                event_type: "NEGOTIATION".into(),
                suite_name: "(none)".into(),
                session_id: session_hex.clone(),
                outcome: "REJECTED".into(),
                transcript_hash: String::new(),
                details: "No approved suite in common.".into(),
                entry_hash: String::new(),
            });
            "No approved algorithm is common to both peers.".to_string()
        })?;

        // #8 FIX: Enforce the security tier. If PQC is required but the selected
        // suite is classical-only, fail closed with a distinct error.
        if tier.requires_pqc() && is_classical_suite(selected) {
            ledger.append(CryptoLedgerEntry {
                timestamp: now_epoch_secs(),
                event_type: "DOWNGRADE_ATTEMPT".into(),
                suite_name: selected.to_string(),
                session_id: session_hex.clone(),
                outcome: "BLOCKED".into(),
                transcript_hash: String::new(),
                details: format!(
                    "Security tier {} requires PQC, but only classical suite '{}' is available. Failing closed.",
                    tier.as_str(), selected
                ),
                entry_hash: String::new(),
            });
            return Err(format!(
                "PQC_REQUIRED_VIOLATION: Security tier '{}' mandates a hybrid/PQC suite, but only classical suite '{}' is available. Negotiation aborted to prevent downgrade.",
                tier.as_str(), selected
            ));
        }

        // #8 FIX: Log when a PQC-capable peer falls back to classical (audit trail)
        if tier.allows_classical() && is_classical_suite(selected) {
            let peer_advertised_pqc = remote_suites.iter().any(|s| is_hybrid_suite(s));
            if peer_advertised_pqc {
                ledger.append(CryptoLedgerEntry {
                    timestamp: now_epoch_secs(),
                    event_type: "PQC_DEGRADATION".into(),
                    suite_name: selected.to_string(),
                    session_id: session_hex.clone(),
                    outcome: "DEGRADED".into(),
                    transcript_hash: String::new(),
                    details: format!(
                        "Peer advertised PQC suites but negotiation selected classical '{}'. Downgrade sentinel: {:?}",
                        selected,
                        String::from_utf8_lossy(compute_downgrade_sentinel(true, selected))
                    ),
                    entry_hash: String::new(),
                });
            }
        }

        // #2 FIX: Determine if the remote peer advertised any PQC suites.
        // This is used to compute the downgrade sentinel.
        let peer_advertised_pqc = remote_suites.iter().any(|s| is_hybrid_suite(s));

        let transcript = NegotiationTranscript::new(
            local_suites.iter().map(|s| s.to_string()).collect(),
            remote_suites.iter().map(|s| s.to_string()).collect(),
            selected.to_string(),
            pv.to_string(),
            session_id.to_vec(),
            tier,
            peer_advertised_pqc,
        );

        ledger.append(CryptoLedgerEntry {
            timestamp: now_epoch_secs(),
            event_type: "NEGOTIATION".into(),
            suite_name: selected.to_string(),
            session_id: session_hex,
            outcome: "SELECTED".into(),
            transcript_hash: transcript.transcript_hash_hex(),
            details: format!(
                "Suite '{}' selected under tier {} and bound to session transcript.",
                selected,
                tier.as_str()
            ),
            entry_hash: String::new(),
        });

        Ok(transcript)
    }

    /// Log a suite rotation event.
    pub fn log_rotation(
        ledger: &CryptoTransparencyLedger,
        old_suite: &str,
        new_suite: &str,
        session_id: &[u8],
        reason: &str,
    ) {
        ledger.append(CryptoLedgerEntry {
            timestamp: now_epoch_secs(),
            event_type: "ROTATION".into(),
            suite_name: new_suite.into(),
            session_id: hex::encode(session_id),
            outcome: "APPROVED".into(),
            transcript_hash: String::new(),
            details: format!(
                "Rotated from '{}' to '{}'. {}",
                old_suite, new_suite, reason
            ),
            entry_hash: String::new(),
        });
    }

    /// Log a deprecation event.
    pub fn log_deprecation(ledger: &CryptoTransparencyLedger, suite: &str, reason: &str) {
        ledger.append(CryptoLedgerEntry {
            timestamp: now_epoch_secs(),
            event_type: "DEPRECATION".into(),
            suite_name: suite.into(),
            session_id: String::new(),
            outcome: "BLOCKED".into(),
            transcript_hash: String::new(),
            details: format!("Suite '{}' deprecated. {}", suite, reason),
            entry_hash: String::new(),
        });
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// ── Module-level policy singletons (matching Python PRODUCTION_POLICY / LAB_POLICY) ──

/// Process-wide production [`ApprovedSuitePolicy`] singleton.
/// Matches Python's `PRODUCTION_POLICY` module-level variable.
pub static PRODUCTION_POLICY: std::sync::LazyLock<ApprovedSuitePolicy> =
    std::sync::LazyLock::new(production_policy);

/// Process-wide lab [`ApprovedSuitePolicy`] singleton.
/// Matches Python's `LAB_POLICY` module-level variable.
pub static LAB_POLICY: std::sync::LazyLock<ApprovedSuitePolicy> =
    std::sync::LazyLock::new(lab_policy);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_status() {
        assert_eq!(SuiteStatus::parse("APPROVED"), SuiteStatus::Approved);
        assert_eq!(SuiteStatus::parse("FORBIDDEN"), SuiteStatus::Forbidden);
        assert_eq!(SuiteStatus::parse("unknown"), SuiteStatus::Forbidden);
    }

    #[test]
    fn test_production_policy() {
        let p = production_policy();
        assert!(p.is_approved("ed25519"));
        assert!(!p.is_approved("rsa-2048"));
        assert_eq!(p.get_status("ed25519"), SuiteStatus::Approved);
        assert_eq!(p.get_status("unknown"), SuiteStatus::Forbidden);
    }

    #[test]
    fn test_ledger_append_and_verify() {
        let ledger = CryptoTransparencyLedger::new();
        ledger.append(CryptoLedgerEntry {
            timestamp: 1.0,
            event_type: "TEST".into(),
            suite_name: "ed25519".into(),
            session_id: "".into(),
            outcome: "APPROVED".into(),
            transcript_hash: "".into(),
            details: "test entry".into(),
            entry_hash: String::new(),
        });
        assert_eq!(ledger.entries().len(), 1);
        assert!(ledger.verify_chain());
    }

    /// H-10 regression: control characters and quote/backslash sequences in
    /// ledger fields must round-trip through the hash chain correctly (full
    /// JSON escaping), and two entries that would have collided under the
    /// old partial-escaping `format!` encoding must now hash differently.
    #[test]
    fn test_ledger_entry_hash_full_json_escaping() {
        let ledger = CryptoTransparencyLedger::new();
        ledger.append(CryptoLedgerEntry {
            timestamp: 1.0,
            event_type: "TEST".into(),
            suite_name: "ed25519".into(),
            session_id: "sess-1".into(),
            outcome: "APPROVED".into(),
            transcript_hash: "".into(),
            details: "evil\": \\ \n\t injected \"entry_hash\":\"forged".into(),
            entry_hash: String::new(),
        });
        ledger.append(CryptoLedgerEntry {
            timestamp: 2.0,
            event_type: "TEST".into(),
            suite_name: "ed25519".into(),
            session_id: "sess-2".into(),
            outcome: "APPROVED".into(),
            transcript_hash: "".into(),
            details: "control\r\nchars\u{0001}\u{0007}here".into(),
            entry_hash: String::new(),
        });
        assert_eq!(ledger.entries().len(), 2);
        assert!(
            ledger.verify_chain(),
            "hash chain must remain self-consistent with control characters and \
             quote/backslash sequences embedded in ledger fields"
        );

        // Direct structural proof: the old `format!`-based encoding only ever
        // escaped `\`/`"` inside `details` — every other field (event_type,
        // outcome, session_id, suite_name, transcript_hash) was interpolated
        // raw, so an embedded quote there corrupted the JSON structure
        // itself (premature string close, attacker-controlled bytes spliced
        // into the "canonical" form). Prove the new encoding is valid,
        // round-trippable JSON even when the injection-prone characters are
        // in one of those previously-unescaped fields.
        let evil = CryptoLedgerEntry {
            timestamp: 3.0,
            event_type: "A\",\"outcome\":\"FORGED".into(),
            suite_name: "ed25519\n".into(),
            session_id: "sid\t\"".into(),
            outcome: "APPROVED".into(),
            transcript_hash: "".into(),
            details: "x".into(),
            entry_hash: String::new(),
        };
        let encoded = canonical_json(&evil);
        let parsed: serde_json::Value = serde_json::from_str(&encoded)
            .expect("canonical_json output must always be valid, parseable JSON");
        assert_eq!(parsed["event_type"], "A\",\"outcome\":\"FORGED");
        assert_eq!(parsed["outcome"], "APPROVED");
        assert_eq!(parsed["suite_name"], "ed25519\n");
        assert_eq!(parsed["session_id"], "sid\t\"");
    }

    #[test]
    fn test_negotiation_success() {
        let ledger = CryptoTransparencyLedger::new();
        let policy = production_policy();
        let result = SuiteNegotiator::negotiate(
            &["ed25519"],
            &["ed25519"],
            b"session-1",
            None,
            Some(&policy),
            &ledger,
            None,
        );
        assert!(result.is_ok());
        let t = result.unwrap();
        assert_eq!(t.selected_suite, "ed25519");
        assert!(!t.transcript_hash.is_empty());
    }

    #[test]
    fn test_negotiation_baseline_missing() {
        let ledger = CryptoTransparencyLedger::new();
        let policy = production_policy();
        let result = SuiteNegotiator::negotiate(
            &["ed25519"],
            &[],
            b"session-1",
            None,
            Some(&policy),
            &ledger,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_negotiation_no_common() {
        let ledger = CryptoTransparencyLedger::new();
        let mut approved = HashSet::new();
        approved.insert("ed25519".into());
        approved.insert("ml-dsa-65".into());
        let policy = ApprovedSuitePolicy {
            approved_algorithms: approved,
            minimum_signature_length: 32,
            minimum_public_key_length: 16,
            allow_experimental: false,
            suite_status_map: vec![
                ("ed25519".into(), SuiteStatus::Approved),
                ("ml-dsa-65".into(), SuiteStatus::Approved),
            ],
            mandatory_baseline: "ed25519".into(),
        };
        // Both advertise baseline, but no other common approved suite
        // This should still succeed because ed25519 is common
        let result = SuiteNegotiator::negotiate(
            &["ed25519"],
            &["ed25519"],
            b"s1",
            None,
            Some(&policy),
            &ledger,
            None,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_negotiation_transcript_hash() {
        let t1 = NegotiationTranscript::new(
            vec!["ed25519".into()],
            vec!["ed25519".into()],
            "ed25519".into(),
            "SAACP/0.2-beta1".into(),
            b"session".to_vec(),
            SecurityTier::PqcPreferred,
            false,
        );
        let t2 = NegotiationTranscript::new(
            vec!["ed25519".into()],
            vec!["ed25519".into()],
            "ed25519".into(),
            "SAACP/0.2-beta1".into(),
            b"session".to_vec(),
            SecurityTier::PqcPreferred,
            false,
        );
        assert_eq!(t1.transcript_hash_hex(), t2.transcript_hash_hex());
    }

    /// H-9 regression: separator-ambiguous suite lists must NOT collide.
    /// `["a,b", "c"]` and `["a", "b,c"]` both joined to the byte-identical
    /// string "a,b,c" under the old comma-join encoding, producing the same
    /// transcript_hash for two genuinely different negotiations.
    #[test]
    fn test_negotiation_transcript_hash_no_suite_list_collision() {
        let t1 = NegotiationTranscript::new(
            vec!["a,b".into(), "c".into()],
            vec!["ed25519".into()],
            "ed25519".into(),
            "SAACP/0.2-beta1".into(),
            b"session".to_vec(),
            SecurityTier::PqcPreferred,
            false,
        );
        let t2 = NegotiationTranscript::new(
            vec!["a".into(), "b,c".into()],
            vec!["ed25519".into()],
            "ed25519".into(),
            "SAACP/0.2-beta1".into(),
            b"session".to_vec(),
            SecurityTier::PqcPreferred,
            false,
        );
        assert_ne!(t1.transcript_hash_hex(), t2.transcript_hash_hex());
    }

    #[test]
    fn test_validate_registration() {
        let p = production_policy();
        assert!(p
            .validate_registration("ed25519", 64, 32, "PRODUCTION")
            .is_err());
        assert!(p
            .validate_registration("ed25519", 64, 32, "DEVELOPMENT")
            .is_ok());
    }

    /// Task: suite_negotiator_downgrade_logs_event
    /// When the mandatory baseline is missing from one peer, DOWNGRADE_ATTEMPT must be logged.
    #[test]
    fn suite_negotiator_downgrade_logs_event() {
        let ledger = CryptoTransparencyLedger::new();
        // Local has baseline; remote does NOT → downgrade attempt
        let result = SuiteNegotiator::negotiate(
            &["ed25519", "AES-256-GCM-HKDF-SHA256"],
            &["AES-256-GCM-HKDF-SHA256"], // no ed25519 baseline
            b"session-id-test",
            None,
            None, // uses production_policy (baseline="ed25519")
            &ledger,
            None,
        );
        assert!(result.is_err(), "missing baseline must fail negotiation");
        // The ledger must contain a DOWNGRADE_ATTEMPT entry
        let entries = ledger.entries();
        let has_downgrade = entries.iter().any(|e| e.event_type == "DOWNGRADE_ATTEMPT");
        assert!(
            has_downgrade,
            "DOWNGRADE_ATTEMPT must be logged in the ledger"
        );
        let blocked = entries.iter().any(|e| e.outcome == "BLOCKED");
        assert!(blocked, "the downgrade entry must have outcome=BLOCKED");
    }

    /// Task: approved_suite_policy_forbidden_rejected
    /// A suite with status=Forbidden must be reported as Forbidden by get_status(),
    /// and must NOT be in the approved_algorithms set.
    #[test]
    fn approved_suite_policy_forbidden_rejected() {
        let mut policy = production_policy();
        // Add a known-bad suite to the status map as Forbidden
        policy
            .suite_status_map
            .push(("RC4-MD5".into(), SuiteStatus::Forbidden));

        // get_status() must return Forbidden for RC4-MD5
        assert_eq!(
            policy.get_status("RC4-MD5"),
            SuiteStatus::Forbidden,
            "RC4-MD5 status must be Forbidden"
        );
        // is_approved() must return false since RC4-MD5 is not in approved_algorithms
        assert!(
            !policy.is_approved("RC4-MD5"),
            "Forbidden suite must not be in approved_algorithms"
        );
        // Add a Deprecated suite
        policy
            .suite_status_map
            .push(("3DES-CBC-SHA1".into(), SuiteStatus::Deprecated));
        assert_eq!(
            policy.get_status("3DES-CBC-SHA1"),
            SuiteStatus::Deprecated,
            "3DES-CBC-SHA1 status must be Deprecated"
        );
        // Unknown suite defaults to Forbidden (per get_status implementation)
        assert_eq!(
            policy.get_status("unknown-alg"),
            SuiteStatus::Forbidden,
            "Unknown suite must default to Forbidden"
        );
        // Approved baseline ed25519 must still be approved
        assert!(
            policy.is_approved("ed25519"),
            "Approved baseline must still be in approved_algorithms"
        );
        assert_eq!(
            policy.get_status("ed25519"),
            SuiteStatus::Approved,
            "ed25519 status must be Approved"
        );
    }
}
