//! crypto_governance.rs — Cryptographic Suite Governance and Downgrade Resistance
//!
//! Implements ApprovedSuitePolicy, CryptoTransparencyLedger,
//! NegotiationTranscript, and SuiteNegotiator.

use std::collections::HashSet;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use sha2::{Sha256, Digest};

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

    pub fn from_str(s: &str) -> Self {
        match s {
            "APPROVED" => Self::Approved,
            "EXPERIMENTAL" => Self::Experimental,
            "DEPRECATED" => Self::Deprecated,
            _ => Self::Forbidden,
        }
    }
}

/// Signature algorithm baseline — Ed25519.
pub const SIGNATURE_ALGO_BASELINE: &str = "ed25519";
/// Cipher suite baseline.
pub const CIPHER_SUITE_BASELINE: &str = "ed25519";

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

/// Append-only, hash-chained ledger of all cryptographic governance events.
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
        let canonical = format!(
            "{{\"details\":\"{}\",\"event_type\":\"{}\",\"outcome\":\"{}\",\"session_id\":\"{}\",\"suite_name\":\"{}\",\"timestamp\":{},\"transcript_hash\":\"{}\"}}",
            entry.details.replace('\\', "\\\\").replace('"', "\\\""),
            entry.event_type,
            entry.outcome,
            entry.session_id,
            entry.suite_name,
            entry.timestamp,
            entry.transcript_hash,
        );
        let prev = self.last_hash.lock().unwrap().clone();
        let chain_input = format!("{}{}", prev, canonical);
        let hash = sha256_hex(chain_input.as_bytes());
        entry.entry_hash = hash.clone();
        *self.last_hash.lock().unwrap() = hash;
        self.log.lock().unwrap().push(entry);
    }

    /// Return all entries.
    pub fn entries(&self) -> Vec<CryptoLedgerEntry> {
        self.log.lock().unwrap().clone()
    }

    /// Verify the hash chain integrity.
    pub fn verify_chain(&self) -> bool {
        let log = self.log.lock().unwrap();
        let mut prev_hash = "0".repeat(64);
        for entry in log.iter() {
            let canonical = format!(
                "{{\"details\":\"{}\",\"event_type\":\"{}\",\"outcome\":\"{}\",\"session_id\":\"{}\",\"suite_name\":\"{}\",\"timestamp\":{},\"transcript_hash\":\"{}\"}}",
                entry.details.replace('\\', "\\\\").replace('"', "\\\""),
                entry.event_type,
                entry.outcome,
                entry.session_id,
                entry.suite_name,
                entry.timestamp,
                entry.transcript_hash,
            );
            let chain_input = format!("{}{}", prev_hash, canonical);
            let expected = sha256_hex(chain_input.as_bytes());
            if entry.entry_hash != expected {
                return false;
            }
            prev_hash = entry.entry_hash.clone();
        }
        true
    }

    /// Reset the ledger (for tests only).
    pub fn reset(&self) {
        self.log.lock().unwrap().clear();
        *self.last_hash.lock().unwrap() = "0".repeat(64);
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
            return Err(format!("Suite '{}' is not on the approved allowlist.", algorithm));
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

/// Production policy.
pub fn production_policy() -> ApprovedSuitePolicy {
    let mut approved = HashSet::new();
    approved.insert("ed25519".into());
    ApprovedSuitePolicy {
        approved_algorithms: approved,
        minimum_signature_length: 64,
        minimum_public_key_length: 32,
        allow_experimental: false,
        suite_status_map: vec![("ed25519".into(), SuiteStatus::Approved)],
        mandatory_baseline: "ed25519".into(),
    }
}

/// Lab/development policy.
pub fn lab_policy() -> ApprovedSuitePolicy {
    let mut approved = HashSet::new();
    approved.insert("ed25519".into());
    ApprovedSuitePolicy {
        approved_algorithms: approved,
        minimum_signature_length: 32,
        minimum_public_key_length: 16,
        allow_experimental: true,
        suite_status_map: vec![("ed25519".into(), SuiteStatus::Approved)],
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
}

impl NegotiationTranscript {
    pub fn new(
        peer_a_suites: Vec<String>,
        peer_b_suites: Vec<String>,
        selected_suite: String,
        protocol_version: String,
        session_id: Vec<u8>,
    ) -> Self {
        let mut canonical = Vec::new();
        canonical.extend_from_slice(b"|A|");
        canonical.extend_from_slice(peer_a_suites.join(",").as_bytes());
        canonical.extend_from_slice(b"|B|");
        canonical.extend_from_slice(peer_b_suites.join(",").as_bytes());
        canonical.extend_from_slice(b"|S|");
        canonical.extend_from_slice(selected_suite.as_bytes());
        canonical.extend_from_slice(b"|V|");
        canonical.extend_from_slice(protocol_version.as_bytes());
        canonical.extend_from_slice(b"|ID|");
        canonical.extend_from_slice(&session_id);

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
        }
    }

    pub fn transcript_hash_hex(&self) -> String {
        hex::encode(&self.transcript_hash)
    }
}

// ---------------------------------------------------------------------------
// SuiteNegotiator
// ---------------------------------------------------------------------------

/// Protocol version string.
pub const PROTOCOL_VERSION: &str = "SAACP/0.1-beta2";

/// Enforces cryptographic suite selection under the governance policy.
pub struct SuiteNegotiator;

impl SuiteNegotiator {
    /// Negotiate a cryptographic suite and return a bound NegotiationTranscript.
    pub fn negotiate(
        local_suites: &[&str],
        remote_suites: &[&str],
        session_id: &[u8],
        protocol_version: Option<&str>,
        policy: Option<&ApprovedSuitePolicy>,
        ledger: &CryptoTransparencyLedger,
    ) -> Result<NegotiationTranscript, String> {
        let default_policy = production_policy();
        let policy = policy.unwrap_or(&default_policy);
        let pv = protocol_version.unwrap_or(PROTOCOL_VERSION);
        let session_hex = hex::encode(session_id);
        let ts = now_epoch_secs();

        // Log advertisement
        ledger.append(CryptoLedgerEntry {
            timestamp: ts,
            event_type: "NEGOTIATION".into(),
            suite_name: "(advertisement)".into(),
            session_id: session_hex.clone(),
            outcome: "PENDING".into(),
            transcript_hash: String::new(),
            details: format!(
                "Local advertised: {:?}; Remote advertised: {:?}",
                local_suites, remote_suites
            ),
            entry_hash: String::new(),
        });

        let remote_set: HashSet<&str> = remote_suites.iter().copied().collect();
        let local_set: HashSet<&str> = local_suites.iter().copied().collect();

        // Mandatory baseline enforcement
        let baseline = &policy.mandatory_baseline;
        let local_has = local_set.contains(baseline.as_str());
        let remote_has = remote_set.contains(baseline.as_str());
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
            if !remote_set.contains(candidate) {
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

        let transcript = NegotiationTranscript::new(
            local_suites.iter().map(|s| s.to_string()).collect(),
            remote_suites.iter().map(|s| s.to_string()).collect(),
            selected.to_string(),
            pv.to_string(),
            session_id.to_vec(),
        );

        ledger.append(CryptoLedgerEntry {
            timestamp: now_epoch_secs(),
            event_type: "NEGOTIATION".into(),
            suite_name: selected.to_string(),
            session_id: session_hex,
            outcome: "SELECTED".into(),
            transcript_hash: transcript.transcript_hash_hex(),
            details: format!("Suite '{}' selected and bound to session transcript.", selected),
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
            details: format!("Rotated from '{}' to '{}'. {}", old_suite, new_suite, reason),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_suite_status() {
        assert_eq!(SuiteStatus::from_str("APPROVED"), SuiteStatus::Approved);
        assert_eq!(SuiteStatus::from_str("FORBIDDEN"), SuiteStatus::Forbidden);
        assert_eq!(SuiteStatus::from_str("unknown"), SuiteStatus::Forbidden);
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
        );
        assert!(result.is_ok());
    }

    #[test]
    fn test_negotiation_transcript_hash() {
        let t1 = NegotiationTranscript::new(
            vec!["ed25519".into()],
            vec!["ed25519".into()],
            "ed25519".into(),
            "SAACP/0.1-beta2".into(),
            b"session".to_vec(),
        );
        let t2 = NegotiationTranscript::new(
            vec!["ed25519".into()],
            vec!["ed25519".into()],
            "ed25519".into(),
            "SAACP/0.1-beta2".into(),
            b"session".to_vec(),
        );
        assert_eq!(t1.transcript_hash_hex(), t2.transcript_hash_hex());
    }

    #[test]
    fn test_validate_registration() {
        let p = production_policy();
        assert!(p.validate_registration("ed25519", 64, 32, "PRODUCTION").is_err());
        assert!(p.validate_registration("ed25519", 64, 32, "DEVELOPMENT").is_ok());
    }
}
