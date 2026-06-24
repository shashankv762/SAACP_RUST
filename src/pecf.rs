//! saacp/pecf.rs — Protocol Error Confidentiality Framework (PECF)
//!
//! Implements the full PECF specification:
//!
//! 1. ExternalCode       — the 6 generic wire-visible outcome classes.
//! 2. internal_to_external — maps every SAACPBytecodes value to one ExternalCode.
//! 3. DeploymentProfile  — DEVELOPMENT / STAGING / PRODUCTION runtime profiles.
//! 4. SecureDiagnosticLedger (SDL) — thread-safe, in-memory diagnostic store.
//! 5. SREL               — Security Response Equalization Layer.
//! 6. PECFFilter         — single choke-point converting internal exceptions to opaque ExternalResponse.
//! 7. ExternalResponse   — the wire-visible structure returned to the remote peer.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use sha2::{Sha256, Digest};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ---------------------------------------------------------------------------
// Deployment profile
// ---------------------------------------------------------------------------

/// Controls how much detail escapes to the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeploymentProfile {
    /// Full internal detail returned; timing equalisation disabled.
    Development,
    /// Limited debug metadata; timing equalisation enabled.
    Staging,
    /// Strict confidentiality; only ExternalCode + correlation_id.
    Production,
}

impl DeploymentProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Development => "DEVELOPMENT",
            Self::Staging => "STAGING",
            Self::Production => "PRODUCTION",
        }
    }
}

impl Default for DeploymentProfile {
    fn default() -> Self {
        Self::Production
    }
}

/// Global active profile (protected by a Mutex for thread safety).
static ACTIVE_PROFILE: Mutex<DeploymentProfile> = Mutex::new(DeploymentProfile::Production);

/// Return the currently active DeploymentProfile.
pub fn get_active_profile() -> DeploymentProfile {
    *ACTIVE_PROFILE.lock().unwrap()
}

/// Override the active profile (used in tests and admin tooling).
pub fn set_active_profile(profile: DeploymentProfile) {
    *ACTIVE_PROFILE.lock().unwrap() = profile;
}

// ---------------------------------------------------------------------------
// External wire codes — the ONLY codes ever sent to remote peers
// ---------------------------------------------------------------------------

/// Six generic outcome classes safe to transmit over the wire.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalCode {
    /// Malformed / structurally invalid request
    RequestRejected = 0x01,
    /// Auth / capability / signature failure
    AccessDenied = 0x02,
    /// Session-level protocol violation
    SessionTerminated = 0x03,
    /// Rate limit / circuit breaker active
    RateLimited = 0x04,
    /// Transient state issue; caller may retry
    ServiceUnavailable = 0x05,
    /// Catch-all for unmapped internal errors
    InternalFailure = 0x06,
}

impl ExternalCode {
    pub fn name(&self) -> &'static str {
        match self {
            Self::RequestRejected => "REQUEST_REJECTED",
            Self::AccessDenied => "ACCESS_DENIED",
            Self::SessionTerminated => "SESSION_TERMINATED",
            Self::RateLimited => "RATE_LIMITED",
            Self::ServiceUnavailable => "SERVICE_UNAVAILABLE",
            Self::InternalFailure => "INTERNAL_FAILURE",
        }
    }
}

// ---------------------------------------------------------------------------
// Internal → External mapping  (Failure Path Normalisation)
// ---------------------------------------------------------------------------

/// Map an internal SAACPBytecodes value to a generic ExternalCode.
pub fn internal_to_external(bytecode: SAACPBytecodes) -> ExternalCode {
    use SAACPBytecodes as B;
    match bytecode {
        // ── REQUEST_REJECTED ────────────────────────────────────────────
        B::MalformedHeader
        | B::SchemaMismatch
        | B::AmbiguousIntent
        | B::PayloadTooLarge
        | B::StreamStart
        | B::StreamContinuation
        | B::StreamEnd => ExternalCode::RequestRejected,

        // ── ACCESS_DENIED ───────────────────────────────────────────────
        B::InvalidSignature
        | B::TokenExpired
        | B::LateralMovementBlocked
        | B::ScopeViolation
        | B::PromptInjectionDetected
        | B::ActionClassEscalation
        | B::DelegationRejected
        | B::ExternalInputTainted => ExternalCode::AccessDenied,

        // ── SESSION_TERMINATED ──────────────────────────────────────────
        B::EpistemicUncertainty
        | B::BudgetExceeded
        | B::StreamAbort => ExternalCode::SessionTerminated,

        // ── RATE_LIMITED ────────────────────────────────────────────────
        B::CircuitBreakerOpen => ExternalCode::RateLimited,

        // ── SERVICE_UNAVAILABLE ─────────────────────────────────────────
        B::StateExpiredOrStale
        | B::StateSyncRequired
        | B::TemporalTimeout => ExternalCode::ServiceUnavailable,

        // ── Everything else maps to INTERNAL_FAILURE ────────────────────
        _ => ExternalCode::InternalFailure,
    }
}

/// Map a raw bytecode u8 value to ExternalCode (convenience for translate_raw).
pub fn internal_to_external_raw(bytecode: u8) -> ExternalCode {
    use SAACPBytecodes as B;
    // Try to convert the raw byte to a known bytecode, then map.
    let bc = match bytecode {
        0x00 => B::Success,
        0x01 => B::MalformedHeader,
        0x02 => B::SchemaMismatch,
        0x03 => B::InvalidSignature,
        0x04 => B::AmbiguousIntent,
        0x05 => B::LateralMovementBlocked,
        0x06 => B::PromptInjectionDetected,
        0x07 => B::StateExpiredOrStale,
        0x08 => B::InputRequired,
        0x09 => B::BudgetExceeded,
        0x0A => B::PreFlightBudget,
        0x0B => B::CostEstimate,
        0x0C => B::ActionClassEscalation,
        0x0D => B::EpistemicUncertainty,
        0x0E => B::PayloadTooLarge,
        0x0F => B::HeartbeatPing,
        0x10 => B::StateSyncRequired,
        0x11 => B::TemporalTimeout,
        0x12 => B::TokenExpired,
        0x13 => B::ScopeViolation,
        0x14 => B::CircuitBreakerOpen,
        0x15 => B::DelegationRejected,
        0x16 => B::ExternalInputTainted,
        0x17 => B::StreamStart,
        0x18 => B::StreamContinuation,
        0x19 => B::StreamEnd,
        0x1A => B::StreamAbort,
        0x1B => B::PsnReplayDetected,
        0x1C => B::PsnOutOfWindow,
        0x1D => B::EpochExpired,
        0x1E => B::SequenceOverflow,
        0x1F => B::KeyEvolutionRequired,
        0x20 => B::AegfLoopDetected,
        0x21 => B::AegfHopLimitExceeded,
        0x22 => B::AegfDepthLimitExceeded,
        0x23 => B::AegfTtlExpired,
        0x24 => B::AegfInvalidTransition,
        0x25 => B::ScrUnauthorized,
        0x26 => B::ScrNotFound,
        0x27 => B::RrbcReplayDetected,
        0x28 => B::RrbcUsageExhausted,
        0x29 => B::RrbcBindingMismatch,
        0x2A => B::RrbcPopFailed,
        0x2B => B::RgcResourceLimitExceeded,
        0x2C => B::KeyRevoked,
        0x2D => B::KeyVersionMismatch,
        0x2E => B::AcsvafDelegationAmplification,
        0x2F => B::AcsvafDelegationDepthExceeded,
        0x30 => B::AcsvafCircularDelegation,
        0x31 => B::AcsvafOrphanChain,
        0x32 => B::AcsvafMissingCapabilityAuthority,
        0x33 => B::AcsvafKeyNotTrusted,
        0x34 => B::AcsvafThresholdNotReached,
        0x35 => B::AcsvafManifestInvalid,
        0x36 => B::AcsvafSessionBindingViolated,
        0x37 => B::SelfIssuedCapability,
        0x38 => B::UnauthorizedIssuerClass,
        0x39 => B::DelegationMetadataIncomplete,
        0x3A => B::AuthorityClassViolation,
        0x3B => B::FederationRootRequired,
        0x3C => B::IdentityBindingMissing,
        0x3D => B::IdentityMisbinding,
        0x3E => B::TranscriptHashMismatch,
        0x3F => B::IdentityNotVerified,
        0x40 => B::SessionSpliceDetected,
        _ => return ExternalCode::InternalFailure,
    };
    internal_to_external(bc)
}

// ---------------------------------------------------------------------------
// Secure Diagnostic Ledger (SDL)
// ---------------------------------------------------------------------------

/// One immutable diagnostic record stored in the SDL.
#[derive(Debug, Clone)]
pub struct SdlEntry {
    pub correlation_id: String,
    pub timestamp: f64,
    pub internal_bytecode: u8,
    pub internal_message: String,
    pub validation_stage: String,
    pub external_code: ExternalCode,
    pub session_id_hash: String,
    pub ip_hash: String,
    pub deployment_profile: String,
    pub remediation_hint: String,
}

impl SdlEntry {
    /// Serialise this entry to a JSON-compatible map (for admin tooling).
    pub fn to_map(&self) -> Vec<(String, String)> {
        vec![
            ("correlation_id".into(), self.correlation_id.clone()),
            ("timestamp".into(), format!("{}", self.timestamp)),
            ("internal_bytecode".into(), format!("0x{:02X}", self.internal_bytecode)),
            ("internal_message".into(), self.internal_message.clone()),
            ("validation_stage".into(), self.validation_stage.clone()),
            ("external_code".into(), self.external_code.name().into()),
            ("session_id_hash".into(), self.session_id_hash.clone()),
            ("ip_hash".into(), self.ip_hash.clone()),
            ("deployment_profile".into(), self.deployment_profile.clone()),
            ("remediation_hint".into(), self.remediation_hint.clone()),
        ]
    }

    /// Serialise to a JSON string.
    pub fn to_json(&self) -> String {
        let pairs: Vec<String> = self.to_map().iter()
            .map(|(k, v)| format!("\"{}\":\"{}\"", k, v.replace('\\', "\\\\").replace('"', "\\\"")))
            .collect();
        format!("{{{}}}", pairs.join(","))
    }
}

/// Maximum number of entries in the Secure Diagnostic Ledger.
pub const SDL_MAX_ENTRIES: usize = 100_000;

/// Thread-safe, bounded in-memory Secure Diagnostic Ledger.
///
/// All internal failure details are recorded here.
/// This store must NEVER be exposed via the network layer.
pub struct SecureDiagnosticLedger {
    entries: Mutex<VecDeque<SdlEntry>>,
}

impl SecureDiagnosticLedger {
    /// Create a new empty ledger.
    pub fn new() -> Self {
        Self {
            entries: Mutex::new(VecDeque::new()),
        }
    }

    /// Append one diagnostic entry to the ledger (thread-safe).
    pub fn record(&self, entry: SdlEntry) {
        let mut entries = self.entries.lock().unwrap();
        if entries.len() >= SDL_MAX_ENTRIES {
            entries.pop_front(); // evict oldest; preserve most-recent window
        }
        entries.push_back(entry);
    }

    /// Return up to `limit` SDL entries, optionally filtered by correlation_id.
    ///
    /// IMPORTANT: This method must only be called by authorised admin tooling.
    /// It must NEVER be wired to any network-accessible endpoint.
    pub fn query(&self, correlation_id: Option<&str>, limit: usize) -> Vec<SdlEntry> {
        let entries = self.entries.lock().unwrap();
        let filtered: Vec<SdlEntry> = if let Some(cid) = correlation_id {
            entries.iter().filter(|e| e.correlation_id == cid).cloned().collect()
        } else {
            entries.iter().cloned().collect()
        };
        let start = filtered.len().saturating_sub(limit);
        filtered[start..].to_vec()
    }

    /// Wipe the ledger (used in tests).
    pub fn clear(&self) {
        self.entries.lock().unwrap().clear();
    }

    /// Return the current number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap().len()
    }
}

impl Default for SecureDiagnosticLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Security Response Equalization Layer (SREL)
// ---------------------------------------------------------------------------

/// Minimum wall-clock delay (seconds) before a rejection response is sent.
/// Equalises fast vs. slow rejection paths.
pub const SREL_FLOOR_SECONDS: f64 = 0.050; // 50 ms

/// Fixed-size wire response length in bytes.
pub const SREL_WIRE_RESPONSE_SIZE: usize = 64;

/// PECF wire marker byte.
pub const PECF_MARKER: u8 = 0xFE;

/// Security Response Equalization Layer.
///
/// * Enforces a minimum wall-clock delay on rejection paths so that latency
///   cannot distinguish which validation step triggered the rejection.
/// * Normalises the response byte-size to a fixed-length structure so packet
///   length cannot be used as a timing/oracle signal.
pub struct SREL;

impl SREL {
    /// Sleep until at least SREL_FLOOR_SECONDS have elapsed since `start`.
    ///
    /// Does nothing in DEVELOPMENT mode.
    pub fn equalize_timing(start: Instant) {
        if get_active_profile() == DeploymentProfile::Development {
            return;
        }
        let elapsed = start.elapsed().as_secs_f64();
        let remaining = SREL_FLOOR_SECONDS - elapsed;
        if remaining > 0.0 {
            std::thread::sleep(std::time::Duration::from_secs_f64(remaining));
        }
    }

    /// Build a fixed-size, constant-structure wire response.
    ///
    /// Format (64 bytes):
    ///   [1 byte ] PECF marker 0xFE
    ///   [1 byte ] ExternalCode byte value
    ///   [32 bytes] correlation_id (truncated/padded to 32 ASCII bytes)
    ///   [30 bytes] zero padding
    pub fn normalize_response(code: ExternalCode, correlation_id: &str) -> Vec<u8> {
        let mut buf = vec![0u8; SREL_WIRE_RESPONSE_SIZE];
        buf[0] = PECF_MARKER;
        buf[1] = code as u8;
        let corr_bytes = correlation_id.as_bytes();
        let copy_len = corr_bytes.len().min(32);
        buf[2..2 + copy_len].copy_from_slice(&corr_bytes[..copy_len]);
        // remaining bytes stay zero (padding)
        buf
    }
}

// ---------------------------------------------------------------------------
// ExternalResponse — what travels over the wire
// ---------------------------------------------------------------------------

/// The only thing the remote peer ever receives on failure.
#[derive(Debug, Clone)]
pub struct ExternalResponse {
    pub code: ExternalCode,
    pub correlation_id: String,
    /// Only populated in DEVELOPMENT mode.
    pub detail: Option<String>,
}

impl ExternalResponse {
    /// Create a new ExternalResponse.
    pub fn new(code: ExternalCode, correlation_id: String, detail: Option<String>) -> Self {
        Self { code, correlation_id, detail }
    }

    /// Serialise for network transmission.
    ///
    /// PRODUCTION/STAGING: fixed-size, opaque binary blob via SREL.
    /// DEVELOPMENT: JSON envelope (rich diagnostics, for local testing only).
    pub fn to_wire(&self) -> Vec<u8> {
        if get_active_profile() == DeploymentProfile::Development {
            let detail_str = self.detail.as_deref().unwrap_or("");
            let json = format!(
                "{{\"code\":\"{}\",\"correlation_id\":\"{}\",\"detail\":\"{}\"}}",
                self.code.name(),
                self.correlation_id,
                detail_str.replace('\\', "\\\\").replace('"', "\\\""),
            );
            return json.into_bytes();
        }
        // PRODUCTION / STAGING: fixed-size opaque binary
        SREL::normalize_response(self.code, &self.correlation_id)
    }
}

// ---------------------------------------------------------------------------
// PECFFilter — single choke-point at the network boundary
// ---------------------------------------------------------------------------

/// One-way hash a sensitive value (IP address, session UUID) for the SDL.
fn hash_sensitive(value: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value.as_bytes());
    hex::encode(hasher.finalize())
}

/// Hash raw bytes (for session_id).
fn hash_bytes(value: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hex::encode(hasher.finalize())
}

/// Heuristically map a bytecode to a human-readable validation stage name
/// for SDL records. This detail never crosses the wire.
fn infer_stage(bytecode: u8) -> &'static str {
    use SAACPBytecodes as B;
    let framing_codes: &[u8] = &[
        B::MalformedHeader as u8,
        B::PayloadTooLarge as u8,
    ];
    let schema_codes: &[u8] = &[
        B::SchemaMismatch as u8,
        B::AmbiguousIntent as u8,
    ];
    let auth_codes: &[u8] = &[
        B::InvalidSignature as u8,
        B::TokenExpired as u8,
        B::LateralMovementBlocked as u8,
        B::ScopeViolation as u8,
        B::DelegationRejected as u8,
        B::ActionClassEscalation as u8,
    ];
    let replay_codes: &[u8] = &[
        B::CircuitBreakerOpen as u8,
        B::TemporalTimeout as u8,
    ];
    let memory_codes: &[u8] = &[
        B::StateExpiredOrStale as u8,
        B::StateSyncRequired as u8,
    ];

    if framing_codes.contains(&bytecode) {
        "framing"
    } else if schema_codes.contains(&bytecode) {
        "schema_validation"
    } else if auth_codes.contains(&bytecode) {
        "capability_validation"
    } else if replay_codes.contains(&bytecode) {
        "replay_detection"
    } else if memory_codes.contains(&bytecode) {
        "memory_access"
    } else {
        "internal"
    }
}

/// Generate a cryptographically random correlation ID (16 random bytes → 32 hex chars).
fn generate_correlation_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Current wall-clock time as seconds since UNIX epoch.
fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Convert any internal exception into an opaque ExternalResponse.
///
/// This is the single mandatory choke-point between the internal gate
/// pipeline and the network write path.
pub struct PECFFilter;

impl PECFFilter {
    /// Translate a SAACPHardDrop into an opaque ExternalResponse.
    ///
    /// Steps:
    /// 1. Extract the internal bytecode (or fall back to INTERNAL_FAILURE).
    /// 2. Map to ExternalCode via Failure Path Normalisation.
    /// 3. Generate a cryptographically random correlation_id.
    /// 4. Record full internal details in the SDL (never on the wire).
    /// 5. Return an ExternalResponse with only the ExternalCode + correlation_id.
    pub fn translate(
        exc: &SAACPHardDrop,
        ledger: &SecureDiagnosticLedger,
        session_id: &[u8],
        ip: &str,
    ) -> ExternalResponse {
        let bytecode_raw = exc.bytecode as u8;
        let internal_message = &exc.message;

        // Map to ExternalCode (FPN)
        let ext_code = internal_to_external(exc.bytecode);

        // Correlation ID: 16 random bytes → 32 hex chars
        let correlation_id = generate_correlation_id();

        // SDL record (NEVER transmitted)
        let session_id_hash = if session_id.is_empty() {
            String::new()
        } else {
            hash_bytes(session_id)
        };
        let ip_hash = if ip.is_empty() {
            String::new()
        } else {
            hash_sensitive(ip)
        };

        let entry = SdlEntry {
            correlation_id: correlation_id.clone(),
            timestamp: now_epoch_secs(),
            internal_bytecode: bytecode_raw,
            internal_message: internal_message.clone(),
            validation_stage: infer_stage(bytecode_raw).into(),
            external_code: ext_code,
            session_id_hash,
            ip_hash,
            deployment_profile: get_active_profile().as_str().into(),
            remediation_hint: "Check SDL via admin tooling using the correlation_id.".into(),
        };
        ledger.record(entry);

        // Build response
        let detail = if get_active_profile() == DeploymentProfile::Development {
            Some(format!(
                "[DEV] {} (bytecode=0x{:02X})",
                internal_message, bytecode_raw
            ))
        } else {
            None
        };

        ExternalResponse::new(ext_code, correlation_id, detail)
    }

    /// Convenience wrapper when there is no exception object — just a raw bytecode and message.
    pub fn translate_raw(
        bytecode: SAACPBytecodes,
        message: &str,
        ledger: &SecureDiagnosticLedger,
        session_id: &[u8],
        ip: &str,
    ) -> ExternalResponse {
        let exc = SAACPHardDrop::new(bytecode, message);
        Self::translate(&exc, ledger, session_id, ip)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_external_code_values() {
        assert_eq!(ExternalCode::RequestRejected as u8, 0x01);
        assert_eq!(ExternalCode::AccessDenied as u8, 0x02);
        assert_eq!(ExternalCode::SessionTerminated as u8, 0x03);
        assert_eq!(ExternalCode::RateLimited as u8, 0x04);
        assert_eq!(ExternalCode::ServiceUnavailable as u8, 0x05);
        assert_eq!(ExternalCode::InternalFailure as u8, 0x06);
    }

    #[test]
    fn test_internal_to_external_mapping() {
        assert_eq!(internal_to_external(SAACPBytecodes::MalformedHeader), ExternalCode::RequestRejected);
        assert_eq!(internal_to_external(SAACPBytecodes::SchemaMismatch), ExternalCode::RequestRejected);
        assert_eq!(internal_to_external(SAACPBytecodes::InvalidSignature), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external(SAACPBytecodes::TokenExpired), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external(SAACPBytecodes::EpistemicUncertainty), ExternalCode::SessionTerminated);
        assert_eq!(internal_to_external(SAACPBytecodes::BudgetExceeded), ExternalCode::SessionTerminated);
        assert_eq!(internal_to_external(SAACPBytecodes::CircuitBreakerOpen), ExternalCode::RateLimited);
        assert_eq!(internal_to_external(SAACPBytecodes::StateExpiredOrStale), ExternalCode::ServiceUnavailable);
        assert_eq!(internal_to_external(SAACPBytecodes::StreamAbort), ExternalCode::SessionTerminated);
        // Unmapped code → InternalFailure
        assert_eq!(internal_to_external(SAACPBytecodes::Success), ExternalCode::InternalFailure);
        assert_eq!(internal_to_external(SAACPBytecodes::HeartbeatPing), ExternalCode::InternalFailure);
    }

    #[test]
    fn test_internal_to_external_raw() {
        assert_eq!(internal_to_external_raw(0x01), ExternalCode::RequestRejected);
        assert_eq!(internal_to_external_raw(0x03), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external_raw(0xFF), ExternalCode::InternalFailure);
    }

    #[test]
    fn test_srel_normalize_response_format() {
        set_active_profile(DeploymentProfile::Production);
        let resp = SREL::normalize_response(ExternalCode::AccessDenied, "abcd1234");
        assert_eq!(resp.len(), 64);
        assert_eq!(resp[0], 0xFE); // PECF marker
        assert_eq!(resp[1], 0x02); // AccessDenied
        assert_eq!(&resp[2..10], b"abcd1234");
        // Rest is zero-padded
        assert!(resp[10..].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_sdl_record_and_query() {
        let ledger = SecureDiagnosticLedger::new();
        let entry = SdlEntry {
            correlation_id: "test-corr-id".into(),
            timestamp: 1234567890.0,
            internal_bytecode: 0x01,
            internal_message: "test message".into(),
            validation_stage: "framing".into(),
            external_code: ExternalCode::RequestRejected,
            session_id_hash: "".into(),
            ip_hash: "".into(),
            deployment_profile: "PRODUCTION".into(),
            remediation_hint: "".into(),
        };
        ledger.record(entry);
        assert_eq!(ledger.entry_count(), 1);

        let results = ledger.query(Some("test-corr-id"), 100);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].correlation_id, "test-corr-id");

        let results = ledger.query(Some("nonexistent"), 100);
        assert_eq!(results.len(), 0);

        ledger.clear();
        assert_eq!(ledger.entry_count(), 0);
    }

    #[test]
    fn test_sdl_max_entries_eviction() {
        let ledger = SecureDiagnosticLedger::new();
        for i in 0..SDL_MAX_ENTRIES + 10 {
            let entry = SdlEntry {
                correlation_id: format!("cid-{}", i),
                timestamp: i as f64,
                internal_bytecode: 0x01,
                internal_message: "msg".into(),
                validation_stage: "framing".into(),
                external_code: ExternalCode::RequestRejected,
                session_id_hash: "".into(),
                ip_hash: "".into(),
                deployment_profile: "PRODUCTION".into(),
                remediation_hint: "".into(),
            };
            ledger.record(entry);
        }
        assert_eq!(ledger.entry_count(), SDL_MAX_ENTRIES);
        // The oldest 10 entries should have been evicted
        let results = ledger.query(Some("cid-0"), 100);
        assert_eq!(results.len(), 0);
        // The most recent entry should exist
        let last_id = format!("cid-{}", SDL_MAX_ENTRIES + 9);
        let results = ledger.query(Some(&last_id), 100);
        assert_eq!(results.len(), 1);
        ledger.clear();
    }

    #[test]
    fn test_pecf_filter_translate_production() {
        set_active_profile(DeploymentProfile::Production);
        let ledger = SecureDiagnosticLedger::new();
        let exc = SAACPHardDrop::new(SAACPBytecodes::MalformedHeader, "bad header");
        let resp = PECFFilter::translate(&exc, &ledger, b"sess-1", "192.168.1.1");

        assert_eq!(resp.code, ExternalCode::RequestRejected);
        assert_eq!(resp.correlation_id.len(), 32); // 16 bytes hex
        assert!(resp.detail.is_none()); // No detail in production

        // SDL should have one entry
        assert_eq!(ledger.entry_count(), 1);
        let entries = ledger.query(None, 100);
        assert_eq!(entries[0].validation_stage, "framing");
        assert!(!entries[0].session_id_hash.is_empty());
        assert!(!entries[0].ip_hash.is_empty());
        ledger.clear();
    }

    #[test]
    fn test_pecf_filter_translate_development() {
        set_active_profile(DeploymentProfile::Development);
        let ledger = SecureDiagnosticLedger::new();
        let exc = SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "sig mismatch");
        let resp = PECFFilter::translate(&exc, &ledger, &[], "");

        assert_eq!(resp.code, ExternalCode::AccessDenied);
        assert!(resp.detail.is_some());
        assert!(resp.detail.unwrap().contains("[DEV]"));
        ledger.clear();
        set_active_profile(DeploymentProfile::Production);
    }

    #[test]
    fn test_pecf_filter_translate_raw() {
        set_active_profile(DeploymentProfile::Production);
        let ledger = SecureDiagnosticLedger::new();
        let resp = PECFFilter::translate_raw(
            SAACPBytecodes::CircuitBreakerOpen,
            "rate limited",
            &ledger,
            &[],
            "",
        );
        assert_eq!(resp.code, ExternalCode::RateLimited);
        assert_eq!(ledger.entry_count(), 1);
        ledger.clear();
    }

    #[test]
    fn test_external_response_to_wire_production() {
        set_active_profile(DeploymentProfile::Production);
        let resp = ExternalResponse::new(
            ExternalCode::AccessDenied,
            "a".repeat(32),
            None,
        );
        let wire = resp.to_wire();
        assert_eq!(wire.len(), 64);
        assert_eq!(wire[0], 0xFE);
        assert_eq!(wire[1], 0x02);
    }

    #[test]
    fn test_external_response_to_wire_development() {
        set_active_profile(DeploymentProfile::Development);
        let resp = ExternalResponse::new(
            ExternalCode::AccessDenied,
            "corr-id-123".into(),
            Some("debug info".into()),
        );
        let wire = resp.to_wire();
        let json_str = String::from_utf8(wire).unwrap();
        assert!(json_str.contains("ACCESS_DENIED"));
        assert!(json_str.contains("corr-id-123"));
        assert!(json_str.contains("debug info"));
        set_active_profile(DeploymentProfile::Production);
    }

    #[test]
    fn test_infer_stage() {
        assert_eq!(infer_stage(SAACPBytecodes::MalformedHeader as u8), "framing");
        assert_eq!(infer_stage(SAACPBytecodes::SchemaMismatch as u8), "schema_validation");
        assert_eq!(infer_stage(SAACPBytecodes::InvalidSignature as u8), "capability_validation");
        assert_eq!(infer_stage(SAACPBytecodes::CircuitBreakerOpen as u8), "replay_detection");
        assert_eq!(infer_stage(SAACPBytecodes::StateExpiredOrStale as u8), "memory_access");
        assert_eq!(infer_stage(0xFF), "internal");
    }

    #[test]
    fn test_deployment_profile_default() {
        assert_eq!(DeploymentProfile::default(), DeploymentProfile::Production);
    }

    #[test]
    fn test_hash_sensitive() {
        let h1 = hash_sensitive("192.168.1.1");
        let h2 = hash_sensitive("192.168.1.1");
        assert_eq!(h1, h2); // deterministic
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }
}
