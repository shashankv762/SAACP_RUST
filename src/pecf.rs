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
#[derive(Default)]
pub enum DeploymentProfile {
    /// Full internal detail returned; timing equalisation disabled.
    Development,
    /// Limited debug metadata; timing equalisation enabled.
    Staging,
    /// Strict confidentiality; only ExternalCode + correlation_id.
    #[default]
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


/// Backing state for the global active profile: the profile itself plus
/// whether it was ever set programmatically via `set_active_profile`.
///
/// M-34 fix: previously this was a bare `Mutex<DeploymentProfile>`, and
/// `get_active_profile()` decided whether to re-apply the env var by
/// checking `*profile == DeploymentProfile::Production` — indistinguishable
/// from "never explicitly set". An explicit `set_active_profile(Production)`
/// (e.g. a test resetting state, or admin tooling pinning PRODUCTION) left
/// that same value in the Mutex, so the very next `get_active_profile()`
/// call would re-read the env var and silently overwrite the explicit
/// choice if `SAACP_DEPLOYMENT_PROFILE` was set to STAGING/DEVELOPMENT.
/// `manually_set` makes "was explicitly set" its own bit of state, so an
/// explicit set always sticks regardless of which profile value it set.
struct ProfileState {
    profile: DeploymentProfile,
    manually_set: bool,
}

/// Global active profile (protected by a Mutex for thread safety).
/// Initialized from `SAACP_DEPLOYMENT_PROFILE` env var at first access.
static ACTIVE_PROFILE: Mutex<ProfileState> = Mutex::new(ProfileState {
    profile: DeploymentProfile::Production,
    manually_set: false,
});

/// Env var name for deployment profile (Appendix A).
pub const ENV_DEPLOYMENT_PROFILE: &str = "SAACP_DEPLOYMENT_PROFILE";

/// Read deployment profile from `SAACP_DEPLOYMENT_PROFILE` env var.
/// Unknown values default to PRODUCTION (most restrictive).
fn profile_from_env() -> DeploymentProfile {
    match std::env::var(ENV_DEPLOYMENT_PROFILE).as_deref() {
        Ok("DEVELOPMENT") => DeploymentProfile::Development,
        Ok("STAGING")     => DeploymentProfile::Staging,
        _                 => DeploymentProfile::Production,
    }
}

/// Return the currently active DeploymentProfile.
///
/// On first call, initializes from `SAACP_DEPLOYMENT_PROFILE` env var
/// if it has not already been set programmatically via `set_active_profile`.
///
/// M-38 fix: recovers the lock via `into_inner()` on poison rather than
/// panicking — this Mutex backs a process-wide singleton read on every
/// hard-drop response, so one poisoning panic must not cascade into every
/// other in-flight connection losing the ability to read the deployment
/// profile at all.
pub fn get_active_profile() -> DeploymentProfile {
    let mut state = ACTIVE_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
    // M-34: only ever consult the env var before the profile has been set
    // programmatically — once `manually_set` is true, the explicit choice
    // always wins, no matter which profile value it was set to.
    if !state.manually_set {
        state.profile = profile_from_env();
    }
    state.profile
}

/// Override the active profile (used in tests and admin tooling).
pub fn set_active_profile(profile: DeploymentProfile) {
    let mut state = ACTIVE_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
    state.profile = profile;
    state.manually_set = true;
}

/// Initialize the global deployment profile from the environment variable.
/// Call this once at process startup before handling any requests.
/// Calling this after `set_active_profile()` overwrites the programmatic value.
pub fn init_profile_from_env() {
    let mut state = ACTIVE_PROFILE.lock().unwrap_or_else(|e| e.into_inner());
    state.profile = profile_from_env();
    state.manually_set = false;
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
///
/// H-34: bytecodes 0x1B-0x40 (PSN/replay, AEGF governance, SCR, RRBC, RGC,
/// KLMS key, the ACSVAF delegation/authority family, and the identity-binding
/// family) previously had no explicit arm here and fell through to the
/// generic `InternalFailure` catch-all — masking real auth failures,
/// session-terminating conditions, and rate-limit conditions behind an
/// opaque "internal error" code. Each is now classified by caller-actionable
/// semantics, consistent with the other groups below: RequestRejected =
/// malformed/structural, retrying the same request will not help;
/// AccessDenied = credential/authorization/identity failure; SessionTerminated
/// = session-level protocol violation, caller must re-establish a session;
/// RateLimited = quota/throttling, caller should back off and retry;
/// ServiceUnavailable = transient state issue, caller may retry.
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
        | B::StreamEnd
        // H-34: structural/resource-shape violations inherent to the
        // request itself — retrying the identical request cannot succeed.
        | B::RgcResourceLimitExceeded
        | B::ScrNotFound
        | B::AcsvafManifestInvalid
        | B::DelegationMetadataIncomplete
        | B::AegfHopLimitExceeded
        | B::AegfDepthLimitExceeded => ExternalCode::RequestRejected,

        // ── ACCESS_DENIED ───────────────────────────────────────────────
        B::InvalidSignature
        | B::TokenExpired
        | B::LateralMovementBlocked
        | B::ScopeViolation
        | B::PromptInjectionDetected
        | B::ActionClassEscalation
        | B::DelegationRejected
        | B::ExternalInputTainted
        // H-34: credential / authorization / identity failures.
        | B::PsnReplayDetected
        | B::EpochExpired
        | B::ScrUnauthorized
        | B::RrbcReplayDetected
        | B::RrbcBindingMismatch
        | B::RrbcPopFailed
        | B::KeyRevoked
        | B::KeyVersionMismatch
        | B::AcsvafDelegationAmplification
        | B::AcsvafDelegationDepthExceeded
        | B::AcsvafCircularDelegation
        | B::AcsvafOrphanChain
        | B::AcsvafMissingCapabilityAuthority
        | B::AcsvafKeyNotTrusted
        | B::AcsvafThresholdNotReached
        | B::AcsvafSessionBindingViolated
        | B::SelfIssuedCapability
        | B::UnauthorizedIssuerClass
        | B::AuthorityClassViolation
        | B::FederationRootRequired
        | B::IdentityBindingMissing
        | B::IdentityMisbinding
        | B::TranscriptHashMismatch
        | B::IdentityNotVerified => ExternalCode::AccessDenied,

        // ── SESSION_TERMINATED ──────────────────────────────────────────
        B::EpistemicUncertainty
        | B::BudgetExceeded
        | B::StreamAbort
        // H-34: session-level protocol violations — the daemon/handler
        // layer terminates the connection for each of these; the caller
        // must re-establish a session rather than retry.
        | B::SequenceOverflow
        | B::AegfLoopDetected
        | B::AegfTtlExpired
        | B::AegfInvalidTransition
        | B::SessionSpliceDetected => ExternalCode::SessionTerminated,

        // ── RATE_LIMITED ────────────────────────────────────────────────
        B::CircuitBreakerOpen
        // H-34: quota / throttling conditions.
        | B::PsnOutOfWindow
        | B::RrbcUsageExhausted => ExternalCode::RateLimited,

        // ── SERVICE_UNAVAILABLE ─────────────────────────────────────────
        B::StateExpiredOrStale
        | B::StateSyncRequired
        | B::TemporalTimeout
        | B::AuditSubsystemDegraded
        // H-34: caller should rotate credentials and retry.
        | B::KeyEvolutionRequired => ExternalCode::ServiceUnavailable,

        // CRIT-11: 0x42/0x43 previously fell through to INTERNAL_FAILURE,
        // hiding an auth-failure (retry won't help, re-auth will) and a
        // policy violation (session must terminate) behind a generic code.
        B::TrustReauthRequired => ExternalCode::AccessDenied,
        B::IntentChainDriftExceeded => ExternalCode::SessionTerminated,

        // ── Everything else maps to INTERNAL_FAILURE ────────────────────
        // Only genuinely internal-only codes remain here (Success,
        // InputRequired, PreFlightBudget, CostEstimate, HeartbeatPing) —
        // none of which should ever reach this function as a rejection.
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
        0x41 => B::AuditSubsystemDegraded,
        0x42 => B::TrustReauthRequired,
        0x43 => B::IntentChainDriftExceeded,
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
    ///
    /// M-35 fix: previously built the JSON text by hand with a
    /// `.replace('\\', ..).replace('"', ..)` pass over each value — that
    /// escapes backslashes and quotes but not the other characters JSON
    /// requires escaping in a string (control characters like `\n`, `\t`,
    /// `\r`, or bare `\x00`-`\x1F` bytes), any of which appearing in
    /// `internal_message` (attacker-influenced free text from a rejected
    /// packet) would have produced invalid, unparseable JSON. Routes through
    /// `serde_json::Value` instead, whose `Display`/`to_string()` escaping is
    /// complete and spec-compliant.
    pub fn to_json(&self) -> String {
        let map: serde_json::Map<String, serde_json::Value> = self.to_map()
            .into_iter()
            .map(|(k, v)| (k, serde_json::Value::String(v)))
            .collect();
        serde_json::to_string(&serde_json::Value::Object(map)).unwrap_or_default()
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
        let mut entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
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
        let entries = self.entries.lock().unwrap_or_else(|e| e.into_inner());
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
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).clear();
    }

    /// Return the current number of entries.
    pub fn entry_count(&self) -> usize {
        self.entries.lock().unwrap_or_else(|e| e.into_inner()).len()
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
    ///
    /// M-33 fix: uses `tokio::time::sleep` (async), not `std::thread::sleep`.
    /// `tokio` is a mandatory (non-optional) dependency of this crate
    /// already including the `time` feature, and this function's only
    /// caller (`daemon.rs`'s `handle_client`, in the hard-drop response
    /// path) runs on the async executor — specifically AFTER the gate
    /// pipeline's own `spawn_blocking` call has already completed and been
    /// `.await`ed, not inside it. The previous `std::thread::sleep` blocked
    /// a tokio worker thread for up to `SREL_FLOOR_SECONDS` (50ms) on every
    /// single hard-drop response; under load, enough concurrent hard-drops
    /// could exhaust the whole worker pool and stall unrelated in-flight
    /// connections, not just the one being timing-equalized. There are no
    /// synchronous callers of this function anywhere in this crate (grepped
    /// call sites and tests) to preserve compatibility for, so this is a
    /// pure behavior fix, not an API compromise.
    pub async fn equalize_timing(start: Instant) {
        if get_active_profile() == DeploymentProfile::Development {
            return;
        }
        let elapsed = start.elapsed().as_secs_f64();
        let remaining = SREL_FLOOR_SECONDS - elapsed;
        if remaining > 0.0 {
            tokio::time::sleep(std::time::Duration::from_secs_f64(remaining)).await;
        }
    }

    /// Build a fixed-size, constant-structure wire response.
    ///
    /// Format (64 bytes, spec §9.3):
    ///   [0]      PECF marker 0xFE
    ///   [1]      ExternalCode byte value
    ///   [2..34]  correlation_id — exactly 32 ASCII hex chars (16 random bytes hex-encoded)
    ///   [34..64] 30 bytes zero padding
    ///
    /// # Panics (debug only)
    /// Asserts `correlation_id` is exactly 32 chars in debug builds to catch
    /// silent truncation — the internal generator always produces 32 chars via
    /// `hex::encode([u8; 16])`, so this should never fire in production.
    pub fn normalize_response(code: ExternalCode, correlation_id: &str) -> Vec<u8> {
        // SECURITY: spec §9.3 requires EXACTLY 32 ASCII hex chars.
        // The internal generator always produces 32 chars; this assert catches
        // any caller passing a wrong-length string.
        debug_assert_eq!(
            correlation_id.len(), 32,
            "PECF correlation_id must be exactly 32 hex chars, got {}",
            correlation_id.len()
        );
        let mut buf = vec![0u8; SREL_WIRE_RESPONSE_SIZE];
        buf[0] = PECF_MARKER;
        buf[1] = code as u8;
        // Always exactly 32 hex ASCII bytes — copy_len is always 32.
        let corr_bytes = correlation_id.as_bytes();
        let copy_len = corr_bytes.len().min(32);
        buf[2..2 + copy_len].copy_from_slice(&corr_bytes[..copy_len]);
        // [34..64]: 30 bytes zero padding (already zeroed)
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
///
/// `pub(crate)` (rather than private): `daemon.rs`'s fast hard-drop paths
/// (`send_hard_drop` and the main connection-loop error arm) build their wire
/// response directly via `SREL::normalize_response` without going through the
/// full `PECFFilter::translate`/SDL-logging pipeline, but still owe the wire
/// format a real 32-hex-char correlation ID — reuse this generator rather than
/// duplicate the random-byte-to-hex logic in `daemon.rs`.
pub(crate) fn generate_correlation_id() -> String {
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
    use serial_test::serial;

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

    /// CRIT-11 regression: 0x41-0x43 must resolve to their intended external
    /// codes, not the generic INTERNAL_FAILURE catch-all.
    #[test]
    fn test_internal_to_external_crit11_bytecodes() {
        assert_eq!(
            internal_to_external(SAACPBytecodes::AuditSubsystemDegraded),
            ExternalCode::ServiceUnavailable
        );
        assert_eq!(
            internal_to_external(SAACPBytecodes::TrustReauthRequired),
            ExternalCode::AccessDenied
        );
        assert_eq!(
            internal_to_external(SAACPBytecodes::IntentChainDriftExceeded),
            ExternalCode::SessionTerminated
        );

        assert_eq!(internal_to_external_raw(0x41), ExternalCode::ServiceUnavailable);
        assert_eq!(internal_to_external_raw(0x42), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external_raw(0x43), ExternalCode::SessionTerminated);
    }

    #[test]
    fn test_internal_to_external_raw() {
        assert_eq!(internal_to_external_raw(0x01), ExternalCode::RequestRejected);
        assert_eq!(internal_to_external_raw(0x03), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external_raw(0xFF), ExternalCode::InternalFailure);
    }

    /// H-34 regression: every named bytecode from 0x1B through 0x43 must
    /// resolve to a specific ExternalCode, not silently fall through to the
    /// generic INTERNAL_FAILURE catch-all. Exhaustive so that a future
    /// bytecode added in this range without an explicit mapping fails this
    /// test immediately rather than surviving as a silent confidentiality
    /// regression.
    #[test]
    fn test_internal_to_external_h34_no_catchall_in_named_range() {
        for raw in 0x1Bu8..=0x43u8 {
            let code = internal_to_external_raw(raw);
            assert_ne!(
                code,
                ExternalCode::InternalFailure,
                "bytecode 0x{:02X} must not fall through to INTERNAL_FAILURE",
                raw
            );
        }
    }

    /// H-34 spot checks: representative bytecode from each newly-mapped group.
    #[test]
    fn test_internal_to_external_h34_representative_mappings() {
        assert_eq!(internal_to_external(SAACPBytecodes::RgcResourceLimitExceeded), ExternalCode::RequestRejected);
        assert_eq!(internal_to_external(SAACPBytecodes::PsnReplayDetected), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external(SAACPBytecodes::IdentityNotVerified), ExternalCode::AccessDenied);
        assert_eq!(internal_to_external(SAACPBytecodes::SessionSpliceDetected), ExternalCode::SessionTerminated);
        assert_eq!(internal_to_external(SAACPBytecodes::SequenceOverflow), ExternalCode::SessionTerminated);
        assert_eq!(internal_to_external(SAACPBytecodes::RrbcUsageExhausted), ExternalCode::RateLimited);
        assert_eq!(internal_to_external(SAACPBytecodes::PsnOutOfWindow), ExternalCode::RateLimited);
        assert_eq!(internal_to_external(SAACPBytecodes::KeyEvolutionRequired), ExternalCode::ServiceUnavailable);
    }

    #[test]
    #[serial]
    fn test_srel_normalize_response_format() {
        set_active_profile(DeploymentProfile::Production);
        // Must be exactly 32 hex chars (spec §9.3: "16 random bytes as 32 hex ASCII chars")
        let corr = "abcd1234ef567890abcd1234ef567890"; // 32 hex chars
        let resp = SREL::normalize_response(ExternalCode::AccessDenied, corr);
        assert_eq!(resp.len(), 64);
        assert_eq!(resp[0], 0xFE); // PECF marker
        assert_eq!(resp[1], 0x02); // AccessDenied
        assert_eq!(&resp[2..34], corr.as_bytes()); // exactly 32 ASCII hex chars
        // [34..64]: 30 bytes zero padding
        assert!(resp[34..].iter().all(|&b| b == 0));
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
    #[serial]
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
