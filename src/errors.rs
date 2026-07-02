use std::fmt;

/// All SAACP protocol bytecodes (0x00 through 0x40).
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SAACPBytecodes {
    Success = 0x00,
    MalformedHeader = 0x01,
    SchemaMismatch = 0x02,
    InvalidSignature = 0x03,
    AmbiguousIntent = 0x04,
    LateralMovementBlocked = 0x05,
    PromptInjectionDetected = 0x06,
    StateExpiredOrStale = 0x07,
    InputRequired = 0x08,
    BudgetExceeded = 0x09,
    PreFlightBudget = 0x0A,
    CostEstimate = 0x0B,
    ActionClassEscalation = 0x0C,
    EpistemicUncertainty = 0x0D,
    PayloadTooLarge = 0x0E,
    HeartbeatPing = 0x0F,
    StateSyncRequired = 0x10,
    TemporalTimeout = 0x11,
    TokenExpired = 0x12,
    ScopeViolation = 0x13,
    CircuitBreakerOpen = 0x14,
    DelegationRejected = 0x15,
    ExternalInputTainted = 0x16,
    StreamStart = 0x17,
    StreamContinuation = 0x18,
    StreamEnd = 0x19,
    StreamAbort = 0x1A,
    PsnReplayDetected = 0x1B,
    PsnOutOfWindow = 0x1C,
    EpochExpired = 0x1D,
    SequenceOverflow = 0x1E,
    KeyEvolutionRequired = 0x1F,
    AegfLoopDetected = 0x20,
    AegfHopLimitExceeded = 0x21,
    AegfDepthLimitExceeded = 0x22,
    AegfTtlExpired = 0x23,
    AegfInvalidTransition = 0x24,
    ScrUnauthorized = 0x25,
    ScrNotFound = 0x26,
    RrbcReplayDetected = 0x27,
    RrbcUsageExhausted = 0x28,
    RrbcBindingMismatch = 0x29,
    RrbcPopFailed = 0x2A,
    RgcResourceLimitExceeded = 0x2B,
    KeyRevoked = 0x2C,
    KeyVersionMismatch = 0x2D,
    AcsvafDelegationAmplification = 0x2E,
    AcsvafDelegationDepthExceeded = 0x2F,
    AcsvafCircularDelegation = 0x30,
    AcsvafOrphanChain = 0x31,
    AcsvafMissingCapabilityAuthority = 0x32,
    AcsvafKeyNotTrusted = 0x33,
    AcsvafThresholdNotReached = 0x34,
    AcsvafManifestInvalid = 0x35,
    AcsvafSessionBindingViolated = 0x36,
    SelfIssuedCapability = 0x37,
    UnauthorizedIssuerClass = 0x38,
    DelegationMetadataIncomplete = 0x39,
    AuthorityClassViolation = 0x3A,
    FederationRootRequired = 0x3B,
    IdentityBindingMissing = 0x3C,
    IdentityMisbinding = 0x3D,
    TranscriptHashMismatch = 0x3E,
    IdentityNotVerified = 0x3F,
    SessionSpliceDetected = 0x40,
    /// Gate 2.5 rejection: an IRREVERSIBLE_ACTION-class packet was blocked
    /// because Gate 6.0's audit subsystem is SATURATED or FATAL (see
    /// `security::AuditHealth`) — the protocol will not authorize an
    /// irreversible action it cannot durably record.
    AuditSubsystemDegraded = 0x41,
}

impl fmt::Display for SAACPBytecodes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?}(0x{:02X})", self, *self as u8)
    }
}

/// Hard error type for the SAACP protocol.
#[derive(Debug, Clone)]
pub struct SAACPHardDrop {
    pub bytecode: SAACPBytecodes,
    pub message: String,
}

impl SAACPHardDrop {
    pub fn new(bytecode: SAACPBytecodes, message: impl Into<String>) -> Self {
        Self {
            bytecode,
            message: message.into(),
        }
    }
}

impl fmt::Display for SAACPHardDrop {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SAACPHardDrop[{}]: {}", self.bytecode, self.message)
    }
}

impl std::error::Error for SAACPHardDrop {}
