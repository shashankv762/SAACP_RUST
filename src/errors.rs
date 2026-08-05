use std::fmt;

/// All SAACP protocol bytecodes (0x00 through 0x49).
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
    /// Trust Decay Engine sidecar rejection (`trust_decay.rs`): this agent's
    /// behavioral trust score has dropped below `TRUST_REAUTH_THRESHOLD` — a
    /// soft reset, not a full token revocation. The capability token remains
    /// cryptographically valid; the agent is time-boxed out until its score
    /// recovers *and* the minimum cooldown floor elapses. *New in Rust* — no
    /// Python parity (the Trust Decay Engine has no Python-reference analog).
    TrustReauthRequired = 0x42,
    /// Gate 1.5 reinforcement (`handler.rs`): cumulative intent divergence
    /// across a delegation chain (tracked per `session_uuid` by
    /// `trust_decay::IntentDriftTracker`) exceeded `CHAIN_DRIFT_CEILING`,
    /// independent of any single hop passing its own per-hop check. Answers
    /// the "small, individually-plausible scope creep at every hop" failure
    /// mode. *New in Rust* — no Python parity.
    IntentChainDriftExceeded = 0x43,
    /// IEVL (`ievl.rs`, Phase 6 / Part 8.1) rejection: a submitted
    /// `ExecutionReceipt`'s `actual_action`/`actual_targets` exceeded the
    /// action_class the matching `IntentDeclaration` declared at Gate 1.5
    /// registration time — the agent executed something more dangerous than
    /// it promised. Triggers immediate revocation, not just a trust penalty
    /// (Monotonic Security — Part 12 principle 9). *New in Rust* — no Python
    /// parity (IEVL has no Python-reference analog).
    IntentClassEscalationDetected = 0x44,
    /// SID Layer 1 (`sid.rs`, Phase 6 / Part 8.3) rejection: structural
    /// heuristic score (role-override phrasing, context-break markers,
    /// authority claims, exfiltration patterns, instruction density,
    /// intent/payload contradiction) met or exceeded the 0.75 threshold —
    /// catches semantically-novel prompt injection that Gate 4.0's
    /// Aho-Corasick keyword scan cannot see. Runs strictly after Gate 4.0.
    /// *New in Rust* — no Python parity.
    SemanticInjectionDetected = 0x45,
    /// ACA (`aca.rs`, Phase 6 / Part 8.4) rejection: the session's
    /// `AttestationClaim` safety level is below the minimum required for the
    /// packet's resolved action_class (default policy: IRREVERSIBLE requires
    /// at least `AlignedModel`). Only enforced when ACA is explicitly
    /// configured on for the deployment (fail-closed only once enabled — Part
    /// 12 principle 3). *New in Rust* — no Python parity.
    InsufficientAttestation = 0x46,
    /// MACE (`mace.rs`, Phase 6 / Part 8.2) rejection: the Multi-Agent
    /// Collusion Detection Engine confirmed a circular-delegation cycle or a
    /// Sybil-cluster match (cosine similarity >= 0.92 across per-agent
    /// gate-outcome behavioral fingerprints) implicating this agent —
    /// triggers simultaneous trust penalty and revocation (Part A.10: "MACE
    /// -> Trust + DRI: Collusion detection simultaneously penalizes trust AND
    /// revokes credentials"). *New in Rust* — no Python parity.
    CollusionDetected = 0x47,

    /// `cluster.rs` (Active-Active Clustering & Failover) — an inbound cluster
    /// membership message was refused: bad/absent Ed25519 signature, an untrusted or
    /// unrostered sender, a replayed or stale message, or an envelope whose plaintext
    /// routing fields disagreed with the signed body. See
    /// `cluster::ClusterRejection` for the specific reason. *New in Rust* — no Python
    /// parity.
    ClusterMessageRejected = 0x48,

    /// `rulepack.rs` (Dynamic Hot-Reloadable Injection Rules) — a pushed
    /// injection-signature rule pack was refused and NOT adopted: absent or
    /// unmatched trust anchor, bad Ed25519 signature, an expired/not-yet-valid
    /// or over-long validity window, a replayed or downgraded `version`, or a
    /// rule that is over-broad enough to be a denial of service. See
    /// `rulepack::RulePackRejection` for the specific reason. Rejection leaves
    /// the previously active rule set untouched, so detection never degrades —
    /// packs are additive-only over the compiled-in baseline (Monotonic
    /// Security, Part 12 principle 9). *New in Rust* — no Python parity.
    RulePackRejected = 0x49,
}

impl SAACPBytecodes {
    /// Number of distinct bytecodes. Discriminants run contiguously from
    /// `Success = 0x00` to `RulePackRejected = 0x49` with no gaps, so this is
    /// also one past the largest discriminant.
    pub const COUNT: usize = 0x49 + 1;

    /// Dense array index for this bytecode — its `#[repr(u8)]` discriminant.
    ///
    /// Lets callers keep a fixed `[T; SAACPBytecodes::COUNT]` bank instead of a
    /// `HashMap` keyed by the `Debug` string, which is what `telemetry.rs`'s
    /// per-(gate, bytecode) rejection counters do: no hashing, no allocation,
    /// and no lock on a path that runs once per rejected packet.
    #[inline]
    pub fn index(self) -> usize {
        self as u8 as usize
    }

    /// Inverse of [`index`](Self::index) — `None` if `index >= COUNT`.
    ///
    /// Needed to render a dense counter bank back into labelled Prometheus
    /// output, where the bytecode NAME (not its number) is the label value.
    pub fn from_index(index: usize) -> Option<Self> {
        if index >= Self::COUNT {
            return None;
        }
        // Safety-by-construction: the discriminant range is contiguous and
        // `#[repr(u8)]`, and `ALL` is asserted below to cover it exactly, so an
        // in-range index always names a real variant. Using the table rather
        // than a transmute keeps this in safe Rust.
        Some(Self::ALL[index])
    }

    /// Every bytecode, ordered by discriminant so `ALL[i].index() == i`.
    ///
    /// The unit test `bytecodes_are_dense_and_ordered` asserts exactly that
    /// invariant, so adding a variant without extending this table (or leaving a
    /// discriminant gap) fails the build's test run rather than silently
    /// mis-indexing a counter into a neighbouring bytecode's slot.
    pub const ALL: [SAACPBytecodes; Self::COUNT] = {
        use SAACPBytecodes::*;
        [
            Success, MalformedHeader, SchemaMismatch, InvalidSignature,
            AmbiguousIntent, LateralMovementBlocked, PromptInjectionDetected,
            StateExpiredOrStale, InputRequired, BudgetExceeded, PreFlightBudget,
            CostEstimate, ActionClassEscalation, EpistemicUncertainty,
            PayloadTooLarge, HeartbeatPing, StateSyncRequired, TemporalTimeout,
            TokenExpired, ScopeViolation, CircuitBreakerOpen, DelegationRejected,
            ExternalInputTainted, StreamStart, StreamContinuation, StreamEnd,
            StreamAbort, PsnReplayDetected, PsnOutOfWindow, EpochExpired,
            SequenceOverflow, KeyEvolutionRequired, AegfLoopDetected,
            AegfHopLimitExceeded, AegfDepthLimitExceeded, AegfTtlExpired,
            AegfInvalidTransition, ScrUnauthorized, ScrNotFound,
            RrbcReplayDetected, RrbcUsageExhausted, RrbcBindingMismatch,
            RrbcPopFailed, RgcResourceLimitExceeded, KeyRevoked,
            KeyVersionMismatch, AcsvafDelegationAmplification,
            AcsvafDelegationDepthExceeded, AcsvafCircularDelegation,
            AcsvafOrphanChain, AcsvafMissingCapabilityAuthority,
            AcsvafKeyNotTrusted, AcsvafThresholdNotReached,
            AcsvafManifestInvalid, AcsvafSessionBindingViolated,
            SelfIssuedCapability, UnauthorizedIssuerClass,
            DelegationMetadataIncomplete, AuthorityClassViolation,
            FederationRootRequired, IdentityBindingMissing, IdentityMisbinding,
            TranscriptHashMismatch, IdentityNotVerified, SessionSpliceDetected,
            AuditSubsystemDegraded, TrustReauthRequired,
            IntentChainDriftExceeded, IntentClassEscalationDetected,
            SemanticInjectionDetected, InsufficientAttestation,
            CollusionDetected, ClusterMessageRejected, RulePackRejected,
        ]
    };
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

#[cfg(test)]
mod tests {
    use super::*;

    /// `SAACPBytecodes::ALL` must be ordered by discriminant and cover the whole
    /// contiguous range, because `telemetry.rs` uses `index()` to address a
    /// fixed-size counter bank and `from_index()` to turn a slot back into a
    /// Prometheus label.
    ///
    /// If a new variant is added without extending `ALL`, or a discriminant gap
    /// is introduced, this fails loudly. The failure mode it prevents is silent
    /// and nasty: rejections would be attributed to the WRONG bytecode in
    /// exported security metrics, or a counter write would land out of bounds.
    #[test]
    fn bytecodes_are_dense_and_ordered() {
        for (i, bc) in SAACPBytecodes::ALL.iter().enumerate() {
            assert_eq!(
                bc.index(), i,
                "SAACPBytecodes::ALL[{i}] is {bc:?}, whose discriminant is \
                 0x{:02X} — ALL must be sorted by discriminant with no gaps",
                bc.index(),
            );
            assert_eq!(SAACPBytecodes::from_index(i), Some(*bc));
        }
        assert_eq!(SAACPBytecodes::ALL.len(), SAACPBytecodes::COUNT);
        assert_eq!(SAACPBytecodes::from_index(SAACPBytecodes::COUNT), None);
        // Endpoints, pinned explicitly so a re-ordering that happens to stay
        // dense still trips.
        assert_eq!(SAACPBytecodes::Success.index(), 0x00);
        assert_eq!(SAACPBytecodes::RulePackRejected.index(), 0x49);
    }
}
