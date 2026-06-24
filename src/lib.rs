pub mod errors;
pub mod schemas;
pub mod framing;
pub mod measc;
pub mod acsvaf;
pub mod aegf;
pub mod faitf;
pub mod factf;
pub mod pecf;
pub mod klms;
pub mod handler;
pub mod gateway;
pub mod crypto_governance;
pub mod cryptosuite;
pub mod hth;
pub mod identity_binding;
pub mod acsvaf_authority;
pub mod memory;
pub mod security;
pub mod temporal;
pub mod streaming;
pub mod pool;
pub mod estimator;
pub mod rgc;
pub mod error_confidentiality;
pub mod acsvaf_audit;
pub mod faitf_audit;

pub use errors::{SAACPBytecodes, SAACPHardDrop};
pub use schemas::PreCompiledSchemas;
pub use framing::{MEASCFrame, MEASC_MAGIC, MEASC_HEADER_SIZE, MAX_PAYLOAD_SIZE, ParsedFrame};
pub use framing::{FLAG_COVER_TRAFFIC, FLAG_HAS_TOKEN, FLAG_BINARY_STREAM, FLAG_ENCRYPTED};
pub use framing::{ACTION_CLASS_READ_ONLY, ACTION_CLASS_REVERSIBLE, ACTION_CLASS_IRREVERSIBLE};
pub use measc::{
    ReplayWindow, PacketSequencer, KeyEvolutionEngine,
    SessionEpoch, SessionEpochManager, AnomalyPolicy,
    MEASC_REPLAY_WINDOW_SIZE, MEASC_MAX_PSN_ADVANCE, MEASC_PSN_MAX,
    MEASC_DEFAULT_EPOCH_TIME_SECONDS, MEASC_EPOCH_GRACE_PERIOD_SECONDS,
};
pub use acsvaf::{
    CapabilitySigningKey, SignedCapabilityToken, CapabilityIssuanceAuthority,
    CapabilityVerificationAuthority, CapabilityVerificationResult, KeyManifest,
    ACSVAF_MAX_DELEGATION_DEPTH,
};
pub use aegf::{
    AEGFMetadata, ExecutionState, ExecutionStateMachine, StateRecord,
    DistributedExecutionGraph, AEGFPolicy, AEGFGovernor, GovernanceDecision,
    AEGF_META_SIZE, AEGF_META_FORMAT_VERSION, RID_ROOT, CID_NONE,
};
pub use faitf::{
    AgentIdentity, AgentCredential, TrustAnchor, TrustStore,
    DistributedRevocationInfrastructure, TrustMeshFederation,
    SignedFederationAgreement, IdentityProver, DelegationChain,
    DelegatedCredential, CredentialRenewal, CredentialRenewalRecord,
    HardwareAttestationStub, TrustModel, AttestationType,
    SignedRevocationRecord, provision_issuer,
    FAITF_VERSION, FAITF_MAX_DELEGATION_DEPTH, IDENTITY_PROOF_TTL, MAX_CLOCK_SKEW,
};
pub use factf::{
    DelegationChainValidator, DelegationChainResult,
    ThresholdAuthorityIssuer, ThresholdCapabilityToken, ThresholdApprovalState,
    ThresholdSignatureEntry, CapabilityTransparencyLog, TransparencyLogEntry,
    InMemoryBackend, AuthorizationContext, RiskEvaluation,
    DefaultPolicy, RiskAwareAuthorizationEvaluator,
    PostCompromiseRecovery, CompromiseRecoveryReport,
};
pub use pecf::{
    DeploymentProfile, ExternalCode, ExternalResponse,
    PECFFilter, SREL, SecureDiagnosticLedger, SdlEntry,
    internal_to_external, internal_to_external_raw,
    get_active_profile, set_active_profile,
    SDL_MAX_ENTRIES, SREL_FLOOR_SECONDS, SREL_WIRE_RESPONSE_SIZE, PECF_MARKER,
};
pub use klms::{
    KeyStatus, KeyAlgorithm, KeyCategory, KeyDescriptor,
    KeyRotationPolicy, KeyRevocationRecord, KeyAuditEntry,
    KeyRegistry, KeyLifecycleManager, make_kid, make_descriptor,
};
pub use handler::{
    GateTier, PromptInjectionScanner, JsonValue, ParsedPacket,
    SAACPProtocolHandler, GATE_EXECUTION_BUDGET_SECONDS,
    EPISTEMIC_THRESHOLD, INTENT_MIN_OVERLAP,
};
pub use gateway::{
    ZeroTrustGateway, AgentRateLimiter, DelegationGuard,
    RRBCGateway, RRBCRedemptionResult, TokenValidationResult,
    RATE_LIMITER_THRESHOLD, RATE_LIMITER_WINDOW_SECONDS, RATE_LIMITER_LOCKOUT_SECONDS,
    COVER_TRAFFIC_THRESHOLD, COVER_TRAFFIC_WINDOW_SECONDS,
};
pub use crypto_governance::{
    SuiteStatus, CryptoLedgerEntry, CryptoTransparencyLedger,
    ApprovedSuitePolicy, NegotiationTranscript, SuiteNegotiator,
    SIGNATURE_ALGO_BASELINE, CIPHER_SUITE_BASELINE, PROTOCOL_VERSION,
    production_policy, lab_policy, get_active_policy,
};
pub use cryptosuite::{
    CryptoSuite, Ed25519Suite, DEFAULT_ALGORITHM,
    get_suite, get_ed25519_suite, ed25519_sign, ed25519_verify,
};
pub use hth::{
    TranscriptElementType, TranscriptElement, HandshakeTranscript,
    TranscriptSession, TranscriptRegistry, DEFAULT_REGISTRY,
    bind_capability, verify_capability_binding,
};
pub use identity_binding::{
    AgentIdentityCertificate, TranscriptBoundSession,
    IdentityVerifier, IdentityGate, SessionIdentityRegistry,
    DEFAULT_IDENTITY_VERIFIER, DEFAULT_IDENTITY_GATE, DEFAULT_IDENTITY_REGISTRY,
    IDENTITY_GATE_PHASES,
};
pub use acsvaf_authority::{
    AuthorityClass, AuthorityPolicy, AuthorityRegistry,
    enforce_issuance_policy, enforce_verification_policy,
    DEFAULT_AUTHORITY_REGISTRY,
};
pub use memory::{
    CheckpointedSession, FederatedMemory, SecureContextStore, StallReport,
    CHECKPOINT_MAX_ENTRIES, CHECKPOINT_TTL_SECONDS,
    STALL_WARN_SECONDS, STALL_CHECKPOINT_SECONDS, STALL_ABORT_SECONDS,
    FEDERATED_TTL_SECONDS, FEDERATED_MAX_ENTRIES, INTENT_MAX_LIFETIME,
};
pub use security::{
    NonceTracker, ImmutableAuditLog, AuditRecord, AuditLogEntry,
    NONCE_MAX_AGE_SECONDS, NONCE_MAX_ENTRIES, AUDIT_LOG_FILE, AUDIT_MAX_LOG_SIZE,
};
pub use temporal::{
    DeadMansSwitch, TemporalHeartbeat,
    DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS, HEARTBEAT_INTERVAL_SECONDS,
};
pub use streaming::{
    StreamSession, StreamRegistry,
    STREAM_MAX_TOTAL_BYTES, STREAM_MAX_DURATION_SECONDS, STREAM_MAX_FRAME_GAP_SECONDS,
    MAX_ACTIVE_STREAMS, MAX_STREAMS_PER_AGENT,
};
pub use pool::{
    PinnedConnection, ConnectionPool,
    TOKEN_REVALIDATION_INTERVAL, MAX_POOL_SIZE, MAX_IDLE_SECONDS,
};
pub use estimator::AutonomousTokenEstimator;
pub use rgc::{
    RGCPolicy, ResourceGovernanceParser, ExecutionBudgetGuard,
    DEFAULT_POLICY,
};
pub use error_confidentiality::{
    ErrorCategory, WireErrorResponse, ErrorConfidentialityFilter,
    make_opaque_error,
    WIRE_SIZE, SENTINEL_NO_RETRY, PROTOCOL_VERSION_WIRE, DEFAULT_PROTOCOL_VERSION,
};
pub use acsvaf_audit::{
    CapabilityAuditEntry, ACSVAFAuditLog,
    EVENT_ISSUED, EVENT_VERIFIED, EVENT_REJECTED, EVENT_DELEGATED,
    EVENT_REVOKED, EVENT_KEY_ROTATED, EVENT_KEY_COMPROMISED,
};
pub use faitf_audit::FAITFAuditLog;
