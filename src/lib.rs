pub mod errors;
pub mod schemas;
pub mod framing;
pub mod easi;
pub mod measc;
pub mod acsvaf;
pub mod aegf;
pub mod faitf;
pub mod factf;
pub mod gossip;
pub mod cluster;
pub mod pecf;
pub mod klms;
pub mod handler;
pub mod rulepack;
pub mod gateway;
pub mod cscs;
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
pub mod daemon;
// Metadata Privacy (cover traffic / adaptive padding / timing jitter): traffic-
// analysis resistance. Never wired into the default gate pipeline (verified —
// it was already dead code before this feature gate existed), and matters far
// more for anonymity-network threat models than for AI agent pipelines running
// inside a controlled infrastructure boundary. Off by default so IoT/low-
// resource builds don't compile it at all; enable explicitly if your
// deployment's threat model includes passive traffic analysis.
#[cfg(feature = "mpf")]
pub mod mpf;
pub mod telemetry;
pub mod transport;
pub mod state_backend;
pub mod trust_decay;
pub mod hrt;
pub mod type_state;
pub mod sid;
pub mod ievl;
pub mod mace;
pub mod aca;
pub mod maintenance;
#[cfg(feature = "sidecar")]
pub mod sidecar;
#[cfg(feature = "command-center")]
pub mod command_center;
#[cfg(feature = "command-center")]
pub mod command_center_demo;

pub use errors::{SAACPBytecodes, SAACPHardDrop};
pub use schemas::PreCompiledSchemas;
pub use framing::{MEASC_MAGIC as FRAMING_MEASC_MAGIC, MEASC_HEADER_SIZE as FRAMING_HEADER_SIZE, MAX_PAYLOAD_SIZE, ParsedFrame};
pub use framing::{FLAG_COVER_TRAFFIC, FLAG_HAS_TOKEN, FLAG_BINARY_STREAM, FLAG_ENCRYPTED};
pub use framing::{ACTION_CLASS_READ_ONLY, ACTION_CLASS_REVERSIBLE, ACTION_CLASS_IRREVERSIBLE};
pub use measc::{
    ReplayWindow, ReplayWindowPolicy, AnomalyPolicy,
    ReplayWindowStats, EpochSnapshot,
    PacketSequencer, KeyEvolutionEngine,
    SessionEpoch, SessionEpochManager,
    ParsedMEASCFrame, MEASCFrame,
    PSKCompromiseRecovery, PSKCompromiseReport,
    MEASC_REPLAY_WINDOW_SIZE, MEASC_MAX_PSN_ADVANCE, MEASC_PSN_MAX,
    MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD, MEASC_REPLAY_RATE_LIMIT_WINDOW_SEC,
    MEASC_REPLAY_MAX_LARGE_ADVANCES, MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE,
    MEASC_DEFAULT_EPOCH_TIME_SECONDS, MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
    MEASC_EPOCH_GRACE_PERIOD_SECONDS, MEASC_AUTH_TAG_SIZE,
    MEASC_HEADER_SIZE, MEASC_MAGIC,
    MEASC_CONTEXT_REF_ID_OFFSET, MEASC_CONTEXT_REF_ID_SIZE,
};
pub use acsvaf::{
    CapabilitySigningKey, SignedCapabilityToken, CapabilityIssuanceAuthority,
    CapabilityVerificationAuthority, CapabilityVerificationResult, KeyManifest,
    KeyManifestEntry,
    ACSVAF_MAX_DELEGATION_DEPTH,
};
pub use aegf::{
    AEGFMetadata, ExecutionState, ExecutionStateMachine, StateRecord,
    DistributedExecutionGraph, AEGFPolicy, AEGFGovernor, GovernanceDecision,
    AEGF_META_SIZE, AEGF_META_FORMAT_VERSION, RID_ROOT, CID_NONE,
    AEGF_META_FIELD_OFFSETS, AEGF_TEST_VECTOR_BYTES,
    GLOBAL_DAEG, GLOBAL_AEGF_GOVERNOR,
};
pub use faitf::{
    AgentIdentity, AgentCredential, TrustAnchor, TrustStore,
    DistributedRevocationInfrastructure, DRIError, TrustMeshFederation,
    SignedFederationAgreement, IdentityProver, DelegationChain,
    DelegatedCredential, CredentialRenewal, CredentialRenewalRecord,
    HardwareAttestationStub, TrustModel, AttestationType,
    SignedRevocationRecord, provision_issuer,
    FAITF_VERSION, FAITF_MAX_DELEGATION_DEPTH, IDENTITY_PROOF_TTL, MAX_CLOCK_SKEW,
};
pub use factf::{
    DelegationChainValidator, DelegationChainResult,
    ThresholdAuthorityIssuer, ThresholdCapabilityToken, ThresholdApprovalState,
    ThresholdNotReached,
    ThresholdSignatureEntry, CapabilityTransparencyLog, TransparencyLogEntry,
    TransparencyLogBackend, InMemoryBackend, FilesystemBackend,
    AuthorizationContext, RiskEvaluation,
    AuthorizationPolicy, DefaultAuthorizationPolicy,
    DefaultPolicy, RiskAwareAuthorizationEvaluator,
    PostCompromiseRecovery, CompromiseRecoveryReport,
};
pub use pecf::{
    DeploymentProfile, ExternalCode, ExternalResponse,
    PECFFilter, SREL, SecureDiagnosticLedger, SdlEntry,
    internal_to_external, internal_to_external_raw,
    get_active_profile, set_active_profile, init_profile_from_env,
    SDL_MAX_ENTRIES, SREL_FLOOR_SECONDS, SREL_WIRE_RESPONSE_SIZE, PECF_MARKER,
    ENV_DEPLOYMENT_PROFILE,
};
pub use klms::{
    KeyStatus, KeyAlgorithm, KeyCategory, KeyDescriptor,
    KeyRotationPolicy, KeyRevocationRecord, KeyAuditEntry,
    KeyRegistry, KeyLifecycleManager, make_kid, make_descriptor,
    default_key_generator,
    default_policy as klms_default_policy,
};
/// Alias matching Python's KLMS_DEFAULT_REGISTRY export.
pub use klms::DEFAULT_REGISTRY as KLMS_DEFAULT_REGISTRY;
/// Alias matching Python's KLMS_DEFAULT_POLICY export.
pub use klms::DEFAULT_POLICY as KLMS_DEFAULT_POLICY;
pub use handler::{
    GateTier, PromptInjectionScanner, JsonValue, ParsedPacket, CachedTokenResult,
    SAACPProtocolHandler, GATE_EXECUTION_BUDGET_SECONDS,
    EPISTEMIC_THRESHOLD, EPISTEMIC_CLAIMED_CONFIDENCE_MAX, INTENT_MIN_OVERLAP,
    MANDATORY_GATES, serde_value_to_json_value,
    builtin_injection_patterns, normalize_scan_window,
};
pub use rulepack::{
    InjectionRule, RulePack, RulePackRejection, RulePackStatus, RulePackStore,
    CompiledRuleSet, active_ruleset, install_from_json,
    MAX_RULES_PER_PACK, MAX_PATTERN_LEN, MAX_RULE_ID_LEN,
    MIN_NORMALIZED_PATTERN_LEN, MAX_PACK_LIFETIME_SECS, RULEPACK_FORMAT,
};
pub use gateway::{
    ZeroTrustGateway, AgentRateLimiter, DelegationGuard,
    RRBCGateway, RRBCRedemptionResult, TokenValidationResult,
    RATE_LIMITER_THRESHOLD, RATE_LIMITER_WINDOW_SECONDS, RATE_LIMITER_LOCKOUT_SECONDS,
    COVER_TRAFFIC_THRESHOLD, COVER_TRAFFIC_WINDOW_SECONDS,
};
pub use cscs::{CSCSLoopDetector, OscillationFingerprinter, CSCS_MAX_OSCILLATION_COUNT};
pub use crypto_governance::{
    SuiteStatus, CryptoLedgerEntry, CryptoTransparencyLedger,
    ApprovedSuitePolicy, NegotiationTranscript, SuiteNegotiator,
    SIGNATURE_ALGO_BASELINE, CIPHER_SUITE_BASELINE, PROTOCOL_VERSION,
    production_policy, lab_policy, get_active_policy,
    PRODUCTION_POLICY, LAB_POLICY,
};
pub use cryptosuite::{
    CryptoSuite, Ed25519Suite, DEFAULT_ALGORITHM,
    get_suite, get_ed25519_suite, ed25519_sign, ed25519_verify,
    CRYPTO_SUITES, register_suite,
};
pub use hth::{
    TranscriptElementType, TranscriptElement, HandshakeTranscript,
    TranscriptSession, TranscriptRegistry, DEFAULT_REGISTRY,
    bind_capability, verify_capability_binding,
};
/// Alias matching Python HTH_DEFAULT_REGISTRY.
pub use hth::DEFAULT_REGISTRY as HTH_DEFAULT_REGISTRY;
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
    NonceTracker, ImmutableAuditLog, AuditRecord, AuditLogEntry, AuditHealth,
    NONCE_MAX_AGE_SECONDS, NONCE_MAX_ENTRIES, AUDIT_LOG_FILE, AUDIT_MAX_LOG_SIZE,
    AUDIT_COUNT_FILE, AUDIT_WAL_QUEUE_CAPACITY,
    AUDIT_WAL_FLUSH_EVERY_N_ENTRIES, AUDIT_WAL_FLUSH_INTERVAL_MS,
    ENV_AUDIT_LOG, ENV_COUNT_FILE,
};
pub use temporal::{
    DeadMansSwitch, TemporalHeartbeat,
    GLOBAL_DEAD_MANS_SWITCH,
    DEAD_MAN_MAX_TIMEOUT, DEAD_MAN_MAX_SESSIONS, HEARTBEAT_INTERVAL_SECONDS,
};
/// Python parity alias: TemporalHeartbeatThread = TemporalHeartbeat.
pub use temporal::TemporalHeartbeat as TemporalHeartbeatThread;
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
    DEFAULT_POLICY, EXECUTION_BUDGET_MAX_SECONDS,
};
/// Alias matching Python RGC_DEFAULT_POLICY.
pub use rgc::DEFAULT_POLICY as RGC_DEFAULT_POLICY;
#[cfg(feature = "mpf")]
pub use mpf::{
    AdaptivePadding, CoverTraffic, TimingObfuscator, MpfBundle,
    MPF_PAD_BLOCK_SIZE, MPF_PAD_MAX_BUCKET, MPF_COVER_RATE_HZ,
    MPF_TIMING_JITTER_MS, MPF_VERSION,
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
pub use daemon::{
    SAACPNetworkDaemon,
    MAX_ASSEMBLY_TIME, MAX_CIRCUIT_BREAKER_IPS, HANDSHAKE_TIMEOUT_SECS,
    IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS,
};
pub use cluster::{
    ClusterConfig, ClusterEngine, ClusterMessage, ClusterMessageKind, ClusterRejection,
    ClusterTransport, LeadershipChange, MemberRecord, MemberUpdate, NodeState,
    StaticClusterTransport, TickOutcome,
    CLUSTER_MAX_CLOCK_SKEW, CLUSTER_MAX_MEMBERS, CLUSTER_SCHEMA_ID,
    DEFAULT_DEAD_TIMEOUT, DEFAULT_LEASE_TTL, DEFAULT_MESSAGE_MAX_AGE, DEFAULT_SUSPECT_TIMEOUT,
    LEASE_KEY_PREFIX,
};
pub use easi::EasiEncryptor;
pub use telemetry::{
    TelemetryCollector, global_telemetry, GLOBAL_TELEMETRY,
    report_rulepack_rejection,
};
pub use hrt::{
    HardwareKeyStore, SoftwareKeyStore, HrtError,
    ed25519_public_key_from_spki,
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, ED25519_SPKI_PREFIX,
};
/// PKCS#11 (Cryptoki) hardware token / network HSM key store — on-premise HSMs
/// (Thales, Entrust, Utimaco, YubiHSM) and SoftHSM2.
#[cfg(feature = "hrt-pkcs11")]
pub use hrt::pkcs11::Pkcs11KeyStore;
/// AWS KMS key store (`ECC_NIST_EDWARDS25519` keys).
#[cfg(feature = "hrt-aws-kms")]
pub use hrt::aws_kms::AwsKmsKeyStore;
/// Google Cloud KMS key store (`EC_SIGN_ED25519` key versions).
#[cfg(feature = "hrt-gcp-kms")]
pub use hrt::gcp_kms::GcpKmsKeyStore;
pub use type_state::PipelineToken;
pub use sid::{SemanticInjectionDefense, SID_THRESHOLD};
pub use sid::{
    set_required as sid_set_required,
    is_required as sid_is_required,
    enforce_semantic_injection as sid_enforce_semantic_injection,
};
pub use mace::{
    MultiAgentCollusionEngine, DelegationSignal,
    activate as mace_activate, is_enabled as mace_is_enabled,
    sweep_and_enforce as mace_sweep_and_enforce, wire_mace_alert_feed,
    SYBIL_COSINE_THRESHOLD,
};

// ─── Protocol Version Constants ───────────────────────────────────────────────
/// Python parity: `__version__ = "0.1-beta2"`
pub const SAACP_VERSION: &str = "0.1-beta2";
/// Python parity: `__protocol__ = "SAACP/0.1-beta2"`
pub const SAACP_PROTOCOL: &str = "SAACP/0.1-beta2";
