// SAACP security invariant: the protocol implementation is — and must remain —
// 100% safe Rust. Zero `unsafe` blocks anywhere in `src/` was a manual property
// until now; `forbid(unsafe_code)` makes it a compile-time guarantee (kimiplan
// recommendation #6). Any future requirement that seems to demand `unsafe`
// must go through a design review that first proves no safe alternative exists.
#![forbid(unsafe_code)]

pub mod acsvaf;
pub mod acsvaf_audit;
pub mod acsvaf_authority;
pub mod aegf;
pub mod cluster;
pub mod context;
pub mod crypto_governance;
pub mod cryptosuite;
pub mod cscs;
pub mod daemon;
pub mod easi;
pub mod error_confidentiality;
pub mod errors;
pub mod estimator;
pub mod factf;
pub mod faitf;
pub mod faitf_audit;
pub mod framing;
pub mod gateway;
pub mod gossip;
pub mod handler;
pub mod hth;
pub mod identity_binding;
pub mod klms;
pub mod measc;
pub mod memory;
pub mod pecf;
pub mod pool;
pub mod rgc;
pub mod rulepack;
pub mod schemas;
pub mod security;
pub mod shard;
pub mod streaming;
pub mod temporal;
// Metadata Privacy (cover traffic / adaptive padding / timing jitter): traffic-
// analysis resistance. Never wired into the default gate pipeline (verified —
// it was already dead code before this feature gate existed), and matters far
// more for anonymity-network threat models than for AI agent pipelines running
// inside a controlled infrastructure boundary. Off by default so IoT/low-
// resource builds don't compile it at all; enable explicitly if your
// deployment's threat model includes passive traffic analysis.
pub mod aca;
#[cfg(feature = "command-center")]
pub mod command_center;
#[cfg(feature = "command-center")]
pub mod command_center_demo;
pub mod hrt;
pub mod ievl;
pub mod mace;
pub mod maintenance;
#[cfg(feature = "mpf")]
pub mod mpf;
pub mod sid;
#[cfg(feature = "sidecar")]
pub mod sidecar;
pub mod state_backend;
pub mod telemetry;
pub mod transport;
pub mod trust_decay;
pub mod type_state;

pub use acsvaf::{
    CapabilityIssuanceAuthority, CapabilitySigningKey, CapabilityVerificationAuthority,
    CapabilityVerificationResult, KeyManifest, KeyManifestEntry, SignedCapabilityToken,
    ACSVAF_MAX_DELEGATION_DEPTH,
};
pub use acsvaf_audit::{
    ACSVAFAuditLog, CapabilityAuditEntry, EVENT_DELEGATED, EVENT_ISSUED, EVENT_KEY_COMPROMISED,
    EVENT_KEY_ROTATED, EVENT_REJECTED, EVENT_REVOKED, EVENT_VERIFIED,
};
pub use acsvaf_authority::{
    enforce_issuance_policy, enforce_verification_policy, AuthorityClass, AuthorityPolicy,
    AuthorityRegistry, DEFAULT_AUTHORITY_REGISTRY,
};
pub use aegf::{
    AEGFGovernor, AEGFMetadata, AEGFPolicy, DistributedExecutionGraph, ExecutionState,
    ExecutionStateMachine, GovernanceDecision, StateRecord, AEGF_META_FIELD_OFFSETS,
    AEGF_META_FORMAT_VERSION, AEGF_META_SIZE, AEGF_TEST_VECTOR_BYTES, CID_NONE,
    GLOBAL_AEGF_GOVERNOR, GLOBAL_DAEG, RID_ROOT,
};
pub use cluster::{
    ClusterConfig, ClusterEngine, ClusterMessage, ClusterMessageKind, ClusterRejection,
    ClusterTransport, LeadershipChange, MemberRecord, MemberUpdate, NodeState,
    StaticClusterTransport, TickOutcome, CLUSTER_MAX_CLOCK_SKEW, CLUSTER_MAX_MEMBERS,
    CLUSTER_SCHEMA_ID, DEFAULT_DEAD_TIMEOUT, DEFAULT_LEASE_TTL, DEFAULT_MESSAGE_MAX_AGE,
    DEFAULT_SUSPECT_TIMEOUT, LEASE_KEY_PREFIX,
};
pub use context::SaacpContext;
pub use crypto_governance::{
    get_active_policy, lab_policy, production_policy, ApprovedSuitePolicy, CryptoLedgerEntry,
    CryptoTransparencyLedger, NegotiationTranscript, SuiteNegotiator, SuiteStatus,
    CIPHER_SUITE_BASELINE, LAB_POLICY, PRODUCTION_POLICY, PROTOCOL_VERSION,
    SIGNATURE_ALGO_BASELINE,
};
pub use cryptosuite::{
    ed25519_sign, ed25519_verify, get_ed25519_suite, get_suite, register_suite, CryptoSuite,
    Ed25519Suite, CRYPTO_SUITES, DEFAULT_ALGORITHM,
};
pub use cscs::{CSCSLoopDetector, OscillationFingerprinter, CSCS_MAX_OSCILLATION_COUNT};
pub use daemon::{
    SAACPNetworkDaemon, HANDSHAKE_TIMEOUT_SECS, IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS,
    MAX_ASSEMBLY_TIME, MAX_CIRCUIT_BREAKER_IPS,
};
pub use easi::EasiEncryptor;
pub use error_confidentiality::{
    make_opaque_error, ErrorCategory, ErrorConfidentialityFilter, WireErrorResponse,
    DEFAULT_PROTOCOL_VERSION, PROTOCOL_VERSION_WIRE, SENTINEL_NO_RETRY, WIRE_SIZE,
};
pub use errors::{SAACPBytecodes, SAACPHardDrop};
pub use estimator::AutonomousTokenEstimator;
pub use factf::{
    AuthorizationContext, AuthorizationPolicy, CapabilityTransparencyLog, CompromiseRecoveryReport,
    DefaultAuthorizationPolicy, DefaultPolicy, DelegationChainResult, DelegationChainValidator,
    FilesystemBackend, InMemoryBackend, PostCompromiseRecovery, RiskAwareAuthorizationEvaluator,
    RiskEvaluation, ThresholdApprovalState, ThresholdAuthorityIssuer, ThresholdCapabilityToken,
    ThresholdNotReached, ThresholdSignatureEntry, TransparencyLogBackend, TransparencyLogEntry,
};
pub use faitf::{
    provision_issuer, AgentCredential, AgentIdentity, AttestationType, CredentialRenewal,
    CredentialRenewalRecord, DRIError, DelegatedCredential, DelegationChain,
    DistributedRevocationInfrastructure, HardwareAttestationStub, IdentityProver,
    SignedFederationAgreement, SignedRevocationRecord, TrustAnchor, TrustMeshFederation,
    TrustModel, TrustStore, FAITF_MAX_DELEGATION_DEPTH, FAITF_VERSION, IDENTITY_PROOF_TTL,
    MAX_CLOCK_SKEW,
};
pub use faitf_audit::FAITFAuditLog;
pub use framing::{
    ParsedFrame, MAX_PAYLOAD_SIZE, MEASC_HEADER_SIZE as FRAMING_HEADER_SIZE,
    MEASC_MAGIC as FRAMING_MEASC_MAGIC,
};
pub use framing::{ACTION_CLASS_IRREVERSIBLE, ACTION_CLASS_READ_ONLY, ACTION_CLASS_REVERSIBLE};
pub use framing::{FLAG_BINARY_STREAM, FLAG_COVER_TRAFFIC, FLAG_ENCRYPTED, FLAG_HAS_TOKEN};
pub use gateway::{
    AgentRateLimiter, DelegationGuard, RRBCGateway, RRBCRedemptionResult, TokenValidationResult,
    ZeroTrustGateway, COVER_TRAFFIC_THRESHOLD, COVER_TRAFFIC_WINDOW_SECONDS,
    RATE_LIMITER_LOCKOUT_SECONDS, RATE_LIMITER_THRESHOLD, RATE_LIMITER_WINDOW_SECONDS,
};
pub use handler::{
    builtin_injection_patterns, normalize_scan_window, serde_value_to_json_value,
    CachedTokenResult, GateTier, JsonValue, ParsedPacket, PromptInjectionScanner,
    SAACPProtocolHandler, EPISTEMIC_CLAIMED_CONFIDENCE_MAX, EPISTEMIC_THRESHOLD,
    GATE_EXECUTION_BUDGET_SECONDS, INTENT_MIN_OVERLAP, MANDATORY_GATES,
};
/// AWS KMS key store (`ECC_NIST_EDWARDS25519` keys).
#[cfg(feature = "hrt-aws-kms")]
pub use hrt::aws_kms::AwsKmsKeyStore;
/// Google Cloud KMS key store (`EC_SIGN_ED25519` key versions).
#[cfg(feature = "hrt-gcp-kms")]
pub use hrt::gcp_kms::GcpKmsKeyStore;
/// PKCS#11 (Cryptoki) hardware token / network HSM key store — on-premise HSMs
/// (Thales, Entrust, Utimaco, YubiHSM) and SoftHSM2.
#[cfg(feature = "hrt-pkcs11")]
pub use hrt::pkcs11::Pkcs11KeyStore;
pub use hrt::{
    ed25519_public_key_from_spki, HardwareKeyStore, HrtError, SoftwareKeyStore,
    ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, ED25519_SPKI_PREFIX,
};
/// Alias matching Python HTH_DEFAULT_REGISTRY.
pub use hth::DEFAULT_REGISTRY as HTH_DEFAULT_REGISTRY;
pub use hth::{
    bind_capability, verify_capability_binding, HandshakeTranscript, TranscriptElement,
    TranscriptElementType, TranscriptRegistry, TranscriptSession, DEFAULT_REGISTRY,
};
pub use identity_binding::{
    AgentIdentityCertificate, IdentityGate, IdentityVerifier, SessionIdentityRegistry,
    TranscriptBoundSession, DEFAULT_IDENTITY_GATE, DEFAULT_IDENTITY_REGISTRY,
    DEFAULT_IDENTITY_VERIFIER, IDENTITY_GATE_PHASES,
};
/// Alias matching Python's KLMS_DEFAULT_POLICY export.
pub use klms::DEFAULT_POLICY as KLMS_DEFAULT_POLICY;
/// Alias matching Python's KLMS_DEFAULT_REGISTRY export.
pub use klms::DEFAULT_REGISTRY as KLMS_DEFAULT_REGISTRY;
pub use klms::{
    default_key_generator, default_policy as klms_default_policy, make_descriptor, make_kid,
    KeyAlgorithm, KeyAuditEntry, KeyCategory, KeyDescriptor, KeyLifecycleManager, KeyRegistry,
    KeyRevocationRecord, KeyRotationPolicy, KeyStatus,
};
pub use mace::{
    activate as mace_activate, is_enabled as mace_is_enabled,
    sweep_and_enforce as mace_sweep_and_enforce, wire_mace_alert_feed, DelegationSignal,
    MultiAgentCollusionEngine, SYBIL_COSINE_THRESHOLD,
};
pub use measc::{
    AnomalyPolicy, EpochSnapshot, KeyEvolutionEngine, MEASCFrame, PSKCompromiseRecovery,
    PSKCompromiseReport, PacketSequencer, ParsedMEASCFrame, ReplayWindow, ReplayWindowPolicy,
    ReplayWindowStats, SessionEpoch, SessionEpochManager, MEASC_AUTH_SESSION_IDLE_SECS,
    MEASC_AUTH_TAG_SIZE, MEASC_CONTEXT_REF_ID_OFFSET, MEASC_CONTEXT_REF_ID_SIZE,
    MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS,
    MEASC_EPOCH_GRACE_PERIOD_SECONDS, MEASC_HEADER_SIZE, MEASC_MAGIC, MEASC_MAX_PSN_ADVANCE,
    MEASC_MAX_TRACKED_SESSIONS, MEASC_PSN_MAX, MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD,
    MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE, MEASC_REPLAY_MAX_LARGE_ADVANCES,
    MEASC_REPLAY_RATE_LIMIT_WINDOW_SEC, MEASC_REPLAY_WINDOW_SIZE, MEASC_UNAUTH_SESSION_IDLE_SECS,
};
pub use memory::{
    CheckpointedSession, FederatedMemory, SecureContextStore, StallReport, CHECKPOINT_MAX_ENTRIES,
    CHECKPOINT_TTL_SECONDS, FEDERATED_MAX_ENTRIES, FEDERATED_TTL_SECONDS, INTENT_MAX_LIFETIME,
    STALL_ABORT_SECONDS, STALL_CHECKPOINT_SECONDS, STALL_WARN_SECONDS,
};
#[cfg(feature = "mpf")]
pub use mpf::{
    AdaptivePadding, CoverTraffic, MpfBundle, TimingObfuscator, MPF_COVER_RATE_HZ,
    MPF_PAD_BLOCK_SIZE, MPF_PAD_MAX_BUCKET, MPF_TIMING_JITTER_MS, MPF_VERSION,
};
pub use pecf::{
    get_active_profile, init_profile_from_env, internal_to_external, internal_to_external_raw,
    set_active_profile, DeploymentProfile, ExternalCode, ExternalResponse, PECFFilter, SdlEntry,
    SecureDiagnosticLedger, ENV_DEPLOYMENT_PROFILE, PECF_MARKER, SDL_MAX_ENTRIES, SREL,
    SREL_FLOOR_SECONDS, SREL_WIRE_RESPONSE_SIZE,
};
pub use pool::{
    ConnectionPool, PinnedConnection, MAX_IDLE_SECONDS, MAX_POOL_SIZE, TOKEN_REVALIDATION_INTERVAL,
};
/// Alias matching Python RGC_DEFAULT_POLICY.
pub use rgc::DEFAULT_POLICY as RGC_DEFAULT_POLICY;
pub use rgc::{
    ExecutionBudgetGuard, RGCPolicy, ResourceGovernanceParser, DEFAULT_POLICY,
    EXECUTION_BUDGET_MAX_SECONDS,
};
pub use rulepack::{
    active_ruleset, install_from_json, CompiledRuleSet, InjectionRule, RulePack, RulePackRejection,
    RulePackStatus, RulePackStore, MAX_PACK_LIFETIME_SECS, MAX_PATTERN_LEN, MAX_RULES_PER_PACK,
    MAX_RULE_ID_LEN, MIN_NORMALIZED_PATTERN_LEN, RULEPACK_FORMAT,
};
pub use schemas::PreCompiledSchemas;
pub use security::{
    AuditHealth, AuditLogEntry, AuditRecord, ImmutableAuditLog, NonceTracker, AUDIT_COUNT_FILE,
    AUDIT_LOG_FILE, AUDIT_MAX_LOG_SIZE, AUDIT_WAL_FLUSH_EVERY_N_ENTRIES,
    AUDIT_WAL_FLUSH_INTERVAL_MS, AUDIT_WAL_QUEUE_CAPACITY, ENV_AUDIT_LOG, ENV_COUNT_FILE,
    NONCE_MAX_AGE_SECONDS, NONCE_MAX_ENTRIES,
};
pub use sid::{
    enforce_semantic_injection as sid_enforce_semantic_injection, is_required as sid_is_required,
    set_required as sid_set_required,
};
pub use sid::{SemanticInjectionDefense, SID_THRESHOLD};
pub use streaming::{
    StreamRegistry, StreamSession, MAX_ACTIVE_STREAMS, MAX_STREAMS_PER_AGENT,
    STREAM_MAX_DURATION_SECONDS, STREAM_MAX_FRAME_GAP_SECONDS, STREAM_MAX_TOTAL_BYTES,
};
pub use telemetry::{
    global_telemetry, report_rulepack_rejection, TelemetryCollector, GLOBAL_TELEMETRY,
};
/// Python parity alias: TemporalHeartbeatThread = TemporalHeartbeat.
pub use temporal::TemporalHeartbeat as TemporalHeartbeatThread;
pub use temporal::{
    DeadMansSwitch, TemporalHeartbeat, DEAD_MAN_MAX_SESSIONS, DEAD_MAN_MAX_TIMEOUT,
    GLOBAL_DEAD_MANS_SWITCH, HEARTBEAT_INTERVAL_SECONDS,
};
pub use type_state::PipelineToken;

// ─── Protocol Version Constants ───────────────────────────────────────────────
/// Python parity: `__version__ = "0.1-beta2"`
pub const SAACP_VERSION: &str = "0.1-beta2";
/// Python parity: `__protocol__ = "SAACP/0.1-beta2"`
pub const SAACP_PROTOCOL: &str = "SAACP/0.1-beta2";
