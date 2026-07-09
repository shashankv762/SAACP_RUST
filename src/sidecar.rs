//! sidecar.rs — local HTTP proxy translating plain JSON into SAACP-secured traffic.
//!
//! The pitch: a Python (or any other language's) agent should get SAACP's crypto/gate-
//! pipeline guarantees without knowing SAACP exists. Rather than a native binding (PyO3),
//! which would just relocate this crate's inherently stateful session/epoch/token
//! machinery into the caller's language, this runs as a local sidecar process: the agent
//! POSTs/GETs plain JSON to `http://127.0.0.1:<port>` and the sidecar does 100% of the
//! ECDH handshake, AES-256-GCM framing, capability-token issuance/verification, and
//! 16-gate pipeline dispatch internally, reusing `daemon.rs`/`handler.rs` almost verbatim
//! (see `SAACPNetworkDaemon::with_gateway`/`with_encrypted_transport`/`with_on_delivered`).
//!
//! ## V1 scope
//! - One shared 32-byte `token_issuer_secret` across the whole trusted mesh by default (an
//!   out-of-band pre-shared key) — same "honest v1, real v2 later" pattern as
//!   `trust_decay.rs`. `SidecarConfig::peer_secrets` (see "Production hardening" below) is
//!   the opt-in v2 upgrade to per-peer issuer keys via `ZeroTrustGateway::register_issuer_key`.
//! - `send_message` opens a fresh TCP connection, ECDH handshake, and one-shot session per
//!   call — no connection pooling/reuse. Simple and correct; a real perf cost for
//!   high-throughput use, flagged as a known follow-up rather than solved here.
//! - Every outbound send is the first (and only) packet on its connection, so the
//!   receiving daemon's identity-pinning bootstrap always resolves `current_agent_name` to
//!   the literal string `"unknown"` (see `daemon.rs::handle_client`) — the issued token's
//!   `allow` list must contain `"unknown"`, not the semantic peer name, or every message
//!   would be rejected by Gate 1.0's scope check. This is a real, surprising consequence of
//!   pairing "one-shot connections" with the daemon's existing pinning model, handled here
//!   so the sidecar's HTTP API surface doesn't need to expose it.
//! - Messages are schema-1 ("Task": `{task, priority}`) only; other schemas are a natural
//!   extension of this same pattern, not built here.
//!
//! ## Production hardening (this pass)
//! - **Per-peer issuer secrets** (`SidecarConfig::peer_secrets`): an opt-in upgrade from
//!   "one shared secret for the whole mesh" to a real allowlist of known peers, each with
//!   their own pairwise HMAC secret. Confirmed via `gateway.rs::validate_lateral_movement`:
//!   once `ZeroTrustGateway::register_issuer_key` has been called for *any* peer, the
//!   registry becomes authoritative — an unregistered issuer is hard-rejected with no
//!   fallback to a shared secret. So `peer_secrets` empty (default) = today's exact
//!   behavior; non-empty = every peer this sidecar talks to must have an entry (on both
//!   ends, since HMAC is symmetric), or that peer's traffic is rejected outright.
//! - **Bounded outbound concurrency** (`SidecarConfig::max_concurrent_sends`): a
//!   `tokio::sync::Semaphore` around `/send` dispatch, so an unbounded burst of outbound
//!   sends can't exhaust local sockets/file descriptors. A saturated sidecar returns
//!   `503` with `status: "saturated"` rather than queuing without bound — the same
//!   explicit-backpressure philosophy as `security.rs`'s `AuditHealth`.
//! - **Bounded retry** (`SidecarConfig::send_retry_attempts`): only the initial TCP
//!   connect step is retried on transient failure/timeout. Handshake, session setup, and
//!   post-connect I/O errors are never retried — those indicate a real protocol problem,
//!   not network flakiness, and retrying would just mask it.
//! - **Real `/healthz`**: reports live inbox depth/capacity and how many peers are
//!   registered, instead of a static `"ok"`.
//!
//! Deliberately *not* attempted here: real TCP connection reuse/pooling for
//! `send_message`. `daemon.rs::handle_client`'s identity-pinning model checks every
//! packet *after* the first one on a connection against `target_agent = pinned_agent`
//! (set from the first packet's token issuer), not `"unknown"` — reusing a socket across
//! multiple sends would require tracking that per-connection pin state on the sending
//! side and changing the token's `allow` list accordingly, a real protocol-level change
//! with identity-pinning/trust-decay implications, not a safe thing to bolt on here.
//! `pool.rs`'s `ConnectionPool` is bookkeeping-only (no actual socket), so it doesn't
//! help either. Flagged as follow-up, matching this codebase's "honest v1 scope"
//! convention elsewhere (`trust_decay.rs`, this module's own scope notes above).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, Mutex};

use crate::daemon::{client_handshake, SAACPNetworkDaemon};
use crate::faitf_audit::FAITFAuditLog;
use crate::gateway::ZeroTrustGateway;
use crate::handler::{JsonValue, ParsedPacket};
use crate::measc::{MEASCFrame, SessionEpochManager, MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS};
use crate::security::ImmutableAuditLog;
use crate::MAX_PAYLOAD_SIZE;

/// Bounded inbox capacity — matches this codebase's existing bounded-queue idiom (e.g.
/// `AUDIT_WAL_QUEUE_CAPACITY` in `security.rs`) rather than an unbounded channel. A sidecar
/// whose local Python agent stops polling `/receive` will start dropping the oldest-pending
/// deliveries once this fills, rather than growing memory without bound.
pub const SIDECAR_INBOX_CAPACITY: usize = 1000;

/// Upper bound on `/receive?wait_secs=N` long-poll duration, so a slow/idle caller can't
/// hold an HTTP connection (and the underlying task) open indefinitely.
pub const SIDECAR_MAX_RECEIVE_WAIT_SECS: f64 = 60.0;

/// Fixed connect/handshake/ack timeout for outbound `send_message` calls.
pub const SIDECAR_SEND_TIMEOUT_SECS: u64 = 10;

/// Bootstrap identity every one-shot outbound connection's token must be issued against —
/// see this module's doc comment for why.
const BOOTSTRAP_AGENT: &str = "unknown";

/// Default bound on concurrent outbound `/send` dispatches (see module doc).
pub const SIDECAR_DEFAULT_MAX_CONCURRENT_SENDS: usize = 64;

/// Default number of retries for a transient failure at the initial TCP-connect step only.
pub const SIDECAR_DEFAULT_SEND_RETRY_ATTEMPTS: u32 = 2;

/// Fixed backoff between connect retries.
const SEND_RETRY_BACKOFF_MS: u64 = 100;

/// How long `/send` will wait for a free concurrency permit before reporting saturation.
const SEND_PERMIT_ACQUIRE_WAIT_MS: u64 = 50;

// ─── Configuration ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SidecarConfig {
    /// This sidecar's own agent identity — used as the `iss` claim on tokens it issues.
    pub agent_id: String,
    /// Shared out-of-band HMAC secret trusted by every peer in this mesh (see module doc).
    /// Used as the signing/verification fallback for any peer without its own entry in
    /// `peer_secrets`.
    pub token_issuer_secret: [u8; 32],
    /// Address the real SAACP protocol listener binds (peer sidecars dial this).
    pub saacp_listen_addr: SocketAddr,
    /// Address the local plain-HTTP/JSON API binds (the co-located agent talks to this).
    pub http_listen_addr: SocketAddr,
    /// Pairwise secrets shared with specific peers, keyed by peer `agent_id` (see module
    /// doc's "per-peer issuer secrets" section). Empty (default) preserves today's exact
    /// single-shared-secret behavior. Non-empty makes the peer registry authoritative —
    /// only these named peers can be accepted as senders.
    pub peer_secrets: HashMap<String, [u8; 32]>,
    /// Bound on concurrent outbound `/send` dispatches.
    pub max_concurrent_sends: usize,
    /// Retries for a transient failure at the initial TCP-connect step only.
    pub send_retry_attempts: u32,
    /// H-21 (SSRF) fix: explicit allowlist of private/link-local CIDR ranges `/send` is
    /// permitted to dial, as `(network_address, prefix_len)` pairs (e.g.
    /// `(Ipv4Addr::new(10,0,0,0).into(), 8)` for all of `10.0.0.0/8`). Empty by default.
    /// Only consulted for addresses that `is_default_blocked_target` would otherwise
    /// reject (RFC 1918 + link-local); addresses outside those ranges never need an
    /// allowlist entry. Ignored entirely when `allow_private_targets` is `true`.
    pub target_allowlist: Vec<(IpAddr, u8)>,
    /// H-21 (SSRF) fix escape hatch: when `true`, disables the RFC-1918/link-local
    /// default-block entirely (equivalent to an allowlist matching everything). Intended
    /// only for deployments where the entire mesh deliberately lives inside one private
    /// network and every peer is already trusted at the network layer. Defaults to
    /// `false` — the safe, fail-closed setting.
    pub allow_private_targets: bool,
}

impl SidecarConfig {
    /// Convenience constructor for the common case: single shared mesh secret, default
    /// concurrency/retry limits, no per-peer overrides, and the default (safe) SSRF
    /// posture — RFC 1918 + link-local targets blocked, loopback and public addresses
    /// allowed. Use struct-update syntax (`SidecarConfig { peer_secrets,
    /// ..SidecarConfig::new(...) }`) to customize.
    pub fn new(
        agent_id: impl Into<String>,
        token_issuer_secret: [u8; 32],
        saacp_listen_addr: SocketAddr,
        http_listen_addr: SocketAddr,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            token_issuer_secret,
            saacp_listen_addr,
            http_listen_addr,
            peer_secrets: HashMap::new(),
            max_concurrent_sends: SIDECAR_DEFAULT_MAX_CONCURRENT_SENDS,
            send_retry_attempts: SIDECAR_DEFAULT_SEND_RETRY_ATTEMPTS,
            target_allowlist: Vec::new(),
            allow_private_targets: false,
        }
    }
}

// ─── SSRF target validation (H-21) ────────────────────────────────────────────

/// Is `ip` inside one of the RFC 1918 private ranges, or link-local (v4
/// `169.254.0.0/16`, v6 `fe80::/10`), or IPv6 unique-local (`fc00::/7`)?
///
/// Deliberately does NOT include loopback: sidecars routinely dial peer sidecars on
/// `127.0.0.1` in same-host dev/test/container-per-agent deployments (see
/// `tests/test_sidecar_rs.rs`), and blocking it would break that common, legitimate
/// topology without meaningfully closing a different attack surface than blocking RFC
/// 1918 already does. The cloud-metadata endpoint (`169.254.169.254`) — the highest-value
/// SSRF target in practice — is covered by the v4 link-local check.
fn is_default_blocked_target(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            o[0] == 10
                || (o[0] == 172 && (16..=31).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || v4.is_link_local()
        }
        IpAddr::V6(v6) => {
            let seg0 = v6.segments()[0];
            (seg0 & 0xfe00) == 0xfc00 // fc00::/7 (unique local)
                || (seg0 & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
        }
    }
}

/// Does `ip` fall within the `(network, prefix_len)` CIDR block? Mismatched address
/// families (v4 ip vs v6 network or vice versa) never match.
fn ip_in_cidr(ip: &IpAddr, network: &IpAddr, prefix_len: u8) -> bool {
    match (ip, network) {
        (IpAddr::V4(ip), IpAddr::V4(net)) => {
            let bits = prefix_len.min(32);
            let mask: u32 = if bits == 0 { 0 } else { u32::MAX << (32 - bits) };
            (u32::from(*ip) & mask) == (u32::from(*net) & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(net)) => {
            let bits = prefix_len.min(128);
            let mask: u128 = if bits == 0 { 0 } else { u128::MAX << (128 - bits) };
            (u128::from(*ip) & mask) == (u128::from(*net) & mask)
        }
        _ => false,
    }
}

/// H-21 (SSRF) fix: is `ip` a permitted `/send` target? Public and loopback addresses are
/// always allowed. RFC-1918/link-local addresses are allowed only if `allow_private` is
/// set, or `ip` matches an entry in `allowlist`.
fn target_ip_allowed(ip: &IpAddr, allowlist: &[(IpAddr, u8)], allow_private: bool) -> bool {
    if !is_default_blocked_target(ip) {
        return true;
    }
    allow_private || allowlist.iter().any(|(net, len)| ip_in_cidr(ip, net, *len))
}

/// Resolve `target_addr` (a `host:port` string) exactly once and return the first
/// candidate `SocketAddr` that passes [`target_ip_allowed`]. Resolving once — rather than
/// letting `TcpStream::connect` re-resolve the hostname on every retry — closes a
/// DNS-rebinding variant of the SSRF: a malicious/compromised DNS answer can't swap from a
/// public IP (that passed validation) to an internal one between the initial check and a
/// later connection attempt, because every subsequent retry dials the same validated
/// `SocketAddr`, never the hostname again.
async fn resolve_allowed_target(
    target_addr: &str,
    allowlist: &[(IpAddr, u8)],
    allow_private: bool,
) -> Result<SocketAddr, SidecarError> {
    let mut first_seen: Option<IpAddr> = None;
    let candidates = tokio::net::lookup_host(target_addr).await.map_err(SidecarError::Io)?;
    for addr in candidates {
        if first_seen.is_none() {
            first_seen = Some(addr.ip());
        }
        if target_ip_allowed(&addr.ip(), allowlist, allow_private) {
            return Ok(addr);
        }
    }
    Err(SidecarError::TargetForbidden(
        first_seen.map(|ip| ip.to_string()).unwrap_or_else(|| target_addr.to_string()),
    ))
}

// ─── Inbox ────────────────────────────────────────────────────────────────────

/// A message decrypted, gate-verified, and delivered to this sidecar, ready to be handed to
/// the local (e.g. Python) agent via `/receive`.
#[derive(Debug, Clone, Serialize)]
pub struct DeliveredMessage {
    pub from_agent: String,
    pub task: String,
    pub priority: i64,
    pub action_class: u8,
    pub session_uuid: String,
}

impl DeliveredMessage {
    /// Extracts a schema-1 ("Task") message from a gate-verified `ParsedPacket`. Returns
    /// `None` for anything that isn't a `{task, priority}` payload — other schemas are a
    /// natural extension of this same pattern (see module doc), not handled in v1.
    fn from_parsed(parsed: &ParsedPacket) -> Option<Self> {
        let task = match parsed.payload_dict.get("task") {
            Some(JsonValue::String(s)) => s.clone(),
            _ => return None,
        };
        let priority = match parsed.payload_dict.get("priority") {
            Some(JsonValue::Number(n)) => *n as i64,
            _ => 1,
        };
        Some(Self {
            from_agent: parsed.source_agent.clone(),
            task,
            priority,
            action_class: parsed.action_class,
            session_uuid: parsed.session_uuid.clone(),
        })
    }
}

/// Bounded, single-consumer inbox fed by `SAACPNetworkDaemon`'s `on_delivered` hook.
struct Inbox {
    rx: Mutex<mpsc::Receiver<DeliveredMessage>>,
}

impl Inbox {
    async fn recv_timeout(&self, wait: Duration) -> Option<DeliveredMessage> {
        let mut rx = self.rx.lock().await;
        tokio::time::timeout(wait, rx.recv()).await.ok().flatten()
    }

    /// Current number of undelivered messages waiting for `/receive` to pick them up.
    async fn len(&self) -> usize {
        self.rx.lock().await.len()
    }
}

// ─── Outbound send ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendOutcome {
    /// The peer's gate pipeline accepted the packet (wire ack was `SUCCESS`/`STREAM_ACK`/...).
    Success,
    /// The peer's gate pipeline rejected the packet (a PECF opaque-error wire response).
    Rejected,
}

#[derive(Debug)]
pub enum SidecarError {
    /// TCP connect failed outright — retried up to `send_retry_attempts` times.
    Connect(std::io::Error),
    /// TCP connect didn't complete within the timeout — retried the same as `Connect`.
    ConnectTimeout,
    Handshake(crate::errors::SAACPHardDrop),
    Session(crate::errors::SAACPHardDrop),
    Io(std::io::Error),
    /// Timed out at any post-connect step (handshake, write, or ack read) — never
    /// retried, since it indicates a live but misbehaving/slow peer, not a transient
    /// connect failure.
    Timeout,
    /// H-21 (SSRF) fix: `target_addr` resolved to an address in a blocked range (RFC
    /// 1918 / link-local) with no matching allowlist entry and `allow_private_targets`
    /// unset. Carries the offending IP for diagnostics. No socket is ever opened for a
    /// forbidden target.
    TargetForbidden(String),
}

impl std::fmt::Display for SidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::ConnectTimeout => write!(f, "timed out connecting to peer"),
            Self::Handshake(e) => write!(f, "handshake failed: {}", e.message),
            Self::Session(e) => write!(f, "session setup failed: {}", e.message),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Timeout => write!(f, "timed out waiting for a response"),
            Self::TargetForbidden(ip) => {
                write!(f, "target address '{ip}' is not permitted (private/link-local range blocked)")
            }
        }
    }
}

impl std::error::Error for SidecarError {}

/// Connect to `target` (a pre-resolved, allowlist-validated `SocketAddr` — see
/// `resolve_allowed_target`), retrying only a transient failure/timeout at this exact step
/// up to `retry_attempts` times with a fixed short backoff. See this module's doc comment
/// for why only the connect step is retried. Takes a concrete `SocketAddr` rather than a
/// hostname so retries never re-resolve DNS (see `resolve_allowed_target`'s doc comment on
/// why that matters for H-21).
async fn connect_with_retry(
    target: SocketAddr,
    retry_attempts: u32,
    timeout: Duration,
) -> Result<TcpStream, SidecarError> {
    let mut attempt = 0u32;
    loop {
        match tokio::time::timeout(timeout, TcpStream::connect(target)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(e)) => {
                if attempt >= retry_attempts {
                    return Err(SidecarError::Connect(e));
                }
            }
            Err(_) => {
                if attempt >= retry_attempts {
                    return Err(SidecarError::ConnectTimeout);
                }
            }
        }
        attempt += 1;
        tokio::time::sleep(Duration::from_millis(SEND_RETRY_BACKOFF_MS)).await;
    }
}

/// Send one schema-1 ("Task") message to a peer's SAACP listener. Opens a fresh TCP
/// connection (retrying transient connect failures up to `retry_attempts` times), performs
/// a real X25519 ECDH handshake (`daemon::client_handshake`), issues a capability token
/// signed with `secret` (the mesh-wide shared secret, or a peer-specific one — see this
/// module's "per-peer issuer secrets" doc section), builds a real AES-256-GCM frame
/// (`measc::MEASCFrame::build_frame`), and classifies the peer's ack. See this module's doc
/// comment for why the token's `allow` list is always `["unknown"]` rather than
/// `target_agent`.
#[allow(clippy::too_many_arguments)]
pub async fn send_message(
    target_addr: &str,
    target_agent: &str,
    from_agent: &str,
    secret: &[u8; 32],
    task: &str,
    priority: i64,
    action_class: u8,
    retry_attempts: u32,
    target_allowlist: &[(IpAddr, u8)],
    allow_private_targets: bool,
    audit_log: Option<&ImmutableAuditLog>,
) -> Result<SendOutcome, SidecarError> {
    let timeout = Duration::from_secs(SIDECAR_SEND_TIMEOUT_SECS);

    // H-21 (SSRF) fix: resolve and validate BEFORE ever opening a socket. A rejected
    // target never reaches `connect_with_retry`.
    let validated_target = tokio::time::timeout(
        timeout,
        resolve_allowed_target(target_addr, target_allowlist, allow_private_targets),
    )
        .await
        .map_err(|_| SidecarError::Timeout)??;

    let mut stream = connect_with_retry(validated_target, retry_attempts, timeout).await?;

    let (session_key, _identity_session_id) = tokio::time::timeout(timeout, client_handshake(&mut stream, None))
        .await
        .map_err(|_| SidecarError::Timeout)?
        .map_err(SidecarError::Handshake)?;

    let session_id: [u8; 16] = rand::random();
    let epoch_mgr = SessionEpochManager::new();
    epoch_mgr
        .create_session(
            session_id,
            session_key,
            MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
            MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
            None,
        )
        .map_err(SidecarError::Session)?;
    let epoch_id = epoch_mgr.get_current_epoch_id(&session_id).unwrap_or(0);

    // See module doc: every send is the first packet on a fresh connection, so the peer's
    // bootstrap identity is always "unknown" — the allow-list must match that, not
    // `target_agent`. `target_agent` is still the real semantic recipient though, and is
    // used below (not discarded) for the Command Center's delegation-edge audit logging —
    // see this module's "SAACP Command Center" wiring note.
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        secret, from_agent, &[BOOTSTRAP_AGENT], &[], 60, None, action_class, None,
    );

    // Command Center trust-mesh wiring: log a real (from_agent -> target_agent) capability
    // grant edge once per dispatch. Deliberately hooked here (token issuance), not inside
    // `ZeroTrustGateway::validate_lateral_movement` (Gate 1.0, which re-verifies the SAME
    // already-issued token on every packet and only ever sees the bootstrap "unknown"
    // identity from this call site) — see CLAUDE.md's "SAACP Command Center" section for
    // why this is the correct, low-frequency, semantically-real place for this edge.
    if let Some(log) = audit_log {
        FAITFAuditLog::log_delegation(
            log, from_agent, target_agent, 0, "sidecar message capability", None, "",
        );
    }
    let token_str = String::from_utf8(token).map_err(|_| SidecarError::Session(
        crate::errors::SAACPHardDrop::new(
            crate::errors::SAACPBytecodes::SchemaMismatch, "issued token was not valid UTF-8",
        ),
    ))?;

    let payload = serde_json::json!({
        "task": task,
        "priority": priority,
        "_capability_token": token_str,
    }).to_string();

    let frame = epoch_mgr
        .with_epoch_mut(&session_id, epoch_id, |epoch| {
            MEASCFrame::build_frame(
                epoch, 1, 0x10, 0, action_class,
                payload.as_bytes(), &[0u8; 32], &[0u8; 24], 0,
            )
        })
        .ok_or_else(|| SidecarError::Session(crate::errors::SAACPHardDrop::new(
            crate::errors::SAACPBytecodes::EpochExpired, "epoch disappeared immediately after creation",
        )))?
        .map_err(SidecarError::Session)?
        .0;

    tokio::time::timeout(timeout, {
        use tokio::io::AsyncWriteExt;
        stream.write_all(&frame)
    })
        .await
        .map_err(|_| SidecarError::Timeout)?
        .map_err(SidecarError::Io)?;

    let mut response = [0u8; 128];
    let n = tokio::time::timeout(timeout, {
        use tokio::io::AsyncReadExt;
        stream.read(&mut response)
    })
        .await
        .map_err(|_| SidecarError::Timeout)?
        .map_err(SidecarError::Io)?;

    if &response[..n] == b"SUCCESS"
        || &response[..n] == b"STREAM_ACK"
        || &response[..n] == b"STREAM_END_ACK"
    {
        Ok(SendOutcome::Success)
    } else {
        Ok(SendOutcome::Rejected)
    }
}

// ─── HTTP API ─────────────────────────────────────────────────────────────────

struct SidecarState {
    agent_id: String,
    token_issuer_secret: [u8; 32],
    peer_secrets: HashMap<String, [u8; 32]>,
    send_retry_attempts: u32,
    send_semaphore: tokio::sync::Semaphore,
    inbox: Inbox,
    inbox_capacity: usize,
    /// H-21 (SSRF) fix — see `SidecarConfig::target_allowlist`.
    target_allowlist: Vec<(IpAddr, u8)>,
    /// H-21 (SSRF) fix — see `SidecarConfig::allow_private_targets`.
    allow_private_targets: bool,
}

impl SidecarState {
    /// The secret to sign/verify traffic with `target_agent` under: their own pairwise
    /// entry if one is registered, else the mesh-wide shared secret (see module doc's
    /// "per-peer issuer secrets" section).
    fn secret_for(&self, target_agent: &str) -> [u8; 32] {
        self.peer_secrets
            .get(target_agent)
            .copied()
            .unwrap_or(self.token_issuer_secret)
    }
}

#[derive(Deserialize)]
struct SendRequest {
    to_agent: String,
    target_addr: String,
    task: String,
    #[serde(default = "default_priority")]
    priority: i64,
    #[serde(default)]
    action_class: u8,
}
fn default_priority() -> i64 { 1 }

#[derive(Serialize)]
struct SendResponse {
    status: &'static str,
    detail: Option<String>,
}

async fn handle_send(
    State(state): State<Arc<SidecarState>>,
    Json(req): Json<SendRequest>,
) -> (StatusCode, Json<SendResponse>) {
    // Bounded outbound concurrency: a short bounded wait for a free permit, then an
    // explicit saturation response rather than queuing without bound (see module doc).
    let _permit = match tokio::time::timeout(
        Duration::from_millis(SEND_PERMIT_ACQUIRE_WAIT_MS),
        state.send_semaphore.acquire(),
    ).await {
        Ok(Ok(permit)) => permit,
        _ => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(SendResponse {
                    status: "saturated",
                    detail: Some("too many concurrent outbound sends in flight; retry shortly".into()),
                }),
            );
        }
    };

    let secret = state.secret_for(&req.to_agent);
    match send_message(
        &req.target_addr, &req.to_agent, &state.agent_id, &secret,
        &req.task, req.priority, req.action_class, state.send_retry_attempts,
        &state.target_allowlist, state.allow_private_targets,
        Some(ImmutableAuditLog::global()),
    ).await {
        Ok(SendOutcome::Success) => (
            StatusCode::OK,
            Json(SendResponse { status: "success", detail: None }),
        ),
        Ok(SendOutcome::Rejected) => (
            StatusCode::OK,
            Json(SendResponse { status: "rejected", detail: Some("peer rejected the packet".into()) }),
        ),
        // H-21 (SSRF) fix: a forbidden target is a client-request problem (bad/malicious
        // `target_addr`), not an upstream failure — 403, not 502.
        Err(e @ SidecarError::TargetForbidden(_)) => (
            StatusCode::FORBIDDEN,
            Json(SendResponse { status: "error", detail: Some(e.to_string()) }),
        ),
        Err(e) => (
            StatusCode::BAD_GATEWAY,
            Json(SendResponse { status: "error", detail: Some(e.to_string()) }),
        ),
    }
}

#[derive(Deserialize)]
struct ReceiveQuery {
    #[serde(default = "default_wait_secs")]
    wait_secs: f64,
}
fn default_wait_secs() -> f64 { 5.0 }

async fn handle_receive(
    State(state): State<Arc<SidecarState>>,
    Query(q): Query<ReceiveQuery>,
) -> Response {
    let wait = Duration::from_secs_f64(q.wait_secs.clamp(0.0, SIDECAR_MAX_RECEIVE_WAIT_SECS));
    match state.inbox.recv_timeout(wait).await {
        Some(msg) => (StatusCode::OK, Json(msg)).into_response(),
        None => StatusCode::NO_CONTENT.into_response(),
    }
}

async fn handle_healthz(State(state): State<Arc<SidecarState>>) -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "status": "ok",
        "agent_id": state.agent_id,
        "inbox_depth": state.inbox.len().await,
        "inbox_capacity": state.inbox_capacity,
        "peers_configured": state.peer_secrets.len(),
    }))
}

/// Start the sidecar: the real SAACP protocol listener (peer sidecars dial in) plus the
/// local plain-HTTP/JSON API (the co-located agent talks to this). Runs forever.
pub async fn run(config: SidecarConfig) {
    let (tx, rx) = mpsc::channel::<DeliveredMessage>(SIDECAR_INBOX_CAPACITY);

    let gateway = Arc::new(ZeroTrustGateway::new());
    let epoch_manager = Arc::new(SessionEpochManager::new());

    // Per-peer issuer secrets (see module doc): once any entry is registered, the
    // registry becomes authoritative for every subsequent token — no more falling back
    // to a shared secret for anyone. Empty `peer_secrets` (default) never calls this, so
    // today's single-shared-secret behavior is unchanged.
    for (peer_id, secret) in &config.peer_secrets {
        gateway
            .register_issuer_key(peer_id.as_str(), secret)
            .unwrap_or_else(|e| {
                panic!("saacp-sidecar: failed to register peer secret for '{peer_id}': {}", e.message)
            });
    }

    let daemon = SAACPNetworkDaemon::new(
        &config.saacp_listen_addr.ip().to_string(),
        config.saacp_listen_addr.port(),
        Some(config.token_issuer_secret.to_vec()),
    )
        .with_gateway(Arc::clone(&gateway))
        .with_encrypted_transport(Arc::clone(&epoch_manager))
        .with_on_delivered(Arc::new(move |parsed: ParsedPacket| {
            if let Some(msg) = DeliveredMessage::from_parsed(&parsed) {
                // Synchronous, non-blocking — called from inside `spawn_blocking` (see
                // `SAACPNetworkDaemon`'s `on_delivered` field doc comment). A full inbox
                // drops the message rather than blocking the gate-pipeline thread.
                let _ = tx.try_send(msg);
            }
        }));

    tokio::spawn(async move { daemon.start().await; });

    let state = Arc::new(SidecarState {
        agent_id: config.agent_id,
        token_issuer_secret: config.token_issuer_secret,
        peer_secrets: config.peer_secrets,
        send_retry_attempts: config.send_retry_attempts,
        send_semaphore: tokio::sync::Semaphore::new(config.max_concurrent_sends.max(1)),
        inbox: Inbox { rx: Mutex::new(rx) },
        inbox_capacity: SIDECAR_INBOX_CAPACITY,
        target_allowlist: config.target_allowlist,
        allow_private_targets: config.allow_private_targets,
    });

    let app = Router::new()
        .route("/send", post(handle_send))
        .route("/receive", get(handle_receive))
        .route("/healthz", get(handle_healthz))
        .layer(DefaultBodyLimit::max(MAX_PAYLOAD_SIZE))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind(config.http_listen_addr)
        .await
        .unwrap_or_else(|e| panic!("saacp-sidecar: bind HTTP {} failed: {}", config.http_listen_addr, e));

    eprintln!("[SAACP Sidecar] HTTP API listening on {}", config.http_listen_addr);
    axum::serve(listener, app)
        .await
        .unwrap_or_else(|e| panic!("saacp-sidecar: HTTP server failed: {}", e));
}

#[cfg(test)]
mod ssrf_target_validation_tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rfc1918_ranges_are_blocked_by_default() {
        assert!(is_default_blocked_target(&v4("10.0.0.1")));
        assert!(is_default_blocked_target(&v4("10.255.255.255")));
        assert!(is_default_blocked_target(&v4("172.16.0.1")));
        assert!(is_default_blocked_target(&v4("172.31.255.255")));
        assert!(is_default_blocked_target(&v4("192.168.1.1")));
    }

    #[test]
    fn adjacent_ranges_outside_rfc1918_are_not_blocked() {
        // 172.15.x and 172.32.x are outside the 172.16.0.0/12 block.
        assert!(!is_default_blocked_target(&v4("172.15.255.255")));
        assert!(!is_default_blocked_target(&v4("172.32.0.0")));
        // 11.x is outside 10.0.0.0/8.
        assert!(!is_default_blocked_target(&v4("11.0.0.1")));
        // 193.168.x is not 192.168.x.
        assert!(!is_default_blocked_target(&v4("193.168.1.1")));
    }

    #[test]
    fn link_local_and_cloud_metadata_are_blocked() {
        assert!(is_default_blocked_target(&v4("169.254.169.254"))); // AWS/GCP/Azure metadata
        assert!(is_default_blocked_target(&v4("169.254.1.1")));
    }

    #[test]
    fn ipv6_unique_local_and_link_local_are_blocked() {
        assert!(is_default_blocked_target(&"fc00::1".parse().unwrap()));
        assert!(is_default_blocked_target(&"fd12:3456::1".parse().unwrap()));
        assert!(is_default_blocked_target(&"fe80::1".parse().unwrap()));
    }

    #[test]
    fn loopback_and_public_addresses_are_not_blocked() {
        assert!(!is_default_blocked_target(&v4("127.0.0.1")));
        assert!(!is_default_blocked_target(&v4("8.8.8.8")));
        assert!(!is_default_blocked_target(&"::1".parse().unwrap()));
        assert!(!is_default_blocked_target(&"2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn target_ip_allowed_respects_allow_private_flag() {
        let ip = v4("10.1.2.3");
        assert!(!target_ip_allowed(&ip, &[], false));
        assert!(target_ip_allowed(&ip, &[], true));
    }

    #[test]
    fn target_ip_allowed_respects_explicit_allowlist_entry() {
        let ip = v4("10.1.2.3");
        let allowlist = vec![(v4("10.1.0.0"), 16)];
        assert!(target_ip_allowed(&ip, &allowlist, false));

        let outside = v4("10.2.0.1");
        assert!(!target_ip_allowed(&outside, &allowlist, false));
    }

    #[test]
    fn ip_in_cidr_handles_exact_and_boundary_prefixes() {
        assert!(ip_in_cidr(&v4("192.168.5.9"), &v4("192.168.0.0"), 16));
        assert!(!ip_in_cidr(&v4("192.169.5.9"), &v4("192.168.0.0"), 16));
        // /32 = exact match only.
        assert!(ip_in_cidr(&v4("1.2.3.4"), &v4("1.2.3.4"), 32));
        assert!(!ip_in_cidr(&v4("1.2.3.5"), &v4("1.2.3.4"), 32));
        // /0 matches everything of the same family.
        assert!(ip_in_cidr(&v4("255.255.255.255"), &v4("0.0.0.0"), 0));
    }

    #[test]
    fn ip_in_cidr_never_matches_across_address_families() {
        let v4_ip = v4("10.0.0.1");
        let v6_net: IpAddr = "fc00::".parse().unwrap();
        assert!(!ip_in_cidr(&v4_ip, &v6_net, 8));
    }

    #[tokio::test]
    async fn resolve_allowed_target_rejects_blocked_target_before_connecting() {
        let err = resolve_allowed_target("10.55.66.77:9", &[], false).await.unwrap_err();
        assert!(matches!(err, SidecarError::TargetForbidden(_)), "expected TargetForbidden, got {err}");
    }

    #[tokio::test]
    async fn resolve_allowed_target_permits_loopback_by_default() {
        // Port 0 target won't actually accept a connection, but resolution + the
        // allowlist check must succeed (this only tests validation, not connect).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let resolved = resolve_allowed_target(&addr.to_string(), &[], false).await.unwrap();
        assert_eq!(resolved, addr);
    }

    #[tokio::test]
    async fn resolve_allowed_target_permits_private_target_when_allowlisted() {
        let allowlist = vec![(v4("10.55.0.0"), 16)];
        let resolved = resolve_allowed_target("10.55.66.77:9", &allowlist, false).await.unwrap();
        assert_eq!(resolved.ip(), v4("10.55.66.77"));
    }

    #[tokio::test]
    async fn resolve_allowed_target_permits_private_target_when_flag_set() {
        let resolved = resolve_allowed_target("10.55.66.77:9", &[], true).await.unwrap();
        assert_eq!(resolved.ip(), v4("10.55.66.77"));
    }
}
