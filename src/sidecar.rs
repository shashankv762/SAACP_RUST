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
//! - One shared 32-byte `token_issuer_secret` across the whole trusted mesh (an out-of-band
//!   pre-shared key, not a per-peer registry) — same "honest v1, real v2 later" pattern as
//!   `trust_decay.rs`. A v2 could add per-peer issuer keys via
//!   `ZeroTrustGateway::register_issuer_key`.
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

use std::net::SocketAddr;
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
use crate::gateway::ZeroTrustGateway;
use crate::handler::{JsonValue, ParsedPacket};
use crate::measc::{MEASCFrame, SessionEpochManager, MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS};
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

// ─── Configuration ───────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct SidecarConfig {
    /// This sidecar's own agent identity — used as the `iss` claim on tokens it issues.
    pub agent_id: String,
    /// Shared out-of-band HMAC secret trusted by every peer in this mesh (see module doc).
    pub token_issuer_secret: [u8; 32],
    /// Address the real SAACP protocol listener binds (peer sidecars dial this).
    pub saacp_listen_addr: SocketAddr,
    /// Address the local plain-HTTP/JSON API binds (the co-located agent talks to this).
    pub http_listen_addr: SocketAddr,
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
    Connect(std::io::Error),
    Handshake(crate::errors::SAACPHardDrop),
    Session(crate::errors::SAACPHardDrop),
    Io(std::io::Error),
    Timeout,
}

impl std::fmt::Display for SidecarError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(e) => write!(f, "connect failed: {e}"),
            Self::Handshake(e) => write!(f, "handshake failed: {}", e.message),
            Self::Session(e) => write!(f, "session setup failed: {}", e.message),
            Self::Io(e) => write!(f, "io error: {e}"),
            Self::Timeout => write!(f, "timed out waiting for a response"),
        }
    }
}

impl std::error::Error for SidecarError {}

/// Send one schema-1 ("Task") message to a peer's SAACP listener. Opens a fresh TCP
/// connection, performs a real X25519 ECDH handshake (`daemon::client_handshake`), issues a
/// capability token signed with `token_issuer_secret`, builds a real AES-256-GCM frame
/// (`measc::MEASCFrame::build_frame`), and classifies the peer's ack. See this module's doc
/// comment for why the token's `allow` list is always `["unknown"]` rather than
/// `target_agent`.
pub async fn send_message(
    target_addr: &str,
    target_agent: &str,
    from_agent: &str,
    token_issuer_secret: &[u8; 32],
    task: &str,
    priority: i64,
    action_class: u8,
) -> Result<SendOutcome, SidecarError> {
    let timeout = Duration::from_secs(SIDECAR_SEND_TIMEOUT_SECS);

    let mut stream = tokio::time::timeout(timeout, TcpStream::connect(target_addr))
        .await
        .map_err(|_| SidecarError::Timeout)?
        .map_err(SidecarError::Connect)?;

    let session_key = tokio::time::timeout(timeout, client_handshake(&mut stream))
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
    // `target_agent` (which is retained as a parameter for future connection-reuse/pinning
    // scenarios and for the caller's own bookkeeping).
    let _ = target_agent;
    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        token_issuer_secret, from_agent, &[BOOTSTRAP_AGENT], &[], 60, None, action_class, None,
    );
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
    inbox: Inbox,
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
    match send_message(
        &req.target_addr, &req.to_agent, &state.agent_id, &state.token_issuer_secret,
        &req.task, req.priority, req.action_class,
    ).await {
        Ok(SendOutcome::Success) => (
            StatusCode::OK,
            Json(SendResponse { status: "success", detail: None }),
        ),
        Ok(SendOutcome::Rejected) => (
            StatusCode::OK,
            Json(SendResponse { status: "rejected", detail: Some("peer rejected the packet".into()) }),
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
    Json(serde_json::json!({"status": "ok", "agent_id": state.agent_id}))
}

/// Start the sidecar: the real SAACP protocol listener (peer sidecars dial in) plus the
/// local plain-HTTP/JSON API (the co-located agent talks to this). Runs forever.
pub async fn run(config: SidecarConfig) {
    let (tx, rx) = mpsc::channel::<DeliveredMessage>(SIDECAR_INBOX_CAPACITY);

    let gateway = Arc::new(ZeroTrustGateway::new());
    let epoch_manager = Arc::new(SessionEpochManager::new());

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
        inbox: Inbox { rx: Mutex::new(rx) },
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
