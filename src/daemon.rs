//! daemon.rs — SAACPNetworkDaemon
//!
//! Full feature-parity with Python SAACP daemon.py (329 lines).
//! Async TCP server using Tokio. One task spawned per accepted connection.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::timeout;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::handler::{ParsedPacket, SAACPProtocolHandler};
use crate::measc::SessionEpochManager;
use crate::pecf::{internal_to_external_raw, SREL};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum seconds to assemble a full MTU-chunked packet (VULN-02).
pub const MAX_ASSEMBLY_TIME: f64 = 30.0;

/// Maximum seconds to complete the ECDH handshake before DDoS-dropping.
pub const HANDSHAKE_TIMEOUT_SECS: f64 = 0.1;

/// Maximum distinct IP addresses tracked by the circuit breaker.
pub const MAX_CIRCUIT_BREAKER_IPS: usize = 10_000;

/// Number of consecutive errors before an IP is locked out.
const CIRCUIT_BREAKER_ERROR_THRESHOLD: u32 = 5;

/// Lockout duration in seconds after threshold breached.
const CIRCUIT_BREAKER_LOCKOUT_SECS: f64 = 30.0;

/// Token re-validation interval for pinned connections (VULN-04).
const TOKEN_REVALIDATION_INTERVAL_SECS: f64 = 30.0;

/// Maximum payload size (10 MB).
const MAX_PAYLOAD_SIZE: usize = 10_000_000;

/// MEASC header size in bytes.
const HEADER_SIZE: usize = 128;

/// Wire response strings (must match Python daemon.py exactly).
const WIRE_SUCCESS: &[u8]        = b"SUCCESS";
const WIRE_STREAM_ACK: &[u8]     = b"STREAM_ACK";
const WIRE_STREAM_END_ACK: &[u8] = b"STREAM_END_ACK";
const WIRE_YIELD_ASYNC: &[u8]    = b"YIELD_ASYNC";

// ─── CircuitBreakerEntry ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub(crate) struct CircuitBreakerEntry {
    error_count: u32,
    lockout_until: Option<Instant>,
}

impl CircuitBreakerEntry {
    fn new() -> Self {
        Self { error_count: 0, lockout_until: None }
    }

    fn is_locked(&self) -> bool {
        self.lockout_until.is_some_and(|t| Instant::now() < t)
    }

    fn record_error(&mut self) {
        // Reset if previous lockout has expired
        if self.lockout_until.is_some_and(|t| Instant::now() >= t) {
            self.error_count = 0;
            self.lockout_until = None;
        }
        self.error_count += 1;
        if self.error_count >= CIRCUIT_BREAKER_ERROR_THRESHOLD {
            self.lockout_until = Some(Instant::now()
                + Duration::from_secs_f64(CIRCUIT_BREAKER_LOCKOUT_SECS));
        }
    }
}

// ─── SAACPNetworkDaemon ──────────────────────────────────────────────────────

/// Async TCP server implementing the full SAACP network daemon.
///
/// Features (matching Python daemon.py):
///   - X25519 ECDH handshake with 100ms DDoS timeout
///   - Optional Ed25519 server authentication (DAEMON-MTLS fix): server signs its
///     X25519 ephemeral public key so active MITM cannot substitute their key.
///   - Per-IP circuit breaker (5 errors → 30s lockout, OOM guard at 10k IPs)
///   - Persistent connection loop with 2s header read timeout
///   - MTU chunking assembly with 30s aggregate timeout (VULN-02)
///   - Agent identity pinning with 30s re-validation interval (VULN-04)
///   - Stream routing: STREAM_CONTINUATION → STREAM_ACK, STREAM_END → STREAM_END_ACK
///   - INPUT_REQUIRED → YIELD_ASYNC + connection close
///   - PECF error translation + SREL timing equalization on hard drops
pub struct SAACPNetworkDaemon {
    host: String,
    port: u16,
    token_issuer_secret: Option<Vec<u8>>,
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>,
    /// DAEMON-MTLS: optional Ed25519 signing key seed (32 bytes) for server auth.
    server_ed25519_seed: Option<[u8; 32]>,
    /// Opt-in real Gate 1.0 token verification (DAEMON-NO-TOKEN-VERIFY fix). `None`
    /// preserves today's existing behavior byte-for-byte: `handle_client` calls the 4-arg
    /// `intercept_packet` wrapper, which always passes `gateway: None` into Gate 1.0 and
    /// grants every token a hardcoded `max_action_class = 0` / `source_agent = "unknown"`
    /// without ever checking its HMAC signature. `Some` routes through
    /// `intercept_packet_full`/`intercept_packet_encrypted` with a real gateway instead.
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    /// Opt-in real AES-256-GCM decryption (DAEMON-NO-AEAD fix). `None` preserves today's
    /// existing behavior: Gate 0 uses the structural-only `framing::MEASCFrame::parse_header`,
    /// which never decrypts. `Some` routes incoming packets through the real encrypting
    /// `measc::MEASCFrame::parse_frame`/`SessionEpochManager` machinery instead — see
    /// `with_encrypted_transport`.
    epoch_manager: Option<Arc<SessionEpochManager>>,
    /// Opt-in hook invoked with every successfully-verified `ParsedPacket` right before the
    /// ack is written back — lets a caller (e.g. `sidecar.rs`) observe decrypted, gate-passed
    /// payloads without forking `handle_client`'s dispatch logic. Called from inside
    /// `spawn_blocking`, so implementations must not `.await` (use `try_send`/`blocking_send`).
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
}

impl SAACPNetworkDaemon {
    pub fn new(host: &str, port: u16, token_issuer_secret: Option<Vec<u8>>) -> Self {
        Self {
            host: host.to_string(),
            port,
            token_issuer_secret,
            circuit_breakers: Arc::new(Mutex::new(HashMap::new())),
            server_ed25519_seed: None,
            gateway: None,
            epoch_manager: None,
            on_delivered: None,
        }
    }

    /// Enable server-side Ed25519 authentication for the ECDH handshake.
    ///
    /// `seed` must be 32 bytes (Ed25519 signing key seed). The corresponding
    /// verifying key should be distributed out-of-band to all connecting clients
    /// via FAITF TrustStore or configuration.
    ///
    /// When enabled, the server handshake wire format changes from
    /// `[x25519_pub(32)]` to
    /// `[x25519_pub(32)] || [ed25519_sig(64)] || [ed25519_vk(32)]` = 128 bytes.
    ///
    /// Clients MUST verify the signature before accepting the DH exchange.
    pub fn with_server_auth(mut self, seed: [u8; 32]) -> Self {
        self.server_ed25519_seed = Some(seed);
        self
    }

    /// Opt in to real Gate 1.0 capability-token signature verification
    /// (`ZeroTrustGateway::validate_lateral_movement`) instead of the structural-only
    /// presence check every connection gets by default. See the `gateway` field doc comment.
    pub fn with_gateway(mut self, gateway: Arc<crate::gateway::ZeroTrustGateway>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Opt in to real AES-256-GCM decryption + replay-window enforcement of incoming
    /// packets via `measc::MEASCFrame::parse_frame`, instead of the structural-only Gate 0.
    /// See the `epoch_manager` field doc comment.
    pub fn with_encrypted_transport(mut self, epoch_manager: Arc<SessionEpochManager>) -> Self {
        self.epoch_manager = Some(epoch_manager);
        self
    }

    /// Observe every successfully-verified `ParsedPacket` (see the `on_delivered` field doc
    /// comment).
    pub fn with_on_delivered(
        mut self,
        callback: Arc<dyn Fn(ParsedPacket) + Send + Sync>,
    ) -> Self {
        self.on_delivered = Some(callback);
        self
    }

    /// Start listening for connections. Runs forever.
    pub async fn start(&self) {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await
            .unwrap_or_else(|e| panic!("SAACPNetworkDaemon: bind {} failed: {}", addr, e));

        let auth_mode = if self.server_ed25519_seed.is_some() { "authenticated" } else { "unauthenticated" };
        eprintln!("[SAACP Daemon] Listening on {} ({} handshake)", addr, auth_mode);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let cbs    = Arc::clone(&self.circuit_breakers);
                    let secret = self.token_issuer_secret.clone();
                    let seed   = self.server_ed25519_seed;
                    let gateway       = self.gateway.clone();
                    let epoch_manager = self.epoch_manager.clone();
                    let on_delivered  = self.on_delivered.clone();
                    tokio::spawn(async move {
                        handle_client(
                            stream, peer_addr, cbs, secret, seed,
                            gateway, epoch_manager, on_delivered,
                        ).await;
                    });
                }
                Err(e) => {
                    eprintln!("[SAACP Daemon] Accept error: {}", e);
                }
            }
        }
    }

    /// Derive the server's Ed25519 verifying key from the seed (32 bytes → 32-byte VK).
    /// Returns `None` if server auth is not configured.
    pub fn server_verifying_key(&self) -> Option<[u8; 32]> {
        use ed25519_dalek::SigningKey;
        self.server_ed25519_seed.map(|seed| {
            SigningKey::from_bytes(&seed).verifying_key().to_bytes()
        })
    }
}

// ─── handle_client ───────────────────────────────────────────────────────────

/// Per-connection async handler (mirrors Python SAACPNetworkDaemon.handle_client).
///
/// Generic over any duplex byte stream (`AsyncRead + AsyncWrite`), not just
/// `TcpStream`. This lets the same handshake/framing/gate-pipeline logic run
/// unmodified over a tunneled transport (e.g. `transport::ws::WsByteStream`
/// behind the `transport-ws` feature) — only the byte source/sink differs; the
/// MEASC header parsing, MTU assembly, and gate dispatch below are identical.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_client<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>,
    // DAEMON-NO-TOKEN-VERIFY fix: previously received but never read (hence the leading
    // underscore) — the structural default path still ignores it (matching today's exact
    // behavior), but the `gateway`-opted-in branches below now use it as the stable,
    // out-of-band Gate 1.0 issuer-secret fallback instead of the ephemeral per-connection
    // ECDH `session_key`, since coupling token validity to a key that changes every
    // reconnect would be a fragile, unintended design.
    token_issuer_secret: Option<Vec<u8>>,
    server_ed25519_seed: Option<[u8; 32]>,
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    epoch_manager: Option<Arc<SessionEpochManager>>,
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let ip_key = peer_addr.ip().to_string();
    let ip_trust_key = ip_trust_key(&ip_key);

    // ── Step 0: Circuit breaker check ────────────────────────────────────────
    {
        let cbs = circuit_breakers.lock().unwrap();
        if let Some(entry) = cbs.get(&ip_key) {
            if entry.is_locked() {
                // Silent drop — no response, no logging (DDoS defence)
                return;
            }
        }
    }

    // ── Step 0b: IP-level behavioral trust check (identity-rotation defense) ──
    // `TrustDecayEngine` (trust_decay.rs) is keyed by the packet's claimed
    // agent identity (`current_agent_name` / capability-token `iss`), by
    // design — it tracks *behavior*, not identity, and assumes identity
    // itself is already stable. But a connection's `pinned_agent` resets to
    // `None` on every hard drop (see below), so a caller that holds (or has
    // compromised) signing credentials for more than one agent identity —
    // or is simply relying on a single shared issuer secret with no
    // per-issuer registry configured, in which case `iss` is a free-form
    // self-chosen claim — can "launder" its accumulated trust penalty by
    // claiming a fresh identity on its next packet, resetting straight back
    // to `TRUST_SCORE_INITIAL`. That defeats the entire point of a
    // *continuous* behavioral signal. The one thing that can't be rotated
    // away for free is the underlying network endpoint, so this tracks a
    // second, independent trust bucket keyed by IP (namespaced via
    // `ip_trust_key` so it can never collide with a real agent_id in the same
    // map) and rejects new connection attempts from an IP whose accumulated
    // distrust has crossed the reauth floor — regardless of what identity it
    // claims next. Checked once per connection (mirroring the IP circuit
    // breaker's own check above, which is likewise only evaluated at connect
    // time, not per-packet) and penalized on every hard drop below.
    if crate::trust_decay::TrustDecayEngine::global().requires_reauth(&ip_trust_key) {
        // Silent drop — no response, no logging (same DDoS-defence rationale
        // as the circuit breaker check above: don't give a probing attacker
        // a distinguishable signal for which defense tripped).
        return;
    }

    // ── Step 1: X25519 ECDH handshake with 100ms timeout ─────────────────────
    let session_key = match timeout(
        Duration::from_secs_f64(HANDSHAKE_TIMEOUT_SECS),
        ecdh_handshake(&mut stream, server_ed25519_seed),
    ).await {
        Ok(Ok(k)) => k,
        _ => {
            record_error(&circuit_breakers, &ip_key);
            return;
        }
    };

    // Identity pinning state (VULN-04)
    let mut pinned_agent: Option<String>           = None;
    let mut last_validated_at: Option<Instant>    = None;
    // Track the revocation epoch at the time of last successful validation.
    // If the global epoch advances (i.e. all tokens are revoked), this connection
    // must be disconnected — continuing would accept a revoked token.
    let mut pinned_revocation_epoch: u64 =
        crate::gateway::ZeroTrustGateway::global().get_revocation_epoch();
    
    // ── C-3 Identity Gate ──────────────────────────────────────────────────────
    // NOTE: no phase is advanced here at connection-init time. A previous
    // version of this code called `GLOBAL_IDENTITY_GATE.advance("unknown", ...,
    // "connection_init")`, but `"connection_init"` is not one of the six
    // canonical `IDENTITY_GATE_PHASES` (`identity_binding.rs`) — `advance()`
    // rejects unknown phase names and returns `Err`, which the `let _ = ...`
    // silently discarded. That call had done nothing, ever, since it was
    // written: recording "unknown" as having completed a phase before any
    // authentication has even happened would itself be a false security
    // signal, not a fix, so it is removed outright rather than patched to a
    // real phase name. The first real phase is advanced below, once Gate 1.0
    // has actually validated a capability token for this connection.

    // ── Step 2: Persistent connection loop ────────────────────────────────────
    loop {
        // 2a. Read 128-byte header with 2s timeout
        let mut header_buf = [0u8; HEADER_SIZE];
        match timeout(Duration::from_secs(2), stream.read_exact(&mut header_buf)).await {
            Ok(Ok(_)) => {}
            _ => break, // Connection closed or timeout
        }

        // 2b. Parse payload_length from header bytes [12..16]
        let payload_length = u32::from_be_bytes(
            header_buf[12..16].try_into().unwrap_or([0u8; 4])
        ) as usize;

        if payload_length > MAX_PAYLOAD_SIZE {
            send_hard_drop(&mut stream, SAACPBytecodes::PayloadTooLarge, "Payload exceeds 10MB MTU").await;
            record_error(&circuit_breakers, &ip_key);
            break;
        }

        // 2c. MTU chunking assembly with MAX_ASSEMBLY_TIME aggregate timeout
        // payload_length <= MAX_PAYLOAD_SIZE (10 MB); +16 for auth tag is safe.
        let assembly_start = Instant::now();
        let mut payload_buf = vec![0u8; payload_length.saturating_add(16)];
        let mut bytes_read  = 0usize;

        while bytes_read < payload_buf.len() {
            if assembly_start.elapsed().as_secs_f64() > MAX_ASSEMBLY_TIME {
                send_hard_drop(&mut stream, SAACPBytecodes::TemporalTimeout, "MTU assembly timeout").await;
                record_error(&circuit_breakers, &ip_key);
                return;
            }
            match timeout(Duration::from_secs(1), stream.read(&mut payload_buf[bytes_read..])).await {
                Ok(Ok(0)) => break,   // EOF
                Ok(Ok(n)) => bytes_read += n,
                _ => break,
            }
        }

        // Assemble full frame: header || auth_tag || ciphertext
        let mut full_packet = Vec::with_capacity(HEADER_SIZE + payload_buf.len());
        full_packet.extend_from_slice(&header_buf);
        full_packet.extend_from_slice(&payload_buf[..bytes_read]);

        // 2d. Revocation epoch pinning check (C1 fix).
        // If the global revocation epoch has advanced since this connection last
        // validated, all previously-accepted tokens are revoked. Force disconnect
        // so the client must re-authenticate with a fresh token.
        {
            let current_rev = crate::gateway::ZeroTrustGateway::global().get_revocation_epoch();
            if pinned_agent.is_some() && current_rev > pinned_revocation_epoch {
                send_hard_drop(
                    &mut stream,
                    SAACPBytecodes::KeyRevoked,
                    "Global token revocation — reconnect and re-authenticate",
                ).await;
                break;
            }
            // Periodic re-validation timestamp update
            if let Some(validated_at) = last_validated_at {
                if validated_at.elapsed().as_secs_f64() >= TOKEN_REVALIDATION_INTERVAL_SECS {
                    last_validated_at = Some(Instant::now());
                    pinned_revocation_epoch = current_rev;
                }
            }
        }

        // 2e. Route to handler pipeline — H-1 fix: run CPU-bound gate work on the
        // blocking thread pool so we don't starve tokio I/O workers.
        // AES-GCM, SHA-256, Ed25519 verify, NFKC normalization, DFS graph traversal,
        // and the injection scanner (up to 3.1ms at 50KB) are all synchronous CPU work.
        let start = Instant::now();
        let agent_name = pinned_agent.as_deref().unwrap_or("unknown").to_string();
        let is_pinned  = pinned_agent.is_some();

        // DAEMON-NO-AEAD / DAEMON-NO-TOKEN-VERIFY fix: when the daemon was built with
        // `.with_encrypted_transport(...)`/`.with_gateway(...)`, lazily create the epoch-0
        // session for this packet's session_id (bytes [16..32] of the header) on first
        // sight, then route through the real-AEAD `intercept_packet_encrypted` /
        // `intercept_packet_full` instead of the structural-only `intercept_packet`.
        // `epoch_manager`/`gateway` both `None` (the default) preserves today's exact
        // existing behavior byte-for-byte.
        //
        // `gate_secret` is the stable, out-of-band `token_issuer_secret` this daemon was
        // constructed with, used as Gate 1.0's issuer-secret fallback and to HMAC-bind audit
        // entries — deliberately NOT the ephemeral per-connection ECDH `session_key`, which
        // changes every reconnect and would make token validity fragile if coupled to it.
        // Falls back to `session_key` only if the daemon has no configured issuer secret
        // (keeps `with_gateway`-without-a-configured-secret at least self-consistent rather
        // than panicking on an empty slice).
        let gate_secret: Vec<u8> = token_issuer_secret
            .clone()
            .unwrap_or_else(|| session_key.to_vec());

        let intercept_result = if let Some(epoch_mgr) = epoch_manager.clone() {
            let session_id: [u8; 16] = full_packet.get(16..32)
                .and_then(|s| <[u8; 16]>::try_from(s).ok())
                .unwrap_or([0u8; 16]);
            if epoch_mgr.get_current_epoch_id(&session_id).is_none() {
                // Idempotent: ignore "already exists" races from concurrent packets on
                // the same not-yet-registered session_id — the loser just reuses the
                // winner's session.
                let _ = epoch_mgr.create_session(
                    session_id,
                    session_key,
                    crate::measc::MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
                    crate::measc::MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
                    None,
                );
            }
            let gw_for_task = gateway.clone();
            tokio::task::spawn_blocking(move || {
                SAACPProtocolHandler::intercept_packet_encrypted(
                    &full_packet,
                    &epoch_mgr,
                    &gate_secret,
                    &agent_name,
                    is_pinned,
                    gw_for_task.as_deref(),
                    None,
                    None,
                )
            }).await
        } else {
            let gw_for_task = gateway.clone();
            tokio::task::spawn_blocking(move || {
                match gw_for_task.as_deref() {
                    Some(gw) => SAACPProtocolHandler::intercept_packet_full(
                        &full_packet, &gate_secret, &agent_name, is_pinned,
                        Some(gw), None, None, None, None,
                    ),
                    None => SAACPProtocolHandler::intercept_packet(
                        &full_packet, &session_key, &agent_name, is_pinned,
                    ),
                }
            }).await
        };
        // Flatten JoinError (panic in gate pipeline) into SAACPHardDrop
        let intercept_result = match intercept_result {
            Ok(inner) => inner,
            Err(_join_err) => Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "Gate pipeline task panicked",
            )),
        };
        match intercept_result {
            Ok(parsed) => {
                // Opt-in observer hook (sidecar.rs's Inbox) — invoked synchronously, same
                // as any other post-gate bookkeeping here; implementations must not block
                // (see the `on_delivered` field doc comment on `SAACPNetworkDaemon`).
                if let Some(cb) = on_delivered.as_ref() {
                    cb(parsed.clone());
                }
                // Update pinning state
                if pinned_agent.is_none() && !parsed.source_agent.is_empty() {
                    pinned_agent    = Some(parsed.source_agent.clone());
                    last_validated_at = Some(Instant::now());
                    // Snapshot the current revocation epoch so future revocations
                    // trigger disconnect (C1 fix).
                    pinned_revocation_epoch =
                        crate::gateway::ZeroTrustGateway::global().get_revocation_epoch();
                    // C-3 Identity Gate bookkeeping: by the time `intercept_packet`
                    // returns `Ok`, Gate 1.0 (capability token validation) through
                    // Gate 12.0 have all already passed for this packet, so both
                    // "identity verified" and "authorized" are true facts about
                    // this (agent, session) pair. Use the real phase names from
                    // `IDENTITY_GATE_PHASES` — a prior version of this call used
                    // `"authenticated"`, which is not one of the six canonical
                    // phases and silently failed every single time (see the
                    // removed connection-init call above for the same bug).
                    let _ = crate::identity_binding::GLOBAL_IDENTITY_GATE
                        .advance(&parsed.source_agent, &parsed.session_uuid, "IDENTITY_VERIFIED");
                    let _ = crate::identity_binding::GLOBAL_IDENTITY_GATE
                        .advance(&parsed.source_agent, &parsed.session_uuid, "AUTHORIZED");
                }

                // Route response by status code
                let response = if parsed.is_cover_traffic {
                    WIRE_SUCCESS
                } else {
                    match parsed.status_code {
                        0x17 => WIRE_STREAM_ACK,       // STREAM_START / CONTINUATION
                        0x18 => WIRE_STREAM_ACK,
                        0x19 => WIRE_STREAM_END_ACK,   // STREAM_END
                        0x08 => {
                            // INPUT_REQUIRED → yield + close
                            let _ = stream.write_all(WIRE_YIELD_ASYNC).await;
                            break;
                        }
                        _ => WIRE_SUCCESS,
                    }
                };

                if stream.write_all(response).await.is_err() {
                    break;
                }
            }
            Err(drop) => {
                // PECF error translation + SREL timing equalization
                SREL::equalize_timing(start);
                let ext  = internal_to_external_raw(drop.bytecode as u8);
                let wire = SREL::normalize_response(ext, "");
                let _ = stream.write_all(&wire).await;
                // Clear pinned state on hard drops
                pinned_agent       = None;
                last_validated_at  = None;
                record_error(&circuit_breakers, &ip_key);
                // IP-level trust penalty (identity-rotation defense — see the
                // Step 0b comment above): applied unconditionally on every
                // hard drop, independent of whatever identity this packet
                // claimed, so switching identities cannot reset it.
                let _ = crate::trust_decay::TrustDecayEngine::global()
                    .penalize(&ip_trust_key, crate::trust_decay::PenaltyKind::GenericHardDrop);
                // Most hard drops are non-fatal; loop continues.
                // Fatal drops (epoch expired, etc.) close the connection.
                match drop.bytecode {
                    SAACPBytecodes::EpochExpired
                    | SAACPBytecodes::InvalidSignature
                    | SAACPBytecodes::PsnReplayDetected => break,
                    _ => {}
                }
            }
        }
    }
}

// ─── X25519 ECDH handshake ───────────────────────────────────────────────────

/// Perform X25519 ECDH key exchange and derive a 32-byte AES-GCM session key.
///
/// ## Unauthenticated mode (server_ed25519_seed = None)
/// Classic ECDH — no peer authentication. Vulnerable to active MITM.
///   Client → Server: [x25519_pub(32)]
///   Server → Client: [x25519_pub(32)]
///
/// ## Authenticated mode (server_ed25519_seed = Some(seed))
/// Server signs `client_nonce || server_x25519_pub` with its Ed25519 identity key.
/// The nonce ensures every handshake signature is unique — capturing a previous
/// server message and replaying it against a new connection will fail because the
/// nonce the server signs won't match what the client sent this time.
///
/// Wire protocol (C2 fix — nonce added for freshness):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] || [ed25519_sig(64)] || [ed25519_vk(32)] = 128B
///     where sig = Ed25519.sign(client_nonce || server_x25519_pub)
///
/// Unauthenticated mode (no seed):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
///
/// The client nonce is also mixed into HKDF as the salt so every session key
/// is unique even if the X25519 shared secret is somehow repeated.
async fn ecdh_handshake<S>(
    stream: &mut S,
    server_ed25519_seed: Option<[u8; 32]>,
) -> Result<[u8; 32], SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use rand::rngs::OsRng;
    use ed25519_dalek::{SigningKey, Signer};

    // Step 1: Read client's nonce (32B) + X25519 public key (32B)
    let mut client_msg = [0u8; 64];
    stream.read_exact(&mut client_msg).await.map_err(|_| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader, "Handshake read (nonce+key) failed",
    ))?;
    let client_nonce    = &client_msg[0..32];
    let peer_pub_bytes: [u8; 32] = client_msg[32..64].try_into().unwrap();

    // Step 2: Generate our ephemeral X25519 keypair
    let local_secret = EphemeralSecret::random_from_rng(OsRng);
    let local_pub    = PublicKey::from(&local_secret);

    // Step 3: Send server's public key (with optional Ed25519 authentication)
    if let Some(seed) = server_ed25519_seed {
        // Sign client_nonce || server_x25519_pub so the signature is fresh and
        // bound to this specific client interaction (replay resistance).
        let signing_key   = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let mut to_sign   = Vec::with_capacity(64);
        to_sign.extend_from_slice(client_nonce);
        to_sign.extend_from_slice(local_pub.as_bytes());
        let sig = signing_key.sign(&to_sign);

        let mut auth_msg = Vec::with_capacity(128);
        auth_msg.extend_from_slice(local_pub.as_bytes());
        auth_msg.extend_from_slice(&sig.to_bytes());
        auth_msg.extend_from_slice(verifying_key.as_bytes());

        stream.write_all(&auth_msg).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader, "Authenticated handshake write failed",
        ))?;
    } else {
        stream.write_all(local_pub.as_bytes()).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader, "Handshake write failed",
        ))?;
    }

    // Step 4: X25519 key agreement
    let peer_pub = PublicKey::from(peer_pub_bytes);
    let shared   = local_secret.diffie_hellman(&peer_pub);

    // Step 5: HKDF-SHA256 key derivation.
    // Use the client nonce as salt so that even if the DH shared secret were
    // somehow repeated across sessions, each session derives a distinct key.
    let hk = Hkdf::<Sha256>::new(Some(client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;

    Ok(session_key)
}

/// Client-side (initiator) counterpart of `ecdh_handshake`, unauthenticated mode only —
/// promotes the hand-rolled logic already proven correct in
/// `tests/test_transport_ws_rs.rs`'s `ws_client_handshake` (and this crate's own
/// `tests/test_daemon_encrypted_rs.rs::tcp_client_handshake`) into real library code, so
/// callers that need to dial *out* to a SAACP daemon (e.g. `sidecar.rs`) don't have to
/// hand-roll the wire protocol themselves. `daemon.rs` itself only ever plays the responder
/// role (`ecdh_handshake`); this is the first initiator-side implementation in the crate.
///
/// Ed25519 server-authentication mode (mirroring `ecdh_handshake`'s `server_ed25519_seed`
/// path) is intentionally not implemented here — a v1 scope limit, not a correctness gap:
/// a client that needs to verify a server's signature would need the corresponding
/// verifying key distributed out-of-band first, which is deployment-specific and not yet
/// wired into any caller.
///
/// Wire protocol (must match `ecdh_handshake`'s unauthenticated mode exactly):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
pub async fn client_handshake<S>(stream: &mut S) -> Result<[u8; 32], SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use rand::rngs::OsRng;

    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());
    stream.write_all(&client_msg).await.map_err(|_| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader, "client_handshake: write failed",
    ))?;

    let mut server_pub_bytes = [0u8; 32];
    stream.read_exact(&mut server_pub_bytes).await.map_err(|_| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader, "client_handshake: read server pubkey failed",
    ))?;
    let server_pub = PublicKey::from(server_pub_bytes);

    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;

    Ok(session_key)
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Namespaced `TrustDecayEngine` key for an IP address — distinct prefix so
/// it can never collide with a real agent_id sharing the same process-wide
/// map (see the Step 0b comment in `handle_client` for the full rationale).
fn ip_trust_key(ip: &str) -> String {
    format!("ip:{ip}")
}

fn record_error(cbs: &Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>, ip: &str) {
    let mut map = cbs.lock().unwrap();
    // OOM guard: drop oldest 10% when at capacity
    if map.len() >= MAX_CIRCUIT_BREAKER_IPS && !map.contains_key(ip) {
        let drop_count = MAX_CIRCUIT_BREAKER_IPS / 10;
        let to_drop: Vec<String> = map.keys().take(drop_count).cloned().collect();
        for k in to_drop { map.remove(&k); }
    }
    map.entry(ip.to_string()).or_insert_with(CircuitBreakerEntry::new).record_error();
}

async fn send_hard_drop<S>(stream: &mut S, bc: SAACPBytecodes, _msg: &str)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let ext  = internal_to_external_raw(bc as u8);
    let wire = SREL::normalize_response(ext, "");
    let _ = stream.write_all(&wire).await;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_lockout() {
        let mut entry = CircuitBreakerEntry::new();
        assert!(!entry.is_locked());
        for _ in 0..CIRCUIT_BREAKER_ERROR_THRESHOLD {
            entry.record_error();
        }
        assert!(entry.is_locked(), "Should be locked after threshold errors");
    }

    #[test]
    fn test_circuit_breaker_oom_guard() {
        let cbs: Arc<Mutex<HashMap<String, CircuitBreakerEntry>>> =
            Arc::new(Mutex::new(HashMap::new()));
        // Fill to capacity
        {
            let mut map = cbs.lock().unwrap();
            for i in 0..MAX_CIRCUIT_BREAKER_IPS {
                map.insert(format!("10.0.{}.{}", i / 256, i % 256), CircuitBreakerEntry::new());
            }
        }
        assert_eq!(cbs.lock().unwrap().len(), MAX_CIRCUIT_BREAKER_IPS);
        // Adding a new IP should trigger eviction
        record_error(&cbs, "192.168.1.1");
        assert!(cbs.lock().unwrap().len() < MAX_CIRCUIT_BREAKER_IPS + 1,
            "OOM guard must prevent unbounded growth");
    }

    #[test]
    fn test_ip_trust_key_namespaced() {
        // Namespaced distinctly from a bare agent_id of the same string, so
        // the shared TrustDecayEngine map can never confuse an IP bucket
        // with a real agent identity bucket.
        assert_eq!(ip_trust_key("127.0.0.1"), "ip:127.0.0.1");
        assert_ne!(ip_trust_key("agent-a"), "agent-a");
    }

    #[test]
    fn test_ip_trust_key_evasion_resistance() {
        // Simulates the exact scenario Step 0b defends against: an attacker
        // rotates its claimed agent identity on every request (resetting its
        // own per-agent TrustDecayEngine bucket each time), but the shared
        // IP-level bucket still accumulates penalties across every identity
        // it ever claimed and eventually requires reauth regardless.
        use crate::trust_decay::{TrustDecayEngine, PenaltyKind};
        let engine = TrustDecayEngine::new();
        let ip_key = ip_trust_key("203.0.113.7");

        for i in 0..5 {
            let rotating_identity = format!("agent-rotating-{i}");
            // Per-agent bucket resets fresh every time (fully trusted) —
            // rotating identity alone is a successful evasion of it.
            assert_eq!(engine.score(&rotating_identity), 1.0);
            engine.penalize(&rotating_identity, PenaltyKind::ReplaySuspicion);
            // But the IP-level bucket accumulates regardless of identity.
            engine.penalize(&ip_key, PenaltyKind::ReplaySuspicion);
        }
        // Five ReplaySuspicion penalties (0.40 each) on the same IP bucket
        // drive it below TRUST_REAUTH_THRESHOLD (0.25), forcing reauth even
        // though no single rotating identity ever crossed it.
        assert!(engine.requires_reauth(&ip_key));
    }

    #[test]
    fn test_daemon_new() {
        let d = SAACPNetworkDaemon::new("127.0.0.1", 9900, None);
        assert_eq!(d.host, "127.0.0.1");
        assert_eq!(d.port, 9900);
        assert!(d.token_issuer_secret.is_none());
    }

    #[test]
    fn test_daemon_with_secret() {
        let secret = vec![0u8; 32];
        let d = SAACPNetworkDaemon::new("0.0.0.0", 9901, Some(secret.clone()));
        assert_eq!(d.token_issuer_secret.unwrap(), secret);
    }
}
