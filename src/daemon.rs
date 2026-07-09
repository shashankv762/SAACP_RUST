//! daemon.rs — SAACPNetworkDaemon
//!
//! Full feature-parity with Python SAACP daemon.py (329 lines).
//! Async TCP server using Tokio. One task spawned per accepted connection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::handler::{ParsedPacket, SAACPProtocolHandler};
use crate::measc::SessionEpochManager;
use crate::pecf::{generate_correlation_id, internal_to_external_raw, SREL};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum seconds to assemble a full MTU-chunked packet (VULN-02).
pub const MAX_ASSEMBLY_TIME: f64 = 30.0;

/// Maximum seconds to complete the ECDH handshake before DDoS-dropping.
pub const HANDSHAKE_TIMEOUT_SECS: f64 = 0.1;

/// Maximum seconds to complete a C-3 identity-bound ECDH handshake (`with_identity_binding`)
/// before DDoS-dropping. Larger than `HANDSHAKE_TIMEOUT_SECS` because this mode does
/// genuinely more work on the same wire round-trip — reading a variable-length certificate,
/// an Ed25519 CA-signature verification, and an Ed25519 proof-of-possession verification,
/// versus the plain mode's single fixed-size read. Still tight enough to bound the
/// resource cost of a slow-loris connection attempt to a small multiple of the plain mode.
pub const IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS: f64 = 0.5;

/// Maximum distinct IP addresses tracked by the circuit breaker.
pub const MAX_CIRCUIT_BREAKER_IPS: usize = 10_000;

/// CRIT-9 fix: maximum concurrent connections accepted across the whole listener.
/// Without this, `tokio::spawn` is called for every accepted connection with no bound,
/// and each connection can be forced (via a crafted header claiming a large payload) to
/// hold up to `MAX_PAYLOAD_SIZE` (10MB) — ~1,000 slow-feed connections exhausts 10GB.
pub const MAX_CONNECTIONS: usize = 10_000;

/// CRIT-9 fix: maximum concurrent connections accepted from a single source IP.
/// Bounds a single attacker from consuming the entire `MAX_CONNECTIONS` budget alone.
pub const MAX_CONNECTIONS_PER_IP: usize = 100;

/// Number of consecutive errors before an IP is locked out.
const CIRCUIT_BREAKER_ERROR_THRESHOLD: u32 = 5;

/// Lockout duration in seconds after threshold breached.
const CIRCUIT_BREAKER_LOCKOUT_SECS: f64 = 30.0;

/// Token re-validation interval for pinned connections (VULN-04).
const TOKEN_REVALIDATION_INTERVAL_SECS: f64 = 30.0;

/// Maximum payload size (10 MB).
pub(crate) const MAX_PAYLOAD_SIZE: usize = 10_000_000;

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

// ─── PerIpConnectionGuard ────────────────────────────────────────────────────

/// CRIT-9 fix: RAII guard enforcing `MAX_CONNECTIONS_PER_IP`. `acquire` increments the
/// caller's IP's live-connection count (rejecting once at the per-IP cap); the count is
/// decremented automatically when the guard is dropped (connection closes or errors),
/// mirroring how `CircuitBreakerEntry` state is keyed per-IP.
pub(crate) struct PerIpConnectionGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl PerIpConnectionGuard {
    /// Returns `None` if `ip` already has `max_per_ip` live connections.
    pub(crate) fn acquire(
        counts: &Arc<Mutex<HashMap<IpAddr, usize>>>,
        ip: IpAddr,
        max_per_ip: usize,
    ) -> Option<Self> {
        let mut guard = counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = guard.entry(ip).or_insert(0);
        if *count >= max_per_ip {
            return None;
        }
        *count += 1;
        drop(guard);
        Some(Self { counts: Arc::clone(counts), ip })
    }
}

impl Drop for PerIpConnectionGuard {
    fn drop(&mut self) {
        let mut guard = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = guard.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                guard.remove(&self.ip);
            }
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
    /// Opt-in C-3 identity binding (see `identity_binding.rs` and `with_identity_binding`).
    /// `None` preserves today's exact handshake wire format and behavior. `Some` requires
    /// every connecting client to present an `AgentIdentityCertificate` and prove possession
    /// of the certified private key during the ECDH handshake, before any packet is
    /// processed.
    server_agent_id: Option<String>,
    /// CRIT-9 fix: caps total concurrent connections at `MAX_CONNECTIONS`.
    connection_semaphore: Arc<Semaphore>,
    /// CRIT-9 fix: caps concurrent connections per source IP at `MAX_CONNECTIONS_PER_IP`.
    per_ip_connections: Arc<Mutex<HashMap<IpAddr, usize>>>,
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
            server_agent_id: None,
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            per_ip_connections: Arc::new(Mutex::new(HashMap::new())),
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

    /// Opt in to C-3 identity binding (`identity_binding.rs`): every connecting client
    /// must present an `AgentIdentityCertificate` signed by one of `ca_keys` and prove
    /// possession of the certified private key during the ECDH handshake, before any
    /// packet is processed. Implies `with_server_auth(seed)` — a `TranscriptBoundSession`
    /// needs a server identity key on both sides of the transcript, so the two cannot be
    /// configured independently.
    ///
    /// Registers `ca_keys` into the process-wide `DEFAULT_IDENTITY_VERIFIER` (keyed by
    /// `ca_kid`) so the handshake can validate certificates against them.
    ///
    /// When enabled, the client handshake message grows from
    /// `[client_nonce(32)] || [client_x25519_pub(32)]` to additionally carry
    /// `[session_id(16)] || [cert_len(u32 LE)] || [cert_json(cert_len)] || [pop_sig(64)]`,
    /// where `pop_sig` is an Ed25519 signature — made with the certified private key —
    /// over `client_nonce || client_x25519_pub || session_id`. A client not configured to
    /// send this extended message will fail to complete the handshake against a daemon
    /// built with `with_identity_binding`.
    pub fn with_identity_binding(
        mut self,
        seed: [u8; 32],
        server_agent_id: &str,
        ca_keys: &[(&str, ed25519_dalek::VerifyingKey)],
    ) -> Self {
        for (kid, vk) in ca_keys {
            crate::identity_binding::DEFAULT_IDENTITY_VERIFIER.register_ca_key(kid, *vk);
        }
        self.server_ed25519_seed = Some(seed);
        self.server_agent_id = Some(server_agent_id.to_string());
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
                    // CRIT-9 fix: bound total and per-IP concurrent connections before
                    // spawning a handler task, so an unbounded flood of slow-feed
                    // connections cannot exhaust memory (each connection can be forced
                    // to hold up to MAX_PAYLOAD_SIZE via a crafted header).
                    let permit = match Arc::clone(&self.connection_semaphore).try_acquire_owned() {
                        Ok(permit) => permit,
                        Err(_) => {
                            eprintln!(
                                "[SAACP Daemon] Connection limit ({}) reached — rejecting {}",
                                MAX_CONNECTIONS, peer_addr,
                            );
                            drop(stream);
                            continue;
                        }
                    };
                    let per_ip_guard = match PerIpConnectionGuard::acquire(
                        &self.per_ip_connections, peer_addr.ip(), MAX_CONNECTIONS_PER_IP,
                    ) {
                        Some(guard) => guard,
                        None => {
                            eprintln!(
                                "[SAACP Daemon] Per-IP connection limit ({}) reached for {} — rejecting",
                                MAX_CONNECTIONS_PER_IP, peer_addr.ip(),
                            );
                            drop(stream);
                            continue;
                        }
                    };

                    let cbs    = Arc::clone(&self.circuit_breakers);
                    let secret = self.token_issuer_secret.clone();
                    let seed   = self.server_ed25519_seed;
                    let gateway       = self.gateway.clone();
                    let epoch_manager = self.epoch_manager.clone();
                    let on_delivered  = self.on_delivered.clone();
                    let server_agent_id = self.server_agent_id.clone();
                    tokio::spawn(async move {
                        let _permit = permit; // released on drop when this task ends
                        let _per_ip_guard = per_ip_guard;
                        handle_client(
                            stream, peer_addr, cbs, secret, seed,
                            gateway, epoch_manager, on_delivered, server_agent_id,
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
    // C-3 fix: `Some(server_agent_id)` requires the connecting client to present an
    // `AgentIdentityCertificate` + proof-of-possession during the ECDH handshake (see
    // `SAACPNetworkDaemon::with_identity_binding`). `None` preserves today's exact
    // handshake wire format and behavior.
    server_agent_id: Option<String>,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let ip_key = peer_addr.ip().to_string();
    let ip_trust_key = ip_trust_key(&ip_key);

    // ── Step 0: Circuit breaker check ────────────────────────────────────────
    {
        // H-22 fix: recover from a poisoned mutex instead of propagating the panic —
        // a poisoned `circuit_breakers` lock would otherwise cascade into every future
        // connection's Step 0 check panicking too, DoSing the whole daemon from one
        // unrelated panic. Matches `PerIpConnectionGuard`'s existing recovery pattern.
        let cbs = circuit_breakers.lock().unwrap_or_else(|e| e.into_inner());
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

    // ── Step 1: X25519 ECDH handshake with a DDoS timeout ─────────────────────
    let handshake_timeout_secs = if server_agent_id.is_some() {
        IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS
    } else {
        HANDSHAKE_TIMEOUT_SECS
    };
    let (session_key, verified_identity) = match timeout(
        Duration::from_secs_f64(handshake_timeout_secs),
        ecdh_handshake(&mut stream, server_ed25519_seed, server_agent_id.as_deref()),
    ).await {
        Ok(Ok(k)) => k,
        _ => {
            record_error(&circuit_breakers, &ip_key);
            return;
        }
    };

    // C-3: the session_id every subsequent packet header on this connection must carry.
    // `None` unless this daemon opted into identity binding (`with_identity_binding`).
    let bound_session_id: Option<[u8; 16]> = verified_identity.as_ref().map(|v| v.session_id);
    if let Some(ref v) = verified_identity {
        eprintln!("[SAACP Daemon] {peer_addr}: C-3 identity-bound as agent '{}'", v.agent_id);
    }

    // Identity pinning state (VULN-04) — deliberately NOT pre-seeded from
    // `verified_identity`, even though the agent is already cryptographically known at
    // this point. `pinned_agent` doubles as `target_agent` fed into Gate 1.0's
    // `validate_lateral_movement` (`current_agent_name` below), which enforces a
    // self-issue guard rejecting any token whose `iss` equals `target_agent`. Pre-pinning
    // to the proven agent_id would make a well-behaved agent's own correctly-self-named
    // token collide with that guard on its very first packet. Identity binding is instead
    // enforced independently and unconditionally in `handler.rs`'s Gate 1.0 — by comparing
    // the token's claimed `source_agent` against the `TranscriptBoundSession` registered
    // for this connection's session_id — so bootstrap pinning here is untouched.
    let mut pinned_agent: Option<String>       = None;
    let mut last_validated_at: Option<Instant> = None;
    // Track the revocation epoch at the time of last successful validation.
    // If the global epoch advances (i.e. all tokens are revoked), this connection
    // must be disconnected — continuing would accept a revoked token.
    let mut pinned_revocation_epoch: u64 =
        crate::gateway::ZeroTrustGateway::global().get_revocation_epoch();

    // ── C-3 Identity Gate ──────────────────────────────────────────────────────
    // NOTE: no phase is advanced here at connection-init time beyond what
    // `ecdh_handshake` itself already advanced (IDENTITY_VERIFIED, only when identity
    // binding is configured). A previous version of this code called
    // `GLOBAL_IDENTITY_GATE.advance("unknown", ..., "connection_init")`, but
    // `"connection_init"` is not one of the six canonical `IDENTITY_GATE_PHASES`
    // (`identity_binding.rs`) — `advance()` rejects unknown phase names and returns
    // `Err`, which the `let _ = ...` silently discarded. That call had done nothing,
    // ever, since it was written: recording "unknown" as having completed a phase
    // before any authentication has even happened would itself be a false security
    // signal, not a fix, so it is removed outright rather than patched to a real phase
    // name. AUTHORIZED is advanced below, once Gate 1.0 has actually validated a
    // capability token for this connection (`handler.rs`).

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

        // 2d0. C-3 session-splice defense: when this connection is identity-bound, every
        // packet's header session_id (bytes 16..32) must equal the one committed — and
        // proof-of-possession signed — during the handshake. Without this check, a
        // connection that proved identity X at handshake time could present a different
        // session_id per packet, silently bypassing the Gate 1.0 identity cross-check in
        // `handler.rs` (which looks up the registered `TranscriptBoundSession` by
        // session_id: an unregistered session_id simply skips the check).
        if let Some(bound_sid) = bound_session_id {
            let packet_sid: Option<[u8; 16]> = full_packet.get(16..32).and_then(|s| s.try_into().ok());
            if packet_sid != Some(bound_sid) {
                send_hard_drop(
                    &mut stream,
                    SAACPBytecodes::SessionSpliceDetected,
                    "Packet session_id does not match identity-bound handshake session_id",
                ).await;
                record_error(&circuit_breakers, &ip_key);
                break;
            }
        }

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
                // Wire format requires a real 32-hex-char correlation ID (spec §9.3);
                // an empty string both violates that contract and previously produced
                // a zero-filled correlation_id region on the wire (silently in release
                // builds, via a debug_assert panic in debug/test builds).
                let wire = SREL::normalize_response(ext, &generate_correlation_id());
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
///
/// ## C-3 identity binding mode (`identity_binding_server_agent_id = Some(..)`)
/// Requires `with_identity_binding` on the daemon (which also forces
/// `server_ed25519_seed = Some`). The client message grows to additionally carry:
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] || [session_id(16)]
///                    || [cert_len(u32 LE, 4)] || [cert_json(cert_len)] || [pop_sig(64)]
/// where `pop_sig` = Ed25519.sign(client_nonce || client_x25519_pub || session_id) made
/// with the private key certified in `cert_json` (an `AgentIdentityCertificate`). This
/// proves possession of the agent's long-term identity key — something a stolen bearer
/// capability token alone can never produce — closing the gap where any holder of a
/// leaked token could otherwise impersonate the agent it names. On success, a
/// `TranscriptBoundSession` is registered in `identity_binding::DEFAULT_IDENTITY_REGISTRY`
/// keyed by this `session_id`, and `IDENTITY_VERIFIED` is advanced in
/// `identity_binding::GLOBAL_IDENTITY_GATE` for (agent_id, session_id). See
/// `handler.rs`'s Gate 1.0 for the corresponding capability-token cross-check.
async fn ecdh_handshake<S>(
    stream: &mut S,
    server_ed25519_seed: Option<[u8; 32]>,
    identity_binding_server_agent_id: Option<&str>,
) -> Result<([u8; 32], Option<VerifiedClientIdentity>), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use rand::rngs::OsRng;
    use ed25519_dalek::{SigningKey, Signer, Signature, VerifyingKey, Verifier};

    // Step 1: Read client's nonce (32B) + X25519 public key (32B)
    let mut client_msg = [0u8; 64];
    stream.read_exact(&mut client_msg).await.map_err(|_| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader, "Handshake read (nonce+key) failed",
    ))?;
    let client_nonce: [u8; 32]   = client_msg[0..32].try_into().unwrap();
    let peer_pub_bytes: [u8; 32] = client_msg[32..64].try_into().unwrap();

    // Step 1b: When identity binding is required, read the extended identity block and
    // verify the certificate + proof-of-possession before proceeding with the DH exchange.
    let pending_identity = if let Some(server_agent_id) = identity_binding_server_agent_id {
        let mut fixed = [0u8; 16 + 4];
        stream.read_exact(&mut fixed).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::IdentityBindingMissing,
            "Identity handshake block (session_id + cert_len) missing",
        ))?;
        let session_id: [u8; 16] = fixed[0..16].try_into().unwrap();
        let cert_len = u32::from_le_bytes(fixed[16..20].try_into().unwrap()) as usize;

        // Bound the certificate size to prevent unbounded allocation from a malicious peer.
        const MAX_CERT_JSON_BYTES: usize = 16_384;
        if cert_len == 0 || cert_len > MAX_CERT_JSON_BYTES {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing,
                "Identity certificate length out of bounds",
            ));
        }

        let mut cert_buf = vec![0u8; cert_len];
        stream.read_exact(&mut cert_buf).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::IdentityBindingMissing, "Identity certificate read failed",
        ))?;
        let mut pop_sig_buf = [0u8; 64];
        stream.read_exact(&mut pop_sig_buf).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::IdentityBindingMissing, "Proof-of-possession signature read failed",
        ))?;

        let cert_json = std::str::from_utf8(&cert_buf).map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::IdentityBindingMissing, "Identity certificate is not valid UTF-8",
        ))?;
        let cert = crate::identity_binding::AgentIdentityCertificate::from_json(cert_json)
            .map_err(|_| SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing, "Identity certificate is malformed",
            ))?;

        // Verify the CA signature, expiry, and revocation status.
        crate::identity_binding::DEFAULT_IDENTITY_VERIFIER.verify_certificate(&cert)?;

        // Verify proof-of-possession: the peer must sign this exact handshake's
        // (client_nonce || client_x25519_pub || session_id) with the certified key. Since
        // client_nonce is fresh random per connection, this cannot be precomputed or
        // replayed from a captured transcript — only possession of the actual private key
        // (never present in a bearer capability token) can produce a valid signature here.
        let cert_pk_bytes: [u8; 32] = hex::decode(&cert.public_key_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding, "Identity certificate public key malformed",
            ))?;
        let cert_vk = VerifyingKey::from_bytes(&cert_pk_bytes).map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding, "Identity certificate public key invalid",
        ))?;
        let mut pop_transcript = Vec::with_capacity(64 + 16);
        pop_transcript.extend_from_slice(&client_nonce);
        pop_transcript.extend_from_slice(&peer_pub_bytes);
        pop_transcript.extend_from_slice(&session_id);
        let pop_sig = Signature::from_bytes(&pop_sig_buf);
        if cert_vk.verify(&pop_transcript, &pop_sig).is_err() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "Proof-of-possession signature verification failed",
            ));
        }

        Some((cert, session_id, server_agent_id.to_string()))
    } else {
        None
    };

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
        to_sign.extend_from_slice(&client_nonce);
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
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;

    // Step 6: On successful identity binding, establish and register the
    // TranscriptBoundSession, then advance IDENTITY_VERIFIED. This runs only after the DH
    // exchange (and thus the handshake write above) has completed, but the certificate +
    // proof-of-possession were already verified in Step 1b before any server secret was
    // committed to the wire.
    let verified_identity = if let Some((cert, session_id, server_agent_id)) = pending_identity {
        let server_pub_hex = server_ed25519_seed
            .map(|seed| {
                let vk = SigningKey::from_bytes(&seed).verifying_key();
                hex::encode(vk.as_bytes())
            })
            .unwrap_or_default();
        let server_nonce: [u8; 32] = rand::random();

        let mut session = crate::identity_binding::TranscriptBoundSession::establish(
            session_id.to_vec(),
            &cert.agent_id,
            &server_agent_id,
            &cert.public_key_hex,
            &server_pub_hex,
            &hex::encode(client_nonce),
            &hex::encode(server_nonce),
            "SAACP/0.1-beta2",
            "Ed25519-AES256GCM",
            None,
        );
        session.mark_identity_verified();

        let agent_id = cert.agent_id.clone();
        let session_id_hex = hex::encode(session_id);
        crate::identity_binding::DEFAULT_IDENTITY_REGISTRY.register(session);
        let _ = crate::identity_binding::GLOBAL_IDENTITY_GATE
            .advance(&agent_id, &session_id_hex, "IDENTITY_VERIFIED");

        Some(VerifiedClientIdentity { agent_id, session_id })
    } else {
        None
    };

    Ok((session_key, verified_identity))
}

/// Result of a successful C-3 identity-bound handshake (see `ecdh_handshake`'s doc
/// comment). `agent_id` is the certified identity proven via proof-of-possession;
/// `session_id` is the client-committed session identifier that every subsequent packet
/// header on this connection must match (enforced in `handle_client`).
pub(crate) struct VerifiedClientIdentity {
    pub agent_id: String,
    pub session_id: [u8; 16],
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
/// path) is only implemented when `identity` (below) is supplied — a client not opting into
/// C-3 identity binding still gets the plain unauthenticated read, matching today's exact
/// behavior byte-for-byte.
///
/// Wire protocol (unauthenticated mode, `identity = None` — must match `ecdh_handshake`'s
/// unauthenticated mode exactly):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
///
/// Wire protocol (C-3 identity-bound mode, `identity = Some(..)` — must match
/// `ecdh_handshake`'s identity-binding mode exactly, and requires the target daemon be
/// built with `SAACPNetworkDaemon::with_identity_binding`):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] || [session_id(16)]
///                    || [cert_len(u32 LE, 4)] || [cert_json(cert_len)] || [pop_sig(64)]
///   Server → Client: [server_x25519_pub(32)] || [ed25519_sig(64)] || [ed25519_vk(32)] = 128B
///
/// Returns `(session_key, session_id)` — `session_id` is `Some` only in identity-bound mode,
/// and is the value the caller must place in every subsequent MEASC packet header's
/// session_id field (bytes 16..32) — the daemon rejects any mismatch as a session-splice
/// attempt.
pub async fn client_handshake<S>(
    stream: &mut S,
    identity: Option<&ClientIdentityConfig>,
) -> Result<([u8; 32], Option<[u8; 16]>), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use rand::rngs::OsRng;
    use ed25519_dalek::{Signature, Signer, VerifyingKey, Verifier};

    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());

    let session_id: Option<[u8; 16]> = if let Some(cfg) = identity {
        let sid: [u8; 16] = rand::random();

        // Proof-of-possession: sign this exact handshake's transcript with the
        // certificate's private key. Fresh per connection (client_nonce/sid), so it
        // cannot be replayed from a captured transcript by anyone who only holds a
        // bearer capability token, not the actual identity private key.
        let mut pop_transcript = Vec::with_capacity(64 + 16);
        pop_transcript.extend_from_slice(&client_nonce);
        pop_transcript.extend_from_slice(client_pub.as_bytes());
        pop_transcript.extend_from_slice(&sid);
        let pop_sig = cfg.signing_key.sign(&pop_transcript);

        let cert_json = cfg.certificate.to_json();
        let cert_bytes = cert_json.as_bytes();
        client_msg.extend_from_slice(&sid);
        client_msg.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
        client_msg.extend_from_slice(cert_bytes);
        client_msg.extend_from_slice(&pop_sig.to_bytes());

        Some(sid)
    } else {
        None
    };

    stream.write_all(&client_msg).await.map_err(|_| SAACPHardDrop::new(
        SAACPBytecodes::MalformedHeader, "client_handshake: write failed",
    ))?;

    let server_pub_bytes: [u8; 32] = if let Some(cfg) = identity {
        // Identity-bound mode implies the daemon was built with `with_identity_binding`,
        // which always enables server auth — read and verify the full authenticated
        // response rather than silently trusting an unauthenticated server pubkey.
        let mut auth_msg = [0u8; 128];
        stream.read_exact(&mut auth_msg).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader, "client_handshake: read authenticated server response failed",
        ))?;
        let server_pub_bytes: [u8; 32] = auth_msg[0..32].try_into().unwrap();
        let sig_bytes: [u8; 64]        = auth_msg[32..96].try_into().unwrap();
        let vk_bytes: [u8; 32]         = auth_msg[96..128].try_into().unwrap();

        if vk_bytes != cfg.expected_server_verifying_key {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "client_handshake: server verifying key does not match pinned expectation",
            ));
        }
        let server_vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding, "client_handshake: server verifying key invalid",
        ))?;
        let mut to_verify = Vec::with_capacity(64);
        to_verify.extend_from_slice(&client_nonce);
        to_verify.extend_from_slice(&server_pub_bytes);
        let sig = Signature::from_bytes(&sig_bytes);
        if server_vk.verify(&to_verify, &sig).is_err() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "client_handshake: server signature verification failed",
            ));
        }
        server_pub_bytes
    } else {
        let mut server_pub_bytes = [0u8; 32];
        stream.read_exact(&mut server_pub_bytes).await.map_err(|_| SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader, "client_handshake: read server pubkey failed",
        ))?;
        server_pub_bytes
    };
    let server_pub = PublicKey::from(server_pub_bytes);

    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;

    Ok((session_key, session_id))
}

/// Client-side configuration for C-3 identity binding (see `client_handshake`'s doc
/// comment and `ecdh_handshake`'s server-side counterpart). Constructing one requires an
/// `AgentIdentityCertificate` already issued by a CA the target daemon trusts.
pub struct ClientIdentityConfig {
    /// This agent's CA-issued identity certificate.
    pub certificate: crate::identity_binding::AgentIdentityCertificate,
    /// Ed25519 signing key corresponding to `certificate.public_key_hex` — used to prove
    /// possession via the handshake's proof-of-possession signature.
    pub signing_key: ed25519_dalek::SigningKey,
    /// The target daemon's expected Ed25519 verifying key (from
    /// `SAACPNetworkDaemon::server_verifying_key`), distributed out-of-band. Required
    /// because `with_identity_binding` always enables server authentication — an
    /// identity-bound client must never accept an unauthenticated server response.
    pub expected_server_verifying_key: [u8; 32],
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Namespaced `TrustDecayEngine` key for an IP address — distinct prefix so
/// it can never collide with a real agent_id sharing the same process-wide
/// map (see the Step 0b comment in `handle_client` for the full rationale).
fn ip_trust_key(ip: &str) -> String {
    format!("ip:{ip}")
}

fn record_error(cbs: &Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>, ip: &str) {
    // H-22 fix: same poison-recovery as the Step 0 check above — this is the other
    // call site sharing the same process-wide `Arc<Mutex<...>>`.
    let mut map = cbs.lock().unwrap_or_else(|e| e.into_inner());
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
    // Wire format requires a real 32-hex-char correlation ID (spec §9.3); see the
    // matching fix in the main connection-loop error arm above for the full rationale.
    let wire = SREL::normalize_response(ext, &generate_correlation_id());
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
