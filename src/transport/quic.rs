//! quic.rs — QUIC transport for SAACP (Phase 1.1, `transport-quic` feature).
//!
//! Implements [SAACPQuicDaemon]: an async QUIC server that accepts connections
//! via [quinn] and hands each bidirectional QUIC stream to the existing, untouched
//! [crate::daemon::handle_client] generic — which already operates on any
//! `AsyncRead + AsyncWrite + Unpin + Send`, so no changes to the MEASC header parsing,
//! gate-pipeline dispatch, or session epoch machinery are required.
//!
//! # Why QUIC solves sticky sessions
//!
//! The current MEASC v1 `ReplayWindow` (a 4096-entry per-session bitmap) is held in the
//! `SessionEpochManager`, which is process-local. When a load balancer routes a session's
//! packets to different nodes (non-affine LB, or node failure + reconnect), the second
//! node has no window state and either:
//! 1. Accepts potential replays (if it creates a fresh session), or
//! 2. Rejects all packets until the new session's epoch is established.
//!
//! QUIC solves this at the transport layer via:
//! - **Connection migration** (quinn's native path migration): when an agent's IP/port
//!   changes (e.g., Wi-Fi to 5G), the QUIC connection migrates without a new handshake.
//!   The same logical QUIC connection (and thus the same SAACP session) continues on
//!   the same server node, so the `ReplayWindow` state is never lost.
//! - **0-RTT resumption**: reconnecting agents resume in 0 round trips (using QUIC's
//!   session ticket, which quinn handles automatically), eliminating the X25519 ECDH
//!   handshake latency on reconnect.
//! - **Stateless retry tokens**: quinn issues cryptographic retry tokens to new
//!   connections, which validates the client's IP address before allocating any
//!   server-side session state — providing DDoS protection equivalent to the existing
//!   TCP circuit-breaker without requiring per-IP state before authentication.
//!
//! MEASC v2 packet chaining ([crate::measc::PacketChainVerifier]) extends this
//! further: when a session DOES migrate to a new node (e.g., node failure), the
//! new node can verify chain continuity without needing the full bitmap.
//!
//! # TLS + MEASC double encryption
//!
//! QUIC's own TLS 1.3 handshake encrypts the transport layer. SAACP's MEASC AEAD
//! (AES-256-GCM + HKDF-ratcheted epoch keys) encrypts the application layer on top.
//! This is the same defense-in-depth pattern as the existing `transport-tls` feature.
//! The application-layer MEASC encryption is never removed — it is an Authorization
//! Invariance requirement (Gate 0 must execute on every packet).
//!
//! # Feature gate
//!
//! This module is compiled only when `features = ["transport-quic"]` is set.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use quinn::{Endpoint, ServerConfig};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;

use crate::context::SaacpContext;
use crate::daemon::{
    new_shared_circuit_breakers, PerIpConnectionGuard, SharedCircuitBreakers, MAX_CONNECTIONS,
    MAX_CONNECTIONS_PER_IP,
};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Maximum seconds for the initial QUIC+TLS handshake to complete.
/// Mirrors `daemon::HANDSHAKE_TIMEOUT_SECS` (5s).
const QUIC_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// Maximum seconds to wait for the agent to open the first QUIC bidirectional
/// stream after the connection handshake completes.
const QUIC_STREAM_OPEN_TIMEOUT_SECS: u64 = 5;

/// Maximum concurrent bidi QUIC streams per connection.
/// Set to 1: one SAACP session per QUIC connection (parity with TCP/WS model).
const QUIC_MAX_CONCURRENT_BIDI_STREAMS: u64 = 1;

// ── SAACPQuicDaemon ───────────────────────────────────────────────────────────

/// Async QUIC server implementing the SAACP network daemon over QUIC/UDP.
///
/// Mirrors SAACPNetworkDaemon (TCP) and SAACPWebSocketDaemon (WebSocket) in
/// constructor pattern, connection-semaphore limiting, per-IP circuit breakers,
/// and graceful shutdown. The core security machinery (handle_client, gate
/// pipeline, MEASC frame parsing) is reused identically.
pub struct SAACPQuicDaemon {
    endpoint: Endpoint,
    connection_semaphore: Arc<Semaphore>,
    circuit_breakers: SharedCircuitBreakers,
    context: Option<Arc<SaacpContext>>,
    shutdown: CancellationToken,
    max_connections_per_ip: usize,
    /// DAEMON-NO-TOKEN-VERIFY parity: stable, out-of-band Gate 1.0 issuer
    /// secret. `None` keeps today's structural behavior — but unlike the early
    /// QUIC draft, this is now a *configurable* opt-in rather than a hardcoded
    /// `None` at the dispatch site.
    token_issuer_secret: Option<Vec<u8>>,
    /// Server Ed25519 seed for authenticated ECDH handshakes.
    server_ed25519_seed: Option<[u8; 32]>,
    /// Real token verification / revocation enforcement. Without this, Gate 1.0
    /// is fail-closed for token-bearing packets.
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    /// MEASC AEAD decryption + replay window. Without this, Gate 0 is
    /// structural-only (no confidentiality, no replay protection).
    epoch_manager: Option<Arc<crate::measc::SessionEpochManager>>,
    /// Delivered-packet observability hook.
    on_delivered: Option<Arc<dyn Fn(crate::handler::ParsedPacket) + Send + Sync>>,
    /// C-3: requires an `AgentIdentityCertificate` + proof-of-possession.
    server_agent_id: Option<String>,
    /// M4: global in-flight payload byte budget (permits = bytes).
    inflight_payload_semaphore: Option<Arc<Semaphore>>,
    /// M12: bound on concurrent gate-pipeline executions.
    pipeline_semaphore: Option<Arc<Semaphore>>,
}

impl SAACPQuicDaemon {
    /// Create a new QUIC daemon bound to `addr` using the given TLS server_config.
    pub async fn new(addr: SocketAddr, server_config: ServerConfig) -> std::io::Result<Self> {
        let mut transport_config = quinn::TransportConfig::default();
        transport_config
            .max_concurrent_bidi_streams(
                u8::try_from(QUIC_MAX_CONCURRENT_BIDI_STREAMS)
                    .expect("QUIC stream limit must fit in a VarInt byte")
                    .into(),
            );
        // 1800s matches the MEASC dead man's switch idle period.
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_secs(1800))
                .expect("1800s within quinn's ms range"),
        ));
        // 30s keep-alive prevents NAT/firewall table expiry on quiet sessions.
        transport_config.keep_alive_interval(Some(Duration::from_secs(30)));

        let mut server_config = server_config;
        server_config.transport_config(Arc::new(transport_config));

        let endpoint = Endpoint::server(server_config, addr)?;

        Ok(Self {
            endpoint,
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            circuit_breakers: new_shared_circuit_breakers(),
            context: None,
            shutdown: CancellationToken::new(),
            max_connections_per_ip: MAX_CONNECTIONS_PER_IP,
            token_issuer_secret: None,
            server_ed25519_seed: None,
            gateway: None,
            epoch_manager: None,
            on_delivered: None,
            server_agent_id: None,
            inflight_payload_semaphore: None,
            pipeline_semaphore: None,
        })
    }

    /// Override the global maximum concurrent connections (default: MAX_CONNECTIONS).
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.connection_semaphore = Arc::new(Semaphore::new(max));
        self
    }

    /// Inject a shared circuit-breaker map — IPs locked out on TCP/WS are also blocked here.
    pub fn with_circuit_breakers(mut self, breakers: SharedCircuitBreakers) -> Self {
        self.circuit_breakers = breakers;
        self
    }

    /// Override the per-IP connection limit (default: MAX_CONNECTIONS_PER_IP).
    pub fn with_max_connections_per_ip(mut self, max: usize) -> Self {
        self.max_connections_per_ip = max;
        self
    }

    /// Inject a SaacpContext (for multi-tenant deployments).
    pub fn with_context(mut self, ctx: Arc<SaacpContext>) -> Self {
        self.context = Some(ctx);
        self
    }

    /// Stable, out-of-band Gate 1.0 issuer secret (see the `token_issuer_secret`
    /// doc on `daemon::handle_client`).
    pub fn with_token_issuer_secret(mut self, secret: Vec<u8>) -> Self {
        self.token_issuer_secret = Some(secret);
        self
    }

    /// Enable authenticated ECDH handshakes with this server Ed25519 seed.
    pub fn with_server_ed25519_seed(mut self, seed: [u8; 32]) -> Self {
        self.server_ed25519_seed = Some(seed);
        self
    }

    /// Inject a real `ZeroTrustGateway` so Gate 1.0 performs full token
    /// verification and revocation enforcement.
    pub fn with_gateway(mut self, gateway: Arc<crate::gateway::ZeroTrustGateway>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Inject the MEASC session-epoch manager so Gate 0 performs real AEAD
    /// decryption and replay-window enforcement.
    pub fn with_epoch_manager(mut self, mgr: Arc<crate::measc::SessionEpochManager>) -> Self {
        self.epoch_manager = Some(mgr);
        self
    }

    /// Observability hook invoked for every delivered (gate-passing) packet.
    pub fn with_on_delivered(
        mut self,
        cb: Arc<dyn Fn(crate::handler::ParsedPacket) + Send + Sync>,
    ) -> Self {
        self.on_delivered = Some(cb);
        self
    }

    /// C-3: require an `AgentIdentityCertificate` + proof-of-possession from
    /// every connecting client.
    pub fn with_server_agent_id(mut self, agent_id: impl Into<String>) -> Self {
        self.server_agent_id = Some(agent_id.into());
        self
    }

    /// M4: global in-flight payload byte budget (semaphore permits = bytes).
    pub fn with_inflight_payload_semaphore(mut self, sem: Arc<Semaphore>) -> Self {
        self.inflight_payload_semaphore = Some(sem);
        self
    }

    /// M12: bound concurrent gate-pipeline executions.
    pub fn with_pipeline_semaphore(mut self, sem: Arc<Semaphore>) -> Self {
        self.pipeline_semaphore = Some(sem);
        self
    }

    /// Returns a CancellationToken that triggers graceful shutdown when cancelled.
    pub fn cancellation_token(&self) -> CancellationToken {
        self.shutdown.clone()
    }

    /// Returns the local UDP address the QUIC endpoint is bound to.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Run the QUIC accept loop until the cancellation token fires.
    pub async fn run(self) -> std::io::Result<()> {
        let endpoint = self.endpoint;
        let semaphore = self.connection_semaphore;
        let circuit_breakers = self.circuit_breakers;
        let per_ip_counts: Arc<Mutex<HashMap<IpAddr, usize>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let shutdown = self.shutdown;
        let max_per_ip = self.max_connections_per_ip;
        let context = self.context;
        let token_issuer_secret = self.token_issuer_secret;
        let server_ed25519_seed = self.server_ed25519_seed;
        let gateway = self.gateway;
        let epoch_manager = self.epoch_manager;
        let on_delivered = self.on_delivered;
        let server_agent_id = self.server_agent_id;
        let inflight_payload_semaphore = self.inflight_payload_semaphore;
        let pipeline_semaphore = self.pipeline_semaphore;

        tracing::info!(
            local_addr = ?endpoint.local_addr(),
            "SAACPQuicDaemon: listening on QUIC/UDP"
        );

        // F3 parity (secure-by-default nudge): the same startup warning the TCP
        // daemon prints. A QUIC listener that silently runs without server auth,
        // AEAD, or a token gateway is indistinguishable from an open relay at a
        // glance, so enumerate exactly what is OFF on every start.
        if server_ed25519_seed.is_none() || epoch_manager.is_none() || gateway.is_none() {
            tracing::warn!(
                "SAACPQuicDaemon: protections DISABLED — server_auth={}, transport_crypto={}, token_gateway={}. \
                 Use with_server_ed25519_seed/with_epoch_manager/with_gateway for the hardened profile.",
                server_ed25519_seed.is_some(),
                epoch_manager.is_some(),
                gateway.is_some()
            );
        }

        loop {
            tokio::select! {
                biased;
                () = shutdown.cancelled() => {
                    tracing::info!("SAACPQuicDaemon: shutdown requested");
                    endpoint.close(0u32.into(), b"server shutdown");
                    // Wait for in-flight connections to finish draining.
                    endpoint.wait_idle().await;
                    break;
                }
                incoming = endpoint.accept() => {
                    let conn_attempt = match incoming {
                        Some(c) => c,
                        None => {
                            tracing::debug!("SAACPQuicDaemon: endpoint closed");
                            break;
                        }
                    };

                    let remote_addr = conn_attempt.remote_address();
                    let remote_ip = remote_addr.ip();
                    let remote_ip_str = remote_ip.to_string();

                    // ── Pre-handshake gate: refuse BEFORE accepting ────────
                    // `Incoming` is not a handshake future — it is the pre-accept
                    // handle. `refuse()`/`accept()` must be called on it directly,
                    // while still on the accept-loop task (so the refusal packet is
                    // emitted from the endpoint's own task, not a detached one).
                    let connecting = {
                        // ── Circuit-breaker check ──────────────────────────
                        {
                            let cb = circuit_breakers.lock();
                            if let Some(entry) = cb.get(&remote_ip_str) {
                                if entry.is_locked() {
                                    tracing::warn!(ip = %remote_ip_str,
                                        "SAACPQuicDaemon: circuit breaker active, refusing");
                                    conn_attempt.refuse();
                                    continue;
                                }
                            }
                        }

                        // ── Global connection semaphore ────────────────────
                        let permit = match semaphore.clone().try_acquire_owned() {
                            Ok(p) => p,
                            Err(_) => {
                                tracing::warn!("SAACPQuicDaemon: connection cap reached, refusing");
                                conn_attempt.refuse();
                                continue;
                            }
                        };

                        // ── Per-IP limit ───────────────────────────────────
                        let ip_guard = match PerIpConnectionGuard::acquire(
                            &per_ip_counts, remote_ip, max_per_ip,
                        ) {
                            Some(g) => g,
                            None => {
                                tracing::warn!(ip = %remote_ip_str,
                                    "SAACPQuicDaemon: per-IP cap reached, refusing");
                                conn_attempt.refuse();
                                drop(permit);
                                continue;
                            }
                        };

                        // Handshake begins only after every pre-handshake gate passed.
                        let connecting = match conn_attempt.accept() {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::debug!(ip = %remote_ip_str, error = %e,
                                    "SAACPQuicDaemon: QUIC accept failed");
                                drop((permit, ip_guard));
                                continue;
                            }
                        };
                        (connecting, permit, ip_guard)
                    };
                    let (connecting, permit, ip_guard) = connecting;

                    let cb_clone = Arc::clone(&circuit_breakers);
                    let ctx_clone = context.clone();
                    let secret_clone = token_issuer_secret.clone();
                    let gateway_clone = gateway.clone();
                    let epoch_clone = epoch_manager.clone();
                    let on_delivered_clone = on_delivered.clone();
                    let agent_id_clone = server_agent_id.clone();
                    let inflight_clone = inflight_payload_semaphore.clone();
                    let pipeline_clone = pipeline_semaphore.clone();

                    tokio::spawn(async move {
                        // ── Complete QUIC TLS handshake ────────────────────
                        // `Connecting` (returned by `Incoming::accept`) IS the
                        // handshake future — awaiting it yields the established
                        // `Connection` or a `ConnectionError`.
                        let connection = match tokio::time::timeout(
                            Duration::from_secs(QUIC_HANDSHAKE_TIMEOUT_SECS),
                            connecting,
                        ).await {
                            Ok(Ok(conn)) => conn,
                            Ok(Err(e)) => {
                                tracing::debug!(ip = %remote_ip_str, error = %e,
                                    "SAACPQuicDaemon: QUIC handshake failed");
                                cb_clone.lock()
                                    .entry(remote_ip_str)
                                    .or_insert_with(crate::daemon::CircuitBreakerEntry::new)
                                    .record_error();
                                drop((permit, ip_guard));
                                return;
                            }
                            Err(_) => {
                                tracing::warn!(ip = %remote_ip_str,
                                    "SAACPQuicDaemon: QUIC handshake timeout");
                                cb_clone.lock()
                                    .entry(remote_ip_str)
                                    .or_insert_with(crate::daemon::CircuitBreakerEntry::new)
                                    .record_error();
                                drop((permit, ip_guard));
                                return;
                            }
                        };

                        tracing::debug!(ip = %remote_ip_str,
                            "SAACPQuicDaemon: QUIC handshake complete");

                        // ── Accept first bidi stream ───────────────────────
                        // The agent opens a bidi stream; we get (SendStream, RecvStream).
                        let (send_stream, recv_stream) = match tokio::time::timeout(
                            Duration::from_secs(QUIC_STREAM_OPEN_TIMEOUT_SECS),
                            connection.accept_bi(),
                        ).await {
                            Ok(Ok(pair)) => pair,
                            Ok(Err(e)) => {
                                tracing::debug!(ip = %remote_ip_str, error = %e,
                                    "SAACPQuicDaemon: failed to accept bidi stream");
                                drop((permit, ip_guard));
                                return;
                            }
                            Err(_) => {
                                tracing::warn!(ip = %remote_ip_str,
                                    "SAACPQuicDaemon: timeout waiting for first QUIC stream");
                                drop((permit, ip_guard));
                                return;
                            }
                        };

                        // ── Wrap QUIC streams into a single duplex AsyncRead+AsyncWrite ──
                        // quinn::RecvStream implements AsyncRead; quinn::SendStream implements
                        // AsyncWrite. tokio::io::join combines them into one object that
                        // implements both — exactly what handle_client expects. No adapter
                        // struct needed (unlike WsByteStream for WebSocket).
                        let stream = tokio::io::join(recv_stream, send_stream);

                        // ── Dispatch to the shared handle_client ──────────
                        let _permit = permit;
                        let _ip_guard = ip_guard;
                        // O-4 parity: pair this connection's lifetime with the live
                        // active-connection gauge. QUIC is a TCP-family transport
                        // (one SAACP session per connection), so it reports under
                        // the tcp gauge rather than inflating the ws one.
                        let _conn_count_guard = crate::telemetry::ConnectionCountGuard::tcp();

                        crate::daemon::handle_client(
                            stream,
                            remote_addr,
                            cb_clone,
                            secret_clone,
                            server_ed25519_seed,
                            gateway_clone,
                            epoch_clone,
                            on_delivered_clone,
                            agent_id_clone,
                            // gossip / cluster: QUIC is a point-to-point agent
                            // transport; the mesh engines are wired on the TCP
                            // daemon only (no quorum/lease traffic over QUIC).
                            None,
                            None,
                            // F12: no per-deployment handshake-timeout override here.
                            None,
                            ctx_clone,
                            inflight_clone,
                            pipeline_clone,
                            // M11: session affinity is TCP/TLS-scoped today.
                            None,
                            None,
                            crate::session_affinity::AffinityViolationPolicy::AlertOnly,
                        ).await;
                    });
                }
            }
        }

        Ok(())
    }
}
