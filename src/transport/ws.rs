//! ws.rs — WebSocket tunnel for SAACP binary frames.
//!
//! Wraps a `tokio_tungstenite::WebSocketStream<S>` (a message-framed duplex)
//! behind `AsyncRead + AsyncWrite` (a byte-framed duplex) so the existing,
//! untouched `daemon::handle_client<S: AsyncRead + AsyncWrite>` runs over it
//! with zero changes to the ECDH handshake, MEASC header parsing, MTU
//! assembly, or gate-pipeline dispatch — all of that already operates on
//! plain bytes, never on `TcpStream` directly.
//!
//! Framing strategy: every WebSocket **binary** message carries an arbitrary
//! chunk of the underlying SAACP byte stream (not necessarily one MEASC frame
//! per message — `handle_client` already reassembles the byte stream into
//! frames via its own 128-byte-header + payload_length logic, exactly as it
//! does over TCP, so message boundaries here are irrelevant to correctness).
//! Text/Ping/Pong frames are skipped transparently (tungstenite answers Ping
//! with Pong automatically); Close ends the byte stream (EOF).
//!
//! [`SAACPWebSocketDaemon`] mirrors `daemon::SAACPNetworkDaemon`'s shape
//! (same constructor/builder pattern, same per-IP circuit breaker) but speaks
//! the WebSocket upgrade handshake instead of raw TCP — this is what lets a
//! SAACP agent connect through an HTTP-only corporate proxy, AWS API Gateway,
//! or Cloudflare tunnel that would otherwise drop unrecognized raw-TCP binary
//! traffic (the "ecosystem isolation" gap: every mainstream LLM framework
//! already speaks HTTP/WebSocket, not a bespoke binary protocol).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::BytesMut;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::daemon::{
    PerIpConnectionGuard, SharedCircuitBreakers, MAX_CONNECTIONS,
    MAX_CONNECTIONS_PER_IP, MAX_PAYLOAD_SIZE, SHUTDOWN_DRAIN_TIMEOUT_SECS,
};
use crate::handler::ParsedPacket;
use crate::measc::SessionEpochManager;

/// H-18 fix: maximum seconds to complete the WebSocket HTTP-Upgrade handshake before the
/// connection is dropped. Without a deadline here, a peer that opens the TCP socket and
/// then never completes (or trickles one byte at a time) the Upgrade request ties up a
/// spawned task, a `connection_semaphore` permit, and a per-IP connection slot
/// indefinitely — a slow-loris DoS that, unlike a stalled MEASC handshake on the raw-TCP
/// path (bounded by `daemon::HANDSHAKE_TIMEOUT_SECS`), previously had no bound at all.
const WS_UPGRADE_TIMEOUT_SECS: u64 = 5;

// ─── WsByteStream ────────────────────────────────────────────────────────────

/// Adapts a WebSocket binary-message stream into a plain byte stream.
///
/// Generic over the underlying transport `S` (typically `TcpStream`, but any
/// `AsyncRead + AsyncWrite + Unpin` works — e.g. a TLS-wrapped stream, for a
/// future `wss://` binding).
pub struct WsByteStream<S> {
    inner: WebSocketStream<S>,
    /// Bytes from a previously-received binary message not yet consumed by
    /// the caller's `poll_read`.
    read_buf: BytesMut,
    /// Set once the peer sends Close or the stream ends — further reads
    /// return EOF (zero bytes) rather than re-polling a closed stream.
    read_closed: bool,
    /// Byte count of a write already handed to the Sink via `start_send` but
    /// not yet confirmed flushed to the peer. `WebSocketStream`'s `Sink`
    /// buffers `start_send`'d messages internally and only pushes them onto
    /// the socket on `poll_flush` — unlike `TcpStream::poll_write`, which
    /// hands bytes straight to the OS send buffer. `daemon.rs`'s call sites
    /// use `AsyncWriteExt::write_all`, which never calls `.flush()`, so
    /// `poll_write` here drives the flush itself (see its doc comment)
    /// rather than requiring changes to already-tested TCP-path code.
    pending_write_len: Option<usize>,
}

impl<S> WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(inner: WebSocketStream<S>) -> Self {
        Self { inner, read_buf: BytesMut::new(), read_closed: false, pending_write_len: None }
    }
}

impl<S> AsyncRead for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.read_buf.is_empty() {
                let take = this.read_buf.len().min(buf.remaining());
                let chunk = this.read_buf.split_to(take);
                buf.put_slice(&chunk);
                return Poll::Ready(Ok(()));
            }
            if this.read_closed {
                return Poll::Ready(Ok(())); // EOF
            }
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(Message::Binary(data)))) => {
                    this.read_buf = BytesMut::from(&data[..]);
                    // Loop back around to copy the freshly-filled buffer.
                }
                Poll::Ready(Some(Ok(Message::Close(_)))) | Poll::Ready(None) => {
                    this.read_closed = true;
                    return Poll::Ready(Ok(())); // EOF
                }
                Poll::Ready(Some(Ok(_other))) => {
                    // Text/Ping/Pong/raw Frame — not part of the SAACP byte
                    // stream. Skip and poll again.
                }
                Poll::Ready(Some(Err(e))) => {
                    this.read_closed = true;
                    return Poll::Ready(Err(ws_err(e)));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S> AsyncWrite for WsByteStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Sends `buf` as one WebSocket binary message, then drives the flush to
    /// completion before reporting success — see `pending_write_len`'s doc
    /// comment on the struct for why this doesn't just `start_send` and
    /// return. Safe to poll again after `Pending`: a write already handed to
    /// the Sink is tracked in `pending_write_len` and is never re-sent, only
    /// the flush is retried.
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write_len.is_none() {
            match Pin::new(&mut this.inner).poll_ready(cx) {
                Poll::Ready(Ok(())) => {}
                Poll::Ready(Err(e)) => return Poll::Ready(Err(ws_err(e))),
                Poll::Pending => return Poll::Pending,
            }
            let msg = Message::Binary(buf.to_vec());
            match Pin::new(&mut this.inner).start_send(msg) {
                Ok(()) => this.pending_write_len = Some(buf.len()),
                Err(e) => return Poll::Ready(Err(ws_err(e))),
            }
        }
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(this.pending_write_len.take().unwrap())),
            Poll::Ready(Err(e)) => {
                this.pending_write_len = None;
                Poll::Ready(Err(ws_err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_flush(cx).map_err(ws_err)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner).poll_close(cx).map_err(ws_err)
    }
}

fn ws_err(e: tokio_tungstenite::tungstenite::Error) -> std::io::Error {
    std::io::Error::other(e.to_string())
}

// ─── SAACPWebSocketDaemon ────────────────────────────────────────────────────

/// WebSocket-tunneled sibling of `daemon::SAACPNetworkDaemon`.
///
/// Same constructor/builder shape and the same per-IP circuit breaker
/// semantics as the raw-TCP daemon; only the accept loop differs (performs an
/// HTTP Upgrade → WebSocket handshake before handing the connection to the
/// shared `handle_client` pipeline via [`WsByteStream`]).
///
/// Run this alongside (or instead of) `SAACPNetworkDaemon` to expose the same
/// agent on a port that survives HTTP-only proxies/gateways. The two daemons
/// currently keep independent circuit-breaker state; unifying per-IP
/// lockout state across listeners (or across a horizontally-scaled cluster)
/// is exactly the kind of cross-node state `state_backend.rs` targets.
pub struct SAACPWebSocketDaemon {
    host: String,
    port: u16,
    token_issuer_secret: Option<Vec<u8>>,
    circuit_breakers: SharedCircuitBreakers,
    server_ed25519_seed: Option<[u8; 32]>,
    /// CRIT-9 fix: caps total concurrent connections at `MAX_CONNECTIONS`.
    connection_semaphore: Arc<Semaphore>,
    /// CRIT-9 fix: caps concurrent connections per source IP at `MAX_CONNECTIONS_PER_IP`.
    per_ip_connections: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// H-20 fix: opt-in real Gate 1.0 capability-token signature verification. See
    /// `SAACPNetworkDaemon`'s field of the same name — identical semantics; `None`
    /// preserves the structural-only default.
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    /// H-20 fix: opt-in real AES-256-GCM decryption + replay-window enforcement. See
    /// `SAACPNetworkDaemon`'s field of the same name — identical semantics; `None`
    /// preserves the structural-only default.
    epoch_manager: Option<Arc<SessionEpochManager>>,
    /// H-20 fix: opt-in observer invoked with every successfully-verified `ParsedPacket`.
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
    /// H-20 fix: opt-in C-3 identity binding. See `SAACPNetworkDaemon`'s field of the
    /// same name — identical semantics; `None` preserves today's handshake wire format.
    server_agent_id: Option<String>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    gossip: Option<Arc<crate::gossip::GossipEngine>>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    cluster: Option<Arc<crate::cluster::ClusterEngine>>,
}

impl SAACPWebSocketDaemon {
    pub fn new(host: &str, port: u16, token_issuer_secret: Option<Vec<u8>>) -> Self {
        Self {
            host: host.to_string(),
            port,
            token_issuer_secret,
            // L-18 fix: `SharedCircuitBreakers` now wraps `parking_lot::Mutex`, not
            // `std::sync::Mutex` — use the constructor so this stays in sync with
            // `daemon.rs`'s own default instead of hand-rolling a mismatched type here.
            circuit_breakers: crate::daemon::new_shared_circuit_breakers(),
            server_ed25519_seed: None,
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            per_ip_connections: Arc::new(Mutex::new(HashMap::new())),
            gateway: None,
            epoch_manager: None,
            on_delivered: None,
            server_agent_id: None,
            gossip: None,
            cluster: None,
        }
    }

    /// Enable server-side Ed25519 authentication for the ECDH handshake that
    /// runs once the WebSocket upgrade completes. See
    /// `SAACPNetworkDaemon::with_server_auth` — identical semantics.
    pub fn with_server_auth(mut self, seed: [u8; 32]) -> Self {
        self.server_ed25519_seed = Some(seed);
        self
    }

    /// H-20 fix: opt in to real Gate 1.0 capability-token signature verification instead
    /// of the structural-only presence check every connection gets by default. See
    /// `SAACPNetworkDaemon::with_gateway` — identical semantics.
    pub fn with_gateway(mut self, gateway: Arc<crate::gateway::ZeroTrustGateway>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// H-20 fix: opt in to real AES-256-GCM decryption + replay-window enforcement of
    /// incoming packets instead of the structural-only Gate 0. See
    /// `SAACPNetworkDaemon::with_encrypted_transport` — identical semantics.
    pub fn with_encrypted_transport(mut self, epoch_manager: Arc<SessionEpochManager>) -> Self {
        self.epoch_manager = Some(epoch_manager);
        self
    }

    /// H-20 fix: observe every successfully-verified `ParsedPacket`. See
    /// `SAACPNetworkDaemon::with_on_delivered` — identical semantics.
    pub fn with_on_delivered(
        mut self,
        callback: Arc<dyn Fn(ParsedPacket) + Send + Sync>,
    ) -> Self {
        self.on_delivered = Some(callback);
        self
    }

    /// R-5 / L-12 fix: opt in to a circuit-breaker map shared with other transport
    /// daemons (e.g. `SAACPNetworkDaemon`, `SAACPTlsDaemon`) so an IP locked out on one
    /// transport can't bypass the lockout by reconnecting on another. See
    /// `daemon::SharedCircuitBreakers`. Not calling this preserves today's exact
    /// behavior: this daemon tracks per-IP lockouts independently of any other daemon.
    pub fn with_circuit_breakers(mut self, shared: SharedCircuitBreakers) -> Self {
        self.circuit_breakers = shared;
        self
    }

    /// Opt in to the revocation gossip mesh. See
    /// `SAACPNetworkDaemon::with_gossip_engine` — identical semantics.
    pub fn with_gossip_engine(mut self, engine: Arc<crate::gossip::GossipEngine>) -> Self {
        self.gossip = Some(engine);
        self
    }

    /// Opt in to the Active-Active cluster membership mesh. See
    /// `SAACPNetworkDaemon::with_cluster_engine` — identical semantics.
    pub fn with_cluster_engine(mut self, engine: Arc<crate::cluster::ClusterEngine>) -> Self {
        self.cluster = Some(engine);
        self
    }

    /// H-20 fix: opt in to C-3 identity binding — every connecting client must present an
    /// `AgentIdentityCertificate` signed by one of `ca_keys` and prove possession of the
    /// certified private key during the ECDH handshake, before any packet is processed.
    /// Implies `with_server_auth(seed)`, exactly like the TCP daemon. See
    /// `SAACPNetworkDaemon::with_identity_binding` — identical semantics.
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

    /// Start listening for WebSocket connections. Runs forever (until the process is
    /// killed) — equivalent to `start_with_shutdown` with a token that's never
    /// cancelled. M-37 fix: returns `Result` (propagates a bind failure) instead of
    /// panicking.
    pub async fn start(&self) -> std::io::Result<()> {
        self.start_with_shutdown(tokio_util::sync::CancellationToken::new()).await
    }

    /// M-15/R-2 fix: same as `start`, but stops accepting new connections as soon as
    /// `shutdown` is cancelled, then drains in-flight connections (bounded by
    /// `daemon::SHUTDOWN_DRAIN_TIMEOUT_SECS`) before flushing the audit-log WAL
    /// (L-10) and returning. See `daemon::SAACPNetworkDaemon::start_with_shutdown` —
    /// identical shape.
    pub async fn start_with_shutdown(&self, shutdown: tokio_util::sync::CancellationToken) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;

        let auth_mode = if self.server_ed25519_seed.is_some() { "authenticated" } else { "unauthenticated" };
        eprintln!("[SAACP Daemon/WS] Listening on {} ({} handshake)", addr, auth_mode);

        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    eprintln!("[SAACP Daemon/WS] Shutdown signal received — no longer accepting new connections");
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            // CRIT-9 fix: same total + per-IP concurrency bound as the raw-TCP
                            // daemon — see `daemon::SAACPNetworkDaemon::start`'s doc comment.
                            let permit = match Arc::clone(&self.connection_semaphore).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    eprintln!(
                                        "[SAACP Daemon/WS] Connection limit ({}) reached — rejecting {}",
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
                                        "[SAACP Daemon/WS] Per-IP connection limit ({}) reached for {} — rejecting",
                                        MAX_CONNECTIONS_PER_IP, peer_addr.ip(),
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            let cbs    = Arc::clone(&self.circuit_breakers);
                            let secret = self.token_issuer_secret.clone();
                            let seed   = self.server_ed25519_seed;
                            let gateway         = self.gateway.clone();
                            let epoch_manager   = self.epoch_manager.clone();
                            let on_delivered    = self.on_delivered.clone();
                            let server_agent_id = self.server_agent_id.clone();
                            let gossip          = self.gossip.clone();
                            let cluster         = self.cluster.clone();
                            tasks.spawn(async move {
                                let _permit = permit; // released on drop when this task ends
                                let _per_ip_guard = per_ip_guard;
                                // O-4 fix: pair this connection's lifetime with the live
                                // `saacp_active_connections{transport="ws"}` gauge — see
                                // `daemon::SAACPNetworkDaemon::start_with_shutdown`'s identical
                                // fix for the TCP transport.
                                let _conn_count_guard = crate::telemetry::ConnectionCountGuard::ws();
                                serve_ws_connection(
                                    stream, peer_addr, cbs, secret, seed,
                                    gateway, epoch_manager, on_delivered, server_agent_id, gossip, cluster,
                                ).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("[SAACP Daemon/WS] Accept error: {}", e);
                        }
                    }
                }
            }
        }

        // Drain: let in-flight connections finish naturally, bounded by
        // SHUTDOWN_DRAIN_TIMEOUT_SECS, then hard-abort whatever's left.
        let drained = tokio::time::timeout(
            Duration::from_secs(SHUTDOWN_DRAIN_TIMEOUT_SECS),
            async { while tasks.join_next().await.is_some() {} },
        ).await;
        if drained.is_err() {
            eprintln!(
                "[SAACP Daemon/WS] Drain timeout ({}s) exceeded — aborting {} in-flight connection(s)",
                SHUTDOWN_DRAIN_TIMEOUT_SECS, tasks.len(),
            );
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }

        // Terminal step (R-2's stated sequence: "stop accepting → drain → flush WAL → exit").
        let flushed = tokio::task::spawn_blocking(|| {
            crate::security::ImmutableAuditLog::global()
                .flush(Duration::from_secs(crate::security::AUDIT_FLUSH_ON_SHUTDOWN_TIMEOUT_SECS))
        }).await.unwrap_or(false);
        if !flushed {
            eprintln!("[SAACP Daemon/WS] WAL flush on shutdown did not confirm in time");
        }

        Ok(())
    }
}

/// Accept one already-connected TCP socket, perform the WebSocket upgrade
/// handshake, and hand the resulting byte stream to the unmodified
/// `daemon::handle_client` pipeline. Every MEASC frame is tunneled inside
/// WebSocket binary messages — the ECDH handshake, AES-256-GCM crypto, replay
/// window, and full 12-gate pipeline are byte-identical to the raw-TCP path.
#[allow(clippy::too_many_arguments)]
async fn serve_ws_connection(
    raw: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    circuit_breakers: SharedCircuitBreakers,
    token_issuer_secret: Option<Vec<u8>>,
    server_ed25519_seed: Option<[u8; 32]>,
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    epoch_manager: Option<Arc<SessionEpochManager>>,
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
    server_agent_id: Option<String>,
    gossip: Option<Arc<crate::gossip::GossipEngine>>,
    cluster: Option<Arc<crate::cluster::ClusterEngine>>,
) {
    // H-19 fix: cap the incoming WebSocket message/frame size at the same
    // `MAX_PAYLOAD_SIZE` the raw-TCP path already enforces for MEASC payloads (+1024
    // bytes slack for the 128-byte MEASC header and framing overhead), instead of
    // trusting tokio-tungstenite's generic 64 MiB / 16 MiB defaults — a malicious peer
    // could otherwise force each WS connection to buffer up to 64 MiB before the byte
    // stream ever reaches `handle_client`'s own payload-length check.
    let ws_config = WebSocketConfig {
        max_message_size: Some(MAX_PAYLOAD_SIZE + 1024),
        max_frame_size: Some(MAX_PAYLOAD_SIZE + 1024),
        ..Default::default()
    };

    // H-18 fix: bound the HTTP-Upgrade handshake itself, so a peer that opens the TCP
    // socket and then never completes (or trickles) the Upgrade request cannot hold a
    // spawned task / connection-semaphore permit / per-IP slot forever (slow-loris DoS).
    let upgrade = tokio_tungstenite::accept_async_with_config(raw, Some(ws_config));
    let ws_stream = match tokio::time::timeout(Duration::from_secs(WS_UPGRADE_TIMEOUT_SECS), upgrade).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("[SAACP Daemon/WS] Upgrade handshake failed from {}: {}", peer_addr, e);
            return;
        }
        Err(_) => {
            eprintln!(
                "[SAACP Daemon/WS] Upgrade handshake from {} exceeded {}s — dropping",
                peer_addr, WS_UPGRADE_TIMEOUT_SECS,
            );
            return;
        }
    };
    let adapted = WsByteStream::new(ws_stream);
    // H-20 fix: forward the daemon's configured security opt-ins through to the shared
    // pipeline instead of hardcoding `None` — gives the WS transport full feature parity
    // with `SAACPNetworkDaemon`'s raw-TCP path (real Gate 1.0 verification, real AEAD
    // decryption, C-3 identity binding, delivered-packet observability).
    crate::daemon::handle_client(
        adapted,
        peer_addr,
        circuit_breakers,
        token_issuer_secret,
        server_ed25519_seed,
        gateway,
        epoch_manager,
        on_delivered,
        server_agent_id,
        gossip,
        cluster,
    )
    .await;
}
