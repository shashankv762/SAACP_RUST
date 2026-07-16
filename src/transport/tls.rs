//! tls.rs — TLS-terminated raw-TCP transport for SAACP.
//!
//! Deliberately raw TCP wrapped in TLS, **not** WebSocket-over-TLS (`wss://`) — see
//! `transport.rs`'s module doc. A `tokio_rustls::server::TlsStream<TcpStream>` already
//! implements `AsyncRead + AsyncWrite + Unpin + Send`, so unlike [`super::ws::WsByteStream`]
//! (which has to adapt a message-framed WebSocket stream into a byte-framed one), the
//! TLS-terminated stream is handed straight to the existing, untouched
//! `daemon::handle_client<S: AsyncRead + AsyncWrite>` — no adapter needed. The ECDH
//! handshake, MEASC header parsing, MTU assembly, and gate-pipeline dispatch are all
//! byte-identical to the raw-TCP path; TLS here only protects the bytes in transit
//! (defense-in-depth alongside, not instead of, the protocol's own AES-256-GCM Gate 0).
//!
//! [`SAACPTlsDaemon`] mirrors `daemon::SAACPNetworkDaemon`/`transport::ws::SAACPWebSocketDaemon`'s
//! shape (same constructor/builder pattern, same per-IP circuit breaker, same
//! CRIT-9 connection limits, same M-15/R-2 graceful shutdown) — only the accept loop
//! differs (TLS-terminates the socket before handing it to `handle_client`).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio_rustls::rustls;
use tokio_rustls::TlsAcceptor;

use crate::daemon::{
    PerIpConnectionGuard, SharedCircuitBreakers, MAX_CONNECTIONS,
    MAX_CONNECTIONS_PER_IP, SHUTDOWN_DRAIN_TIMEOUT_SECS,
};
use crate::handler::ParsedPacket;
use crate::measc::SessionEpochManager;

/// H-18-equivalent fix: maximum seconds to complete the TLS server handshake
/// (ClientHello → Finished) before the connection is dropped. Without a deadline here, a
/// peer that opens the TCP socket and never completes (or trickles) the TLS handshake ties
/// up a spawned task, a `connection_semaphore` permit, and a per-IP connection slot
/// indefinitely — the same slow-loris shape `transport/ws.rs::WS_UPGRADE_TIMEOUT_SECS`
/// guards against for the WebSocket upgrade.
const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 5;

/// Build a `rustls::ServerConfig` from a PEM certificate chain file and a PEM private-key
/// file (PKCS#8, SEC1, or PKCS#1 — whatever `rustls_pemfile::private_key` auto-detects).
///
/// Uses `ServerConfig::builder_with_provider(...)` with an explicit `aws-lc-rs` crypto
/// provider rather than `ServerConfig::builder()` (which relies on a process-wide default
/// provider installed via `CryptoProvider::install_default()`) — this crate is a library,
/// not the owner of the whole process, and another dependency in the same binary (e.g. a
/// caller's own `reqwest`/`rustls` usage) may already have installed a different default
/// provider, or none at all. Building with an explicit provider avoids that global-state
/// footgun entirely, at the cost of needing to name the provider here.
pub fn load_tls_config(
    cert_path: impl AsRef<std::path::Path>,
    key_path: impl AsRef<std::path::Path>,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let cert_file = std::fs::File::open(cert_path)?;
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let certs: Vec<rustls::pki_types::CertificateDer<'static>> =
        rustls_pemfile::certs(&mut cert_reader).collect::<Result<Vec<_>, _>>()?;
    if certs.is_empty() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "no certificates found in cert file",
        ));
    }

    let key_file = std::fs::File::open(key_path)?;
    let mut key_reader = std::io::BufReader::new(key_file);
    let key = rustls_pemfile::private_key(&mut key_reader)?.ok_or_else(|| {
        std::io::Error::new(std::io::ErrorKind::InvalidData, "no private key found in key file")
    })?;

    server_config_from_cert_and_key(certs, key)
}

/// Build a `rustls::ServerConfig` directly from an already-parsed certificate chain and
/// private key — the in-memory counterpart to [`load_tls_config`], useful for callers (and
/// tests) that generate or otherwise obtain certificate material without touching disk.
pub fn server_config_from_cert_and_key(
    certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    key: rustls::pki_types::PrivateKeyDer<'static>,
) -> std::io::Result<Arc<rustls::ServerConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(Arc::new(config))
}

// ─── SAACPTlsDaemon ──────────────────────────────────────────────────────────

/// TLS-terminated-raw-TCP sibling of `daemon::SAACPNetworkDaemon`.
///
/// Same constructor/builder shape and the same per-IP circuit breaker semantics as the
/// plain-TCP daemon; only the accept loop differs (performs a TLS server handshake before
/// handing the connection to the shared `handle_client` pipeline).
///
/// Run this alongside (or instead of) `SAACPNetworkDaemon`/`SAACPWebSocketDaemon` to expose
/// the same agent on a port that TLS-protects the wire in transit — e.g. for deployments
/// crossing an untrusted network segment where a reverse-proxy TLS terminator isn't already
/// in front of the raw MEASC listener.
pub struct SAACPTlsDaemon {
    host: String,
    port: u16,
    token_issuer_secret: Option<Vec<u8>>,
    tls_config: Arc<rustls::ServerConfig>,
    circuit_breakers: SharedCircuitBreakers,
    server_ed25519_seed: Option<[u8; 32]>,
    /// CRIT-9 fix: caps total concurrent connections at `MAX_CONNECTIONS`.
    connection_semaphore: Arc<Semaphore>,
    /// CRIT-9 fix: caps concurrent connections per source IP at `MAX_CONNECTIONS_PER_IP`.
    per_ip_connections: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    epoch_manager: Option<Arc<SessionEpochManager>>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    server_agent_id: Option<String>,
    /// See `SAACPNetworkDaemon`'s field of the same name — identical semantics.
    gossip: Option<Arc<crate::gossip::GossipEngine>>,
}

impl SAACPTlsDaemon {
    pub fn new(
        host: &str,
        port: u16,
        token_issuer_secret: Option<Vec<u8>>,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Self {
        Self {
            host: host.to_string(),
            port,
            token_issuer_secret,
            tls_config,
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
        }
    }

    /// Enable server-side Ed25519 authentication for the ECDH handshake that runs once the
    /// TLS handshake completes. See `SAACPNetworkDaemon::with_server_auth` — identical
    /// semantics. This is independent of (and layered underneath) TLS: TLS authenticates
    /// the TCP byte stream, this authenticates the SAACP session key exchange carried
    /// inside it.
    pub fn with_server_auth(mut self, seed: [u8; 32]) -> Self {
        self.server_ed25519_seed = Some(seed);
        self
    }

    /// Opt in to real Gate 1.0 capability-token signature verification instead of the
    /// structural-only presence check every connection gets by default. See
    /// `SAACPNetworkDaemon::with_gateway` — identical semantics.
    pub fn with_gateway(mut self, gateway: Arc<crate::gateway::ZeroTrustGateway>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Opt in to real AES-256-GCM decryption + replay-window enforcement of incoming
    /// packets instead of the structural-only Gate 0. See
    /// `SAACPNetworkDaemon::with_encrypted_transport` — identical semantics.
    pub fn with_encrypted_transport(mut self, epoch_manager: Arc<SessionEpochManager>) -> Self {
        self.epoch_manager = Some(epoch_manager);
        self
    }

    /// Observe every successfully-verified `ParsedPacket`. See
    /// `SAACPNetworkDaemon::with_on_delivered` — identical semantics.
    pub fn with_on_delivered(
        mut self,
        callback: Arc<dyn Fn(ParsedPacket) + Send + Sync>,
    ) -> Self {
        self.on_delivered = Some(callback);
        self
    }

    /// R-5 / L-12 fix: opt in to a circuit-breaker map shared with other transport daemons
    /// (e.g. `SAACPNetworkDaemon`, `SAACPWebSocketDaemon`) so an IP locked out on one
    /// transport can't bypass the lockout by reconnecting on another. See
    /// `daemon::SharedCircuitBreakers`. Not calling this preserves today's exact behavior:
    /// this daemon tracks per-IP lockouts independently of any other daemon.
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

    /// Opt in to C-3 identity binding — every connecting client must present an
    /// `AgentIdentityCertificate` signed by one of `ca_keys` and prove possession of the
    /// certified private key during the ECDH handshake, before any packet is processed.
    /// Implies `with_server_auth(seed)`, exactly like the TCP and WebSocket daemons. See
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

    /// Start listening for TLS connections. Runs forever (until the process is killed) —
    /// equivalent to `start_with_shutdown` with a token that's never cancelled. Returns
    /// `Result` (propagates a bind failure) instead of panicking, matching
    /// `SAACPNetworkDaemon::start`/`SAACPWebSocketDaemon::start`.
    pub async fn start(&self) -> std::io::Result<()> {
        self.start_with_shutdown(tokio_util::sync::CancellationToken::new()).await
    }

    /// M-15/R-2 fix: same as `start`, but stops accepting new connections as soon as
    /// `shutdown` is cancelled, then drains in-flight connections (bounded by
    /// `daemon::SHUTDOWN_DRAIN_TIMEOUT_SECS`) before flushing the audit-log WAL (L-10) and
    /// returning. See `daemon::SAACPNetworkDaemon::start_with_shutdown` — identical shape.
    pub async fn start_with_shutdown(&self, shutdown: tokio_util::sync::CancellationToken) -> std::io::Result<()> {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;
        let acceptor = TlsAcceptor::from(Arc::clone(&self.tls_config));

        let auth_mode = if self.server_ed25519_seed.is_some() { "authenticated" } else { "unauthenticated" };
        eprintln!("[SAACP Daemon/TLS] Listening on {} ({} handshake)", addr, auth_mode);

        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    eprintln!("[SAACP Daemon/TLS] Shutdown signal received — no longer accepting new connections");
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            // CRIT-9 fix: same total + per-IP concurrency bound as the raw-TCP
                            // and WebSocket daemons.
                            let permit = match Arc::clone(&self.connection_semaphore).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    eprintln!(
                                        "[SAACP Daemon/TLS] Connection limit ({}) reached — rejecting {}",
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
                                        "[SAACP Daemon/TLS] Per-IP connection limit ({}) reached for {} — rejecting",
                                        MAX_CONNECTIONS_PER_IP, peer_addr.ip(),
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            let tls_acceptor = acceptor.clone();
                            let cbs    = Arc::clone(&self.circuit_breakers);
                            let secret = self.token_issuer_secret.clone();
                            let seed   = self.server_ed25519_seed;
                            let gateway         = self.gateway.clone();
                            let epoch_manager   = self.epoch_manager.clone();
                            let on_delivered    = self.on_delivered.clone();
                            let server_agent_id = self.server_agent_id.clone();
                            let gossip          = self.gossip.clone();
                            tasks.spawn(async move {
                                let _permit = permit; // released on drop when this task ends
                                let _per_ip_guard = per_ip_guard;
                                serve_tls_connection(
                                    stream, peer_addr, tls_acceptor, cbs, secret, seed,
                                    gateway, epoch_manager, on_delivered, server_agent_id, gossip,
                                ).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("[SAACP Daemon/TLS] Accept error: {}", e);
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
                "[SAACP Daemon/TLS] Drain timeout ({}s) exceeded — aborting {} in-flight connection(s)",
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
            eprintln!("[SAACP Daemon/TLS] WAL flush on shutdown did not confirm in time");
        }

        Ok(())
    }
}

/// Accept one already-connected TCP socket, perform the TLS server handshake, and hand the
/// resulting `AsyncRead + AsyncWrite` stream directly to the unmodified
/// `daemon::handle_client` pipeline — no byte-framing adapter needed (see this module's doc
/// comment). The ECDH handshake, AES-256-GCM crypto, replay window, and full 12-gate
/// pipeline are byte-identical to the raw-TCP path; only the outer transport is TLS instead
/// of plaintext TCP.
#[allow(clippy::too_many_arguments)]
async fn serve_tls_connection(
    raw: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
    circuit_breakers: SharedCircuitBreakers,
    token_issuer_secret: Option<Vec<u8>>,
    server_ed25519_seed: Option<[u8; 32]>,
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    epoch_manager: Option<Arc<SessionEpochManager>>,
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
    server_agent_id: Option<String>,
    gossip: Option<Arc<crate::gossip::GossipEngine>>,
) {
    // H-18-equivalent fix: bound the TLS handshake itself, so a peer that opens the TCP
    // socket and then never completes (or trickles) ClientHello cannot hold a spawned task
    // / connection-semaphore permit / per-IP slot forever (slow-loris DoS).
    let handshake = acceptor.accept(raw);
    let tls_stream = match tokio::time::timeout(Duration::from_secs(TLS_HANDSHAKE_TIMEOUT_SECS), handshake).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => {
            eprintln!("[SAACP Daemon/TLS] TLS handshake failed from {}: {}", peer_addr, e);
            return;
        }
        Err(_) => {
            eprintln!(
                "[SAACP Daemon/TLS] TLS handshake from {} exceeded {}s — dropping",
                peer_addr, TLS_HANDSHAKE_TIMEOUT_SECS,
            );
            return;
        }
    };

    crate::daemon::handle_client(
        tls_stream,
        peer_addr,
        circuit_breakers,
        token_issuer_secret,
        server_ed25519_seed,
        gateway,
        epoch_manager,
        on_delivered,
        server_agent_id,
        gossip,
    )
    .await;
}
