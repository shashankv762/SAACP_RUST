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
use crate::handler::SAACPProtocolHandler;
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
}

impl SAACPNetworkDaemon {
    pub fn new(host: &str, port: u16, token_issuer_secret: Option<Vec<u8>>) -> Self {
        Self {
            host: host.to_string(),
            port,
            token_issuer_secret,
            circuit_breakers: Arc::new(Mutex::new(HashMap::new())),
            server_ed25519_seed: None,
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
                    tokio::spawn(async move {
                        handle_client(stream, peer_addr, cbs, secret, seed).await;
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
pub(crate) async fn handle_client<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>,
    _token_issuer_secret: Option<Vec<u8>>,
    server_ed25519_seed: Option<[u8; 32]>,
)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let ip_key = peer_addr.ip().to_string();

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
    
    // ── C-3 Identity Gate: Connection Init ────────────────────────────────────
    let connection_sid = uuid::Uuid::new_v4().to_string();
    let _ = crate::identity_binding::GLOBAL_IDENTITY_GATE.advance("unknown", &connection_sid, "connection_init");

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
        let intercept_result = tokio::task::spawn_blocking(move || {
            SAACPProtocolHandler::intercept_packet(
                &full_packet,
                &session_key,
                &agent_name,
                is_pinned,
            )
        }).await;
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
                // Update pinning state
                if pinned_agent.is_none() && !parsed.source_agent.is_empty() {
                    pinned_agent    = Some(parsed.source_agent.clone());
                    last_validated_at = Some(Instant::now());
                    // Snapshot the current revocation epoch so future revocations
                    // trigger disconnect (C1 fix).
                    pinned_revocation_epoch =
                        crate::gateway::ZeroTrustGateway::global().get_revocation_epoch();
                    let _ = crate::identity_binding::GLOBAL_IDENTITY_GATE.advance(&parsed.source_agent, &parsed.session_uuid, "authenticated");
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

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
