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
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::BytesMut;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::WebSocketStream;

use crate::daemon::CircuitBreakerEntry;

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
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>,
    server_ed25519_seed: Option<[u8; 32]>,
}

impl SAACPWebSocketDaemon {
    pub fn new(host: &str, port: u16, token_issuer_secret: Option<Vec<u8>>) -> Self {
        Self {
            host: host.to_string(),
            port,
            token_issuer_secret,
            circuit_breakers: Arc::new(Mutex::new(HashMap::new())),
            server_ed25519_seed: None,
        }
    }

    /// Enable server-side Ed25519 authentication for the ECDH handshake that
    /// runs once the WebSocket upgrade completes. See
    /// `SAACPNetworkDaemon::with_server_auth` — identical semantics.
    pub fn with_server_auth(mut self, seed: [u8; 32]) -> Self {
        self.server_ed25519_seed = Some(seed);
        self
    }

    /// Start listening for WebSocket connections. Runs forever.
    pub async fn start(&self) {
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await
            .unwrap_or_else(|e| panic!("SAACPWebSocketDaemon: bind {} failed: {}", addr, e));

        let auth_mode = if self.server_ed25519_seed.is_some() { "authenticated" } else { "unauthenticated" };
        eprintln!("[SAACP Daemon/WS] Listening on {} ({} handshake)", addr, auth_mode);

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    let cbs    = Arc::clone(&self.circuit_breakers);
                    let secret = self.token_issuer_secret.clone();
                    let seed   = self.server_ed25519_seed;
                    tokio::spawn(async move {
                        serve_ws_connection(stream, peer_addr, cbs, secret, seed).await;
                    });
                }
                Err(e) => {
                    eprintln!("[SAACP Daemon/WS] Accept error: {}", e);
                }
            }
        }
    }
}

/// Accept one already-connected TCP socket, perform the WebSocket upgrade
/// handshake, and hand the resulting byte stream to the unmodified
/// `daemon::handle_client` pipeline. Every MEASC frame is tunneled inside
/// WebSocket binary messages — the ECDH handshake, AES-256-GCM crypto, replay
/// window, and full 12-gate pipeline are byte-identical to the raw-TCP path.
async fn serve_ws_connection(
    raw: tokio::net::TcpStream,
    peer_addr: SocketAddr,
    circuit_breakers: Arc<Mutex<HashMap<String, CircuitBreakerEntry>>>,
    token_issuer_secret: Option<Vec<u8>>,
    server_ed25519_seed: Option<[u8; 32]>,
) {
    let ws_stream = match tokio_tungstenite::accept_async(raw).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[SAACP Daemon/WS] Upgrade handshake failed from {}: {}", peer_addr, e);
            return;
        }
    };
    let adapted = WsByteStream::new(ws_stream);
    crate::daemon::handle_client(
        adapted,
        peer_addr,
        circuit_breakers,
        token_issuer_secret,
        server_ed25519_seed,
    )
    .await;
}
