//! transport.rs — pluggable network transports for SAACP.
//!
//! The core protocol (framing.rs, measc.rs, handler.rs) is transport-agnostic:
//! `MEASCFrame::build_frame`/`parse_frame` and `SAACPFrame::parse_header` all
//! operate purely on `&[u8]` byte slices. `daemon.rs::handle_client` itself is
//! generic over any `AsyncRead + AsyncWrite` duplex stream, not hardcoded to
//! `TcpStream`.
//!
//! This module hosts additional transport bindings that tunnel the same wire
//! bytes over protocols more likely to survive corporate firewalls, API
//! gateways, and CDNs that drop unrecognized raw-TCP binary traffic —
//! addressing the "ecosystem isolation" gap: every mainstream LLM
//! orchestration framework already speaks HTTP/WebSocket, not raw TCP.
//!
//! Each binding is opt-in via a Cargo feature so a plain TCP-only deployment
//! never pulls in the extra dependencies:
//!   - `transport-ws`   → [`ws`] — WebSocket binary-message tunnel. Natural
//!     fit for SAACP's persistent, ordered stream sessions
//!     (STREAM_START/CONTINUATION/END — see `streaming.rs`).

#[cfg(feature = "transport-ws")]
pub mod ws;
