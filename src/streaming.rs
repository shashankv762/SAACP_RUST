// SAACP Rust Implementation — StreamSession + StreamRegistry
// Translated from SAACP/src/saacp/streaming.py
//!
//! Streaming continuation support for SAACP.
//!
//! A *stream session* tracks an ordered sequence of continuation frames
//! that together represent a single logical payload.  Each frame is
//! validated for:
//!
//! * **Sequence ordering** — monotonically increasing frame numbers.
//! * **Cumulative byte cap** — 5 MB total across all frames.
//! * **Session duration** — 120 seconds from first frame.
//! * **Frame gap** — max 10 seconds between consecutive frames.
//!
//! The [`StreamRegistry`] enforces global and per-agent limits on the
//! number of concurrent stream sessions.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::SystemTime;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ── Constants ──────────────────────────────────────────────────────────────

/// Maximum cumulative payload bytes across all frames in a stream.
pub const STREAM_MAX_TOTAL_BYTES: usize = 5 * 1024 * 1024; // 5 MB
/// Maximum wall-clock duration of a stream session (seconds).
pub const STREAM_MAX_DURATION_SECONDS: f64 = 120.0;
/// Maximum idle gap between consecutive frames (seconds).
pub const STREAM_MAX_FRAME_GAP_SECONDS: f64 = 10.0;
/// Maximum concurrent active stream sessions (global).
pub const MAX_ACTIVE_STREAMS: usize = 1000;
/// Maximum concurrent stream sessions per agent.
pub const MAX_STREAMS_PER_AGENT: usize = 10;

// ── Helpers ────────────────────────────────────────────────────────────────

fn now_epoch_secs() -> f64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ── StreamSession ──────────────────────────────────────────────────────────

/// A single streaming continuation session.
pub struct StreamSession {
    /// Unique stream identifier.
    pub stream_id: String,
    /// Agent that owns this stream.
    pub agent_id: String,
    /// Frame number of the last accepted frame.
    pub last_sequence: u64,
    /// Cumulative byte count across all frames.
    pub total_bytes: usize,
    /// Epoch time when the first frame was received.
    pub started_at: f64,
    /// Epoch time when the most recent frame was received.
    pub last_frame_at: f64,
    /// Whether the stream has been closed gracefully.
    pub closed: bool,
}

impl StreamSession {
    /// Create a new stream session from the first frame.
    pub fn new(stream_id: String, agent_id: String, first_frame_bytes: usize) -> Self {
        let now = now_epoch_secs();
        Self {
            stream_id,
            agent_id,
            last_sequence: 0,
            total_bytes: first_frame_bytes,
            started_at: now,
            last_frame_at: now,
            closed: false,
        }
    }

    /// Validate and accept the next continuation frame.
    ///
    /// Returns `Ok(())` on success or `Err(SAACPHardDrop)` for any
    /// protocol violation (ordering, byte cap, duration, gap).
    pub fn validate_continuation(
        &mut self,
        sequence: u64,
        frame_bytes: usize,
    ) -> Result<(), SAACPHardDrop> {
        if self.closed {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                "Stream session is already closed.",
            ));
        }

        // 1. Sequence ordering
        if sequence <= self.last_sequence {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!(
                    "Frame sequence {} is not strictly greater than last accepted {}.",
                    sequence, self.last_sequence
                ),
            ));
        }

        // 2. Cumulative byte cap
        if self.total_bytes + frame_bytes > STREAM_MAX_TOTAL_BYTES {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!(
                    "Cumulative bytes {} would exceed cap of {}.",
                    self.total_bytes + frame_bytes,
                    STREAM_MAX_TOTAL_BYTES
                ),
            ));
        }

        // 3. Session duration
        let now = now_epoch_secs();
        if now - self.started_at > STREAM_MAX_DURATION_SECONDS {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!(
                    "Stream duration {:.1}s exceeds limit of {}s.",
                    now - self.started_at,
                    STREAM_MAX_DURATION_SECONDS
                ),
            ));
        }

        // 4. Frame gap
        if now - self.last_frame_at > STREAM_MAX_FRAME_GAP_SECONDS {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!(
                    "Frame gap {:.1}s exceeds limit of {}s.",
                    now - self.last_frame_at,
                    STREAM_MAX_FRAME_GAP_SECONDS
                ),
            ));
        }

        // Accept frame
        self.last_sequence = sequence;
        self.total_bytes += frame_bytes;
        self.last_frame_at = now;
        Ok(())
    }

    /// Mark the stream as closed (no more frames expected).
    pub fn close(&mut self) {
        self.closed = true;
    }
}

// ── StreamRegistry ─────────────────────────────────────────────────────────

/// Global registry of active stream sessions.
pub struct StreamRegistry {
    streams: Mutex<HashMap<String, StreamSession>>,
    agent_counts: Mutex<HashMap<String, usize>>,
}

impl StreamRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            agent_counts: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new stream session.
    ///
    /// Enforces `MAX_ACTIVE_STREAMS` and `MAX_STREAMS_PER_AGENT`.
    /// If the global cap is reached the oldest session is evicted.
    pub fn register(&self, session: StreamSession) -> Result<(), SAACPHardDrop> {
        let mut streams = self.streams.lock().unwrap();
        let mut agent_counts = self.agent_counts.lock().unwrap();

        // Per-agent limit
        let agent_count = agent_counts.get(&session.agent_id).copied().unwrap_or(0);
        if agent_count >= MAX_STREAMS_PER_AGENT {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!(
                    "Agent '{}' already has {} active streams (max {}).",
                    session.agent_id, agent_count, MAX_STREAMS_PER_AGENT
                ),
            ));
        }

        // Global cap — evict oldest if needed
        if streams.len() >= MAX_ACTIVE_STREAMS {
            let oldest_id = streams
                .iter()
                .min_by(|a, b| a.1.started_at.partial_cmp(&b.1.started_at).unwrap())
                .map(|(k, _)| k.clone());
            if let Some(id) = oldest_id {
                if let Some(evicted) = streams.remove(&id) {
                    let cnt = agent_counts.entry(evicted.agent_id.clone()).or_insert(1);
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 {
                        agent_counts.remove(&evicted.agent_id);
                    }
                }
            }
        }

        *agent_counts.entry(session.agent_id.clone()).or_insert(0) += 1;
        streams.insert(session.stream_id.clone(), session);
        Ok(())
    }

    /// Retrieve a mutable reference to a stream session by ID and
    /// validate the next frame.
    pub fn validate_frame(
        &self,
        stream_id: &str,
        sequence: u64,
        frame_bytes: usize,
    ) -> Result<(), SAACPHardDrop> {
        let mut streams = self.streams.lock().unwrap();
        let session = streams.get_mut(stream_id).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!("No active stream with id '{}'.", stream_id),
            )
        })?;
        session.validate_continuation(sequence, frame_bytes)
    }

    /// Close and remove a stream session.
    pub fn close(&self, stream_id: &str) -> Result<(), SAACPHardDrop> {
        let mut streams = self.streams.lock().unwrap();
        let mut agent_counts = self.agent_counts.lock().unwrap();

        if let Some(session) = streams.remove(stream_id) {
            let cnt = agent_counts.entry(session.agent_id.clone()).or_insert(0);
            *cnt = cnt.saturating_sub(1);
            if *cnt == 0 {
                agent_counts.remove(&session.agent_id);
            }
            Ok(())
        } else {
            Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!("No active stream with id '{}'.", stream_id),
            ))
        }
    }

    /// Number of currently active streams.
    pub fn active_count(&self) -> usize {
        self.streams.lock().unwrap().len()
    }

    /// Number of active streams for a given agent.
    pub fn agent_stream_count(&self, agent_id: &str) -> usize {
        self.agent_counts
            .lock()
            .unwrap()
            .get(agent_id)
            .copied()
            .unwrap_or(0)
    }
}

impl Default for StreamRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_session(id: &str, agent: &str) -> StreamSession {
        StreamSession::new(id.into(), agent.into(), 100)
    }

    #[test]
    fn test_stream_session_new() {
        let s = make_session("s1", "agent-a");
        assert_eq!(s.last_sequence, 0);
        assert_eq!(s.total_bytes, 100);
        assert!(!s.closed);
    }

    #[test]
    fn test_validate_continuation_ok() {
        let mut s = make_session("s1", "agent-a");
        assert!(s.validate_continuation(1, 200).is_ok());
        assert_eq!(s.last_sequence, 1);
        assert_eq!(s.total_bytes, 300);
    }

    #[test]
    fn test_validate_continuation_bad_sequence() {
        let mut s = make_session("s1", "agent-a");
        assert!(s.validate_continuation(1, 200).is_ok());
        // Same sequence → error
        assert!(s.validate_continuation(1, 200).is_err());
        // Lower sequence → error
        assert!(s.validate_continuation(0, 200).is_err());
    }

    #[test]
    fn test_validate_continuation_byte_cap() {
        let mut s = make_session("s1", "agent-a");
        // Request more than 5 MB remaining
        let result = s.validate_continuation(1, STREAM_MAX_TOTAL_BYTES);
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_continuation_closed() {
        let mut s = make_session("s1", "agent-a");
        s.close();
        assert!(s.validate_continuation(1, 100).is_err());
    }

    #[test]
    fn test_registry_register_and_count() {
        let reg = StreamRegistry::new();
        let s1 = make_session("s1", "agent-a");
        let s2 = make_session("s2", "agent-a");
        let s3 = make_session("s3", "agent-b");
        assert!(reg.register(s1).is_ok());
        assert!(reg.register(s2).is_ok());
        assert!(reg.register(s3).is_ok());
        assert_eq!(reg.active_count(), 3);
        assert_eq!(reg.agent_stream_count("agent-a"), 2);
        assert_eq!(reg.agent_stream_count("agent-b"), 1);
    }

    #[test]
    fn test_registry_per_agent_limit() {
        let reg = StreamRegistry::new();
        for i in 0..MAX_STREAMS_PER_AGENT {
            let s = make_session(&format!("s{}", i), "agent-a");
            assert!(reg.register(s).is_ok());
        }
        // Next one should fail
        let s = make_session("overflow", "agent-a");
        assert!(reg.register(s).is_err());
    }

    #[test]
    fn test_registry_close() {
        let reg = StreamRegistry::new();
        let s = make_session("s1", "agent-a");
        reg.register(s).unwrap();
        assert_eq!(reg.active_count(), 1);
        assert!(reg.close("s1").is_ok());
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.agent_stream_count("agent-a"), 0);
    }

    #[test]
    fn test_registry_close_nonexistent() {
        let reg = StreamRegistry::new();
        assert!(reg.close("no-such-stream").is_err());
    }

    #[test]
    fn test_registry_validate_frame() {
        let reg = StreamRegistry::new();
        let s = make_session("s1", "agent-a");
        reg.register(s).unwrap();
        assert!(reg.validate_frame("s1", 1, 200).is_ok());
        assert!(reg.validate_frame("s1", 2, 100).is_ok());
        assert!(reg.validate_frame("s1", 1, 100).is_err()); // bad seq
    }

    #[test]
    fn test_registry_global_cap_eviction() {
        let reg = StreamRegistry::new();
        for i in 0..MAX_ACTIVE_STREAMS {
            let mut s = make_session(&format!("s{}", i), &format!("agent-{}", i));
            // Stagger timestamps slightly so ordering is deterministic
            s.started_at = now_epoch_secs() + i as f64;
            reg.register(s).unwrap();
        }
        assert_eq!(reg.active_count(), MAX_ACTIVE_STREAMS);

        // Adding one more should evict the oldest and succeed
        let mut s = make_session("overflow", "agent-overflow");
        s.started_at = now_epoch_secs() + MAX_ACTIVE_STREAMS as f64 + 1.0;
        assert!(reg.register(s).is_ok());
        assert_eq!(reg.active_count(), MAX_ACTIVE_STREAMS);
    }
}
