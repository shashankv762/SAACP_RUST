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
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, SystemTime};

use serde::{Serialize, Deserialize};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::state_backend::StateBackend;

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
#[derive(Clone, Serialize, Deserialize)]
pub struct StreamSession {
    /// Unique stream identifier.
    pub stream_id: String,
    /// Agent that owns this stream (internal agent_id for registry accounting).
    pub agent_id: String,
    /// Source agent identity from the capability token (for audit).
    pub source_agent: String,
    /// Frame number of the last accepted frame.
    pub last_sequence: u64,
    /// Alias for last_sequence for compatibility with handler.rs gate code.
    pub last_sequence_id: Option<u64>,
    /// Cumulative byte count across all frames.
    pub total_bytes: usize,
    /// Number of frames received.
    pub frame_count: u64,
    /// Epoch time when the first frame was received.
    pub started_at: f64,
    /// Epoch time when the most recent frame was received.
    pub last_frame_at: f64,
    /// Whether the stream has been closed gracefully.
    pub closed: bool,
    /// SHA-256 hash of the originating token signature (Gate 1.0 revocation check).
    pub token_sig_hash: String,
    /// Expiry of the originating token (Gate 1.0 expiry check, 0.0 = no expiry).
    pub token_exp: f64,
    /// Trust-decay-capped `max_action_class` the originating token was validated
    /// against at STREAM_START (Gate 1.0 output — see `run_gates_1_through_12`'s
    /// `max_action_class_from_token`). CRIT-2 fix: enforced via Gate 2.5 (kinetic
    /// firewall) on every CONTINUATION/END frame, not just the first frame of the
    /// stream — closes the privilege-escalation-via-continuation-frame gap.
    /// Defaults to 0 (READ_ONLY) — the same safe default Gate 1.0 uses when no
    /// gateway is injected.
    pub max_action_class: u8,
}

impl StreamSession {
    /// Create a new stream session from the first frame.
    pub fn new(stream_id: String, agent_id: String, first_frame_bytes: usize) -> Self {
        let now = now_epoch_secs();
        Self {
            stream_id,
            agent_id,
            source_agent: String::new(),
            last_sequence: 0,
            last_sequence_id: None,
            total_bytes: first_frame_bytes,
            frame_count: 0,
            started_at: now,
            last_frame_at: now,
            closed: false,
            token_sig_hash: String::new(),
            token_exp: 0.0,
            max_action_class: 0,
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
        self.last_sequence_id = Some(sequence);
        self.total_bytes += frame_bytes;
        self.frame_count += 1;
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
///
/// Backed by a process-local `HashMap` by default. [`StreamRegistry::with_backend`]
/// instead routes session state through a shared [`StateBackend`] (e.g.
/// Redis) so a stream started on one SAACP gateway node can be continued
/// against another — see `state_backend.rs` for the design. Every mutating
/// backend-mode operation reuses `StreamSession::validate_continuation`
/// itself (get → mutate in memory → put) rather than reimplementing its
/// ordering/byte-cap/duration/gap checks a second time.
pub struct StreamRegistry {
    streams: Mutex<HashMap<String, StreamSession>>,
    agent_counts: Mutex<HashMap<String, usize>>,
    backend: Option<Arc<dyn StateBackend>>,
}

/// TTL applied to backend-stored stream sessions: comfortably beyond the
/// max session duration plus max frame gap, as a safety net in case a stream
/// is abandoned without an explicit `close`/`end_stream`/`abort_stream`.
fn stream_backend_ttl() -> Duration {
    Duration::from_secs_f64(STREAM_MAX_DURATION_SECONDS + STREAM_MAX_FRAME_GAP_SECONDS + 30.0)
}

impl StreamRegistry {
    /// Create a new empty registry.
    pub fn new() -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            agent_counts: Mutex::new(HashMap::new()),
            backend: None,
        }
    }

    /// Create a StreamRegistry backed by a shared [`StateBackend`] (e.g.
    /// Redis) instead of a process-local `HashMap`. See `state_backend.rs`.
    pub fn with_backend(backend: Arc<dyn StateBackend>) -> Self {
        Self {
            streams: Mutex::new(HashMap::new()),
            agent_counts: Mutex::new(HashMap::new()),
            backend: Some(backend),
        }
    }

    fn stream_key(stream_id: &str) -> String {
        format!("stream:{stream_id}")
    }

    fn get_session_backend(backend: &Arc<dyn StateBackend>, stream_id: &str) -> Option<StreamSession> {
        let bytes = backend.get(&Self::stream_key(stream_id)).ok().flatten()?;
        serde_json::from_slice(&bytes).ok()
    }

    fn put_session_backend(backend: &Arc<dyn StateBackend>, session: &StreamSession) {
        if let Ok(bytes) = serde_json::to_vec(session) {
            let _ = backend.set(&Self::stream_key(&session.stream_id), &bytes, Some(stream_backend_ttl()));
        }
    }

    fn all_sessions_backend(backend: &Arc<dyn StateBackend>) -> Vec<StreamSession> {
        backend.scan_prefix("stream:").unwrap_or_default().iter()
            .filter_map(|k| backend.get(k).ok().flatten())
            .filter_map(|b| serde_json::from_slice(&b).ok())
            .collect()
    }

    /// Register a new stream session.
    ///
    /// Enforces `MAX_ACTIVE_STREAMS` and `MAX_STREAMS_PER_AGENT`.
    /// If the global cap is reached the oldest session is evicted.
    pub fn register(&self, session: StreamSession) -> Result<(), SAACPHardDrop> {
        match &self.backend {
            Some(backend) => self.register_backend(backend, session),
            None => self.register_local(session),
        }
    }

    fn register_local(&self, session: StreamSession) -> Result<(), SAACPHardDrop> {
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

    fn register_backend(&self, backend: &Arc<dyn StateBackend>, session: StreamSession) -> Result<(), SAACPHardDrop> {
        // O(n) over the active-stream set — registration is a once-per-stream
        // connection-lifecycle event, not a per-frame hot path.
        let mut existing = Self::all_sessions_backend(backend);

        let agent_count = existing.iter().filter(|s| s.agent_id == session.agent_id).count();
        if agent_count >= MAX_STREAMS_PER_AGENT {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::StreamAbort,
                format!(
                    "Agent '{}' already has {} active streams (max {}).",
                    session.agent_id, agent_count, MAX_STREAMS_PER_AGENT
                ),
            ));
        }

        if existing.len() >= MAX_ACTIVE_STREAMS {
            existing.sort_by(|a, b| a.started_at.partial_cmp(&b.started_at).unwrap_or(std::cmp::Ordering::Equal));
            if let Some(oldest) = existing.first() {
                let _ = backend.delete(&Self::stream_key(&oldest.stream_id));
            }
        }

        Self::put_session_backend(backend, &session);
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
        match &self.backend {
            Some(backend) => self.validate_frame_backend(backend, stream_id, sequence, frame_bytes),
            None => {
                let mut streams = self.streams.lock().unwrap();
                let session = streams.get_mut(stream_id).ok_or_else(|| {
                    SAACPHardDrop::new(
                        SAACPBytecodes::StreamAbort,
                        format!("No active stream with id '{}'.", stream_id),
                    )
                })?;
                session.validate_continuation(sequence, frame_bytes)
            }
        }
    }

    /// H-23 fix: backend-mode frame validation used a non-atomic get -> mutate -> put
    /// sequence, which races when two frames for the same `stream_id` are processed
    /// concurrently — e.g. two daemon nodes sharing this backend both handling a frame
    /// for the same stream without session-affinity routing, or two racing in-process
    /// tasks. Both could validate against the same stale snapshot, and whichever `put`
    /// landed last would silently clobber the other's update — bypassing the sequence
    /// ordering, cumulative byte cap, or frame-gap enforcement `validate_continuation`
    /// exists to provide (Architecture Principle 8: "Atomic State Transitions").
    ///
    /// Fixed with a bounded compare-and-swap retry loop: each attempt re-fetches the
    /// current raw bytes, validates a working copy against them, and commits via
    /// [`StateBackend::compare_and_swap`] only if nobody else wrote to this key in the
    /// meantime. A concurrent writer causes a retry against the now-current state —
    /// never a lost update. `validate_continuation` only mutates its receiver on the
    /// `Ok` path (every rejection returns before touching any field — see its doc
    /// comment), so a rejected frame needs no write and never enters the CAS race.
    /// Exhausting the retry budget under sustained same-stream contention fails closed
    /// (`StreamAbort`) rather than silently applying a stale mutation.
    fn validate_frame_backend(
        &self,
        backend: &Arc<dyn StateBackend>,
        stream_id: &str,
        sequence: u64,
        frame_bytes: usize,
    ) -> Result<(), SAACPHardDrop> {
        /// Small fixed bound, matching this codebase's preference for bounded retry
        /// loops over unbounded ones (see `sidecar.rs`'s connect-retry idiom).
        const MAX_CAS_ATTEMPTS: u32 = 5;
        let key = Self::stream_key(stream_id);

        for _ in 0..MAX_CAS_ATTEMPTS {
            let raw = backend.get(&key).ok().flatten().ok_or_else(|| {
                SAACPHardDrop::new(
                    SAACPBytecodes::StreamAbort,
                    format!("No active stream with id '{}'.", stream_id),
                )
            })?;
            let mut session: StreamSession = serde_json::from_slice(&raw).map_err(|_| {
                SAACPHardDrop::new(
                    SAACPBytecodes::StreamAbort,
                    format!("Corrupt stream state for id '{}'.", stream_id),
                )
            })?;

            // `?` propagates a rejection immediately — `validate_continuation` only
            // mutates `session` on its `Ok` path, so a rejected frame has nothing to
            // persist and never enters the CAS race below.
            session.validate_continuation(sequence, frame_bytes)?;

            let new_bytes = serde_json::to_vec(&session).map_err(|_| {
                SAACPHardDrop::new(
                    SAACPBytecodes::StreamAbort,
                    format!("Failed to serialize updated stream state for id '{}'.", stream_id),
                )
            })?;

            match backend.compare_and_swap(&key, Some(&raw), &new_bytes, Some(stream_backend_ttl())) {
                Ok(true) => return Ok(()),
                Ok(false) => continue, // lost the race — retry against the fresh state
                Err(_) => {
                    // Fail closed: don't report acceptance of a frame whose acceptance
                    // was never durably recorded.
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::StreamAbort,
                        format!("Failed to persist stream state for id '{}'.", stream_id),
                    ));
                }
            }
        }

        Err(SAACPHardDrop::new(
            SAACPBytecodes::StreamAbort,
            format!(
                "Stream '{}' has too much concurrent write contention; frame rejected.",
                stream_id
            ),
        ))
    }

    /// Close and remove a stream session.
    pub fn close(&self, stream_id: &str) -> Result<(), SAACPHardDrop> {
        match &self.backend {
            Some(backend) => {
                if backend.delete(&Self::stream_key(stream_id)).unwrap_or(false) {
                    Ok(())
                } else {
                    Err(SAACPHardDrop::new(
                        SAACPBytecodes::StreamAbort,
                        format!("No active stream with id '{}'.", stream_id),
                    ))
                }
            }
            None => {
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
        }
    }

    /// Number of currently active streams.
    ///
    /// In backend mode this is a `scan_prefix` over the `stream:` namespace —
    /// an O(n) diagnostic operation, not a hot-path call.
    pub fn active_count(&self) -> usize {
        match &self.backend {
            Some(backend) => backend.scan_prefix("stream:").map(|k| k.len()).unwrap_or(0),
            None => self.streams.lock().unwrap().len(),
        }
    }

    /// Number of active streams for a given agent.
    pub fn agent_stream_count(&self, agent_id: &str) -> usize {
        match &self.backend {
            Some(backend) => Self::all_sessions_backend(backend).iter()
                .filter(|s| s.agent_id == agent_id).count(),
            None => self.agent_counts.lock().unwrap().get(agent_id).copied().unwrap_or(0),
        }
    }

    // ── Methods required by the stream gate pipeline in handler.rs ─────────

    /// Global process-wide singleton StreamRegistry.
    pub fn global() -> &'static StreamRegistry {
        static GLOBAL: OnceLock<StreamRegistry> = OnceLock::new();
        GLOBAL.get_or_init(StreamRegistry::new)
    }

    /// Register a STREAM_START and return a mutable ref snapshot.
    ///
    /// Called by the daemon after Gate 1.0 validates the capability token.
    /// Sets `token_sig_hash` and `token_exp` for downstream Gate 1.0 checks.
    pub fn start_stream(
        &self,
        stream_id: &str,
        source_agent: &str,
        agent_id: &str,
    ) -> Result<(), SAACPHardDrop> {
        let mut session = StreamSession::new(stream_id.to_string(), agent_id.to_string(), 0);
        session.source_agent = source_agent.to_string();
        self.register(session)
    }

    /// Return a clone of the stream session (for inspection; does not hold lock).
    pub fn get_stream(&self, stream_id: &str) -> Option<StreamSession> {
        match &self.backend {
            Some(backend) => Self::get_session_backend(backend, stream_id),
            None => self.streams.lock().unwrap().get(stream_id).cloned(),
        }
    }

    /// Abort (forcibly remove) a stream session without error.
    pub fn abort_stream(&self, stream_id: &str) {
        match &self.backend {
            Some(backend) => { let _ = backend.delete(&Self::stream_key(stream_id)); }
            None => {
                let mut streams = self.streams.lock().unwrap();
                let mut agent_counts = self.agent_counts.lock().unwrap();
                if let Some(session) = streams.remove(stream_id) {
                    let cnt = agent_counts.entry(session.agent_id).or_insert(0);
                    *cnt = cnt.saturating_sub(1);
                }
            }
        }
    }

    /// Advance a stream session's sequence counter and byte total.
    ///
    /// Returns `Err` if sequence is non-monotonic or byte cap exceeded.
    pub fn continue_stream(
        &self,
        stream_id: &str,
        sequence: u64,
        frame_bytes: usize,
    ) -> Result<(), String> {
        match &self.backend {
            Some(backend) => {
                let mut session = Self::get_session_backend(backend, stream_id)
                    .ok_or_else(|| format!("No active stream '{}'.", stream_id))?;
                let result = session.validate_continuation(sequence, frame_bytes);
                Self::put_session_backend(backend, &session);
                result.map_err(|e| e.message)
            }
            None => {
                let mut streams = self.streams.lock().unwrap();
                let session = streams.get_mut(stream_id).ok_or_else(|| {
                    format!("No active stream '{}'.", stream_id)
                })?;
                session.validate_continuation(sequence, frame_bytes)
                    .map_err(|e| e.message)
            }
        }
    }

    /// Get lightweight stream info without removing the stream.
    ///
    /// Returns `(token_exp, token_sig_hash, last_sequence_id, max_action_class,
    /// source_agent)` for Gate 1.0 / Gate 2.5 / Gate 6.0 checks on continuation
    /// and end frames. New fields are appended after the original three so
    /// existing positional destructuring (`.0`/`.1`/`.2`) keeps working.
    pub fn get_stream_info(&self, stream_id: &str) -> Option<(f64, String, Option<u64>, u8, String)> {
        match &self.backend {
            Some(backend) => Self::get_session_backend(backend, stream_id)
                .map(|s| (s.token_exp, s.token_sig_hash, s.last_sequence_id, s.max_action_class, s.source_agent)),
            None => {
                let streams = self.streams.lock().unwrap();
                streams.get(stream_id).map(|s| {
                    (s.token_exp, s.token_sig_hash.clone(), s.last_sequence_id, s.max_action_class, s.source_agent.clone())
                })
            }
        }
    }

    /// Update token auth info on an existing stream (called after STREAM_START validation).
    ///
    /// `max_action_class` is Gate 1.0's already-validated, trust-decay-capped
    /// ceiling for the originating token (CRIT-2 fix) — stored so Gate 2.5 can
    /// re-enforce it on every subsequent CONTINUATION/END frame.
    #[allow(clippy::too_many_arguments)]
    pub fn set_stream_token_info(
        &self,
        stream_id: &str,
        token_sig_hash: &str,
        token_exp: f64,
        source_agent: &str,
        max_action_class: u8,
    ) {
        match &self.backend {
            Some(backend) => {
                if let Some(mut s) = Self::get_session_backend(backend, stream_id) {
                    s.token_sig_hash = token_sig_hash.to_string();
                    s.token_exp = token_exp;
                    s.source_agent = source_agent.to_string();
                    s.max_action_class = max_action_class;
                    Self::put_session_backend(backend, &s);
                }
            }
            None => {
                let mut streams = self.streams.lock().unwrap();
                if let Some(s) = streams.get_mut(stream_id) {
                    s.token_sig_hash = token_sig_hash.to_string();
                    s.token_exp = token_exp;
                    s.source_agent = source_agent.to_string();
                    s.max_action_class = max_action_class;
                }
            }
        }
    }

    /// End a stream: close it and return the final session snapshot for audit.
    pub fn end_stream(&self, stream_id: &str) -> Option<StreamSession> {
        match &self.backend {
            Some(backend) => {
                let mut session = Self::get_session_backend(backend, stream_id)?;
                session.closed = true;
                let _ = backend.delete(&Self::stream_key(stream_id));
                Some(session)
            }
            None => {
                let mut streams = self.streams.lock().unwrap();
                let mut agent_counts = self.agent_counts.lock().unwrap();
                if let Some(mut session) = streams.remove(stream_id) {
                    session.closed = true;
                    let cnt = agent_counts.entry(session.agent_id.clone()).or_insert(0);
                    *cnt = cnt.saturating_sub(1);
                    if *cnt == 0 {
                        agent_counts.remove(&session.agent_id);
                    }
                    Some(session)
                } else {
                    None
                }
            }
        }
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

    // -- StreamRegistry::with_backend tests (state_backend.rs wiring) --

    fn backend_registry() -> StreamRegistry {
        use crate::state_backend::InMemoryBackend;
        StreamRegistry::with_backend(Arc::new(InMemoryBackend::new()))
    }

    #[test]
    fn test_backend_register_and_count() {
        let reg = backend_registry();
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
    fn test_backend_per_agent_limit() {
        let reg = backend_registry();
        for i in 0..MAX_STREAMS_PER_AGENT {
            let s = make_session(&format!("s{}", i), "agent-a");
            assert!(reg.register(s).is_ok());
        }
        let s = make_session("overflow", "agent-a");
        assert!(reg.register(s).is_err());
    }

    #[test]
    fn test_backend_close() {
        let reg = backend_registry();
        let s = make_session("s1", "agent-a");
        reg.register(s).unwrap();
        assert_eq!(reg.active_count(), 1);
        assert!(reg.close("s1").is_ok());
        assert_eq!(reg.active_count(), 0);
        assert_eq!(reg.agent_stream_count("agent-a"), 0);
    }

    #[test]
    fn test_backend_close_nonexistent() {
        let reg = backend_registry();
        assert!(reg.close("no-such-stream").is_err());
    }

    #[test]
    fn test_backend_validate_frame() {
        let reg = backend_registry();
        let s = make_session("s1", "agent-a");
        reg.register(s).unwrap();
        assert!(reg.validate_frame("s1", 1, 200).is_ok());
        assert!(reg.validate_frame("s1", 2, 100).is_ok());
        assert!(reg.validate_frame("s1", 1, 100).is_err()); // bad seq
        // Confirm state actually persisted across the three calls above.
        let session = reg.get_stream("s1").unwrap();
        assert_eq!(session.last_sequence, 2);
        assert_eq!(session.total_bytes, 400); // 100 initial + 200 + 100
    }

    #[test]
    fn test_backend_continue_and_end_stream() {
        let reg = backend_registry();
        assert!(reg.start_stream("s1", "src-agent", "agent-a").is_ok());
        assert!(reg.continue_stream("s1", 1, 50).is_ok());
        let info = reg.get_stream_info("s1").unwrap();
        assert_eq!(info.2, Some(1));

        let ended = reg.end_stream("s1").unwrap();
        assert!(ended.closed);
        assert_eq!(reg.active_count(), 0);
        assert!(reg.get_stream("s1").is_none());
    }

    #[test]
    fn test_backend_set_stream_token_info() {
        let reg = backend_registry();
        reg.start_stream("s1", "src-agent", "agent-a").unwrap();
        reg.set_stream_token_info("s1", "sighash123", 999.0, "src-agent-2", 1);
        let session = reg.get_stream("s1").unwrap();
        assert_eq!(session.token_sig_hash, "sighash123");
        assert_eq!(session.token_exp, 999.0);
        assert_eq!(session.source_agent, "src-agent-2");
        assert_eq!(session.max_action_class, 1);
    }

    #[test]
    fn test_backend_abort_stream() {
        let reg = backend_registry();
        reg.start_stream("s1", "src-agent", "agent-a").unwrap();
        reg.abort_stream("s1");
        assert!(reg.get_stream("s1").is_none());
        assert_eq!(reg.active_count(), 0);
    }

    #[test]
    fn test_backend_and_local_instances_are_independent() {
        let local = StreamRegistry::new();
        let backend = backend_registry();
        local.register(make_session("s1", "agent-a")).unwrap();
        assert_eq!(local.active_count(), 1);
        assert_eq!(backend.active_count(), 0);
    }
}
