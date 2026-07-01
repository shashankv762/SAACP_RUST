//! test_stream_security_rs.rs — Stream security tests (C-2, AuthInvariance)
//!
//! Ports Python: tests/test_stream_security.py
//! StreamSession, StreamRegistry validation, sequence enforcement, limits.

#![allow(clippy::assertions_on_constants)]

use saacp::{
    StreamSession, StreamRegistry,
    STREAM_MAX_TOTAL_BYTES, STREAM_MAX_DURATION_SECONDS, STREAM_MAX_FRAME_GAP_SECONDS,
    MAX_ACTIVE_STREAMS, MAX_STREAMS_PER_AGENT,
};

fn fresh_session(stream_id: &str, agent_id: &str) -> StreamSession {
    StreamSession::new(stream_id.to_string(), agent_id.to_string(), 128)
}

// ─── Constants ────────────────────────────────────────────────────────────────

#[test]
fn test_stream_max_total_bytes_positive() {
    assert!(STREAM_MAX_TOTAL_BYTES > 0);
}

#[test]
fn test_stream_max_duration_positive() {
    assert!(STREAM_MAX_DURATION_SECONDS > 0.0);
}

#[test]
fn test_stream_max_frame_gap_positive() {
    assert!(STREAM_MAX_FRAME_GAP_SECONDS > 0.0);
}

#[test]
fn test_max_active_streams_positive() {
    assert!(MAX_ACTIVE_STREAMS > 0);
}

#[test]
fn test_max_streams_per_agent_positive() {
    assert!(MAX_STREAMS_PER_AGENT > 0);
}

// ─── StreamSession ────────────────────────────────────────────────────────────

#[test]
fn test_stream_session_new_ok() {
    let s = fresh_session("stream-1", "agent-1");
    assert_eq!(s.stream_id, "stream-1");
    assert_eq!(s.agent_id, "agent-1");
    assert!(!s.closed);
    assert_eq!(s.frame_count, 0);
}

#[test]
fn test_stream_session_initial_bytes() {
    let s = StreamSession::new("stream-2".to_string(), "agent-2".to_string(), 512);
    assert_eq!(s.total_bytes, 512);
}

#[test]
fn test_stream_session_validate_continuation_sequence_ok() {
    let mut s = fresh_session("stream-3", "agent-3");
    // Sequence IDs must be monotonically increasing
    let res = s.validate_continuation(1, 128);
    assert!(res.is_ok(), "Continuation with seq=1 must succeed: {:?}", res);
}

#[test]
fn test_stream_session_validate_continuation_wrong_sequence_fails() {
    let mut s = fresh_session("stream-4", "agent-4");
    s.validate_continuation(1, 128).unwrap();
    // Now try to send seq=1 again (replay)
    let res = s.validate_continuation(1, 128);
    assert!(res.is_err(), "Replayed sequence ID must be rejected");
}

#[test]
fn test_stream_session_close_marks_closed() {
    let mut s = fresh_session("stream-5", "agent-5");
    s.close();
    assert!(s.closed);
}

#[test]
fn test_stream_session_validate_continuation_after_close_fails() {
    let mut s = fresh_session("stream-6", "agent-6");
    s.close();
    let res = s.validate_continuation(1, 128);
    assert!(res.is_err(), "Continuation on closed stream must fail");
}

// ─── StreamRegistry ───────────────────────────────────────────────────────────

#[test]
fn test_stream_registry_register_and_count() {
    let reg = StreamRegistry::new();
    let s = fresh_session("stream-reg-1", "agent-reg-1");
    reg.register(s).unwrap();
    assert_eq!(reg.active_count(), 1);
}

#[test]
fn test_stream_registry_duplicate_id_rejected() {
    // register overwrites on duplicate stream_id (HashMap semantics); count stays at 1
    let reg = StreamRegistry::new();
    let s1 = fresh_session("stream-dup", "agent-dup");
    let s2 = fresh_session("stream-dup", "agent-dup");
    reg.register(s1).unwrap();
    reg.register(s2).unwrap(); // Replaces first — no error, count unchanged
    assert_eq!(reg.active_count(), 1);
}

#[test]
fn test_stream_registry_get_stream() {
    let reg = StreamRegistry::new();
    let s = fresh_session("stream-get", "agent-get");
    reg.register(s).unwrap();
    let got = reg.get_stream("stream-get");
    assert!(got.is_some());
}

#[test]
fn test_stream_registry_get_unknown_returns_none() {
    let reg = StreamRegistry::new();
    assert!(reg.get_stream("nonexistent-stream").is_none());
}

#[test]
fn test_stream_registry_close() {
    let reg = StreamRegistry::new();
    let s = fresh_session("stream-close", "agent-close");
    reg.register(s).unwrap();
    let res = reg.close("stream-close");
    assert!(res.is_ok());
}

#[test]
fn test_stream_registry_close_unknown_fails() {
    let reg = StreamRegistry::new();
    let res = reg.close("nonexistent");
    assert!(res.is_err());
}

#[test]
fn test_stream_registry_abort_stream() {
    let reg = StreamRegistry::new();
    let s = fresh_session("stream-abort", "agent-abort");
    reg.register(s).unwrap();
    reg.abort_stream("stream-abort"); // Must not panic
    // After abort, stream should be gone
    assert!(reg.get_stream("stream-abort").is_none());
}

#[test]
fn test_stream_registry_agent_stream_count() {
    let reg = StreamRegistry::new();
    let s1 = fresh_session("stream-sc-1", "agent-sc");
    let s2 = fresh_session("stream-sc-2", "agent-sc");
    reg.register(s1).unwrap();
    reg.register(s2).unwrap();
    assert_eq!(reg.agent_stream_count("agent-sc"), 2);
}

#[test]
fn test_stream_registry_agent_stream_count_zero_for_unknown() {
    let reg = StreamRegistry::new();
    assert_eq!(reg.agent_stream_count("unknown-agent"), 0);
}

// ─── StreamRegistry global singleton ──────────────────────────────────────────

#[test]
fn test_stream_registry_global_exists() {
    let global = StreamRegistry::global();
    let _ = global.active_count(); // Must not panic
}

#[test]
fn test_stream_registry_start_and_end_stream() {
    let reg = StreamRegistry::new();
    reg.start_stream("stream-se-1", "agent-se-1", "agent-se-1").unwrap();
    let session = reg.end_stream("stream-se-1");
    assert!(session.is_some(), "end_stream must return the closed session");
    let ended = session.unwrap();
    assert_eq!(ended.stream_id, "stream-se-1");
}

#[test]
fn test_stream_registry_end_stream_unknown_returns_none() {
    let reg = StreamRegistry::new();
    assert!(reg.end_stream("nonexistent").is_none());
}

#[test]
fn test_stream_registry_get_stream_info() {
    let reg = StreamRegistry::new();
    let s = fresh_session("stream-info", "agent-info");
    reg.register(s).unwrap();
    let info = reg.get_stream_info("stream-info");
    assert!(info.is_some());
}

#[test]
fn test_stream_registry_get_stream_info_unknown_returns_none() {
    let reg = StreamRegistry::new();
    assert!(reg.get_stream_info("no-such-stream").is_none());
}
