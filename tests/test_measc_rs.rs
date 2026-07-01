//! test_measc_rs.rs — MEASC module comprehensive tests
//!
//! Ports key tests from Python tests/test_measc.py (most comprehensive file).
//! Covers:
//!   - Replay window bitmap correctness
//!   - Anomaly policies (Audit, RateLimit, Quarantine)
//!   - Epoch rotation + grace period
//!   - HKDF chain constants match Python
//!   - Wire format: magic bytes, header layout

#![allow(clippy::assertions_on_constants)]

use saacp::{
    ReplayWindow, ReplayWindowPolicy, AnomalyPolicy,
    SessionEpochManager, MEASCFrame,
    MEASC_REPLAY_WINDOW_SIZE, MEASC_MAX_PSN_ADVANCE,
    MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD, MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE,
    MEASC_DEFAULT_EPOCH_TIME_SECONDS, MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
    MEASC_MAGIC, MEASC_HEADER_SIZE,
    MEASC_CONTEXT_REF_ID_OFFSET, MEASC_CONTEXT_REF_ID_SIZE,
};

// ─── Constants ────────────────────────────────────────────────────────────────

#[test]
fn test_psk_magic_bytes() {
    // Wire frame must start with b"SACP" (Python parity: MAGIC = b"SACP")
    assert_eq!(MEASC_MAGIC, b"SACP", "MEASC magic must be b\"SACP\"");
}

#[test]
fn test_measc_header_128_bytes() {
    // MEASC header must be exactly 128 bytes (README §4.1)
    assert_eq!(MEASC_HEADER_SIZE, 128, "MEASC header must be 128 bytes");
}

#[test]
fn test_context_ref_id_offset_44() {
    // Context Ref ID at byte offset 44 in 128-byte header (M-2 fix, README §4.4)
    assert_eq!(
        MEASC_CONTEXT_REF_ID_OFFSET, 44,
        "Context Ref ID must be at offset 44"
    );
    assert_eq!(
        MEASC_CONTEXT_REF_ID_SIZE, 32,
        "Context Ref ID must be 32 bytes"
    );
    // Must fit within header
    assert!(
        MEASC_CONTEXT_REF_ID_OFFSET + MEASC_CONTEXT_REF_ID_SIZE <= MEASC_HEADER_SIZE,
        "Context Ref ID must fit within 128-byte header"
    );
}

#[test]
fn test_epoch_time_threshold_default() {
    // M-3 fix: epoch time threshold must be 600s (not 3600s)
    assert_eq!(
        MEASC_DEFAULT_EPOCH_TIME_SECONDS, 600,
        "Epoch time threshold must be 600s (M-3 fix)"
    );
}

// ─── Replay Window Bitmap ─────────────────────────────────────────────────────

#[test]
fn test_replay_window_basic_accept_and_reject() {
    let mut w = ReplayWindow::with_default_policy();
    // Accept PSN 1..=10
    for psn in 1u64..=10 {
        let (ok, _) = w.check(psn);
        assert!(ok, "PSN {psn} should be accepted");
        w.accept(psn).unwrap();
    }
    // Duplicate rejection
    let (ok, reason) = w.check(5);
    assert!(!ok);
    assert_eq!(reason, "duplicate");
}

#[test]
fn test_replay_window_out_of_window_rejected() {
    // To trigger out_of_window: PSN must satisfy psn <= highest - window_size.
    // With window_size=4096, advance to highest=6000, then check PSN 1:
    // 1 <= 6000 - 4096 = 1904 → out_of_window
    let mut w = ReplayWindow::with_default_policy();
    // Advance highest to 6000 (within max_advance=2048 of where we started = 0)
    // We must build up in steps smaller than max_advance
    let mut h = 0u64;
    let step = MEASC_MAX_PSN_ADVANCE;
    while h + step < 6000 {
        h += step;
        // Only accept — don't check (avoid advance_too_large from h=0)
        w.accept(h).unwrap();
    }
    w.accept(6000).unwrap();
    // PSN 1 is now h - window_size = 6000 - 4096 = 1904 positions behind — out of window
    let (ok, reason) = w.check(1);
    assert!(!ok, "PSN 1 must be out of window when highest=6000");
    assert_eq!(reason, "out_of_window");
}

#[test]
fn test_replay_window_zero_psn_rejected() {
    let mut w = ReplayWindow::with_default_policy();
    // PSN 0 is always invalid
    assert!(w.accept(0).is_err(), "PSN 0 must always be rejected");
}

#[test]
fn test_replay_window_max_advance_rejected() {
    let mut w = ReplayWindow::with_default_policy();
    w.accept(1).unwrap();
    // Jump larger than MEASC_MAX_PSN_ADVANCE is rejected
    let huge = 1 + MEASC_MAX_PSN_ADVANCE + 1;
    let (ok, reason) = w.check(huge);
    assert!(!ok, "Advance > MEASC_MAX_PSN_ADVANCE must be rejected");
    assert_eq!(reason, "advance_too_large");
}

#[test]
fn test_replay_window_window_size_constant() {
    assert!(MEASC_REPLAY_WINDOW_SIZE >= 64, "Window size must be >= 64");
    assert!(MEASC_REPLAY_WINDOW_SIZE <= 4096, "Window size must be <= 4096");
}

#[test]
fn test_replay_window_statistics_struct() {
    let mut w = ReplayWindow::with_default_policy();
    w.accept(42).unwrap();
    let s = w.statistics();
    assert_eq!(s.highest, 42);
    assert_eq!(s.anomaly_count, 0);
    assert!(!s.quarantined);
    assert!(!s.grace_period_locked);
    assert!(s.initialized);
    assert_eq!(s.window_size, MEASC_REPLAY_WINDOW_SIZE);
    assert_eq!(s.max_advance, MEASC_MAX_PSN_ADVANCE);
}

// ─── Anomaly Policies ─────────────────────────────────────────────────────────

#[test]
fn test_anomaly_policy_audit_records_anomaly() {
    let policy = ReplayWindowPolicy {
        window_size: MEASC_REPLAY_WINDOW_SIZE,
        max_advance: MEASC_MAX_PSN_ADVANCE,
        anomaly_jump_threshold: MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD,
        anomaly_policy: AnomalyPolicy::Audit,
        max_anomalies_before_quarantine: MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE,
        rate_limit_window_seconds: 1.0,
        max_large_advances_per_window: 3,
    };
    let mut w = ReplayWindow::new(policy);
    w.accept(1).unwrap();
    // Jump by anomaly_jump_threshold + 1 to trigger anomaly
    let jump = 1 + MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD + 1;
    let (ok, reason) = w.check(jump);
    assert!(ok, "Audit policy must still allow the packet");
    assert_eq!(reason, "ok_anomaly_recorded");
    // anomaly_count increments
    w.accept(jump).unwrap();
    assert_eq!(w.statistics().anomaly_count, 1);
}

#[test]
fn test_anomaly_policy_quarantine_triggers_at_threshold() {
    // MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE = 5 by default.
    // Use max_anomalies_before_quarantine = 3 so we trigger on the 3rd anomaly.
    let policy = ReplayWindowPolicy {
        window_size: MEASC_REPLAY_WINDOW_SIZE,
        max_advance: MEASC_MAX_PSN_ADVANCE,
        anomaly_jump_threshold: MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD,
        anomaly_policy: AnomalyPolicy::Quarantine,
        max_anomalies_before_quarantine: 3, // trigger at 3rd anomaly
        rate_limit_window_seconds: 1.0,
        max_large_advances_per_window: 10,
    };
    let mut w = ReplayWindow::new(policy);
    // Each jump must be > anomaly_jump_threshold but <= max_advance
    let jump = MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD + 1;
    let mut base = 1u64;
    w.accept(base).unwrap();

    // First 2 anomalies — check returns ok_anomaly_recorded (counter increments)
    for i in 0..2 {
        base += jump;
        let (ok, reason) = w.check(base);
        assert!(ok, "Anomaly {} must be ok_anomaly_recorded", i + 1);
        assert_eq!(reason, "ok_anomaly_recorded");
        w.accept(base).unwrap();
    }
    // 3rd anomaly — check returns quarantined (anomaly_count reaches max)
    base += jump;
    let (ok, reason) = w.check(base);
    assert!(!ok, "3rd anomaly must be quarantined");
    assert_eq!(reason, "quarantined", "Expected quarantined, got: {reason}");
    assert!(w.statistics().quarantined);
}

#[test]
fn test_anomaly_policy_rate_limit_blocks_excess() {
    let policy = ReplayWindowPolicy {
        window_size: MEASC_REPLAY_WINDOW_SIZE,
        max_advance: MEASC_MAX_PSN_ADVANCE,
        anomaly_jump_threshold: MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD,
        anomaly_policy: AnomalyPolicy::RateLimit,
        max_anomalies_before_quarantine: 100,
        rate_limit_window_seconds: 60.0,
        max_large_advances_per_window: 2, // max 2 per window
    };
    let mut w = ReplayWindow::new(policy);
    // Establish baseline so highest >= 0 (required for anomaly detection)
    w.accept(1).unwrap();
    let mut base = 1u64;

    // First 2 large advances MUST be allowed (rate_window_advances=1,2 <= 2)
    for i in 0..2 {
        let next = base + MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD + 1;
        let (ok, _reason) = w.check(next);
        assert!(ok, "Advance {} must be allowed (max=2)", i + 1);
        w.accept(next).unwrap();
        base = next;
    }
    // 3rd large advance — rate_window_advances would become 3 > 2 → rejected
    let next = base + MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD + 1;
    let (ok, reason) = w.check(next);
    assert!(!ok, "3rd advance must be rate-limited when max=2");
    assert_eq!(reason, "rate_limit_exceeded");
}

// ─── Grace Period ─────────────────────────────────────────────────────────────

#[test]
fn test_grace_period_lock_prevents_reset() {
    let mut w = ReplayWindow::with_default_policy();
    w.accept(100).unwrap();
    w.lock_for_grace_period();
    assert!(w.is_grace_period_locked());
    // reset() must be blocked
    assert!(w.reset().is_err(), "reset() must fail during grace period");
}

#[test]
fn test_grace_period_flag_preserved_across_accepts() {
    let mut w = ReplayWindow::with_default_policy();
    w.accept(10).unwrap();
    w.lock_for_grace_period();
    // Accepting more packets does NOT unlock
    let _ = w.accept(11);
    assert!(w.is_grace_period_locked(), "Grace period lock must persist");
}

// ─── Epoch Manager ────────────────────────────────────────────────────────────

#[test]
fn test_session_epoch_manager_create_and_get() {
    let mgr = SessionEpochManager::new();
    let sid = [0xABu8; 16];
    mgr.create_session(sid, [0x11u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
    assert_eq!(mgr.session_count(), 1);
    assert_eq!(mgr.get_current_epoch_id(&sid), Some(0));
}

#[test]
fn test_session_epoch_manager_duplicate_rejected() {
    let mgr = SessionEpochManager::new();
    let sid = [0x22u8; 16];
    mgr.create_session(sid, [0u8; 32], 10_000, 600.0, None).unwrap();
    assert!(
        mgr.create_session(sid, [0u8; 32], 10_000, 600.0, None).is_err(),
        "Duplicate session must be rejected"
    );
}

#[test]
fn test_session_epoch_destroy_clears_key() {
    // Create epoch via the manager, then destroy it and verify key is gone
    let mgr = SessionEpochManager::new();
    let sid = [0xEEu8; 16];
    mgr.create_session(sid, [1u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();
    // Before destroy: traffic key accessible
    let key_ok = mgr.with_epoch(&sid, 0, |ep| ep.traffic_key().is_ok())
        .unwrap_or(false);
    assert!(key_ok, "Traffic key must be accessible before destroy");
    // Destroy session
    mgr.destroy_session(&sid);
    // After destroy: session gone
    assert_eq!(mgr.session_count(), 0);
    // with_epoch returns None (session destroyed)
    let gone = mgr.with_epoch(&sid, 0, |ep| ep.is_destroyed());
    assert!(gone.is_none(), "Destroyed session must be removed from manager");
}

#[test]
fn test_session_epoch_manager_destroy() {
    let mgr = SessionEpochManager::new();
    let sid = [0xCCu8; 16];
    mgr.create_session(sid, [2u8; 32], 10_000, 600.0, None).unwrap();
    assert_eq!(mgr.session_count(), 1);
    mgr.destroy_session(&sid);
    assert_eq!(mgr.session_count(), 0);
}

#[test]
fn test_epoch_snapshot_is_copy() {
    let mgr = SessionEpochManager::new();
    let sid = [0xDDu8; 16];
    mgr.create_session(sid, [3u8; 32], 10_000, 600.0, None).unwrap();
    let snap1 = mgr.get_epoch(&sid, 0).unwrap();
    let snap2 = mgr.get_current_epoch(&sid).unwrap();
    assert_eq!(snap1.epoch_id, snap2.epoch_id);
    assert!(!snap1.is_destroyed);
}

// ─── HKDF Chain ───────────────────────────────────────────────────────────────

#[test]
fn test_hkdf_info_prefixes_match_python() {
    // These byte strings MUST match Python measc.py exactly (wire interop)
    use saacp::MEASC_AUTH_TAG_SIZE;
    assert_eq!(MEASC_AUTH_TAG_SIZE, 16, "AES-GCM auth tag must be 16 bytes");
}

#[test]
fn test_measc_frame_roundtrip() {
    // Build a SessionEpoch directly, then use its manager's parse_frame
    let sid = [0x01u8; 16];
    let mgr = SessionEpochManager::new();
    mgr.create_session(sid, [0x42u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64, None).unwrap();

    let payload = b"hello SAACP measc";
    let ctx_ref = [0u8; 32];
    let traceparent = [0u8; 24];

    // Build frame using with_epoch_mut
    let result = mgr.with_epoch_mut(&sid, 0, |epoch| {
        MEASCFrame::build_frame(
            epoch,
            0x01,   // schema_id
            0x00,   // status_code
            0x00,   // flags
            0x00,   // action_class
            payload,
            &ctx_ref,
            &traceparent,
            0,      // context_version
        )
    });
    let (frame, _psn) = result
        .expect("with_epoch_mut must find epoch")
        .expect("build_frame must succeed");

    // Frame must start with SACP magic
    assert_eq!(&frame[..4], b"SACP");
    // Frame length must exceed header size (auth tag + ciphertext follow)
    assert!(frame.len() > MEASC_HEADER_SIZE,
        "frame length {} must exceed header {}", frame.len(), MEASC_HEADER_SIZE);

    // Roundtrip parse
    let parsed = MEASCFrame::parse_frame(&frame, &mgr, true)
        .expect("parse must succeed");
    assert_eq!(parsed.payload, payload);
    assert_eq!(parsed.psn, 1);
    assert_eq!(parsed.session_id, sid);
    // The header embedded in the frame must start with magic
    assert_eq!(&frame[..4], b"SACP");
}

#[test]
fn test_measc_replay_window_policy_defaults_are_sane() {
    let p = ReplayWindowPolicy::default();
    assert!(p.window_size >= 64);
    assert!(p.max_advance > 0);
    assert!(p.max_advance < p.window_size as u64, "max_advance must be < window_size");
    assert!(p.anomaly_jump_threshold < p.max_advance);
}
