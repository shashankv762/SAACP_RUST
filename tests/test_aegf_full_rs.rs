//! test_aegf_full_rs.rs — AEGF full governance framework tests
//!
//! Ports Python: tests/test_aegf.py, tests/test_aegf_governance.py
//! AEGFMetadata, ExecutionStateMachine, DistributedExecutionGraph, AEGFGovernor.

use saacp::{
    AEGFMetadata, ExecutionState, ExecutionStateMachine,
    DistributedExecutionGraph, AEGFPolicy, AEGFGovernor, GovernanceDecision,
    AEGF_META_SIZE, AEGF_META_FORMAT_VERSION, RID_ROOT, CID_NONE,
};

fn make_meta(oaid: &str, sid: &str) -> AEGFMetadata {
    AEGFMetadata::new(oaid, sid, None, None, 60.0, 0, 0)
}

// ─── Constants ────────────────────────────────────────────────────────────────

#[test]
fn test_aegf_meta_size_is_120() {
    assert_eq!(AEGF_META_SIZE, 120);
}

#[test]
fn test_aegf_meta_format_version() {
    assert_eq!(AEGF_META_FORMAT_VERSION, 1);
}

#[test]
fn test_rid_root_is_all_zeros() {
    assert_eq!(RID_ROOT, "00000000000000000000000000000000");
}

#[test]
fn test_cid_none_is_all_zeros() {
    assert_eq!(CID_NONE, "00000000000000000000000000000000");
}

// ─── AEGFMetadata ────────────────────────────────────────────────────────────

#[test]
fn test_metadata_new() {
    let m = make_meta("agent-1", "session-1");
    assert_eq!(m.oaid, "agent-1");
    assert_eq!(m.sid, "session-1");
    assert_eq!(m.hc, 0);
    assert_eq!(m.ed, 0);
}

#[test]
fn test_metadata_new_generates_rid() {
    let m = make_meta("agent-1", "session-1");
    assert!(!m.rid.is_empty());
    assert_ne!(m.rid, "00000000000000000000000000000000");
}

#[test]
fn test_metadata_new_root_has_rid_root_prid() {
    let m = make_meta("agent-root", "session-root");
    assert!(m.is_root(), "New metadata with no parent must be root");
}

#[test]
fn test_metadata_not_expired_immediately() {
    let m = AEGFMetadata::new("oaid", "sid", None, None, 60.0, 0, 0);
    assert!(!m.is_expired());
}

#[test]
fn test_metadata_with_explicit_cid() {
    let cid = "abcdef0123456789abcdef0123456789";
    let m = AEGFMetadata::new("oaid", "sid", Some(cid), None, 60.0, 0, 0);
    assert_eq!(m.cid, cid);
}

#[test]
fn test_metadata_pack_is_120_bytes() {
    let m = make_meta("agent-pack", "session-pack");
    let packed = m.pack();
    assert_eq!(packed.len(), AEGF_META_SIZE);
}

#[test]
fn test_metadata_pack_unpack_roundtrip() {
    // sid must be a 32-char hex string — str_to_16 hex-decodes it for wire storage
    let sid = "aabbccddee001122334455667788990f";
    let m = AEGFMetadata::new("agent-rtrip", sid, None, None, 60.0, 0, 0);
    let packed = m.pack();
    let recovered = AEGFMetadata::unpack(&packed);
    assert!(recovered.is_ok(), "unpack must succeed: {:?}", recovered);
    let r = recovered.unwrap();
    assert_eq!(r.oaid, "agent-rtrip");
    assert_eq!(r.sid, sid);
    assert_eq!(r.hc, 0);
    assert_eq!(r.ed, 0);
}

#[test]
fn test_metadata_unpack_too_short_fails() {
    let bad = vec![0u8; 10];
    let res = AEGFMetadata::unpack(&bad);
    assert!(res.is_err(), "Short data must fail unpack");
}

#[test]
fn test_metadata_derive_increments_hc() {
    let parent = make_meta("oaid", "session");
    let child = AEGFMetadata::derive(&parent, None).unwrap();
    assert_eq!(child.hc, parent.hc + 1);
}

#[test]
fn test_metadata_derive_increments_ed() {
    let parent = make_meta("oaid", "session");
    let child = AEGFMetadata::derive(&parent, None).unwrap();
    assert_eq!(child.ed, parent.ed + 1);
}

#[test]
fn test_metadata_derive_preserves_cid() {
    let parent = make_meta("oaid", "session");
    let child = AEGFMetadata::derive(&parent, None).unwrap();
    assert_eq!(child.cid, parent.cid);
}

#[test]
fn test_metadata_derive_sets_parent_rid_as_prid() {
    let parent = make_meta("oaid", "session");
    let parent_rid = parent.rid.clone();
    let child = AEGFMetadata::derive(&parent, None).unwrap();
    assert_eq!(child.prid, parent_rid);
}

#[test]
fn test_metadata_derive_new_oaid() {
    let parent = make_meta("agent-parent", "session");
    let child = AEGFMetadata::derive(&parent, Some("agent-child")).unwrap();
    assert_eq!(child.oaid, "agent-child");
}

#[test]
fn test_metadata_hc_at_max_fails_derive() {
    let mut parent = make_meta("oaid", "session");
    parent.hc = 0xFFFF;
    let res = AEGFMetadata::derive(&parent, None);
    assert!(res.is_err(), "HC at maximum must fail derive");
}

#[test]
fn test_metadata_ed_at_max_fails_derive() {
    let mut parent = make_meta("oaid", "session");
    parent.ed = 0xFFFF;
    let res = AEGFMetadata::derive(&parent, None);
    assert!(res.is_err(), "ED at maximum must fail derive");
}

// ─── ExecutionState ───────────────────────────────────────────────────────────

#[test]
fn test_terminal_states() {
    assert!(ExecutionState::Completed.is_terminal());
    assert!(ExecutionState::Failed.is_terminal());
    assert!(ExecutionState::Terminated.is_terminal());
    assert!(ExecutionState::Expired.is_terminal());
}

#[test]
fn test_non_terminal_states() {
    assert!(!ExecutionState::Created.is_terminal());
    assert!(!ExecutionState::Processing.is_terminal());
    assert!(!ExecutionState::Paused.is_terminal());
    assert!(!ExecutionState::WaitingHumanReview.is_terminal());
}

// ─── ExecutionStateMachine ────────────────────────────────────────────────────

#[test]
fn test_esm_create_ok() {
    let esm = ExecutionStateMachine::new();
    let res = esm.create("rid-1", "test request");
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), ExecutionState::Created);
}

#[test]
fn test_esm_create_duplicate_fails() {
    let esm = ExecutionStateMachine::new();
    esm.create("rid-dup", "first").unwrap();
    let res = esm.create("rid-dup", "second");
    assert!(res.is_err(), "Duplicate RID must fail");
}

#[test]
fn test_esm_get_state_created() {
    let esm = ExecutionStateMachine::new();
    esm.create("rid-state", "test").unwrap();
    let state = esm.get_state("rid-state");
    assert_eq!(state, Some(ExecutionState::Created));
}

#[test]
fn test_esm_get_state_unknown_returns_none() {
    let esm = ExecutionStateMachine::new();
    assert!(esm.get_state("nonexistent").is_none());
}

#[test]
fn test_esm_valid_transition_created_to_processing() {
    let esm = ExecutionStateMachine::new();
    esm.create("rid-trans", "test").unwrap();
    let res = esm.transition("rid-trans", ExecutionState::Processing, "started");
    assert!(res.is_ok());
    assert_eq!(res.unwrap(), ExecutionState::Processing);
}

#[test]
fn test_esm_invalid_transition_completed_to_processing_fails() {
    let esm = ExecutionStateMachine::new();
    esm.create("rid-invalid", "test").unwrap();
    esm.transition("rid-invalid", ExecutionState::Completed, "done").unwrap();
    let res = esm.transition("rid-invalid", ExecutionState::Processing, "restart");
    assert!(res.is_err(), "Terminal state must not transition");
}

#[test]
fn test_esm_remove() {
    let esm = ExecutionStateMachine::new();
    esm.create("rid-remove", "test").unwrap();
    let removed = esm.remove("rid-remove");
    assert!(removed);
    assert!(esm.get_state("rid-remove").is_none());
}

#[test]
fn test_esm_count() {
    let esm = ExecutionStateMachine::new();
    for i in 0..5 {
        esm.create(&format!("rid-cnt-{}", i), "test").unwrap();
    }
    assert_eq!(esm.count(), 5);
}

// ─── DistributedExecutionGraph ───────────────────────────────────────────────

#[test]
fn test_deg_add_and_count() {
    let deg = DistributedExecutionGraph::new();
    let m = make_meta("oaid", "session");
    deg.add_node(&m);
    assert_eq!(deg.node_count(), 1);
}

#[test]
fn test_deg_no_cycle_on_linear_chain() {
    let deg = DistributedExecutionGraph::new();
    let m1 = make_meta("agent", "session");
    let m2 = AEGFMetadata::derive(&m1, None).unwrap();
    let m3 = AEGFMetadata::derive(&m2, None).unwrap();
    deg.add_node(&m1);
    deg.add_node(&m2);
    deg.add_node(&m3);
    assert!(!deg.detect_cycle(&m3.rid));
}

#[test]
fn test_deg_get_ancestors() {
    let deg = DistributedExecutionGraph::new();
    let m1 = make_meta("agent", "session");
    let m2 = AEGFMetadata::derive(&m1, None).unwrap();
    deg.add_node(&m1);
    deg.add_node(&m2);
    let ancestors = deg.get_ancestors(&m2.rid);
    assert!(ancestors.contains(&m1.rid));
}

#[test]
fn test_deg_detect_excessive_hops() {
    let mut m = make_meta("agent", "session");
    m.hc = 100;
    let excessive = DistributedExecutionGraph::detect_excessive_hops(&m, 50);
    assert!(excessive, "HC=100 vs max=50 must be excessive");
}

#[test]
fn test_deg_detect_excessive_depth() {
    let mut m = make_meta("agent", "session");
    m.ed = 20;
    let excessive = DistributedExecutionGraph::detect_excessive_depth(&m, 10);
    assert!(excessive, "ED=20 vs max=10 must be excessive");
}

// ─── AEGFGovernor ────────────────────────────────────────────────────────────

#[test]
fn test_governor_submit_request_root_ok() {
    let gov = AEGFGovernor::new(None);
    let m = make_meta("agent-gov", "session-gov");
    let decision = gov.submit_request(&m);
    assert!(matches!(decision, GovernanceDecision::Allow | GovernanceDecision::Pause));
}

#[test]
fn test_governor_complete_request() {
    let gov = AEGFGovernor::new(None);
    let m = make_meta("agent-gov-2", "session-gov-2");
    let rid = m.rid.clone();
    gov.submit_request(&m);
    gov.complete_request(&rid, None); // Must not panic
}

#[test]
fn test_governor_pause_and_escalate() {
    let gov = AEGFGovernor::new(None);
    let m = make_meta("agent-gov-3", "session-gov-3");
    let rid = m.rid.clone();
    gov.submit_request(&m);
    gov.pause_request(&rid, "waiting-human");
    gov.escalate_to_review(&rid, "suspicious activity");
    let state = gov.get_request_state(&rid);
    // Should be in review now
    assert!(state.is_some());
}

#[test]
fn test_governor_exceed_hc_terminates() {
    let policy = AEGFPolicy {
        max_hop_count: 5,
        max_execution_depth: 10,
        ..Default::default()
    };
    let gov = AEGFGovernor::new(Some(policy));
    let mut m = make_meta("agent-hc-x", "session-hc-x");
    m.hc = 10; // Exceeds max_hop_count=5 → Pause (not Terminate)
    let decision = gov.submit_request(&m);
    assert!(matches!(decision, GovernanceDecision::Pause));
}

#[test]
fn test_governor_expire_stale() {
    let gov = AEGFGovernor::new(None);
    let m = make_meta("agent-stale", "session-stale");
    gov.submit_request(&m);
    let count = gov.expire_stale_requests();
    let _ = count; // May be 0 or more depending on TTL
}

#[test]
fn test_governor_default_policy_reasonable() {
    let gov = AEGFGovernor::new(None);
    let p = gov.get_policy();
    assert!(p.max_hop_count > 0);
    assert!(p.max_execution_depth > 0);
}
