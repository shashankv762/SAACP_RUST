//! test_mace_rs.rs — Phase 6 item 5 (Part 8.2, Multi-Agent Collusion Detection
//! Engine): proves MACE's alert-feed wiring (`mace::wire_mace_alert_feed`) is a
//! real subscriber to the SAME `telemetry::SecurityAlertFeed`/
//! `telemetry::report_gate_rejection` every gate in `handler.rs` already calls
//! — not just exercised against a bare `MultiAgentCollusionEngine::new()` in
//! `mace.rs`'s own unit tests. Drives `report_gate_rejection` directly (the
//! exact function every gate rejection site in `handler.rs` calls — see
//! `telemetry.rs:1091`'s doc comment) and confirms `MultiAgentCollusionEngine::
//! global()` observes it end-to-end, through to real enforcement
//! (`TrustDecayEngine`/`DistributedRevocationInfrastructure`).
//!
//! Circular Delegation and Privilege Relay (`feed_delegation`) are NOT
//! exercised here through a live handler.rs/daemon.rs call site — per
//! `mace.rs`'s own module docs' "Honest scope" section, no such site exists in
//! this codebase today (the live token path never surfaces a distinct
//! delegator identity). Those two patterns are covered by `mace.rs`'s own
//! thorough unit tests instead, calling the real `MultiAgentCollusionEngine`
//! API directly — the same "call the real function directly" substitute this
//! crate already established for `ievl`'s Gate-1.5 registration hook (see
//! `test_ievl_rs.rs`'s module doc) and, going back further, for
//! `gate_5_0b_scope_consistency`/`gate_1_5_reinforcement`.

use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

use saacp::mace::{self, MultiAgentCollusionEngine};
use saacp::trust_decay::{trust_key_for, TrustDecayEngine};
use saacp::{DistributedRevocationInfrastructure, SAACPBytecodes, SAACPHardDrop};

/// `wire_mace_alert_feed` adds one more subscriber closure to the
/// process-wide `SecurityAlertFeed` on every call — calling it more than once
/// per process would double/triple-count every subsequent alert across every
/// test in this binary. Guard with `Once`, matching the standard Rust
/// integration-test idiom for "wire a global exactly once."
static WIRE_ONCE: Once = Once::new();
fn ensure_wired() {
    WIRE_ONCE.call_once(mace::wire_mace_alert_feed);
}

fn now_secs() -> f64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs_f64()
}

fn reject(gate: &'static str, agent_id: &str, bytecode: SAACPBytecodes) {
    saacp::telemetry::report_gate_rejection(gate, agent_id, &SAACPHardDrop::new(bytecode, "mace e2e test"));
}

// ─── Sybil Cluster through the real alert-feed subscription ──────────────────

#[test]
fn sybil_cluster_through_real_alert_feed_wiring_penalizes_and_revokes_both() {
    ensure_wired();
    let agent_a = "mace-e2e-sybil-a";
    let agent_b = "mace-e2e-sybil-b";

    // Six identical rejection patterns each — well above SYBIL_MIN_OBSERVATIONS
    // (5) and a perfect 1.0 cosine match.
    for _ in 0..6 {
        reject("gate_4_0_inject", agent_a, SAACPBytecodes::PromptInjectionDetected);
        reject("gate_4_0_inject", agent_b, SAACPBytecodes::PromptInjectionDetected);
    }

    let before_a = TrustDecayEngine::global().score(&trust_key_for(agent_a, ""));

    let matches = MultiAgentCollusionEngine::global().detect_and_enforce_sybil_clusters();
    let found = matches.iter().any(|(a, b, sim)| {
        ((a == agent_a && b == agent_b) || (a == agent_b && b == agent_a)) && *sim >= mace::SYBIL_COSINE_THRESHOLD
    });
    assert!(found, "the two agents driven through the REAL report_gate_rejection entry point \
        must appear as a matched Sybil-cluster pair: {matches:?}");

    let after_a = TrustDecayEngine::global().score(&trust_key_for(agent_a, ""));
    assert!(after_a < before_a, "a confirmed Sybil match must penalize trust: before={before_a} after={after_a}");
    assert!(DistributedRevocationInfrastructure::global().is_revoked(agent_a, ""));
    assert!(DistributedRevocationInfrastructure::global().is_revoked(agent_b, ""));
}

#[test]
fn non_colluding_agents_through_real_alert_feed_wiring_not_flagged() {
    ensure_wired();
    let agent_c = "mace-e2e-distinct-c";
    let agent_d = "mace-e2e-distinct-d";

    for _ in 0..6 {
        reject("gate_4_0_inject", agent_c, SAACPBytecodes::PromptInjectionDetected);
    }
    for _ in 0..6 {
        reject("gate_9_0_schema", agent_d, SAACPBytecodes::SchemaMismatch);
    }

    let matches = MultiAgentCollusionEngine::global().detect_sybil_clusters();
    let false_positive = matches.iter().any(|(a, b, _)| {
        (a == agent_c && b == agent_d) || (a == agent_d && b == agent_c)
    });
    assert!(!false_positive, "agents rejected by completely disjoint gates must never be flagged as a Sybil pair");
}

// ─── Coordinated Exhaustion through the real alert-feed subscription ─────────

#[test]
fn coordinated_exhaustion_through_real_alert_feed_wiring() {
    ensure_wired();
    let now = now_secs();

    for i in 0..mace::COORDINATED_EXHAUSTION_MIN_AGENTS {
        reject("gate_pre_ratelimit", &format!("mace-e2e-exhaustion-{i}"), SAACPBytecodes::CircuitBreakerOpen);
    }

    let detected = MultiAgentCollusionEngine::global().detect_coordinated_exhaustion(now + 1.0);
    assert!(
        detected.is_some() && detected.unwrap() >= mace::COORDINATED_EXHAUSTION_MIN_AGENTS,
        "distinct agents driven through the REAL report_gate_rejection entry point with \
         CircuitBreakerOpen must be visible to detect_coordinated_exhaustion: {detected:?}"
    );
}

// ─── Distraction Cover through the real alert feed ────────────────────────────

#[test]
fn distraction_cover_through_real_report_gate_rejection() {
    // Deliberately does NOT require `ensure_wired()` — Distraction Cover reads
    // `SecurityAlertFeed::recent(..)` directly (see `mace.rs`'s
    // `detect_distraction_cover`), not the subscriber path, so it is provable
    // through `report_gate_rejection` regardless of alert-feed wiring state.
    let around = now_secs();
    for i in 0..mace::DISTRACTION_COVER_MIN_LOW_SEVERITY {
        reject("gate_9_0_schema", &format!("mace-e2e-distraction-{i}"), SAACPBytecodes::SchemaMismatch);
    }

    assert!(
        MultiAgentCollusionEngine::global().detect_distraction_cover(around),
        "low-severity rejections driven through the REAL report_gate_rejection entry point, \
         clustered around `around`, must be detected as Distraction Cover"
    );
}

// ─── Background sweep through the real MaintenanceCoordinator ─────────────────

#[test]
fn mace_sweep_and_enforce_through_real_maintenance_coordinator_revokes_sybil_pair() {
    // Proves the production activation path: `mace::sweep_and_enforce` (the exact
    // closure the binaries register under "mace_global") runs the detectors +
    // enforcement when invoked by a real `MaintenanceCoordinator::run_once`
    // cycle, exactly as the 60s background thread would — not just when a test
    // calls `detect_and_enforce_*` directly. `activate()` (idempotent) both
    // subscribes the global engine to the live alert feed and flips the enabled
    // flag `sweep_and_enforce` guards on.
    use saacp::maintenance::MaintenanceCoordinator;

    mace::activate();

    let agent_a = "mace-e2e-sweep-sybil-a";
    let agent_b = "mace-e2e-sweep-sybil-b";
    for _ in 0..6 {
        reject("gate_4_0_inject", agent_a, SAACPBytecodes::PromptInjectionDetected);
        reject("gate_4_0_inject", agent_b, SAACPBytecodes::PromptInjectionDetected);
    }

    let coordinator = MaintenanceCoordinator::new()
        .with_custom("mace_global", saacp::mace::sweep_and_enforce);
    coordinator.run_once();

    assert!(
        DistributedRevocationInfrastructure::global().is_revoked(agent_a, ""),
        "a Sybil pair observed via the live alert feed must be revoked by a real \
         MaintenanceCoordinator sweep cycle calling mace::sweep_and_enforce"
    );
    assert!(DistributedRevocationInfrastructure::global().is_revoked(agent_b, ""));
}
