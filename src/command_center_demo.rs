//! command_center_demo.rs — synthetic activity generator for the Command Center dashboard.
//!
//! ## Why this exists
//!
//! `saacp_command_center` stands up an in-process demo `SAACPNetworkDaemon` so the dashboard
//! "has traffic to look at out of the box" — but a *listening* daemon with no client connecting
//! to it produces exactly zero packets, so every dashboard panel (agents, trust mesh, alerts,
//! financial) rendered its (correct) empty state and looked broken. This module closes that gap
//! by driving the very same process-wide global engines a real gate pipeline drives:
//!
//! - [`TrustDecayEngine::global`]`.penalize()/.reward()` → live agent list + `TrustSignal` SSE
//! - [`FAITFAuditLog::log_delegation`] into [`ImmutableAuditLog::global`] → trust-mesh edges +
//!   `DelegationEdge` SSE (via `command_center`'s permanent audit subscriber)
//! - [`telemetry::report_gate_rejection`] / [`telemetry::report_financial_rejection`] → the
//!   security alert feed + `InjectionAlert` SSE + the financial "tokens rejected" counter
//!
//! Because it feeds the real singletons through their real public instrumentation entry points,
//! the dashboard treats this data identically to production traffic — there is no separate
//! "simulation" code path in `command_center.rs` itself, matching that module's "everything is
//! real backend data" contract.
//!
//! ## Scope / honesty
//!
//! This is **demo-only** and lives entirely behind the `command-center` feature and the
//! `saacp_command_center` binary's `SAACP_DISABLE_DEMO_DAEMON` opt-out: running the dashboard
//! against a real gateway process (the documented production topology) sets that flag and gets
//! zero synthetic data. It adds no dependencies — the tiny xorshift PRNG below keeps the
//! feature's standing "adds ZERO new dependencies" invariant rather than pulling in `rand`.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::faitf_audit::FAITFAuditLog;
use crate::security::ImmutableAuditLog;
use crate::telemetry;
use crate::trust_decay::{PenaltyKind, RewardKind, TrustDecayEngine};

/// A simple, dependency-free xorshift64* PRNG. Seeded from the wall clock so each
/// run looks a little different; deterministic quality is irrelevant for cosmetic
/// demo traffic (this is never a security-relevant randomness source).
struct Rng(u64);

impl Rng {
    fn new() -> Self {
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x9E37_79B9_7F4A_7C15)
            | 1;
        Rng(seed)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, n)`. `n == 0` returns 0.
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// True with probability `p` (clamped to `[0, 1]`).
    fn chance(&mut self, p: f64) -> bool {
        (self.next_u64() as f64 / u64::MAX as f64) < p.clamp(0.0, 1.0)
    }

    fn pick<'a, T>(&mut self, items: &'a [T]) -> &'a T {
        &items[self.below(items.len())]
    }

    /// Uniform `f64` in `[lo, hi)`.
    fn range(&mut self, lo: f64, hi: f64) -> f64 {
        lo + (self.next_u64() as f64 / u64::MAX as f64) * (hi - lo)
    }
}

/// The synthetic agent fleet. Names read like a realistic multi-agent system so the
/// mesh graph and agent table look plausible to an operator.
const FLEET: &[&str] = &[
    "orchestrator-01",
    "planner-02",
    "retriever-03",
    "retriever-04",
    "tool-exec-05",
    "tool-exec-06",
    "summarizer-07",
    "critic-08",
    "coder-09",
    "researcher-10",
    "browser-11",
    "sql-agent-12",
    "email-agent-13",
    "finance-agent-14",
];

/// The subset of the fleet that ever draws gate rejections / trust penalties — the
/// externally-exposed, attacker-reachable agents (a browser, a SQL tool, an email
/// tool, an untrusted retriever/finance path). Penalties (0.05–0.40 each) dwarf a
/// `CleanPassage` reward (0.001) with negligible passive recovery, so an agent that
/// gets penalized *at all* trends downward; confining penalties to this handful is
/// what keeps the other ~10 agents pinned green (authorized) instead of the whole
/// fleet decaying to red. The result reads like a real fleet: a trusted majority plus
/// a few degraded/quarantined nodes the gates are actively catching. Every name here
/// MUST also appear in `FLEET`.
const SUSPECTS: &[&str] = &[
    "browser-11",
    "sql-agent-12",
    "email-agent-13",
    "finance-agent-14",
    "retriever-03",
];

/// `(gate, bytecode)` pairs the demo cycles through for non-financial gate rejections.
/// The gate strings are byte-identical to the real ones `handler.rs` reports, so the
/// dashboard's gate-prefix classification (`gate_12_0…` loop, `gate_0_5…` financial,
/// everything else generic) lights up the same way it would on live traffic.
const GATE_REJECTIONS: &[(&str, SAACPBytecodes)] = &[
    ("gate_4_0_inject", SAACPBytecodes::PromptInjectionDetected),
    ("gate_3_0_lateral", SAACPBytecodes::LateralMovementBlocked),
    ("gate_12_0_cscs", SAACPBytecodes::AegfLoopDetected),
    ("gate_1_0_token", SAACPBytecodes::TokenExpired),
    ("gate_5_0_epistemic", SAACPBytecodes::EpistemicUncertainty),
    ("gate_11_0_aegf", SAACPBytecodes::AegfHopLimitExceeded),
    ("gate_2_5_kinetic", SAACPBytecodes::ActionClassEscalation),
    ("gate_9_0_schema", SAACPBytecodes::SchemaMismatch),
];

const PENALTIES: &[PenaltyKind] = &[
    PenaltyKind::InjectionAttempt,
    PenaltyKind::ScopeViolation,
    PenaltyKind::IntentDriftCeiling,
    PenaltyKind::EpistemicOverclaim,
    PenaltyKind::TargetViolation,
    PenaltyKind::ReplaySuspicion,
    PenaltyKind::GenericHardDrop,
];

/// Interval between demo activity ticks. ~1.2s keeps the feed lively without flooding.
const TICK: Duration = Duration::from_millis(1200);

/// Seed the fleet so the dashboard is populated the instant it connects, instead of
/// waiting for the first random tick. Rewards every agent once (so all appear in
/// `/api/agents`) and lays down a plausible delegation topology (so the mesh has shape).
fn seed_fleet() {
    let trust = TrustDecayEngine::global();
    for agent in FLEET {
        // A clean passage nudges the score and, more importantly, registers the agent
        // in the engine so it shows up in the live snapshot immediately.
        trust.reward(agent, RewardKind::CleanPassage, false);
    }

    let audit = ImmutableAuditLog::global();
    // orchestrator delegates to the planner and both retrievers; the planner fans out
    // to the tool executors and the coder; researchers/browsers hang off a retriever.
    let edges: &[(&str, &str, u32)] = &[
        ("orchestrator-01", "planner-02", 1),
        ("orchestrator-01", "retriever-03", 1),
        ("orchestrator-01", "retriever-04", 1),
        ("planner-02", "tool-exec-05", 2),
        ("planner-02", "tool-exec-06", 2),
        ("planner-02", "coder-09", 2),
        ("retriever-03", "researcher-10", 2),
        ("retriever-04", "browser-11", 2),
        ("tool-exec-05", "sql-agent-12", 3),
        ("tool-exec-06", "email-agent-13", 3),
        ("coder-09", "critic-08", 3),
        ("planner-02", "summarizer-07", 2),
        ("orchestrator-01", "finance-agent-14", 1),
    ];
    for (parent, child, depth) in edges {
        FAITFAuditLog::log_delegation(audit, parent, child, *depth, "read:docs,call:tool", None, "");
    }
}

/// One tick of synthetic activity. Split out so it is trivially unit-testable without
/// the async loop.
fn tick(rng: &mut Rng) {
    let trust = TrustDecayEngine::global();

    // Steady baseline: several clean passages spread across the WHOLE fleet every tick.
    // This keeps every never-penalized agent pinned at the authorized ceiling and
    // continuously emits `Rewarded` `TrustSignal`s into the live feed. Rewards on a
    // suspect also let a degraded (not locked) one slowly claw back toward the reward
    // floor, so the fleet breathes instead of monotonically decaying.
    for _ in 0..4 {
        let agent = rng.pick(FLEET);
        trust.reward(agent, RewardKind::CleanPassage, false);
    }

    // A delegation grant, occasionally — refreshes an existing mesh edge's `last_seen`
    // and animates a pulse along it.
    if rng.chance(0.30) {
        let parent = rng.pick(FLEET);
        let child = rng.pick(FLEET);
        if parent != child {
            let depth = 1 + rng.below(3) as u32;
            FAITFAuditLog::log_delegation(
                ImmutableAuditLog::global(),
                parent,
                child,
                depth,
                "call:tool",
                None,
                "",
            );
        }
    }

    // A gate rejection, fairly often — this is the "attack feed". Confined to the
    // attacker-reachable SUSPECTS so the trusted majority stays green (see SUSPECTS doc).
    if rng.chance(0.55) {
        let agent = *rng.pick(SUSPECTS);
        let (gate, bytecode) = *rng.pick(GATE_REJECTIONS);
        let err = SAACPHardDrop::new(bytecode, "demo: synthetic gate rejection");
        telemetry::report_gate_rejection(gate, agent, &err);
        // A rejection is also a behavioral penalty on the offending agent. The lighter
        // penalty kinds keep a suspect hovering in the degraded/serious band (visibly
        // amber/orange) rather than instantly slamming it to quarantine every time.
        let kind = *rng.pick(PENALTIES);
        trust.penalize(agent, kind);
    }

    // A Gate 0.5 financial circuit-breaker block, with a real claimed cost — drives the
    // financial panel's odometer, session chart and blocked-transactions ledger. Also
    // suspect-scoped (the finance/SQL/email agents are exactly where budget blocks land).
    if rng.chance(0.40) {
        let agent = *rng.pick(SUSPECTS);
        let cost = rng.range(0.75, 42.0);
        telemetry::report_financial_rejection(agent, cost);
    }

    // Rarely, drive ONE suspect all the way into reauth-lockout so the mesh shows a
    // quarantined (red, pulsing) node and the health pill reads DEGRADED — the money
    // shot of the demo. Kept infrequent and single-target so it's a visible event, not
    // the steady state.
    if rng.chance(0.04) {
        let agent = *rng.pick(SUSPECTS);
        for _ in 0..8 {
            trust.penalize(agent, PenaltyKind::ReplaySuspicion);
        }
    }
}

/// Run the demo activity generator forever, on a background tokio task. Call this only
/// from the `saacp_command_center` binary when the demo daemon is enabled; a real
/// gateway deployment must never start it (see module doc).
pub async fn run() {
    seed_fleet();
    let mut rng = Rng::new();
    loop {
        tokio::time::sleep(TICK).await;
        tick(&mut rng);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rng_below_is_in_range() {
        let mut rng = Rng::new();
        for _ in 0..1000 {
            assert!(rng.below(FLEET.len()) < FLEET.len());
        }
        assert_eq!(rng.below(0), 0);
    }

    #[test]
    fn rng_range_within_bounds() {
        let mut rng = Rng::new();
        for _ in 0..1000 {
            let v = rng.range(0.75, 42.0);
            assert!((0.75..42.0).contains(&v));
        }
    }

    #[test]
    fn seed_fleet_registers_all_agents() {
        seed_fleet();
        let snapshot = TrustDecayEngine::global().snapshot(1000);
        for agent in FLEET {
            assert!(
                snapshot.iter().any(|a| a.agent_id == *agent),
                "expected demo agent {agent} to be tracked after seeding"
            );
        }
    }

    #[test]
    fn tick_does_not_panic() {
        let mut rng = Rng::new();
        for _ in 0..200 {
            tick(&mut rng);
        }
    }

    #[test]
    fn suspects_are_all_real_fleet_members() {
        for s in SUSPECTS {
            assert!(
                FLEET.contains(s),
                "SUSPECTS entry {s} is not in FLEET — a penalty would target an agent the mesh never seeds"
            );
        }
    }
}
