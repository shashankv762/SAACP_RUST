// BREAKIT — Adversarial Security Test Suite
//
// Combines all BREAKIT phases into a single integration test binary.
// Each phase targets a specific attack surface and maps to an implementation
// module in tests/breakit/<category>/<file>.rs.
//
// Run all phases:
//   cargo test --test breakit -- --nocapture
//
// Run timing tests in release mode for accurate measurements:
//   cargo test --release --test breakit -- --nocapture --test-threads=1
//
// Individual phase filters:
//   cargo test --test breakit scanner   -- Phase 1: Injection scanner
//   cargo test --test breakit forensics -- Phase 0: Memory forensics
//   cargo test --test breakit timing    -- Phase 2: Timing side-channels
//   cargo test --test breakit downgrade -- Phase 3: Protocol downgrade
//   cargo test --test breakit race      -- Phase 4: Concurrency races
//   cargo test --test breakit supply    -- Phase 5: Supply chain
//   cargo test --test breakit compromise -- Phase 6: Two-agent compromise

// Phase 0: Memory Forensics — key material survival, zeroization gaps
#[path = "breakit/forensics/key_material_survival.rs"]
mod breakit_forensics;

// Phase 1: Injection Scanner — UTF-8 boundary attacks, scanner bypasses
#[path = "breakit/scanner/injection_bypass.rs"]
mod breakit_scanner;

// Phase 2: Statistical Timing Side-Channel Analysis
#[path = "breakit/timing/statistical_timing_attack.rs"]
mod breakit_timing;

// Phase 3: Protocol Downgrade and Version Confusion
#[path = "breakit/downgrade/negotiation_attacks.rs"]
mod breakit_downgrade;

// Phase 4: Concurrency Race Condition Hunter
#[path = "breakit/concurrency/race_hunter.rs"]
mod breakit_concurrency;

// Phase 5: Supply Chain and Operational Security
#[path = "breakit/supplychain/dependency_audit.rs"]
mod breakit_supplychain;

// Phase 6: Two-Agent Real Compromise Scenario
#[path = "breakit/compromise/two_agent_scenario.rs"]
mod breakit_compromise;
