# Changelog

All notable changes to the SAACP Rust implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Longcat.md re-verification residuals (see the "Re-verification addendum
(2026-09)" section of longcat.md). All behavior is byte-identical to
v0.2.1 under the single-tenant shared-default context; the context-aware
behavior only differs for hermetic `SaacpContext::new()` deployments or when
the new opt-ins are enabled.

### Changed
- **`SaacpContext` owns the full hot-path subsystem set** (Gap B completion):
  the handler's remaining global fallbacks (rate limiter, dead-man's-switch,
  federated memory, identity gate, IEVL engine, AEGF governor, CSCS loop
  detector, stream revocation gateway) and the daemon's per-connection checks
  (IP-level trust gating/penalties, revocation-epoch pinning, identity-gate
  advancement including the identity-bound handshake, shutdown WAL flush,
  audit-chain recovery) now resolve through the connection's context.
  `SaacpContext::shared_default()` aliases the exact legacy `::global()`
  instances, so existing deployments observe zero behavior change; hermetic
  per-tenant contexts no longer leak into the process globals — notably the
  daemon's hard-drop IP trust penalty, which previously penalized the GLOBAL
  trust engine even for hermetic contexts (cross-tenant leak, fixed).
- **Clock seam extended to the packet hot path**: the six remaining
  `SystemTime::now()` sites in `handler.rs` (pregate rate-limit/reauth reads,
  Gate 11.0/12.0's shared TTL read, stream token-expiry reads, injection
  corroboration window) plus the daemon affinity-alert timestamp now use
  `crate::clock::now_secs_f64()`. Semantics identical (same
  `unwrap_or_default` behavior); enables future deterministic-time testing.

### Added
- **Gate 6.0 fail-closed on the write itself** (Gap D follow-up): the audit
  checkpoint now uses the fallible `ImmutableAuditLog::try_append_event`. An
  IRREVERSIBLE packet (action_class >= 0x02) whose own audit entry cannot be
  enqueued is hard-dropped with `AuditSubsystemDegraded` instead of executing
  with a silently missing audit record — closing the race window between Gate
  2.5's pre-write health check and Gate 6.0's write. Reversible/read-only
  packets keep the legacy count-only flow (drop is already counted with the
  sticky health floor). Cover-traffic and stream-core audit writes are
  unchanged. Pinned by three white-box unit tests in `handler.rs` plus
  end-to-end contract tests in `tests/test_gate6_backpressure_rs.rs`.
- **Opt-in dropped-audit auto-acknowledgement**: `SAACPNetworkDaemon::
  with_dropped_audit_autoack(quiet_window)` spawns the previously-unwired
  `ImmutableAuditLog::spawn_dropped_audit_autoack` task at startup (bound to
  the daemon shutdown token, joined during drain). After `quiet_window` with
  no NEW drops it releases the sticky Gate-2.5 fail-closed floor; the lifetime
  `dropped_audit_count()` is never reset. Default `None` keeps the
  operator-ack-only posture — the field doc names the availability-cliff
  tradeoff.
- **Startup sweep for orphaned WAL `.bak` files** (Risk 5): every
  `ImmutableAuditLog` construction scans the WAL's directory for
  `<basename>.<ts>.bak` orphans left by a crash between rotation-rename and
  gzip compression, and re-runs the C-4 compression/archival path on each
  (background thread; failures warn and leave the orphan in place — never
  panics, never refuses startup). A process-local in-flight registry, claimed
  inside the compression entry point itself, prevents double-compression of
  the same file — whether the race is sweep-vs-sweep across constructions
  sharing a WAL path or sweep-vs-live-rotation.

### Hardened (v0.2.2 items — integrated from the audit remediation branch)
- **S2 / secure-by-default**: `SAACPNetworkDaemon::new()` is now the
  hardened profile (authenticated ECDH handshake + AEAD encrypted transport
  composed automatically); the permissive pre-S2 shape is reachable only via
  the explicitly-named `insecure_for_testing()`, which prints a loud warning.
- **M1 (audit auto-recovery)**: `audit_chain_recovery` now auto-enables when
  a stable `token_issuer_secret` is configured, with the
  `SAACP_AUDIT_NO_RECOVER=1` / `SAACP_AUDIT_RECOVER=1` force-offs/on taking
  precedence over both the builder and the auto-detect (documented priority).
- **M3 (state-backend circuit breaker)**: new public
  `state_backend::CircuitBreakerBackend<B>` decorator — wraps any
  `StateBackend` with CLOSED → OPEN → HALF_OPEN semantics (fail-fast while a
  degraded backend recovers, single-probe half-open recovery, instant reopen
  on a failed probe). Reports the new gauge
  `saacp_state_backend_circuit_breaker_state` (0/1/2) via
  `TelemetryCollector::set_state_backend_circuit_breaker_state`.

### Documentation
- Corrected `SAACPNetworkDaemon.gateway` field docs + the startup warning:
  the no-gateway path has been fail-closed (`LateralMovementBlocked`) since
  the `dangerously-skip-gateway` hardening; the previous text described the
  removed synthetic READ_ONLY fallback, which now exists only under that
  feature.
- `intercept_packet`'s doc now spells out the 4-arg default-build behavior,
  and the `SaacpContext` scope note documents the two deliberately
  process-global remainders (cluster/gossip engines, the identity session
  registry).
- README test-suite counts corrected (57 `test_*.rs` + 4 harness/fixture
  files = 61; 7 breakit suites) and the module count corrected (52 -> 68
  source modules + 2 `src/bin` binaries).
- `SaacpContext::new`'s doc now discloses that hermetic contexts share the
  default WAL file path (logical per-context state, one interleaved on-disk
  chain) and points at `with_paths`/`with_audit` for physical separation.

### Operational hygiene
- The `SAACP_TEST_LOG_DIR` audit-path redirect is honored in every build
  profile — including release — so its engagement now emits a once-per-process
  stderr warning naming the redirect target; a leftover env var in a
  production container can no longer silently relocate the audit trail.
- Constructing an audit log in in-memory-only mode (empty WAL path — no
  durable, verifiable chain) now emits a once-per-process stderr warning so
  a misconfigured daemon cannot run blind silently. Both notices are
  visibility-only: no behavior change.

## [0.2.1] - 2026-09-06

Production-readiness audit remediations (see PRODUCTION_READINESS_AUDIT.md —
each fix carries its audit gap/risk ID). All knobs default off/unchanged unless
noted.

### Added
- **Audit-chain recovery at startup** (M-A, G1/R1): with
  `SAACP_AUDIT_RECOVER=1` (or `SAACPNetworkDaemon::with_audit_chain_recovery`),
  `start_with_shutdown` verifies the persisted chain via
  `ImmutableAuditLog::initialize_chain` against the configured issuer secret
  and adopts it — restarts continue the on-disk chain instead of silently
  starting from genesis. Fail-closed: an unverifiable chain refuses startup
  (H-6: a torn tail is indistinguishable from tampering; no auto-quarantine).
  Regression: `tests/test_audit_recovery_rs.rs`.
- **External alert delivery** (M-B, G2/R2): new `alert_sink` module — RFC 5424
  syslog over UDP. When `SAACP_ALERT_SYSLOG=<host:port>` is set, every
  `SecurityAlert` is forwarded best-effort; failures increment
  `saacp_security_events_total{event="alert_sink_failures_total"}`. Payloads
  carry only the coarse `/api/alerts` fields (CRIT-10 preserved). Sink tests
  cover RFC 5424 shape, SD escaping, real loopback delivery, timestamp edges.
- **Seed/pin mismatch warning** (M-I, R11): configuring peer pins without
  `SAACP_SERVER_SEED_FILE` now prints a loud startup warning (ephemeral seed
  invalidates pins at restart). Regression-tested in the sidecar binary.

### Changed
- **Demo telemetry is opt-in** (M-G, R7/G6 — BREAKING for demo users): the
  command center's demo daemon + synthetic activity generator are now disabled
  by default; enable with `SAACP_DEMO_MODE=1` or
  `[command_center] demo_mode = true`. `SAACP_DISABLE_DEMO_DAEMON=1` still
  forces off and wins over the opt-in. Regression-tested in the binary.
- **Bounded SessionAffinityTracker** (M-D, G4/R4): capped at 100k entries with
  FIFO eviction (was unbounded growth for process lifetime). Evicted sessions
  lose violation memory — documented tradeoff.
- **Bounded InMemoryBackend** (M-D, G4/R4): new-key inserts capped at 100k
  entries with FIFO eviction of live entries, stale-skip for
  deleted/expired entries, and amortized queue compaction. Eviction direction
  is fail-safe (loosens enforcement memory, never forges it).
- **Bounded gossip send path** (M-E, G5/R5): `StaticPeerListTransport` now
  sends through a fixed 4-worker pool with a 1024-slot queue instead of one
  detached thread per send (unbounded thread creation under a revocation
  storm). Dropped sends and failed connects/writes are counted as
  `saacp_security_events_total{event="gossip_send_failures_total"}`.
- **Docker image** (M-C, G3 partial): `health-endpoint` feature now compiled
  into the shipped binaries so orchestrators can use the daemon health/metrics
  server. `redis-backend` deliberately still absent (no binary wiring yet).

### Fixed
- **Gate 1.5 chain-drift tracking ignored per-tenant contexts** (Longcat Gap B
  completion): the unfinished `gate_1_5_reinforcement_with_ctx` variant took
  `ctx` but hardcoded `IntentDriftTracker::global()`, so hermetic per-tenant
  drift isolation never happened (and the unused parameter tripped rustc
  warnings). The body now tracks on `ctx.intent_drift` (aliases the global for
  the shared default — behavior-identical there), and the pipeline passes its
  context. Regression: `gate_1_5_drift_isolation_per_context`.
- **cp1252 mojibake repaired across the Phase-4 clock modules** (Longcat
  re-verification Step 1): an editor had double-encoded UTF-8 as cp1252, so
  em-dashes/box-drawing/arrows in comments AND user-facing `SAACPHardDrop`
  message strings in the eight clock-refactor modules were corrupted
  (`â€""`-style). Repaired by the exact inverse transform; new
  `tests/test_no_mojibake_rs.rs` guard fails if any artifact character
  reappears.

## [0.2.0] - 2026-09-06

### Added
- **Scoped binary configuration** (`SaacpConfig`, `src/config.rs`): optional
  TOML file for `saacp-sidecar` / `saacp-command-center` via `SAACP_CONFIG`
  (`[sidecar]` / `[command_center]` sections), validated once before any bind;
  env vars override file values and unset env = byte-identical pre-file
  behavior. Raw secrets have no field in the schema — only `*_file` paths —
  preserving the S-8 `_FILE` indirection; the resolved posture is dumped once
  at startup. Library APIs unchanged.
- **`compose.yaml` sample deployment**: both binaries from the
  distroless-nonroot Dockerfile with `/healthz` + `/readyz` probe guidance and
  secret `*_FILE` mounts.
- **README release runbook** (v0.2.0 sign-off steps) and file-based
  configuration section.
- **R9 — revocation-convergence lag metric** (Phase 4): an accepted
  (verified + stored) gossip revocation refreshes a last-received timestamp;
  `saacp_revocation_lag_seconds` (now − last-received, 0 = none received yet)
  renders on `/metrics` with a documented alert threshold (sustained > 300s
  in a gossiped fleet = propagation stalled). Regression-tested in
  `gossip.rs`'s unit tests.
- **R9 — optional bounded gossip retry**: `GOSSIP_SEND_RETRIES` (default `0`
  = fire-and-forget preserved byte-for-byte) + `GOSSIP_RETRY_DELAY_MS`
  (100ms). Raising it re-sends each fanout payload once; the ack-less
  transport seam makes this an at-least-once redelivery, safe under
  receiver-side SeenSet dedup. Gossip send path only.
- **Clock abstraction** (finding I, Phase 4): new `src/clock.rs` with the
  `Clock` trait + `SystemClock` default impl; the eight duplicated
  `now_secs()` helpers (`aca.rs`, `cscs.rs`, `identity_binding.rs`,
  `ievl.rs`, `memory.rs`, `security.rs`, `temporal.rs`, `trust_decay.rs`)
  now delegate to it. Pure refactor — zero behavior change, zero wire
  change, zero test-expectation change.

### Changed
- **M11 hardening — affinity-violation enforcement policy** (Phase 3):
  `session_affinity::AffinityViolationPolicy` (`AlertOnly` default =
  byte-identical to prior behavior; `HardDrop` = fail closed) selectable via
  `SAACPNetworkDaemon::affinity_violation_policy` (TCP, WS, and TLS daemons),
  plus `with_affinity_tracker(node_id, tracker)` for shared-tracker fleets.
  Violations are now counted in the new `session_affinity_violations_total`
  telemetry counter and alerted (gate `session_affinity`) under BOTH
  policies. Regression-tested in `tests/test_session_affinity_policy_rs.rs`.
- **Session-affinity health on `/readyz`** (Phase 3):
  `session_affinity: { tracked, violations }`.
- **Audit-chain node designation** (R8 / finding H, Phase 3): `SAACP_AUDIT_NODE=1`
  env var or `SAACPNetworkDaemon::audit_node(bool)`; one-time startup log,
  `saacp_audit_chain_designated_node` Prometheus gauge, and `audit_chain_role`
  on `/healthz`. Visibility only — no consensus logic (documented scope).
- **Operator audit-ack endpoint** (Phase 3): `POST /api/audit/ack` on the
  health router, ALWAYS bearer-gated (503 when no token is configured),
  wrapping `ImmutableAuditLog::acknowledge_dropped_audits()`; the
  acknowledgement is appended to the audit chain (HMAC-bound with the
  daemon's issuer secret) and a `SecurityAlert` recorded. Fail-closed
  semantics untouched. Regression-tested in
  `tests/test_audit_ack_endpoint_rs.rs` (`health-endpoint` feature).
- **Deployment guide** (Phase 3): new README section covering required LB
  affinity config (`ip_hash` / L4 `sourceIP` / k8s `sessionAffinity: ClientIP`),
  the `HardDrop` fleet posture, affinity health on `/readyz`, and audit-node
  designation.

- **Affinity metric renamed for Prometheus counter convention**:
  `saacp_security_events_total{event="session_affinity_violations"}` →
  `event="session_affinity_violations_total"` (matching the sibling
  `rulepack_*_total` label values); the telemetry snapshot key and
  `/readyz` read path renamed to match. Alert-rule expressions in the README
  updated.

### Changed
- **Pinned CI toolchain** (audit G7): every non-nightly CI job now runs
  `1.96.0` — the same version as `rust-toolchain.toml` — instead of a moving
  `stable`, so a fresh stable release shipping a new lint can no longer break
  `-D warnings` CI with no local repro. Nightly fuzz jobs remain on nightly
  (cargo-fuzz requires it).

### Changed
- **MSRV declared** (audit G7): `Cargo.toml` now declares
  `rust-version = "1.96.0"`, resolving the previous "intentionally not
  declared" TODO. Verified empirically: `cargo clippy --all-targets` (default
  and feature matrices) fires no `clippy::incompatible_msrv` at this floor.
- **SECURITY.md supported-versions table** (audit G6): updated to list 0.2.x
  as supported (0.1.x marked superseded); previously still listed only 0.1.x.
- **deny.toml exception review policy** (audit R7): every duplicate-version
  `skip` entry now carries a dated (`reviewed: 2026-09-05`) justification and
  a quarterly re-review requirement, with the EOL `rustls 0.21` entry flagged
  as the highest-priority re-check.

### Fixed
- **`saacp-sidecar` binary did not compile** (audit G1/R1): missing
  `use sha2::Digest;` in `src/bin/saacp_sidecar.rs`.
- **`tests/test_sidecar_rs.rs` did not compile** (audit G1): 4 stale
  `SidecarConnectionPool::send()` call sites migrated to the 14-argument
  signature (handshake mode + pinned-vk parameters from the R1 hardening).
- **Dockerfile could not build** (audit G6/R1): builder image was
  `rust:1.79`, below the crate's real language-feature floor (1.80+); bumped
  to `rust:1.96-slim-bookworm` matching `rust-toolchain.toml`, and dropped
  the unused `libssl-dev` build dep (all TLS paths are rustls; `cargo tree
  -i openssl -e normal` resolves to nothing for the release bins).
- **`cargo fmt --check` failed at HEAD** (audit G7): 7 pre-existing rustfmt
  violations across `src/bin/saacp_sidecar.rs`, `src/daemon.rs`,
  `src/sidecar.rs`, and the sidecar tests, all in the R1 handshake-hardening
  code; repo is now fmt-clean.
- **Fuzz CI silently swallowed every finding** (audit G7): the fuzz job's
  `|| true` made crashes non-blocking. PR/push CI now runs a blocking
  10s/target smoke pass over all 5 fuzz targets; a new `fuzz-nightly` job
  (cron + manual dispatch) does the 30s/target deep pass and uploads crash
  artifacts.

- **CI pipeline** (`.github/workflows/ci.yml`): full feature-matrix CI running
  `fmt --check`, `clippy -D warnings`, `test`, `cargo deny check` across 12
  feature combinations (default, sidecar, command-center, transport-ws/tls/wss,
  redis-backend, hrt-aws-kms, hrt-gcp-kms, hrt-pkcs11, mpf, all-features).
  This is the single highest-leverage change from the security audit — it
  protects ~80 catalogued security fixes from silent regression.
- **Fuzz job** (nightly, weekly schedule): time-boxed `cargo fuzz run` for all
  5 fuzz targets with committed seed corpus and artifact upload on crash.
- **SECURITY.md**: vulnerability disclosure policy with scope, reporting
  process, and fix commitments.
- **CHANGELOG.md** (this file).

### Security
- **M1 / R1 — sidecar authenticated handshake (active-MITM closure)**: the
  sidecar's outbound (and inbound) ECDH handshakes are now posture-controlled
  via `SidecarHandshakeMode`. The library default stays `LegacyOnly`
  (byte-identical v1 wire compat); the `saacp-sidecar` binary defaults to
  `PREFER_PINNED` and accepts `SAACP_HANDSHAKE_MODE=REQUIRE_PINNED` for the
  production posture, per-peer Ed25519 pins via `SAACP_PEER_PINS_FILE`, and a
  stable server identity via `SAACP_SERVER_SEED_FILE`. A wrong pin is rejected
  (never downgraded silently), `REQUIRE_PINNED` refuses plain peers and fails
  startup without a seed, `PREFER_PINNED` downgrades only with a loud WARN,
  and all three outcomes are visible on `/healthz` (`handshake_pinned_ok` /
  `handshake_fallback_total` / `handshake_reject_total`). Regression-tested in
  `tests/test_sidecar_mitm_rs.rs`.
- **M10 / R6 — default full-body scan for irreversible actions**: 
  `FULL_SCAN_FOR_IRREVERSIBLE` now defaults to **on**. `GateTier::Full`
  (IRREVERSIBLE / EXTERNAL_INPUT) payloads are normalized over their entire
  body (time-budgeted, tail-guaranteed), closing the documented >32KB
  interior-scan gap for the tier where an injected instruction does the most
  damage. Measured cost stays the already-bounded ~2x on >16KB payloads
  (benchmark_results.md §P-4); `set_full_scan_irreversible(false)` restores
  the old posture.
- **M8 / R4 — Gate 4.0 corroboration policy**: the packet rejection behavior
  is unchanged for every action class, but the trust penalty is decoupled
  from the heuristic's false-positive rate. READ_ONLY agents get one
  uncorroborated grace hit per 300s window (counted as the new
  `injection_suspected` metric, alerted as before, but costing no trust); a
  second detection inside the window — or any detection on a
  mutation/irreversible class — applies `PenaltyKind::InjectionAttempt` as
  before. Three benign-sounding false positives can no longer eject an agent
  on their own. Regression-tested in `tests/test_m8_injection_corroboration_rs.rs`.
- **M6 / R13**: Added `overflow-checks = true` to `[profile.release]` in
  `Cargo.toml`. Without this, release builds silently wrapped on integer
  overflow while debug/test builds panicked — giving parser arithmetic
  different semantics in production than in the test suite. Every
  `payload_length: u32`, `psn: u64`, hop counter, and trust/telemetry
  accumulator is attacker-influenced; this makes release fail closed
  (panic → connection-scoped unwind) instead of computing wrong bounds.
  Cost is negligible: AES-GCM and Ed25519 dominate every measured path, and
  code that genuinely wants wrapping already uses `wrapping_*`.

## [0.1.0-beta2] - 2026-08-26

### Added
- **Phase 4**: De-globalized pipeline into `SaacpContext` — trust, telemetry,
  alerts, rulepacks, streams, and audit state are now injectable per-context
  instead of being global singletons.
- **Phase 3**: Scoped-out features C1-C5 completed.
- **Phase 2**: Security remediations S2-S10 including S1 session-table DoS
  fix, S7 cluster auto-start, F6b faitf overflow fixes.
- **Phase 1**: All concrete bugs and LOW findings (F6-F12) fixed.
- **Phase 0**: Clippy-clean baseline and WAL reset race fix (Windows
  unlinked-handle).
- **Hardware Root of Trust**: PKCS#11, AWS KMS, and GCP KMS backends for
  hardware-backed signing keys.
- **Clustering**: Active-active cluster membership with deterministic
  leadership and pluggable state backend.
- **Redis backend**: Shared rate-limiter/session/stream state across
  horizontally-scaled gateway nodes.
- **Command Center**: REST + SSE dashboard backend for live security telemetry.
- **Python sidecar**: `saacp.wrap()` one-liner for Python/HTTP-capable agents.
- **WebSocket transport**: `transport-ws` and `transport-wss` features for
  HTTP-only corporate proxies.
- **Metadata Privacy Filter**: Cover traffic, adaptive padding, and timing
  jitter for traffic-analysis resistance.
- **Immutable audit log**: HMAC-authenticated hash chain with WAL backpressure
  coupling.
- **56 adversarial test files** covering exploit scenarios, red-team simulations,
  black-hat agent hijacking, state DoS, and more.
- **5 fuzz targets**: MEASC frame parsing, SAACPFrame header parsing, capability
  token deserialization, injection scanner bypass, and raw gate pipeline.

### Security
- F1-F5 security audit remediations landed.
- `#![forbid(unsafe_code)]` enforced crate-wide.
- Constant-time comparisons via `subtle` crate.
- Comprehensive `zeroize` usage for key material.
- Per-frame AES-256-GCM with HKDF-SHA256 key evolution.
- Ed25519 signatures with X25519 ECDH and contributory checks.

### Known Limitations
See [opusreview.md](opusreview.md) for comprehensive gap analysis and prioritized
mitigation strategies (M1-M24). Key items:
- R1: Sidecar handshake lacks server authentication (MITM vulnerable)
- R2: Pre-authentication 10 MB allocation from unauthenticated header
- R11: No CI (addressed in this release)
- R13: Release-mode integer overflow wraps (addressed in this release)

[unreleased]: https://github.com/saacp/saacp-rs/compare/v0.1.0-beta2...HEAD
[0.1.0-beta2]: https://github.com/saacp/saacp-rs/releases/tag/v0.1.0-beta2
