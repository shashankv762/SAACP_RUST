# Changelog

All notable changes to the SAACP Rust implementation will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
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
