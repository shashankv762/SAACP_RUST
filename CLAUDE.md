# saacp-rs — Claude Code Session Guide

## Project Identity

**saacp-rs** is the production Rust implementation of SAACP (Secure Autonomous Agent Communication Protocol) v0.1-beta2. It provides full feature parity with the Python reference in `C:\Users\2025\qoder SAACP\SAACP\src\saacp\`.

- Crate: `saacp` (library only — no binary)
- Rust edition: 2021
- Test count: **1283** with default features (all must pass; zero failures tolerated). +2 with `--features transport-ws` (`tests/test_transport_ws_rs.rs`, gated via `required-features`).
- Spec reference: `c:\Users\2025\Downloads\write_readme.py` — the authoritative SAACP v0.1-beta2 specification

## Build & Test

```sh
cargo check          # fast type-check, no linking
cargo build          # debug build — must produce ZERO warnings
cargo test           # run the default-feature test suite (must pass 100%)
cargo test --test <name>   # run a single integration test file
cargo clippy --all-targets --features redis-backend,transport-ws -- -D warnings  # full lint gate, all optional code paths
```

**Target**: `cargo test` must print only `test result: ok` lines. Any `FAILED` is a blocker. `cargo build` must emit zero warnings. This must also hold with every optional feature enabled (`--features redis-backend,transport-ws`) — those are additive, not alternate, code paths.

**Known flaky test (pre-existing, not a regression target):** `blackhat_7d_easi_correct_vs_wrong_key_timing_similar` (`tests/test_blackhat_wire_crypto_rs.rs`) asserts a <5µs wall-clock timing difference over 1000 iterations; under heavy parallel test-suite CPU contention it can occasionally exceed that budget. Re-running it in isolation (`cargo test --test test_blackhat_wire_crypto_rs blackhat_7d_...`) reliably passes. Don't "fix" this by touching `easi.rs` — it's a test-harness timing-noise issue, not a side-channel regression.

## Optional Cargo Features

Both are off by default so a single-node, TCP-only deployment pulls in zero extra dependencies.

| Feature | Adds | Module |
|---------|------|--------|
| `transport-ws` | `tokio-tungstenite`, `bytes`, `futures-util` | `transport::ws` — tunnels SAACP MEASC frames inside WebSocket binary messages, addressing the "every LLM framework speaks HTTP/WS, not raw TCP" ecosystem-isolation gap. `SAACPWebSocketDaemon` mirrors `daemon::SAACPNetworkDaemon`'s shape. `daemon::handle_client`/`ecdh_handshake` are generic over `AsyncRead + AsyncWrite`, so the WS path reuses the exact same handshake/framing/gate-pipeline code as raw TCP — zero protocol duplication. |
| `redis-backend` | `redis` (sync client) | `state_backend::RedisBackend` — see below. |

## Distributed State (`state_backend.rs`)

A single narrow `StateBackend` trait (`get`/`set`/`delete`/`incr`/`scan_prefix`, KV+TTL semantics) lets subsystems share state across a horizontally-scaled fleet of SAACP gateway nodes instead of each node holding an isolated in-memory view. `InMemoryBackend` (default, always available) is byte-for-byte equivalent to the pre-existing per-subsystem `HashMap`; `RedisBackend` (behind `redis-backend`) wraps the synchronous `redis` crate client (deliberately not the async client bridged via `block_on` — that risks deadlocking inside `tokio::task::spawn_blocking` gate-pipeline work).

**Wired** (`with_backend(Arc<dyn StateBackend>)` constructor added; default `::new()`/`::global()` path untouched and still purely in-process):
- `memory.rs::FederatedMemory`
- `temporal.rs::DeadMansSwitch` (`with_backend_and_limits` for custom timeout/cap)
- `streaming.rs::StreamRegistry`

**Deliberately NOT wired** — see `state_backend.rs`'s module doc for full justification of each:
- `measc.rs::ReplayWindow` — per-packet atomic bitmap check-and-mark (C-1 REPLAY-TOCTOU fix); a network round-trip here would be a throughput and correctness regression. Never distribute this.
- `cscs.rs::CSCSLoopDetector` — Gate 12.0 runs on essentially every packet (confirmed by reading the `handler.rs` call site, not assumed); naive per-packet backend round-trips would be a real latency bug. Needs the same local-cache-authoritative / best-effort-backend-mirror design as the rate limiter below, not implemented yet.
- `gateway.rs::AgentRateLimiter` / `RRBCGateway` — near-per-packet hot paths; a correct implementation needs the in-process map to stay the authoritative fast-path read with only best-effort write-behind for cross-node visibility. RRBC replay-safety across nodes specifically needs a synchronous atomic claim (`SET NX EX`), not read-through caching.
- `security.rs::ImmutableAuditLog` — hash-chain with a strict prev-hash ordering dependency; use a single-authoritative-audit-node deployment pattern (ops decision), not a code change. Do not build consensus from scratch for this.

## Gate 6.0 Backpressure Contract (`security.rs`)

Any gate that touches disk, does unbounded-size work, or depends on external system throughput must declare an explicit backpressure contract with the packet pipeline instead of an ad-hoc drop-and-print. For the audit log (Gate 6.0 / WAL writer), that contract is `security::AuditHealth`:

| State | Trigger | Effect |
|-------|---------|--------|
| `Healthy` | WAL queue < 70% capacity | Normal async enqueue. |
| `Degraded` | WAL queue 70–95% capacity | Still enqueuing/writing, but behind. |
| `Saturated` | WAL queue > 95% capacity | New events dropped (`dropped_audit_count()`), never an inline `eprintln!` on the hot path. `handler::gate_2_5_kinetic_firewall` rejects new IRREVERSIBLE_ACTION (`action_class >= 2`) packets with `SAACPBytecodes::AuditSubsystemDegraded` once health reaches this state — fail-safe, not fail-open. READ_ONLY/REVERSIBLE packets are unaffected. |
| `Fatal` | The WAL worker's log file failed to open, or an in-flight write returned an OS error (`wal_write_failure_count()`) | Sticky — only constructing a fresh `ImmutableAuditLog` clears it. Distinguishable from `Saturated`: this means the writer tried and failed, not merely that it's behind. Also gates IRREVERSIBLE_ACTION via Gate 2.5. |

The WAL worker (`WalWriter` in `security.rs`) holds a persistent `BufWriter<File>` for its lifetime instead of reopening the file per event (the original root cause of a measured latency spike on Windows, where per-syscall kernel filter-driver/AV overhead dominates). It flushes + `sync_data()`s at most every `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES` (200) entries or `AUDIT_WAL_FLUSH_INTERVAL_MS` (50ms), whichever comes first — that pair is the **stated maximum audit-data-loss window on an unclean shutdown** (power loss, `kill -9`): at most 200 entries or 50ms of audit history. The sentinel/count file is batched into the same flush boundary (previously it was rewritten via its own open+write+close on every single event — an unnoticed second instance of the same root-cause bug).

This does not reorder the gate pipeline: Gate 2.5 still runs at its existing position (step 7), well before Gate 6.0 itself (step 13) — it only reads Gate 6.0's live health signal.

## Architecture: Source Modules

| Module | Purpose | Python parity |
|--------|---------|--------------|
| `errors.rs` | `SAACPBytecodes` enum (0x00–0x41) + `SAACPHardDrop` | `errors.py` |
| `framing.rs` | `SAACPFrame` (101B app-layer) + `MEASCFrame` (128B transport) | `framing.py` |
| `measc.rs` | `MEASCFrame::build_frame/parse_frame` with AES-256-GCM + HKDF key evolution | `measc.py` |
| `easi.rs` | EASI context-ref-ID encryption (HKDF-SHA256 XOR pad, GAP-9/M-2 fix) | *new in Rust* |
| `handler.rs` | `SAACPProtocolHandler` — full 12-gate pipeline + stream handlers | `handler.py` |
| `gateway.rs` | `ZeroTrustGateway`, `AgentRateLimiter` (global singleton), `RRBCGateway` | `gateway.py` |
| `aegf.rs` | `AEGFGovernor`, `ExecutionStateMachine`, `DistributedExecutionGraph` | `aegf.py` |
| `cscs.rs` | `CSCSLoopDetector` — oscillation + DAEG cycle detection | `cscs.py` |
| `schemas.rs` | `PreCompiledSchemas` — JSON schema validation (IDs 0–9) | `schemas.py` |
| `security.rs` | `ImmutableAuditLog` (hash-chained, WAL thread), `NonceTracker` | `security.py` |
| `memory.rs` | `FederatedMemory`, `SecureContextStore` (AES-256-GCM SCR) | `memory.py` |
| `temporal.rs` | `DeadMansSwitch`, `TemporalHeartbeat` | `temporal.py` |
| `streaming.rs` | `StreamRegistry`, `StreamSession` | `streaming.py` |
| `acsvaf.rs` | Capability signing/verification (Ed25519), MAX_DELEGATION_DEPTH=**3** | `acsvaf.py` |
| `acsvaf_audit.rs` | Capability audit log | `acsvaf_audit.py` |
| `acsvaf_authority.rs` | Issuance/verification authority classes (C-2 fix) | `acsvaf_authority.py` |
| `factf.rs` | `ThresholdAuthorityIssuer` M-of-N quorum, transparency log | `factf.py` |
| `faitf.rs` | Agent identity, trust store, DRI, federation | `faitf.py` |
| `faitf_audit.rs` | FAITF audit log | `faitf_audit.py` |
| `pecf.rs` | `PECFFilter`, `SREL` (50ms floor), `SecureDiagnosticLedger`, 64-byte wire | `pecf.py` |
| `error_confidentiality.rs` | `make_opaque_error`, `WireErrorResponse` (44-byte fixed) | `error_confidentiality.py` |
| `klms.rs` | Key lifecycle management, rotation, revocation | `klms.py` |
| `hth.rs` | Handshake transcript binding | `hth.py` |
| `identity_binding.rs` | C-3 identity gate + session registry | `identity_binding.py` |
| `crypto_governance.rs` | Suite governance, `NegotiationTranscript`, `SuiteNegotiator` | `crypto_governance.py` |
| `cryptosuite.rs` | Ed25519 suite registration | `cryptosuite.py` |
| `pool.rs` | Connection pool / pinned sessions | `pool.py` |
| `estimator.rs` | `AutonomousTokenEstimator` | `estimator.py` |
| `rgc.rs` | Resource governance policy + `ExecutionBudgetGuard` (30s ceiling) | `rgc.py` |
| `mpf.rs` | Metadata privacy (padding, cover traffic, jitter) | `mpf.py` |
| `daemon.rs` | `SAACPNetworkDaemon` — async Tokio TCP server; `handle_client`/`ecdh_handshake` generic over `AsyncRead + AsyncWrite` | `daemon.py` |
| `telemetry.rs` | `TelemetryCollector`, Prometheus-format metrics rendering | *new in Rust* |
| `transport.rs` / `transport/ws.rs` | `SAACPWebSocketDaemon`, `WsByteStream` — WebSocket tunnel for MEASC frames (`transport-ws` feature) | *new in Rust* |
| `state_backend.rs` | `StateBackend` trait, `InMemoryBackend`, `RedisBackend` (`redis-backend` feature) — pluggable KV+TTL storage for horizontal scaling | *new in Rust* |

## Gate Pipeline (Authorization Invariance)

The 12-gate security pipeline in `handler.rs::_intercept_packet_inner()` **must execute on every packet** regardless of tier. Gate order is a protocol invariant — reordering is a security bug.

| Step | Gate | Implementation |
|------|------|---------------|
| 1 | Gate 0: Crypto integrity | `MEASCFrame::parse_header()` → AES-GCM tag |
| 2 | Stream fast-path | `handle_stream_continuation` / `handle_stream_end` |
| 3 | Schema 0 block | Reject raw-binary schema before cover-traffic check |
| 4 | Cover traffic | `AgentRateLimiter::record_cover_traffic()` + audit entry + silent drop |
| 5 | Context state validation | `FederatedMemory::fetch_context()` + `DeadMansSwitch::ping()` |
| 6 | Gate 1.0: Token validation | `ZeroTrustGateway::validate_lateral_movement()` |
| 7 | Gate 2.5: Kinetic firewall | `gate_2_5_kinetic_firewall()` |
| 8 | Gate 1.5: Intent envelope | `enforce_root_intent()` |
| 9 | Gate 0.5: Financial CB | `gate_financial_cb()` (concurrent with 3.0/4.0/5.0) |
| 10 | Gate 3.0: Lateral movement | `gate_3_0_lateral_movement()` |
| 11 | Gate 4.0: Injection scan | `PromptInjectionScanner::scan_payload()` |
| 12 | Gate 5.0: Epistemic CB | `gate_5_0_epistemic_cb(schema_id: u16)` (schema_id == 3 only — u16, NOT u8) |
| 13 | Gate 6.0: Audit checkpoint | `ImmutableAuditLog::append_event()` |
| 14 | Gate 9.0: Schema validation | `PreCompiledSchemas::validate_payload()` |
| 15 | Gate 11.0: AEGF governance | `GLOBAL_AEGF_GOVERNOR.submit_request()` + immediate complete |
| 16 | Gate 12.0: CSCS loop detect | `GLOBAL_CSCS.cs_detect_loop()` |

**CRITICAL**: Gate 5.0 takes `schema_id: u16`. Never cast to `u8` before passing — schema_id 259 (0x103) would truncate to 3, incorrectly triggering/skipping the epistemic gate.

## Key Security Invariants

### GAP fixes applied (original, still active):

| GAP | Fix | File |
|-----|-----|------|
| GAP-3 | `AgentRateLimiter::global()` singleton always enforces circuit breaker | `gateway.rs`, `handler.rs` |
| GAP-9 | EASI encryption of context_ref_id via HKDF-SHA256 keystream | `easi.rs`, `measc.rs` |
| GAP-10 | `record_error()` always called on `SAACPHardDrop` via global rate limiter | `handler.rs` |
| GAP-11 | STREAM_START token extraction → `StreamRegistry::set_stream_token_info()` | `handler.rs` |
| Gate 11.0 | AEGF governance wired with `GLOBAL_AEGF_GOVERNOR` (was stub) | `handler.rs` |
| Gate 12.0 | CSCS loop detection wired with `GLOBAL_CSCS` (was stub) | `handler.rs` |

### Security vulnerability fixes (audit session):

| ID | Severity | Fix | File |
|----|----------|-----|------|
| RRBC-TRUNC | CRITICAL | RRBC HMAC truncated comparison → full-length + `constant_time_eq` | `gateway.rs:851` |
| CT-EQ | CRITICAL | `constant_time_eq_u32` `(a^b)==0` optimizable → byte-loop XOR | `framing.rs:706` |
| SCHEMA-TRUNC | CRITICAL | `schema_id as u8` in epistemic gate → `u16` param, no cast | `handler.rs` |
| MAC-PRIV-ESC | CRITICAL | `max_action_class as u8` silent truncation → reject > 255 | `gateway.rs:584` |
| CT-HMAC | HIGH | Non-constant-time HMAC chain comparison → `constant_time_eq_hex()` | `security.rs` |
| PANIC-ED25519 | HIGH | `.unwrap()` on `try_into()` in Ed25519 path → `.map_err(...)` | `gateway.rs` |
| JSON-LEN | HIGH | `token_json.len() as u32` truncation → `u32::try_from()` | `gateway.rs` |
| NULL-BYTE | HIGH | Null bytes accepted in agent IDs → `contains('\0')` reject | `gateway.rs:330` |
| VERSION-TRUNC | MEDIUM | `version as u32` silent truncation → `u32::try_from().map_err()` | `memory.rs:364` |
| CSCS-FINGERPRINT | CRITICAL | CSCS fingerprint included `rid` (forgeable) → uses `oaid+cid+action_class+hc` | `cscs.rs` |
| COVER-AUDIT | HIGH | Cover traffic left no audit trace → Gate 6.0 entry written before drop | `handler.rs` |
| GW-FALLBACK | HIGH | `gateway=None` fallback gave max_action_class=2 (IRREVERSIBLE) → 0 (READ_ONLY) | `handler.rs` |
| STREAM-REVOKE | HIGH | Stream continuation revocation missing → falls back to `ZeroTrustGateway::global()` | `handler.rs` |
| WAL-BLIND | HIGH | WAL open/write errors silently swallowed (`let _ = ...`), no signal when the audit subsystem stops writing → propagated errors set sticky `AuditHealth::Fatal` + one-time `eprintln!` | `security.rs` |
| WAL-IRREV-UNAUDITED | HIGH | IRREVERSIBLE_ACTION packets could be authorized while Gate 6.0 was saturated/blind, with no durable audit trail → Gate 2.5 rejects with `SAACPBytecodes::AuditSubsystemDegraded` when `AuditHealth >= Saturated` | `handler.rs`, `security.rs` |

### Spec alignment fixes (write_readme.py audit):

| Gap | Spec §| Fix | File |
|-----|-------|-----|------|
| `ACSVAF_MAX_DELEGATION_DEPTH = 8` | §5.7: MAX=**3** | Changed constant + updated 5 test files | `acsvaf.rs` |
| `ExecutionBudgetGuard` no ceiling | §12.3: **30s hard ceiling** | `EXECUTION_BUDGET_MAX_SECONDS=30.0`; `new()` rejects >30s | `rgc.rs` |
| RRBC PoP verification absent | §8.2 step 4 | `redeem_token_with_pop()` with Ed25519 PoP | `gateway.rs` |
| PECF correlation_id unchecked | §9.3: exactly **32 hex chars** | `debug_assert_eq!(len, 32)` | `pecf.rs` |
| `SAACP_DEPLOYMENT_PROFILE` env var | Appendix A | `profile_from_env()` reads env at first call | `pecf.rs` |
| `SAACP_AUDIT_LOG` / `SAACP_COUNT_FILE` | Appendix A | `with_default_path()` reads env vars | `security.rs` |
| WAL worker thread missing | §15.2 | `mpsc::sync_channel` cap=100,000 + daemon thread | `security.rs` |
| `verify_chain` no sentinel check | §15.3 | Checks `count_file` sentinel; `verify_chain_disk()` added | `security.rs` |
| No module-load assertions | §4.1 | `const _: () = assert!(...)` for all frame/MEASC sizes | `measc.rs`, `framing.rs` |

### Global singletons (all process-wide, created once):

```rust
AgentRateLimiter::global()          // circuit breaker + cover traffic
ImmutableAuditLog::global()         // hash-chained audit (reads SAACP_AUDIT_LOG env)
FederatedMemory::global()           // context store
DeadMansSwitch::global()            // heartbeat / dead-man
StreamRegistry::global()            // active stream sessions
ZeroTrustGateway::global()          // token registry + revocation fallback
crate::aegf::GLOBAL_DAEG            // distributed execution graph
crate::aegf::GLOBAL_AEGF_GOVERNOR   // AEGF gate 11.0
crate::cscs::GLOBAL_CSCS            // CSCS gate 12.0
```

## Key Protocol Constants

```rust
// MEASC (measc.rs) — spec §4.1
MEASC_REPLAY_WINDOW_SIZE = 4096
MEASC_MAX_PSN_ADVANCE    = 2048          // MUST be < WINDOW_SIZE (const assert)
MEASC_PSN_MAX            = i64::MAX as u64
MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD = 1_048_576
MEASC_DEFAULT_EPOCH_TIME_SECONDS = 600
MEASC_EPOCH_GRACE_PERIOD_SECONDS = 60
MEASC_REPLAY_ANOMALY_JUMP_THRESHOLD = 512

// ACSVAF (acsvaf.rs) — spec §5.7
ACSVAF_MAX_DELEGATION_DEPTH = 3          // chains > 3 → ACSVAF_DELEGATION_DEPTH_EXCEEDED

// PECF (pecf.rs) — spec §9
SREL_WIRE_RESPONSE_SIZE = 64             // exact wire bytes
SREL_FLOOR_SECONDS      = 0.050          // 50ms minimum rejection delay
PECF_MARKER             = 0xFE           // byte[0] of every wire response
// correlation_id MUST be exactly 32 ASCII hex chars (bytes [2..34])

// RGC (rgc.rs) — spec §12
EXECUTION_BUDGET_MAX_SECONDS = 30.0     // hard ceiling for ExecutionBudgetGuard::new()

// Security (security.rs) — spec §15
AUDIT_WAL_QUEUE_CAPACITY = 100_000      // drop (not reject) if full
AUDIT_MAX_LOG_SIZE       = 50_000_000   // rotate at 50 MB
GENESIS_HASH = "47454e455349535f424c4f434b"  // hex of b"GENESIS_BLOCK"
AUDIT_WAL_FLUSH_EVERY_N_ENTRIES = 200   // flush+sync_data at most every N entries...
AUDIT_WAL_FLUSH_INTERVAL_MS     = 50    // ...or every 50ms, whichever first.
                                         // Max audit data loss on an unclean
                                         // shutdown: 200 entries or 50ms. See
                                         // "Gate 6.0 Backpressure Contract" above.

// Environment variables (Appendix A)
SAACP_DEPLOYMENT_PROFILE  // DEVELOPMENT | STAGING | PRODUCTION (default)
SAACP_AUDIT_LOG           // audit log file path (default: saacp_audit.log)
SAACP_COUNT_FILE          // event count sentinel (default: saacp_event_count.sentinel)
```

## Python Reference

The Python source is at `C:\Users\2025\qoder SAACP\SAACP\src\saacp\`. When adding features or fixing gaps, **always check the Python module first**. The Python implementation is the normative reference for:
- Wire protocol byte offsets
- Gate pipeline order
- Token wire format (4-byte json_len prefix + JSON body + HMAC-32 or Ed25519-64 signature)
- Error codes and their semantics

The spec document at `c:\Users\2025\Downloads\write_readme.py` is the formal written specification. Where the spec document and the Python code differ, the Python code is normative.

## EASI Encryption (GAP-9 / M-2 fix)

Context Ref ID in the MEASC 128-byte transport header (offset 44, 32 bytes) is EASI-encrypted:

```
pad = HKDF-Expand(PRK=traffic_key, info=b"SAACP-EASI-context-ref-v1"||epoch_id_be4||psn_be8, length=32)
wire_bytes = plaintext_ctx_ref_id XOR pad
```

Applied in:
- `measc::MEASCFrame::build_frame()` — encrypt before writing to header
- `measc::MEASCFrame::parse_frame()` — decrypt after AES-GCM auth succeeds (Step 7+)
- `easi.rs` — standalone module with unit tests

## RRBC Proof-of-Possession (spec §8.2 step 4)

When a token is issued with a `pop_key` field (Ed25519 public key in the token JSON), the redeemer must prove possession of the corresponding private key.

```rust
// Standard redemption (no PoP):
rrbc_gateway.redeem_token(token_b64, rnonce, agent, sid, cid, oaid, secret)

// With PoP: pop_proof = Ed25519.sign(private_key, rnonce.as_bytes())
rrbc_gateway.redeem_token_with_pop(token_b64, rnonce, agent, sid, cid, oaid, secret, Some(pop_proof))
```

## Test Files

| File | Tests | Coverage |
|------|-------|---------|
| `tests/test_gate_pipeline.rs` | 44 | Full gate pipeline, tiers, injection, epistemic (schema_id u16), intent |
| `tests/test_measc_rs.rs` | ~322 | ReplayWindow, epochs, key evolution, PSK recovery |
| `tests/test_redteam.rs` | 43 | Exploit scenarios, confusable Unicode, token attacks |
| `tests/test_security_attacks_rs.rs` | 43 | Protocol-level: replay, circuit breaker, injection |
| `tests/test_authorization_invariance_rs.rs` | 24 | Auth invariance, tier bypass attempts |
| `tests/test_stream_security_rs.rs` | 28 | Stream lifecycle, gates on continuations |
| `tests/test_aegf_full_rs.rs` | 40 | DEG, ESM, hop limits, cycle detection |
| `tests/test_acsvaf_rs.rs` | 34 | Token issuance, verification, expiry, revocation, depth=3 max |
| `tests/test_acsvaf_redteam_rs.rs` | 25 | Forgery, delegation attacks, scope escalation |
| `tests/test_factf_rs.rs` | 35 | M-of-N quorum, transparency log, delegation chain |
| `tests/test_faitf_rs.rs` | 34 | Identity, trust store, DRI, federation |
| `tests/test_pecf_rs.rs` | 43 | PECF filter, SREL timing, 64-byte wire, 32-char correlation_id |
| `tests/test_hth_rs.rs` | 23 | Transcript binding, session registry |
| `tests/test_klms_rs.rs` | 33 | Key lifecycle, rotation, revocation |
| `tests/test_error_confidentiality_rs.rs` | 28 | Opaque errors, fixed-size wire response |
| `tests/test_c2_authority_separation_rs.rs` | 22 | Issuance/verification authority separation |
| `tests/test_c3_identity_binding_rs.rs` | 18 | C-3 identity gate, session fixation prevention |
| `tests/test_realworld_rs.rs` | 16 | Multi-agent orchestration, PSK recovery |
| `tests/test_wire_format_rs.rs` | 18 | Wire byte offsets, EASI on wire, roundtrip |
| `tests/integration_tests.rs` | 22 | End-to-end full packet build/intercept, constant checks |
| `tests/test_exploit_vulnerabilities_rs.rs` | 39 | Exploit regression tests (all VULN-* IDs) |
| `tests/test_advanced_redteam_rs.rs` | 59 | Advanced red-team scenarios |
| `tests/test_production_redteam_rs.rs` | 43 | Production protocol survivor tests |
| `tests/test_gate6_backpressure_rs.rs` | 4 | Gate 6.0 WAL backpressure: saturation stress, fatal-open-failure signaling, genuine hard-kill durability-window bound (subprocess re-exec) |

## Common Pitfalls

1. **Gate ordering**: Never reorder the gate pipeline in `_intercept_packet_inner`. It's a security invariant.

2. **`gate_5_0_epistemic_cb` signature**: Takes `schema_id: u16`. **Never cast to `u8` before passing** — schema_id 259 would truncate to 3 and incorrectly trigger/skip the epistemic gate.

3. **`max_action_class` validation**: When parsing from JSON, validate the raw u64 value is ≤ 255 before casting to u8. Values 256–511 can wrap to 0x00–0xFF, creating privilege escalation or denial.

4. **RRBC signature comparison**: Always compare full-length signatures with `constant_time_eq`. Never use `signature[..expected.len()]` — a 1-byte forged signature could match the prefix.

5. **PECF correlation_id**: Must be exactly 32 ASCII hex chars (output of `hex::encode([u8; 16])`). Passing shorter strings to `normalize_response` triggers a `debug_assert` failure.

6. **ACSVAF delegation depth**: `ACSVAF_MAX_DELEGATION_DEPTH = 3` (spec §5.7). Tests that use depth values must stay ≤ 3 to pass; depth 4+ must be rejected.

7. **`ExecutionBudgetGuard::new()`**: Rejects timeout > `EXECUTION_BUDGET_MAX_SECONDS` (30.0). The gate pipeline must always use ≤ 30s.

8. **EASI roundtrip**: `build_frame` encrypts context_ref_id, `parse_frame` decrypts it. Tests checking raw wire bytes at [44..76] must not expect plaintext.

9. **Rate limiter**: Always use `effective_rl` (falls back to `AgentRateLimiter::global()`), never skip the circuit breaker check.

10. **Global singletons**: Test isolation is tricky when globals hold state. Tests that modify global state (audit log, rate limiter, profile) must reset it. Use `#[serial]` for profile-dependent tests.

11. **Constant-time comparisons**: HMAC verification (`constant_time_eq`), chain hash verification (`constant_time_eq_hex`), and Adler32 (`constant_time_eq_u32`) all use branch-resistant comparisons. Do not replace with `==` on secrets.

12. **Cover traffic audit**: Cover traffic packets MUST write a Gate 6.0 audit entry before the silent drop. Removing this creates unlogged reconnaissance vectors.

13. **`ImmutableAuditLog::new(log_file)` sentinel derivation**: The count/sentinel file is derived as `"<log_file>.sentinel"`, NOT the global `AUDIT_COUNT_FILE` default. This was a real bug (fixed in this session): every `new()` instance previously shared one process-wide default sentinel regardless of `log_file`, so unrelated `ImmutableAuditLog` instances (different test files, different production subsystems) clobbered each other's event-count sentinel and caused spurious `verify_chain()` failures. Only `with_default_path()`/`global()` use the env-var-configured shared default — that's intentional (it's the one true global log). Never make `new()` default back to the shared sentinel.

14. **`AuditHealth` is per-instance, not a global static**: `health`/`dropped_audit_count()`/`wal_write_failure_count()` live on each `ImmutableAuditLog` (`Arc`-shared with its own WAL worker thread), deliberately mirroring pitfall #13's per-instance sentinel design — a single process-wide static would let one test's induced WAL failure poison another test's health assertions. `handler::gate_2_5_kinetic_firewall(action_class, max_action_class, audit_log)` reads whichever instance is passed (falling back to `ImmutableAuditLog::global()` on `None`, same pattern as the Gate 6.0 call site itself) — never assume it reads a global.

15. **`AuditHealth::Fatal` is sticky**: Only set by the WAL worker itself (log file open failure, or an in-flight write error) and only cleared by constructing a fresh `ImmutableAuditLog`. The producer-side queue-pressure health update (`fetch_update` in `append_event`) is written to never downgrade a `Fatal` state back to `Healthy`/`Degraded`/`Saturated` — don't "simplify" that into a plain `store()`, it would silently un-blind a broken audit subsystem.
