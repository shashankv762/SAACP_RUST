# saacp-rs — Claude Code Session Guide

## Project Identity

**saacp-rs** is the production Rust implementation of SAACP (Secure Autonomous Agent Communication Protocol) v0.1-beta2. It provides full feature parity with the Python reference in `C:\Users\2025\qoder SAACP\SAACP\src\saacp\`.

- Crate: `saacp` (library, plus one optional binary — `saacp-sidecar`, behind the `sidecar` feature; see "Sidecar Proxy / Python Translation Layer" below)
- Rust edition: 2021
- Test count: **1294** with default features (all must pass; zero failures tolerated) — grown to 1310 by prior-session work already present before this feature (`trust_decay.rs`, `test_blackhat_agent_hijack_rs.rs`, `test_gate5_scope_consistency_rs.rs`) plus this session's `tests/test_daemon_encrypted_rs.rs` (+5). +2 with `--features transport-ws` (`tests/test_transport_ws_rs.rs`, gated via `required-features`). +4 with `--features sidecar` (`tests/test_sidecar_rs.rs`, gated via `required-features`). MPF's own unit/integration tests only compile under `--features mpf` (see "Optional Cargo Features" below) — not counted in the default-feature baseline.
- Spec reference: `c:\Users\2025\Downloads\write_readme.py` — the authoritative SAACP v0.1-beta2 specification

## Build & Test

```sh
cargo check          # fast type-check, no linking
cargo build          # debug build — must produce ZERO warnings
cargo test           # run the default-feature test suite (must pass 100%)
cargo test --test <name>   # run a single integration test file
cargo clippy --all-targets --features redis-backend,transport-ws,mpf -- -D warnings  # full lint gate, all optional code paths
```

**Target**: `cargo test` must print only `test result: ok` lines. Any `FAILED` is a blocker. `cargo build` must emit zero warnings. This must also hold with every optional feature enabled (`--features redis-backend,transport-ws,mpf`) — those are additive, not alternate, code paths. A `[profile.release]` (`lto = "thin"`, `codegen-units = 1`, `opt-level = 3`) is set in `Cargo.toml` — deliberately *not* `panic = "abort"` (this crate runs as a long-lived network daemon with ~70+ internal `.lock().unwrap()` calls; abort-on-panic would turn one attacker-triggered panic in one connection into a full-process crash for every other connection too).

**Known flaky test (pre-existing, not a regression target):** `blackhat_7d_easi_correct_vs_wrong_key_timing_similar` (`tests/test_blackhat_wire_crypto_rs.rs`) asserts a <5µs wall-clock timing difference over 1000 iterations; under heavy parallel test-suite CPU contention it can occasionally exceed that budget. Re-running it in isolation (`cargo test --test test_blackhat_wire_crypto_rs blackhat_7d_...`) reliably passes. Don't "fix" this by touching `easi.rs` — it's a test-harness timing-noise issue, not a side-channel regression.

## Optional Cargo Features

All four are off by default so a single-node, TCP-only deployment pulls in zero extra dependencies — this matters concretely for embedded-Linux-class deployments (Raspberry Pi / OpenWrt-class routers), not just as a nicety.

| Feature | Adds | Module |
|---------|------|--------|
| `transport-ws` | `tokio-tungstenite`, `bytes`, `futures-util` | `transport::ws` — tunnels SAACP MEASC frames inside WebSocket binary messages, addressing the "every LLM framework speaks HTTP/WS, not raw TCP" ecosystem-isolation gap. `SAACPWebSocketDaemon` mirrors `daemon::SAACPNetworkDaemon`'s shape. `daemon::handle_client`/`ecdh_handshake` are generic over `AsyncRead + AsyncWrite`, so the WS path reuses the exact same handshake/framing/gate-pipeline code as raw TCP — zero protocol duplication. |
| `redis-backend` | `redis` (sync client) | `state_backend::RedisBackend` — see below. |
| `mpf` | nothing (pure Rust, no new deps) | `mpf.rs` — cover traffic / adaptive padding / timing jitter for traffic-analysis resistance. **Never wired into the mandatory gate pipeline** (confirmed by grep — this was true before the feature gate existed too; it's opt-in caller-invoked utility code, not a bypassable security control). Demoted to a feature flag because it matters far more for anonymity-network threat models than for AI agent pipelines running inside a controlled infrastructure boundary — the realistic threat here is a compromised agent or insider, not passive traffic analysis on the wire. Off by default so IoT/low-resource builds don't even compile it. |
| `sidecar` | `axum` (HTTP server) | `sidecar.rs` + the `saacp-sidecar` binary (`src/bin/saacp_sidecar.rs`, this crate's first `[[bin]]` target) — see "Sidecar Proxy / Python Translation Layer" below. |

`tokio`'s own feature set is trimmed (not a togglable feature, just a direct dependency choice) from `full` to `["rt", "rt-multi-thread", "net", "io-util", "time", "macros"]` — verified against actual `tokio::` usage across `src/` (only `daemon.rs`/`transport/ws.rs` touch it, via `spawn`/`spawn_blocking`, `TcpListener`, `AsyncRead`/`WriteExt`, and `timeout`). `signal`/`process`/`fs`/`io-std`/`sync` were dead weight. `[dev-dependencies]` still uses `full` since dev-deps never ship to downstream consumers of this library crate.

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

## Trust Decay Engine (`trust_decay.rs`) — *new in Rust, no Python parity*

A sidecar, not a 13th numbered gate — sits outside the numbered 16-step pipeline exactly like the existing `AgentRateLimiter::is_locked()` circuit-breaker check, which is also a pre-gate check outside the numbered list. Gate order remains a protocol invariant; nothing about it changes. Every violation-producing gate reports to it; it never itself decides pass/fail for a gate.

**Why**: every gate makes a binary block/allow decision on one packet in isolation. That leaves a blind spot — an agent that's quietly compromised but still sending individually well-formed packets gets no protocol-level response until a human notices and calls `revoke()`. `TrustDecayEngine` tracks a continuous, decaying *behavioral* trust score per agent (identity trust already came from the handshake/token) and converts sustained low trust into automatic, non-binary effects.

- **Score**: `f64` in `[0.0, 1.0]`, starts at `TRUST_SCORE_INITIAL` (1.0). Recovery is lazy and time-based — computed only when an entry is touched, never via a background thread — so clean traffic adds zero cost beyond the single map lookup already needed for `scope_cap()` (same cost class as the existing rate-limiter check).
- **Penalties** (`PenaltyKind`, weight subtracted, floored at 0): `ReplaySuspicion` 0.40, `IntentDriftCeiling` 0.35, `InjectionAttempt` 0.30, `ScopeViolation` 0.25, `EpistemicOverclaim` 0.20, `GenericHardDrop` 0.05 (the generic catch-all fires unconditionally on every `SAACPHardDrop`, same precedent as `AgentRateLimiter::record_error`; gate-specific penalties are *additional*, never instead of it — a known attack pattern costs more trust than a generic drop).
- **`score < TRUST_DOWNGRADE_THRESHOLD (0.50)`** → `scope_cap()` returns `Some(0)` (READ_ONLY only), intersected into `max_action_class_from_token` **once**, at `handler.rs` where that value is first bound — every downstream gate inherits the downgrade for free.
- **`score < TRUST_REAUTH_THRESHOLD (0.25)`** → `requires_reauth()` true → all non-exempt packets rejected (`SAACPBytecodes::TrustReauthRequired`) until score recovers **and** `TRUST_REAUTH_MIN_COOLDOWN_SECONDS` has elapsed since lockout — closes the "one big penalty, then flood clean traffic to instantly reset" gaming loophole.
- **Honest scope**: this is a v1, time/score-based soft reset, **not** a cryptographic proof-of-rehandshake. The capability token itself is never revoked, only time-boxed. A v2 requiring an actual fresh ECDH/HTH exchange to clear `requires_reauth` early would be a real wire-protocol addition — not built here.
- **Signals**: `subscribe(Arc<dyn Fn(TrustSignal)+Send+Sync>)` for synchronous operator/orchestrator callbacks. `telemetry::wire_trust_decay_metrics()` is an opt-in one-line wiring into `saacp_trust_penalties_total{kind}` / `saacp_trust_downgrades_total` / `saacp_trust_reauth_required_total` / `saacp_trust_agents_tracked` — bounded-cardinality by design (one counter per `PenaltyKind` variant, never a per-agent label).
- **Bounded**: capped at `TRUST_MAX_ENTRIES` with two-pass sweep-on-overflow (drop fully-recovered/unlocked entries first, then oldest-touched-first fallback — the fallback matters because many distinct agents each penalized once and never touched again can't be reclaimed by time-based recovery alone).

**`IntentDriftTracker`** (same file): per-`session_uuid` running total of Gate 1.5 per-hop divergence, bounded the same way, backing the chain-wide ceiling below.

**Wiring** (`handler.rs`, all additive at points already returning `Err`): Gate 3.0 reject → `ScopeViolation`; Gate 4.0 reject → `InjectionAttempt`; PSN/sequence-regression reject in `handle_stream_continuation` → `ReplaySuspicion`; Gate 5.0/5.0b reject → `EpistemicOverclaim`; Gate 1.5/1.5c/chain-drift reject → `IntentDriftCeiling`; any other `SAACPHardDrop` → `GenericHardDrop`.

### Gate 1.5 reinforcement (additive, `handler.rs`)

`enforce_root_intent` (the original Gate 1.5) is left completely unchanged — signature, behavior, all existing tests. Three additive checks run after it, only when `root_intent_hash` is bound, never loosening the base check:

1. **`gate_1_5c_dangerous_action_consistency`** — confused-deputy / intent-padding defense. The base check only enforces a FLOOR on term overlap with the root intent, never a CEILING on unrelated appended terms, so a legitimate-looking prefix can smuggle a high-risk instruction in the tail for free. If the task text contains a `DANGEROUS_ACTION_TERMS` verb absent from the root intent's own vocabulary, reject — relative to the root intent's own words, not a blanket denylist (a data-retention agent whose job is legitimately "delete expired records" isn't penalized for "delete"). Heuristic denylist, not a complete solution; a handful of its terms (`"drop"`, `"format"`, `"transfer"`, `"wire"`, `"disable"`) are common in ordinary business language and carry a real false-positive-rate tradeoff, same class of tradeoff as Gate 4.0's pattern matching.
2. **`gate_1_5_reinforcement`** — per-hop tightening: required overlap increases with `TokenValidationResult::delegation_depth` (an **optional, informational** claim on the general capability-token path — unlike ACSVAF's mandatory one, absent/invalid defaults to 0, no regression for legacy tokens), capped at `INTENT_TIGHTENING_DEPTH_CAP`. The depth-0 baseline is derived from the *same effective ratio* `enforce_root_intent`'s own truncated-integer `required` count produces (`max(1, root_total * INTENT_MIN_OVERLAP) as usize`) — not the raw `INTENT_MIN_OVERLAP` constant directly, which for short root intents would make this reinforcement stricter than the base check even at depth 0 (a real bug caught and fixed during development; the comparison also carries a small epsilon tolerance for the same reason — `1.0 - (1.0 - ratio)` isn't always bit-identical to `ratio`).
3. Same function's **chain-wide cumulative ceiling**: independent of any single hop passing its own check, `IntentDriftTracker::global().accumulate(session_uuid, divergence)` must not exceed `CHAIN_DRIFT_CEILING` — answers "many small, individually-plausible scope-creep hops compounding into something the root task never authorized" (`SAACPBytecodes::IntentChainDriftExceeded`).

Deliberately standalone/directly-testable functions (mirrors `gate_5_0b_scope_consistency`'s shape) rather than inline in `_intercept_packet_inner` — this codebase's established convention for testing Gate-1.5-family logic is calling the gate function directly with a hand-built `payload_dict` (see `tests/test_exploit_vulnerabilities_rs.rs`'s `exploit_intent_*` tests and `tests/test_blackhat_agent_hijack_rs.rs`), **not** routing through a full encrypted MEASC packet. That's a deliberate choice, not a shortcut: `handler::gate_0_crypto_integrity` (`framing::MEASCFrame::parse_header`) parses packet structure only and does not itself perform AES-GCM/EASI decryption (that happens on the separate `measc::MEASCFrame::parse_frame` path) — a packet built via the encrypting `measc::MEASCFrame::build_frame` and fed directly into `intercept_packet_full` never yields a decrypted JSON payload. This was a pre-existing architectural question, orthogonal to Gate 1.5/1.5c/5.0b's own correctness, that no test in this crate had resolved as of when this paragraph was first written (grep confirmed zero tests built a live `_capability_token` payload carrying `root_intent_hash` and routed it through `intercept_packet_full` end-to-end).
>
> **Resolved for the daemon path** (see "Sidecar Proxy / Python Translation Layer" below): `handler::intercept_packet_encrypted` + `gate_0_crypto_integrity_encrypted` give `daemon.rs` (opt-in, via `SAACPNetworkDaemon::with_encrypted_transport`) a genuine `measc::MEASCFrame::build_frame` → real AES-GCM decrypt → gates 1–12 path, and `tests/test_daemon_encrypted_rs.rs` is the first test in this crate to drive that live end-to-end over real TCP. This doesn't change Gate-1.5-family tests' own convention above (hand-built `payload_dict`s remain the right tool for unit-testing one gate function in isolation) — it just means the "does an encrypted packet reach gates 1–12 at all" question this paragraph flagged is no longer unanswered for the daemon's default in-process pipeline.

### Gate 5.0b (additive, `handler.rs`)

`gate_5_0_epistemic_cb` (Gate 5.0) is left untouched. `gate_5_0b_scope_consistency` runs immediately after it, only for `schema_id == 3`: schema 3 ("Epistemic") always carries a `data` field (`schemas.rs`) — the actual claimed content the confidence score vouches for. When a root intent is bound, that claim must stay within it regardless of confidence value — a self-reported float can inflate trust in a claim, but it can never widen the claim's scope beyond what the signed root intent permits. Closes the "fake high confidence bypasses scope" gap: a schema-3 response claiming near-certain confidence for an off-scope `data` claim is now rejected (`tests/test_gate5_scope_consistency_rs.rs`).

## Sidecar Proxy / Python Translation Layer (`sidecar.rs`) — *new in Rust, no Python parity*

Lets a non-Rust agent (Python/LangChain/AutoGen, or anything else that can speak HTTP)
get SAACP's crypto/gate-pipeline guarantees over plain local HTTP/JSON, with **zero**
SAACP protocol knowledge on the caller's side — "secure your agent in one line of code."
Feature-gated (`sidecar`, off by default — see "Optional Cargo Features"), and the first
`[[bin]]` target this otherwise library-only crate has (`saacp-sidecar`,
`src/bin/saacp_sidecar.rs`).

**Why a sidecar, not a PyO3 native binding**: the crate's core (`SessionEpochManager`,
`ZeroTrustGateway`, the 16-gate `SAACPProtocolHandler` pipeline) is a deeply stateful,
session/epoch-oriented protocol library with no stateless `pack()`/`unpack()` facade
anywhere. A PyO3 binding would just relocate that same session/token/frame-ordering
complexity into Python — the opposite of "one line of code" — and would add an ongoing
multi-platform wheel-build burden (maturin/cibuildwheel) this project's own
minimal-dependency, embedded-friendly philosophy argues against. A local sidecar process
that does 100% of the crypto/session/gate work internally and exposes only
`POST /send` / `GET /receive` / `GET /healthz` matches the pitch exactly, and reuses
`daemon.rs`/`handler.rs` almost verbatim — the same low-duplication pattern
`transport::ws` already established for adding a new transport.

**Prerequisite fix (this is why `sidecar.rs` isn't the first thing in this section)**:
before this work, the live TCP daemon path did not actually enforce crypto or
authorization, despite this file's own documentation describing AES-256-GCM +
HMAC-verified tokens — see `DAEMON-NO-AEAD` / `DAEMON-NO-TOKEN-VERIFY` in the GAP-fixes
table below. Building a "secure" sidecar on top of that as-is would have been decorative.
Both gaps are now opt-in-fixed (additive builders on `SAACPNetworkDaemon`, default
behavior byte-for-byte unchanged) before `sidecar.rs` uses them for real.

- **`handler.rs`**: `_intercept_packet_inner` is split into `gate_0_crypto_integrity` (the
  existing structural-only Gate 0, untouched) + a new `run_gates_1_through_12` (everything
  downstream, mechanically extracted, byte-for-byte behavior-neutral — verified by a full
  `cargo test` pass before anything else was added). A new `gate_0_crypto_integrity_encrypted`
  wraps the real, previously-dead-to-the-daemon `measc::MEASCFrame::parse_frame` (genuine
  AES-256-GCM + replay-window enforcement) and feeds the same `ParsedPacket` shape into
  `run_gates_1_through_12`. A new `intercept_packet_encrypted` mirrors
  `intercept_packet_full`'s wrapper (circuit breaker, trust-decay reauth, rate-limiter
  recording, STREAM_START registration) around that encrypted Gate 0. V1 scope limit:
  `STREAM_CONTINUATION`/`STREAM_END` are rejected outright on this path rather than routed to
  `handle_stream_continuation`/`handle_stream_end` (those each call the *structural* Gate 0
  internally — routing an encrypted frame there would silently treat ciphertext as
  plaintext); mirroring them onto the encrypted path is real, scoped-out follow-up work.
- **`daemon.rs`**: `SAACPNetworkDaemon::with_gateway(Arc<ZeroTrustGateway>)` and
  `with_encrypted_transport(Arc<SessionEpochManager>)` builders (mirroring the existing
  `with_server_auth` pattern) opt a daemon into real Gate 1.0 token verification and real
  AEAD decryption respectively; both default to `None`, preserving today's exact existing
  behavior for every caller that doesn't opt in (including `transport::ws`, which passes
  `None, None, None` explicitly at its `handle_client` call site). When both are `Some`,
  `handle_client` lazily creates the epoch-0 session for each incoming `session_id` on
  first sight and dispatches through `intercept_packet_encrypted`. The stable,
  previously-received-but-ignored `token_issuer_secret` constructor argument (not the
  ephemeral per-connection ECDH `session_key`) is what's used as Gate 1.0's issuer-secret
  fallback and to HMAC-bind Gate 6.0 audit entries — coupling token validity to a key that
  changes every reconnect would have been a fragile, unintended design. A new
  `with_on_delivered(Arc<dyn Fn(ParsedPacket) + Send + Sync>)` builder observes every
  gate-verified packet (called synchronously from inside `spawn_blocking`, so
  implementations must use `try_send`, never `.await`) — this is what lets `sidecar.rs`
  capture decrypted payloads without forking `handle_client`'s dispatch logic. A new public
  `daemon::client_handshake` promotes the hand-rolled initiator-side ECDH logic already
  proven correct in `tests/test_transport_ws_rs.rs`'s `ws_client_handshake` into real
  library code — `daemon.rs` itself had only ever implemented the responder side before.
- **`sidecar.rs`**: `SidecarConfig` (agent_id, one shared 32-byte `token_issuer_secret`
  across the whole trusted mesh — an out-of-band pre-shared key, not a per-peer registry;
  same "honest v1, real v2 later" pattern as `trust_decay.rs`), a bounded `Inbox`
  (`tokio::sync::mpsc`, capacity `SIDECAR_INBOX_CAPACITY` — matches the existing
  bounded-queue idiom, e.g. `AUDIT_WAL_QUEUE_CAPACITY`), `send_message()` (dials out,
  `client_handshake`s, issues a token, builds a real encrypted frame, classifies the ack),
  and `run()` (starts a `SAACPNetworkDaemon` with all three builders above plus an `axum`
  HTTP API: `POST /send`, `GET /receive?wait_secs=N` long-poll, `GET /healthz`). One
  surprising consequence of pairing one-shot outbound connections with the daemon's
  existing identity-pinning bootstrap: every send is the *first* packet on a fresh
  connection, so the receiving daemon's `current_agent_name` always resolves to the literal
  `"unknown"` — the issued token's `allow` list must contain `"unknown"`, not the semantic
  peer name, or Gate 1.0's scope check would reject every message. Handled inside
  `send_message` so the HTTP API surface never has to expose this quirk.
- **`python/`**: a pure-Python `saacp_client` package (`requests`-only, no PyO3, no build
  step) — `SaacpClient.send()`/`.receive()`/`.healthz()`, plus a generic
  `SaacpAgentWrapper` pattern (documented as adaptable to LangChain/AutoGen, not a tested
  deep integration with either) and a runnable `examples/demo_two_agents.py`.

## Gate 6.0 Backpressure Contract (`security.rs`)

Any gate that touches disk, does unbounded-size work, or depends on external system throughput must declare an explicit backpressure contract with the packet pipeline instead of an ad-hoc drop-and-print. For the audit log (Gate 6.0 / WAL writer), that contract is `security::AuditHealth`:

| State | Trigger | Effect |
|-------|---------|--------|
| `Healthy` | WAL queue < 70% capacity | Normal async enqueue. |
| `Degraded` | WAL queue 70–95% capacity | Still enqueuing/writing, but behind. |
| `Saturated` | WAL queue > 95% capacity | New events dropped (`dropped_audit_count()`), never an inline `eprintln!` on the hot path. `handler::gate_2_5_kinetic_firewall` rejects new IRREVERSIBLE_ACTION (`action_class >= 2`) packets with `SAACPBytecodes::AuditSubsystemDegraded` once health reaches this state — fail-safe, not fail-open. READ_ONLY/REVERSIBLE packets are unaffected. |
| `Fatal` | The WAL worker's log file failed to open, or an in-flight write returned an OS error (`wal_write_failure_count()`) | Sticky — only constructing a fresh `ImmutableAuditLog` clears it. Distinguishable from `Saturated`: this means the writer tried and failed, not merely that it's behind. Also gates IRREVERSIBLE_ACTION via Gate 2.5. |

The WAL worker (`WalWriter` in `security.rs`) holds a persistent `BufWriter<File>` for its lifetime instead of reopening the file per event (the original root cause of a measured latency spike on Windows, where per-syscall kernel filter-driver/AV overhead dominates). It flushes + `sync_data()`s at most every `AUDIT_WAL_FLUSH_EVERY_N_ENTRIES` (200) entries or `AUDIT_WAL_FLUSH_INTERVAL_MS` (50ms), whichever comes first — that pair is the **stated maximum audit-data-loss window on an unclean shutdown** (power loss, `kill -9`): at most 200 entries or 50ms of audit history. The sentinel/count file is batched into the same flush boundary (previously it was rewritten via its own open+write+close on every single event — an unnoticed second instance of the same root-cause bug).

**Throughput** (`ImmutableAuditLog::append_event`, `security.rs`): measured via `benches/benchmarks.rs`'s `T14_WAL_Sustained_Throughput` (100k-event sustained run, log created once outside the timed closure — timing file-open/WAL-thread-spawn inside the loop would conflate one-time setup cost with steady-state throughput). Two verified fixes raised sustained throughput from ~150K to ~370K events/sec on dev hardware (a ~2.3x gain; still short of the original 500K/s target — closing the rest would need bigger architectural changes, e.g. removing the mutex around `append_event` entirely, out of scope for a measure-then-fix pass):
- `entry_json` (the JSONL line written to disk) previously rebuilt an entire second `serde_json::Value` tree via the `json!` macro, duplicating `record_json` (already built once, immediately prior, for the HMAC input) almost field-for-field. Now spliced directly from the already-serialized `record_json` string plus the hex `chain_hash` (safe: `hex::encode` output is pure ASCII hex, never containing `"` or a control character, so no JSON escaping is needed to embed it raw).
- `record_json` itself switched from `serde_json::to_string(&serde_json::json!({...}))` (builds a full `Value` tree — one boxed `Value`/`String` per field plus a `Map` — before serializing) to `serde_json::to_string(&CanonicalAuditRecord{...})`, a private `#[derive(Serialize)]` struct with borrowed `&str` fields declared in the exact same alphabetical order the old `json!` block used, serializing directly without an intermediate dynamic tree. Field order here is load-bearing (it's the canonical form the chain hash is computed over) — that's why this is a separate borrowed struct rather than adding `#[derive(Serialize)]` straight onto the public `AuditRecord`, whose field *declaration* order isn't alphabetical.

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
| `daemon.rs` | `SAACPNetworkDaemon` — async Tokio TCP server; `handle_client`/`ecdh_handshake` generic over `AsyncRead + AsyncWrite`; opt-in `with_gateway`/`with_encrypted_transport`/`with_on_delivered` builders + initiator-side `client_handshake` (see "Sidecar Proxy" section) | `daemon.py` |
| `telemetry.rs` | `TelemetryCollector`, Prometheus-format metrics rendering, opt-in `wire_trust_decay_metrics()` | *new in Rust* |
| `transport.rs` / `transport/ws.rs` | `SAACPWebSocketDaemon`, `WsByteStream` — WebSocket tunnel for MEASC frames (`transport-ws` feature) | *new in Rust* |
| `state_backend.rs` | `StateBackend` trait, `InMemoryBackend`, `RedisBackend` (`redis-backend` feature) — pluggable KV+TTL storage for horizontal scaling | *new in Rust* |
| `trust_decay.rs` | `TrustDecayEngine` (continuous behavioral trust scoring sidecar), `IntentDriftTracker` (chain-wide drift ceiling) — see "Trust Decay Engine" section above | *new in Rust* |
| `sidecar.rs` | `SidecarConfig`, `Inbox`, `send_message`, `run` — local HTTP proxy for non-Rust agents (`sidecar` feature); `src/bin/saacp_sidecar.rs` binary; see "Sidecar Proxy / Python Translation Layer" section above | *new in Rust* |

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
| DELEGATION-LIVE | CRITICAL | `validate_lateral_movement` (the live, general capability-token path) read `delegation_depth` but never enforced `ACSVAF_MAX_DELEGATION_DEPTH` on it — informational only, unlike the separate (not-live-wired) ACSVAF token system. A compromised HMAC issuer secret could mint a token claiming an arbitrarily deep delegation chain and it passed Gate 1.0 unchecked → now rejects with `SAACPBytecodes::DelegationRejected` when the claim is present but non-numeric, out of `u32` range, or exceeds the max; absent claim still defaults to 0 (no regression for legacy tokens) | `gateway.rs` |
| MEASC-TOCTOU | HIGH | Two `.unwrap()`s on `SessionEpochManager::with_epoch_mut`/`with_epoch` in `MEASCFrame::parse_frame` could panic the whole process if a session/epoch was concurrently destroyed/rotated between the step-4 existence check and step-5/6 use (no lock held across the two steps) → converted to graceful `SAACPBytecodes::EpochExpired` rejections | `measc.rs` |
| FACTF-UNBOUNDED | MEDIUM | `ThresholdAuthorityIssuer::requests` (M-of-N proposal tracking) grew unbounded if a caller never called `submit_partial_approval()`/`purge_expired_requests()` → `FACTF_MAX_TRACKED_REQUESTS = 10_000` with sweep-on-overflow (expire-first, then oldest-created fallback), mirroring the idiom already in `cscs.rs`/`gateway.rs`/`trust_decay.rs` | `factf.rs` |
| RATE-LIMITER-UNBOUNDED / CSCS-UNBOUNDED | MEDIUM | `AgentRateLimiter`'s two maps and `CSCSLoopDetector`'s outer session map grew one permanent entry per distinct agent_id/session_id ever seen, for the life of the process — a real IoT/low-resource RAM risk on long-running deployments → both bounded with the same sweep-on-overflow idiom (`RATE_LIMITER_MAX_ENTRIES`, `CSCS_MAX_TRACKED_SESSIONS`) | `gateway.rs`, `cscs.rs` |
| AUDIT-CLEARTEXT | MEDIUM (Information Disclosure) | `ImmutableAuditLog::append_event`'s `intent` field (task/action text) was written to disk in cleartext JSONL — integrity-protected by the chain-hash HMAC, never confidentiality-protected. An attacker with filesystem read access to the log (a different compromised process on the host, a stolen backup) got a full plaintext history of every agent's tasks → opt-in `append_event_confidential()` encrypts just the `intent` field (AES-256-GCM, key HKDF-derived from `issuer_secret` with domain separation from the chain-hash HMAC) before it reaches `append_event`; `decrypt_intent()` reads it back. Record schema and `verify_chain`/`verify_chain_disk` are unchanged — the HMAC covers whatever string is in `intent` either way. Opt-in (mirrors `mpf.rs`'s pattern) so the default `append_event` path stays byte-for-byte compatible with every existing deployment/test | `security.rs` |
| IDGATE-DEADCODE | MEDIUM (Spoofing / Repudiation bookkeeping) | `daemon.rs::handle_client` called `GLOBAL_IDENTITY_GATE.advance(..., "connection_init")` and `.advance(..., "authenticated")` — neither string is one of the six canonical `IDENTITY_GATE_PHASES` (`identity_binding.rs`), so `advance()` rejected both every single time and the `let _ = ...` silently discarded the error. The C-3 identity-gate bookkeeping had done nothing since it was written → the meaningless connection-init call (which would have falsely recorded `"unknown"` as having completed a phase before any authentication) is removed outright; the post-authentication call now advances the real `"IDENTITY_VERIFIED"` then `"AUTHORIZED"` phases. Still bookkeeping only — no call site anywhere invokes `require_phase()` to actually block on it; see `identity_binding.rs`'s own module docs for the full C-3 design and the honest scope note in `daemon.rs` | `daemon.rs` |
| TRUST-IDENTITY-ROTATION | MEDIUM (Spoofing / DoS evasion) | `TrustDecayEngine` and `AgentRateLimiter` key their accumulated-penalty state solely on the packet's claimed agent identity (`current_agent_name` / capability-token `iss`) — by trust_decay.rs's own design ("tracks behavior, not identity"), which assumes identity is already stable. But `daemon.rs`'s `pinned_agent` resets to `None` on every hard drop, so a caller holding (or having compromised) signing credentials for more than one identity — or simply relying on the common single-shared-issuer-secret deployment mode, where `iss` is a free-form self-chosen claim with no per-issuer registry — could "launder" its accumulated trust penalty for free by claiming a fresh identity on its next packet, defeating the entire point of a continuous behavioral signal → `handle_client` now also tracks a second, IP-namespaced (`ip:<addr>`) `TrustDecayEngine` bucket, penalized on every hard drop regardless of claimed identity and checked once per new connection (mirroring the existing IP circuit breaker's own connect-time-only check) | `daemon.rs` |
| DELEGATION-GUARD-SLICE | HIGH (buffer safety) | `DelegationGuard::validate_not_self_signed` read the token's 4-byte attacker-controlled length prefix (`json_len`) and sliced `raw[4..4+json_len]` with no check that `4+json_len <= raw.len()` — unlike its sibling `parse_token_wire` in the same file, which already guards this exact pattern (`json_len == 0 \|\| json_len > raw.len().saturating_sub(4)`). A token whose length prefix claims more JSON bytes than are actually present (e.g. 4 bytes total declaring a 65535-byte body) panicked with "range end index out of range for slice" instead of returning `SAACPHardDrop`. Not reachable from the live daemon path today (this function is documented as never wired into `validate_lateral_movement`), but it's public API operating on the same attacker-controlled wire format `parse_token_wire` handles safely → applied the identical bounds check | `gateway.rs` |
| MEASC-PARSE-HEADER-OVERFLOW | MEDIUM (buffer safety) | `framing.rs::MEASCFrame::parse_header` (used by `handler.rs::gate_0_crypto_integrity`, the live packet-processing path) computed `payload_end = MEASC_HEADER_SIZE + payload_length as usize` from an attacker-controlled wire `u32` with no upper-bound check first — unlike its sibling `SAACPFrame::parse_header` (same file) and the real decrypting `measc.rs::MEASCFrame::parse_frame`, both of which cap `payload_length` against `MAX_PAYLOAD_SIZE` before using it as a slice offset. On 64-bit this was "only" an unbounded-allocation risk gated by a subsequent length check; on a 32-bit target (this crate explicitly targets OpenWrt/Raspberry-Pi-class deployments) `128 + payload_length` can overflow `usize` and wrap to a value smaller than `payload_start`, passing the length guard and then panicking on `packet[payload_start..payload_end]` (start > end). Mitigated in practice today by `daemon.rs` already enforcing `MAX_PAYLOAD_SIZE` before this function is ever reached, and by the `spawn_blocking`+`JoinError` boundary around the whole gate pipeline — fixed anyway for defense-in-depth, matching the sibling functions' pattern | `framing.rs` |
| DAEMON-NO-AEAD | CRITICAL (Spoofing / Tampering) | `daemon.rs::handle_client` always dispatched through `handler::gate_0_crypto_integrity`, which calls the structural-only `framing::MEASCFrame::parse_header` — its own doc comment admitted "AES-GCM decryption is handled by the SAACPFrame layer," but nothing ever called that layer. The real encrypting/decrypting type, `measc::MEASCFrame::build_frame`/`parse_frame` (genuine AES-256-GCM + replay-window enforcement via `SessionEpochManager`), was never invoked by the live daemon path at all — every "encrypted" packet the daemon ever processed was actually raw ciphertext bytes silently mis-treated as plaintext JSON (JSON decode failed silently, `payload_dict` stayed empty). Found while designing the sidecar's real-crypto requirements → opt-in `SAACPNetworkDaemon::with_encrypted_transport(Arc<SessionEpochManager>)` + new `handler::gate_0_crypto_integrity_encrypted`/`intercept_packet_encrypted` route real packets through genuine AES-GCM decryption; default (`None`) behavior is byte-for-byte unchanged | `daemon.rs`, `handler.rs` |
| DAEMON-NO-TOKEN-VERIFY | CRITICAL (Spoofing / Elevation of Privilege) | `daemon.rs::handle_client` always called the 4-arg `SAACPProtocolHandler::intercept_packet` wrapper, which always passes `gateway: None` into Gate 1.0 — `_intercept_packet_inner`'s `None` branch skips `ZeroTrustGateway::validate_lateral_movement` entirely and hardcodes `TokenValidationResult{is_valid:true, source_agent:"unknown", max_action_class:0}`, only checking that a `_capability_token` field is *present as a string*, never HMAC-verifying its signature. Every capability token the live daemon ever accepted was accepted unconditionally. Found alongside DAEMON-NO-AEAD while designing the sidecar → opt-in `SAACPNetworkDaemon::with_gateway(Arc<ZeroTrustGateway>)` routes through `intercept_packet_full`/`intercept_packet_encrypted` with a real gateway instead; uses the daemon's stable, previously-received-but-ignored `token_issuer_secret` constructor argument (not the ephemeral per-connection ECDH session key) as the issuer-secret fallback, since coupling token validity to a key that changes every reconnect would be fragile. Default (`None`) behavior is byte-for-byte unchanged | `daemon.rs`, `handler.rs` |

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
| `tests/test_redteam.rs` | 33 (39 w/ `mpf`) | Exploit scenarios, confusable Unicode, token attacks; MPF-specific cases gated `#[cfg(feature = "mpf")]` |
| `tests/test_security_attacks_rs.rs` | 24 (28 w/ `mpf`) | Protocol-level: replay, circuit breaker, injection; MPF-specific cases gated `#[cfg(feature = "mpf")]` |
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
| `tests/test_gate5_scope_consistency_rs.rs` | 7 | Gate 5.0b regression proof: Attack 7.2 (fake high confidence on off-scope `data` claim), on-scope controls, no-op conditions (no root intent / missing / non-string `data`) |
| `tests/test_blackhat_agent_hijack_rs.rs` | 15 | The 20-year black-hat multi-step chain attack: delegation-depth escalation (Act I, live `validate_lateral_movement` path) → confused-deputy intent-padding incl. Unicode-confusable evasion (Act II, `gate_1_5c_dangerous_action_consistency`) → chain-wide cumulative drift (Act III, `gate_1_5_reinforcement`) → context-provenance capability check (Act IV, `FederatedMemory::save_context_with_provenance`) → Finale chaining all three live techniques + a "legitimate traffic still works" check. Calls gate functions directly with hand-built `payload_dict`s, matching this repo's established Gate-1.5-family test convention (see the module doc comment for why, and `trust_decay.rs`'s "Gate 1.5 reinforcement" section above) |
| `tests/test_daemon_encrypted_rs.rs` | 5 | DAEMON-NO-AEAD / DAEMON-NO-TOKEN-VERIFY regression proof: real `SAACPNetworkDaemon` over real loopback TCP with `.with_gateway()`/`.with_encrypted_transport()` — validly-signed encrypted frame accepted and decoded via `on_delivered`, tampered ciphertext AEAD-rejected, wrong-issuer-secret token rejected, two independent sessions don't cross-contaminate, and a plain `SAACPNetworkDaemon::new()` (no builders) is unchanged |
| `tests/test_sidecar_rs.rs` | 4 | `sidecar` feature only. Two in-process `sidecar::run()` instances driven purely via HTTP/JSON (`reqwest`, mirroring a Python caller) — real send/receive round trip, `/receive` 204-on-timeout, wrong-shared-secret rejection (proving the HTTP surface rides on the real crypto/token fixes, not just that the routes exist), `/healthz` |

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

16. **Gate 1.5 reinforcement's depth-0 baseline must match `enforce_root_intent`'s truncated-integer effective ratio, not the raw `INTENT_MIN_OVERLAP` constant**: `enforce_root_intent` requires `overlap >= max(1, root_total * INTENT_MIN_OVERLAP) as usize` — for short root intents (few terms), truncating that count down makes the *true* effective ratio more lenient than 20% (e.g. a 6-term root intent only needs 1 shared term ⇒ ~16.7%). `gate_1_5_reinforcement`'s per-hop tightening recomputes this same truncated-ratio baseline (`base_required_ratio`) rather than reusing `INTENT_MIN_OVERLAP` directly — using the raw constant would make the "reinforcement" stricter than the base check even at depth 0, contradicting its whole purpose (only get stricter as delegation depth grows). Also carries a `1e-9` epsilon tolerance in the boundary comparison: `1.0 - (1.0 - ratio)` is not always bit-identical to `ratio` in IEEE 754, so an exact-boundary case can flip the strict `<` without it.

17. **`delegation_depth` is informational on the general HMAC capability-token path, mandatory+enforced on the separate ACSVAF path — don't conflate them**: `TokenValidationResult::delegation_depth` (`gateway.rs::validate_lateral_movement`) defaults to 0 when the claim is absent, but rejects (`SAACPBytecodes::DelegationRejected`) when present-but-invalid (non-numeric, out of `u32` range, or `> ACSVAF_MAX_DELEGATION_DEPTH`). This is a different code path and a different token type from `acsvaf.rs`'s own mandatory-claim enforcement — a token validated via `validate_lateral_movement` was never checked against `ACSVAF_MAX_DELEGATION_DEPTH` at all before this fix (informational-only), which is exactly what `tests/test_blackhat_agent_hijack_rs.rs` Act I regression-tests.

18. **New MPF tests must be `#[cfg(feature = "mpf")]`-gated, not just skip the import**: MPF (`mpf.rs`) is feature-gated (see "Optional Cargo Features"); any test file referencing `AdaptivePadding`/`CoverTraffic`/`TimingObfuscator`/`MPF_*` needs both the `use` statement *and* the `#[test]` function itself behind `#[cfg(feature = "mpf")]` — gating only the import still fails to compile under default features once any test function references the type.

19. **`SAACPNetworkDaemon::with_gateway`/`with_encrypted_transport` are opt-in, not automatic upgrades**: constructing a daemon and calling `.with_gateway(...)` alone (without `.with_encrypted_transport(...)`) still uses the structural-only Gate 0 — real signature verification is useless there, since `payload_dict` (and thus `_capability_token`) is never populated from genuine ciphertext, so every packet will hard-drop with "missing capability token." Both builders are needed together for a functioning real-crypto path; `sidecar.rs::run()` always wires both.

20. **A one-shot outbound connection's capability token must be issued to `"unknown"`, not the semantic peer name**: `daemon.rs::handle_client` resolves `current_agent_name` to the literal string `"unknown"` until a packet's Gate 1.0 validation actually pins an identity — which means the *first* packet on any new connection is always validated with `target_agent = "unknown"`. `sidecar.rs::send_message` (a fresh connection per call, by design — see its module doc) issues every token with `allow: ["unknown"]` for exactly this reason; issuing it to the caller's real `to_agent` name instead would make Gate 1.0's scope check reject every single message.

21. **`intercept_packet_encrypted`'s `audit_secret` parameter does double duty, same as the structural path's `secret_key` always has**: it both HMAC-binds Gate 6.0 audit entries and (via `run_gates_1_through_12` → Gate 1.0) serves as `ZeroTrustGateway::validate_lateral_movement`'s `issuer_secret` fallback when no per-issuer key is registered. `daemon.rs` passes its own stable, constructor-supplied `token_issuer_secret` here (not the ephemeral per-connection ECDH `session_key`) — this is what lets a single shared 32-byte secret validate tokens from an entire trusted mesh with zero `register_issuer_key` calls (`sidecar.rs`'s v1 design relies on exactly this).
