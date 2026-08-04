# SAACP — Secure Autonomous Agent Communication Protocol

**Rust implementation** · Protocol `SAACP/0.1-beta2` · Crate `saacp` v0.1.0 · License MIT

SAACP is a zero-trust, cryptographically-authenticated wire protocol and security
gate pipeline for **autonomous AI agents talking to other autonomous AI agents**.
It treats every inter-agent packet as hostile until proven otherwise: each frame is
individually encrypted and authenticated, then run through a fixed, non-reorderable
pipeline of security gates that enforce capability authorization, action-class
escalation limits, intent binding, prompt-injection resistance, epistemic sanity,
and an immutable audit trail — **before** the payload is ever handed to the receiving
agent's business logic.

> **Design thesis:** classic RPC/service-mesh security answers *"is this connection
> from a trusted host?"*. That is necessary but not sufficient for LLM-driven agents,
> where the threat is often a *legitimately authenticated* agent that has been
> prompt-injected, confused-deputied, or driven into a runaway loop. SAACP adds the
> agent-specific layer on top of transport security: **authorization invariance**,
> **intent envelopes**, **injection scanning**, **epistemic circuit breakers**, and
> **causal-graph governance**.

---

## Table of contents

1. [Highlights](#highlights)
2. [Architecture at a glance](#architecture-at-a-glance)
3. [The security gate pipeline](#the-security-gate-pipeline)
4. [Cryptography & the MEASC wire format](#cryptography--the-measc-wire-format)
5. [Identity, trust & delegation](#identity-trust--delegation)
6. [Module map](#module-map)
7. [Getting started (Rust)](#getting-started-rust)
8. [Python integration (`saacp.wrap`)](#python-integration-saacpwrap)
9. [The Command Center dashboard](#the-command-center-dashboard)
10. [Cargo feature flags](#cargo-feature-flags)
11. [Testing & fuzzing](#testing--fuzzing)
12. [Benchmarks](#benchmarks)
13. [Security model & threat coverage](#security-model--threat-coverage)
14. [Project layout](#project-layout)
15. [License](#license)

---

## Highlights

- **Per-frame AEAD.** Every frame is AES-256-GCM encrypted with a key derived per
  `(session, epoch, packet-sequence-number)` via HKDF-SHA256. The 128-byte transport
  header is authenticated as AAD — tamper any header bit and decryption fails closed.
- **Forward-secret key evolution.** Session keys ratchet forward by epoch (time- or
  packet-threshold-triggered), so compromise of one epoch's key does not expose past
  or future traffic.
- **Authorization Invariance.** All mandatory security gates execute on **every**
  packet regardless of "tier". Tiers affect only telemetry/audit verbosity, never
  which checks run. Reordering the pipeline is treated as a security bug.
- **Capability tokens with bounded delegation.** Ed25519-signed capability tokens
  carry an action-class ceiling and a delegation depth capped at 3 hops.
- **Prompt-injection resistance built into the wire.** Gate 4.0 normalizes Unicode
  (NFKC + ~300 confusable homoglyph mappings + zero-width stripping), then matches a
  precompiled Aho-Corasick automaton of injection signatures — including base64/hex/
  percent-encoded payloads up to 3 decode layers deep.
- **Immutable, hash-chained audit log** with an HMAC-authenticated chain and a
  write-ahead-log (WAL) writer that batches `fsync` for throughput.
- **Replay protection** via a 4096-entry sliding PSN window with anomaly detection
  and quarantine.
- **Runs from cloud to edge.** The core library trims its Tokio feature set for
  embedded-Linux-class targets (Raspberry Pi / OpenWrt-class routers); optional
  transports, Redis state sharing, and dashboards are all behind feature flags.
- **Language-agnostic edge.** A `saacp-sidecar` binary lets any HTTP-capable agent
  (Python, LangChain, AutoGen, plain scripts) get full SAACP guarantees over plain
  localhost HTTP/JSON, with zero SAACP protocol knowledge on the agent side.

---

## Architecture at a glance

```
   ┌──────────────┐      plain HTTP/JSON        ┌──────────────────────┐
   │  Your agent  │ ─────────────────────────▶  │   saacp-sidecar      │
   │ (any lang)   │ ◀─────────────────────────  │  (optional edge)     │
   └──────────────┘                             └──────────┬───────────┘
                                                            │  real SAACP wire
                                                            ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │                     SAACPNetworkDaemon (src/daemon.rs)                 │
   │   TCP / WebSocket / TLS transport  ·  per-IP circuit breakers          │
   └───────────────────────────────┬────────────────────────────────────────┘
                                    ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │            SAACPProtocolHandler::intercept_packet(_full/_encrypted)    │
   │                                                                        │
   │  Gate 0  Crypto integrity  (AES-256-GCM + replay window + Adler-32)    │
   │  Gate 1.0 Capability token validation (Ed25519/HMAC, revocation, expiry)│
   │  Gate 2.5 Kinetic firewall (action-class escalation guard)             │
   │  Gate 1.5 Intent envelope (root-intent binding + drift + dangerous verb)│
   │  Gate 0.5 Financial circuit breaker (token-budget cap)                 │
   │  Gate 3.0 Lateral-movement guard (secondary token for mutations)       │
   │  Gate 4.0 Prompt-injection scanner (Unicode-normalized, multi-encoding)│
   │  Gate 5.0 Epistemic circuit breaker (confidence sanity, schema 3)      │
   │  Gate 5.0b Scope-consistency reinforcement                             │
   │  Gate 6.0 Immutable audit checkpoint (HMAC hash-chain, WAL)            │
   │  Gate 9.0 JSON schema validation + RGC resource governance             │
   │  Gate 11.0 AEGF hop-limit + causal-graph governance                    │
   │  Gate 12.0 CSCS oscillation / loop detection                           │
   └───────────────────────────────┬────────────────────────────────────────┘
                                    ▼
                          delivered to receiving agent
```

Cross-cutting engines run alongside the numbered gates: a per-agent **rate
limiter / circuit breaker**, a **Trust Decay Engine** (continuous behavioral trust
scoring), a **Dead Man's Switch** (stalled-session watchdog), and process-wide
**telemetry** feeding the optional Command Center dashboard.

---

## The security gate pipeline

The canonical, mandatory gate set (`handler::MANDATORY_GATES`) is:

```rust
pub const MANDATORY_GATES: &[&str] = &[
    "gate_0_crypto_integrity",
    "gate_1_0_token_validation",
    "gate_1_5_intent_envelope",
    "gate_2_5_kinetic_firewall",
    "gate_3_0_lateral_movement",
    "gate_4_0_injection_scan",
    "gate_5_0_epistemic_cb",
    "gate_6_0_audit_checkpoint",
];
```

Additional gates (0.5 financial, 5.0b scope-consistency, 9.0 schema/RGC, 11.0 AEGF,
12.0 CSCS) and adjacent checks (ACA attestation, SID semantic-injection defense,
MACE collusion) run in the same pipeline. The numeric labels reflect protocol
history, **not** execution order — the true execution order is documented in
`intercept_packet`'s doc comment and enforced by `run_gates_1_through_12`.

| Gate | Name | What it enforces | Key parameters |
|------|------|------------------|----------------|
| **0** | Crypto Integrity | AES-256-GCM authenticated decryption of the frame; replay-window check; Adler-32 corruption filter; rejects schema-0 (raw binary). | see [MEASC](#cryptography--the-measc-wire-format) |
| **1.0** | Capability Token Validation | Verifies the Ed25519/HMAC capability token: signature, expiry, revocation, subject binding, and the token's `max_action_class` ceiling. | delegation depth ≤ 3 |
| **1.5** | Intent Envelope | When a signed *root intent* is bound to the session, the task must share ≥ 20% term overlap with it. Adds **per-hop tightening** (stricter with delegation depth) and a **chain-wide drift ceiling**. | `INTENT_MIN_OVERLAP = 0.20`, `+0.05`/hop up to `0.60` |
| **1.5c** | Dangerous-Action Consistency | Rejects a task that introduces a high-risk verb (`delete`, `exfiltrate`, `wire`, `escalate`, …) **not present in the root intent** — closes the confused-deputy / intent-padding gap. | 21-verb denylist, relative to root intent |
| **2.5** | Kinetic Firewall | Rejects action-class escalation (`requested > token max`). IRREVERSIBLE actions additionally require a **healthy audit subsystem** (Gate 6.0 backpressure contract). | action classes 0/1/2 |
| **0.5** | Financial Circuit Breaker | For cost-estimate frames, rejects when `estimated_cost > max_token_budget`. Explicitly rejects NaN / ±∞ costs. | fail-closed on non-finite |
| **3.0** | Lateral-Movement Guard | High-risk mutative operations (flag `0x0B`) require a `_secondary_token` in the payload. | — |
| **4.0** | Prompt-Injection Scanner | Normalizes text (NFKC → strip zero-width → map ~300 confusables → ASCII fold → strip `/**/` → lowercase), then matches an Aho-Corasick automaton of injection signatures; also decodes base64 / URL-safe base64 / hex / percent-encoding and re-scans. | `MAX_SCAN_LENGTH = 16 384`, `MAX_DEPTH = 8`, `MAX_DECODE_LAYERS = 3` |
| **5.0** | Epistemic Circuit Breaker | For schema-3 ("Epistemic") frames, quarantines low-confidence data and rejects **over-claimed** confidence (≥ 0.99) and non-finite scores. Threshold is server-side and never read from the payload. | `EPISTEMIC_THRESHOLD = 0.85`, overclaim `≥ 0.99` |
| **5.0b** | Scope-Consistency Reinforcement | A high self-reported confidence can never widen a claim's scope beyond the signed root intent. | reuses intent-divergence |
| **6.0** | Audit Checkpoint | Appends an HMAC-authenticated, hash-chained entry to the immutable audit log (WAL-backed). Emits a health signal consumed by Gate 2.5. | WAL flush every 200 entries / 50 ms |
| **9.0** | Schema + RGC | Validates the decrypted JSON against the frame's precompiled schema and enforces resource-governance limits. | 10 built-in schemas |
| **11.0** | AEGF Governance | Deterministic agent-execution governance: hop limits and a distributed causal execution graph. | — |
| **12.0** | CSCS Loop Detection | Detects oscillation / runaway loops across a session's execution history. | — |

**Gate tiers** (`GateTier::{Lightweight, Standard, Full}`) are resolved by
`resolve_gate_tier(action_class, flags, is_pinned)`:

- `EXTERNAL_INPUT` flag (bit 7) → **Full**
- action class ≥ `IRREVERSIBLE (0x02)` → **Full**
- action class `REVERSIBLE (0x01)` → **Standard**
- action class `READ_ONLY (0x00)` → **Lightweight** if the connection is pinned, else **Standard**

> Tier never removes a gate. Per the source: *"LIGHTWEIGHT never reduces security
> gates. A pinned connection is a transport optimization only."*

### Cross-cutting enforcement (not numbered gates)

- **AgentRateLimiter / circuit breaker** — locks out an agent after
  `RATE_LIMITER_THRESHOLD = 5` errors within `RATE_LIMITER_WINDOW_SECONDS = 10.0`s for
  `RATE_LIMITER_LOCKOUT_SECONDS = 30.0`s. Cover traffic is throttled at
  `COVER_TRAFFIC_THRESHOLD = 50` per `1.0`s window.
- **Trust Decay Engine** (`trust_decay.rs`) — continuous behavioral trust score keyed
  by Ed25519 fingerprint (when identity-bound) or agent id; sustained low trust forces
  a soft-reset / re-handshake. Gate-specific violations carry heavier penalties than a
  generic hard drop.
- **Dead Man's Switch / Temporal Heartbeat** (`temporal.rs`) — watchdog for stalled
  agent sessions.

---

## Cryptography & the MEASC wire format

**MEASC** = *Mandatory Encryption & Authenticated Sequence Control*. It is the
transport-layer frame that carries all live traffic.

### Primitives

| Purpose | Algorithm |
|---------|-----------|
| AEAD (confidentiality + integrity) | **AES-256-GCM** (16-byte auth tag) |
| Key derivation / ratchet | **HKDF-SHA256** |
| Capability & identity signatures | **Ed25519** (`ed25519-dalek`) |
| Session key agreement (sidecar mesh) | **X25519 ECDH** |
| Corruption filter (non-cryptographic) | **Adler-32** |
| Baseline suite string | `AES-256-GCM-HKDF-SHA256` / signature `ed25519` |

Key material uses `zeroize` for best-effort scrubbing on drop. Signature/checksum
comparisons on hot paths use constant-time equality.

### MEASC 128-byte transport header (`framing::MEASCFrame`)

All fields big-endian. Wire layout: `[128-byte header][16-byte GCM tag][ciphertext]`.
The full 128-byte header is authenticated as AES-GCM AAD.

| Offset | Size | Field |
|--------|------|-------|
| 0 | 4 | magic `b"SACP"` |
| 4 | 2 | schema_id (u16) |
| 6 | 1 | status_code |
| 7 | 1 | flags |
| 8 | 1 | action_class |
| 9 | 3 | padding |
| 12 | 4 | payload_length (u32) |
| 16 | 16 | session_id |
| 32 | 4 | epoch_id |
| 36 | 8 | psn (packet sequence number) |
| 44 | 32 | context_ref_id |
| 76 | 4 | context_version |
| 80 | 24 | W3C traceparent |
| 104 | 24 | reserved / padding |

The per-frame `(key, iv)` is derived by a single HKDF-SHA256 expand:
`salt = session_id`, `info = "SAACP-FRAMING-MEASCFrame-key-iv-v1" || epoch_id || psn`,
producing 44 bytes split into a 32-byte AES-256 key and a 12-byte GCM IV — binding
each frame's key to its exact `(session, epoch, psn)` triple.

> There is also a 101-byte **application-layer** header, `framing::SAACPFrame`
> (`>4s H B B B I I 16s 24s 32s I Q`), used for cross-language wire compatibility with
> the Python reference implementation. Its wire packet is
> `[101-byte prefix][16-byte GCM tag][4-byte Adler-32][ciphertext]`, with the IV
> derived as `SHA-256(nonce || session_uuid)[:12]`, and it carries an explicit
> nonce-tracking replay defense checked **before** decryption.

### Frame flags & action classes

| Flag | Value | Meaning |
|------|-------|---------|
| `FLAG_HAS_TOKEN` | `0x01` | payload carries a capability token |
| `FLAG_BINARY_STREAM` | `0x02` | non-text binary stream; skips Gate 4.0 injection scan |
| `FLAG_ENCRYPTED` | `0x10` | payload is AES-256-GCM encrypted (always set post-handshake) |
| `FLAG_COMPRESSED` | `0x20` | payload zlib-compressed before encryption |
| `FLAG_STREAMING` | `0x40` | packet belongs to a stream session |
| `FLAG_COVER_TRAFFIC` / `FLAG_EXTERNAL_INPUT` | `0x80` | cover traffic / external-input (forces Full tier) |

| Action class | Value |
|--------------|-------|
| `READ_ONLY` | `0x00` |
| `REVERSIBLE` | `0x01` |
| `IRREVERSIBLE` | `0x02` |

- **Max payload / MTU:** `MAX_PAYLOAD_SIZE = 10_000_000` (10 MB). Compressed payloads
  are bounded to the same limit on decompression (zip-bomb protection).

### Session epochs & replay protection (`measc.rs`)

- **Epoch rotation** triggers on time (`MEASC_DEFAULT_EPOCH_TIME_SECONDS = 600`) or
  packet count (`MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD = 1_048_576`), with a
  `MEASC_EPOCH_GRACE_PERIOD_SECONDS = 60` overlap window for in-flight frames. Keys
  evolve forward via HKDF (`"SAACP-MEASC-epoch-key-v1"` / `"SAACP-MEASC-iv-v1"`).
- **Replay window:** `MEASC_REPLAY_WINDOW_SIZE = 4096` sliding bitmap;
  `MEASC_MAX_PSN_ADVANCE = 2048` (compile-time asserted `< window size`);
  anomaly jump threshold `512`; escalating `Allow → Audit → RateLimit → Quarantine`
  policy after `MEASC_REPLAY_MAX_ANOMALIES_QUARANTINE = 5` anomalies.
- **PSK compromise recovery** paths are provided for post-incident key rotation.

---

## Identity, trust & delegation

- **FAITF** — *Federated Agent Identity and Trust Framework* (`faitf.rs`): agent
  identities, trust anchors/stores, a **Distributed Revocation Infrastructure**,
  **Trust Mesh Federation** with signed federation agreements, delegation chains, and
  credential renewal. Delegation depth is bounded (`FAITF_MAX_DELEGATION_DEPTH`), with
  identity-proof TTLs and bounded clock skew.
- **FACTF** — *Federated Authorization and Cryptographic Trust Framework*
  (`factf.rs`): m-of-n **threshold capability tokens**, a **Capability Transparency
  Log** (in-memory or filesystem backend), risk-aware authorization evaluation, and
  post-compromise recovery.
- **ACSVAF** — the capability-token core (`acsvaf.rs`): Ed25519 issuance/verification
  authorities and key manifests. `ACSVAF_MAX_DELEGATION_DEPTH = 3`.
- **Authority separation** (`acsvaf_authority.rs`): six authority classes
  (`Root → Federation → Administrative → Service → Delegated → ExecutionAgent`), with
  strict issuer/subject separation; execution agents are a terminal class that may not
  issue tokens.
- **Identity binding + HTH** (`identity_binding.rs`, `hth.rs`): a Handshake Transcript
  Hash binds a capability to the exact handshake it was negotiated in, defeating
  transcript-substitution and capability-replay-across-sessions attacks.
- **Crypto governance** (`crypto_governance.rs`): an approved-suite policy, a crypto
  transparency ledger, and a negotiation transcript to resist downgrade attacks.

---

## Module map

<details>
<summary><strong>Core protocol</strong></summary>

| Module | Responsibility |
|--------|----------------|
| `framing.rs` | MEASC (128-byte) + SAACPFrame (101-byte) wire formats, AES-GCM, Adler-32, zlib |
| `measc.rs` | Session epochs, HKDF key evolution, replay window, packet sequencing |
| `handler.rs` | `SAACPProtocolHandler`, the full gate pipeline, prompt-injection scanner |
| `gateway.rs` | `ZeroTrustGateway`, `AgentRateLimiter`, delegation guard, RRBC gateway |
| `schemas.rs` | 10 precompiled JSON payload schemas (Task, Action, Epistemic, …) |
| `errors.rs` | `SAACPBytecodes` result codes + `SAACPHardDrop` fail-closed error type |
| `easi.rs` | Encrypted Agent State Information |
| `cryptosuite.rs` | Cryptographic agility layer (Ed25519 default) |
| `crypto_governance.rs` | Approved-suite policy, downgrade resistance, transparency ledger |

</details>

<details>
<summary><strong>Identity, trust & authorization</strong></summary>

| Module | Responsibility |
|--------|----------------|
| `acsvaf.rs` | Ed25519 capability tokens: issuance & verification authorities |
| `acsvaf_authority.rs` | Six-class authority hierarchy & issuer/subject separation |
| `acsvaf_audit.rs` | Capability lifecycle event routing to transparency + audit logs |
| `faitf.rs` / `faitf_audit.rs` | Federated identity, revocation, mesh federation, delegation chains |
| `factf.rs` | Threshold tokens, capability transparency log, risk-aware authz |
| `identity_binding.rs` | Authenticated identity binding + transcript integrity |
| `hth.rs` | Handshake Transcript Hash |
| `klms.rs` | Key Lifecycle Management System (rotation, revocation, audit) |
| `trust_decay.rs` | Continuous behavioral trust scoring + intent-drift tracking |
| `aca.rs` | Agent Capability Attestation (operator-signed safety-level claims) |

</details>

<details>
<summary><strong>Agent-execution governance</strong></summary>

| Module | Responsibility |
|--------|----------------|
| `aegf.rs` | Agent Execution Governance Framework: state machine + causal graph |
| `cscs.rs` | Oscillation / loop detection (`CSCSLoopDetector`) |
| `mace.rs` | Multi-Agent Collusion Detection Engine (Sybil / cosine similarity) |
| `sid.rs` | Semantic Injection Defense, layer 1 |
| `ievl.rs` | Intent-Execution Verification Loop (signed execution receipts) |
| `rgc.rs` | Resource Governance Controls (size/nesting/budget limits) |
| `estimator.rs` | Autonomous token-cost estimator |
| `temporal.rs` | Dead Man's Switch + Temporal Heartbeat |
| `memory.rs` | Federated memory + secure context store + stall reports |

</details>

<details>
<summary><strong>Transport, runtime & operations</strong></summary>

| Module | Responsibility |
|--------|----------------|
| `daemon.rs` | `SAACPNetworkDaemon` — async listener, per-IP circuit breakers, timeouts |
| `transport.rs`, `transport/ws.rs`, `transport/tls.rs` | Raw TCP / WebSocket / TLS transports |
| `pool.rs` | Pinned-connection pool with periodic token revalidation |
| `state_backend.rs` | `StateBackend` trait (in-memory or Redis-shared) |
| `security.rs` | Nonce tracker + immutable hash-chained WAL audit log |
| `pecf.rs` | Protocol Error Confidentiality Framework (opaque wire errors) |
| `error_confidentiality.rs` | Fixed-size opaque error responses |
| `telemetry.rs` | Metrics, gate-rejection counters, security alert feed |
| `gossip.rs` | Revocation gossip protocol |
| `hrt.rs` | Hardware Root of Trust — `HardwareKeyStore` seam plus real PKCS#11 / AWS KMS / GCP KMS backends |
| `rulepack.rs` | Dynamic hot-reloadable injection rules — Ed25519-signed, versioned, additive-only rule packs adopted without a restart |
| `cluster.rs` | Active-active clustering, leader leases, and failover over signed membership messages |
| `type_state.rs` | Compile-time gate-ordering enforcement (`PipelineToken`) |
| `maintenance.rs` | Background maintenance sweeps |
| `sidecar.rs` | Local HTTP proxy: plain JSON ⇄ SAACP-secured traffic |
| `command_center.rs` / `command_center_demo.rs` | REST + SSE dashboard backend |

</details>

Daemon safety limits: `HANDSHAKE_TIMEOUT_SECS = 0.1`,
`IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS = 0.5`, `MAX_ASSEMBLY_TIME = 30.0`s,
`MAX_CIRCUIT_BREAKER_IPS = 10_000`. Audit log: HMAC hash chain, WAL flush every
200 entries or 50 ms, `AUDIT_MAX_LOG_SIZE = 50 MB` rotation. Nonce tracker:
`NONCE_MAX_AGE_SECONDS = 30.0`, `NONCE_MAX_ENTRIES = 100_000`.

---

## Getting started (Rust)

**Prerequisites:** Rust 1.96+ (2021 edition).

```sh
git clone https://github.com/shashankv762/SAACP_RUST.git
cd SAACP_RUST
cargo build --release
cargo test
```

### Minimal example — build a frame and run it through the pipeline

```rust
use saacp::{
    SessionEpochManager, MEASCFrame, SAACPProtocolHandler,
    AgentRateLimiter,
};

// 1. Establish a session with a shared 32-byte secret.
let secret_key = [0x42u8; 32];
let session_id = [0x01u8; 16];
let manager = SessionEpochManager::new();
manager.create_session(session_id, secret_key, 1_000_000, 3600.0, None).unwrap();
let epoch_id = manager.get_current_epoch_id(&session_id).unwrap();

// 2. Build an encrypted MEASC frame (schema 1 = "Task").
let payload = br#"{"task":"analyze the quarterly report","priority":1}"#;
let frame = manager.with_epoch_mut(&session_id, epoch_id, |epoch| {
    MEASCFrame::build_frame(
        epoch,
        /* schema_id     */ 1,
        /* status_code   */ 0x10,
        /* flags         */ 0x01,
        /* action_class  */ 0x00, // READ_ONLY
        payload,
        /* context_ref   */ &[0u8; 32],
        /* traceparent   */ &[0u8; 24],
        /* context_ver   */ 0,
    ).unwrap().0
}).unwrap();

// 3. Intercept: runs the full mandatory gate pipeline. Fails closed on any gate.
let rate_limiter = AgentRateLimiter::new();
match SAACPProtocolHandler::intercept_packet(&frame, &secret_key, "agent-a", false) {
    Ok(parsed)  => println!("accepted: schema {}", parsed.schema_id),
    Err(drop)   => println!("rejected: {:?}", drop.bytecode),
}
```

### Run the network daemon

The `SAACPNetworkDaemon` (`src/daemon.rs`) accepts connections over raw TCP by
default, or WebSocket / TLS with the corresponding feature flags. See the module docs
and `tests/test_daemon_encrypted_rs.rs` for a full encrypted round-trip.

---

## Python integration (`saacp.wrap`)

Any HTTP-capable agent can get SAACP's guarantees without speaking the wire protocol,
by talking plain localhost HTTP/JSON to a local `saacp-sidecar` process.

```
Python agent  ⇄ plain HTTP/JSON ⇄  saacp-sidecar  ⇄ real SAACP wire ⇄  peer's saacp-sidecar
                                    (X25519 ECDH, AES-256-GCM,
                                     HMAC capability tokens, full gate pipeline)
```

**1. Build the sidecar** (needs the `sidecar` feature):

```sh
cargo build --release --features sidecar --bin saacp-sidecar
```

**2. Install the client & secure an agent in one line:**

```python
from saacp_client import wrap

agent = wrap(
    agent,                                  # your AutoGen/LangChain-style agent
    agent_id="agent-a",
    secret=b"...32 bytes shared out of band...",
    peers={"agent-b": "127.0.0.1:7444"},    # agent-b's SAACP listen address
)
agent.send("Execute the quarterly report", "agent-b")  # now routed through SAACP
```

`wrap()` finds or spawns the sidecar for you and duck-types AutoGen's `.send()/.receive()`
shape and LangChain's callable/`.run()/.invoke()` shape. Your agent never sees a
capability token, a session key, or a gate rejection code — it sends a task and gets
back `success` or `rejected`. The Python package is `saacp-client` (`requests`-only
dependency, Python ≥ 3.8).

Two places `wrap()` deliberately refuses rather than downgrading silently:

- **No secret available** raises `SaacpError` instead of generating an ephemeral one —
  that would yield an agent that looks secured but can never reach a separately-started
  peer. Opt in with `allow_ephemeral_secret=True` for single-process demos.
- **Wrapping a tool-shaped object** (callable / `.run()` / `.invoke()`) requires
  `fire_and_forget=True`, because the returned `SecuredCallable` delivers the input and
  returns a `SendResult` — it never invokes the original or returns its value. SAACP's
  Task message has no request/response channel to bridge.

Full details and production hardening (per-peer secrets, local HTTP API auth, bounded
concurrency, secret-file hygiene) are in [`python/README.md`](python/README.md).

---

## The Command Center dashboard

An optional operator dashboard shows, in real time, what a fleet of SAACP gateways is
doing: live agent trust scores, the trust-mesh delegation graph, prompt-injection
alerts, and Financial Circuit Breaker activity.

- **Backend** (`src/command_center.rs`, `command-center` feature): a REST + Server-Sent-Events
  API that runs **in-process** alongside a real daemon, subscribing to the global
  telemetry / trust / audit singletons — no cross-process IPC. Binary:
  `saacp-command-center`.
- **Frontend** (`dashboard-ui/`): a Next.js 16 / React 19 app (with D3 for the trust
  mesh graph).

```sh
cargo run --release --features command-center --bin saacp-command-center
# in another shell:
cd dashboard-ui && npm install && npm run dev
```

---

## Cargo feature flags

All features are **off by default** (`default = []`), keeping the core library lean
for embedded targets.

| Feature | Enables | Adds |
|---------|---------|------|
| `transport-ws` | WebSocket tunneling transport (survives HTTP-only proxies/CDNs) | tokio-tungstenite, bytes, futures-util |
| `transport-tls` | Raw TCP + in-protocol TLS termination | tokio-rustls, rustls-pemfile |
| `redis-backend` | Redis-shared `StateBackend` for horizontally-scaled fleets | redis |
| `sidecar` | `saacp-sidecar` HTTP proxy binary | axum |
| `command-center` | `saacp-command-center` REST+SSE dashboard backend | (reuses axum, futures-util) |
| `mpf` | Metadata Privacy Filter (cover traffic, adaptive padding, timing jitter) | — |
| `hrt-pkcs11` | **Hardware Root of Trust: PKCS#11.** Signing keys held in an on-premise HSM or token (Thales, Entrust, Utimaco, YubiHSM, SoftHSM2) — the private key never enters process memory. | cryptoki |
| `hrt-aws-kms` | **Hardware Root of Trust: AWS KMS.** `ECC_NIST_EDWARDS25519` keys; every signature lands in CloudTrail. | aws-sdk-kms, aws-config |
| `hrt-gcp-kms` | **Hardware Root of Trust: Google Cloud KMS.** `EC_SIGN_ED25519` key versions. | gcloud-sdk |
| `hrt-tpm` / `hrt-sgx` | Hardware Root of Trust seams for TPM 2.0 / Intel SGX (compile placeholders — return `NotImplemented`) | — |
| `unsafe-structural-only` | **Debug only.** Exposes unauthenticated structural header parsing. **Must never be enabled in production.** | — |

Release profile is tuned for performance: `lto = "thin"`, `codegen-units = 1`,
`opt-level = 3`. `panic = "abort"` is deliberately **not** set — a long-lived network
daemon must not turn one attacker-triggered panic on one connection into a
whole-process crash.

---

## Testing & fuzzing

The suite spans unit tests (inline `#[cfg(test)]` modules in every source file),
**56 integration/adversarial test files** under `tests/`, and **5 fuzz targets**.

**Adversarial / red-team coverage** includes:

- `tests/test_authorization_invariance_rs.rs` — every gate runs on every tier
- `tests/test_redteam.rs`, `test_production_redteam_rs.rs`, `test_acsvaf_redteam_rs.rs`
- `tests/test_blackhat_agent_hijack_rs.rs`, `test_blackhat_state_dos_rs.rs`
- `tests/breakit/` — timing side-channels, injection-scanner bypass, downgrade
  negotiation, key-material forensics, supply-chain dependency audit, concurrency
  race hunting, and a two-agent compromise scenario
- `tests/test_exploit_vulnerabilities_rs.rs`, `test_crit2_stream_gate_bypass_rs.rs`
- `tests/test_cross_lang_vectors_rs.rs` + `tests/cross_lang_verify.py` — byte-exact
  wire compatibility with the Python reference

**Fuzz targets** (`fuzz/fuzz_targets/`, run with `cargo +nightly fuzz run <target>`):
`fuzz_measc_parse_frame`, `fuzz_saacpframe_parse_header`,
`fuzz_capability_token_from_wire`, `fuzz_bypass_injection_scanner`,
`fuzz_gate_pipeline_raw`.

```sh
cargo test                              # full default suite
cargo test --features sidecar           # feature-gated tests
cargo test --features command-center
```

---

## Benchmarks

Performance is measured with [Criterion](https://github.com/bheisler/criterion.rs),
not asserted. The harness (`benches/benchmarks.rs`) covers three families:

- **Per-gate latency** (`Gate_*`) — every gate in isolation, across payload sizes.
- **End-to-end throughput** (`T1`–`T14`) — frame build, replay window, token
  issue/verify, full-pipeline, audit-log growth, sustained WAL throughput.
- **Worst-case / adversarial** (`WC1`–`WC13`) — DDoS floods, replay saturation,
  rate-limiter lockout storms, maximal injection inputs, multi-agent concurrency,
  token-exhaustion, epoch-rotation pressure, session explosion.

```sh
cargo bench                    # everything
cargo bench -- Gate_           # per-gate latency only
cargo bench -- 'T[0-9]'        # throughput only
cargo bench -- WC              # worst-case only
# HTML reports: target/criterion/*/report/index.html
```

**Measured results from an actual run on this repository are recorded in
[`benchmark_results.md`](benchmark_results.md)**, including the exact hardware, toolchain,
and Criterion point estimates — no fabricated numbers.

---

## Security model & threat coverage

SAACP assumes a hostile network **and** potentially-compromised or manipulated peers.
The protocol is **fail-closed**: any gate failure produces a `SAACPHardDrop` and the
packet is dropped, never partially processed.

| Threat | Primary defense |
|--------|-----------------|
| Passive eavesdropping | Per-frame AES-256-GCM |
| Frame tampering / bit-flipping | GCM auth tag over ciphertext + 128-byte header as AAD |
| Replay | 4096-entry PSN sliding window + nonce tracking (pre-decryption) |
| Key compromise (past/future traffic) | Forward-secret epoch key ratchet (HKDF) |
| Capability forgery | Ed25519-signed tokens, verified against a key registry |
| Privilege escalation | Gate 2.5 action-class ceiling + audit-health gating |
| Over-delegation | Delegation depth capped (ACSVAF ≤ 3, FAITF bounded) |
| Prompt injection (incl. homoglyph / zero-width / encoded) | Gate 4.0 Unicode-normalized multi-encoding scanner |
| Confused deputy / intent padding | Gate 1.5 intent envelope + 1.5c dangerous-verb check |
| Fabricated confidence | Gate 5.0 epistemic circuit breaker (overclaim + NaN rejection) |
| Runaway loops / oscillation | Gate 12.0 CSCS + Gate 11.0 AEGF hop limits |
| Cost/budget exhaustion | Gate 0.5 financial circuit breaker |
| Cryptographic downgrade | Crypto governance approved-suite policy + negotiation transcript |
| DoS via oversized/zip-bomb payloads | 10 MB MTU cap, bounded decompression, per-IP circuit breakers |
| Timing side-channels | Constant-time comparisons on signature/checksum paths |
| Collusion / Sybil | MACE collusion engine |
| Error-message information leakage | PECF opaque fixed-size wire errors |

> **Status:** this is a `0.1-beta2` research/engineering implementation. It has an
> extensive adversarial test suite and fuzz harness, but has not undergone an external
> third-party security audit. Review the threat model against your own deployment
> before production use.

---

## Project layout

```
saacp-rs/
├── src/                     # ~50 Rust modules — protocol core, gates, crypto, trust
│   ├── bin/                 # saacp-sidecar, saacp-command-center binaries
│   └── transport/           # ws.rs, tls.rs
├── benches/benchmarks.rs    # Criterion benchmark harness
├── tests/                   # 56 integration/adversarial test files
│   ├── breakit/             # red-team: timing, injection, downgrade, forensics, …
│   └── adversarial/         # agent framework + attack library
├── fuzz/                    # 5 cargo-fuzz targets
├── python/                  # saacp-client Python package + sidecar demos
├── dashboard-ui/            # Next.js 16 / React 19 Command Center frontend
├── Cargo.toml               # crate + feature definitions
├── README.md                # this file
└── benchmark_results.md     # measured benchmark results (real numbers)
```

---

## License

MIT. See [`LICENSE`](LICENSE).

---

*Protocol version `SAACP/0.1-beta2` · crate version `0.1.0` · Ed25519 + AES-256-GCM + HKDF-SHA256.*
