# SAACP-rs Production Readiness Audit (v0.2.0, commit c48f018)

Audit date: 2026-09-06. Scope: full repo — ~62,900 LOC `src/` across ~65 modules, 60
integration/adversarial test files, 5 fuzz targets, 2 binaries, Python client, dashboard
UI. Assessment only — no code changes accompany this document.

---

## 1. Production Readiness Rating: **6.5 / 10** — "hardened prototype, pilot-ready; not fleet-grade yet"

| Dimension | Score | Justification |
|---|---|---|
| Security | 8/10 | Genuinely strong defense-in-depth: mandatory 8-gate pipeline (`handler::MANDATORY_GATES`: crypto-integrity, token validation, intent envelope, kinetic firewall, lateral-movement, injection scan, epistemic CB, audit checkpoint) plus 6 auxiliary gates. `SAACPNetworkDaemon::new()` is secure-by-default (Ed25519-authenticated handshake + AES-256-GCM per-frame AEAD bound to (session, epoch, psn) via HKDF — daemon.rs:438-461); the permissive path is quarantined in `insecure_for_testing` with a loud banner. `#![forbid(unsafe_code)]`, `overflow-checks=true` in release, constant-time compares, `zeroize` on key material, bounded memory everywhere (every store capped, sweep-on-overflow), fail-closed audit (Gate 2.5 blocks IRREVERSIBLE actions when audit health degrades). Minus: sidecar defaults to the forgeable shared-mesh-secret mode (per-peer secrets + `REQUIRE_PEER_SECRETS` are opt-in), library `SidecarHandshakeMode` default stays `LegacyOnly` for wire compat, security alerts never leave the process. |
| Scalability | 5/10 | Single-node ceiling by default. The PSN replay window (4096, per-packet mutex) is deliberately node-local; Redis sharing is **library-API only — neither shipped binary ever constructs a backend, and the Docker image doesn't even compile the `redis-backend` feature**. Multi-node requires mandatory LB affinity (documented), one operator-designated audit node (visibility only — no election, finding H). Gossip is fire-and-forget with per-send OS-thread spawning; cluster membership is SWIM-style with deterministic lowest-hash leadership + optional 5s CAS lease — **no real consensus**, and transient double-leadership is acknowledged in the module doc. MACE off by default. |
| Maintainability | 8/10 | ~700 inline unit tests + 60 integration files (incl. red-team suites, timing side-channels, two-agent compromise, cross-language wire vectors, pinned audit fixture), 1,891 tests green all-features / 1,760 default. CI: fmt/clippy/test matrix (ubuntu+windows)/cargo-deny/coverage/bench/fuzz-smoke/nightly-fuzz. MSRV+toolchain pinned, SECURITY.md + CHANGELOG hygiene are exemplary (every fix carries a fails-before/passes-after regression test). Minus: `handler.rs` at 4,540 lines and a 62k-LOC single crate; dashboard UI is demo-grade (mixed TS/JSX, no tests, not in CI); Python suite is one file. |
| Performance | 7.5/10 | Measured, not vibes: gate rejections in ns–µs (Gate 0: 179 ns; Gate 4.0 scan ≤16 KB: ~575-660 µs worst adversarial; full e2e valid packet 259 µs), bounded scan windows (16 KB cap, 3 decode layers, S10 50 ms full-scan budget with tail guarantee), LTO thin + codegen-units=1. Minus: every Python `send()` costs a full TCP+ECDH handshake (one-shot sessions); audit fsync window is 200 entries/50 ms not per-entry; the promised full WC4 realistic-traffic campaign is still deferred (spot-run done at v0.2.0). |
| Operations | 6/10 | `/healthz`, `/readyz` (affinity + audit posture), `/metrics` (~28 Prometheus families), bearer-always `/api/audit/ack`, distroless-nonroot Docker, TOML config with structural secret-hygiene, graceful 30s drain, startup security-posture banner. Minus: **no external alert sink** (SecurityAlertFeed is in-process; only Prometheus scrape or SSE dashboard), **audit-chain recovery on startup is implemented but never called by any binary** (`initialize_chain()` has zero call sites), demo daemon + synthetic activity generator **on by default** in the command-center binary, no k8s manifests, `health-endpoint`/`redis-backend` features missing from the Docker build. |

**Verdict:** For a single-host or pilot deployment with the hardened profile (per-peer
secrets, `REQUIRE_PINNED`, bearer tokens, audit node designated), this is deployable
today with unusual confidence for a v0.2.0. It is **not** ready for large multi-node
fleets, regulated environments requiring external audit-sink integrations, or unattended
scale-out — primarily for state-sharing, consensus, and alerting reasons, not
cryptographic ones. The score also reflects zero production mileage and no independent
third-party audit.

---

## 2. Gap Analysis

**G1 — Audit-chain recovery is unwired (correctness + forensics).**
`ImmutableAuditLog::initialize_chain()` (security.rs:1146) with its verify-before-adopt
logic exists but no binary calls it. A restarted daemon starts from an empty in-memory
chain; the on-disk chain can only be verified offline via `verify_chain_disk`. Restart =
loss of the in-memory ring (up to 100k entries) and chain continuity in the live process.

**G2 — No external security-alert delivery.** `SecurityAlertFeed` (2,000-entry ring,
telemetry.rs:1917) notifies in-process subscribers only. No syslog/OTLP/webhook/Sentry
sink exists. An operator without a Prometheus scraper or the dashboard sees nothing in
real time.

**G3 — Fleet state-sharing is library-only.** Redis backend (rate-limit error sharing,
FederatedMemory, DeadMansSwitch trip events, cluster lease) is unreachable from
`saacp-sidecar`/`saacp-command-center`; Docker omits the feature. The documented
multi-node posture therefore reduces to "LB affinity + designated audit node" with all
engine state partitioned per node.

**G4 — Two unbounded-by-default resource controls.** M4 in-flight payload budget
(`inflight_payload_semaphore: None` = up to 10,000 conns × 10 MB aggregate) and M12
gate-pipeline concurrency (unbounded `spawn_blocking` pool) are opt-in
(daemon.rs:406-409, 1633-1650). `SessionAffinityTracker` and `InMemoryBackend` maps have
no cap/TTL (session_affinity.rs:17, state_backend.rs:235).

**G5 — Gossip reliability is nominal.** Ack-less fanout-3/multi-hop with
`GOSSIP_SEND_RETRIES=0` compile-time const; `StaticPeerListTransport` spawns a detached
thread per send per peer (gossip.rs:385) — unbounded thread creation under a revocation
storm; SeenSet eviction sorts a 100k map under lock at cap.

**G6 — Unsafe-ish defaults footguns.** Shared-mesh-secret sidecar mode is the zero-config
default (warning only); `SAACP_ALLOW_UNAUTHENTICATED_HTTP=1` exists for legacy;
command-center demo daemon + fake activity default-on risks "real" dashboards fed by
synthetic data; Windows token-out file lacks 0600.

**G7 — Client ecosystem is thin.** Python client is a plain HTTP wrapper (one test file)
with per-send handshake cost; no Go/JS clients; dashboard untested; no Helm/k8s charts;
no load/chaos test harness.

**G8 — Verification debt.** Local fuzz execution impossible on the development Windows
host (documented); fuzz coverage depends on CI Linux runners. Full WC4 campaign deferred.
No external penetration test or formal verification of the crypto core.

---

## 3. Risk Assessment

| # | Risk | Severity | Likelihood | Trigger scenario |
|---|---|---|---|---|
| R1 | Audit continuity gap across restart (G1) | High | Medium | Crash/OOM/rotation during peak; post-incident forensics needs offline `verify_chain_disk`; in-flight ring contents lost |
| R2 | Silent security events without a scraper (G2) | High | Medium | Operator runs binaries standalone; gate rejections/lockouts/alerts never seen until a Prometheus scrape exists |
| R3 | Per-node state divergence in multi-node fleet (G3) | High | High | Fleet scales past 1 node: replay windows, trust, rate limits all partitioned; affinity misconfig degrades replay protection silently (mitigated by AlertOnly counter, but default policy is alert-not-block) |
| R4 | Memory/CPU exhaustion under load (G4) | Medium-High | Medium | Attacker opens many connections each holding large in-flight payloads; blocking-pool growth; long-lived fleets grow affinity map unboundedly |
| R5 | Revocation-storm self-DoS (G5) | Medium | Low-Medium | Mass token revocation → thread-per-send explosion; lag alert (>300s) fires but retries default off |
| R6 | Sidecar mesh-wide forgery (G6) | High | Medium | Zero-config deployment uses shared HMAC secret; one compromised sidecar forges any agent (documented; `REQUIRE_PEER_SECRETS` opt-in) |
| R7 | Demo data mistaken for production telemetry (G6) | Medium | Medium | Command-center used as ops console without `SAACP_DISABLE_DEMO_DAEMON=1` |
| R8 | Downgrade/compat pressure (LegacyOnly library default, v1 python-parity IV `SHA-256(nonce‖session)`) | Medium | Low | Embedders keep LegacyOnly; the 101-byte legacy frame's IV derivation is weaker than the MEASC one |
| R9 | Redis becomes a sync dependency when wired (250 ms timeout per call, no redis-side circuit breaker) | Medium | Medium | Redis degradation stalls gates at 250 ms/call even in "fail-safe" fallback mode |
| R10 | Supply chain / dependency surface (aws-sdk, gcloud-sdk, tonic, redis — feature-gated but compiled all-features in CI and shipped Docker) | Medium | Low | Compromised upstream; `deny.toml` reviewed but Rust supply-chain assurance is limited |
| R11 | Key-management operational gap: server seed ephemeral by default (fresh per boot), pins via files, no HSM integration wired by default (hrt-* features exist but are library-level) | Medium | Medium | Restart invalidates pinned trust unless `SAACP_SERVER_SEED_FILE` set; operators miss it |
| R12 | Single audit node is a SPOF by design (visibility-only designation, no replication of the chain) | Medium-High | Medium | Audit node dies → fleet loses the fail-closed Gate 2.5/6.0 interlock reference point; chain exists only on that host |

**Verified non-issues:** nonce reuse (MEASC IV bound to unique psn within a 4096 replay
window + epoch rotation at 600 s/2^20 packets); panic-DoS (per-connection JoinError
flattening → HardDrop, daemon.rs:1758); release integer overflow (overflow-checks=true);
unsafe memory (`forbid`); zip-bomb (bounded decompression). Remaining non-test
`expect`/`unwrap` sites in the crypto core are documented fail-closed invariants (HKDF
length asserts, poisoned-lock refusal).

---

## 4. Mitigation Strategies

**M-A (R1, G1):** Wire `initialize_chain()` into both binaries' startup: load
`SAACP_AUDIT_LOG`, verify chain, adopt as live log, refuse to start (or start in
degraded mode with explicit operator flag) if verification fails. Add a regression test:
restart a daemon against a pre-populated chain and assert continuity of `verify_chain` +
dropped-audit accounting. Effort: days; highest value-per-line in the repo.

**M-B (R2, G2):** Add an `AlertSink` trait beside `SecurityAlertFeed` (async,
non-blocking, bounded queue like the audit WAL) with three impls: webhook (JSON POST),
syslog (RFC 5424), OTLP. Fail-open delivery with drop counter exported as
`saacp_alert_sink_dropped_total`. Wire into both binaries via one `SAACP_ALERT_WEBHOOK` /
`SAACP_ALERT_SYSLOG` config key in `SaacpConfig`.

**M-C (R3, G3):** Ship binaries with state-sharing: add `[sidecar.state_backend]` to
`SaacpConfig` (`url_file` only, keep the plaintext-redis refusal), construct
`RedisBackend` in `main()`, call the existing `*_with_backend`/`set_global_backend`
APIs. Enable `redis-backend` + `health-endpoint` in the Dockerfile feature list.
Document which engines actually share (rate-limit errors, memory, trips) vs stay
node-local (PSN window) in the deployment guide.

**M-D (R4, G4):** Flip the safe defaults: default `inflight_payload_semaphore` to a sane
byte budget (e.g. 512 MiB) and `pipeline_semaphore` to ~num_cpus×4, with env/TOML
overrides; add cap+TTL+sweep to `SessionAffinityTracker` (reuse the 10k/sharded idiom
used everywhere else) and a max-entries bound on `InMemoryBackend`. These change
defaults, so gate behind a documented "hardened defaults" profile flag to honor the
byte-identical-defaults convention.

**M-E (R5, G5):** Replace thread-per-send in `StaticPeerListTransport` with a small
bounded worker pool (or spawn a tokio task on the existing runtime); make
`GOSSIP_SEND_RETRIES` a runtime config knob defaulting to 0; export
`saacp_gossip_send_failures_total` so the >300s lag alert has a companion metric.

**M-F (R6, R8):** Make the secure postures the binary defaults and the weak ones
explicit: flip `saacp-sidecar` to warn-and-require-ack for shared-secret mode (e.g.
refuse without `SAACP_ACCEPT_SHARED_SECRET_RISK=1` in a future 0.3), keep
`REQUIRE_PINNED` reachable via config file; roadmap deprecation of the 101-byte
python-parity IV path (negotiate MEASC IV in v2 wire version).

**M-G (R7):** Flip `SAACP_DISABLE_DEMO_DAEMON` default to disabled-with-banner, or
require `SAACP_DEMO_MODE=1` to enable synthetic activity; gate the demo behind a `demo`
cargo feature so the shipped binary can't produce synthetic data at all.

**M-H (R9):** Wrap `RedisBackend` calls in a dedicated circuit breaker (open after N
consecutive timeouts, half-open probe) so a dead Redis costs one 250 ms probe per
interval, not per call; export breaker state as a gauge.

**M-I (R11):** Add a startup check: if `server_seed` is ephemeral and any peer pins
exist, print a hard warning (pins will mismatch after restart); document + compose-example
the seed-file flow; keep hrt-* HSM features on the roadmap for key custody.

**M-J (R12):** Document and tool the audit-node failover runbook (ship the chain file +
`verify_chain_disk`-verified handover script); optionally add chain-replication via the
existing gossip channel (anchor lines are already small) as the first real consensus use
of the cluster lease.

**M-K (G7, G8):** Ship a Helm chart/k8s manifests encoding the mandatory affinity +
audit-node + probe rules; expand the Python suite beyond `test_wrap.py` and add a
keep-alive session mode to the sidecar HTTP API to amortize the per-send handshake;
schedule the full WC4 campaign and an external pen test as 0.3 gate items; run the fuzz
suite on Linux CI artifacts and publish corpus snapshots.

**Suggested sequencing:** M-A, M-C(Docker features), M-G are small and close the
highest-severity gaps → 0.2.1. M-B, M-D, M-E → 0.3. M-F/M-I/M-J policy+roadmap items →
0.3-0.4.
