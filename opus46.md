# opus46.md — Remaining Gaps: Detailed Fix Plan

> **Purpose**: This document lists EVERY remaining gap, bug, and pending fix
> after the first execution pass of the production readiness audit. It is
> written so that any competent model can execute each item precisely by
> following the instructions verbatim.

---

## Status Summary

| Item | Status | Blocking? |
|------|--------|-----------|
| M1 — Audit chain recovery default | ✅ DONE | — |
| M3 — Circuit breaker StateBackend | ✅ DONE | — |
| M4 — PreferPinned sidecar default | ✅ DONE | — |
| M5 — Webhook alert sink | 🔴 **BUG** | Yes — compile failure |
| G7 — CI coverage threshold 70% | ✅ DONE | — |
| M2 — Config schema + binary wiring | ❌ NOT STARTED | No |
| M8 — Kubernetes Helm chart | ❌ NOT STARTED | No |
| M9 — Dashboard UI CI job | ❌ NOT STARTED | No |
| Compile + test verification | ❌ NOT STARTED | Yes |

---

## 🔴 CRITICAL BUG: M5 WebhookAlertSink uses `reqwest` (dev-only dependency)

### Problem

`src/alert_sink.rs` at lines ~196–200 uses `reqwest::Client` for HTTP POSTs.
However, `reqwest` is declared ONLY in `[dev-dependencies]` in `Cargo.toml`
at line 252:

```toml
[dev-dependencies]
reqwest = { version = "0.12", default-features = false, features = ["json", "rustls-tls", "stream"] }
```

This means `cargo build --release` (and any non-test compilation) will **fail to
compile** `alert_sink.rs` because `reqwest` is not available at build time.

### Fix (recommended: feature-gate the webhook behind a new feature)

#### Step 1: Add `reqwest` as an optional runtime dependency

In `Cargo.toml`, add this line AFTER line 82 (`redis = ...`) in the
`[dependencies]` section:

```toml
reqwest = { version = "0.12", optional = true, default-features = false, features = ["json", "rustls-tls"] }
```

Note: remove the `"stream"` feature (not needed for webhook POSTs). The
`dev-dependencies` entry stays as-is (tests may still use the full feature set).

#### Step 2: Add a new feature flag

In `[features]` section (after line 155 `redis-backend = ["dep:redis"]`), add:

```toml
# M5: HTTP webhook alert sink (alert_sink.rs::WebhookAlertSink). Off by default
# so deployments that don't need webhook alerts never pull in reqwest.
webhook-alerts = ["dep:reqwest"]
```

#### Step 3: Gate the WebhookAlertSink behind `#[cfg(feature = "webhook-alerts")]`

In `src/alert_sink.rs`:

1. Find the line `// ─── WebhookAlertSink (M5 remediation) ───` (around line 128).
2. Wrap the ENTIRE block (from that comment through the closing `}` of
   `impl WebhookAlertSink`) inside a `cfg` gated module:

```rust
#[cfg(feature = "webhook-alerts")]
mod webhook {
    use super::*;
    use std::sync::OnceLock;

    static WEBHOOK_SINK: OnceLock<WebhookAlertSink> = OnceLock::new();

    /// The process-wide webhook sink, when installed.
    pub fn webhook_sink() -> Option<&'static WebhookAlertSink> {
        WEBHOOK_SINK.get()
    }

    // ... (rest of WebhookAlertSink struct, const, WebhookPayload, impl block)
    // Copy EVERYTHING from the current code between the WebhookAlertSink
    // comment and end of the impl block. Just move it here as-is.
}

#[cfg(feature = "webhook-alerts")]
pub use webhook::{webhook_sink, WebhookAlertSink};
```

Remove the un-gated `static WEBHOOK_SINK`, `pub fn webhook_sink()`, 
`pub struct WebhookAlertSink`, etc. that currently exist outside the module —
they all move INTO the module.

#### Step 4: Gate the call sites

**In `src/telemetry.rs`** — find the M5 emit block (around line 2088–2093):

```rust
// M5 remediation: best-effort forwarding to the process-wide webhook
if let Some(sink) = crate::alert_sink::webhook_sink() {
    sink.emit(&alert);
}
```

Wrap it:

```rust
#[cfg(feature = "webhook-alerts")]
{
    if let Some(sink) = crate::alert_sink::webhook_sink() {
        sink.emit(&alert);
    }
}
```

**In `src/daemon.rs`** — find the M5 wiring block (around line 1153–1170):

```rust
// M5 remediation: optional webhook alert sink.
if let Ok(url) = std::env::var("SAACP_ALERT_WEBHOOK") {
    ...
}
```

Wrap the entire `if let` in:

```rust
#[cfg(feature = "webhook-alerts")]
{
    if let Ok(url) = std::env::var("SAACP_ALERT_WEBHOOK") {
        // ... existing code ...
    }
}
```

#### Step 5: Enable in Dockerfile

In `Dockerfile` at line 32, add `webhook-alerts` to the feature list:

```dockerfile
RUN cargo build --release --bins --features "transport-ws transport-tls sidecar command-center health-endpoint webhook-alerts"
```

Also update the comment at lines 30–31 to note that `webhook-alerts` is now
included.

---

## ❌ M2 — Config Schema + Binary Wiring for RedisBackend

### What this does

Allows the sidecar binary to use an external Redis as its `StateBackend` instead
of the default in-memory backend, so that a horizontally-scaled fleet shares
rate-limiter/session/stream state.

### Step 1: Add field to `SidecarSection`

In `src/config.rs`, find `pub struct SidecarSection` (line 105). After
line 121 (`pub enable_mace: Option<bool>,`), add:

```rust
    /// M2 remediation: path to a file containing a Redis URL (e.g.
    /// `rediss://user:pass@host:6379/`). The URL itself is secret material
    /// (may contain credentials), so only a file path is accepted — no raw
    /// URL in TOML or env. When set, the sidecar constructs a
    /// `RedisBackend` wrapped in `CircuitBreakerBackend` and passes it to
    /// the gateway.
    pub state_backend_url_file: Option<String>,
```

### Step 2: Add validation

In `SaacpConfig::validate()` (same file), after the existing address
validation loop, add:

```rust
if let Some(ref path) = self.sidecar.state_backend_url_file {
    if path.trim().is_empty() {
        return bad("sidecar.state_backend_url_file must not be empty when set".to_string());
    }
}
```

### Step 3: Add to `redacted_summary()`

In `redacted_summary()`, find the block that iterates over sidecar string
fields. Add `state_backend_url_file` to the list:

```rust
("state_backend_url_file", s.state_backend_url_file.as_deref()),
```

### Step 4: Wire into sidecar binary

In `src/bin/saacp_sidecar.rs`, after the maintenance coordinator setup and
BEFORE the `run_with_shutdown` call (around line 704), add:

```rust
#[cfg(feature = "redis-backend")]
{
    if let Some(url_file_path) = saacp::config::resolve(
        "SAACP_STATE_BACKEND_URL_FILE",
        bin_cfg.sidecar.state_backend_url_file.as_deref(),
    ) {
        let url = std::fs::read_to_string(url_file_path.trim())
            .unwrap_or_else(|e| {
                eprintln!(
                    "[saacp-sidecar] FATAL: could not read state backend URL file \
                     {}: {e}",
                    url_file_path.trim()
                );
                std::process::exit(1);
            })
            .trim()
            .to_string();
        let backend = saacp::state_backend::RedisBackend::new(&url)
            .unwrap_or_else(|e| {
                eprintln!("[saacp-sidecar] FATAL: RedisBackend::new failed: {e}");
                std::process::exit(1);
            });
        let breaker = saacp::state_backend::CircuitBreakerBackend::wrap(backend);
        eprintln!(
            "[saacp-sidecar] state backend: Redis (circuit-breaker wrapped) \
             from file {}",
            url_file_path.trim()
        );
        // NOTE: Check how the gateway accepts a backend. Search for
        // `with_backend` or `set_backend` in gateway.rs. Wire it here.
        // If `ZeroTrustGateway::global()` has a setter, use it.
        // Otherwise the backend may need to be passed through
        // `SidecarConfig` — add a field there.
    }
}
```

> **IMPORTANT**: Before writing this code, search `src/gateway.rs` for
> `set_backend`, `with_backend`, or how the gateway currently gets its
> `StateBackend`. The sidecar's `run_with_shutdown()` constructs a
> `SAACPNetworkDaemon` internally — look at how it wires the gateway and
> adapt. The exact wiring depends on the gateway's current API.

### Step 5: Enable `redis-backend` in Dockerfile

In `Dockerfile` line 32, add `redis-backend` to the feature list:

```dockerfile
RUN cargo build --release --bins --features "transport-ws transport-tls sidecar command-center health-endpoint webhook-alerts redis-backend"
```

Update the comment at lines 30–31: remove the sentence about `redis-backend`
being deliberately NOT enabled.

### Step 6: Add config tests

In `config.rs`'s `#[cfg(test)] mod tests`, add a test verifying that an empty
`state_backend_url_file` fails validation and a non-empty one passes.

---

## ❌ M8 — Kubernetes Helm Chart

### What this does

Creates a minimal Helm chart under `deploy/helm/saacp/` that encodes all README
deployment guidance as machine-readable k8s resources.

### Files to create (4 total)

#### 1. `deploy/helm/saacp/Chart.yaml`

```yaml
apiVersion: v2
name: saacp
description: SAACP (Secure Autonomous Agent Communication Protocol) sidecar + command center
type: application
version: 0.2.2
appVersion: "0.2.2"
```

#### 2. `deploy/helm/saacp/values.yaml`

```yaml
image:
  repository: ghcr.io/shashankv762/saacp
  tag: ""
  pullPolicy: IfNotPresent

sidecar:
  replicaCount: 2
  port: 7443
  httpPort: 8787
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

commandCenter:
  enabled: true
  port: 9090
  replicaCount: 1
  resources:
    requests:
      cpu: 100m
      memory: 128Mi
    limits:
      cpu: 500m
      memory: 512Mi

health:
  enabled: true
  port: 9091

secrets:
  tokenSecret:
    secretName: saacp-token-secret
    key: token-secret
  peerSecrets:
    secretName: saacp-peer-secrets
    key: peers.json
  redisUrl:
    secretName: ""
    key: redis-url

auditNode:
  enabled: true

config: {}
```

#### 3. `deploy/helm/saacp/templates/deployment.yaml`

Create a StatefulSet resource for the sidecar. Key requirements:
- Use `{{ .Values.image.repository }}:{{ .Values.image.tag | default .Chart.AppVersion }}`
- Mount secrets via projected volumes from `values.secrets.*`
- Set env vars: `SAACP_LISTEN_ADDR`, `SAACP_HTTP_ADDR`, `SAACP_TOKEN_SECRET_FILE`,
  `SAACP_PEER_SECRETS_FILE`, `SAACP_REQUIRE_PEER_SECRETS=1`, `SAACP_HANDSHAKE_MODE=PREFER_PINNED`
- Conditionally mount `redis-url` secret when `secrets.redisUrl.secretName` is set
- Add liveness/readiness probes on `/healthz` and `/readyz` when `health.enabled`
- Use `{{ .Values.sidecar.resources }}` for resource limits

#### 4. `deploy/helm/saacp/templates/service.yaml`

Create a ClusterIP service exposing:
- `saacp` port (7443)
- `http` port (8787)

Use standard label selectors matching the StatefulSet.

---

## ❌ M9 — Dashboard UI CI Job

### What this does

Adds a CI job that builds the Next.js dashboard UI on every push/PR, catching
TypeScript and build errors before they reach main.

### File to modify

`.github/workflows/ci.yml`

At the END of the file (after the `fuzz-nightly` job, line 237), append:

```yaml

  # ── Dashboard UI (lint + build) ──────────────────────────────────────────
  # M9 remediation (production audit G5): the dashboard-ui Next.js codebase
  # was not part of CI — TypeScript errors and build regressions were only
  # caught locally. This job runs `npm ci && npm run build` on every push/PR.
  dashboard:
    name: Dashboard UI (build)
    runs-on: ubuntu-latest
    defaults:
      run:
        working-directory: dashboard-ui
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: '20'
          cache: 'npm'
          cache-dependency-path: dashboard-ui/package-lock.json
      - run: npm ci
      - run: npm run build
```

---

## Verification Plan

After all changes above are applied, run these commands to verify:

### 1. Build with default features (must pass)

```powershell
$env:CARGO_TARGET_DIR="R:\saacp-rs-target"; $env:RUST_LOG="warn"
cargo build 2>&1 | Select-Object -Last 5
```

### 2. Build with all features (must pass)

```powershell
$env:CARGO_TARGET_DIR="R:\saacp-rs-target"; $env:RUST_LOG="warn"
cargo build --all-features 2>&1 | Select-Object -Last 5
```

### 3. Run all tests

```powershell
$env:CARGO_TARGET_DIR="R:\saacp-rs-target"; $env:RUST_LOG="warn"; $env:SAACP_TEST_LOG_DIR="R:\"
cargo test --all-features 2>&1 | Select-Object -Last 20
```

### 4. Clippy clean

```powershell
$env:CARGO_TARGET_DIR="R:\saacp-rs-target"
cargo clippy --all-targets --all-features -- -D warnings 2>&1 | Select-Object -Last 10
```

### 5. Specific test cases to verify

```powershell
# M1: audit chain recovery default
cargo test audit_chain --all-features

# M3: circuit breaker
cargo test circuit_breaker --all-features

# M4: handshake default
cargo test default_handshake_mode --all-features

# Config validation
cargo test config --all-features
```

### 6. Clean RAM disk after all tests pass

```powershell
if (Test-Path "R:\saacp-rs-target") { Remove-Item -Recurse -Force "R:\saacp-rs-target" }
```

---

## Execution Order

1. **M5 bug fix** (CRITICAL — blocking compilation)
2. **M2** — Config schema + binary wiring
3. **M8** — Helm chart (new files only, no risk)
4. **M9** — Dashboard CI (append to ci.yml, no risk)
5. **Verification** — build + test + clippy
6. **RAM disk cleanup**
