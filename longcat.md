Now I have a thorough understanding of the codebase. Let me compile the comprehensive technical audit.

---

# SAACP-RS Production Readiness Audit

## 1. Production Readiness Rating: **6.8 / 10**

### Justification

| Dimension | Score | Rationale |
|-----------|-------|-----------|
| **Security** | 8.0/10 | 12-gate pipeline with defense-in-depth, AES-256-GCM, Ed25519, HMAC-SHA256, constant-time comparisons, PECF error confidentiality, SREL timing equalization, replay windows, circuit breakers, identity binding, and extensive red-team test coverage. |
| **Scalability** | 6.0/10 | Sharded audit log (16 shards), `ArcSwap` for lock-free config reads, connection pooling, byte-budget semaphore. However: global singletons remain for several subsystems (AEGF, CSCS, DeadMansSwitch, FederatedMemory), `spawn_blocking` per packet serializes the hot path, and no horizontal clustering of the gateway itself. |
| **Maintainability** | 7.5/10 | Excellent documentation, `#![forbid(unsafe_code)]`, consistent error types, 60+ focused modules, comprehensive test suite (55+ test files). However: ~2.4MB of source, some functions exceed 800 lines, and the `intercept_packet_*` family has 9-argument signatures. |
| **Performance** | 5.5/10 | Aho-Corasick automaton for injection scanning, `Arc<str>` cloning, hash caching. But: JSON payload is parsed TWICE (once for gate pipeline, once for Gate 9.0 schema validation — the `parsed_payload_json` optimization only partially mitigates this), `SystemTime::now()` called multiple times per packet, and the full 12-gate pipeline runs synchronously on a `spawn_blocking` thread. |

The codebase demonstrates **exceptional security engineering** for a v0.1-beta2 protocol library but carries architectural debt in the hot-path performance and global-singleton coupling that would limit throughput in a high-volume production deployment.

---

## 2. Gap Analysis

### Gap A: Dual JSON Parsing on Every Packet

**Location:** `handler.rs` lines 2367-2388 (first parse) and lines 2856-2905 (Gate 9.0 re-parse)

The payload is first parsed into `HashMap<String,JsonValue>` for the gate pipeline, then Gate 9.0 re-validates the same bytes against `PreCompiledSchemas`. The `parsed_payload_json` `Option` is a partial fix but still requires the first parse to succeed for the second to be free.

**Impact:** ~2× serde_json cost per non-binary packet. At 10K packets/sec, this is measurable CPU.

**Recommendation:** Unify into a single parse that produces both the `JsonValue` tree and validates the schema in one pass, or cache the parsed `serde_json::Value` and pass it through the pipeline instead of converting to `HashMap<String,JsonValue>`.

### Gap B: Global Singleton Coupling

**Location:** `context.rs` documents 30+ historical globals; `handler.rs` still calls `DeadMansSwitch::global()`, `FederatedMemory::global()`, `IntentDriftTracker::global()`, `IevlEngine::global()`, `GLOBAL_CSCS`, `GLOBAL_AEGF_GOVERNOR`, `GLOBAL_IDENTITY_GATE`.

**Impact:** Multi-tenant isolation is incomplete. Tests must use `serial_test` to avoid cross-talk. Horizontal scaling within a process is impossible.

**Recommendation:** Extend `SaacpContext` to own these remaining globals, or document a clear migration path with a deadline.

### Gap C: Synchronous Gate Pipeline on `spawn_blocking`

**Location:** `daemon.rs` wraps the entire gate pipeline in `tokio::task::spawn_blocking`.

**Impact:** Each connection occupies a blocking-pool thread for the full gate-pipeline duration. Under load, the blocking pool (default 512 threads) becomes the throughput ceiling, and latency spikes as threads queue.

**Recommendation:** Refactor the gate pipeline into an async-native design where only the genuinely CPU-bound steps (AES-GCM, HMAC) run on `spawn_blocking`, and the rest (gate checks, audit append) run on the async executor.

### Gap D: No Backpressure on Audit WAL

**Location:** `security.rs` — `try_send` on the WAL channel drops events silently when the queue is full (100K capacity).

**Impact:** Under a burst that fills the WAL queue, audit events are dropped without any signal to the caller. Gate 6.0's `AuditHealth` metric reflects queue depth but the handler does not block or reject when the queue is saturated — it just drops.

**Recommendation:** Either block the pipeline when the WAL is saturated (backpressure) or expose a `dropped_audits` counter that Gate 2.5's health check can consult to fail closed.

### Gap E: Missing Observability Integration

**Location:** `telemetry.rs` exposes counters and histograms but no OpenMetrics/HTTP scrape endpoint is wired into the daemon by default.

**Impact:** Operators must build their own telemetry export. The `command-center` binary provides an SSE API but it's opt-in and separate.

**Recommendation:** Embed a `/metrics` Prometheus endpoint directly in the daemon when a `metrics` feature is enabled.

---

## 3. Risk Assessment

### Risk 1: TOCTOU in `NonceTracker::track_key` (MEDIUM)

**Location:** `security.rs` lines 306-339

The `contains_key` + `insert` is done under a single `lock()`, which is correct. However, the pruning logic at line 321-336 runs *inside* the same lock acquisition. Under a sustained flood of 100K unique nonces, the `retain()` pass iterates the entire `HashMap` while holding the lock, blocking all other threads.

**Exploit:** An attacker sending 100K unique nonces/sec causes the lock hold time to spike from microseconds to milliseconds, creating a self-inflicted DoS.

### Risk 2: `SystemTime::now()` Called 3-5 Times Per Packet (LOW-MEDIUM)

**Location:** `handler.rs` lines 1907, 2396, 2924, and `daemon.rs` multiple sites

Each `SystemTime::now()` is a syscall (vDSO-optimized but not free). The codebase acknowledges this with `pregate_now` and `pipeline_now_secs` sharing, but `FederatedMemory::fetch_context_by_hex`, `DeadMansSwitch::ping`, and `trust_decay` each take their own timestamp.

**Impact:** ~5 syscalls/packet × 10K packets/sec = 50K syscalls/sec. Not catastrophic but unnecessary.

### Risk 3: Unbounded `payload_dict` Allocation (MEDIUM)

**Location:** `handler.rs` line 2373-2376

The JSON payload is deserialized into a `HashMap<String,JsonValue>` where each key and value is heap-allocated. An attacker can craft a payload with 1M unique keys, each mapping to a nested object, causing unbounded memory allocation *after* AES-GCM authentication but *before* any depth/size limit is checked on the dict itself.

**Exploit:** A legitimate authenticated agent (or a compromised one) sends a 10MB JSON payload with 1M keys. The `MAX_PAYLOAD_SIZE` (10MB) check passes, but the resulting `HashMap` consumes 100MB+ of RAM.

### Risk 4: `serde_json::Value` Recursion in `serde_value_to_json_value` (LOW)

**Location:** `handler.rs` — `serde_value_to_json_value` is called for every JSON value during payload dict construction.

The `JsonValue` enum in handler.rs has `MAX_DEPTH = 8` for scanning, but the *construction* of the `JsonValue` from `serde_json::Value` does not enforce this depth limit. A deeply nested JSON payload (depth 1000) could overflow the stack during recursive conversion.

### Risk 5: Audit Log Rotation Race (LOW)

**Location:** `security.rs` — `WalWriter::maybe_rotate` and the archival thread

If the archival thread is slow (e.g., writing to a network filesystem), the rotated `.bak` file may not be fully compressed before the next rotation event. The code handles this with atomic renames, but a crash between rename and compression leaves an uncompressed `.bak` file that is not cleaned up.

### Risk 6: `extract_token_sig_hex` Fallback Path (MEDIUM)

**Location:** `handler.rs` line 2475

When no `ZeroTrustGateway` is injected, the token validation falls back to `extract_token_sig_hex` which performs a hand-rolled token parse. This path is documented as "test/daemon-less mode" but the `intercept_packet` public API (used by the daemon when no gateway is configured) routes through it. A production deployment that forgets to call `with_gateway()` silently runs without real token verification.

---

## 4. Mitigation and Remediation Plan

### Fix 1: Single-Pass JSON Parse with Schema Validation

Replace the dual-parse with a single pass that validates the schema while building the `JsonValue` tree:

```rust
// In handler.rs — replace the payload_dict construction + Gate 9.0 re-parse
// with a single unified function:

fn parse_and_validate_payload(
    payload: &[u8],
    schema_id: u16,
) -> Result<(HashMap<String, JsonValue>, serde_json::Value), SAACPHardDrop> {
    let s = std::str::from_utf8(payload).map_err(|_| {
        SAACPHardDrop::new(SAACPBytecodes::SchemaMismatch, "payload is not valid UTF-8")
    })?;
    let json_val: serde_json::Value = serde_json::from_str(s).map_err(|_| {
        SAACPHardDrop::new(SAACPBytecodes::SchemaMismatch, "payload is not valid JSON")
    })?;
    // Schema validation happens on the raw serde_json::Value
    PreCompiledSchemas::validate_payload(schema_id, &json_val)?;
    // Only if schema passes, build the HashMap for downstream gates
    let mut map = HashMap::new();
    if let serde_json::Value::Object(obj) = &json_val {
        for (k, v) in obj {
            map.insert(k.clone(), serde_value_to_json_value(v.clone()));
        }
    }
    Ok((map, json_val))
}
```

This eliminates the second parse entirely and ensures schema validation happens before the expensive HashMap construction.

### Fix 2: Bounded Depth During JsonValue Construction

Add a depth limit to the `serde_value_to_json_value` conversion:

```rust
fn serde_value_to_json_value_depth_limited(
    val: serde_json::Value,
    depth: usize,
) -> Option<JsonValue> {
    if depth > 8 {
        return None; // or reject the whole packet
    }
    Some(match val {
        serde_json::Value::Null => JsonValue::Null,
        serde_json::Value::Bool(b) => JsonValue::Bool(b),
        serde_json::Value::Number(n) => JsonValue::Number(n.as_f64().unwrap_or(0.0)),
        serde_json::Value::String(s) => JsonValue::String(s),
        serde_json::Value::Array(arr) => {
            let items: Vec<_> = arr.into_iter()
                .filter_map(|v| serde_value_to_json_value_depth_limited(v, depth + 1))
                .collect();
            JsonValue::Array(items)
        }
        serde_json::Value::Object(obj) => {
            let entries: Vec<_> = obj.into_iter()
                .filter_map(|(k, v)| {
                    serde_value_to_json_value_depth_limited(v, depth + 1)
                        .map(|v| (k, v))
                })
                .collect();
            JsonValue::Object(entries)
        }
    })
}
```

### Fix 3: Fail-Closed Gateway Default

Change the no-gateway fallback to reject instead of granting READ_ONLY:

```rust
// In handler.rs, replace the fallback TokenValidationResult with:
let token_result = match gateway {
    Some(gw) => gw.validate_lateral_movement(
        current_agent_name,
        capability_token_b64.as_bytes(),
        secret_key,
    )?,
    None => {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::LateralMovementBlocked,
            "No ZeroTrustGateway configured — token cannot be verified. \
             Call with_gateway() to enable real validation.",
        ));
    }
};
```

This makes the secure configuration the *only* configuration. If backward compatibility is needed, gate it behind a `dangerously-skip-gateway` feature flag.

### Fix 4: Incremental Nonce Pruning

Replace the full `retain()` with incremental pruning:

```rust
// In security.rs — NonceTracker::track_key
fn track_key(&self, key: u64) -> Result<(), SAACPHardDrop> {
    let current_time = now_secs();
    let mut inner = self.inner.lock().expect("lock poisoned");

    if inner.seen_nonces.contains_key(&key) {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "REPLAY ATTACK DETECTED: Nonce already used.",
        ));
    }

    inner.seen_nonces.insert(key, current_time);

    // Incremental prune: only check capacity every N inserts
    const PRUNE_INTERVAL: u64 = 1000;
    inner.insert_count += 1;
    if inner.insert_count % PRUNE_INTERVAL == 0 {
        let max_age = inner.max_age_seconds;
        if inner.seen_nonces.len() > inner.max_entries {
            inner.seen_nonces.retain(|_, &mut t| (current_time - t) <= max_age);
        }
        if inner.seen_nonces.len() > inner.max_entries {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::CircuitBreakerOpen,
                "Nonce tracker capacity exceeded under sustained flood.",
            ));
        }
    }
    Ok(())
}
```

This adds an `insert_count: u64` field to `NonceInner` and bounds the prune cost to amortized O(1).

### Fix 5: Payload Dict Size Limit

Add a check before constructing the HashMap:

```rust
// In handler.rs, before the payload_dict construction loop:
const MAX_PAYLOAD_KEYS: usize = 10_000;
if let serde_json::Value::Object(ref map) = v {
    if map.len() > MAX_PAYLOAD_KEYS {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::PayloadTooLarge,
            format!("Payload object exceeds max key count ({})", MAX_PAYLOAD_KEYS),
        ));
    }
    for (k, val) in map.iter() {
        parsed.payload_dict.insert(k.clone(), serde_value_to_json_value(val.clone()));
    }
}
```

### Fix 6: WAL Backpressure

Make the audit append block (with timeout) instead of dropping:

```rust
// In security.rs — replace try_send with a bounded send
pub fn append_event_blocking(
    &self,
    ...,
    timeout: Duration,
) -> Result<(), SAACPHardDrop> {
    let event = AuditLogEntry { ... };
    match self.wal_tx.send_timeout(event, timeout) {
        Ok(()) => Ok(()),
        Err(mpsc::SendTimeoutError::Timeout(_)) => {
            // WAL is saturated — fail closed
            Err(SAACPHardDrop::new(
                SAACPBytecodes::AuditSubsystemDegraded,
                "Audit WAL saturated — backpressure applied.",
            ))
        }
        Err(mpsc::SendTimeoutError::Disconnected(_)) => {
            Err(SAACPHardDrop::new(
                SAACPBytecodes::AuditSubsystemDegraded,
                "Audit WAL worker disconnected.",
            ))
        }
    }
}
```

This converts the silent drop into a hard backpressure signal that Gate 2.5 can detect.

### Fix 7: Shared Timestamp Per Packet

Introduce a `PipelineTimestamps` struct to share a single `SystemTime` read:

```rust
struct PipelineTimestamps {
    pregate: f64,
    pipeline: f64,
}

impl PipelineTimestamps {
    fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64();
        Self {
            pregate: now,
            pipeline: now,
        }
    }
}
```

Pass this through the pipeline instead of calling `SystemTime::now()` at each gate.

---

## Summary

The SAACP-RS codebase is a **security-first, well-engineered protocol implementation** with a 12-gate defense-in-depth pipeline, strong cryptography, and extensive test coverage. Its primary production gaps are:

1. **Performance**: Dual JSON parsing and synchronous `spawn_blocking` dispatch limit throughput
2. **Isolation**: Residual global singletons prevent true multi-tenancy
3. **Fail-safety**: The no-gateway fallback silently degrades security, and the WAL drops events under load

The remediation plan above addresses each gap with specific, implementable changes. With these fixes applied, the codebase would rate **8.5/10** for production readiness.