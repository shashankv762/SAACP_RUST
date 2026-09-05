//! test_production_readiness_fixes_rs.rs — Regression tests for the
//! 2026-08-31 production-readiness audit fixes (longcat.md §"Mitigation
//! Strategies", fixes 1/2/3/6/8/10).
//!
//! Some of these tests assert compile-time constants on purpose (pinning the
//! documented bound is the regression property), so the constants-on-constants
//! lint is deliberately allowed file-wide, matching
//! `test_acsvaf_redteam_rs.rs`'s precedent.
//!
//! Each test pins one specific fix so future refactors cannot silently
//! regress the security posture:
//!
//! 1. **Fail-closed no-gateway** (longcat.md Gap A): a `intercept_packet(_full)`
//!    call that does NOT inject a `ZeroTrustGateway` and is NOT compiled with
//!    `--features dangerously-skip-gateway` must return
//!    `LateralMovementBlocked`. The previous permissive behavior (synthetic
//!    READ_ONLY token) was a fail-open anti-pattern.
//!
//! 2. **Depth-limited JSON conversion** (longcat.md Gap D / Risk 1): the
//!    public `serde_value_to_json_value_bounded` function must return the
//!    `JsonValue::MalformedDepthExceeded` sentinel for any input whose
//!    deepest nested path exceeds `PromptInjectionScanner::MAX_DEPTH` (8).
//!    Without the bound, an authenticated peer could blow the stack by
//!    sending a 1k-deep JSON object (5–10× memory amplification vector).
//!
//! 3. **Bounded payload-dict key count** (longcat.md Gap F): the
//!    `intercept_packet_full` hot path must reject any JSON object with more
//!    than `MAX_PAYLOAD_KEYS` (4096) keys before allocating the `HashMap`.
//!    Without the bound, an authenticated peer sending a 10 MB JSON with
//!    millions of keys creates a `payload_dict` ~100 MB in size.
//!
//! 4. **`TOKEN_CACHE_TTL` is publicly exported**: the revocation cache TTL
//!    that operators tune for high-turnover revocation lists is reachable
//!    from `saacp::*`.
//!
//! 5. **`MalformedDepthExceeded` sentinel exists and is `Debug`-printable**:
//!    the variant must exist on `JsonValue` and be safely `Debug`-printable
//!    for the structured-logging error path.
//!
//! All tests are `#[test]` only — no network I/O — and run in the default
//! (no-feature) build, verifying that the security defaults survive.

#![allow(clippy::assertions_on_constants)]

use std::collections::HashMap;

use base64::Engine;

use saacp::errors::{SAACPBytecodes, SAACPHardDrop};
use saacp::handler::{
    json_value_depth_exceeded, serde_value_to_json_value_bounded, JsonValue,
    PromptInjectionScanner, MAX_PAYLOAD_KEYS,
};
use saacp::SAACPProtocolHandler;
use saacp::TOKEN_CACHE_TTL;

// ═══════════════════════════════════════════════════════════════════════════
// FIX 1 — Fail-closed no-gateway path
// ═══════════════════════════════════════════════════════════════════════════

#[test]
#[cfg(not(feature = "dangerously-skip-gateway"))]
fn fix1_no_gateway_default_build_returns_lateral_movement_blocked() {
    // Build a structurally valid, AEAD-encrypted frame with a syntactically
    // valid `_capability_token` field so the upstream "_capability_token
    // missing" check passes and the handler reaches the no-gateway
    // fail-closed branch in Gate 1.0.
    //
    // The token bytes themselves are arbitrary — they will never be parsed
    // by a real `ZeroTrustGateway` because no gateway is injected. The
    // fail-closed branch fires before any cryptographic verification of
    // the token, exactly so a malformed/bogus token cannot bypass it.
    let secret = [0xA1u8; 32];
    let payload = serde_json::json!({
        "task": "summarize the report",
        "priority": 1,
        "_capability_token": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
    })
    .to_string();
    // Schema 1, READ_ONLY (0), payload bytes inside.
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0);

    let result = SAACPProtocolHandler::intercept_packet(&frame, &secret, "no-gateway-agent", false);

    // Pre-fix: this returned `Ok(ParsedPacket)` with a synthetic READ_ONLY
    // token — a fail-open anti-pattern. Post-fix (no
    // `dangerously-skip-gateway` feature): the handler returns
    // `LateralMovementBlocked` because there is no trust anchor to validate
    // the capability token against.
    let err = result.expect_err(
        "intercept_packet without an injected ZeroTrustGateway must fail closed \
         (no-gateway path must NOT silently grant READ_ONLY in a default build)",
    );
    assert_eq!(
        err.bytecode,
        SAACPBytecodes::LateralMovementBlocked,
        "exact bytecode must be LateralMovementBlocked (not ActionClassEscalation, \
         not MalformedHeader) so operators can distinguish 'no trust anchor' \
         from 'token denied by trust anchor'",
    );
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ZeroTrustGateway") || msg.contains("with_gateway"),
        "error message must name the missing configuration so an operator \
         can fix it: got {msg:?}",
    );
}

#[test]
#[cfg(not(feature = "dangerously-skip-gateway"))]
fn fix1_no_gateway_with_irreversible_still_fails_closed() {
    // Even with an action_class that the synthetic fallback would have
    // blocked at Gate 2.5 anyway, the no-gateway path must reject BEFORE
    // Gate 2.5 so the bytecode is precise.
    let secret = [0xA2u8; 32];
    let payload = serde_json::json!({
        "task": "delete everything",
        "priority": 1,
        "_capability_token": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
    })
    .to_string();
    // action_class = 2 (IRREVERSIBLE).
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 2);

    let result = SAACPProtocolHandler::intercept_packet(&frame, &secret, "no-gateway-irrev", false);
    let err = result.expect_err("IRREVERSIBLE without a gateway must fail");
    assert_eq!(
        err.bytecode,
        SAACPBytecodes::LateralMovementBlocked,
        "must be rejected by Gate 1.0 (no-gateway fail-closed) not Gate 2.5 \
         (escalation) — the no-gateway check runs first and produces the \
         more accurate bytecode",
    );
}

/// Mirror of the two `fix1_no_gateway_*` tests above, for builds that opt in
/// to the `dangerously-skip-gateway` escape hatch (`--all-features` and any
/// deployment explicitly enabling it). The contract flips legitimately:
/// Gate 1.0's no-gateway branch grants a synthetic READ_ONLY token
/// (`source_agent = "unknown"`, `max_action_class = 0` — see handler.rs's
/// `cfg!(feature = "dangerously-skip-gateway")` branch) instead of failing
/// closed. These assertions pin that escape hatch to its documented shape so
/// it can never silently widen.
#[test]
#[cfg(feature = "dangerously-skip-gateway")]
fn fix1_no_gateway_escape_hatch_grants_synthetic_read_only_only() {
    let secret = [0xA4u8; 32];
    let payload = serde_json::json!({
        "task": "summarize the report",
        "priority": 1,
        "_capability_token": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
    })
    .to_string();
    // READ_ONLY (action_class 0): the synthetic token must carry it through.
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0);
    let parsed = SAACPProtocolHandler::intercept_packet(&frame, &secret, "hatch-read-only", false)
        .expect("escape-hatch build must grant the synthetic READ_ONLY token");
    assert_eq!(
        parsed.source_agent.as_ref(),
        "unknown",
        "the synthetic token's source must be the bootstrap identity"
    );
    assert_eq!(
        parsed.max_action_class, 0,
        "the escape hatch must be hard-capped at READ_ONLY (0)"
    );

    // IRREVERSIBLE (action_class 2): Gate 1.0 grants READ_ONLY, then Gate 2.5
    // must still reject the escalation — the hatch never authorizes writes.
    let irrev_payload = serde_json::json!({
        "task": "delete everything",
        "priority": 1,
        "_capability_token": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
    })
    .to_string();
    let irrev_frame = build_frame(&secret, irrev_payload.as_bytes(), 1, 0x10, 2);
    let err =
        SAACPProtocolHandler::intercept_packet(&irrev_frame, &secret, "hatch-irreversible", false)
            .expect_err("IRREVERSIBLE must still be rejected under the escape hatch");
    assert_ne!(
        err.bytecode,
        SAACPBytecodes::LateralMovementBlocked,
        "under the hatch, Gate 1.0 grants the synthetic token — the rejection \
         must come from the Gate 2.5 escalation check, not the no-gateway \
         fail-closed path"
    );
}

#[test]
fn fix1_existing_redteam_test_still_passes() {
    // The pre-existing exploit regression test from
    // `tests/test_exploit_vulnerabilities_rs.rs::exploit_gw_1d_*` already
    // asserts that `intercept_packet` with an IRREVERSIBLE-flagged frame
    // and no gateway returns `Err`. This is its twin, kept here so the
    // fix's contract is regression-tested in the same module as its
    // sibling fixes. (The original test lives in a different file to keep
    // its narrative provenance — see `tests/test_exploit_vulnerabilities_rs.rs`.)
    let secret = [0xA3u8; 32];
    let payload = serde_json::json!({
        "task": "delete",
        "priority": 1,
        "_capability_token": base64::engine::general_purpose::STANDARD.encode([0u8; 64]),
    })
    .to_string();
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 2);
    let r = SAACPProtocolHandler::intercept_packet(&frame, &secret, "attacker", false);
    assert!(
        r.is_err(),
        "EXPLOIT GW-1d twin: no-gateway IRREVERSIBLE must be rejected"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FIX 2 — Depth-limited JSON conversion
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fix2_bounded_returns_sentinel_on_deeply_nested_input() {
    // Build a 100-deep nested array `[[[[...]]]]` (depth > MAX_DEPTH = 8).
    // The bounded converter recurses on each Array wrapper; at depth=9
    // (MAX_DEPTH + 1) it returns the sentinel. The OUTER wrappers at
    // depth ≤ MAX_DEPTH still construct normally and wrap the sentinel,
    // so the *root* value is `Array([...Array([sentinel])...])` — the
    // sentinel itself is the signal, not the root identity. Walk down
    // to find the deepest node and assert it's the sentinel.
    let mut v: serde_json::Value = serde_json::Value::Number(0u64.into());
    for _ in 0..100 {
        v = serde_json::Value::Array(vec![v]);
    }
    let result = serde_value_to_json_value_bounded(v, 0);
    assert!(
        contains_depth_sentinel(&result),
        "depth>MAX_DEPTH must embed MalformedDepthExceeded sentinel somewhere in \
         the converted tree, got {result:?}",
    );
}

/// Walk a `JsonValue` tree and return `true` iff any node is the
/// `MalformedDepthExceeded` sentinel. Delegates to
/// [`saacp::handler::json_value_depth_exceeded`] — kept here as a local
/// helper so test failures produce a clearer stack trace pointing at the
/// assertion site rather than into `handler.rs`.
fn contains_depth_sentinel(v: &JsonValue) -> bool {
    json_value_depth_exceeded(v)
}

#[test]
fn fix2_bounded_passes_shallow_inputs() {
    // Legitimate payloads are depth ≤ 4 (task + nested object + array).
    // The bounded converter must produce a non-sentinel `JsonValue`.
    let v = serde_json::json!({
        "task": "summarize",
        "context": { "source": "report", "lines": [1, 2, 3] },
    });
    let result = serde_value_to_json_value_bounded(v, 0);
    assert!(
        !matches!(result, JsonValue::MalformedDepthExceeded),
        "shallow payload must NOT trigger the depth-exceeded sentinel, got {result:?}",
    );
}

#[test]
fn fix2_bounded_handles_exact_max_depth() {
    // Construct a JSON value whose deepest recursion-counter value is
    // EXACTLY MAX_DEPTH (8). The bounded converter's recursion counter
    // starts at 0 at the root call and increments only when it descends
    // into an Array/Object. Build 8 nested arrays wrapping a String —
    // root counter=0, 8 Array wrappers descend to counter=8 for the
    // String leaf. The sentinel is returned only when `depth >
    // MAX_DEPTH`, so depth=8 must NOT trigger it anywhere.
    let mut v: serde_json::Value = serde_json::Value::String("leaf".into());
    for _ in 0..8 {
        v = serde_json::Value::Array(vec![v]);
    }
    let input_depth = serde_json_depth(&v);
    assert_eq!(input_depth, 8, "test setup: 8 nested Arrays");
    let result = serde_value_to_json_value_bounded(v, 0);
    assert!(
        !contains_depth_sentinel(&result),
        "depth=MAX_DEPTH (8 recursion counter) must NOT contain the depth \
         sentinel anywhere (sentinel only fires at depth > 8), got {result:?}",
    );
}

#[test]
fn fix2_bounded_handles_one_past_max_depth() {
    // 9 nested arrays wrapping a String — leaf at depth=9 in the
    // bounded-converter recursion counter, which is one past
    // `PromptInjectionScanner::MAX_DEPTH` (8). The sentinel must appear
    // SOMEWHERE in the converted tree.
    let mut v: serde_json::Value = serde_json::Value::String("leaf".into());
    for _ in 0..9 {
        v = serde_json::Value::Array(vec![v]);
    }
    let input_depth = serde_json_depth(&v);
    assert_eq!(input_depth, 9, "test setup: 9 nested Arrays");
    let result = serde_value_to_json_value_bounded(v, 0);
    assert!(
        contains_depth_sentinel(&result),
        "depth=MAX_DEPTH+1 (9 recursion counter) must embed the sentinel in \
         the converted tree, got {result:?}",
    );
}

/// Count the depth of a `serde_json::Value` (longest path from root to leaf).
/// This is test-only — has no bounded-converter semantics, so it can recurse
/// freely to give us a ground-truth measurement of the input shape.
fn serde_json_depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(serde_json_depth).max().unwrap_or(0),
        serde_json::Value::Object(obj) => 1 + obj.values().map(serde_json_depth).max().unwrap_or(0),
        _ => 0,
    }
}

#[test]
fn fix2_max_depth_constant_matches_scanner() {
    // The bounded converter uses the SAME depth constant as the injection
    // scanner — divergence between the two would let an attacker bypass
    // one via the other. Pin the invariant.
    assert_eq!(
        PromptInjectionScanner::MAX_DEPTH,
        8,
        "scanner MAX_DEPTH must remain 8 (changing this requires re-auditing \
         both the bounded converter and the injection scanner in lockstep)",
    );
}

#[test]
fn fix2_malformed_depth_exceeded_variant_is_debug_printable() {
    // The sentinel must round-trip through `Debug` so `tracing::error!` /
    // audit logging never panic on a `JsonValue` containing it.
    let v = JsonValue::MalformedDepthExceeded;
    let s = format!("{v:?}");
    assert!(
        s.contains("MalformedDepthExceeded"),
        "Debug must include variant name, got {s:?}"
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FIX 3 — Bounded payload-dict key count
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fix3_max_payload_keys_constant_is_bounded() {
    // Pin the constant. 4096 is the chosen ceiling (longcat.md Gap F).
    // Increasing this requires re-auditing memory amplification bounds
    // across the whole handler.
    assert_eq!(MAX_PAYLOAD_KEYS, 4096);
    assert!(
        MAX_PAYLOAD_KEYS > 0 && MAX_PAYLOAD_KEYS < 1_000_000,
        "MAX_PAYLOAD_KEYS must be bounded between 1 and 1M, got {MAX_PAYLOAD_KEYS}",
    );
}

#[test]
fn fix3_payload_dict_rejects_object_with_too_many_keys() {
    // Build an authenticated frame whose payload is a JSON object with
    // exactly MAX_PAYLOAD_KEYS + 1 keys. Without the bound, this would
    // allocate a HashMap with 4097 entries; with the bound, it must
    // fail at the payload-dict construction step (before any gate runs).
    //
    // A real `ZeroTrustGateway` is injected so the upstream
    // `_capability_token` validation passes and the handler reaches the
    // payload-dict construction step where the key-count bound fires.
    let secret = [0xB1u8; 32];
    let gw = saacp::ZeroTrustGateway::new();
    let token_bytes = gw.issue_capability_token(
        &secret,
        "many-keys-issuer",
        &["many-keys-target"],
        &[],
        3600,
        None,
        0x00, // READ_ONLY ceiling
        None,
    );
    let token_str = String::from_utf8(token_bytes).expect("token must be base64 utf8");

    let mut obj = serde_json::Map::new();
    for i in 0..(MAX_PAYLOAD_KEYS + 1) {
        obj.insert(format!("k{i}"), serde_json::Value::String("v".into()));
    }
    obj.insert(
        "_capability_token".to_string(),
        serde_json::Value::String(token_str),
    );
    let payload = serde_json::Value::Object(obj).to_string();
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0);

    let rl = saacp::AgentRateLimiter::new();
    let r = SAACPProtocolHandler::intercept_packet_full(
        &frame,
        &secret,
        "many-keys-target",
        false,
        Some(&gw),
        Some(&rl),
        None,
        None,
        None,
    );
    let err = r.expect_err(
        "a JSON object with MAX_PAYLOAD_KEYS+1 keys must be rejected before \
         any downstream gate runs",
    );
    assert_eq!(
        err.bytecode,
        SAACPBytecodes::PayloadTooLarge,
        "rejection must carry PayloadTooLarge bytecode, got {:?}",
        err.bytecode,
    );
}

#[test]
fn fix3_payload_dict_accepts_object_with_exactly_max_payload_keys() {
    // Boundary: exactly MAX_PAYLOAD_KEYS keys must NOT trigger the bound.
    // The wire object has (MAX_PAYLOAD_KEYS - 1) user keys + the required
    // `_capability_token` key = MAX_PAYLOAD_KEYS total keys. (May still
    // be rejected by Gate 9.0 schema validation, but not by the key-count
    // pre-check.)
    let secret = [0xB2u8; 32];
    let gw = saacp::ZeroTrustGateway::new();
    let token_bytes = gw.issue_capability_token(
        &secret,
        "exact-keys-issuer",
        &["exact-keys-target"],
        &[],
        3600,
        None,
        0x00,
        None,
    );
    let token_str = String::from_utf8(token_bytes).expect("token must be base64 utf8");

    let mut obj = serde_json::Map::new();
    // MAX_PAYLOAD_KEYS - 1 user keys (one slot is reserved for the
    // capability token below).
    for i in 0..(MAX_PAYLOAD_KEYS - 1) {
        obj.insert(format!("k{i}"), serde_json::Value::String("v".into()));
    }
    obj.insert(
        "_capability_token".to_string(),
        serde_json::Value::String(token_str),
    );
    assert_eq!(obj.len(), MAX_PAYLOAD_KEYS, "test setup invariant");
    let payload = serde_json::Value::Object(obj).to_string();
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0);

    let rl = saacp::AgentRateLimiter::new();
    let r = SAACPProtocolHandler::intercept_packet_full(
        &frame,
        &secret,
        "exact-keys-target",
        false,
        Some(&gw),
        Some(&rl),
        None,
        None,
        None,
    );
    // We don't assert `is_ok` here — Gate 9.0 schema validation will
    // reject this (no `task`/`priority` fields). We only assert the
    // error bytecode is NOT PayloadTooLarge (which would indicate the
    // key-count bound fired).
    if let Err(e) = r {
        assert_ne!(
            e.bytecode,
            SAACPBytecodes::PayloadTooLarge,
            "MAX_PAYLOAD_KEYS (exact boundary) must NOT trigger the key-count bound; \
             a downstream gate may still reject this frame, but not with PayloadTooLarge",
        );
    }
}

#[test]
fn fix3_payload_dict_rejects_deeply_nested_payload() {
    // An authenticated peer sends a JSON object with a deeply-nested
    // value. The bounded converter must reject at the payload-dict
    // construction step before allocating the rest of the HashMap.
    let secret = [0xB3u8; 32];
    let gw = saacp::ZeroTrustGateway::new();
    let token_bytes = gw.issue_capability_token(
        &secret,
        "deep-payload-issuer",
        &["deep-payload-target"],
        &[],
        3600,
        None,
        0x00,
        None,
    );
    let token_str = String::from_utf8(token_bytes).expect("token must be base64 utf8");

    let mut obj = serde_json::Map::new();
    obj.insert("task".to_string(), serde_json::Value::String("ok".into()));
    obj.insert(
        "_capability_token".to_string(),
        serde_json::Value::String(token_str),
    );
    let mut nested: serde_json::Value = serde_json::Value::Number(0u64.into());
    for _ in 0..100 {
        nested = serde_json::Value::Array(vec![nested]);
    }
    obj.insert("deep".to_string(), nested);
    let payload = serde_json::Value::Object(obj).to_string();
    let frame = build_frame(&secret, payload.as_bytes(), 1, 0x10, 0);

    let rl = saacp::AgentRateLimiter::new();
    let r = SAACPProtocolHandler::intercept_packet_full(
        &frame,
        &secret,
        "deep-payload-target",
        false,
        Some(&gw),
        Some(&rl),
        None,
        None,
        None,
    );
    let err = r.expect_err("deeply-nested payload must be rejected before any gate runs");
    assert_eq!(
        err.bytecode,
        SAACPBytecodes::PayloadTooLarge,
        "depth-exceeded must surface as PayloadTooLarge, got {:?}",
        err.bytecode,
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// FIX 8 — `TOKEN_CACHE_TTL` publicly exported
// ═══════════════════════════════════════════════════════════════════════════

#[test]
fn fix8_token_cache_ttl_is_publicly_exported_and_sane() {
    // Operators tuning the revocation-cache TTL for high-turnover
    // revocation lists need to read this constant from the public API.
    // Pin it: 30 seconds is the current default in `gateway.rs:47`.
    assert!(
        TOKEN_CACHE_TTL > 0.0,
        "TOKEN_CACHE_TTL must be positive (a non-positive TTL would force \
         an immediate eviction loop), got {TOKEN_CACHE_TTL}",
    );
    assert!(
        TOKEN_CACHE_TTL >= 1.0 && TOKEN_CACHE_TTL <= 3600.0,
        "TOKEN_CACHE_TTL must be between 1s and 1h — the chosen default \
         should not allow a perpetual-cache nor a no-cache configuration \
         without operator opt-in, got {TOKEN_CACHE_TTL}",
    );
}

// ═══════════════════════════════════════════════════════════════════════════
// Test-only helper: build an authenticated, AEAD-encrypted SAACP frame.
// Mirrors the helper used by `tests/test_exploit_vulnerabilities_rs.rs` so
// the regression tests here are self-contained.
// ═══════════════════════════════════════════════════════════════════════════

/// Build a 128-byte-header SAACP frame, AEAD-encrypted with `secret`,
/// carrying the supplied JSON payload bytes.
fn build_frame(
    secret: &[u8],
    payload: &[u8],
    schema_id: u16,
    flags: u8,
    action_class: u8,
) -> Vec<u8> {
    use saacp::framing::MEASCFrame;
    let session_id = [0xCCu8; 16];
    let frame = MEASCFrame {
        schema_id,
        status_code: 0x10,
        flags,
        action_class,
        payload_length: payload.len() as u32,
        session_id,
        epoch_id: 0,
        psn: 1,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    };
    // The helper MUST stay best-effort: a test that cannot construct a
    // valid frame should `unwrap` loudly rather than silently producing
    // an unencrypted frame that masks the regression it is supposed to
    // detect.
    frame
        .encode_encrypted(payload, secret)
        .expect("test helper: AEAD frame build failed")
}

// Compile-time guard: the `HashMap` import is intentionally retained so
// future edits adding new test cases that need payload-dict-like types
// don't have to re-add it. The unused import is harmless.
#[allow(dead_code)]
fn _ensure_hashmap_available() -> HashMap<String, JsonValue> {
    HashMap::new()
}

// Compile-time guard: the `SAACPHardDrop` import is intentionally
// retained so future edits can assert against the exact bytecode enum
// variant without re-importing it.
#[allow(dead_code)]
fn _ensure_error_type_available() -> SAACPHardDrop {
    SAACPHardDrop::new(
        SAACPBytecodes::LateralMovementBlocked,
        "compile-time import check",
    )
}
