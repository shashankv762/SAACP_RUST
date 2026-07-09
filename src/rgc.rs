// SAACP Rust Implementation — Resource Governance Controls (RGC)
// Translated from SAACP/src/saacp/rgc.py
//!
//! Pre-parsing resource governance for all inbound SAACP payloads.
//! The scanner runs BEFORE `serde_json::from_slice` and BEFORE schema
//! validation so that a deliberately crafted adversarial payload
//! (deeply nested, gigantic arrays, multi-megabyte strings) cannot
//! exhaust CPU or memory before any gate has had a chance to reject it.
//!
//! # Architecture
//!
//! * [`RGCPolicy`] — 12 configurable safety limits with conservative defaults.
//! * [`ResourceGovernanceParser`] — Recursive-descent character-level scanner.
//!   `check()` is the sole public entry point.  It walks the raw text one
//!   character at a time and stops early the instant any policy limit is
//!   exceeded — it does NOT wait for the full payload to be scanned.
//! * [`ExecutionBudgetGuard`] — Wall-clock deadline enforcer for agent tasks.
//! * [`DEFAULT_POLICY`] — Module-level default policy singleton.

use std::collections::HashMap;
use std::time::Instant;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ============================================================================
// 1. Policy
// ============================================================================

/// Configurable resource-governance limits applied to every inbound payload.
///
/// All limits are checked BEFORE `serde_json::from_slice` is ever called so
/// that adversarial payloads cannot exhaust resources inside the process.
#[derive(Debug, Clone)]
pub struct RGCPolicy {
    /// Maximum JSON object/array nesting depth (default 8).
    pub max_depth: usize,
    /// Maximum total structural nodes — objects + arrays (default 1000).
    pub max_object_count: usize,
    /// Maximum elements in any single JSON array (default 256).
    pub max_array_length: usize,
    /// Maximum Unicode characters in any single JSON string (default 65536).
    pub max_string_length: usize,
    /// Maximum key-value pairs in any single JSON object (default 64).
    pub max_field_count: usize,
    /// Maximum payload size in bytes (default 1 MB).
    pub max_total_size: usize,
    /// Total colon (`:`) tokens — proxy for schema complexity (default 512).
    pub max_schema_complexity: usize,
    /// Weighted aggregate resource unit budget (default 10000).
    pub max_aggregate_resource_units: usize,
    /// Maximum characters in any JSON object key (default 256).
    pub max_key_length: usize,
    /// Maximum total Unicode code-points across ALL strings (default 1_000_000).
    pub max_unicode_scalar_values: usize,
    /// Maximum absolute value of any JSON number (default 1e18).
    pub max_numeric_magnitude: f64,
    /// When true, raise immediately if depth exceeds max_depth (default true).
    pub enable_recursive_object_detection: bool,
}

impl Default for RGCPolicy {
    fn default() -> Self {
        Self {
            max_depth: 8,
            max_object_count: 1000,
            max_array_length: 256,
            max_string_length: 65_536,
            max_field_count: 64,
            max_total_size: 1_048_576,
            max_schema_complexity: 512,
            max_aggregate_resource_units: 10_000,
            max_key_length: 256,
            max_unicode_scalar_values: 1_000_000,
            max_numeric_magnitude: 1e18,
            enable_recursive_object_detection: true,
        }
    }
}

/// Module-level default policy.
pub static DEFAULT_POLICY: std::sync::LazyLock<RGCPolicy> =
    std::sync::LazyLock::new(RGCPolicy::default);

/// Hard maximum for the ExecutionBudgetGuard (spec §12.3).
/// The gate pipeline ceiling and any agent task budget MUST NOT exceed this.
pub const EXECUTION_BUDGET_MAX_SECONDS: f64 = 30.0;

// ============================================================================
// 2. ExecutionBudgetGuard
// ============================================================================

/// Wall-clock deadline enforcer for agent execution blocks.
///
/// Wraps any agent execution.  If the block does not complete within
/// `timeout_seconds`, `check()` raises [`SAACPHardDrop`].
///
/// H-33: this guard is purely a deadline comparison — `Instant::now() >
/// self.deadline` — and previously spawned a redundant background OS thread
/// per instance just to flip an `AtomicBool` at the same deadline `check()`
/// already computes independently. Guards are constructed per
/// agent-execution block, so that thread leaked one OS thread (living for
/// up to `EXECUTION_BUDGET_MAX_SECONDS`) for every call. Removed entirely;
/// `deadline: Instant` is the sole source of truth.
pub struct ExecutionBudgetGuard {
    timeout_seconds: f64,
    deadline: Instant,
}

impl ExecutionBudgetGuard {
    /// Create a new budget guard with the given wall-clock deadline.
    ///
    /// Returns an error if `timeout_seconds` is non-positive or exceeds the
    /// hard ceiling of `EXECUTION_BUDGET_MAX_SECONDS` (30 s, spec §12.3).
    pub fn new(timeout_seconds: f64) -> Result<Self, String> {
        if timeout_seconds <= 0.0 {
            return Err("timeout_seconds must be positive".into());
        }
        if timeout_seconds > EXECUTION_BUDGET_MAX_SECONDS {
            return Err(format!(
                "timeout_seconds {timeout_seconds:.1}s exceeds hard ceiling \
                 of {EXECUTION_BUDGET_MAX_SECONDS:.1}s (spec §12.3)"
            ));
        }
        let deadline = Instant::now()
            + std::time::Duration::from_secs_f64(timeout_seconds);

        Ok(Self {
            timeout_seconds,
            deadline,
        })
    }

    /// Raise [`SAACPHardDrop`] if the execution deadline has been exceeded.
    pub fn check(&self) -> Result<(), SAACPHardDrop> {
        if Instant::now() > self.deadline {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RgcResourceLimitExceeded,
                format!(
                    "ExecutionBudgetGuard: agent execution exceeded {:.1}s wall-clock deadline.",
                    self.timeout_seconds
                ),
            ));
        }
        Ok(())
    }

    /// Seconds remaining before deadline (0.0 if already expired).
    pub fn remaining_seconds(&self) -> f64 {
        let now = Instant::now();
        if now >= self.deadline {
            0.0
        } else {
            (self.deadline - now).as_secs_f64()
        }
    }

    /// Whether the guard has timed out.
    pub fn is_timed_out(&self) -> bool {
        Instant::now() > self.deadline
    }
}

// ============================================================================
// 3. ResourceGovernanceParser
// ============================================================================

/// Token-level pre-parsing scanner that enforces [`RGCPolicy`] limits.
///
/// The scanner walks the raw payload one character at a time without ever
/// calling `serde_json`.  It bails out at the first sign of a limit
/// violation rather than completing a full parse.
pub struct ResourceGovernanceParser;

/// Internal statistics collected during scanning.
#[allow(dead_code)]
struct ScanStats {
    depth: usize,
    max_depth_seen: usize,
    object_count: usize,
    array_count: usize,
    total_nodes: usize,
    max_array_length_seen: usize,
    max_field_count_seen: usize,
    max_string_length_seen: usize,
    max_key_length_seen: usize,
    total_string_chars: usize,
    max_numeric_magnitude_seen: f64,
    schema_complexity: usize,
    aggregate_resource_units: usize,
}

impl ResourceGovernanceParser {
    /// Main public entry point.  Validates `payload` against `policy`
    /// and returns `Err(SAACPHardDrop)` if any limit is exceeded.
    pub fn check(payload: &[u8], policy: Option<&RGCPolicy>) -> Result<(), SAACPHardDrop> {
        let pol = policy.unwrap_or(&DEFAULT_POLICY);

        // Step a: byte-level size gate
        if payload.len() > pol.max_total_size {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RgcResourceLimitExceeded,
                format!(
                    "RGC: max_total_size exceeded: {} > {}",
                    payload.len(),
                    pol.max_total_size
                ),
            ));
        }

        // Step b: UTF-8 decode
        let text = std::str::from_utf8(payload).map_err(|e| {
            SAACPHardDrop::new(
                SAACPBytecodes::AmbiguousIntent,
                format!("RGC: payload is not valid UTF-8 -- {}", e),
            )
        })?;

        // Step c: token-level scan
        let stats = Self::scan_tokens(text, pol)?;

        // Step d: post-scan limit checks
        Self::check_limit("max_depth", stats.max_depth_seen, pol.max_depth)?;
        Self::check_limit("max_object_count", stats.object_count, pol.max_object_count)?;
        Self::check_limit("max_array_length", stats.max_array_length_seen, pol.max_array_length)?;
        Self::check_limit("max_string_length", stats.max_string_length_seen, pol.max_string_length)?;
        Self::check_limit("max_field_count", stats.max_field_count_seen, pol.max_field_count)?;
        Self::check_limit("max_schema_complexity", stats.schema_complexity, pol.max_schema_complexity)?;
        Self::check_limit("max_key_length", stats.max_key_length_seen, pol.max_key_length)?;
        Self::check_limit("max_unicode_scalar_values", stats.total_string_chars, pol.max_unicode_scalar_values)?;
        Self::check_limit("max_aggregate_resource_units", stats.aggregate_resource_units, pol.max_aggregate_resource_units)?;
        Self::check_limit("total_nodes", stats.total_nodes, pol.max_object_count)?;

        if stats.max_numeric_magnitude_seen > pol.max_numeric_magnitude {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RgcResourceLimitExceeded,
                format!(
                    "RGC: max_numeric_magnitude exceeded: {} > {}",
                    stats.max_numeric_magnitude_seen, pol.max_numeric_magnitude
                ),
            ));
        }

        Ok(())
    }

    /// Character-level scanner.  Walks `text` and returns statistics.
    ///
    /// H-35: walks a `Peekable<CharIndices>` directly over the original
    /// `&str` instead of collecting the whole payload into a `Vec<char>`
    /// first. The old `Vec<char>` collect allocated a second buffer up to
    /// ~4x the payload's UTF-8 byte size (each `char` is 4 bytes) purely
    /// for random-access indexing — memory amplification RGC exists to
    /// prevent, happening inside RGC's own pre-parse hot path. No upfront
    /// allocation proportional to payload size remains; the only
    /// allocations left are the per-depth bookkeeping maps below, which
    /// scale with nesting depth (bounded by `max_depth`), not payload size.
    fn scan_tokens(text: &str, policy: &RGCPolicy) -> Result<ScanStats, SAACPHardDrop> {
        let mut chars = text.char_indices().peekable();

        let mut depth: usize = 0;
        let mut max_depth_seen: usize = 0;
        let mut container_stack: Vec<char> = Vec::new(); // 'o' or 'a'

        let mut object_count: usize = 0;
        let mut array_count: usize = 0;
        let mut total_nodes: usize = 0;

        let mut array_element_counts: HashMap<usize, usize> = HashMap::new();
        let mut max_array_length_seen: usize = 0;

        let mut field_counts: HashMap<usize, usize> = HashMap::new();
        let mut max_field_count_seen: usize = 0;

        let mut total_string_chars: usize = 0;
        let mut max_string_length_seen: usize = 0;
        let mut max_key_length_seen: usize = 0;

        let mut max_numeric_magnitude_seen: f64 = 0.0;
        let mut schema_complexity: usize = 0;
        let mut aggregate_resource_units: usize = 0;
        let mut expecting_key: bool = false;

        while let Some(&(byte_i, ch)) = chars.peek() {
            // Whitespace
            if ch == ' ' || ch == '\t' || ch == '\n' || ch == '\r' {
                chars.next();
                continue;
            }

            // Opening brace
            if ch == '{' {
                chars.next();
                depth += 1;
                if max_depth_seen < depth {
                    max_depth_seen = depth;
                }
                if policy.enable_recursive_object_detection {
                    Self::check_limit("max_depth", depth, policy.max_depth)?;
                }
                object_count += 1;
                total_nodes += 1;
                aggregate_resource_units += 11; // 1 (node) + 10 (depth)
                Self::check_limit("max_object_count", object_count, policy.max_object_count)?;
                Self::check_limit("max_aggregate_resource_units", aggregate_resource_units, policy.max_aggregate_resource_units)?;

                container_stack.push('o');
                field_counts.insert(depth, 0);
                expecting_key = true;
                continue;
            }

            // Opening bracket
            if ch == '[' {
                chars.next();
                depth += 1;
                if max_depth_seen < depth {
                    max_depth_seen = depth;
                }
                if policy.enable_recursive_object_detection {
                    Self::check_limit("max_depth", depth, policy.max_depth)?;
                }
                array_count += 1;
                total_nodes += 1;
                aggregate_resource_units += 11;
                Self::check_limit("max_object_count", total_nodes, policy.max_object_count)?;
                Self::check_limit("max_aggregate_resource_units", aggregate_resource_units, policy.max_aggregate_resource_units)?;

                container_stack.push('a');
                array_element_counts.insert(depth, 0);
                expecting_key = false;
                continue;
            }

            // Closing brace
            if ch == '}' {
                chars.next();
                if let Some(last) = container_stack.last() {
                    let _ = *last;
                    if let Some(fc) = field_counts.remove(&depth) {
                        if fc > max_field_count_seen {
                            max_field_count_seen = fc;
                        }
                    }
                    container_stack.pop();
                }
                depth = depth.saturating_sub(1);
                expecting_key = container_stack.last() == Some(&'o');
                continue;
            }

            // Closing bracket
            if ch == ']' {
                chars.next();
                if let Some(_last) = container_stack.last() {
                    if let Some(ac) = array_element_counts.remove(&depth) {
                        if ac > max_array_length_seen {
                            max_array_length_seen = ac;
                        }
                    }
                    container_stack.pop();
                }
                depth = depth.saturating_sub(1);
                expecting_key = container_stack.last() == Some(&'o');
                continue;
            }

            // Colon
            if ch == ':' {
                chars.next();
                schema_complexity += 1;
                Self::check_limit("max_schema_complexity", schema_complexity, policy.max_schema_complexity)?;
                expecting_key = false;
                if depth > 0 {
                    let fc = field_counts.entry(depth).or_insert(0);
                    *fc += 1;
                    let fc_val = *fc;
                    if fc_val > max_field_count_seen {
                        max_field_count_seen = fc_val;
                    }
                    Self::check_limit("max_field_count", fc_val, policy.max_field_count)?;
                }
                continue;
            }

            // Comma
            if ch == ',' {
                chars.next();
                if container_stack.last() == Some(&'a') {
                    let ac = array_element_counts.entry(depth).or_insert(0);
                    *ac += 1;
                    let ac_val = *ac;
                    if ac_val > max_array_length_seen {
                        max_array_length_seen = ac_val;
                    }
                    Self::check_limit("max_array_length", ac_val, policy.max_array_length)?;
                } else if container_stack.last() == Some(&'o') {
                    expecting_key = true;
                }
                continue;
            }

            // String
            if ch == '"' {
                chars.next(); // consume opening quote
                let mut char_count: usize = 0;

                loop {
                    match chars.next() {
                        Some((_, '\\')) => {
                            // Blindly consume the escaped character as a second
                            // "position" without validating it — matches the
                            // original scanner's behavior exactly. Full escape
                            // validation happens later in the real serde_json
                            // parse; RGC is a pre-filter, not a validator.
                            chars.next();
                            char_count += 2;
                        }
                        Some((_, '"')) => break, // consumed closing quote
                        Some(_) => char_count += 1,
                        None => break, // unterminated string; scanner stops here
                    }
                }

                total_string_chars += char_count;
                Self::check_limit("max_unicode_scalar_values", total_string_chars, policy.max_unicode_scalar_values)?;

                let string_ru = std::cmp::max(1, (char_count as f64 * 0.01) as usize);
                aggregate_resource_units += string_ru;
                Self::check_limit("max_aggregate_resource_units", aggregate_resource_units, policy.max_aggregate_resource_units)?;

                if expecting_key {
                    if char_count > max_key_length_seen {
                        max_key_length_seen = char_count;
                    }
                    Self::check_limit("max_key_length", char_count, policy.max_key_length)?;
                    expecting_key = false;
                } else {
                    if char_count > max_string_length_seen {
                        max_string_length_seen = char_count;
                    }
                    Self::check_limit("max_string_length", char_count, policy.max_string_length)?;
                }
                continue;
            }

            // Number
            if ch == '-' || ch.is_ascii_digit() {
                let num_start = byte_i;
                chars.next(); // consume leading '-' or first digit

                while chars.peek().map(|(_, c)| c.is_ascii_digit()).unwrap_or(false) {
                    chars.next();
                }
                if chars.peek().map(|(_, c)| *c) == Some('.') {
                    chars.next();
                    while chars.peek().map(|(_, c)| c.is_ascii_digit()).unwrap_or(false) {
                        chars.next();
                    }
                }
                if matches!(chars.peek().map(|(_, c)| *c), Some('e') | Some('E')) {
                    chars.next();
                    if matches!(chars.peek().map(|(_, c)| *c), Some('+') | Some('-')) {
                        chars.next();
                    }
                    while chars.peek().map(|(_, c)| c.is_ascii_digit()).unwrap_or(false) {
                        chars.next();
                    }
                }

                // End of the numeric token = byte offset of whatever is peeked
                // next (or end-of-text). Always a char boundary since it comes
                // straight from char_indices.
                let num_end = chars.peek().map(|(bi, _)| *bi).unwrap_or(text.len());
                let num_str = &text[num_start..num_end];
                let num_val: f64 = num_str.parse().unwrap_or(0.0);
                let magnitude = num_val.abs();

                if magnitude > max_numeric_magnitude_seen {
                    max_numeric_magnitude_seen = magnitude;
                }
                if magnitude > policy.max_numeric_magnitude {
                    return Err(SAACPHardDrop::new(
                        SAACPBytecodes::RgcResourceLimitExceeded,
                        format!(
                            "RGC: max_numeric_magnitude exceeded: {} > {}",
                            magnitude, policy.max_numeric_magnitude
                        ),
                    ));
                }

                aggregate_resource_units += 1;
                Self::check_limit("max_aggregate_resource_units", aggregate_resource_units, policy.max_aggregate_resource_units)?;
                continue;
            }

            // Literals: true, false, null
            if ch == 't' && text[byte_i..].starts_with("true") {
                for _ in 0..4 { chars.next(); }
                continue;
            }
            if ch == 'f' && text[byte_i..].starts_with("false") {
                for _ in 0..5 { chars.next(); }
                continue;
            }
            if ch == 'n' && text[byte_i..].starts_with("null") {
                for _ in 0..4 { chars.next(); }
                continue;
            }

            // Unknown — advance defensively
            chars.next();
        }

        // Final bookkeeping for unclosed containers
        for fc in field_counts.values() {
            if *fc > max_field_count_seen {
                max_field_count_seen = *fc;
            }
        }
        for ac in array_element_counts.values() {
            if *ac > max_array_length_seen {
                max_array_length_seen = *ac;
            }
        }

        Ok(ScanStats {
            depth,
            max_depth_seen,
            object_count,
            array_count,
            total_nodes,
            max_array_length_seen,
            max_field_count_seen,
            max_string_length_seen,
            max_key_length_seen,
            total_string_chars,
            max_numeric_magnitude_seen,
            schema_complexity,
            aggregate_resource_units,
        })
    }

    /// Raise [`SAACPHardDrop`] immediately if `value > limit`.
    fn check_limit(name: &str, value: usize, limit: usize) -> Result<(), SAACPHardDrop> {
        if value > limit {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::RgcResourceLimitExceeded,
                format!("RGC: {} exceeded: {} > {}", name, value, limit),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_policy_values() {
        let p = RGCPolicy::default();
        assert_eq!(p.max_depth, 8);
        assert_eq!(p.max_object_count, 1000);
        assert_eq!(p.max_total_size, 1_048_576);
        assert_eq!(p.max_array_length, 256);
        assert!((p.max_numeric_magnitude - 1e18).abs() < 1.0);
    }

    #[test]
    fn test_check_simple_valid_json() {
        let payload = br#"{"task":"analyze CSV","count":42}"#;
        assert!(ResourceGovernanceParser::check(payload, None).is_ok());
    }

    #[test]
    fn test_check_empty_object() {
        assert!(ResourceGovernanceParser::check(b"{}", None).is_ok());
    }

    #[test]
    fn test_check_empty_array() {
        assert!(ResourceGovernanceParser::check(b"[]", None).is_ok());
    }

    #[test]
    fn test_check_null_literal() {
        assert!(ResourceGovernanceParser::check(b"null", None).is_ok());
    }

    #[test]
    fn test_max_total_size_exceeded() {
        let policy = RGCPolicy {
            max_total_size: 10,
            ..Default::default()
        };
        let payload = b"a".repeat(20);
        let result = ResourceGovernanceParser::check(&payload, Some(&policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_utf8() {
        let payload: &[u8] = &[0xFF, 0xFE, 0xFD];
        let result = ResourceGovernanceParser::check(payload, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_depth_exceeded() {
        // depth 9 with max_depth=8
        let payload = br#"{"a":{"b":{"c":{"d":{"e":{"f":{"g":{"h":1}}}}}}}}"#;
        let policy = RGCPolicy {
            max_depth: 4,
            ..Default::default()
        };
        let result = ResourceGovernanceParser::check(payload, Some(&policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_max_array_length_exceeded() {
        let mut s = String::from("[");
        for i in 0..300 {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&i.to_string());
        }
        s.push(']');
        let policy = RGCPolicy {
            max_array_length: 100,
            ..Default::default()
        };
        let result = ResourceGovernanceParser::check(s.as_bytes(), Some(&policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_max_string_length_exceeded() {
        let long_string = "x".repeat(70_000);
        let payload = format!("\"{}\"", long_string);
        let policy = RGCPolicy {
            max_string_length: 1000,
            ..Default::default()
        };
        let result = ResourceGovernanceParser::check(payload.as_bytes(), Some(&policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_max_field_count_exceeded() {
        let mut s = String::from("{");
        for i in 0..100 {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&format!("\"k{}\":{}", i, i));
        }
        s.push('}');
        let policy = RGCPolicy {
            max_field_count: 10,
            ..Default::default()
        };
        let result = ResourceGovernanceParser::check(s.as_bytes(), Some(&policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_max_numeric_magnitude_exceeded() {
        let payload = br#"{"val": 1e20}"#;
        let result = ResourceGovernanceParser::check(payload, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_schema_complexity() {
        // 3 colons → schema_complexity = 3
        let payload = br#"{"a":1,"b":2,"c":3}"#;
        let policy = RGCPolicy {
            max_schema_complexity: 2,
            ..Default::default()
        };
        let result = ResourceGovernanceParser::check(payload, Some(&policy));
        assert!(result.is_err());
    }

    #[test]
    fn test_nested_arrays() {
        let payload = br#"[[1,2],[3,4]]"#;
        assert!(ResourceGovernanceParser::check(payload, None).is_ok());
    }

    #[test]
    fn test_escaped_strings() {
        let payload = br#"{"key": "hello \"world\""}"#;
        assert!(ResourceGovernanceParser::check(payload, None).is_ok());
    }

    #[test]
    fn test_boolean_and_null_values() {
        let payload = br#"{"a":true,"b":false,"c":null}"#;
        assert!(ResourceGovernanceParser::check(payload, None).is_ok());
    }

    #[test]
    fn test_negative_numbers() {
        let payload = br#"{"val": -42.5}"#;
        assert!(ResourceGovernanceParser::check(payload, None).is_ok());
    }

    #[test]
    fn test_scientific_notation() {
        let payload = br#"{"val": 1.5e10}"#;
        assert!(ResourceGovernanceParser::check(payload, None).is_ok());
    }

    // ── ExecutionBudgetGuard tests ─────────────────────────────────────

    #[test]
    fn test_budget_guard_creation() {
        let guard = ExecutionBudgetGuard::new(5.0).unwrap();
        assert!(guard.remaining_seconds() > 0.0);
        assert!(!guard.is_timed_out());
    }

    #[test]
    fn test_budget_guard_invalid_timeout() {
        assert!(ExecutionBudgetGuard::new(0.0).is_err());
        assert!(ExecutionBudgetGuard::new(-1.0).is_err());
    }

    #[test]
    fn test_budget_guard_check_ok() {
        let guard = ExecutionBudgetGuard::new(10.0).unwrap();
        assert!(guard.check().is_ok());
    }

    #[test]
    fn test_budget_guard_remaining() {
        let guard = ExecutionBudgetGuard::new(5.0).unwrap();
        let remaining = guard.remaining_seconds();
        assert!(remaining > 4.0 && remaining <= 5.0);
    }

    /// Task: execution_budget_guard_timeout_fires
    /// check() must return RgcResourceLimitExceeded after the budget expires.
    #[test]
    fn execution_budget_guard_timeout_fires() {
        // Very short budget: 10ms
        let guard = ExecutionBudgetGuard::new(0.01).unwrap();
        // Immediately it should be OK
        assert!(guard.check().is_ok(), "guard must be OK immediately after creation");
        // Sleep 50ms to guarantee deadline has passed
        std::thread::sleep(std::time::Duration::from_millis(50));
        // Now check() must raise an error
        let result = guard.check();
        assert!(result.is_err(), "guard.check() must fail after timeout");
        let err = result.unwrap_err();
        assert_eq!(
            err.bytecode, crate::errors::SAACPBytecodes::RgcResourceLimitExceeded,
            "timeout must produce RgcResourceLimitExceeded bytecode"
        );
    }
}
