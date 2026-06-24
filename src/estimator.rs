// SAACP Rust Implementation — AutonomousTokenEstimator
// Translated from SAACP/src/saacp/estimator.py
//!
//! Lightweight cost estimator for autonomous agent payloads.
//! Estimates the token budget required to process a JSON payload
//! so that gate and budget checks can short-circuit oversized
//! requests before they consume expensive resources.

use serde_json::Value as JsonValue;

/// Autonomous Token Estimator.
///
/// Provides a fast, deterministic cost estimate for a JSON payload
/// without requiring a live LLM call.  The formula mirrors the Python
/// reference:  `int(len(json.dumps(d)) / 4 * complexity_multiplier) + 50`.
pub struct AutonomousTokenEstimator;

impl AutonomousTokenEstimator {
    /// Estimate the token cost of a JSON payload.
    ///
    /// `complexity_multiplier` should be >= 1.0.  Values above 1.0
    /// account for structured / nested payloads that inflate token counts
    /// beyond their raw byte length.
    pub fn estimate_cost(payload: &JsonValue, complexity_multiplier: f64) -> usize {
        let serialized = serde_json::to_string(payload).unwrap_or_default();
        let byte_len = serialized.len() as f64;
        let cost = (byte_len / 4.0 * complexity_multiplier) as usize + 50;
        cost
    }

    /// Convenience wrapper with default multiplier of 1.0.
    pub fn estimate_cost_default(payload: &JsonValue) -> usize {
        Self::estimate_cost(payload, 1.0)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_estimate_cost_empty_object() {
        let v: JsonValue = serde_json::from_str("{}").unwrap();
        let cost = AutonomousTokenEstimator::estimate_cost_default(&v);
        // "{}" = 2 bytes → 2/4 * 1.0 = 0 → 0 + 50 = 50
        assert_eq!(cost, 50);
    }

    #[test]
    fn test_estimate_cost_with_multiplier() {
        let v: JsonValue = serde_json::from_str(r#"{"key":"value"}"#).unwrap();
        let cost_1x = AutonomousTokenEstimator::estimate_cost(&v, 1.0);
        let cost_2x = AutonomousTokenEstimator::estimate_cost(&v, 2.0);
        // 2x multiplier should produce a larger cost
        assert!(cost_2x > cost_1x);
    }

    #[test]
    fn test_estimate_cost_larger_payload() {
        let small: JsonValue = serde_json::from_str(r#"{"a":1}"#).unwrap();
        let large: JsonValue = serde_json::from_str(
            r#"{"a":1,"b":"a long string value","c":[1,2,3,4,5],"d":{"nested":true}}"#,
        )
        .unwrap();
        let cost_small = AutonomousTokenEstimator::estimate_cost_default(&small);
        let cost_large = AutonomousTokenEstimator::estimate_cost_default(&large);
        assert!(cost_large > cost_small);
    }

    #[test]
    fn test_estimate_cost_minimum_is_50() {
        // Even for an empty payload the baseline is 50
        let v: JsonValue = serde_json::from_str("null").unwrap();
        let cost = AutonomousTokenEstimator::estimate_cost_default(&v);
        assert!(cost >= 50);
    }
}
