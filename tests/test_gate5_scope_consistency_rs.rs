//! test_gate5_scope_consistency_rs.rs — Gate 5.0b regression proof (Attack 7.2)
//!
//! Gate 5.0 (`gate_5_0_epistemic_cb`) trusts a self-reported confidence float
//! with only a NaN guard and an overclaim check — nothing ties a *high*
//! confidence claim to what the request is actually authorized to assert.
//! Attack 7.2 (fake high confidence): a schema-3 ("Epistemic") response
//! claims near-certain confidence to vouch for a `data` claim that has
//! nothing to do with the signed root intent — Gate 5.0 alone happily lets
//! it through as long as the confidence value itself looks plausible.
//!
//! Gate 5.0b (`gate_5_0b_scope_consistency`) closes this: when a root intent
//! is bound, the claimed `data` content must stay consistent with it,
//! regardless of the confidence value — a self-reported float can never
//! substitute for scope authorization. Deliberately additive: it does not
//! touch `gate_5_0_epistemic_cb`'s own signature or behavior.

use std::collections::HashMap;
use saacp::{SAACPProtocolHandler, JsonValue};

const ROOT_INTENT: &str = "analyze quarterly financial report for board review";

fn schema3_payload(confidence: f64, data: &str) -> HashMap<String, JsonValue> {
    let mut pd = HashMap::new();
    pd.insert("epistemic_metadata".into(), JsonValue::Number(confidence));
    pd.insert("data".into(), JsonValue::String(data.to_string()));
    pd
}

// ─── Attack 7.2 regression: fake high confidence must not bypass scope ───────

#[test]
fn attack_7_2_fake_high_confidence_on_off_scope_claim_rejected() {
    let payload = schema3_payload(0.97, "wire transfer approval for offshore account 88213");

    // Gate 5.0 alone (confidence-only) passes — this is exactly the gap
    // Attack 7.2 exploits: a plausible-looking confidence value alone says
    // nothing about whether the claim is in scope.
    assert!(
        SAACPProtocolHandler::gate_5_0_epistemic_cb(3, &payload).is_ok(),
        "sanity: Gate 5.0 alone must not reject on confidence grounds here — \
         proving Gate 5.0b, not Gate 5.0, is what catches this"
    );

    // Gate 5.0b must catch what Gate 5.0 alone cannot.
    let result = SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, Some(ROOT_INTENT));
    assert!(
        result.is_err(),
        "a high-confidence claim whose data is off-scope from the root intent must be rejected"
    );
}

#[test]
fn attack_7_2_variant_near_max_credible_confidence_still_rejected() {
    // 0.98 — just under the overclaim threshold (0.99), i.e. the most
    // credible-looking confidence an attacker could plausibly fake.
    let payload = schema3_payload(0.98, "grant admin access to external-contractor-99");
    let result = SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, Some(ROOT_INTENT));
    assert!(
        result.is_err(),
        "even a near-maximum credible confidence value must not grant scope it doesn't have"
    );
}

// ─── Control: on-scope claims must not be falsely flagged ────────────────────

#[test]
fn on_scope_claim_with_high_confidence_passes() {
    let payload = schema3_payload(0.96, ROOT_INTENT);
    assert!(
        SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, Some(ROOT_INTENT)).is_ok(),
        "a claim that matches the root intent must not be rejected by Gate 5.0b"
    );
}

#[test]
fn on_scope_claim_with_low_confidence_still_passes_5_0b_but_not_5_0() {
    // Gate 5.0b only checks scope consistency, not confidence — a low
    // confidence value is Gate 5.0's problem, not Gate 5.0b's.
    let payload = schema3_payload(0.10, ROOT_INTENT);
    assert!(
        SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, Some(ROOT_INTENT)).is_ok(),
        "Gate 5.0b must not reject on confidence grounds — that's Gate 5.0's job"
    );
    assert!(
        SAACPProtocolHandler::gate_5_0_epistemic_cb(3, &payload).is_err(),
        "sanity: Gate 5.0 itself must still reject the low-confidence claim"
    );
}

// ─── No-op conditions: Gate 5.0b must never fire outside its narrow scope ────

#[test]
fn no_root_intent_bound_is_a_noop() {
    // No intent envelope bound to this request at all — nothing to check
    // consistency against, so Gate 5.0b must not fire regardless of content.
    let payload = schema3_payload(0.97, "wire transfer approval for offshore account 88213");
    assert!(
        SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, None).is_ok(),
        "Gate 5.0b must be a no-op when no root intent is bound"
    );
}

#[test]
fn missing_data_field_is_a_noop() {
    let mut payload = HashMap::new();
    payload.insert("epistemic_metadata".into(), JsonValue::Number(0.97));
    assert!(
        SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, Some(ROOT_INTENT)).is_ok(),
        "Gate 5.0b must be a no-op when the payload has no 'data' field to check"
    );
}

#[test]
fn non_string_data_field_is_a_noop() {
    let mut payload = HashMap::new();
    payload.insert("epistemic_metadata".into(), JsonValue::Number(0.97));
    payload.insert("data".into(), JsonValue::Number(42.0));
    assert!(
        SAACPProtocolHandler::gate_5_0b_scope_consistency(&payload, Some(ROOT_INTENT)).is_ok(),
        "Gate 5.0b must be a no-op for non-textual 'data' claims (lexical overlap doesn't apply)"
    );
}
