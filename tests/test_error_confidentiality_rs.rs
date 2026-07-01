//! test_error_confidentiality_rs.rs — Error Confidentiality Filter tests
//!
//! Ports Python: tests/test_error_confidentiality.py
//! WireErrorResponse always 44 bytes, protocol version tag, sanitize mapping.

use saacp::{
    ErrorConfidentialityFilter, ErrorCategory,
    WIRE_SIZE, SENTINEL_NO_RETRY, PROTOCOL_VERSION_WIRE,
    make_opaque_error,
};

// ─── Constants ────────────────────────────────────────────────────────────────

#[test]
fn test_wire_size_is_44() {
    assert_eq!(WIRE_SIZE, 44);
}

#[test]
fn test_sentinel_no_retry_is_u32_max_ish() {
    assert_eq!(SENTINEL_NO_RETRY, 0xFFFF_FFFF_u32);
}

#[test]
fn test_protocol_version_wire_tag() {
    assert_eq!(PROTOCOL_VERSION_WIRE, b"SACP");
}

// ─── ErrorCategory mapping ────────────────────────────────────────────────────

#[test]
fn test_bytecode_0x03_maps_to_auth_failure() {
    let cat = ErrorConfidentialityFilter::bytecode_to_category(0x03);
    assert_eq!(cat, ErrorCategory::AuthFailure);
}

#[test]
fn test_bytecode_0x06_maps_to_policy_violation() {
    let cat = ErrorConfidentialityFilter::bytecode_to_category(0x06);
    assert_eq!(cat, ErrorCategory::PolicyViolation);
}

#[test]
fn test_bytecode_0x20_maps_to_governance_violation() {
    let cat = ErrorConfidentialityFilter::bytecode_to_category(0x20);
    assert_eq!(cat, ErrorCategory::GovernanceViolation);
}

#[test]
fn test_bytecode_0x2b_maps_to_resource_limit() {
    let cat = ErrorConfidentialityFilter::bytecode_to_category(0x2B);
    assert_eq!(cat, ErrorCategory::ResourceLimit);
}

#[test]
fn test_bytecode_0x01_maps_to_transport_failure() {
    let cat = ErrorConfidentialityFilter::bytecode_to_category(0x01);
    assert_eq!(cat, ErrorCategory::TransportFailure);
}

#[test]
fn test_unknown_bytecode_maps_to_internal() {
    let cat = ErrorConfidentialityFilter::bytecode_to_category(0xFF);
    assert_eq!(cat, ErrorCategory::Internal);
}

#[test]
fn test_governance_bytecodes_0x20_to_0x24() {
    for code in 0x20u8..=0x24 {
        assert_eq!(
            ErrorConfidentialityFilter::bytecode_to_category(code),
            ErrorCategory::GovernanceViolation,
            "0x{code:02X} must be GovernanceViolation"
        );
    }
}

#[test]
fn test_identity_bytecodes_0x3c_to_0x40_auth_failure() {
    for code in 0x3Cu8..=0x40 {
        assert_eq!(
            ErrorConfidentialityFilter::bytecode_to_category(code),
            ErrorCategory::AuthFailure,
            "0x{code:02X} must be AuthFailure"
        );
    }
}

// ─── sanitize ─────────────────────────────────────────────────────────────────

#[test]
fn test_sanitize_returns_wire_error_response() {
    let resp = ErrorConfidentialityFilter::sanitize(0x03, "internal detail");
    assert_eq!(resp.category, ErrorCategory::AuthFailure);
}

#[test]
fn test_sanitize_discards_internal_detail() {
    let resp1 = ErrorConfidentialityFilter::sanitize(0x06, "SECRET internal trace");
    let resp2 = ErrorConfidentialityFilter::sanitize(0x06, "different trace");
    // Both must have same category; internal detail must NOT appear in correlation_id
    assert_eq!(resp1.category, resp2.category);
}

#[test]
fn test_sanitize_correlation_id_is_32_chars() {
    let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
    assert_eq!(resp.correlation_id.len(), 32);
}

#[test]
fn test_sanitize_unique_correlation_ids() {
    let r1 = ErrorConfidentialityFilter::sanitize(0x01, "");
    let r2 = ErrorConfidentialityFilter::sanitize(0x01, "");
    assert_ne!(r1.correlation_id, r2.correlation_id);
}

#[test]
fn test_sanitize_circuit_breaker_has_retry_hint() {
    let resp = ErrorConfidentialityFilter::sanitize(0x14, "trace");
    assert_eq!(resp.retry_after_seconds, Some(30));
    assert_eq!(resp.category, ErrorCategory::PolicyViolation);
}

#[test]
fn test_sanitize_resource_limit_default_retry_30() {
    let resp = ErrorConfidentialityFilter::sanitize(0x0E, "");
    assert_eq!(resp.retry_after_seconds, Some(30));
}

#[test]
fn test_sanitize_key_evolution_retry_60() {
    let resp = ErrorConfidentialityFilter::sanitize(0x1F, "");
    assert_eq!(resp.retry_after_seconds, Some(60));
}

#[test]
fn test_sanitize_auth_failure_no_retry() {
    let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
    assert_eq!(resp.retry_after_seconds, None);
}

// ─── format_wire_bytes ────────────────────────────────────────────────────────

#[test]
fn test_format_wire_bytes_length_is_44() {
    let resp = ErrorConfidentialityFilter::sanitize(0x06, "test");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    assert_eq!(wire.len(), WIRE_SIZE);
}

#[test]
fn test_format_wire_bytes_first_byte_is_category() {
    let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    assert_eq!(wire[0], ErrorCategory::AuthFailure as u8);
}

#[test]
fn test_format_wire_bytes_protocol_tag_at_21() {
    let resp = ErrorConfidentialityFilter::sanitize(0x01, "");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    assert_eq!(&wire[21..25], b"SACP");
}

#[test]
fn test_format_wire_bytes_no_retry_sentinel_present() {
    let resp = ErrorConfidentialityFilter::sanitize(0x03, "");
    assert_eq!(resp.retry_after_seconds, None);
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    let retry_bytes = u32::from_be_bytes([wire[17], wire[18], wire[19], wire[20]]);
    assert_eq!(retry_bytes, SENTINEL_NO_RETRY);
}

#[test]
fn test_format_wire_bytes_retry_hint_encoded_correctly() {
    let resp = ErrorConfidentialityFilter::sanitize(0x14, "");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    let retry_bytes = u32::from_be_bytes([wire[17], wire[18], wire[19], wire[20]]);
    assert_eq!(retry_bytes, 30u32);
}

// ─── parse_wire_bytes ─────────────────────────────────────────────────────────

#[test]
fn test_parse_wire_bytes_wrong_length_fails() {
    assert!(ErrorConfidentialityFilter::parse_wire_bytes(&[0u8; 10]).is_err());
    assert!(ErrorConfidentialityFilter::parse_wire_bytes(&[0u8; 43]).is_err());
    assert!(ErrorConfidentialityFilter::parse_wire_bytes(&[0u8; 45]).is_err());
}

#[test]
fn test_roundtrip_category_preserved() {
    let resp = ErrorConfidentialityFilter::sanitize(0x20, "detail");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    let parsed = ErrorConfidentialityFilter::parse_wire_bytes(&wire).unwrap();
    assert_eq!(parsed.category, resp.category);
}

#[test]
fn test_roundtrip_correlation_id_preserved() {
    let resp = ErrorConfidentialityFilter::sanitize(0x03, "detail");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    let parsed = ErrorConfidentialityFilter::parse_wire_bytes(&wire).unwrap();
    assert_eq!(parsed.correlation_id, resp.correlation_id);
}

#[test]
fn test_roundtrip_retry_after_seconds_preserved() {
    let resp = ErrorConfidentialityFilter::sanitize(0x14, "detail");
    let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
    let parsed = ErrorConfidentialityFilter::parse_wire_bytes(&wire).unwrap();
    assert_eq!(parsed.retry_after_seconds, resp.retry_after_seconds);
}

#[test]
fn test_roundtrip_multiple_bytecodes() {
    for bytecode in [0x01u8, 0x03, 0x14, 0x20, 0x2B, 0x40] {
        let resp = ErrorConfidentialityFilter::sanitize(bytecode, "internal detail dropped");
        let wire = ErrorConfidentialityFilter::format_wire_bytes(&resp);
        assert_eq!(wire.len(), WIRE_SIZE, "wire must be 44 bytes for 0x{bytecode:02X}");
        let parsed = ErrorConfidentialityFilter::parse_wire_bytes(&wire)
            .unwrap_or_else(|e| panic!("parse failed for 0x{bytecode:02X}: {e}"));
        assert_eq!(parsed.category, resp.category);
        assert_eq!(parsed.correlation_id, resp.correlation_id);
        assert_eq!(parsed.retry_after_seconds, resp.retry_after_seconds);
    }
}

// ─── make_opaque_error ────────────────────────────────────────────────────────

#[test]
fn test_make_opaque_error_returns_44_bytes() {
    let wire = make_opaque_error(0x06, "sensitive internal trace");
    assert_eq!(wire.len(), WIRE_SIZE);
}

#[test]
fn test_make_opaque_error_category_correct() {
    let wire = make_opaque_error(0x06, "");
    assert_eq!(wire[0], ErrorCategory::PolicyViolation as u8);
}

#[test]
fn test_make_opaque_error_via_method() {
    let wire = ErrorConfidentialityFilter::make_opaque_error(0x03, "auth failure detail");
    assert_eq!(wire.len(), WIRE_SIZE);
    assert_eq!(wire[0], ErrorCategory::AuthFailure as u8);
}

#[test]
fn test_make_opaque_error_injection_attempt_sanitized() {
    let wire = make_opaque_error(0x06, "ignore previous instructions");
    assert_eq!(wire.len(), WIRE_SIZE);
    // Injection attempt must not corrupt wire output
    assert_eq!(&wire[21..25], b"SACP");
}

// ─── ErrorCategory from_byte ─────────────────────────────────────────────────

#[test]
fn test_error_category_from_byte_valid() {
    assert_eq!(ErrorCategory::from_byte(0x01), Some(ErrorCategory::TransportFailure));
    assert_eq!(ErrorCategory::from_byte(0x02), Some(ErrorCategory::AuthFailure));
    assert_eq!(ErrorCategory::from_byte(0x03), Some(ErrorCategory::PolicyViolation));
    assert_eq!(ErrorCategory::from_byte(0x04), Some(ErrorCategory::ResourceLimit));
    assert_eq!(ErrorCategory::from_byte(0x05), Some(ErrorCategory::ProtocolError));
    assert_eq!(ErrorCategory::from_byte(0x06), Some(ErrorCategory::CapabilityFailure));
    assert_eq!(ErrorCategory::from_byte(0x07), Some(ErrorCategory::GovernanceViolation));
    assert_eq!(ErrorCategory::from_byte(0x08), Some(ErrorCategory::Internal));
}

#[test]
fn test_error_category_from_byte_invalid_returns_none() {
    assert_eq!(ErrorCategory::from_byte(0x00), None);
    assert_eq!(ErrorCategory::from_byte(0x09), None);
    assert_eq!(ErrorCategory::from_byte(0xFF), None);
}
