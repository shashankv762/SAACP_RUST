//! test_pecf_rs.rs — PECF error confidentiality tests
//!
//! Ports Python: tests/test_pecf.py, tests/test_error_translation.py
//! ExternalCode mappings, deployment profiles, SREL timing, SDL.

#![allow(clippy::assertions_on_constants)]

use std::sync::Mutex;

// Serialise all tests that mutate the global DeploymentProfile to avoid races.
static PROFILE_LOCK: Mutex<()> = Mutex::new(());

use saacp::{
    ExternalCode, ExternalResponse, PECFFilter, SREL, SecureDiagnosticLedger, SdlEntry,
    DeploymentProfile, internal_to_external, internal_to_external_raw,
    get_active_profile, set_active_profile,
    SDL_MAX_ENTRIES, SREL_FLOOR_SECONDS, SREL_WIRE_RESPONSE_SIZE, PECF_MARKER,
    SAACPHardDrop, SAACPBytecodes,
};

fn make_sdl_entry(correlation_id: &str, bytecode: u8) -> SdlEntry {
    SdlEntry {
        correlation_id: correlation_id.to_string(),
        timestamp: 0.0,
        internal_bytecode: bytecode,
        internal_message: "test".to_string(),
        validation_stage: "framing".to_string(),
        external_code: ExternalCode::InternalFailure,
        session_id_hash: String::new(),
        ip_hash: String::new(),
        deployment_profile: "PRODUCTION".to_string(),
        remediation_hint: String::new(),
    }
}

// ─── ExternalCode variants ───────────────────────────────────────────────────

#[test]
fn test_external_code_request_rejected() {
    let code = internal_to_external_raw(SAACPBytecodes::MalformedHeader as u8);
    assert!(matches!(code, ExternalCode::RequestRejected));
}

#[test]
fn test_external_code_access_denied() {
    let code = internal_to_external_raw(SAACPBytecodes::InvalidSignature as u8);
    assert!(matches!(code, ExternalCode::AccessDenied));
}

#[test]
fn test_external_code_rate_limited() {
    let code = internal_to_external_raw(SAACPBytecodes::CircuitBreakerOpen as u8);
    assert!(matches!(code, ExternalCode::RateLimited));
}

#[test]
fn test_external_code_session_terminated() {
    let code = internal_to_external_raw(SAACPBytecodes::BudgetExceeded as u8);
    assert!(matches!(code, ExternalCode::SessionTerminated));
}

#[test]
fn test_external_code_service_unavailable() {
    let code = internal_to_external_raw(SAACPBytecodes::StateExpiredOrStale as u8);
    assert!(matches!(code, ExternalCode::ServiceUnavailable));
}

#[test]
fn test_external_code_internal_failure_unmapped() {
    // Unknown bytecode maps to InternalFailure
    let code = internal_to_external_raw(0xFF);
    assert!(matches!(code, ExternalCode::InternalFailure));
}

#[test]
fn test_external_code_access_denied_lateral_movement() {
    let code = internal_to_external_raw(SAACPBytecodes::LateralMovementBlocked as u8);
    assert!(matches!(code, ExternalCode::AccessDenied));
}

#[test]
fn test_external_code_access_denied_injection() {
    let code = internal_to_external_raw(SAACPBytecodes::PromptInjectionDetected as u8);
    assert!(matches!(code, ExternalCode::AccessDenied));
}

#[test]
fn test_external_code_schema_mismatch_request_rejected() {
    let code = internal_to_external_raw(SAACPBytecodes::SchemaMismatch as u8);
    assert!(matches!(code, ExternalCode::RequestRejected));
}

#[test]
fn test_all_bytecodes_map_without_panic() {
    for code in 0u8..=0x40 {
        let _ = internal_to_external_raw(code);
    }
}

#[test]
fn test_external_code_values() {
    assert_eq!(ExternalCode::RequestRejected as u8, 0x01);
    assert_eq!(ExternalCode::AccessDenied as u8, 0x02);
    assert_eq!(ExternalCode::SessionTerminated as u8, 0x03);
    assert_eq!(ExternalCode::RateLimited as u8, 0x04);
    assert_eq!(ExternalCode::ServiceUnavailable as u8, 0x05);
    assert_eq!(ExternalCode::InternalFailure as u8, 0x06);
}

#[test]
fn test_internal_to_external_enum_values() {
    assert!(matches!(
        internal_to_external(SAACPBytecodes::MalformedHeader),
        ExternalCode::RequestRejected
    ));
    assert!(matches!(
        internal_to_external(SAACPBytecodes::InvalidSignature),
        ExternalCode::AccessDenied
    ));
    assert!(matches!(
        internal_to_external(SAACPBytecodes::CircuitBreakerOpen),
        ExternalCode::RateLimited
    ));
    assert!(matches!(
        internal_to_external(SAACPBytecodes::StreamAbort),
        ExternalCode::SessionTerminated
    ));
    assert!(matches!(
        internal_to_external(SAACPBytecodes::StateSyncRequired),
        ExternalCode::ServiceUnavailable
    ));
    assert!(matches!(
        internal_to_external(SAACPBytecodes::Success),
        ExternalCode::InternalFailure
    ));
}

// ─── ExternalCode name() ─────────────────────────────────────────────────────

#[test]
fn test_external_code_name() {
    assert_eq!(ExternalCode::RequestRejected.name(), "REQUEST_REJECTED");
    assert_eq!(ExternalCode::AccessDenied.name(), "ACCESS_DENIED");
    assert_eq!(ExternalCode::SessionTerminated.name(), "SESSION_TERMINATED");
    assert_eq!(ExternalCode::RateLimited.name(), "RATE_LIMITED");
    assert_eq!(ExternalCode::ServiceUnavailable.name(), "SERVICE_UNAVAILABLE");
    assert_eq!(ExternalCode::InternalFailure.name(), "INTERNAL_FAILURE");
}

// ─── SREL wire format ────────────────────────────────────────────────────────

#[test]
fn test_srel_wire_response_size_is_64() {
    assert_eq!(SREL_WIRE_RESPONSE_SIZE, 64);
}

#[test]
fn test_srel_floor_seconds_positive() {
    assert!(SREL_FLOOR_SECONDS >= 0.0);
    assert!(SREL_FLOOR_SECONDS < 10.0);
}

#[test]
fn test_pecf_marker_is_0xfe() {
    assert_eq!(PECF_MARKER, 0xFE_u8);
}

// Spec §9.3: correlation_id must be exactly 32 ASCII hex chars (16 bytes hex-encoded).
const TEST_CORR: &str = "abcd1234ef567890abcd1234ef567890"; // 32 hex chars

#[test]
fn test_normalize_response_is_64_bytes() {
    let wire = SREL::normalize_response(ExternalCode::AccessDenied, TEST_CORR);
    assert_eq!(wire.len(), 64);
}

#[test]
fn test_normalize_response_first_byte_pecf_marker() {
    let wire = SREL::normalize_response(ExternalCode::RequestRejected, TEST_CORR);
    assert_eq!(wire[0], PECF_MARKER);
}

#[test]
fn test_normalize_response_second_byte_code() {
    let wire = SREL::normalize_response(ExternalCode::AccessDenied, TEST_CORR);
    assert_eq!(wire[1], ExternalCode::AccessDenied as u8);
}

#[test]
fn test_normalize_response_correlation_id_at_bytes_2_to_34() {
    // Spec §9.3: bytes [2..34] = 32 ASCII hex chars of the correlation_id
    let wire = SREL::normalize_response(ExternalCode::RateLimited, TEST_CORR);
    assert_eq!(&wire[2..34], TEST_CORR.as_bytes());
}

#[test]
fn test_normalize_response_padding_zeroes() {
    // Spec §9.3: bytes [34..64] = 30 zero bytes
    let wire = SREL::normalize_response(ExternalCode::InternalFailure, TEST_CORR);
    assert!(wire[34..].iter().all(|&b| b == 0));
}

#[test]
fn test_normalize_response_all_codes_64_bytes() {
    for code in [
        ExternalCode::RequestRejected,
        ExternalCode::AccessDenied,
        ExternalCode::SessionTerminated,
        ExternalCode::RateLimited,
        ExternalCode::ServiceUnavailable,
        ExternalCode::InternalFailure,
    ] {
        let wire = SREL::normalize_response(code, TEST_CORR);
        assert_eq!(wire.len(), 64, "code {:?} must produce 64-byte wire response", code);
    }
}

// ─── DeploymentProfile ────────────────────────────────────────────────────────

#[test]
fn test_deployment_profile_variants_exist() {
    let _ = DeploymentProfile::Production;
    let _ = DeploymentProfile::Staging;
    let _ = DeploymentProfile::Development;
}

#[test]
fn test_deployment_profile_default_is_production() {
    assert_eq!(DeploymentProfile::default(), DeploymentProfile::Production);
}

#[test]
fn test_deployment_profile_as_str() {
    assert_eq!(DeploymentProfile::Production.as_str(), "PRODUCTION");
    assert_eq!(DeploymentProfile::Staging.as_str(), "STAGING");
    assert_eq!(DeploymentProfile::Development.as_str(), "DEVELOPMENT");
}

#[test]
fn test_get_set_active_profile_roundtrip() {
    let _g = PROFILE_LOCK.lock().unwrap();
    let original = get_active_profile();
    set_active_profile(DeploymentProfile::Development);
    assert_eq!(get_active_profile(), DeploymentProfile::Development);
    set_active_profile(original);
}

// ─── PECFFilter ───────────────────────────────────────────────────────────────

#[test]
fn test_pecf_filter_translate_production_hides_detail() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Production);
    let ledger = SecureDiagnosticLedger::new();
    let exc = SAACPHardDrop::new(SAACPBytecodes::MalformedHeader, "internal secret detail");
    let resp = PECFFilter::translate(&exc, &ledger, b"session-1", "1.2.3.4");
    assert!(matches!(resp.code, ExternalCode::RequestRejected));
    assert!(resp.detail.is_none());
    assert_eq!(resp.correlation_id.len(), 32);
    ledger.clear();
    set_active_profile(DeploymentProfile::Production);
}

#[test]
fn test_pecf_filter_translate_development_includes_detail() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Development);
    let ledger = SecureDiagnosticLedger::new();
    let exc = SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "sig mismatch");
    let resp = PECFFilter::translate(&exc, &ledger, &[], "");
    assert!(matches!(resp.code, ExternalCode::AccessDenied));
    assert!(resp.detail.is_some());
    assert!(resp.detail.unwrap().contains("[DEV]"));
    ledger.clear();
    set_active_profile(DeploymentProfile::Production);
}

#[test]
fn test_pecf_filter_translate_logs_to_sdl() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Production);
    let ledger = SecureDiagnosticLedger::new();
    let exc = SAACPHardDrop::new(SAACPBytecodes::CircuitBreakerOpen, "rate limited");
    let _resp = PECFFilter::translate(&exc, &ledger, &[], "");
    assert_eq!(ledger.entry_count(), 1);
    ledger.clear();
    set_active_profile(DeploymentProfile::Production);
}

#[test]
fn test_pecf_filter_translate_raw_maps_correctly() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Production);
    let ledger = SecureDiagnosticLedger::new();
    let resp = PECFFilter::translate_raw(
        SAACPBytecodes::TokenExpired, "expired",
        &ledger, &[], "",
    );
    assert!(matches!(resp.code, ExternalCode::AccessDenied));
    ledger.clear();
    set_active_profile(DeploymentProfile::Production);
}

#[test]
fn test_pecf_filter_unique_correlation_ids() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Production);
    let ledger = SecureDiagnosticLedger::new();
    let exc = SAACPHardDrop::new(SAACPBytecodes::MalformedHeader, "x");
    let r1 = PECFFilter::translate(&exc, &ledger, &[], "");
    let r2 = PECFFilter::translate(&exc, &ledger, &[], "");
    assert_ne!(r1.correlation_id, r2.correlation_id);
    ledger.clear();
    set_active_profile(DeploymentProfile::Production);
}

// ─── ExternalResponse ─────────────────────────────────────────────────────────

#[test]
fn test_external_response_to_wire_production_64_bytes() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Production);
    let resp = ExternalResponse::new(ExternalCode::AccessDenied, "a".repeat(32), None);
    let wire = resp.to_wire();
    assert_eq!(wire.len(), 64);
    assert_eq!(wire[0], PECF_MARKER);
    assert_eq!(wire[1], ExternalCode::AccessDenied as u8);
    set_active_profile(DeploymentProfile::Production);
}

#[test]
fn test_external_response_to_wire_development_is_json() {
    let _g = PROFILE_LOCK.lock().unwrap();
    set_active_profile(DeploymentProfile::Development);
    let resp = ExternalResponse::new(
        ExternalCode::AccessDenied,
        "corr-123".to_string(),
        Some("dev detail".to_string()),
    );
    let wire = resp.to_wire();
    let json = String::from_utf8(wire).unwrap();
    assert!(json.contains("ACCESS_DENIED"));
    assert!(json.contains("corr-123"));
    assert!(json.contains("dev detail"));
    set_active_profile(DeploymentProfile::Production);
}

// ─── SecureDiagnosticLedger ───────────────────────────────────────────────────

#[test]
fn test_sdl_empty_initially() {
    let sdl = SecureDiagnosticLedger::new();
    assert_eq!(sdl.entry_count(), 0);
}

#[test]
fn test_sdl_record_and_entry_count() {
    let sdl = SecureDiagnosticLedger::new();
    sdl.record(make_sdl_entry("cid-1", 0x01));
    sdl.record(make_sdl_entry("cid-2", 0x03));
    assert_eq!(sdl.entry_count(), 2);
}

#[test]
fn test_sdl_query_without_filter_returns_all() {
    let sdl = SecureDiagnosticLedger::new();
    for i in 0..5u8 {
        sdl.record(make_sdl_entry(&format!("cid-{}", i), 0x01));
    }
    let results = sdl.query(None, 100);
    assert_eq!(results.len(), 5);
}

#[test]
fn test_sdl_query_with_correlation_id_filter() {
    let sdl = SecureDiagnosticLedger::new();
    sdl.record(make_sdl_entry("target-corr", 0x01));
    sdl.record(make_sdl_entry("other-corr", 0x03));
    let results = sdl.query(Some("target-corr"), 100);
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].correlation_id, "target-corr");
}

#[test]
fn test_sdl_query_limit_respected() {
    let sdl = SecureDiagnosticLedger::new();
    for i in 0..10u8 {
        sdl.record(make_sdl_entry(&format!("cid-{}", i), 0x01));
    }
    let results = sdl.query(None, 3);
    assert_eq!(results.len(), 3);
}

#[test]
fn test_sdl_query_nonexistent_correlation_returns_empty() {
    let sdl = SecureDiagnosticLedger::new();
    sdl.record(make_sdl_entry("existing", 0x01));
    let results = sdl.query(Some("nonexistent"), 100);
    assert!(results.is_empty());
}

#[test]
fn test_sdl_clear_resets_count() {
    let sdl = SecureDiagnosticLedger::new();
    sdl.record(make_sdl_entry("c1", 0x01));
    sdl.clear();
    assert_eq!(sdl.entry_count(), 0);
}

#[test]
fn test_sdl_max_entries_constant() {
    assert_eq!(SDL_MAX_ENTRIES, 100_000);
}

#[test]
fn test_sdl_max_entries_evicts_oldest() {
    let sdl = SecureDiagnosticLedger::new();
    for i in 0..(SDL_MAX_ENTRIES + 10) {
        sdl.record(SdlEntry {
            correlation_id: format!("cid-{}", i),
            timestamp: i as f64,
            internal_bytecode: 0x01,
            internal_message: "msg".to_string(),
            validation_stage: "framing".to_string(),
            external_code: ExternalCode::RequestRejected,
            session_id_hash: String::new(),
            ip_hash: String::new(),
            deployment_profile: "PRODUCTION".to_string(),
            remediation_hint: String::new(),
        });
    }
    assert_eq!(sdl.entry_count(), SDL_MAX_ENTRIES);
    let oldest = sdl.query(Some("cid-0"), 10);
    assert!(oldest.is_empty(), "Oldest entries must have been evicted");
    sdl.clear();
}

#[test]
fn test_sdl_entry_to_json_not_empty() {
    let entry = make_sdl_entry("test-json", 0x01);
    let json = entry.to_json();
    assert!(json.contains("test-json"));
    assert!(json.contains("framing"));
}
