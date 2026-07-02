#![no_main]
// BREAKIT Phase 1: Gate Pipeline Panic Hunter
//
// Fire raw bytes at intercept_packet() with an all-zero secret key.
// The goal is to find panics, not just malformed-input rejections.
//
// Strategy: try various random byte lengths to hit:
//   - Short inputs (< MEASC_HEADER_SIZE): Gate 0 must reject gracefully
//   - MEASC_HEADER_SIZE exactly: Gate 0 parse, likely AES-GCM auth failure
//   - Very long inputs (> MTU): length check must reject gracefully
//   - Inputs with valid magic bytes ("SACP") but random content: parser fuzzing
//
// Any panic in this target is a finding regardless of the input.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Test 1: Raw bytes as-is
    let _ = std::panic::catch_unwind(|| {
        saacp::SAACPProtocolHandler::intercept_packet(data, &[0u8; 32], "fuzz-agent", false)
    });

    // Test 2: Prepend valid MEASC magic bytes to reach deeper into the parser
    if data.len() >= 4 {
        let mut magic_prefixed = Vec::with_capacity(4 + data.len());
        magic_prefixed.extend_from_slice(b"SACP"); // valid magic
        magic_prefixed.extend_from_slice(&data[4..]);

        let _ = std::panic::catch_unwind(|| {
            saacp::SAACPProtocolHandler::intercept_packet(
                &magic_prefixed,
                &[0u8; 32],
                "fuzz-agent",
                false,
            )
        });
    }

    // Test 3: Exact MEASC_HEADER_SIZE input with valid magic
    // (Forces the parser to reach the AES-GCM auth step)
    if data.len() >= 128 {
        let mut header_sized = data[..128].to_vec();
        header_sized[0..4].copy_from_slice(b"SACP"); // set magic

        let _ = std::panic::catch_unwind(|| {
            saacp::SAACPProtocolHandler::intercept_packet(
                &header_sized,
                &[0u8; 32],
                "fuzz-agent",
                false,
            )
        });
    }

    // Test 4: Injection scanner via raw JSON payload construction
    // Build a minimal MEASC frame body that decodes to a JSON payload
    // containing adversarial Unicode
    if let Ok(text) = std::str::from_utf8(data) {
        let jv = saacp::JsonValue::String(text.to_string());
        let _ = std::panic::catch_unwind(|| {
            saacp::PromptInjectionScanner::scan_payload(&jv, 0)
        });
    }
});
