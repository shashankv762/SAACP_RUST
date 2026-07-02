#![no_main]
// BREAKIT Phase 1: Mutation Fuzzer for Injection Scanner Bypass
//
// This fuzzer does NOT start from known malicious strings.
// It starts from a corpus of BENIGN strings and mutates bytes randomly,
// searching for any mutation that:
//   (a) the scanner allows through (returns Ok, no PromptInjectionDetected)
//   (b) but which, when independently NFKC-normalized by a DIFFERENT
//       normalization path (not the scanner's own internal path), decodes
//       to a recognizable injection root pattern
//
// Also directly tests FINDING-1: any UTF-8 string with .len() > 16384 where
// the split byte is mid-codepoint will cause normalize() to PANIC.
//
// Fuzzer corpus directory: fuzz/corpus/fuzz_bypass_injection_scanner/
// Seed it with: echo -n "safe text here" > fuzz/corpus/.../seed_safe.txt

use libfuzzer_sys::fuzz_target;
use unicode_normalization::UnicodeNormalization;

const KNOWN_INJECTION_ROOTS: &[&str] = &[
    "ignoreprevious",
    "ignoreabove",
    "ignoreallinstructions",
    "disregardprevious",
    "systemoverride",
    "youarenowa",
    "newinstructions",
    "jailbreak",
    "bypassfilters",
    "disablesafety",
    "developermode",
];

fuzz_target!(|data: &[u8]| {
    let text = match std::str::from_utf8(data) {
        Ok(s) => s,
        Err(_) => return, // skip invalid UTF-8 — we'll handle boundary panics via valid UTF-8
    };

    // ── FINDING-1 CHECK: panic on UTF-8 boundary slice ────────────────────────
    //
    // If text.len() > MAX_SCAN_LENGTH and the byte at position MAX_SCAN_LENGTH
    // is a UTF-8 continuation byte, normalize() will panic.
    // We wrap in catch_unwind to capture the panic as a finding rather than crash.
    let scan_result = std::panic::catch_unwind(|| {
        let jv = saacp::JsonValue::String(text.to_string());
        saacp::PromptInjectionScanner::scan_payload(&jv, 0)
    });

    match scan_result {
        Err(_panic) => {
            // FINDING-1 REPRODUCED: normalize() panicked on this input.
            // libFuzzer will save this input automatically as a crash.
            // Re-panic to let libFuzzer record the finding.
            panic!(
                "FINDING-1: normalize() panicked on input of {} bytes. \
                 Byte at boundary [{}] = {:#04x}",
                data.len(),
                saacp::PromptInjectionScanner::MAX_SCAN_LENGTH,
                if data.len() > saacp::PromptInjectionScanner::MAX_SCAN_LENGTH {
                    data[saacp::PromptInjectionScanner::MAX_SCAN_LENGTH]
                } else {
                    0
                }
            );
        }
        Ok(Ok(())) => {
            // ── FINDING-4 CHECK: scanner bypass via unicode deletion ───────────
            //
            // The scanner returned Ok (no injection detected).
            // Now independently normalize using NFKC via the unicode-normalization crate
            // and check if the result matches any known injection root.
            //
            // If the independent normalization finds a root that the scanner missed,
            // we have a bypass.
            let independently_normalized: String = text.nfkc().collect();
            let lower = independently_normalized.to_lowercase();
            // Also strip all non-ASCII chars (simulating how a downstream LLM
            // tokenizer would handle the input after its own preprocessing)
            let ascii_only: String = lower.chars()
                .filter(|c| c.is_ascii())
                .collect();
            let no_whitespace: String = ascii_only.chars()
                .filter(|c| !c.is_whitespace())
                .collect();

            for root in KNOWN_INJECTION_ROOTS {
                if no_whitespace.contains(root) {
                    // BYPASS FOUND: scanner said OK but independent normalization
                    // reveals a known injection pattern in the text.
                    panic!(
                        "FINDING-4 BYPASS: scanner returned Ok() but independent \
                         NFKC+ASCII-filter normalization found root '{}' in input: {:?}\n\
                         Original text (first 200 chars): {:?}\n\
                         Independently normalized: {:?}",
                        root,
                        &text[..text.len().min(200)],
                        &text[..text.len().min(200)],
                        &no_whitespace[..no_whitespace.len().min(200)]
                    );
                }
            }
        }
        Ok(Err(_)) => {
            // Scanner caught it — this is the CORRECT behavior.
            // No action needed.
        }
    }
});
