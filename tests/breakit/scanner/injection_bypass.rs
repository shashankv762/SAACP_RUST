// BREAKIT: Injection Scanner Attack Tests
//
// FINDING-1 (CRITICAL, FIXED): scanner panicked on UTF-8 boundary slice.
//   text.len() returns byte count; &str slicing at a non-char-boundary panics.
//   FIX: normalize() now walks back to the nearest char boundary before
//   slicing (src/handler.rs). These tests are regression guards — they now
//   assert normalize()/scan_payload() do NOT panic on boundary bombs.
//
// FINDING-4 (HIGH, largely already mitigated): unicode deletion bypass.
//   The confusable-replacement table already covers Greek iota, Latin dotless
//   ı, and Cyrillic а (the three PoC characters below), so the specific
//   "silent drop of a keyword-prefix homoglyph" bypass they demonstrate is
//   blocked. `finding_4_systematic_position_spray` still shows that inserting
//   ANY single character (mapped or not) inside a keyword defeats literal
//   substring matching — that is an inherent limitation of exact keyword
//   scanning (see the doc comment on `normalize()`), not something a 3-line
//   patch fixes, so that test remains observational/documenting rather than
//   a hard assertion.

use saacp::{PromptInjectionScanner, JsonValue};

// ─── FINDING-1: UTF-8 Boundary Panic ─────────────────────────────────────────

/// Build a string of exactly `n` bytes by repeating ASCII 'A',
/// then append a 2-byte UTF-8 codepoint so the total exceeds MAX_SCAN_LENGTH
/// with the boundary falling mid-codepoint.
fn make_utf8_boundary_bomb(lead_ascii_count: usize) -> String {
    // 'é' = U+00E9 = 0xC3 0xA9 (2 bytes in UTF-8)
    // We want lead_ascii_count == MAX_SCAN_LENGTH - 1 so that:
    //   total bytes = (MAX_SCAN_LENGTH - 1) + 2 = MAX_SCAN_LENGTH + 1
    //   slicing at MAX_SCAN_LENGTH cuts through the FIRST byte of 'é' → panic
    let mut s = "A".repeat(lead_ascii_count);
    s.push('é'); // push the 2-byte codepoint
    s
}

/// FINDING-1 REGRESSION GUARD: calling normalize() on this string must NOT
/// panic, even though &text[..16384] would split the 'é' codepoint in half.
/// normalize() must walk back to a char boundary before slicing.
#[test]
fn finding_1_utf8_boundary_slice_panics() {
    let bomb = make_utf8_boundary_bomb(PromptInjectionScanner::MAX_SCAN_LENGTH - 1);

    // Sanity: string must be longer than MAX_SCAN_LENGTH bytes
    assert!(
        bomb.len() > PromptInjectionScanner::MAX_SCAN_LENGTH,
        "precondition: bomb.len()={} must exceed MAX_SCAN_LENGTH={}",
        bomb.len(), PromptInjectionScanner::MAX_SCAN_LENGTH
    );

    // Sanity: the byte at position MAX_SCAN_LENGTH must be mid-codepoint
    let boundary = PromptInjectionScanner::MAX_SCAN_LENGTH;
    let b = bomb.as_bytes()[boundary];
    assert!(
        b & 0b11000000 == 0b10000000,
        "PRECONDITION FAILED: byte at boundary ({:#04x}) is not a UTF-8 continuation byte — \
         this specific payload doesn't trigger the bug, revise construction",
        b
    );

    // FIX: std::str slice at a non-char-boundary would panic; normalize()
    // now finds a safe boundary first. Confirm no panic occurs.
    let result = std::panic::catch_unwind(|| PromptInjectionScanner::normalize(&bomb));

    assert!(
        result.is_ok(),
        "FINDING-1 REGRESSED: normalize() panicked on a UTF-8 boundary slice again. \
         Bomb length = {}, MAX_SCAN_LENGTH = {}.",
        bomb.len(), PromptInjectionScanner::MAX_SCAN_LENGTH
    );

    eprintln!(
        "[FINDING-1 FIXED] normalize() safely handled a {}-byte string with a mid-codepoint \
         boundary at byte offset {} — no panic.",
        bomb.len(), boundary
    );
}

/// Additional DoS vector regression guard: send the boundary bomb through
/// scan_payload(). Must not panic anywhere along the gate pipeline path.
#[test]
fn finding_1_scan_payload_panics_on_boundary_bomb() {
    let bomb = make_utf8_boundary_bomb(PromptInjectionScanner::MAX_SCAN_LENGTH - 1);
    let jv = JsonValue::String(bomb.clone());

    let result = std::panic::catch_unwind(|| {
        let _ = PromptInjectionScanner::scan_payload(&jv, 0);
    });

    assert!(
        result.is_ok(),
        "FINDING-1 (scan_payload path) REGRESSED: scan_payload() panicked on the boundary bomb. \
         Bomb len={}.", bomb.len()
    );
    eprintln!("[FINDING-1 FIXED via scan_payload()] No panic on the scan_payload path.");
}

/// Confirm that strings of EXACTLY MAX_SCAN_LENGTH bytes (all ASCII) don't panic.
/// This is the control case: the bug only triggers when the boundary falls mid-codepoint.
#[test]
fn finding_1_exact_ascii_boundary_is_safe() {
    let exact = "A".repeat(PromptInjectionScanner::MAX_SCAN_LENGTH);
    // Must not panic
    let norm = PromptInjectionScanner::normalize(&exact);
    assert_eq!(norm.len(), PromptInjectionScanner::MAX_SCAN_LENGTH, "ASCII boundary should normalize without panic");
}

/// Test with a 3-byte UTF-8 codepoint (e.g., '€' = U+20AC = 0xE2 0x82 0xAC).
/// Any placement where boundary lands on byte 1 or byte 2 of the sequence
/// must be handled without a panic.
#[test]
fn finding_1_three_byte_codepoint_also_panics() {
    // '€' is 3 bytes. Place it so that MAX_SCAN_LENGTH lands on the 2nd byte.
    // lead = MAX_SCAN_LENGTH - 2: total = (MAX_SCAN_LENGTH-2) + 3 = MAX_SCAN_LENGTH + 1
    // Boundary byte index MAX_SCAN_LENGTH-2+1 = 0x82 — a continuation byte.
    let mut s = "A".repeat(PromptInjectionScanner::MAX_SCAN_LENGTH - 2);
    s.push('€');
    s.push('A'); // pad so total len > MAX_SCAN_LENGTH + 1

    if s.len() > PromptInjectionScanner::MAX_SCAN_LENGTH {
        let b = s.as_bytes()[PromptInjectionScanner::MAX_SCAN_LENGTH];
        if b & 0b11000000 == 0b10000000 {
            let result = std::panic::catch_unwind(|| {
                let _ = PromptInjectionScanner::normalize(&s);
            });
            assert!(
                result.is_ok(),
                "FINDING-1 (3-byte codepoint variant) REGRESSED. Byte at boundary = {:#04x}",
                b
            );
            eprintln!("[FINDING-1 FIXED] 3-byte variant handled without a panic (byte={:#04x}).", b);
            return;
        }
    }
    // If precondition not met, just note it
    eprintln!("[FINDING-1 3-byte variant] Boundary byte not a continuation byte — skipping assertion.");
}

// ─── FINDING-4: Unicode Deletion Bypass ──────────────────────────────────────
//
// The normalize() pipeline is:
//   1. NFKC normalize
//   2. Strip zero-width chars
//   3. replace_confusable() — covers only ~15 specific codepoints
//   4. Filter: keep only chars where (*c as u32) < 128 && !c.is_whitespace()
//      ← THIS DROPS any char that survived NFKC but is still non-ASCII
//   5. Strip /**/ → lowercase
//
// Attack: insert non-ASCII chars that (a) are NOT in the confusable table,
// (b) are NOT normalized away by NFKC, and (c) are visually similar to
// ASCII letters that form injection keywords. The filter SILENTLY DROPS them,
// fragmenting the keyword so the Aho-Corasick automaton misses it.

/// Greek ι (iota, U+03B9) is mapped to ASCII 'i' by `replace_confusable`
/// (src/handler.rs). Inserting it into "ignore" → "ιgnorepreviousinstructions"
/// must normalize back to "ignorepreviousinstructions" and be caught.
#[test]
fn finding_4_greek_iota_deletion_bypass() {
    let payload = "ιgnorepreviousinstructions";

    let normalized = PromptInjectionScanner::normalize(payload);
    println!("[FINDING-4] Greek-iota payload normalized to: {:?}", normalized);
    assert_eq!(
        normalized, "ignorepreviousinstructions",
        "FINDING-4 REGRESSED: Greek iota (U+03B9) is no longer mapped to 'i' by \
         replace_confusable — check src/handler.rs."
    );

    let jv = JsonValue::String(payload.to_string());
    let result = PromptInjectionScanner::scan_payload(&jv, 0);

    assert!(
        result.is_err(),
        "FINDING-4 REGRESSED: scanner returned Ok() for Greek-iota-prefixed injection {:?} \
         (normalized: {:?}) — the scanner failed to catch a known homoglyph bypass.",
        payload, normalized
    );
    eprintln!("[FINDING-4 FIXED] Scanner caught the Greek-iota payload: {:?}.", payload);
}

/// Cyrillic 'а' (U+0430, visually identical to ASCII 'a') is mapped to ASCII
/// 'a' by `replace_confusable`. "disregаrdprevious" (Cyrillic а) must
/// normalize to "disregardprevious" and be caught.
#[test]
fn finding_4_cyrillic_a_deletion_bypass() {
    let mut payload = String::from("disreg");
    payload.push('\u{0430}'); // Cyrillic а in "disregard"
    payload.push_str("rdprevious");

    let normalized = PromptInjectionScanner::normalize(&payload);
    println!("[FINDING-4 Cyrillic] payload={:?}, normalized={:?}", payload, normalized);
    assert_eq!(
        normalized, "disregardprevious",
        "FINDING-4 REGRESSED: Cyrillic а (U+0430) is no longer mapped to 'a' — \
         check src/handler.rs replace_confusable."
    );

    let jv = JsonValue::String(payload.clone());
    let result = PromptInjectionScanner::scan_payload(&jv, 0);

    assert!(
        result.is_err(),
        "FINDING-4 REGRESSED: scanner missed Cyrillic-'а' in 'disregardprevious'. \
         Normalized to: {:?}", normalized
    );
    eprintln!("[FINDING-4 FIXED] Scanner caught Cyrillic-'а' variant.");
}

/// Latin dotless ı (U+0131) is mapped to ASCII 'i' by `replace_confusable`.
/// "ıgnorepreviousinstructions" must normalize to
/// "ignorepreviousinstructions" and be caught.
#[test]
fn finding_4_dotless_i_deletion_bypass() {
    let mut payload = String::from("");
    payload.push('\u{0131}'); // Dotless ı
    payload.push_str("gnorepreviousinstructions");

    let normalized = PromptInjectionScanner::normalize(&payload);
    println!("[FINDING-4 dotless-i] payload={:?}, normalized={:?}", payload, normalized);
    assert_eq!(
        normalized, "ignorepreviousinstructions",
        "FINDING-4 REGRESSED: Latin dotless ı (U+0131) is no longer mapped to 'i' — \
         check src/handler.rs replace_confusable."
    );

    let jv = JsonValue::String(payload.clone());
    let result = PromptInjectionScanner::scan_payload(&jv, 0);

    assert!(result.is_err(), "FINDING-4 REGRESSED: scanner missed dotless-ı variant.");
    eprintln!("[FINDING-4 FIXED] Scanner caught dotless-ı variant.");
}

/// Stress test: spray a mapped confusable char (Greek iota, which correctly
/// maps to 'i') through ALL positions of a long injection keyword.
///
/// This is NOT the FINDING-4 silent-drop bug (iota is table-mapped, so it's
/// never dropped). It demonstrates a broader, inherent limitation: inserting
/// ANY single character — ASCII or not, table-mapped or not — into the
/// interior of a keyword changes the literal string and defeats exact
/// substring matching (e.g. "ignore" + inserted char != "ignore"). Only
/// positions that don't corrupt the literal keyword (here: before the existing
/// leading 'i', which just makes a redundant "ii") stay caught. Fixing this
/// class fully requires fuzzy/edit-distance matching, not a table fix — see
/// the doc comment on `PromptInjectionScanner::normalize()`. Documented here,
/// not asserted as a hard failure, matching `decode_layer_limit_4_deep_not_scanned`.
#[test]
fn finding_4_systematic_position_spray() {
    let keyword = "ignorepreviousinstructions";
    let spray_char = '\u{03B9}'; // Greek iota — mapped to 'i' by replace_confusable

    let mut bypass_positions: Vec<usize> = Vec::new();

    for pos in 0..keyword.len() {
        let mut payload = String::new();
        payload.push_str(&keyword[..pos]);
        payload.push(spray_char);
        payload.push_str(&keyword[pos..]);

        let jv = JsonValue::String(payload.clone());
        // Wrap in catch_unwind in case normalize() panics (FINDING-1 interaction)
        let result = std::panic::catch_unwind(|| {
            PromptInjectionScanner::scan_payload(&jv, 0)
        });

        match result {
            Ok(Ok(())) => {
                bypass_positions.push(pos);
            }
            Ok(Err(_)) => {} // blocked
            Err(_) => {
                panic!(
                    "FINDING-1 REGRESSED: scan_payload() panicked at spray position {}",
                    pos
                );
            }
        }
    }

    eprintln!(
        "[FINDING-4 position spray, documented limitation] Injection keyword '{}' bypassed at \
         byte positions: {:?} ({}/{}). Mid-keyword single-character insertion defeats literal \
         substring matching regardless of confusable-table coverage — not a regression target.",
        keyword, bypass_positions, bypass_positions.len(), keyword.len()
    );
}

// ─── Encoding Nesting Limit (MAX_DECODE_LAYERS = 3) ─────────────────────────

/// Confirm that 4-level-nested base64 injection is NOT caught (depth limit = 3).
/// This is NOT a bug — it's an intentional trade-off. Document the limit.
#[test]
fn decode_layer_limit_4_deep_not_scanned() {
    let inner = "ignorepreviousinstructions";
    // Base64-encode 4 times
    use base64::Engine;
    let l1 = base64::engine::general_purpose::STANDARD.encode(inner);
    let l2 = base64::engine::general_purpose::STANDARD.encode(&l1);
    let l3 = base64::engine::general_purpose::STANDARD.encode(&l2);
    let l4 = base64::engine::general_purpose::STANDARD.encode(&l3);

    let jv = JsonValue::String(l4.clone());
    let result = PromptInjectionScanner::scan_payload(&jv, 0);

    match result {
        Ok(()) => {
            eprintln!(
                "[DEPTH LIMIT] 4-level base64 injection passed scanner (expected: MAX_DECODE_LAYERS=3 \
                 means layer 4 is never decoded). This is the documented limit, not a new bug. \
                 The 4x-nested payload is: {:?}", l4
            );
        }
        Err(_) => {
            eprintln!("[DEPTH LIMIT] Unexpectedly blocked at 4 levels — scanner may check more layers now.");
        }
    }
}

/// Confirm that 3-level-nested base64 IS caught (must catch at the limit).
#[test]
fn decode_layer_limit_3_deep_is_caught() {
    let inner = "ignorepreviousinstructions";
    use base64::Engine;
    let l1 = base64::engine::general_purpose::STANDARD.encode(inner);
    let l2 = base64::engine::general_purpose::STANDARD.encode(&l1);
    let l3 = base64::engine::general_purpose::STANDARD.encode(&l2);

    let jv = JsonValue::String(l3);
    let result = PromptInjectionScanner::scan_payload(&jv, 0);

    assert!(
        result.is_err(),
        "3-level base64 injection should be caught by the scanner (MAX_DECODE_LAYERS = 3)"
    );
}
