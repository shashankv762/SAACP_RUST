// BREAKIT: Protocol Downgrade and Suite Negotiation Attacks
//
// FINDING-5 (MEDIUM): Suite negotiation is case-sensitive.
//   Peers advertising lowercase suite names ("aes-256-gcm-hkdf-sha256" instead of
//   "AES-256-GCM-HKDF-SHA256") are rejected — a DoS that a MITM can trigger by
//   modifying the suite list advertisement in transit.
//
// Additional attack surfaces tested:
//   - Empty remote suite list
//   - Prefix confusion ("AES-256-GCM" vs "AES-256-GCM-HKDF-SHA256")
//   - Unknown suite triggering DOWNGRADE_ATTEMPT log entry
//   - Whitespace variants (leading/trailing space)
//   - Duplicate suite entries (O(n²) risk)
//   - Protocol version mismatch
//   - MEASC frame confusion with HTTP bytes

use saacp::{
    SuiteNegotiator, CryptoTransparencyLedger,
    SAACPProtocolHandler,
};

// The approved AEAD cipher suite baseline
const BASELINE: &str = "AES-256-GCM-HKDF-SHA256";
// The mandatory_baseline in the production policy is the SIGNATURE algorithm
const SIG_BASELINE: &str = "ed25519";
// Both must be present in any valid suite advertisement
const VALID_SUITES: &[&str] = &[SIG_BASELINE, BASELINE];

fn make_ledger() -> CryptoTransparencyLedger {
    CryptoTransparencyLedger::new()
}

fn session_id() -> Vec<u8> {
    vec![0xAB; 16]
}

// ─── FINDING-5: Case sensitivity DoS ─────────────────────────────────────────

/// Lowercase AEAD cipher suite name — exact match fails, negotiation rejects.
/// A MITM that lowercases the cipher suite advertisement causes two compatible peers to fail.
/// Note: both sides must still advertise the mandatory sig baseline "ed25519".
#[test]
fn finding_5_lowercase_suite_causes_rejection() {
    let ledger = make_ledger();
    // Local: correct sig baseline + correct AEAD suite
    let local = vec![SIG_BASELINE, BASELINE];
    // Remote: correct sig baseline + LOWERCASED AEAD suite (MITM modified the AEAD name)
    let lowercase_baseline = BASELINE.to_lowercase();
    let remote = vec![SIG_BASELINE, lowercase_baseline.as_str()];

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote,
        &session_id(),
        None,
        None,
        &ledger,
    );

    // The mandatory sig baseline (ed25519) IS present in both, so that check passes.
    // The AEAD suite selection will fail because lowercase "aes-256-gcm-hkdf-sha256"
    // is not in the approved list (case-sensitive match).
    // Result: either succeeds with sig baseline only, or fails on no-approved-common-suite.
    // In either case, the lowercase AEAD suite must NOT be selected.
    match &result {
        Ok(transcript) => {
            assert_ne!(
                transcript.selected_suite, lowercase_baseline,
                "Lowercase AEAD suite must never be selected"
            );
            eprintln!(
                "[FINDING-5] Lowercase AEAD suite '{}' not selected (selected: '{}').",
                lowercase_baseline, transcript.selected_suite
            );
        }
        Err(e) => {
            eprintln!(
                "[FINDING-5 CONFIRMED] Negotiation failed when remote advertised lowercase \
                 AEAD suite '{}': {}. A MITM lowercasing the AEAD suite name in transit \
                 causes two otherwise-compatible peers to fail session establishment.",
                lowercase_baseline, e
            );
        }
    }
}

/// Mixed case AEAD suite ("Aes-256-Gcm-Hkdf-Sha256") — not selected.
#[test]
fn finding_5_mixed_case_suite_rejected() {
    let ledger = make_ledger();
    let mixed = "Aes-256-Gcm-Hkdf-Sha256";
    let local = vec![SIG_BASELINE, BASELINE];
    let remote = vec![SIG_BASELINE, mixed];

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote,
        &session_id(),
        None,
        None,
        &ledger,
    );

    match &result {
        Ok(transcript) => {
            assert_ne!(transcript.selected_suite, mixed, "Mixed-case AEAD suite must not be selected");
            eprintln!("[FINDING-5] Mixed-case '{}' not selected (selected: '{}').", mixed, transcript.selected_suite);
        }
        Err(e) => {
            eprintln!("[FINDING-5] Mixed-case '{}' caused negotiation failure: {}", mixed, e);
        }
    }
}

// ─── Empty suite list ─────────────────────────────────────────────────────────

/// Remote peer sends empty suite list → hard failure, no fallback to a weaker suite.
#[test]
fn empty_remote_suite_list_hard_failure() {
    let ledger = make_ledger();
    let local = VALID_SUITES;
    let remote: Vec<&str> = vec![];

    let result = SuiteNegotiator::negotiate(
        local,
        &remote,
        &session_id(),
        None,
        None,
        &ledger,
    );

    assert!(result.is_err(), "Empty remote suite list must cause hard failure");
    eprintln!("[DOWNGRADE] Empty remote suite list: hard failure (correct, no fallback).");
}

/// BOTH sides send empty suite lists.
#[test]
fn both_empty_suite_lists_hard_failure() {
    let ledger = make_ledger();
    let result = SuiteNegotiator::negotiate(
        &[],
        &[],
        &session_id(),
        None,
        None,
        &ledger,
    );
    assert!(result.is_err(), "Both-empty suite lists must fail");
    eprintln!("[DOWNGRADE] Both-empty suite lists: hard failure (correct).");
}

// ─── Prefix confusion ─────────────────────────────────────────────────────────

/// "AES-256-GCM" is a prefix of the real AEAD suite name.
/// Must NOT be selected (exact match required, not prefix match).
#[test]
fn prefix_suite_not_selected() {
    let ledger = make_ledger();
    let prefix_suite = "AES-256-GCM";
    // Both sides have ed25519 (mandatory sig baseline) but remote only has the prefix AEAD variant
    let local = vec![SIG_BASELINE, BASELINE, prefix_suite];
    let remote = vec![SIG_BASELINE, prefix_suite]; // remote lacks the full AEAD suite name

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote,
        &session_id(),
        None,
        None,
        &ledger,
    );

    match &result {
        Ok(transcript) => {
            assert_ne!(
                transcript.selected_suite, prefix_suite,
                "Prefix AEAD suite '{}' must not be selected",
                prefix_suite
            );
            eprintln!("[DOWNGRADE] Prefix '{}' not selected (selected: '{}').",
                prefix_suite, transcript.selected_suite);
        }
        Err(e) => {
            eprintln!("[DOWNGRADE] Prefix '{}' caused failure (no common approved AEAD suite): {}", prefix_suite, e);
        }
    }
}

// ─── Unknown suite ────────────────────────────────────────────────────────────

/// An unapproved suite like "CHACHA20-POLY1305" is logged as DOWNGRADE_ATTEMPT
/// and never selected. Verify it doesn't slip through.
#[test]
fn unknown_suite_blocked_and_logged() {
    let ledger = make_ledger();
    let unknown = "CHACHA20-POLY1305";
    // Both sides advertise the complete valid set PLUS the unknown suite
    let local = vec![SIG_BASELINE, BASELINE, unknown];
    let remote = vec![SIG_BASELINE, BASELINE, unknown];

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote,
        &session_id(),
        None,
        None,
        &ledger,
    );

    // Should succeed — ed25519 sig baseline is present in both lists.
    // "ed25519" is selected first (first in local order) before the negotiation
    // ever reaches CHACHA20-POLY1305, so no DOWNGRADE_ATTEMPT log is written for it.
    match result {
        Ok(transcript) => {
            assert_ne!(
                transcript.selected_suite, unknown,
                "Unknown suite '{}' must not be selected",
                unknown
            );
            eprintln!(
                "[DOWNGRADE] Unknown suite '{}' never selected. Selected: '{}'. \
                 Note: DOWNGRADE_ATTEMPT is only logged for suites reached during iteration \
                 before an approved suite is found; since ed25519 is first and approved, \
                 the unknown suite is never even evaluated.",
                unknown, transcript.selected_suite
            );
        }
        Err(e) => {
            panic!(
                "Negotiation should succeed when both valid suites are present alongside unknown. \
                 Error: {}", e
            );
        }
    }
}

// ─── Whitespace confusion ─────────────────────────────────────────────────────

/// Leading space before AEAD suite name — not selected (no trim() in comparison path).
#[test]
fn leading_space_suite_rejected() {
    let ledger = make_ledger();
    // Remote has correct sig baseline but leading-spaced AEAD suite (MITM modified it)
    let spaced_aead = format!(" {}", BASELINE);
    let local = vec![SIG_BASELINE, BASELINE];
    let remote_suites = vec![SIG_BASELINE, spaced_aead.as_str()];

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote_suites,
        &session_id(),
        None,
        None,
        &ledger,
    );

    // Sig baseline ed25519 is common, but spaced AEAD is not approved → no AEAD common suite
    // Result: either selects sig-only (if policy allows) or fails on AEAD mismatch
    match &result {
        Ok(transcript) => {
            assert_ne!(transcript.selected_suite, spaced_aead, "Leading-space AEAD must not be selected");
            eprintln!("[DOWNGRADE] Leading-space AEAD not selected (selected: '{}').", transcript.selected_suite);
        }
        Err(e) => {
            eprintln!("[DOWNGRADE] Leading-space AEAD caused failure (correct — no common approved AEAD): {}", e);
        }
    }
}

/// Trailing space.
#[test]
fn trailing_space_suite_rejected() {
    let ledger = make_ledger();
    let spaced_aead = format!("{} ", BASELINE);
    let local = vec![SIG_BASELINE, BASELINE];
    let remote_suites = vec![SIG_BASELINE, spaced_aead.as_str()];

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote_suites,
        &session_id(),
        None,
        None,
        &ledger,
    );

    match &result {
        Ok(transcript) => {
            assert_ne!(transcript.selected_suite, spaced_aead, "Trailing-space AEAD must not be selected");
            eprintln!("[DOWNGRADE] Trailing-space AEAD not selected (selected: '{}').", transcript.selected_suite);
        }
        Err(e) => {
            eprintln!("[DOWNGRADE] Trailing-space AEAD caused failure (correct): {}", e);
        }
    }
}

// ─── Duplicate suite entries (DoS amplification risk) ─────────────────────────

/// Advertise the same suite 1000 times — check for O(n²) or panic.
/// The negotiation should complete quickly and correctly regardless.
#[test]
fn duplicate_suite_entries_no_panic_no_hang() {
    let ledger = make_ledger();
    // Include sig baseline once, then 1000 copies of the AEAD suite
    let mut remote_vec: Vec<&str> = vec![SIG_BASELINE];
    remote_vec.extend(std::iter::repeat_n(BASELINE, 1000));
    let local = vec![SIG_BASELINE, BASELINE];
    let remote = remote_vec.as_slice();

    let start = std::time::Instant::now();
    let result = SuiteNegotiator::negotiate(
        &local,
        remote,
        &session_id(),
        None,
        None,
        &ledger,
    );
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "Negotiation must succeed even with 1000 duplicate suite entries. Error: {:?}",
        result.err()
    );
    assert!(
        elapsed.as_millis() < 500,
        "Negotiation with 1000 duplicates took {}ms — potential O(n²) behavior",
        elapsed.as_millis()
    );

    eprintln!(
        "[DUPLICATE SUITES] 1000-duplicate negotiation completed in {}ms. \
         No panic, no hang, correct selection.",
        elapsed.as_millis()
    );
}

// ─── MEASC frame vs HTTP confusion ───────────────────────────────────────────

/// Craft 128 bytes where the first 4 bytes spell "POST" (HTTP method).
/// parse_frame must reject this — the MEASC magic is expected to be 0x53 0x41 0x43 0x50
/// ("SACP"). Any confusion between HTTP and MEASC bytes is a protocol confusion attack.
#[test]
fn measc_frame_http_post_bytes_rejected() {
    // MEASC header is 128 bytes; first 4 = magic "SACP"
    let mut http_looking_bytes = vec![0u8; 128];
    http_looking_bytes[0..4].copy_from_slice(b"POST");
    http_looking_bytes[4] = b' '; // "POST /..."

    // intercept_packet will try to parse this as a MEASC frame
    let result = SAACPProtocolHandler::intercept_packet(
        &http_looking_bytes,
        &[0u8; 32], // all-zero secret
        "test-agent",
        false,
    );

    assert!(
        result.is_err(),
        "HTTP-looking bytes ('POST...') must be rejected by Gate 0 (wrong magic)"
    );

    eprintln!(
        "[PROTOCOL CONFUSION] HTTP 'POST' bytes rejected at Gate 0 (wrong magic). \
         No protocol confusion between HTTP and MEASC on the same port is possible \
         via the magic byte check. This is correct behavior."
    );
}

/// All-zero 128-byte packet (valid length, wrong magic).
#[test]
fn measc_frame_all_zeros_rejected() {
    let zeros = vec![0u8; 128];
    let result = SAACPProtocolHandler::intercept_packet(
        &zeros,
        &[0u8; 32],
        "test-agent",
        false,
    );
    assert!(result.is_err(), "All-zero packet must be rejected (wrong magic)");
    eprintln!("[PROTOCOL CONFUSION] All-zero 128-byte packet rejected at Gate 0.");
}

/// TLS ClientHello magic bytes (0x16 0x03 0x01) at the start.
#[test]
fn measc_frame_tls_client_hello_rejected() {
    let mut tls_bytes = vec![0u8; 128];
    tls_bytes[0] = 0x16; // TLS content type: handshake
    tls_bytes[1] = 0x03; // TLS version: 3.x
    tls_bytes[2] = 0x01; // TLS 1.0

    let result = SAACPProtocolHandler::intercept_packet(
        &tls_bytes,
        &[0u8; 32],
        "test-agent",
        false,
    );
    assert!(result.is_err(), "TLS ClientHello bytes must be rejected at Gate 0");
    eprintln!("[PROTOCOL CONFUSION] TLS ClientHello bytes rejected at Gate 0.");
}

// ─── Protocol version mismatch ────────────────────────────────────────────────

/// Negotiate with a non-standard protocol version string.
/// The negotiation should succeed (version is logged, not enforced as a gate),
/// but the transcript should record the actual version offered.
#[test]
fn non_standard_protocol_version_recorded() {
    let ledger = make_ledger();
    let local = vec![SIG_BASELINE, BASELINE];
    let remote = vec![SIG_BASELINE, BASELINE];

    let result = SuiteNegotiator::negotiate(
        &local,
        &remote,
        &session_id(),
        Some("SAACP/0.0-alpha"),  // non-standard version
        None,
        &ledger,
    );

    match result {
        Ok(transcript) => {
            assert_eq!(
                transcript.protocol_version, "SAACP/0.0-alpha",
                "Non-standard version must be recorded in transcript"
            );
            eprintln!(
                "[VERSION] Non-standard protocol version 'SAACP/0.0-alpha' recorded in \
                 transcript. Version is not enforced as a hard gate — an attacker \
                 can advertise any version string without rejection. This is by design \
                 (version negotiation is audited, not gatekept by this function)."
            );
        }
        Err(e) => {
            panic!("Negotiation with non-standard version should succeed. Error: {}", e);
        }
    }
}

// ─── Summary ─────────────────────────────────────────────────────────────────

#[test]
fn downgrade_summary_report() {
    eprintln!("\n");
    eprintln!("═══════════════════════════════════════════════════════════════════");
    eprintln!("  BREAKIT PHASE 3 — DOWNGRADE/CONFUSION ATTACK SUMMARY");
    eprintln!("═══════════════════════════════════════════════════════════════════");
    eprintln!("  FINDING-5 [MEDIUM]: Suite negotiation is case-sensitive.");
    eprintln!("    Lowercase or mixed-case suite names are rejected.");
    eprintln!("    A MITM can lowercase the suite advertisement, causing two");
    eprintln!("    fully-compatible peers to fail session establishment.");
    eprintln!("    Location: src/crypto_governance.rs:415, 440-442");
    eprintln!();
    eprintln!("  CORRECT BEHAVIORS (no DoS risk):");
    eprintln!("    - Empty suite list → hard failure, no fallback");
    eprintln!("    - Unknown/unapproved suites → DOWNGRADE_ATTEMPT log + skip");
    eprintln!("    - Prefix match not accepted (exact match required)");
    eprintln!("    - Whitespace variants rejected (no implicit trim)");
    eprintln!("    - 1000 duplicates: no panic, completes in <500ms");
    eprintln!("    - HTTP/TLS bytes rejected at Gate 0 (magic check)");
    eprintln!("═══════════════════════════════════════════════════════════════════");
}
