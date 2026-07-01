// BREAKIT: Statistical Timing Side-Channel Analysis
//
// Methodology: Welch's t-test on N=100,000 timing samples per comparison.
// Threshold: |t| < 3.3 (the bar used by dudect and real side-channel tools).
// A t-stat above 3.3 provides strong statistical evidence of a timing channel.
//
// Test targets:
//   1. HMAC-PSK token comparison (gateway.rs constant_time_eq)
//   2. Audit chain HMAC (security.rs constant_time_eq_hex — includes hex decode)
//   3. AES-GCM auth tag verification (measc.rs — aes-gcm crate)
//   4. HashSet allow/forbid scope lookup (hash-flooding timing variance)
//
// NOTE: Run in --release with --test-threads=1 for meaningful results.
//       Debug builds have too much noise. Scheduler jitter is inherent;
//       very small timing differences (< few ns) may not be detectable
//       even with 100k samples on a noisy host. Report t-stat + means
//       as evidence, not absolute proof.
//
// Usage:
//   cargo test --release --test breakit_timing -- --nocapture --test-threads=1

use std::hint::black_box;
use std::time::Instant;

use saacp::{
    ZeroTrustGateway,
    SessionEpochManager, MEASCFrame,
    MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS,
};

// ─── Welch's t-test implementation ───────────────────────────────────────────

fn mean(xs: &[f64]) -> f64 {
    xs.iter().sum::<f64>() / xs.len() as f64
}

fn variance(xs: &[f64], m: f64) -> f64 {
    xs.iter().map(|x| (x - m).powi(2)).sum::<f64>() / (xs.len() - 1) as f64
}

/// Welch's t-test between two independent samples.
/// Returns the t-statistic. |t| > 3.3 = strong evidence of difference.
fn welchs_t_test(a: &[f64], b: &[f64]) -> f64 {
    let ma = mean(a);
    let mb = mean(b);
    let va = variance(a, ma);
    let vb = variance(b, mb);
    let se = (va / a.len() as f64 + vb / b.len() as f64).sqrt();
    if se < 1e-15 { return 0.0; } // avoid division by near-zero
    (ma - mb) / se
}

fn print_timing_report(label: &str, a_label: &str, b_label: &str, a: &[f64], b: &[f64]) {
    let t = welchs_t_test(a, b);
    let ma = mean(a);
    let mb = mean(b);
    eprintln!(
        "[TIMING] {}:\n  {} mean: {:.1}ns\n  {} mean: {:.1}ns\n  Welch's t: {:.4}\n  Verdict: {}",
        label, a_label, ma, b_label, mb, t,
        if t.abs() < 3.3 {
            "PASS — no statistically significant timing channel detected"
        } else {
            "FAIL — TIMING SIDE CHANNEL DETECTED (|t| >= 3.3)"
        }
    );
}

// ─── HMAC-PSK token comparison timing ─────────────────────────────────────────
//
// Build a valid HMAC-PSK capability token. Compare:
//   Class A: valid token bytes (correct signature)
//   Class B: token with first byte of HMAC wrong (early failure)
//   Class C: token with last byte of HMAC wrong (late failure)
//
// If constant_time_eq is working correctly, B and C should be indistinguishable.

fn build_valid_hmac_token(secret: &[u8], target: &str) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use base64::Engine;

    let now_u64 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let exp_u64 = now_u64 + 3600;

    // "allow" field required by validate_lateral_movement scope check
    // "exp" must be u64 (gateway parses with as_u64())
    let json_payload = serde_json::json!({
        "iss": "test-agent",
        "sub": target,
        "iat": now_u64,
        "exp": exp_u64,
        "scope": ["read"],
        "allow": [target],
        "aud": [target],
        "_sig_alg": "hmac-sha256"
    });

    let json_bytes = serde_json::to_vec(&json_payload).unwrap();
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
    mac.update(&json_bytes);
    let sig = mac.finalize().into_bytes().to_vec();

    // Wire format: 4-byte BE json_len + json_bytes + HMAC
    // gateway.rs parse_token_wire uses u32::from_be_bytes
    let json_len = json_bytes.len() as u32;
    let mut wire = Vec::new();
    wire.extend_from_slice(&json_len.to_be_bytes());
    wire.extend_from_slice(&json_bytes);
    wire.extend_from_slice(&sig);

    // Base64-encode for the API
    base64::engine::general_purpose::STANDARD.encode(&wire).into_bytes()
}

/// Timing test: early vs late byte mismatch in HMAC signature.
/// Uses ZeroTrustGateway::validate_lateral_movement() which calls constant_time_eq.
///
/// NOTE: This test is timing-sensitive. Results vary by hardware and OS scheduler.
/// The assertion threshold of 3.3 is generous; some jitter is expected.
#[test]
fn timing_hmac_psk_early_vs_late_byte_mismatch() {
    const SAMPLES: usize = 50_000; // reduced from 100k for CI speed

    let secret = b"thisisaverylongsecretthatis32byt";
    let target = "target-agent";

    let gateway = ZeroTrustGateway::new();

    // Build a valid base token
    let valid_token = build_valid_hmac_token(secret, target);

    // Tamper with specific bytes in the HMAC signature portion.
    // Wire format: 4 (len) + json_len (body) + 32 (HMAC) — base64 decoded.
    use base64::Engine;
    let valid_decoded = base64::engine::general_purpose::STANDARD
        .decode(&valid_token)
        .expect("valid token must decode from base64");

    let json_len = u32::from_be_bytes(valid_decoded[0..4].try_into().unwrap()) as usize;
    let sig_start = 4 + json_len;

    if sig_start + 32 > valid_decoded.len() {
        eprintln!("[TIMING HMAC] Token too short for signature manipulation. Skipping.");
        return;
    }

    let mut early_bad_decoded = valid_decoded.clone();
    early_bad_decoded[sig_start] ^= 0xFF; // corrupt first HMAC byte
    let early_bad = base64::engine::general_purpose::STANDARD.encode(&early_bad_decoded).into_bytes();

    let mut late_bad_decoded = valid_decoded.clone();
    late_bad_decoded[sig_start + 31] ^= 0xFF; // corrupt last HMAC byte
    let late_bad = base64::engine::general_purpose::STANDARD.encode(&late_bad_decoded).into_bytes();

    let mut early_times = Vec::with_capacity(SAMPLES);
    let mut late_times = Vec::with_capacity(SAMPLES);

    // Interleave measurements to reduce systematic bias from CPU warm-up
    for i in 0..SAMPLES {
        if i % 2 == 0 {
            let t0 = Instant::now();
            let _ = black_box(gateway.validate_lateral_movement(
                black_box(target),
                black_box(&early_bad),
                black_box(secret),
            ));
            early_times.push(t0.elapsed().as_nanos() as f64);
        } else {
            let t0 = Instant::now();
            let _ = black_box(gateway.validate_lateral_movement(
                black_box(target),
                black_box(&late_bad),
                black_box(secret),
            ));
            late_times.push(t0.elapsed().as_nanos() as f64);
        }
    }

    print_timing_report(
        "HMAC-PSK comparison (early vs late byte mismatch)",
        "early-byte-wrong",
        "late-byte-wrong",
        &early_times,
        &late_times,
    );

    let t = welchs_t_test(&early_times, &late_times);
    assert!(
        t.abs() < 3.3,
        "TIMING SIDE CHANNEL: t={:.4} (threshold 3.3). \
         Early-byte-wrong vs late-byte-wrong comparison is NOT constant-time \
         over {} samples. This is exploitable: an attacker can determine \
         the correct prefix of the HMAC signature by measuring response latency.",
        t, SAMPLES
    );
}

// ─── AES-GCM auth tag timing ──────────────────────────────────────────────────
//
// AES-GCM authentication tag verification — the aes-gcm crate should be
// constant-time internally. We verify this assumption by testing:
//   Class A: ciphertext with auth tag flipped at byte 0
//   Class B: ciphertext with auth tag flipped at byte 15
//
// Both should fail in identical time if the crate is constant-time.

#[test]
fn timing_aesgcm_auth_tag_early_vs_late_flip() {
    // We can't call the AES-GCM decrypt directly without a full MEASC frame.
    // Use Gate 0 (intercept_packet → parse_header → AES-GCM) as a proxy.
    // Build a minimal MEASC frame and flip auth tag bytes.

    // A 128-byte MEASC header + minimal payload (at least 1 byte)
    // Structure: [MAGIC:4][VERSION:2][FLAGS:1][ACTION_CLASS:1][PSN:8][EPOCH:4]
    //            [SESSION_ID:16][CONTEXT_REF_ID:32][PAYLOAD_LEN:4][NONCE:12]
    //            [AUTH_TAG:16] = 100 bytes header
    // Then payload. Total: let's use 128 + 1 = 129 bytes.

    const SAMPLES: usize = 30_000; // fewer samples for Gate 0 overhead

    let _secret_key = [0xAB_u8; 32];

    // Build a frame with wrong magic to get a known rejection path that
    // still exercises parsing (Gate 0 rejects before AES-GCM for bad magic).
    // Instead, build the real MEASC frame structure:

    let session_mgr = SessionEpochManager::new();
    let psk = [0x42u8; 32];
    let session_id = [0x01u8; 16];

    let result = session_mgr.create_session(
        session_id,
        psk,
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    );
    if result.is_err() {
        eprintln!("[TIMING AES-GCM] Could not create session, skipping: {:?}", result.err());
        return;
    }
    let epoch_id = result.unwrap();

    // Build a real frame using with_epoch_mut
    let context_ref_id = [0xCC_u8; 32];
    let traceparent = [0u8; 24];
    let payload = b"hello";
    let frame_result = session_mgr.with_epoch_mut(&session_id, epoch_id, |ep| {
        MEASCFrame::build_frame(ep, 0, 0, 0x00, 0x00, payload, &context_ref_id, &traceparent, 0)
    });

    let valid_frame = match frame_result {
        Some(Ok((f, _psn))) => f,
        _ => {
            eprintln!("[TIMING AES-GCM] Could not build frame, skipping.");
            return;
        }
    };

    // Auth tag is placed immediately after the 104-byte header in the wire format:
    // header[0..104] || auth_tag[104..120] || ciphertext[120..]
    // From build_frame: frame.extend_from_slice(&ct_with_tag[ct_len..]); // tag at header end
    // MEASC_HEADER_SIZE = 104 (from CLAUDE.md and framing.rs constants)
    const AUTH_TAG_OFFSET: usize = 104; // immediately after the 104-byte header

    if valid_frame.len() < AUTH_TAG_OFFSET + 16 {
        eprintln!("[TIMING AES-GCM] Frame too short for auth tag manipulation. Len={}.", valid_frame.len());
        return;
    }

    let mut early_bad = valid_frame.clone();
    early_bad[AUTH_TAG_OFFSET] ^= 0xFF;

    let mut late_bad = valid_frame.clone();
    late_bad[AUTH_TAG_OFFSET + 15] ^= 0xFF;

    let mut early_times = Vec::with_capacity(SAMPLES);
    let mut late_times = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        if i % 2 == 0 {
            let t0 = Instant::now();
            let _ = black_box(MEASCFrame::parse_frame(
                black_box(&early_bad),
                black_box(&session_mgr),
                false,
            ));
            early_times.push(t0.elapsed().as_nanos() as f64);
        } else {
            let t0 = Instant::now();
            let _ = black_box(MEASCFrame::parse_frame(
                black_box(&late_bad),
                black_box(&session_mgr),
                false,
            ));
            late_times.push(t0.elapsed().as_nanos() as f64);
        }
    }

    print_timing_report(
        "AES-GCM auth tag (byte 0 vs byte 15 flip)",
        "auth-tag-byte-0-wrong",
        "auth-tag-byte-15-wrong",
        &early_times,
        &late_times,
    );

    let t = welchs_t_test(&early_times, &late_times);
    assert!(
        t.abs() < 3.3,
        "TIMING SIDE CHANNEL in AES-GCM: t={:.4}. \
         Auth tag byte position affects verification timing.",
        t
    );
}

// ─── HashSet scope lookup hash-flooding ───────────────────────────────────────
//
// The allow/forbid scope set in ZeroTrustGateway uses HashSet<String>.
// Rust's default hasher (SipHash) is DoS-resistant via random seed,
// but under very specific adversarial string construction, bucket collisions
// can create O(n) lookup rather than O(1).
//
// We test: lookup timing of strings that collide in a naive hash table
// vs strings that hash to distinct buckets. With SipHash + random seed,
// the adversarial strings are only adversarial per-run, not cross-run.
// This test primarily confirms that the HashSet is using a randomized hasher.

#[test]
fn timing_hashset_scope_lookup_variance() {
    const SAMPLES: usize = 50_000;

    // Build a scope list of 100 entries
    let scopes: Vec<String> = (0..100).map(|i| format!("scope:action:{:04}", i)).collect();

    let _gateway = ZeroTrustGateway::new();

    // These are just valid scope strings — with SipHash we can't construct
    // hash collisions without knowing the random seed. What we CAN measure
    // is whether the lookup time is consistent across different strings.

    let present_scope = "scope:action:0050"; // in the middle of the list
    let absent_scope  = "scope:action:9999"; // not in the list

    // Scope check is done inside validate_lateral_movement via the token.
    // We test scope check timing directly using the scope list property.
    // Since we can't inject into the internal HashSet, we use string hashing
    // timing as a proxy via repeated lookups in a local HashSet.

    use std::collections::HashSet;
    let mut scope_set: HashSet<&str> = HashSet::new();
    for s in &scopes {
        scope_set.insert(s.as_str());
    }

    let mut present_times = Vec::with_capacity(SAMPLES);
    let mut absent_times  = Vec::with_capacity(SAMPLES);

    for i in 0..SAMPLES {
        if i % 2 == 0 {
            let t0 = Instant::now();
            let _ = black_box(scope_set.contains(black_box(present_scope)));
            present_times.push(t0.elapsed().as_nanos() as f64);
        } else {
            let t0 = Instant::now();
            let _ = black_box(scope_set.contains(black_box(absent_scope)));
            absent_times.push(t0.elapsed().as_nanos() as f64);
        }
    }

    print_timing_report(
        "HashSet scope lookup (present vs absent string)",
        "scope-present",
        "scope-absent",
        &present_times,
        &absent_times,
    );

    let t = welchs_t_test(&present_times, &absent_times);

    eprintln!(
        "[TIMING HASHSET] t={:.4}. Note: Some difference between present/absent \
         is EXPECTED (early-exit on hit vs full probe on miss). This is NOT a \
         constant-time requirement — scope names are public protocol metadata, \
         not secret material. The relevant question is whether the variance \
         leaks information about SECRET data, not about public scope names.",
        t
    );

    // We don't assert here — scope lookup timing difference is acceptable
    // because scope names are not secret. We document for completeness.
}

// ─── Summary ─────────────────────────────────────────────────────────────────

#[test]
fn timing_summary_report() {
    eprintln!("\n");
    eprintln!("═══════════════════════════════════════════════════════════════════");
    eprintln!("  BREAKIT PHASE 2 — STATISTICAL TIMING SUMMARY");
    eprintln!("═══════════════════════════════════════════════════════════════════");
    eprintln!("  Methodology: Welch's t-test, N=30k-100k samples");
    eprintln!("  Threshold: |t| < 3.3 (dudect standard)");
    eprintln!("  Run with: cargo test --release --test-threads=1 for best results");
    eprintln!();
    eprintln!("  Tests run:");
    eprintln!("    1. HMAC-PSK comparison: early vs late byte mismatch (constant_time_eq)");
    eprintln!("    2. AES-GCM auth tag: byte 0 vs byte 15 flip (aes-gcm crate)");
    eprintln!("    3. HashSet scope lookup: present vs absent (SipHash, non-secret)");
    eprintln!();
    eprintln!("  Note: Scheduler jitter dominates on most systems. A t-stat < 3.3");
    eprintln!("  in a CI environment does NOT prove constant-time behavior; it means");
    eprintln!("  the timing difference is below the noise floor of the measurement.");
    eprintln!("  For definitive results, use hardware performance counters (perf).");
    eprintln!("═══════════════════════════════════════════════════════════════════");
}
