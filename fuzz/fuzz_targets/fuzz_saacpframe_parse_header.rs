#![no_main]

use libfuzzer_sys::fuzz_target;
use saacp::framing::SAACPFrame;
use saacp::{NonceTracker, RGCPolicy};

// Attack surface: 7-step pipeline — magic check, length limits, nonce dedup,
// Adler-32, AES-256-GCM decrypt+auth, schema check.
// Fixed key and fresh NonceTracker each invocation so the fuzzer owns
// the entire buffer. Any input must return Ok or Err, never panic.
fuzz_target!(|data: &[u8]| {
    let secret_key = [0u8; 32];
    let nonce_tracker = NonceTracker::new();
    let rgc_policy = RGCPolicy::default();
    let _ = SAACPFrame::parse_header(data, &secret_key, &nonce_tracker, &rgc_policy);
});
