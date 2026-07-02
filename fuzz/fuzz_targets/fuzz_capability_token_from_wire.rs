#![no_main]

use libfuzzer_sys::fuzz_target;
use saacp::acsvaf::SignedCapabilityToken;

// Attack surface: base64 decode → u32 length prefix → JSON parse → 64-byte sig slice.
// Any input must return Ok or Err, never panic.
fuzz_target!(|data: &[u8]| {
    let _ = SignedCapabilityToken::from_wire(data);
});
