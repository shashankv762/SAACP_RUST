#![no_main]

use libfuzzer_sys::fuzz_target;
use saacp::{
    MEASCFrame, SessionEpochManager,
    MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS,
};

// Attack surface: 9-step parse pipeline — magic, length, MTU, epoch lookup,
// replay window, AES-256-GCM auth+decrypt, EASI decrypt, schema ID gate.
//
// Strategy: extract bytes [16..32] from the fuzz input as session_id (matching
// the MEASC header layout) and pre-seed the epoch manager with that session.
// This lets the fuzzer reach step 5 (replay window) and beyond rather than
// short-circuiting at step 4 (epoch not found) for every corpus entry.
// The AES-GCM tag will still reject almost every input — that is expected and
// is itself the correctness property being verified (no panic on bad tag).
fuzz_target!(|data: &[u8]| {
    // Need at least 32 bytes to extract a session_id from the header.
    if data.len() < 32 {
        return;
    }

    let mut session_id = [0u8; 16];
    session_id.copy_from_slice(&data[16..32]);

    let epoch_manager = SessionEpochManager::new();
    let secret = [0u8; 32];
    // Ignore create_session errors (e.g., duplicate session_id across corpus entries
    // when the fuzzer happens to generate the same bytes 16..32).
    let _ = epoch_manager.create_session(
        session_id,
        secret,
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    );

    let _ = MEASCFrame::parse_frame(data, &epoch_manager, false);
});
