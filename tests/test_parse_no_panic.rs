/// No-panic property tests for the three highest-stakes parse surfaces.
///
/// These complement the libfuzzer targets in fuzz/ (which require Linux/nightly).
/// They run on every platform with `cargo test` and exercise the parsers with:
///   - known structural edge cases (empty, one byte, exact-minimum-size)
///   - high-entropy random inputs generated with a fixed PRNG seed
///
/// The only invariant: every call returns Ok(..) or Err(..), never panics.
use saacp::acsvaf::SignedCapabilityToken;
use saacp::framing::SAACPFrame;
use saacp::{
    MEASCFrame, NonceTracker, RGCPolicy, SessionEpochManager,
    MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD, MEASC_DEFAULT_EPOCH_TIME_SECONDS,
};

/// Minimal PRNG (xorshift64) — no external crate, deterministic, reproducible.
struct Xorshift64(u64);
impl Xorshift64 {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i < buf.len() {
            let v = self.next().to_le_bytes();
            let n = (buf.len() - i).min(8);
            buf[i..i + n].copy_from_slice(&v[..n]);
            i += n;
        }
    }
}

fn random_buffers(seed: u64, sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut rng = Xorshift64(seed);
    sizes
        .iter()
        .map(|&sz| {
            let mut buf = vec![0u8; sz];
            rng.fill(&mut buf);
            buf
        })
        .collect()
}

// ── SignedCapabilityToken::from_wire ─────────────────────────────────────────

#[test]
fn from_wire_never_panics_edge_cases() {
    let cases: &[&[u8]] = &[
        b"",
        b"\x00",
        b"====",
        b"AAAA",
        &[0xffu8; 1],
        &[0xffu8; 68], // 4 + 64 exactly
        &[0u8; 256],
        &[0u8; 1024],
    ];
    for input in cases {
        let _ = SignedCapabilityToken::from_wire(input);
    }
}

#[test]
fn from_wire_never_panics_random() {
    let sizes: Vec<usize> = (0..500).map(|i| i % 512).collect();
    for buf in random_buffers(0xDEAD_BEEF_0001, &sizes) {
        let _ = SignedCapabilityToken::from_wire(&buf);
    }
}

// ── SAACPFrame::parse_header ─────────────────────────────────────────────────

fn make_parse_header_deps() -> (NonceTracker, RGCPolicy) {
    (NonceTracker::new(), RGCPolicy::default())
}

#[test]
fn saacpframe_parse_header_never_panics_edge_cases() {
    let secret = [0u8; 32];
    let (nt, pol) = make_parse_header_deps();

    let cases: &[&[u8]] = &[
        b"",
        &[0u8; 1],
        &[0u8; 120],  // one byte under min (121)
        &[0u8; 121],  // exact minimum
        &[0xffu8; 200],
        &[0u8; 65536],
    ];
    for input in cases {
        let _ = SAACPFrame::parse_header(input, &secret, &nt, &pol);
    }
}

#[test]
fn saacpframe_parse_header_never_panics_random() {
    let secret = [0u8; 32];
    let (nt, pol) = make_parse_header_deps();

    let sizes: Vec<usize> = (0..500).map(|i| i % 1024).collect();
    for buf in random_buffers(0xDEAD_BEEF_0002, &sizes) {
        let _ = SAACPFrame::parse_header(&buf, &secret, &nt, &pol);
    }
}

// ── MEASCFrame::parse_frame ──────────────────────────────────────────────────

fn make_epoch_manager_with_session(session_id: [u8; 16]) -> SessionEpochManager {
    let mgr = SessionEpochManager::new();
    let _ = mgr.create_session(
        session_id,
        [0u8; 32],
        MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
        MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
        None,
    );
    mgr
}

#[test]
fn measc_parse_frame_never_panics_edge_cases() {
    let session_id = [0u8; 16];
    let mgr = make_epoch_manager_with_session(session_id);

    let cases: &[&[u8]] = &[
        b"",
        &[0u8; 1],
        &[0u8; 127],   // one byte under MEASC_HEADER_SIZE (128)
        &[0u8; 128],   // exact header, no payload
        &[0xffu8; 256],
        &[0u8; 65536],
    ];
    for input in cases {
        let _ = MEASCFrame::parse_frame(input, &mgr, false);
    }
}

#[test]
fn measc_parse_frame_never_panics_random() {
    let mut rng = Xorshift64(0xDEAD_BEEF_0003);
    let sizes: Vec<usize> = (0..500).map(|i| i % 1024).collect();

    for sz in &sizes {
        let mut buf = vec![0u8; *sz];
        rng.fill(&mut buf);

        // Extract session_id from bytes 16..32 (MEASC header layout) and pre-seed
        // so the fuzzer can reach past epoch validation.
        let session_id: [u8; 16] = if buf.len() >= 32 {
            buf[16..32].try_into().unwrap()
        } else {
            [0u8; 16]
        };
        let mgr = make_epoch_manager_with_session(session_id);
        let _ = MEASCFrame::parse_frame(&buf, &mgr, false);
    }
}
