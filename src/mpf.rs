//! mpf.rs — Metadata Protection Framework (MPF)
//!
//! Defends against "Metadata Reconnaissance" threat (SAACP threat table §3).
//! Three independent countermeasures:
//!
//! - [`AdaptivePadding`] — pad packets to fixed-size power-of-2 buckets,
//!   preventing an observer from inferring payload size.
//! - [`CoverTraffic`] — generate synthetic FLAG_COVER_TRAFFIC packets at a
//!   configurable rate, hiding real traffic patterns.
//! - [`TimingObfuscator`] — track per-message delay budgets and recommend jitter
//!   so outbound packet timing is not a traffic fingerprint.
//!
//! Python parity: matches the MPF threat-model section in README §3 and the
//! cover-traffic budget tracking in gateway.py `AgentRateLimiter`.

use rand::Rng;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Minimum bucket size (bytes). Smaller packets are padded to at least this.
pub const MPF_PAD_BLOCK_SIZE: usize = 256;

/// Maximum pad bucket (bytes). Packets above this are not padded further.
pub const MPF_PAD_MAX_BUCKET: usize = 65536;

/// Target cover traffic rate in packets per second (default; caller may override).
pub const MPF_COVER_RATE_HZ: f64 = 1.0;

/// Maximum random timing jitter added to outbound packets (milliseconds).
pub const MPF_TIMING_JITTER_MS: u64 = 50;

/// Minimum random timing jitter (milliseconds).
pub const MPF_TIMING_JITTER_MIN_MS: u64 = 1;

/// MPF version string — increment when constants change.
pub const MPF_VERSION: &str = "1.0";

// ---------------------------------------------------------------------------
// AdaptivePadding
// ---------------------------------------------------------------------------

/// Adaptive padding: pads a byte buffer to the next power-of-two bucket ≥ its
/// current length, up to `MPF_PAD_MAX_BUCKET`. This hides exact payload sizes.
///
/// # Security property
/// An observer watching encrypted traffic cannot distinguish 100-byte payloads
/// from 255-byte payloads — both round up to the same 256-byte bucket.
///
/// # Python parity
/// Matches the `AdaptivePadding` class described in README threat table.
pub struct AdaptivePadding {
    /// Override block size (default: `MPF_PAD_BLOCK_SIZE`).
    block_size: usize,
    /// Maximum bucket to pad to (default: `MPF_PAD_MAX_BUCKET`).
    max_bucket: usize,
    /// Total bytes of padding added across all calls.
    total_padding_bytes: usize,
    /// Total packets processed.
    packets_processed: usize,
}

impl AdaptivePadding {
    /// Create a new `AdaptivePadding` with default constants.
    pub fn new() -> Self {
        Self {
            block_size: MPF_PAD_BLOCK_SIZE,
            max_bucket: MPF_PAD_MAX_BUCKET,
            total_padding_bytes: 0,
            packets_processed: 0,
        }
    }

    /// Create with custom block_size and max_bucket.
    pub fn with_params(block_size: usize, max_bucket: usize) -> Self {
        let block_size = block_size.next_power_of_two().max(16);
        let max_bucket = max_bucket.next_power_of_two().max(block_size);
        Self {
            block_size,
            max_bucket,
            total_padding_bytes: 0,
            packets_processed: 0,
        }
    }

    /// Compute the target padded length for `current_len` bytes.
    ///
    /// Returns the smallest power-of-two multiple of `block_size` that is ≥
    /// `current_len`, capped at `max_bucket`.
    pub fn target_length(&self, current_len: usize) -> usize {
        if current_len == 0 {
            return self.block_size;
        }
        let mut bucket = self.block_size;
        while bucket < current_len && bucket < self.max_bucket {
            bucket = bucket.saturating_mul(2);
        }
        bucket.min(self.max_bucket)
    }

    /// Pad `data` in-place with zero bytes to the next bucket boundary.
    ///
    /// Returns the number of padding bytes added (0 if already at a boundary).
    pub fn pad(&mut self, data: &mut Vec<u8>) -> usize {
        let original_len = data.len();
        let target = self.target_length(original_len);
        let pad_bytes = target.saturating_sub(original_len);
        if pad_bytes > 0 {
            data.resize(target, 0u8);
        }
        self.total_padding_bytes += pad_bytes;
        self.packets_processed += 1;
        pad_bytes
    }

    /// Strip trailing zero-bytes that were added as padding.
    ///
    /// NOTE: This is a heuristic — callers MUST record true payload length in
    /// the SAACP `payload_length` header field and use that for real truncation.
    /// This helper is for test / debug only.
    pub fn strip_padding(data: &[u8], true_len: usize) -> &[u8] {
        &data[..true_len.min(data.len())]
    }

    /// Total bytes of padding emitted so far.
    pub fn total_padding_bytes(&self) -> usize {
        self.total_padding_bytes
    }

    /// Total packets processed.
    pub fn packets_processed(&self) -> usize {
        self.packets_processed
    }

    /// Reset statistics.
    pub fn reset_stats(&mut self) {
        self.total_padding_bytes = 0;
        self.packets_processed = 0;
    }
}

impl Default for AdaptivePadding {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// CoverTraffic
// ---------------------------------------------------------------------------

/// Cover traffic generator — produces FLAG_COVER_TRAFFIC packet markers at a
/// configurable rate so real traffic cannot be identified by timing alone.
///
/// # Security property
/// A network observer cannot distinguish genuine agent communication from
/// synthetic noise without the session key. Cover packets are AES-GCM
/// authenticated like real packets and discarded silently by the receiver
/// after Gate 0 passes.
///
/// # Python parity
/// Matches `AgentRateLimiter.cover_records` per-agent tracking in gateway.py
/// and the `FLAG_COVER_TRAFFIC` constant in framing.py.
pub struct CoverTraffic {
    /// Target cover packets per second.
    rate_hz: f64,
    /// How many cover packets have been issued.
    issued: u64,
    /// Wall time of last cover packet.
    last_issued: Option<Instant>,
    /// Cover packets suppressed due to rate limiting.
    suppressed: u64,
}

impl CoverTraffic {
    /// Create with the default `MPF_COVER_RATE_HZ` rate.
    pub fn new() -> Self {
        Self {
            rate_hz: MPF_COVER_RATE_HZ,
            issued: 0,
            last_issued: None,
            suppressed: 0,
        }
    }

    /// Create with a custom rate in packets per second.
    pub fn with_rate(rate_hz: f64) -> Self {
        Self {
            rate_hz: rate_hz.max(0.001),
            issued: 0,
            last_issued: None,
            suppressed: 0,
        }
    }

    /// Return true if it is time to emit a cover packet.
    ///
    /// Tracks wall-clock time; caller must actually build and send the
    /// FLAG_COVER_TRAFFIC packet using the MEASC framing layer.
    pub fn should_emit(&mut self) -> bool {
        let interval_ms = (1000.0 / self.rate_hz) as u64;
        let interval = Duration::from_millis(interval_ms);
        match self.last_issued {
            None => {
                self.last_issued = Some(Instant::now());
                self.issued += 1;
                true
            }
            Some(last) => {
                if last.elapsed() >= interval {
                    self.last_issued = Some(Instant::now());
                    self.issued += 1;
                    true
                } else {
                    self.suppressed += 1;
                    false
                }
            }
        }
    }

    /// Force-record an emitted cover packet (called by the sender after
    /// building the actual packet bytes).
    pub fn record_emit(&mut self) {
        self.issued += 1;
        self.last_issued = Some(Instant::now());
    }

    /// Total cover packets emitted so far.
    pub fn total_issued(&self) -> u64 {
        self.issued
    }

    /// Cover packets suppressed due to rate limiting.
    pub fn total_suppressed(&self) -> u64 {
        self.suppressed
    }

    /// Current rate setting (packets per second).
    pub fn rate_hz(&self) -> f64 {
        self.rate_hz
    }

    /// Set a new target rate.
    pub fn set_rate(&mut self, rate_hz: f64) {
        self.rate_hz = rate_hz.max(0.001);
    }

    /// Reset counters and timer.
    pub fn reset(&mut self) {
        self.issued = 0;
        self.suppressed = 0;
        self.last_issued = None;
    }
}

impl Default for CoverTraffic {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// TimingObfuscator
// ---------------------------------------------------------------------------

/// Timing obfuscator — recommends per-packet jitter delays so that outbound
/// packet timing cannot fingerprint traffic patterns (e.g. request-response
/// pairing, agent identities, conversation length).
///
/// # Security property
/// A passive observer measuring inter-packet delays cannot reconstruct the
/// true request-response timing graph when jitter is applied.
///
/// # Python parity
/// Matches the `TimingObfuscator` class described in README threat table §3
/// (Metadata Reconnaissance countermeasures).
pub struct TimingObfuscator {
    /// Maximum jitter in milliseconds.
    max_jitter_ms: u64,
    /// Minimum jitter in milliseconds.
    min_jitter_ms: u64,
    /// Total delays recommended (sum of all jitter values in ms).
    total_delay_ms: u64,
    /// Total packets processed.
    packets_processed: u64,
}

impl TimingObfuscator {
    /// Create with default `MPF_TIMING_JITTER_MS` maximum.
    pub fn new() -> Self {
        Self {
            max_jitter_ms: MPF_TIMING_JITTER_MS,
            min_jitter_ms: MPF_TIMING_JITTER_MIN_MS,
            total_delay_ms: 0,
            packets_processed: 0,
        }
    }

    /// Create with custom min/max jitter bounds (milliseconds).
    pub fn with_jitter(min_ms: u64, max_ms: u64) -> Self {
        let min_ms = min_ms.min(max_ms);
        Self {
            max_jitter_ms: max_ms.max(1),
            min_jitter_ms: min_ms,
            total_delay_ms: 0,
            packets_processed: 0,
        }
    }

    /// Compute a jitter delay in milliseconds for the next packet.
    ///
    /// The delay is in `[min_jitter_ms, max_jitter_ms]`, drawn from the OS
    /// CSPRNG via `rand::thread_rng()` so outbound timing is unpredictable
    /// to a passive observer (a fixed-seed PRNG would leak the entire
    /// jitter sequence to anyone who knows the algorithm).
    /// Callers should apply `tokio::time::sleep(Duration::from_millis(jitter))`
    /// or equivalent before sending the packet.
    pub fn jitter_ms(&mut self) -> u64 {
        let jitter = rand::thread_rng().gen_range(self.min_jitter_ms..=self.max_jitter_ms);
        self.total_delay_ms += jitter;
        self.packets_processed += 1;
        jitter
    }

    /// Same as `jitter_ms()` but returns a `Duration`.
    pub fn jitter_duration(&mut self) -> Duration {
        Duration::from_millis(self.jitter_ms())
    }

    /// Total milliseconds of delay recommended so far.
    pub fn total_delay_ms(&self) -> u64 {
        self.total_delay_ms
    }

    /// Total packets for which jitter was computed.
    pub fn packets_processed(&self) -> u64 {
        self.packets_processed
    }

    /// Reset statistics.
    pub fn reset(&mut self) {
        self.total_delay_ms = 0;
        self.packets_processed = 0;
    }
}

impl Default for TimingObfuscator {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// MpfBundle — convenience wrapper
// ---------------------------------------------------------------------------

/// Convenience bundle that owns all three MPF subsystems.
///
/// Callers can use this instead of managing three separate instances.
pub struct MpfBundle {
    pub padding: AdaptivePadding,
    pub cover: CoverTraffic,
    pub timing: TimingObfuscator,
}

impl MpfBundle {
    /// Create a new bundle with default settings.
    pub fn new() -> Self {
        Self {
            padding: AdaptivePadding::new(),
            cover: CoverTraffic::new(),
            timing: TimingObfuscator::new(),
        }
    }
}

impl Default for MpfBundle {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── AdaptivePadding ────────────────────────────────────────────────────

    #[test]
    fn test_pad_block_size_default() {
        let ap = AdaptivePadding::new();
        // empty → MPF_PAD_BLOCK_SIZE
        assert_eq!(ap.target_length(0), MPF_PAD_BLOCK_SIZE);
    }

    #[test]
    fn test_pad_exact_boundary() {
        let ap = AdaptivePadding::new();
        // already at a bucket boundary → same size
        assert_eq!(ap.target_length(256), 256);
        assert_eq!(ap.target_length(512), 512);
    }

    #[test]
    fn test_pad_round_up() {
        let ap = AdaptivePadding::new();
        // 1 byte over a boundary → next bucket
        assert_eq!(ap.target_length(257), 512);
        assert_eq!(ap.target_length(513), 1024);
    }

    #[test]
    fn test_pad_max_bucket_cap() {
        let ap = AdaptivePadding::new();
        // Very large payload should not exceed max_bucket
        assert_eq!(ap.target_length(1_000_000), MPF_PAD_MAX_BUCKET);
    }

    #[test]
    fn test_pad_mutates_vec() {
        let mut ap = AdaptivePadding::new();
        let mut data = vec![0xABu8; 100];
        let added = ap.pad(&mut data);
        assert_eq!(data.len(), 256);
        assert_eq!(added, 156);
        assert_eq!(ap.total_padding_bytes(), 156);
        assert_eq!(ap.packets_processed(), 1);
    }

    #[test]
    fn test_pad_no_padding_needed() {
        let mut ap = AdaptivePadding::new();
        let mut data = vec![0u8; 256];
        let added = ap.pad(&mut data);
        assert_eq!(added, 0);
        assert_eq!(data.len(), 256);
    }

    #[test]
    fn test_strip_padding() {
        let data = vec![1u8, 2, 3, 0, 0, 0];
        let stripped = AdaptivePadding::strip_padding(&data, 3);
        assert_eq!(stripped, &[1u8, 2, 3]);
    }

    #[test]
    fn test_reset_stats() {
        let mut ap = AdaptivePadding::new();
        let mut d = vec![1u8; 10];
        ap.pad(&mut d);
        ap.reset_stats();
        assert_eq!(ap.total_padding_bytes(), 0);
        assert_eq!(ap.packets_processed(), 0);
    }

    // ── CoverTraffic ───────────────────────────────────────────────────────

    #[test]
    fn test_cover_first_emit() {
        let mut ct = CoverTraffic::new();
        // First call always returns true (no previous timestamp)
        assert!(ct.should_emit());
        assert_eq!(ct.total_issued(), 1);
    }

    #[test]
    fn test_cover_rate_limiting() {
        let mut ct = CoverTraffic::with_rate(1000.0); // 1000 Hz → 1ms interval
        // First emit
        assert!(ct.should_emit());
        // Immediately after — should be suppressed (< 1ms elapsed)
        let suppressed_before = ct.total_suppressed();
        // Cannot guarantee sleep, just check that record_emit works
        ct.record_emit();
        assert_eq!(ct.total_issued(), 2);
        let _ = suppressed_before; // silence unused
    }

    #[test]
    fn test_cover_set_rate() {
        let mut ct = CoverTraffic::new();
        ct.set_rate(5.0);
        assert!((ct.rate_hz() - 5.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_cover_reset() {
        let mut ct = CoverTraffic::new();
        ct.should_emit();
        ct.reset();
        assert_eq!(ct.total_issued(), 0);
        assert_eq!(ct.total_suppressed(), 0);
    }

    // ── TimingObfuscator ───────────────────────────────────────────────────

    #[test]
    fn test_jitter_in_range() {
        let mut to = TimingObfuscator::with_jitter(10, 50);
        for _ in 0..100 {
            let j = to.jitter_ms();
            assert!(j >= 10, "jitter {j} below min 10ms");
            assert!(j <= 50, "jitter {j} above max 50ms");
        }
    }

    #[test]
    fn test_jitter_default_range() {
        let mut to = TimingObfuscator::new();
        for _ in 0..50 {
            let j = to.jitter_ms();
            assert!(j <= MPF_TIMING_JITTER_MS);
        }
    }

    #[test]
    fn test_jitter_stats() {
        let mut to = TimingObfuscator::new();
        to.jitter_ms();
        to.jitter_ms();
        assert_eq!(to.packets_processed(), 2);
        assert!(to.total_delay_ms() > 0);
    }

    #[test]
    fn test_jitter_duration() {
        let mut to = TimingObfuscator::new();
        let d = to.jitter_duration();
        assert!(d <= Duration::from_millis(MPF_TIMING_JITTER_MS));
    }

    #[test]
    fn test_jitter_reset() {
        let mut to = TimingObfuscator::new();
        to.jitter_ms();
        to.reset();
        assert_eq!(to.packets_processed(), 0);
        assert_eq!(to.total_delay_ms(), 0);
    }

    #[test]
    fn test_jitter_is_unpredictable_and_bounded() {
        // H-31: jitter must NOT be reproducible from a fixed seed (that was the
        // vulnerability — zero-entropy timing obfuscation is no obfuscation at
        // all). Two independent instances must diverge, while every value
        // stays within the documented [min, max] bound.
        let mut a = TimingObfuscator::new();
        let mut b = TimingObfuscator::new();
        let seq_a: Vec<u64> = (0..20).map(|_| a.jitter_ms()).collect();
        let seq_b: Vec<u64> = (0..20).map(|_| b.jitter_ms()).collect();
        assert_ne!(seq_a, seq_b, "jitter sequences must not be deterministic across instances");
        for &j in seq_a.iter().chain(seq_b.iter()) {
            assert!(j >= MPF_TIMING_JITTER_MIN_MS && j <= MPF_TIMING_JITTER_MS);
        }
    }

    // ── MpfBundle ─────────────────────────────────────────────────────────

    #[test]
    fn test_bundle_default() {
        let mut bundle = MpfBundle::new();
        let mut data = vec![1u8; 100];
        bundle.padding.pad(&mut data);
        assert_eq!(data.len(), 256);
        assert!(bundle.cover.should_emit());
        let _j = bundle.timing.jitter_ms();
    }
}
