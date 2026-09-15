//! clock.rs — injectable clock seam (finding I, Phase 4).
//!
//! Every time-sensitive subsystem in this codebase previously grew its own
//! identical `now_secs()` helper (`aca.rs`, `cscs.rs`, `identity_binding.rs`,
//! `ievl.rs`, `memory.rs`, `security.rs`, `temporal.rs`, `trust_decay.rs`).
//! Those helpers now delegate to this module's [`SystemClock`], so the
//! "what time is it" seam lives in exactly one place and future work that
//! needs deterministic time (property tests, replay harnesses) can inject a
//! [`Clock`] implementation instead of patching eight copies.
//!
//! # Dual-Clock Architecture
//!
//! Two clock sources serve different semantic needs:
//!
//! - **[`MonotonicClock`]** (via [`now_secs_f64()`] / [`monotonic()`]): for
//!   elapsed-time consumers (key TTLs, trust penalty decay, cluster failure
//!   detection, nonce age). Immune to NTP jumps — time never goes backward.
//! - **[`SystemClock`]** (via [`wall_clock_now()`]): for fields that must
//!   correlate with external system clocks — WAL audit timestamps, token `exp`
//!   validation, and signed wire fields verified by peers.

/// Injectable time source. `Send + Sync` so implementations can live in
/// `Arc<dyn Clock>` behind the subsystems that need them.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch, fractional.
    fn now_secs_f64(&self) -> f64;
}

/// The production wall clock. Identical semantics to the eight former
/// `now_secs()` copies (`unwrap_or_default()`: a clock before the epoch
/// reads as `0.0`, never panics).
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_secs_f64(&self) -> f64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs_f64()
    }
}

/// Monotonic clock: immune to NTP jumps and backward clock adjustments.
///
/// Uses `Instant::elapsed()` anchored to a wall-clock snapshot captured once
/// at construction time via [`MonotonicClock::start`]. This means:
///
/// - `now_secs_f64()` can NEVER decrease between consecutive calls within
///   the same process. NTP stepping the clock backward has zero effect.
/// - The returned `f64` is still a plausible Unix epoch timestamp (not an
///   arbitrary offset), so it remains safe to store in `KeyDescriptor::
///   created_at`, `TrustEntry::last_update`, `MemberRecord::last_seen`, etc.
/// - An NTP correction forward adds at most one step; wild forward jumps
///   can only cause keys to expire slightly early — the safe direction.
///
/// # When to use
/// Subsystems measuring **elapsed time** for TTLs, rotation windows, and
/// failure detection — KLMS, cluster tick, trust decay, nonce age.
///
/// # When NOT to use
/// Fields that must correlate with external system clocks: WAL audit
/// timestamps, token `exp` validation, wire `sent_at` fields.
/// Use [`wall_clock_now()`] for those.
#[derive(Debug, Clone)]
pub struct MonotonicClock {
    /// Wall-clock epoch seconds captured at process start, used as the
    /// anchor so returned values look like real Unix timestamps.
    boot_wall: f64,
    /// Monotonic instant captured at the same moment as `boot_wall`.
    boot_instant: std::time::Instant,
}

impl MonotonicClock {
    /// Capture the current wall-clock and monotonic instant together.
    pub fn start() -> Self {
        Self {
            boot_wall: SystemClock.now_secs_f64(),
            boot_instant: std::time::Instant::now(),
        }
    }
}

impl Clock for MonotonicClock {
    fn now_secs_f64(&self) -> f64 {
        self.boot_wall + self.boot_instant.elapsed().as_secs_f64()
    }
}

/// Process-wide monotonic clock singleton. Initialized once on first call.
///
/// Subsystems that need NTP-immune elapsed time use this:
/// KLMS rotation, trust decay, cluster failure detection, nonce age.
pub fn monotonic() -> &'static MonotonicClock {
    static M: std::sync::OnceLock<MonotonicClock> = std::sync::OnceLock::new();
    M.get_or_init(MonotonicClock::start)
}

/// Convenience free function used by per-module `now_secs()` helpers.
///
/// Returns **monotonic time** (via [`monotonic()`]) so all elapsed-time
/// consumers are immune to NTP jumps. For real wall-clock time needed for
/// external correlation (WAL timestamps, token `exp`), call
/// [`wall_clock_now()`] explicitly.
pub fn now_secs_f64() -> f64 {
    monotonic().now_secs_f64()
}

/// Wall-clock epoch seconds — always calls `SystemTime::now()` directly.
///
/// Use for:
/// - WAL audit log timestamps (SIEM / Splunk correlation)
/// - Token `exp` claim validation (RFC 7519 Unix epoch)
/// - Signed wire fields (`sent_at`, `quote_timestamp`) verified by peers
///
/// Do NOT use for TTL / elapsed-time comparisons — use [`now_secs_f64()`].
pub fn wall_clock_now() -> f64 {
    SystemClock.now_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_sane_monotonic_epoch_seconds() {
        let clock = SystemClock;
        let a = clock.now_secs_f64();
        // Sane range: after 2020-01-01, before 2100-01-01.
        assert!(
            a > 1_577_836_800.0 && a < 4_102_444_800.0,
            "SystemClock returned an implausible epoch value: {a}"
        );
        let b = clock.now_secs_f64();
        assert!(
            b >= a,
            "SystemClock must be non-decreasing within a process: {a} -> {b}"
        );
    }

    #[test]
    fn monotonic_clock_never_decreases() {
        let clock = MonotonicClock::start();
        let a = clock.now_secs_f64();
        let b = clock.now_secs_f64();
        assert!(b >= a, "MonotonicClock must be non-decreasing: {a} -> {b}");
    }

    #[test]
    fn monotonic_clock_returns_plausible_epoch() {
        let t = monotonic().now_secs_f64();
        assert!(
            t > 1_577_836_800.0 && t < 4_102_444_800.0,
            "monotonic() returned an implausible epoch value: {t}"
        );
    }

    #[test]
    fn wall_clock_now_returns_plausible_epoch() {
        let t = wall_clock_now();
        assert!(
            t > 1_577_836_800.0 && t < 4_102_444_800.0,
            "wall_clock_now() returned an implausible epoch value: {t}"
        );
    }

    #[test]
    fn now_secs_f64_is_nondecreasing() {
        let a = now_secs_f64();
        let b = now_secs_f64();
        assert!(b >= a, "now_secs_f64() must be non-decreasing: {a} -> {b}");
    }
}
