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
//! Pure refactor — zero behavior change, zero wire change: [`SystemClock`]
//! reproduces the exact `SystemTime::now().duration_since(UNIX_EPOCH)
//! .unwrap_or_default().as_secs_f64()` semantics the eight helpers shared.

/// Injectable time source. `Send + Sync` so implementations can live in
/// `Arc<dyn Clock>` behind the subsystems that need them.
pub trait Clock: Send + Sync {
    /// Seconds since the Unix epoch, fractional.
    fn now_secs_f64(&self) -> f64;
}

/// The production clock: the real system wall clock. Default impl of
/// [`Clock`] with identical semantics to the eight former `now_secs()`
/// copies (including the `unwrap_or_default()` failure mode: a clock set
/// before the epoch reads as `0.0`, never panics).
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

/// Convenience free function over [`SystemClock`]: the current epoch time in
/// (fractional) seconds. What the eight former per-module `now_secs()`
/// helpers now delegate to.
pub fn now_secs_f64() -> f64 {
    SystemClock.now_secs_f64()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn system_clock_returns_sane_monotonic_epoch_seconds() {
        let clock = SystemClock;
        let a = clock.now_secs_f64();
        // Sane range: after 2020-01-01, before 2100-01-01 (catches a broken
        // system clock without being time-bomb brittle).
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
}
