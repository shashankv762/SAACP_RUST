//! security_mutex.rs — Observable M-38 Poison-Recovery Mutex
//!
//! SAACP's M-38 hardening invariant requires that a panic inside a
//! security-critical `Mutex` guard NEVER leaves the affected shard in a
//! fail-open (no-trust) state. Standard `Mutex::lock().unwrap()` propagates
//! the panic to the caller, potentially crashing the gate pipeline and
//! defaulting to permissive behavior. The `.unwrap_or_else(|e| e.into_inner())`
//! recovery pattern used throughout the codebase preserves this invariant —
//! it recovers the (possibly partially-mutated) map state rather than crashing.
//!
//! `SecurityMutex<T>` wraps this recovery with:
//!
//! 1. **A process-wide atomic counter** (`SECURITY_MUTEX_POISON_RECOVERIES`)
//!    incremented on every recovery — Prometheus-exported via
//!    [`poison_recovery_count()`] so operators get an unambiguous signal.
//! 2. **A structured tracing error** naming the affected mutex so incidents
//!    can be correlated with the exact subsystem that panicked.
//!
//! # Security subsystems that MUST use `SecurityMutex`
//!
//! Any `Mutex` guarding per-agent security state where partial mutation after
//! a panic would be a security concern (fail-open risk):
//!
//! - [`crate::trust_decay::TrustDecayEngine`] shards
//! - [`crate::gateway::ZeroTrustGateway`] shards
//! - [`crate::streaming::StreamRegistry`] shards
//! - [`crate::ievl::IevlEngine`] shards
//! - [`crate::cscs::CSCSLoopDetector`] shards
//! - [`crate::memory::FederatedMemory`] shards
//! - [`crate::security::ImmutableAuditLog`] nonce tracker

use std::sync::{Mutex, MutexGuard};
use std::sync::atomic::{AtomicU64, Ordering};

/// Process-wide count of security mutex poison recoveries.
/// Prometheus-exported via [`poison_recovery_count()`].
static SECURITY_MUTEX_POISON_RECOVERIES: AtomicU64 = AtomicU64::new(0);

/// Returns the count of poison-recovery events since process start.
pub fn poison_recovery_count() -> u64 {
    SECURITY_MUTEX_POISON_RECOVERIES.load(Ordering::Relaxed)
}

/// Increment the poison-recovery counter.
///
/// Use this in modules that implement the M-38 recovery pattern inline with a
/// plain `std::sync::Mutex` (e.g. where changing the struct field type to
/// `SecurityMutex<T>` would cascade to hundreds of call sites). This keeps
/// the global counter as the single source of truth for Prometheus.
pub fn inc_poison_recovery_count() {
    SECURITY_MUTEX_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
}

/// A `Mutex<T>` wrapper for security-critical sharded maps.
pub struct SecurityMutex<T> {
    inner: Mutex<T>,
    name: &'static str,
}

impl<T> SecurityMutex<T> {
    pub fn new(value: T, name: &'static str) -> Self {
        Self { inner: Mutex::new(value), name }
    }

    pub fn lock(&self) -> MutexGuard<'_, T> {
        match self.inner.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                SECURITY_MUTEX_POISON_RECOVERIES.fetch_add(1, Ordering::Relaxed);
                tracing::error!(
                    mutex_name = self.name,
                    "SECURITY GATE STATE CORRUPTION: SecurityMutex poison recovered. \
                     A thread panicked while holding this lock."
                );
                poisoned.into_inner()
            }
        }
    }

    pub fn name(&self) -> &'static str { self.name }
}

// Send + Sync are derived automatically through `inner: Mutex<T>`:
// Mutex<T>: Send when T: Send, Mutex<T>: Sync when T: Send.
// No unsafe impl needed — and unsafe_code is forbidden crate-wide (#![forbid(unsafe_code)]).

impl<T: std::fmt::Debug> std::fmt::Debug for SecurityMutex<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecurityMutex").field("name", &self.name).field("inner", &self.inner).finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;

    #[test]
    fn lock_and_modify() {
        let m = SecurityMutex::new(0u32, "test_mutex");
        *m.lock() = 42;
        assert_eq!(*m.lock(), 42);
    }

    #[test]
    fn recovers_from_poison_and_increments_counter() {
        let before = poison_recovery_count();
        let m = std::sync::Arc::new(SecurityMutex::new(0u32, "poison_test"));
        let m2 = m.clone();
        let _ = thread::spawn(move || {
            let _guard = m2.lock();
            panic!("intentional panic to poison the mutex");
        }).join();
        let val = *m.lock();
        assert_eq!(val, 0);
        assert!(poison_recovery_count() > before);
    }
}
