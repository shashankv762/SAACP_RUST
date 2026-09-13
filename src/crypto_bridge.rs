//! crypto_bridge.rs — wires saacp-core telemetry into the saacp-crypto FIPS boundary.
//!
//! # FIPS Boundary isolation
//! `saacp-crypto` exposes [`saacp_crypto::CryptoTelemetry`] trait but knows nothing
//! about `saacp-core`'s [`crate::telemetry`] module. This module lives in the facade
//! (saacp crate) and is the only place both sides are visible simultaneously — so it
//! is the *only* correct place for the bridge.
//!
//! # Usage
//! Call [`init_crypto_telemetry_bridge`] once during startup, from
//! [`crate::gateway::ZeroTrustGateway::shared_default`] (or your top-level init).
//! All subsequent crypto-layer telemetry calls will reach the real collector.

use std::sync::Arc;

/// Core-side implementation of the crypto telemetry bridge.
struct CoreCryptoTelemetry;

impl saacp_crypto::CryptoTelemetry for CoreCryptoTelemetry {
    fn record_mutex_contention(&self, lock_name: &str) {
        // telemetry expects &'static str; intern the name so it lives forever.
        // The set of lock_name values from saacp-crypto is small and fixed
        // ("wal_append") so the leak is bounded and deliberate.
        let static_name: &'static str = Box::leak(lock_name.to_string().into_boxed_str());
        crate::telemetry::global_telemetry().record_mutex_contention(static_name);
    }

    fn record_audit_gate_rejection(&self) {
        // Mirrors the old: global_telemetry().record_gate_rejection("gate_6_0_audit")
        crate::telemetry::global_telemetry().record_gate_rejection("gate_6_0_audit");
    }

    fn record_key_rotation(&self) {
        // Mirrors the old: global_telemetry().record_key_rotation()
        crate::telemetry::global_telemetry().record_key_rotation();
    }
}

/// Wire the real telemetry bridge into the `saacp-crypto` crate.
///
/// # Idempotent
/// Uses `OnceLock` internally — safe to call multiple times (only the first
/// call takes effect). Subsequent calls are silently ignored.
///
/// # When to call
/// Call this once, early in your binary's startup sequence, before any
/// [`saacp_crypto::security::ImmutableAuditLog`] or
/// [`saacp_crypto::klms::KeyLifecycleManager`] operations are triggered.
/// In practice this means inside [`crate::gateway::ZeroTrustGateway::shared_default`]
/// or the `main()` of each binary.
pub fn init_crypto_telemetry_bridge() {
    saacp_crypto::set_crypto_telemetry(Arc::new(CoreCryptoTelemetry));
}
