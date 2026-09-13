// SAACP Layer 1: FIPS Cryptographic Boundary.
//
// CRITICAL INVARIANT: This crate MUST NOT depend on saacp-core, tokio
// observability (tracing macros are allowed), axum, or any networking
// library beyond what the crypto primitives themselves need.
//
// Telemetry is surfaced via the CryptoTelemetry trait below — saacp-core
// injects the real implementation at startup; the default is a no-op.
#![forbid(unsafe_code)]

use std::sync::Arc;

// ── FIPS Boundary Telemetry Bridge ──────────────────────────────────────────
// Allows saacp-core to observe crypto-layer events without creating a
// reverse dependency (crypto → core) that would violate the FIPS boundary.

/// Events emitted by the cryptographic layer that the observability layer
/// may want to record. Implemented by saacp-core; the default is no-op.
pub trait CryptoTelemetry: Send + Sync {
    /// A WAL shard mutex experienced lock contention.
    fn record_mutex_contention(&self, lock_name: &str);
    /// The audit WAL async queue was full — an event was dropped.
    fn record_audit_gate_rejection(&self);
    /// A key lifecycle rotation completed.
    fn record_key_rotation(&self);
}

struct NullCryptoTelemetry;
impl CryptoTelemetry for NullCryptoTelemetry {
    fn record_mutex_contention(&self, _: &str) {}
    fn record_audit_gate_rejection(&self) {}
    fn record_key_rotation(&self) {}
}

static CRYPTO_TELEMETRY: std::sync::OnceLock<Arc<dyn CryptoTelemetry>> =
    std::sync::OnceLock::new();

/// Wire in the real telemetry bridge. Called once during saacp-core startup.
/// Subsequent calls are silently ignored (OnceLock semantics).
pub fn set_crypto_telemetry(t: Arc<dyn CryptoTelemetry>) {
    let _ = CRYPTO_TELEMETRY.set(t);
}

/// Returns the active telemetry bridge. Falls back to a no-op if
/// `set_crypto_telemetry` has not been called yet (e.g. in unit tests).
pub fn crypto_telemetry() -> &'static dyn CryptoTelemetry {
    static NULL: NullCryptoTelemetry = NullCryptoTelemetry;
    CRYPTO_TELEMETRY
        .get()
        .map(|a| a.as_ref())
        .unwrap_or(&NULL)
}

// ── Module declarations ──────────────────────────────────────────────────────
// Populated progressively as Phase 2 copies modules here.
// The facade crate (src/lib.rs) re-exports these as `pub use saacp_crypto::*`.
pub mod security;
pub mod framing;
pub mod measc;
pub mod easi;
pub mod schemas;
pub mod rgc;
pub mod crypto_governance;
pub mod cryptosuite;
pub mod response_auth;
pub mod klms;
pub mod attestation;
pub mod pqc;
pub mod hrt;
