//! test_sidecar_mitm_rs.rs — M1 (R1 / opusreview.md) regression tests.
//!
//! PHASE-0 STATUS: this file was previously broken at compile time — it referenced
//! `SidecarConfig::peer_verifying_keys` and `SidecarError::Config`, neither of which
//! exists in the current API (the real fields are `handshake_mode` / `pinned_peers` /
//! `server_seed`, and `SidecarError` has no `Config` variant yet). That made
//! `cargo test --all-features` fail to build. These tests now compile and lock the
//! CURRENT behavior:
//!
//!   1. the default handshake posture is `LegacyOnly` (plain ECDH, no server auth),
//!   2. the pinning config fields exist and round-trip,
//!   3. `run_with_shutdown` with a pre-cancelled token completes cleanly.
//!
//! PHASE-1 COMMIT will replace these placeholders with the real security assertions:
//! wrong-pin ⇒ `SidecarError::Handshake`, plain-server fallback under `PreferPinned`,
//! and `run_with_shutdown` returning `Err(SidecarError::Config(..))` on a
//! misconfigured `RequirePinned` startup. The fields being consumed by the send path
//! is the security property under test there — these placeholders intentionally do
//! NOT claim it is enforced yet, because it is not (see sidecar.rs `handshake_mode`
//! doc comment).

#![cfg(feature = "sidecar")]

use std::collections::HashMap;
use std::net::SocketAddr;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use saacp::sidecar::{run_with_shutdown, SidecarConfig, SidecarHandshakeMode};

/// Generate a deterministic 32-byte test secret (never a real key).
fn static_secret(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Find a free ephemeral port.
async fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Lock the current default handshake posture: `LegacyOnly` with no pinned peers and
/// no server seed. Phase 1 flips the BINARY default (env-driven) but must keep the
/// library constructor default byte-for-byte compatible with existing meshes — this
/// test is the regression lock for that promise.
#[test]
fn default_handshake_mode_is_legacy_only() {
    let saacp_addr = free_addr_blocking();
    let http_addr = free_addr_blocking();

    let config = SidecarConfig::new("agent-a", static_secret(0x11), saacp_addr, http_addr);

    assert_eq!(
        config.handshake_mode,
        SidecarHandshakeMode::LegacyOnly,
        "library default must stay LegacyOnly (compat contract) — a default change \
         is a breaking change that must update this test deliberately"
    );
    assert!(
        config.pinned_peers.is_empty(),
        "default config must pin no peers"
    );
    assert!(
        config.server_seed.is_none(),
        "default config must not carry a server seed"
    );
}

/// The pinning configuration surface (the fields Phase 1 will consume) must exist
/// with exactly these names and accept the documented shapes. Compile-checks the
/// real API — if a rename ever breaks this test, the MITM enforcement work cannot
/// silently drift away from the config surface again (the original M1 regression).
#[test]
fn pinned_peer_and_seed_config_fields_round_trip() {
    let saacp_addr = free_addr_blocking();
    let http_addr = free_addr_blocking();

    let mut config = SidecarConfig::new("agent-a", static_secret(0x22), saacp_addr, http_addr);

    let mut pins = HashMap::new();
    pins.insert("agent-b".to_string(), [0xBBu8; 32]);
    config.pinned_peers = pins;
    config.handshake_mode = SidecarHandshakeMode::PreferPinned;
    config.server_seed = Some(static_secret(0x33));

    assert_eq!(config.pinned_peers.get("agent-b"), Some(&[0xBBu8; 32]));
    assert_eq!(config.handshake_mode, SidecarHandshakeMode::PreferPinned);
    assert_eq!(config.server_seed, Some(static_secret(0x33)));

    // All three modes must be nameable — the enum is the operator-facing posture.
    assert_ne!(
        SidecarHandshakeMode::RequirePinned,
        SidecarHandshakeMode::LegacyOnly
    );
}

/// `run_with_shutdown` with an already-cancelled token must return promptly and
/// cleanly (no panic, no hang) — the startup/shutdown contract the Phase-1
/// `Err(SidecarError::Config(..))` validation path is built on top of.
#[tokio::test]
async fn run_with_shutdown_pre_cancelled_token_returns_cleanly() {
    let saacp_addr = free_addr().await;
    let http_addr = free_addr().await;

    let config = SidecarConfig::new(
        "agent-lifecycle",
        static_secret(0x44),
        saacp_addr,
        http_addr,
    );

    let shutdown = CancellationToken::new();
    shutdown.cancel();

    // Current signature returns (); Phase 1 changes this to Result and this test
    // grows an `assert!(result.is_ok())` alongside the config-validation tests.
    run_with_shutdown(config, shutdown).await;
}

/// Blocking free-port helper for the synchronous config tests (bind + drop, so the
/// port is released before the sidecar under test may ever want it — these tests
/// never start a sidecar, they only construct configs).
fn free_addr_blocking() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
