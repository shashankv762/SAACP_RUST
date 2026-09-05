//! test_sidecar_mitm_rs.rs — M1 (R1 / opusreview.md) regression tests.
//!
//! The sidecar's outbound handshake posture ([`SidecarHandshakeMode`]) and its
//! pinned-peer / server-identity configuration are the security property under
//! test here:
//!
//! 1. the library default handshake posture is `LegacyOnly` (plain ECDH) — a
//!    byte-for-byte compat contract any default change must update deliberately;
//! 2. the pinning configuration surface round-trips (the anti-drift lock on the
//!    original M1 regression, where the config fields existed but were never
//!    read by any send path);
//! 3. `REQUIRE_PINNED` fails closed at startup without a server seed, and
//!    fails closed per-dial without a pin — refuse, never silently downgrade;
//! 4. a wrong pinned verifying key is REJECTED (suspected MITM) — against the
//!    real 128-byte `[pub‖sig‖vk]` authenticated response of a live server;
//! 5. the correct pin completes an authenticated `REQUIRE_PINNED` send;
//! 6. `PREFER_PINNED` transparently falls back to plain ECDH against a legacy
//!    (v1) peer — the documented migration-window downgrade posture — and the
//!    downgrade is visible in the `handshake_fallback_total` telemetry;
//! 7. `REQUIRE_PINNED` against a legacy plain peer fails closed;
//! 8. `/healthz` exposes the active posture and all three outcome counters.
//!
//! Every dial scenario exercises the REAL handshake byte layouts end to end
//! against a real in-process sidecar — 64-byte client hello `[nonce‖pub]`,
//! 32-byte plain `[pub]` response, 128-byte authed `[pub‖sig‖vk]` response.
//! Nothing here stubs the crypto, so wire-format drift fails these tests too.

#![cfg(feature = "sidecar")]

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use saacp::daemon::SAACPNetworkDaemon;
use saacp::sidecar::{
    handshake_telemetry, run, run_with_shutdown, send_message, SendOutcome, SidecarConfig,
    SidecarError, SidecarHandshakeMode,
};

/// Shared mesh secret for both ends of every scenario here.
static MESH_SECRET: [u8; 32] = [0x5Eu8; 32];

/// Deterministic test-only server seed (never a real key).
fn test_server_seed(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// Generate a deterministic 32-byte test secret (never a real key).
fn static_secret(byte: u8) -> [u8; 32] {
    [byte; 32]
}

/// The Ed25519 verifying key a client must pin for a server built from
/// `seed` — derived through the same public path the daemon itself uses
/// (`SAACPNetworkDaemon::server_verifying_key`), so this test cannot drift
/// from the real seed→VK derivation.
fn server_vk_for(seed: [u8; 32]) -> [u8; 32] {
    SAACPNetworkDaemon::insecure_for_testing("127.0.0.1", 0, None)
        .with_server_auth(seed)
        .server_verifying_key()
        .expect("server auth was just configured")
}

/// Find a free ephemeral port.
async fn free_addr() -> SocketAddr {
    let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap()
}

/// Spawn a server-side sidecar whose SAACP protocol listener is the dial
/// target; `customize` sets the handshake posture / seed / pins before
/// start. Returns the SAACP protocol address to dial.
async fn spawn_server_sidecar(
    agent_id: &str,
    customize: impl FnOnce(&mut SidecarConfig),
) -> SocketAddr {
    let saacp_addr = free_addr().await;
    let http_addr = free_addr().await;
    let mut config = SidecarConfig::new(agent_id, MESH_SECRET, saacp_addr, http_addr);
    customize(&mut config);
    tokio::spawn(async move {
        run(config).await;
    });
    // Give both listeners a moment to bind.
    tokio::time::sleep(Duration::from_millis(200)).await;
    saacp_addr
}

/// One outbound `send_message` dial from the "client" role, with the caller's
/// chosen handshake posture and (optional) pinned verifying key. This is the
/// exact code path `/send` dispatches to, so every assertion here holds for
/// the HTTP surface too.
async fn send_probe(
    target: &SocketAddr,
    mode: SidecarHandshakeMode,
    pin: Option<&[u8; 32]>,
) -> Result<SendOutcome, SidecarError> {
    let allow: Vec<(std::net::IpAddr, u8)> = Vec::new();
    send_message(
        &target.to_string(),
        "agent-server",
        "agent-client",
        &MESH_SECRET,
        "mitm-probe task",
        1,
        0,
        1,
        &allow,
        false,
        None,
        false,
        mode,
        pin,
    )
    .await
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

// ─── 3: fail-closed startup validation ───────────────────────────────────────

/// `REQUIRE_PINNED` without a server seed must fail startup validation BEFORE
/// any listener binds: the authenticated inbound handshake needs a stable
/// Ed25519 server identity clients can pin. The pre-cancelled token proves
/// validation runs first (the call returns promptly without serving).
#[tokio::test]
async fn require_pinned_without_server_seed_fails_startup_validation() {
    let saacp_addr = free_addr().await;
    let http_addr = free_addr().await;

    let mut config = SidecarConfig::new("agent-cfg", MESH_SECRET, saacp_addr, http_addr);
    config.handshake_mode = SidecarHandshakeMode::RequirePinned;
    config.server_seed = None;

    let shutdown = CancellationToken::new();
    shutdown.cancel();
    let result = run_with_shutdown(config, shutdown).await;

    let msg = match result {
        Err(SidecarError::Config(msg)) => msg,
        other => panic!("expected Err(SidecarError::Config(..)), got: {other:?}"),
    };
    assert!(
        msg.contains("server_seed") && msg.contains("SAACP_SERVER_SEED_FILE"),
        "config error must name the missing seed and its env var, got: {msg}"
    );
}

/// Spawn the live REQUIRE_PINNED server every dial scenario below targets.
async fn spawn_require_pinned_server(seed: [u8; 32]) -> SocketAddr {
    spawn_server_sidecar("agent-server", |cfg| {
        cfg.handshake_mode = SidecarHandshakeMode::RequirePinned;
        cfg.server_seed = Some(seed);
    })
    .await
}

// ─── 4/5/7: REQUIRE_PINNED dial enforcement (against a live server) ──────────

/// `REQUIRE_PINNED` without a configured pin for the peer must REFUSE the dial
/// (`SidecarError::Config`) rather than silently downgrading to plain ECDH,
/// and the refusal must be counted in `handshake_reject_total`.
#[tokio::test]
async fn require_pinned_dial_without_pin_is_refused_not_downgraded() {
    let seed = test_server_seed(0x41);
    let target = spawn_require_pinned_server(seed).await;

    let (_, _, rejects_before) = handshake_telemetry();
    let Err(err) = send_probe(&target, SidecarHandshakeMode::RequirePinned, None).await else {
        panic!("RequirePinned without a pin must refuse the dial, not succeed");
    };
    let (_, _, rejects_after) = handshake_telemetry();

    let msg = match err {
        SidecarError::Config(msg) => msg,
        other => panic!("expected Err(SidecarError::Config(..)), got: {other:?}"),
    };
    assert!(
        msg.contains("pinned"),
        "refusal must point at the missing pinned key, got: {msg}"
    );
    assert!(
        rejects_after > rejects_before,
        "handshake_reject_total must increase on a refused RequirePinned dial"
    );
}

/// THE MITM regression: a client pinning the WRONG verifying key must get a
/// handshake failure (`SidecarError::Handshake`) against a server presenting
/// its genuine 128-byte authenticated response — an impostor (or a corrupted
/// pin) can never be silently accepted, and the rejection is counted.
#[tokio::test]
async fn require_pinned_wrong_pin_is_rejected() {
    let seed = test_server_seed(0x42);
    let target = spawn_require_pinned_server(seed).await;

    let wrong_pin: [u8; 32] = [0x99u8; 32];
    let (_, _, rejects_before) = handshake_telemetry();
    let Err(err) = send_probe(
        &target,
        SidecarHandshakeMode::RequirePinned,
        Some(&wrong_pin),
    )
    .await
    else {
        panic!("a wrong pinned verifying key must be rejected, not accepted");
    };
    let (_, _, rejects_after) = handshake_telemetry();

    assert!(
        matches!(err, SidecarError::Handshake(_)),
        "expected SidecarError::Handshake, got: {err:?}"
    );
    assert!(
        rejects_after > rejects_before,
        "handshake_reject_total must increase on a rejected pinned handshake"
    );
}

/// The positive path (now possible without any external dependency: both
/// endpoints are ours): the CORRECT pin — derived from the same seed through
/// the daemon's public derivation — completes the authenticated handshake AND
/// the task delivery, and is counted in `handshake_pinned_ok`.
#[tokio::test]
async fn require_pinned_correct_pin_authenticates_end_to_end() {
    let seed = test_server_seed(0x43);
    let real_vk = server_vk_for(seed);
    let target = spawn_require_pinned_server(seed).await;

    let (pinned_ok_before, _, _) = handshake_telemetry();
    let Ok(outcome) =
        send_probe(&target, SidecarHandshakeMode::RequirePinned, Some(&real_vk)).await
    else {
        panic!(
            "a correct pin against a REQUIRE_PINNED server must complete the \
             authenticated handshake"
        );
    };
    let (pinned_ok_after, _, _) = handshake_telemetry();

    assert!(
        matches!(outcome, SendOutcome::Success),
        "expected the task to be delivered (SendOutcome::Success)"
    );
    assert!(
        pinned_ok_after > pinned_ok_before,
        "handshake_pinned_ok must increase on an authenticated handshake"
    );
}

/// A legacy (v1 `LegacyOnly`) server answers the plain 32-byte format and
/// nothing more. `REQUIRE_PINNED` must fail closed against it — never
/// downgrade, never deliver.
#[tokio::test]
async fn require_pinned_against_plain_server_fails_closed() {
    let seed = test_server_seed(0x45);
    let real_vk = server_vk_for(seed);
    // Server keeps the library-default LegacyOnly posture.
    let target = spawn_server_sidecar("agent-server", |_| {}).await;

    let Err(err) = send_probe(&target, SidecarHandshakeMode::RequirePinned, Some(&real_vk)).await
    else {
        panic!("REQUIRE_PINNED must fail closed against a peer that answers the plain format");
    };
    // The exact variant depends on which side gives up first: the client's
    // 10s dial timeout (`Timeout`) if the plain peer keeps the socket open, or
    // the transport read (`Handshake`) if it closes. Both are fail-closed;
    // neither is ever Ok.
    assert!(
        matches!(err, SidecarError::Handshake(_) | SidecarError::Timeout),
        "expected a fail-closed handshake/timeout error, got: {err:?}"
    );
}

// ─── 6: PREFER_PINNED migration-window fallback ──────────────────────────────

/// `PREFER_PINNED` against a legacy peer must INTEROPERATE via the documented
/// plain-ECDH fallback (the peer's genuine 32-byte response with no
/// authenticated suffix), the delivery must succeed, and the downgrade must
/// be counted in `handshake_fallback_total` — the operator's
/// migration-progress signal.
#[tokio::test]
async fn prefer_pinned_falls_back_to_plain_against_legacy_server() {
    let seed = test_server_seed(0x44);
    let real_vk = server_vk_for(seed);
    // Server keeps the library-default LegacyOnly posture.
    let target = spawn_server_sidecar("agent-server", |_| {}).await;

    let (_, fallback_before, _) = handshake_telemetry();
    let Ok(outcome) = send_probe(&target, SidecarHandshakeMode::PreferPinned, Some(&real_vk)).await
    else {
        panic!("PreferPinned must interoperate with a legacy peer via the plain fallback");
    };
    let (_, fallback_after, _) = handshake_telemetry();

    assert!(
        matches!(outcome, SendOutcome::Success),
        "expected the fallback delivery to succeed (SendOutcome::Success)"
    );
    assert!(
        fallback_after > fallback_before,
        "the plain downgrade must be counted in handshake_fallback_total"
    );
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

// ─── 8: /healthz observability ───────────────────────────────────────────────

/// `/healthz` must expose the active handshake posture and the three lifetime
/// outcome counters — the operator's window into migration progress
/// (`handshake_fallback_total`) and suspected-MITM activity
/// (`handshake_reject_total`).
#[tokio::test]
async fn healthz_reports_handshake_posture_and_telemetry() {
    let saacp_addr = free_addr().await;
    let http_addr = free_addr().await;
    let config = SidecarConfig::new("agent-health-m1", MESH_SECRET, saacp_addr, http_addr);
    tokio::spawn(async move {
        run(config).await;
    });
    tokio::time::sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/healthz", http_addr))
        .send()
        .await
        .expect("healthz request failed");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("healthz json");
    assert_eq!(
        body["handshake_mode"], "LEGACY_ONLY",
        "spawned config used the library default; body: {body}"
    );
    assert!(body["handshake_pinned_ok"].is_u64(), "body: {body}");
    assert!(body["handshake_fallback_total"].is_u64(), "body: {body}");
    assert!(body["handshake_reject_total"].is_u64(), "body: {body}");
}
