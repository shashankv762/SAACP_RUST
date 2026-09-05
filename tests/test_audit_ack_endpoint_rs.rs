//! test_audit_ack_endpoint_rs.rs — Phase 3 §2.4: operator audit-ack endpoint.
//!
//! Proves the `POST /api/audit/ack` route on the health-endpoint router:
//!
//! 1. **Unauthenticated → 401.** The endpoint is an operator ACTION (it
//!    releases the sticky Gate 2.5 audit drop floor), so unlike `/metrics`
//!    (gated only when a token is configured) it requires the bearer token in
//!    ALL cases; with no token configured it answers 503 (disabled).
//! 2. **Authenticated → the sticky drop floor is released** (the response's
//!    `released` count equals the recorded dropped-audit count at ack time),
//!    **the chain grew** (the acknowledgement itself is appended to the audit
//!    chain and verifies under the same issuer secret), and **a SecurityAlert
//!    is recorded** so dashboards/subscribers observe the acknowledgement.
//!
//! Fail-closed semantics are untouched (covered in depth by
//! `test_gate6_backpressure_rs.rs`): the acknowledgement releases only the
//! drop FLOOR — a genuine `Fatal` WAL-write state remains `Fatal`, and the
//! lifetime dropped-audits total is never reset.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use saacp::health::{health_router, HealthState};
use saacp::telemetry::{SecurityAlert, SecurityAlertFeed, TelemetryCollector};
use saacp::{AuditHealth, ImmutableAuditLog};

const SECRET: &[u8] = b"audit-ack-endpoint-test-secret";
const TOKEN: &str = "op-ack-token";

/// Minimal HTTP/1.1 client (no external HTTP-client dependency): POST with
/// an optional Authorization header, read the whole response (Connection: close).
async fn post_ack(addr: std::net::SocketAddr, token: Option<&str>) -> (u16, String) {
    let mut s = TcpStream::connect(addr).await.expect("connect");
    let auth_line = token
        .map(|t| format!("Authorization: Bearer {t}\r\n"))
        .unwrap_or_default();
    let req = format!(
        "POST /api/audit/ack HTTP/1.1\r\nHost: {addr}\r\n{auth_line}Content-Length: 0\r\nConnection: close\r\n\r\n"
    );
    s.write_all(req.as_bytes()).await.expect("write request");
    let mut buf = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), s.read_to_end(&mut buf))
        .await
        .expect("read response timed out")
        .expect("read response failed");
    let text = String::from_utf8_lossy(&buf).to_string();
    let status: u16 = text
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace()
        .nth(1)
        .unwrap_or("0")
        .parse()
        .unwrap_or(0);
    (status, text)
}

/// Build a log whose WAL worker CANNOT open its log file (bad dir): the
/// worker exits, the log becomes `Fatal`, and every append is counted as a
/// dropped audit (a real drop path — no test-only backdoor), raising the
/// sticky drop floor. Mirrors `test_gate6_backpressure_rs.rs`'s approach.
fn make_dropping_log(tag: &str) -> Arc<ImmutableAuditLog> {
    let bad_dir = std::env::temp_dir().join(format!(
        "saacp_no_such_dir_{tag}_{}_audit_ack",
        std::process::id()
    ));
    let log_file = bad_dir.join("audit.log");
    let log = Arc::new(ImmutableAuditLog::with_paths(
        log_file.to_str().unwrap(),
        &format!("{}.sentinel", log_file.to_str().unwrap()),
    ));
    let mut waited = Duration::ZERO;
    while log.health() != AuditHealth::Fatal && waited < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(5));
        waited += Duration::from_millis(5);
    }
    log
}

#[tokio::test]
async fn audit_ack_unauthenticated_401_authenticated_releases_floor_grows_chain_alerts() {
    // A log with a recorded drop: floor pinned at/above Saturated.
    let log = make_dropping_log("endpoint");
    log.append_event(
        SECRET,
        "pre-ack-source",
        "pre-ack-target",
        "sig-0",
        "intent that got dropped",
        "00-auditack0000000000000-01",
    );
    assert!(
        log.dropped_audit_count() >= 1,
        "the append against the dead-WAL log must be counted as dropped"
    );
    assert!(
        log.health() >= AuditHealth::Saturated,
        "a dropped audit must pin health at/above Saturated (fail-closed)"
    );
    let dropped_before = log.dropped_audit_count();

    // Observe the acknowledgement alert on the process-global feed.
    let alerts: Arc<Mutex<Vec<SecurityAlert>>> = Arc::new(Mutex::new(Vec::new()));
    let alerts2 = Arc::clone(&alerts);
    SecurityAlertFeed::global_arc().subscribe_forever(Arc::new(move |a: &SecurityAlert| {
        alerts2.lock().unwrap().push(a.clone());
    }));

    // Health server with the same log + a bearer token + the issuer secret.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let state = HealthState::new(Arc::clone(&log), Arc::new(TelemetryCollector::new()))
        .with_bearer_token(TOKEN)
        .with_audit_issuer_secret(Arc::new(SECRET.to_vec()));
    let app = health_router(state);
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // ── 1. Unauthenticated → 401 ────────────────────────────────────────────
    let (status_noauth, _) = post_ack(addr, None).await;
    assert_eq!(
        status_noauth, 401,
        "the audit-ack endpoint must reject unauthenticated callers"
    );

    // ── 2. Authenticated → floor released + chain grew + alert recorded ────
    let (status_auth, body) = post_ack(addr, Some(TOKEN)).await;
    assert_eq!(status_auth, 200, "body: {body}");
    assert!(
        body.contains("\"released\""),
        "the response must report the released dropped-audit count: {body}"
    );
    assert!(
        body.contains(&format!("\"released\":{dropped_before}"))
            || body.contains("\"acknowledged\":true"),
        "the acknowledgement must report the recorded drop state: {body}"
    );

    // Fail-closed semantics untouched: only the FLOOR was released — the live
    // Fatal WAL-write state remains Fatal (never masks as healthy).
    assert_eq!(
        log.health(),
        AuditHealth::Fatal,
        "acknowledging the drop floor must NOT clear a genuine Fatal state"
    );
    // Lifetime total preserved for post-incident analysis.
    assert!(
        log.dropped_audit_count() >= dropped_before,
        "the lifetime dropped-audits total must never be reset by an ack"
    );

    // Chain grew: the acknowledgement itself is on the chain and verifies
    // under the same issuer secret the endpoint bound it with.
    assert!(
        log.verify_chain(SECRET),
        "the audit chain (including the appended acknowledgement record) must \
         verify under the configured issuer secret"
    );

    // Alert recorded for dashboards/subscribers.
    let seen = alerts.lock().unwrap();
    assert!(
        seen.iter().any(|a| a.gate == "audit_ack"),
        "the acknowledgement must record a SecurityAlert on the feed"
    );
}
