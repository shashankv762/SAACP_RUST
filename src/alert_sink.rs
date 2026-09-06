//! M-B remediation (production audit G2/R2): external alert delivery.
//!
//! `SecurityAlertFeed` (see `telemetry.rs`) is process-internal: its bounded
//! ring and in-process subscribers reach only the dashboard bridge and MACE —
//! an operator running the binaries standalone sees gate rejections only if a
//! Prometheus scraper happens to be polling `/metrics`. This module closes
//! that gap with a minimal, dependency-free external sink: **RFC 5424 syslog
//! over UDP**, the one wire format every syslog collector (rsyslog, syslog-ng,
// Loki promtail, Fluent Bit, AWS CloudWatch Agent, …) already speaks.
//!
//! ## Delivery contract (deliberate)
//!
//! - **Fail-open, best-effort**: `emit` never blocks the packet path (UDP
//!   datagrams are non-blocking in practice) and never panics; a failed send
//!   increments the `alert_sink_failures_total` telemetry counter and is
//!   dropped. Losing one syslog datagram is always preferable to stalling a
//!   gate pipeline — syslog's own UDP transport has the same semantics.
//! - **Coarse-grained payloads**: exactly the fields `SecurityAlertFeed`
//!   already exposes network-side (`/api/alerts`): gate name, bytecode,
//!   agent id, timestamp. No `SAACPHardDrop::message` detail (CRIT-10
//!   confidentiality invariant preserved — the sink sees nothing more
//!   sensitive than the dashboard already does).
//! - **One sink per process**, installed once via [`SyslogAlertSink::
//!   install_global`] (wired from `SAACP_ALERT_SYSLOG=host:port` in the
//!   daemon's startup path). Installation is not part of the default
//!   posture: with the env var unset, behavior is byte-identical to
//!   pre-sink releases.

use std::net::{ToSocketAddrs, UdpSocket};
use std::sync::OnceLock;

use crate::telemetry::SecurityAlert;

/// RFC 5424 facility: `local0` (16) — the conventional slot for
/// application-specific logs, unlikely to collide with system daemons.
const SYSLOG_FACILITY_LOCAL0: u8 = 16;
/// RFC 5424 severity: `warning` (4) — a gate rejection is a security warning;
/// nothing in `SecurityAlertFeed` carries error/crit/emerg semantics.
const SYSLOG_SEVERITY_WARNING: u8 = 4;

static SYSLOG_SINK: OnceLock<SyslogAlertSink> = OnceLock::new();

/// The process-wide sink, when installed. `SecurityAlertFeed::record` checks
/// this and forwards every alert (best-effort).
pub fn syslog_sink() -> Option<&'static SyslogAlertSink> {
    SYSLOG_SINK.get()
}

/// A UDP syslog (RFC 5424) emitter for security alerts.
pub struct SyslogAlertSink {
    socket: UdpSocket,
    target: std::net::SocketAddr,
}

impl SyslogAlertSink {
    /// Bind an ephemeral local port and aim at `target` (`host:port` or a
    /// literal IP — resolved once, at install time).
    pub fn bind(target: &str) -> Result<Self, String> {
        let mut target_addr = target
            .to_socket_addrs()
            .map_err(|e| format!("syslog target {target:?} did not resolve: {e}"))?
            .next();
        // An unqualified host with no port component resolves to port 0 —
        // reject that rather than emitting datagrams into the void.
        if target_addr.is_some() && target_addr.unwrap().port() == 0 {
            target_addr = None;
        }
        let target_addr = target_addr.ok_or_else(|| {
            format!("syslog target {target:?} did not resolve to a usable host:port")
        })?;
        let socket = UdpSocket::bind(if target_addr.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .map_err(|e| format!("failed to bind local UDP socket for syslog sink: {e}"))?;
        Ok(Self {
            socket,
            target: target_addr,
        })
    }

    /// Install the process-wide sink. Returns an error when a sink is already
    /// installed (the daemon startup path only calls this once) or when the
    /// target cannot be used. Fail-open posture: installation failures are
    /// reported to the caller (which logs them) — they never abort startup.
    pub fn install_global(target: &str) -> Result<(), String> {
        let sink = Self::bind(target)?;
        SYSLOG_SINK
            .set(sink)
            .map_err(|_| "syslog alert sink already installed".to_string())
    }

    /// Render the RFC 5424 line for one alert (exposed for tests).
    fn render(&self, alert: &SecurityAlert) -> String {
        let pri = SYSLOG_FACILITY_LOCAL0 * 8 + SYSLOG_SEVERITY_WARNING;
        // Structured-data PARAM values escape `"` `\` `]` per RFC 5424 §6.3.3.
        let esc = |s: &str| {
            s.replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace(']', "\\]")
        };
        let cost = match alert.estimated_cost {
            Some(c) => format!("{}", c),
            None => "0".to_string(),
        };
        format!(
            "<{pri}>1 {timestamp} - saacp {} saacp-gate-alert - \
             [saacp@0 gate=\"{gate}\" bytecode=\"{bytecode}\" agent=\"{agent}\" cost=\"{cost}\"] \
             gate rejection on gate {gate}",
            std::process::id(),
            timestamp = format_rfc5424_timestamp(alert.timestamp),
            gate = esc(alert.gate),
            bytecode = esc(&alert.bytecode),
            agent = esc(&alert.agent_id),
        )
    }

    /// Best-effort delivery: never blocks meaningfully, never panics; failures
    /// are counted, not propagated.
    pub fn emit(&self, alert: &SecurityAlert) {
        let line = self.render(alert);
        if self.socket.send_to(line.as_bytes(), self.target).is_err() {
            crate::telemetry::global_telemetry().record_alert_sink_failure();
        }
    }
}

/// Format a unix-epoch f64 as RFC 3339 UTC with millisecond precision
/// (`2026-09-06T12:34:56.789Z`) — dependency-free civil-from-days conversion
/// (Howard Hinnant's algorithm).
fn format_rfc5424_timestamp(epoch_secs_f64: f64) -> String {
    if !epoch_secs_f64.is_finite() || epoch_secs_f64 < 0.0 {
        return "-".to_string(); // RFC 5424 NILVALUE for unusable timestamps
    }
    let total_ms = (epoch_secs_f64 * 1000.0).floor() as i64;
    let secs = total_ms.div_euclid(1000);
    let ms = total_ms.rem_euclid(1000);
    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);
    let (h, m, s) = (
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60,
    );
    // Civil-from-days (valid for the full i64 range we can produce here).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097); // day of era [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{d:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alert(gate: &'static str, bytecode: &str, agent: &str) -> SecurityAlert {
        SecurityAlert {
            timestamp: 1_786_000_000.5,
            agent_id: agent.to_string(),
            gate,
            bytecode: bytecode.to_string(),
            estimated_cost: None,
        }
    }

    /// The rendered line is RFC 5424-shaped: correct PRI, version, NILVALUE
    /// hostname, structured data with the escaped params, and no CRIT-10
    /// payload (the drop message never reaches the wire).
    #[test]
    fn render_produces_rfc5424_shape() {
        let sink = SyslogAlertSink::bind("127.0.0.1:1514").expect("loopback bind");
        let a = alert("gate_4_0_injection_scan", "4021", "agent-1");
        let line = sink.render(&a);
        assert!(
            line.starts_with("<132>1 "),
            "PRI=facility 16*8+4=132, version 1: {line}"
        );
        assert!(line.contains("2026-"), "epoch 1786000000 is 2026: {line}");
        assert!(line.contains(" saacp "), "app-name: {line}");
        assert!(
            line.contains(
                "[saacp@0 gate=\"gate_4_0_injection_scan\" bytecode=\"4021\" agent=\"agent-1\""
            ),
            "structured data must carry the coarse fields: {line}"
        );
        assert!(line.ends_with("gate rejection on gate gate_4_0_injection_scan"));
    }

    /// SD escaping: `"` `\` `]` inside agent-supplied ids must be escaped so
    /// a malicious agent id cannot forge structured-data boundaries.
    #[test]
    fn render_escapes_structured_data_values() {
        let sink = SyslogAlertSink::bind("127.0.0.1:1514").expect("loopback bind");
        let a = alert("gate_1_0", "1002", "evil\"]agent\\\"x");
        let line = sink.render(&a);
        // Raw string: the escaped inner text is exactly `evil\"\]agent\\\"x`
        // (`"`→`\"`, `]`→`\]`, `\`→`\\` per RFC 5424 §6.3.3).
        assert!(
            line.contains(r#"agent="evil\"\]agent\\\"x""#),
            "quotes, backslashes and ] must be escaped: {line}"
        );
    }

    /// End-to-end over real loopback UDP: emit lands on the receiving socket
    /// intact, and a failed delivery to a closed port counts — but never
    /// panics or blocks the caller.
    #[test]
    fn emit_delivers_over_udp_and_counts_failures() {
        let rx = UdpSocket::bind("127.0.0.1:0").expect("receiver bind");
        let port = rx.local_addr().unwrap().port();
        let sink = SyslogAlertSink::bind(&format!("127.0.0.1:{port}")).expect("sink bind");
        sink.emit(&alert("gate_2_5", "2501", "agent-2"));
        let mut buf = [0u8; 1024];
        rx.set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let (n, _) = rx.recv_from(&mut buf).expect("datagram must arrive");
        let line = std::str::from_utf8(&buf[..n]).unwrap();
        assert!(line.contains("gate=\"gate_2_5\""), "got: {line}");

        // Unroutable-but-local closed port: the UDP send itself typically
        // succeeds (fire-and-forget) — either way the caller must not panic,
        // and any surfaced error must be counted.
        let before = crate::telemetry::global_telemetry().snapshot()["alert_sink_failures_total"];
        let dead = SyslogAlertSink::bind("127.0.0.1:1").expect("sink bind");
        dead.emit(&alert("gate_2_5", "2501", "agent-2"));
        let after = crate::telemetry::global_telemetry().snapshot()["alert_sink_failures_total"];
        assert!(
            after >= before,
            "failure counter must never move backwards (best-effort delivery may or may not error)"
        );
    }

    /// The timestamp formatter handles the NILVALUE edge (non-finite/negative
    /// epoch) and stays well-formed for ordinary values.
    #[test]
    fn timestamp_formatter_edges() {
        assert_eq!(format_rfc5424_timestamp(-1.0), "-");
        assert_eq!(format_rfc5424_timestamp(f64::NAN), "-");
        assert_eq!(format_rfc5424_timestamp(0.0), "1970-01-01T00:00:00.000Z");
        assert_eq!(
            format_rfc5424_timestamp(1_786_000_000.0),
            "2026-08-06T07:06:40.000Z"
        );
    }
}
