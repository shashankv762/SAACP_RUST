//! otlp.rs — OTLP/HTTP JSON Log Exporter (Phase 4.2)
//!
//! Ships `AuditEvent` records to any OpenTelemetry-compatible collector
//! (Grafana Loki, Jaeger, Tempo, Honeycomb, etc.) over the OTLP/HTTP JSON
//! endpoint (`/v1/logs`). This exporter is:
//!
//! - **Zero-tonic**: uses plain `reqwest` HTTP — no gRPC/protobuf compile cost.
//! - **Zero-allocation hot path**: events are buffered in a `Vec` and flushed
//!   in a single HTTP request per batch.
//! - **Wasm/edge safe**: the `otlp-export` feature flag is off by default;
//!   the gate pipeline never references this module.
//! - **Fail-safe**: a failed flush emits `tracing::warn!` but never panics
//!   and never blocks the gate pipeline.
//!
//! # Wire format
//!
//! Follows the [OTLP/HTTP JSON spec](https://opentelemetry.io/docs/specs/otlp/#json-encoding)
//! for `ExportLogsServiceRequest`. Only the fields required for Grafana Loki /
//! standard OTEL backends are populated — no vendor-specific extensions.
//!
//! # Usage
//!
//! ```rust,ignore
//! let exporter = OtlpHttpExporter::new("http://localhost:4318");
//! let sink = OtlpLogSink::new(exporter, "saacp-gateway");
//! // Wire into ImmutableAuditLog via AuditEventSink trait.
//! ```

#![cfg(feature = "otlp-export")]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;

use crate::security_mutex::inc_poison_recovery_count;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum events to buffer before an automatic flush.
const OTLP_BATCH_MAX: usize = 512;

/// HTTP request timeout for each OTLP flush call.
const OTLP_FLUSH_TIMEOUT_SECS: u64 = 5;

/// OTLP/HTTP JSON logs endpoint path.
const OTLP_LOGS_PATH: &str = "/v1/logs";

// ---------------------------------------------------------------------------
// Wire types (OTLP/HTTP JSON schema, trimmed to used fields)
// ---------------------------------------------------------------------------

/// Top-level OTLP ExportLogsServiceRequest.
#[derive(Serialize)]
struct ExportLogsServiceRequest<'a> {
    #[serde(rename = "resourceLogs")]
    resource_logs: Vec<ResourceLogs<'a>>,
}

#[derive(Serialize)]
struct ResourceLogs<'a> {
    resource: Resource<'a>,
    #[serde(rename = "scopeLogs")]
    scope_logs: Vec<ScopeLogs<'a>>,
}

#[derive(Serialize)]
struct Resource<'a> {
    attributes: Vec<KeyValue<'a>>,
}

#[derive(Serialize)]
struct ScopeLogs<'a> {
    scope: InstrumentationScope<'a>,
    #[serde(rename = "logRecords")]
    log_records: Vec<LogRecord<'a>>,
}

#[derive(Serialize)]
struct InstrumentationScope<'a> {
    name: &'a str,
    version: &'a str,
}

/// A single OTLP log record.
#[derive(Serialize)]
struct LogRecord<'a> {
    /// Unix epoch nanoseconds.
    #[serde(rename = "timeUnixNano")]
    time_unix_nano: String,
    #[serde(rename = "severityNumber")]
    severity_number: u32,
    #[serde(rename = "severityText")]
    severity_text: &'a str,
    body: AnyValue<'a>,
    attributes: Vec<KeyValue<'a>>,
    #[serde(rename = "traceId")]
    trace_id: &'a str,
    #[serde(rename = "spanId")]
    span_id: &'a str,
}

#[derive(Serialize)]
struct AnyValue<'a> {
    #[serde(rename = "stringValue")]
    string_value: &'a str,
}

#[derive(Serialize)]
struct KeyValue<'a> {
    key: &'a str,
    value: AnyValue<'a>,
}

use crate::security::AuditEventSink;

// ---------------------------------------------------------------------------
// OtlpHttpExporter (reqwest-backed, feature-gated)
// ---------------------------------------------------------------------------

/// Low-level OTLP/HTTP client — batches raw JSON event strings and ships
/// them to a collector endpoint in a single POST per flush.
///
/// Thread-safe: wraps the buffer in a `Mutex` (poison-recovery via M-38).
pub struct OtlpHttpExporter {
    /// Base URL of the OTLP collector, e.g. `"http://localhost:4318"`.
    endpoint: String,
    /// Buffered event JSON strings awaiting the next flush.
    buffer: Mutex<Vec<String>>,
    /// Service name reported in the OTLP `resource.attributes`.
    service_name: String,
    /// Blocking reqwest client (kept as `Arc` for cheap clone into flush tasks).
    client: Arc<reqwest::blocking::Client>,
}

impl OtlpHttpExporter {
    /// Create a new exporter targeting `endpoint` (no trailing slash).
    ///
    /// # Panics
    /// Never panics — `reqwest::blocking::Client::new()` only fails on
    /// thread-creation failure, which is treated as an environment bug.
    pub fn new(endpoint: impl Into<String>, service_name: impl Into<String>) -> Self {
        let client = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(OTLP_FLUSH_TIMEOUT_SECS))
            .build()
            .unwrap_or_else(|_| reqwest::blocking::Client::new());

        Self {
            endpoint: endpoint.into(),
            service_name: service_name.into(),
            buffer: Mutex::new(Vec::with_capacity(OTLP_BATCH_MAX)),
            client: Arc::new(client),
        }
    }

    /// Buffer one event JSON string. Triggers an automatic flush when the
    /// buffer exceeds `OTLP_BATCH_MAX`.
    pub fn buffer_event(&self, event_json: String) {
        let mut buf = match self.buffer.lock() {
            Ok(g) => g,
            Err(p) => {
                inc_poison_recovery_count();
                tracing::error!(
                    mutex_name = "otlp_exporter_buffer",
                    "SECURITY GATE STATE CORRUPTION: OtlpHttpExporter buffer poison recovered."
                );
                p.into_inner()
            }
        };
        buf.push(event_json);
        if buf.len() >= OTLP_BATCH_MAX {
            let batch = std::mem::take(&mut *buf);
            drop(buf); // release lock before HTTP call
            // Never perform blocking collector I/O on the audit/gate caller.
            // The WAL remains authoritative if the detached best-effort export
            // cannot complete.
            let exporter = self.clone_handle();
            let _ = std::thread::Builder::new()
                .name("saacp-otlp-flush".to_owned())
                .spawn(move || exporter.send_batch(batch));
        }
    }

    /// Flush all buffered events immediately.
    pub fn flush_now(&self) {
        let batch = {
            let mut buf = match self.buffer.lock() {
                Ok(g) => g,
                Err(p) => {
                    inc_poison_recovery_count();
                    tracing::error!(
                        mutex_name = "otlp_exporter_buffer",
                        "OtlpHttpExporter buffer poison recovered during flush."
                    );
                    p.into_inner()
                }
            };
            std::mem::take(&mut *buf)
        };
        if !batch.is_empty() {
            self.send_batch(batch);
        }
    }

    fn clone_handle(&self) -> OtlpHttpExporterHandle {
        OtlpHttpExporterHandle {
            endpoint: self.endpoint.clone(),
            service_name: self.service_name.clone(),
            client: Arc::clone(&self.client),
        }
    }

    /// Build and POST an OTLP ExportLogsServiceRequest for `batch`.
    ///
    /// Failures are logged at `warn` level but never propagate — the audit
    /// WAL is the source of truth; OTLP export is best-effort telemetry.
    fn send_batch(&self, batch: Vec<String>) {
        Self::send_batch_parts(&self.endpoint, &self.service_name, &self.client, batch);
    }

    fn send_batch_parts(
        endpoint: &str,
        service_name: &str,
        client: &reqwest::blocking::Client,
        batch: Vec<String>,
    ) {
        // wall_clock_now() returns epoch seconds as f64; convert to nanoseconds.
        let now_ns = {
            let secs = crate::clock::wall_clock_now();
            let nanos = (secs * 1_000_000_000.0) as u128;
            nanos.to_string()
        };

        // Build log records from raw JSON event strings.
        let records: Vec<LogRecord<'_>> = batch
            .iter()
            .map(|json| LogRecord {
                time_unix_nano: now_ns.clone(),
                severity_number: 9, // INFO
                severity_text: "INFO",
                body: AnyValue { string_value: json.as_str() },
                attributes: vec![KeyValue {
                    key: "saacp.event",
                    value: AnyValue { string_value: "audit" },
                }],
                trace_id: "",
                span_id: "",
            })
            .collect();

        let payload = ExportLogsServiceRequest {
            resource_logs: vec![ResourceLogs {
                resource: Resource {
                    attributes: vec![KeyValue {
                        key: "service.name",
                         value: AnyValue { string_value: service_name },
                    }],
                },
                scope_logs: vec![ScopeLogs {
                    scope: InstrumentationScope {
                        name: "saacp",
                        version: env!("CARGO_PKG_VERSION"),
                    },
                    log_records: records,
                }],
            }],
        };

        let url = format!("{}{}", endpoint, OTLP_LOGS_PATH);
        match client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
        {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!(
                    records = batch.len(),
                    "OTLP flush: {} records exported to {}",
                    batch.len(),
                    url
                );
            }
            Ok(resp) => {
                tracing::warn!(
                    status = %resp.status(),
                    url = %url,
                    records = batch.len(),
                    "OTLP flush: collector returned non-2xx status; events dropped"
                );
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    url = %url,
                    records = batch.len(),
                    "OTLP flush: HTTP request failed; events dropped"
                );
            }
        }
    }
}

struct OtlpHttpExporterHandle {
    endpoint: String,
    service_name: String,
    client: Arc<reqwest::blocking::Client>,
}

impl OtlpHttpExporterHandle {
    fn send_batch(&self, batch: Vec<String>) {
        OtlpHttpExporter::send_batch_parts(&self.endpoint, &self.service_name, &self.client, batch);
    }
}

// ---------------------------------------------------------------------------
// StdoutJsonSink — always-available JSONL sink (no feature flag needed)
// ---------------------------------------------------------------------------

/// `AuditEventSink` that writes newline-delimited JSON to stdout.
///
/// Zero-dependency, always-available output for `kubectl logs`, Fluentd,
/// Vector, and any log aggregator that reads container stdout.
pub struct StdoutJsonSink;

impl AuditEventSink for StdoutJsonSink {
    fn on_event(&self, event_json: &str) {
        println!("{}", event_json);
    }

    fn flush(&self) {
        // stdout is unbuffered on most platforms; no-op here.
    }
}




// ---------------------------------------------------------------------------
// OtlpLogSink — AuditEventSink adapter over OtlpHttpExporter
// ---------------------------------------------------------------------------

/// `AuditEventSink` implementation that forwards events to an
/// [`OtlpHttpExporter`]. Wire this into `ImmutableAuditLog` alongside
/// `StdoutJsonSink` for dual-sink output.
pub struct OtlpLogSink {
    exporter: Arc<OtlpHttpExporter>,
}

impl OtlpLogSink {
    pub fn new(exporter: OtlpHttpExporter) -> Self {
        Self { exporter: Arc::new(exporter) }
    }
}

impl AuditEventSink for OtlpLogSink {
    fn on_event(&self, event_json: &str) {
        self.exporter.buffer_event(event_json.to_owned());
    }

    fn flush(&self) {
        self.exporter.flush_now();
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stdout_sink_does_not_panic() {
        let sink = StdoutJsonSink;
        sink.on_event(r#"{"type":"test"}"#);
        sink.flush();
    }

    #[test]
    fn otlp_exporter_buffers_events() {
        let exp = OtlpHttpExporter::new("http://127.0.0.1:19999", "test-service");
        exp.buffer_event(r#"{"type":"test"}"#.to_owned());
        // Buffer should now have 1 event (no auto-flush since < OTLP_BATCH_MAX)
        let buf = exp.buffer.lock().unwrap_or_else(|e| e.into_inner());
        assert_eq!(buf.len(), 1);
    }

    #[test]
    fn otlp_log_sink_forwards_to_exporter() {
        let exp = OtlpHttpExporter::new("http://127.0.0.1:19999", "test-service");
        let sink = OtlpLogSink::new(exp);
        sink.on_event(r#"{"type":"forward_test"}"#);
        // Flush hits a non-existent server — should log warn, not panic.
        sink.flush();
    }
}
