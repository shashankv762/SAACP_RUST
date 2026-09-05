//! `logging.rs` — structured logging initialization for SAACP binaries
//! (plan item 2c).
//!
//! # Usage
//!
//! ```ignore
//! // At the very top of `main()`, before any other code runs:
//! saacp::logging::init_logging(saacp::logging::LogConfig::default());
//! ```
//!
//! After that, hot-path code uses `tracing` macros directly:
//!
//! ```ignore
//! tracing::info!(session_id = %sid, gate = "gate_4_0", "packet accepted");
//! tracing::warn!(gate = "gate_3_0", bytecode = %drop.bytecode, "packet rejected");
//! ```
//!
//! # Properties
//!
//! - **Idempotent.** Calling [`init_logging`] more than once is a no-op
//!   (`tracing-subscriber` returns an `Err` on the second init, which we
//!   silently swallow — the first subscriber wins, which matches the
//!   "exactly one global subscriber" contract).
//! - **No allocation when no subscriber is installed.** `tracing::info!`
//!   et al. compile down to a no-op when no subscriber is registered, so
//!   the library can call them freely on the hot path without paying a
//!   cost in a deployment that does not call [`init_logging`].
//! - **Two output formats.** Human-readable pretty output (default) for
//!   local dev, JSON lines (set `SAACP_LOG_JSON=1` or pass
//!   [`LogConfig::json`]) for Loki/ELK/Splunk ingestion.
//! - **Env-filter driven.** The filter is `RUST_LOG`-style, e.g.
//!   `"saacp=info,saacp::handler=debug,warn"`. The default if neither
//!   `RUST_LOG` nor [`LogConfig::env_filter`] is set is `"saacp=info"`.

use std::env;

use tracing_subscriber::EnvFilter;

/// Logging configuration. Construct with [`LogConfig::default`] (reads
/// `SAACP_LOG` / `SAACP_LOG_JSON` from the environment) or build manually
/// in tests and embedded deployments.
#[derive(Debug, Clone)]
pub struct LogConfig {
    /// RUST_LOG-style filter (e.g. `"saacp=info,warn"`). `None` falls back
    /// to the `SAACP_LOG` environment variable, then to `"saacp=info"`.
    pub env_filter: Option<String>,
    /// `true` to emit JSON lines (for Loki/ELK/Splunk ingestion). `false`
    /// for human-readable pretty output. Defaults to the value of
    /// `SAACP_LOG_JSON` (set to any value to enable).
    pub json: bool,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            env_filter: env::var("SAACP_LOG").ok(),
            json: env::var("SAACP_LOG_JSON").is_ok(),
        }
    }
}

/// Initialize the global tracing subscriber. Idempotent — safe to call
/// from `main()` of every binary, and from tests that need structured
/// output. Returns silently if a subscriber is already installed.
pub fn init_logging(config: LogConfig) {
    let filter = config
        .env_filter
        .unwrap_or_else(|| "saacp=info".to_string());

    let env_filter = EnvFilter::try_new(&filter)
        .or_else(|_| EnvFilter::try_new("saacp=info"))
        .expect("fallback filter 'saacp=info' must parse");

    let result = if config.json {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_thread_ids(true)
            .with_line_number(true)
            .json()
            .try_init()
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .with_target(true)
            .with_line_number(true)
            .try_init()
    };

    // Idempotent: ignore "already initialized" errors silently. A first
    // caller's choice of subscriber wins — consistent with the standard
    // tracing-subscriber contract.
    if let Err(e) = result {
        // We can only surface this if tracing is initialized, so it
        // usually means an EARLIER init_logging call already succeeded.
        // Print to stderr as a one-time diagnostic for operators
        // debugging "why are my logs not showing up?".
        eprintln!("[saacp::logging] init_logging: subscriber install refused: {e}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_log_config_reads_from_env_or_uses_safe_defaults() {
        // Constructing `LogConfig::default()` must not panic even when the
        // env vars are unset (the test process may or may not have them).
        let _ = LogConfig::default();
    }

    #[test]
    fn init_logging_is_idempotent() {
        // Call init_logging twice; the second call must NOT panic. The
        // exact format of the first installed subscriber is not asserted —
        // we only require that the second call returns silently.
        init_logging(LogConfig {
            env_filter: Some("info".to_string()),
            json: false,
        });
        init_logging(LogConfig {
            env_filter: Some("info".to_string()),
            json: false,
        });
    }
}
