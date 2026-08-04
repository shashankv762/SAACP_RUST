//! hrt/remote.rs — bridging a *synchronous* [`HardwareKeyStore`] onto *asynchronous*
//! cloud KMS SDKs.
//!
//! [`crate::hrt::HardwareKeyStore::sign`] is synchronous by design: it mirrors what a
//! real HSM API looks like (hand the device a message, get a signature back), and the
//! overwhelming majority of this crate's signing call sites are plain sync functions
//! (`aca.rs`, `identity_binding.rs`, `faitf.rs`, `acsvaf.rs`). Both the AWS and GCP KMS
//! Rust SDKs, however, are async-only. This module owns the one correct way to cross
//! that boundary, so `aws_kms.rs` and `gcp_kms.rs` don't each re-derive it — and, more
//! importantly, don't each re-derive it *wrongly*.
//!
//! ## Why not `Runtime::block_on`
//!
//! The obvious implementation — own a private `tokio::runtime::Runtime` and call
//! `self.rt.block_on(fut)` — **panics** whenever the calling thread is already inside a
//! Tokio runtime:
//!
//! ```text
//! Cannot start a runtime from within a runtime. This happens because a function
//! (like `block_on`) attempted to block the current thread while the thread is being
//! used to drive asynchronous tasks.
//! ```
//!
//! This is worth stating precisely because the intuition is wrong: the panic is *not*
//! avoided by blocking on a **separate** runtime. Tokio's guard is a thread-local
//! marker for "this thread is currently driving tasks", not a per-runtime flag, so a
//! second, unrelated runtime panics exactly the same way. Verified empirically against
//! tokio 1.x, not inferred from the docs.
//!
//! That matters here because `daemon.rs`'s two handshake paths (`ecdh_handshake`,
//! `client_handshake`) are `async fn`. Signing a handshake transcript from a KMS-backed
//! store via `block_on` would panic and drop the connection — a self-inflicted denial
//! of service that would only appear once a real deployment pointed at a real KMS.
//!
//! ## What this module does instead
//!
//! [`RemoteSignerRuntime`] spawns the future **onto** its dedicated runtime's worker
//! threads and waits on a `std::sync::mpsc` channel. The calling thread blocks on a
//! plain channel receive — an operation with no Tokio thread-local involvement at all —
//! while the future is driven by a thread that *is* owned by the dedicated runtime.
//! This is correct from all three contexts that occur in this codebase:
//!
//! | Calling context                              | `block_on` | this module |
//! |----------------------------------------------|------------|-------------|
//! | plain sync (startup, a sync signing path)     | works      | works       |
//! | inside `async fn` (daemon handshakes)         | **panics** | works       |
//! | inside `spawn_blocking` (gate pipeline)       | works      | works       |
//!
//! One caveat, stated plainly: blocking a Tokio worker thread is still something to do
//! sparingly. It is sound here because the migrated call sites are all
//! credential-issuance paths (CA signing, capability issuance) — low-frequency control
//! plane operations, not the per-packet data plane. A KMS round-trip is milliseconds of
//! network latency; putting that on Gate 4.0's per-packet path would be the wrong design
//! regardless of how the runtime bridge is built.
//!
//! ## Timeouts
//!
//! Every call is wrapped in [`tokio::time::timeout`]. A KMS that never answers must not
//! wedge a signing call site forever — a hung `sign` inside a handshake would hold the
//! connection open and consume a slot until the peer gave up. [`HrtError::Timeout`] is
//! deliberately a distinct variant from [`HrtError::Backend`] because it is the one
//! failure a caller may sensibly retry.

use std::future::Future;
use std::sync::mpsc;
use std::time::Duration;

use tokio::runtime::{Builder, Runtime};

use super::HrtError;

/// Default per-call ceiling for a cloud KMS request. Generous relative to a healthy
/// KMS call (single-digit milliseconds in-region) so a transient latency spike is not
/// converted into a spurious signing failure, but far below any protocol-level timeout
/// so the failure surfaces here, with a precise message, rather than as an opaque
/// upstream stall.
pub const DEFAULT_REMOTE_TIMEOUT: Duration = Duration::from_secs(10);

/// A dedicated Tokio runtime that drives cloud-KMS futures on behalf of synchronous
/// callers. See the module doc for why this is not `Runtime::block_on`.
pub struct RemoteSignerRuntime {
    runtime: Runtime,
    timeout: Duration,
    backend: &'static str,
}

impl RemoteSignerRuntime {
    /// Build a runtime for `backend`, named for observability so a stuck KMS thread is
    /// identifiable in a stack dump or profiler rather than appearing as an anonymous
    /// `tokio-runtime-worker`.
    ///
    /// Two worker threads: enough that a slow call cannot fully starve a concurrent one,
    /// while keeping the footprint negligible for the IoT/low-resource deployments this
    /// crate's `Cargo.toml` explicitly targets. KMS signing is a control-plane
    /// operation, so this is not a throughput-sensitive pool.
    pub fn new(backend: &'static str, timeout: Duration) -> Result<Self, HrtError> {
        let runtime = Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name(format!("saacp-hrt-{backend}"))
            .enable_all()
            .build()
            .map_err(|e| {
                HrtError::Configuration(format!(
                    "could not start a dedicated Tokio runtime for the {backend} key store: {e}"
                ))
            })?;
        Ok(Self { runtime, timeout, backend })
    }

    /// The backend label this runtime reports in errors.
    pub fn backend(&self) -> &'static str {
        self.backend
    }

    /// Run `fut` to completion on the dedicated runtime and return its output.
    ///
    /// Safe to call from a synchronous function, from inside an `async fn`, and from
    /// inside `spawn_blocking` — see the table in the module doc.
    pub fn run<F, T>(&self, fut: F) -> Result<T, HrtError>
    where
        F: Future<Output = Result<T, HrtError>> + Send + 'static,
        T: Send + 'static,
    {
        let (tx, rx) = mpsc::channel();
        let timeout = self.timeout;
        let backend = self.backend;

        // `spawn` (not `block_on`): the future is driven by this runtime's OWN worker
        // threads, so the calling thread never enters a runtime context and the
        // "runtime within a runtime" panic cannot occur.
        self.runtime.spawn(async move {
            let outcome = match tokio::time::timeout(timeout, fut).await {
                Ok(result) => result,
                Err(_elapsed) => Err(HrtError::Timeout { backend }),
            };
            // A send failure means the receiver was dropped — only possible if the
            // caller was unwinding. Nothing to report to, so discard it.
            let _ = tx.send(outcome);
        });

        // A plain channel receive: no Tokio thread-local is consulted, so this blocks
        // correctly from any calling context.
        rx.recv().map_err(|_| HrtError::Backend {
            backend,
            detail: "the dedicated KMS runtime dropped the request without answering \
                     (the worker task panicked or the runtime was shut down)"
                .to_string(),
        })?
    }
}

impl std::fmt::Debug for RemoteSignerRuntime {
    // `tokio::runtime::Runtime` has no useful Debug output; report the operator-relevant
    // configuration instead so a `{:?}` on a keystore is informative.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteSignerRuntime")
            .field("backend", &self.backend)
            .field("timeout", &self.timeout)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The property the whole module exists for. If this ever regresses, every
    /// KMS-backed signature taken from a daemon handshake path panics.
    #[test]
    fn runs_from_inside_an_async_context_without_panicking() {
        let remote = RemoteSignerRuntime::new("test", DEFAULT_REMOTE_TIMEOUT).unwrap();

        // Sanity: works from a plain synchronous caller.
        assert_eq!(remote.run(async { Ok::<_, HrtError>(7u8) }).unwrap(), 7);

        // The case `Runtime::block_on` would panic on: an unrelated outer runtime is
        // already driving this thread, exactly like `daemon.rs::ecdh_handshake`.
        let outer = Builder::new_multi_thread().worker_threads(2).enable_all().build().unwrap();
        outer.block_on(async {
            assert_eq!(
                remote.run(async { Ok::<_, HrtError>(9u8) }).unwrap(),
                9,
                "signing from inside an async context must not panic — see module doc"
            );
        });

        // And from inside spawn_blocking, the gate-pipeline shape.
        outer.block_on(async {
            let out = tokio::task::spawn_blocking(move || {
                remote.run(async { Ok::<_, HrtError>(11u8) })
            })
            .await
            .unwrap();
            assert_eq!(out.unwrap(), 11);
        });
    }

    #[test]
    fn a_hanging_backend_times_out_instead_of_blocking_forever() {
        let remote = RemoteSignerRuntime::new("test", Duration::from_millis(50)).unwrap();
        let result: Result<u8, HrtError> = remote.run(async {
            // Never resolves — models a KMS endpoint that accepts the connection and
            // then goes silent.
            tokio::time::sleep(Duration::from_secs(3600)).await;
            Ok(0)
        });
        assert_eq!(result, Err(HrtError::Timeout { backend: "test" }));
    }

    #[test]
    fn a_backend_error_propagates_unchanged() {
        let remote = RemoteSignerRuntime::new("test", DEFAULT_REMOTE_TIMEOUT).unwrap();
        let result: Result<u8, HrtError> = remote.run(async {
            Err(HrtError::Backend { backend: "test", detail: "AccessDeniedException".to_string() })
        });
        assert!(matches!(result, Err(HrtError::Backend { detail, .. }) if detail.contains("AccessDenied")));
    }
}
