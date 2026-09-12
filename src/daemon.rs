//! daemon.rs — SAACPNetworkDaemon
//!
//! Full feature-parity with Python SAACP daemon.py (329 lines).
//! Async TCP server using Tokio. One task spawned per accepted connection.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::time::timeout;

use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroizing;

use crate::errors::{SAACPBytecodes, SAACPHardDrop};
use crate::handler::{JsonValue, ParsedPacket, SAACPProtocolHandler};
use crate::measc::SessionEpochManager;
use crate::pecf::{generate_correlation_id, internal_to_external_raw, SREL};
use crate::response_auth::{compute_response_mac, RESPONSE_MAC_LEN};

// ─── Constants ───────────────────────────────────────────────────────────────

/// Maximum seconds to assemble a full MTU-chunked packet (VULN-02).
pub const MAX_ASSEMBLY_TIME: f64 = 30.0;

/// Maximum seconds to complete the ECDH handshake before DDoS-dropping.
///
/// F12 fix: was 0.1s — genuinely tight for high-latency links (a single
/// intercontinental RTT can exceed 150ms; satellite links 600ms+), rejecting
/// legitimate clients. 2.0s matches the per-packet header timeout and still
/// bounds a slow-loris connection attempt tightly (the connection semaphore,
/// per-IP caps, circuit breaker, and 64KB buffer cap do the resource bounding
/// — this timeout is one layer, not the only one). Per-deployment override:
/// [`SAACPNetworkDaemon::with_handshake_timeout`].
pub const HANDSHAKE_TIMEOUT_SECS: f64 = 2.0;

/// Maximum seconds to complete a C-3 identity-bound ECDH handshake (`with_identity_binding`)
/// before DDoS-dropping. Larger than `HANDSHAKE_TIMEOUT_SECS` because this mode does
/// genuinely more work on the same wire round-trip — reading a variable-length certificate,
/// an Ed25519 CA-signature verification, and an Ed25519 proof-of-possession verification,
/// versus the plain mode's single fixed-size read. Still tight enough to bound the
/// resource cost of a slow-loris connection attempt to a small multiple of the plain mode.
pub const IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS: f64 = 3.0;

/// Maximum distinct IP addresses tracked by the circuit breaker.
pub const MAX_CIRCUIT_BREAKER_IPS: usize = 10_000;

/// CRIT-9 fix: maximum concurrent connections accepted across the whole listener.
/// Without this, `tokio::spawn` is called for every accepted connection with no bound,
/// and each connection can be forced (via a crafted header claiming a large payload) to
/// hold up to `MAX_PAYLOAD_SIZE` (10MB) — ~1,000 slow-feed connections exhausts 10GB.
pub const MAX_CONNECTIONS: usize = 10_000;

/// CRIT-9 fix: maximum concurrent connections accepted from a single source IP.
/// Bounds a single attacker from consuming the entire `MAX_CONNECTIONS` budget alone.
pub const MAX_CONNECTIONS_PER_IP: usize = 100;

/// M-15/R-2 fix: how long graceful shutdown waits for in-flight connections to finish
/// their current packet/loop iteration naturally before hard-aborting them.
/// `handle_client`'s per-connection loop is persistent (exits only on EOF, a 2s header
/// read timeout, or a fatal bytecode) — an unbounded drain could otherwise hang the
/// whole shutdown on a single idle-but-still-open client.
pub const SHUTDOWN_DRAIN_TIMEOUT_SECS: u64 = 30;

/// Number of consecutive errors before an IP is locked out.
const CIRCUIT_BREAKER_ERROR_THRESHOLD: u32 = 5;

/// Base lockout duration in seconds after threshold breached — this exact value is what a
/// fresh IP's first-ever lockout still gets; see `CIRCUIT_BREAKER_MAX_LOCKOUT_SECS` for the
/// L-20 escalation applied to repeat offenders.
const CIRCUIT_BREAKER_LOCKOUT_SECS: f64 = 30.0;

/// L-20 fix, opusplan.md 6.6: ceiling on the exponentially-escalating lockout duration
/// (`CircuitBreakerEntry::record_error`) — grows with `consecutive_lockouts` so a
/// persistent attacker can't just wait out the same flat 30s window forever, but is still
/// capped so it never becomes a de facto permanent ban stemming from a transient issue far
/// in the past. 4 hours.
const CIRCUIT_BREAKER_MAX_LOCKOUT_SECS: f64 = 14400.0;

/// L-20 fix: how long a `CircuitBreakerEntry` must go completely error-free before its
/// `consecutive_lockouts` escalation counter resets to 0 — genuine passive recovery, not
/// merely surviving out its own most recent lockout window (which is much shorter). Chosen
/// as a multiple of the base lockout so "quiet long enough to be trusted again" is clearly
/// distinguishable from "just reconnected right after the lockout expired".
const CIRCUIT_BREAKER_RECOVERY_PERIOD_SECS: f64 = 300.0;

/// Token re-validation interval for pinned connections (VULN-04).
const TOKEN_REVALIDATION_INTERVAL_SECS: f64 = 30.0;

/// Maximum payload size (10 MB).
pub(crate) const MAX_PAYLOAD_SIZE: usize = 10_000_000;

/// opusplan.md 6.6 ("Per-connection memory": ~16KB steady-state target). `payload_buf`'s
/// P-6 reuse (below) never *shrinks* on its own — `.clear()` + `.resize()` only grows the
/// backing allocation when a later packet needs more room than any prior one on the same
/// connection. Without a ceiling, a single legitimately large packet (up to
/// `MAX_PAYLOAD_SIZE`, 10MB) permanently pins that allocation for the connection's entire
/// remaining lifetime, even if every subsequent packet is tiny — across `MAX_CONNECTIONS`
/// that is a real memory-amplification vector, not just a missed micro-optimization.
/// Chosen with headroom above the spec's literal 16KB (most legitimate payloads comfortably
/// M4 (R2 / opusreview.md): global in-flight payload byte budget. When a daemon
/// enables the budget (`with_inflight_payload_budget`), every packet's
/// `payload_length` reserves this many permits-worth of bytes from a shared
/// `Semaphore` before its buffer is assembled, bounding AGGREGATE in-flight
/// payload memory across all connections; an exhausted budget rejects the packet
/// with `PayloadTooLarge` (fail closed). 2 GiB is the documented default ceiling.
pub const MAX_INFLIGHT_PAYLOAD_BYTES: usize = 2 * 1024 * 1024 * 1024;

/// P-6 fix: steady-state per-connection payload buffer ceiling (sized so typical
/// fit under 64KB) so ordinary size variation within normal traffic never triggers a
/// reallocation — only a genuine outlier does.
pub const CONNECTION_BUFFER_STEADY_STATE_CAP: usize = 65_536;

/// MEASC header size in bytes.
const HEADER_SIZE: usize = 128;

/// Wire response strings (must match Python daemon.py exactly).
const WIRE_SUCCESS: &[u8] = b"SUCCESS";
const WIRE_STREAM_ACK: &[u8] = b"STREAM_ACK";
const WIRE_STREAM_END_ACK: &[u8] = b"STREAM_END_ACK";
const WIRE_YIELD_ASYNC: &[u8] = b"YIELD_ASYNC";

// ─── CircuitBreakerEntry ─────────────────────────────────────────────────────

/// R-5 / L-12 fix: `pub` (not `pub(crate)`) so [`SharedCircuitBreakers`] below can be a
/// fully public type alias. Only the struct's *nameability* changes here — `record_error`/
/// `is_locked` stay module-private, so this is not a new capability for external callers,
/// just lets them hold and pass an opaque handle (exactly as `transport/ws.rs` already
/// does today by importing this type).
#[derive(Debug, Clone)]
pub struct CircuitBreakerEntry {
    error_count: u32,
    lockout_until: Option<Instant>,
    /// M-16 fix: last time this entry was touched by `record_error`. Lets
    /// `record_error`'s eviction step sort candidates oldest-first instead of
    /// relying on `HashMap`'s arbitrary iteration order.
    last_activity: Instant,
    /// L-20 fix: number of times this entry has entered a NEW lockout (i.e.
    /// transitioned from not-locked to locked), used to exponentially escalate the
    /// lockout duration for repeat offenders. Reset to 0 after a full
    /// `CIRCUIT_BREAKER_RECOVERY_PERIOD_SECS` with zero errors — see `record_error`.
    consecutive_lockouts: u32,
}

impl CircuitBreakerEntry {
    fn new() -> Self {
        Self {
            error_count: 0,
            lockout_until: None,
            last_activity: Instant::now(),
            consecutive_lockouts: 0,
        }
    }

    fn is_locked(&self) -> bool {
        self.lockout_until.is_some_and(|t| Instant::now() < t)
    }

    /// M-16: does this entry's lockout (if any) currently protect anything?
    /// An entry with no lockout, or an expired one, has zero remaining
    /// protective value and is always safe to evict ahead of one still
    /// actively blocking a misbehaving IP.
    fn lockout_expired_or_absent(&self) -> bool {
        match self.lockout_until {
            None => true,
            Some(t) => Instant::now() >= t,
        }
    }

    fn record_error(&mut self) {
        let now = Instant::now();

        // L-20 fix: genuine passive recovery — this entry has gone a full recovery
        // period with zero activity (of any kind, not just while locked out), so
        // whatever escalation streak it had built up no longer reflects an ongoing
        // problem. Checked BEFORE `last_activity` is overwritten below, using the
        // still-stale timestamp from the last call.
        if now.duration_since(self.last_activity).as_secs_f64()
            >= CIRCUIT_BREAKER_RECOVERY_PERIOD_SECS
        {
            self.consecutive_lockouts = 0;
        }

        // Captured before this call's mutations so the eventual "did a NEW lockout
        // just begin" check below can't be fooled by an already-locked entry simply
        // getting its lockout extended.
        let was_locked = self.is_locked();

        self.last_activity = now;
        // Reset if previous lockout has expired
        if self.lockout_until.is_some_and(|t| now >= t) {
            self.error_count = 0;
            self.lockout_until = None;
        }
        self.error_count += 1;
        if self.error_count >= CIRCUIT_BREAKER_ERROR_THRESHOLD {
            // L-20 fix: escalate the lockout duration using the PRE-increment
            // `consecutive_lockouts` value, so a fresh IP's first-ever lockout is
            // exactly `CIRCUIT_BREAKER_LOCKOUT_SECS` (today's unescalated behavior,
            // unchanged) — only the SECOND and later lockouts of the same IP grow.
            let lockout_secs = (CIRCUIT_BREAKER_LOCKOUT_SECS
                * 2f64.powi(self.consecutive_lockouts.min(20) as i32))
            .min(CIRCUIT_BREAKER_MAX_LOCKOUT_SECS);
            self.lockout_until = Some(now + Duration::from_secs_f64(lockout_secs));
        }

        if !was_locked && self.is_locked() {
            self.consecutive_lockouts = self.consecutive_lockouts.saturating_add(1);
        }
    }
}

// ─── PerIpConnectionGuard ────────────────────────────────────────────────────

/// CRIT-9 fix: RAII guard enforcing `MAX_CONNECTIONS_PER_IP`. `acquire` increments the
/// caller's IP's live-connection count (rejecting once at the per-IP cap); the count is
/// decremented automatically when the guard is dropped (connection closes or errors),
/// mirroring how `CircuitBreakerEntry` state is keyed per-IP. Deliberately still
/// `std::sync::Mutex` (not `parking_lot`, unlike [`SharedCircuitBreakers`] below) — L-18's
/// finding is scoped to the circuit-breaker map specifically; this guard's own critical
/// sections are equally short/non-`.await`-holding today, but widening the parking_lot
/// swap to every lock in this file is out of scope for that finding.
pub(crate) struct PerIpConnectionGuard {
    counts: Arc<Mutex<HashMap<IpAddr, usize>>>,
    ip: IpAddr,
}

impl PerIpConnectionGuard {
    /// Returns `None` if `ip` already has `max_per_ip` live connections.
    pub(crate) fn acquire(
        counts: &Arc<Mutex<HashMap<IpAddr, usize>>>,
        ip: IpAddr,
        max_per_ip: usize,
    ) -> Option<Self> {
        let mut guard = counts.lock().unwrap_or_else(|e| e.into_inner());
        let count = guard.entry(ip).or_insert(0);
        if *count >= max_per_ip {
            return None;
        }
        *count += 1;
        drop(guard);
        Some(Self {
            counts: Arc::clone(counts),
            ip,
        })
    }
}

impl Drop for PerIpConnectionGuard {
    fn drop(&mut self) {
        let mut guard = self.counts.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = guard.get_mut(&self.ip) {
            *count -= 1;
            if *count == 0 {
                guard.remove(&self.ip);
            }
        }
    }
}

// ─── Shared circuit-breaker state (R-5 / L-12) ───────────────────────────────

/// A per-IP circuit-breaker map that can be handed to more than one transport daemon
/// (TCP, WebSocket, TLS) so an IP address locked out on one transport cannot bypass the
/// lockout simply by reconnecting on another. Each daemon defaults to its own
/// independent map (today's exact behavior) unless a caller opts in via
/// `with_circuit_breakers(shared)`.
///
/// L-18 fix: backed by `parking_lot::Mutex`, not `std::sync::Mutex`. The lock is only
/// ever held across small, synchronous, non-`.await`-containing critical sections today
/// (verified at every call site: here, `record_error`, and the Step 0 check in
/// `handle_client`), so this was never a live deadlock/executor-starvation bug — but a
/// future edit that added an `.await` inside one of those sections would silently
/// reintroduce exactly that hazard with `std::sync::Mutex` (whose guard is `Send`-permissive
/// across `.await` points in a way that just compiles and then misbehaves under
/// contention). `parking_lot::Mutex` also never poisons, which is strictly better than
/// this codebase's own H-22 `.unwrap_or_else(|e| e.into_inner())` poison-recovery pattern
/// (that boilerplate is gone from every call site below, not just papered over).
pub type SharedCircuitBreakers = Arc<parking_lot::Mutex<HashMap<String, CircuitBreakerEntry>>>;

/// Construct a fresh, empty [`SharedCircuitBreakers`] map suitable for handing to
/// multiple daemons' `with_circuit_breakers(...)`.
pub fn new_shared_circuit_breakers() -> SharedCircuitBreakers {
    Arc::new(parking_lot::Mutex::new(HashMap::new()))
}

// ─── SAACPNetworkDaemon ──────────────────────────────────────────────────────

/// Async TCP server implementing the full SAACP network daemon.
///
/// Features (matching Python daemon.py):
///   - X25519 ECDH handshake with 100ms DDoS timeout
///   - Optional Ed25519 server authentication (DAEMON-MTLS fix): server signs its
///     X25519 ephemeral public key so active MITM cannot substitute their key.
///   - Per-IP circuit breaker (5 errors → 30s lockout, OOM guard at 10k IPs)
///   - Persistent connection loop with 2s header read timeout
///   - MTU chunking assembly with 30s aggregate timeout (VULN-02)
///   - Agent identity pinning with 30s re-validation interval (VULN-04)
///   - Stream routing: STREAM_CONTINUATION → STREAM_ACK, STREAM_END → STREAM_END_ACK
///   - INPUT_REQUIRED → YIELD_ASYNC + connection close
///   - PECF error translation + SREL timing equalization on hard drops
pub struct SAACPNetworkDaemon {
    host: String,
    port: u16,
    token_issuer_secret: Option<Vec<u8>>,
    circuit_breakers: SharedCircuitBreakers,
    /// DAEMON-MTLS: optional Ed25519 signing key seed (32 bytes) for server auth.
    server_ed25519_seed: Option<[u8; 32]>,
    /// Opt-in real Gate 1.0 token verification (DAEMON-NO-TOKEN-VERIFY fix).
    /// `Some` routes through `intercept_packet_full`/`intercept_packet_encrypted`
    /// with a real gateway. `None` (the default) is FAIL-CLOSED in any build
    /// without the `dangerously-skip-gateway` feature: Gate 1.0 hard-drops
    /// every token-bearing packet with `LateralMovementBlocked`, because a
    /// capability token cannot be verified without a trust anchor. The old
    /// synthetic READ_ONLY grant (`max_action_class = 0`,
    /// `source_agent = "unknown"`, no signature check) was removed as an
    /// unauthenticated-transaction anti-pattern; it survives ONLY in builds
    /// explicitly compiled with `dangerously-skip-gateway` (local dev parity).
    ///
    /// Note the corresponding **availability cliff** (longcat.md Steps 3-4):
    /// Gate 6.0's fail-closed audit contract hard-drops IRREVERSIBLE traffic
    /// (action_class >= 0x02) whenever the audit WAL cannot durably record
    /// it. See `crate::security::AuditHealth` for the health model and
    /// [`Self::with_dropped_audit_autoack`] for the opt-in quiet-window
    /// recovery of the Gate 2.5 sticky floor.
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    /// Opt-in real AES-256-GCM decryption (DAEMON-NO-AEAD fix). `None` preserves today's
    /// existing behavior: Gate 0 uses the structural-only `framing::MEASCFrame::parse_header`,
    /// which never decrypts. `Some` routes incoming packets through the real encrypting
    /// `measc::MEASCFrame::parse_frame`/`SessionEpochManager` machinery instead — see
    /// `with_encrypted_transport`.
    epoch_manager: Option<Arc<SessionEpochManager>>,
    /// Opt-in hook invoked with every successfully-verified `ParsedPacket` right before the
    /// ack is written back — lets a caller (e.g. `sidecar.rs`) observe decrypted, gate-passed
    /// payloads without forking `handle_client`'s dispatch logic.
    ///
    /// M-18 fix: genuinely called from INSIDE the `tokio::task::spawn_blocking`
    /// closure that runs the gate pipeline (immediately after a successful
    /// intercept, still on the blocking-pool thread) — not merely documented
    /// as such while actually running after `.await` back on the async
    /// executor, which was the case before this fix. Implementations must
    /// still not `.await` (use `try_send`/`blocking_send`); that contract is
    /// now enforced by where the call actually happens, not just by this
    /// comment.
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
    /// Opt-in C-3 identity binding (see `identity_binding.rs` and `with_identity_binding`).
    /// `None` preserves today's exact handshake wire format and behavior. `Some` requires
    /// every connecting client to present an `AgentIdentityCertificate` and prove possession
    /// of the certified private key during the ECDH handshake, before any packet is
    /// processed.
    server_agent_id: Option<String>,
    /// CRIT-9 fix: caps total concurrent connections at `MAX_CONNECTIONS`.
    connection_semaphore: Arc<Semaphore>,
    /// CRIT-9 fix: caps concurrent connections per source IP at `MAX_CONNECTIONS_PER_IP`.
    per_ip_connections: Arc<Mutex<HashMap<IpAddr, usize>>>,
    /// Opt-in revocation gossip mesh (Phase 6 / item 4, `gossip.rs`, Part 8.6). `None`
    /// preserves today's exact behavior: a schema_id=11 `Gossip Envelope` packet still
    /// passes Gate 0 through Gate 12.0 like any other packet (schema 11 is a real,
    /// already-registered schema — see `schemas.rs`), but nothing ever acts on its
    /// contents. `Some` (via `with_gossip_engine`) additionally decodes the envelope and
    /// calls `gossip::GossipEngine::receive` once the packet has cleared the full gate
    /// pipeline — reusing the exact same "observe a successfully-verified `ParsedPacket`"
    /// point the `on_delivered` hook already taps (see that field's doc comment), rather
    /// than adding a gossip-specific gate or special-casing schema 11 inside `handler.rs`'s
    /// gate pipeline itself.
    gossip: Option<Arc<crate::gossip::GossipEngine>>,
    /// Opt-in Active-Active cluster membership mesh (`cluster.rs`). `None` preserves
    /// today's exact behavior: a schema_id=12 `Cluster Envelope` packet still passes Gate
    /// 0 through Gate 12.0 like any other packet (schema 12 is a real, already-registered
    /// schema — see `schemas.rs`), but nothing acts on its contents. `Some` (via
    /// `with_cluster_engine`) additionally hands the envelope to
    /// `cluster::ClusterEngine::receive_envelope` once the packet has cleared the full
    /// gate pipeline — the same dispatch point the `gossip` field above uses, and for the
    /// same reason.
    ///
    /// Note the layered authentication: clearing the gate pipeline proves the *packet*
    /// was well-formed and from an authenticated session, but grants a peer nothing at
    /// the cluster layer. `receive_envelope` independently verifies the message's own
    /// Ed25519 signature against the cluster `TrustStore` and enforces roster membership,
    /// freshness, and replay protection before a single field reaches the membership view.
    cluster: Option<Arc<crate::cluster::ClusterEngine>>,
    /// Phase 4: explicit pipeline context (trust engine, audit log, stream
    /// registry, rulepacks). `None` runs the pipeline on
    /// [`crate::context::SaacpContext::shared_default`] — byte-identical to
    /// the pre-Phase-4 global behavior. Set via [`Self::with_context`] for
    /// multi-tenant deployments where this daemon's trust/audit universe must
    /// be isolated from other tenants in the same process.
    context: Option<std::sync::Arc<crate::context::SaacpContext>>,
    /// F12: per-deployment override for the plain-mode ECDH handshake timeout
    /// (seconds). `None` uses [`HANDSHAKE_TIMEOUT_SECS`] (2.0s). Set via
    /// [`SAACPNetworkDaemon::with_handshake_timeout`] — e.g. 10.0 for
    /// satellite/high-latency links, 0.5 to tighten slow-loris bounding on a
    /// LAN. The C-3 identity-bound mode always uses at least
    /// [`IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS`] regardless of this value.
    handshake_timeout_secs: Option<f64>,
    /// Plan item 2b: health-endpoint bind address. `None` (the default)
    /// means no health/metrics HTTP server is spawned. `Some(addr)`
    /// spawns a dedicated `axum` listener on `addr` exposing
    /// `/healthz`, `/readyz`, and (Prometheus) `/metrics`. Loopback
    /// is the default recommendation; non-loopback binds require a
    /// bearer token (fail-closed — see `with_health_endpoint`).
    ///
    /// Requires the `health-endpoint` Cargo feature.
    health_bind: Option<std::net::SocketAddr>,
    /// Bearer token required on `/metrics` when [`health_bind`] is
    /// non-loopback. Constant-time compared on every request. `None`
    /// when no health server is configured, OR when the bind is
    /// loopback.
    health_bearer_token: Option<Arc<str>>,
    /// M4 (R2 / opusreview.md): optional global in-flight payload byte budget
    /// (`Semaphore` permits = bytes). `None` (the default) preserves the
    /// unbounded behavior; `Some` (via [`Self::with_inflight_payload_budget`])
    /// makes every packet reserve its `payload_length` in bytes before assembly.
    inflight_payload_semaphore: Option<Arc<Semaphore>>,
    /// M12 (R3 / opusreview.md): optional bound on concurrent gate-pipeline
    /// executions dispatched to `spawn_blocking`. `None` (the default) preserves
    /// the unbounded tokio blocking-pool behavior; `Some` (via
    /// [`Self::with_pipeline_concurrency`]) applies backpressure instead of
    /// unbounded queue latency.
    pipeline_semaphore: Option<Arc<Semaphore>>,
    /// M11 (R7 / opusreview.md): this node's fleet-unique identifier. Required
    /// together with [`Self::session_affinity_tracker`] (set together via
    /// [`Self::with_node_id`]); `None` disables affinity tracking entirely.
    node_id: Option<String>,
    /// M11 (R7 / opusreview.md): session-affinity tracker. When `Some` (with
    /// `node_id`), every packet's header session_id is checked against the node
    /// that first recorded it — a violation proves a non-affine load balancer is
    /// degrading the node-local replay-window guarantee (AlertOnly enforcement).
    session_affinity_tracker: Option<Arc<crate::session_affinity::SessionAffinityTracker>>,
    /// M11 hardening (Phase 3): enforcement policy for affinity violations.
    /// Defaults to [`crate::session_affinity::AffinityViolationPolicy::AlertOnly`]
    /// (byte-identical to the pre-Phase-3 behavior); set via
    /// [`Self::affinity_violation_policy`].
    affinity_violation_policy: crate::session_affinity::AffinityViolationPolicy,
    /// R8 (finding H): whether this process is the fleet's designated
    /// audit-chain node. Visibility ONLY — no consensus/routing logic reads
    /// this (documented scope). Initialized from `SAACP_AUDIT_NODE` and
    /// overridable via [`Self::audit_node`].
    audit_node_designated: bool,
    /// M-A remediation (production audit G1/R1): startup recovery of the
    /// persisted audit chain.
    ///
    /// **Default behavior (v0.2.2+):** auto-enabled when `token_issuer_secret`
    /// is `Some`. The `insecure_for_testing()` path passes its caller's
    /// secret through unchanged, so this only matters when you actually
    /// configure one. Explicitly controllable via
    /// [`Self::with_audit_chain_recovery`], `SAACP_AUDIT_RECOVER=1` (force
    /// on), or `SAACP_AUDIT_NO_RECOVER=1` (force off — preserves the file
    /// for forensics without blocking startup).
    audit_chain_recovery: bool,
    /// longcat.md Step 4: opt-in quiet-window auto-acknowledgement of dropped
    /// audit events (see
    /// [`crate::security::ImmutableAuditLog::spawn_dropped_audit_autoack`]).
    /// `None` (the default) keeps the strictly operator-driven posture: once a
    /// single audit event has been dropped, the sticky health floor pins Gate
    /// 2.5 fail-closed on IRREVERSIBLE_ACTION until an operator calls
    /// `acknowledge_dropped_audits` — this is the availability-cliff tradeoff
    /// to understand before opting in: with a `Some(window)` an unattended
    /// node re-authorizes irreversible traffic `window` after the last drop.
    /// The lifetime `dropped_audit_count()` total is NEVER reset either way.
    dropped_audit_autoack: Option<Duration>,
}

impl SAACPNetworkDaemon {
    /// S2 (SECURE-BY-DEFAULT): construct a HARDENED daemon. The returned
    /// listener always has:
    ///
    /// - an **Ed25519-authenticated handshake** — a fresh ephemeral server
    ///   identity (seed generated here, exposed once via
    ///   [`Self::server_verifying_key`] so clients can pin it out-of-band) —
    ///   instead of an unauthenticated X25519 exchange;
    /// - **AEAD-encrypted transport** (a fresh [`SessionEpochManager`]) —
    ///   every post-handshake frame is AES-256-GCM verified with per-epoch
    ///   key evolution and the 4096-entry replay window, instead of the
    ///   structural-only Gate 0.
    ///
    /// Callers wanting the full C-3 identity-bound profile (mutual CA-signed
    /// client certificates) should use [`Self::secure`]. The permissive
    /// pre-S2 behavior (unauthenticated handshake, structural-only frames) is
    /// available ONLY via [`Self::insecure_for_testing`] — its name is the
    /// documentation.
    pub fn new(host: &str, port: u16, token_issuer_secret: Option<Vec<u8>>) -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::insecure_for_testing(host, port, token_issuer_secret)
            .with_server_auth(seed)
            .with_encrypted_transport(Arc::new(SessionEpochManager::new()))
    }

    /// S2: the pre-S2 permissive constructor — unauthenticated ECDH
    /// handshake and structural-only (no AEAD) frame verification. Kept for
    /// tests and local wire-format experimentation ONLY; every use prints a
    /// loud warning naming this method so an accidental production use is
    /// greppable in logs. Production deployments should use [`Self::new`]
    /// (hardened default) or [`Self::secure`] (identity-bound profile).
    pub fn insecure_for_testing(
        host: &str,
        port: u16,
        token_issuer_secret: Option<Vec<u8>>,
    ) -> Self {
        eprintln!(
            "[SAACP] WARNING: SAACPNetworkDaemon::insecure_for_testing() constructed a \
             PERMISSIVE daemon (unauthenticated handshake, structural-only frames). \
             Use SAACPNetworkDaemon::new() or ::secure() in production."
        );
        // M1 remediation: auto-enable audit chain recovery when a stable
        // issuer secret is available (production posture). Computed BEFORE the
        // struct literal below moves `token_issuer_secret` into the field.
        let auto_recovery = token_issuer_secret.is_some();
        Self {
            host: host.to_string(),
            port,
            token_issuer_secret,
            circuit_breakers: new_shared_circuit_breakers(),
            server_ed25519_seed: None,
            gateway: None,
            epoch_manager: None,
            on_delivered: None,
            server_agent_id: None,
            connection_semaphore: Arc::new(Semaphore::new(MAX_CONNECTIONS)),
            per_ip_connections: Arc::new(Mutex::new(HashMap::new())),
            gossip: None,
            cluster: None,
            handshake_timeout_secs: None,
            context: None,
            health_bind: None,
            health_bearer_token: None,
            inflight_payload_semaphore: None,
            pipeline_semaphore: None,
            node_id: None,
            session_affinity_tracker: None,
            affinity_violation_policy: Default::default(),
            audit_node_designated: std::env::var("SAACP_AUDIT_NODE")
                .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
                .unwrap_or(false),
            // M1 remediation: auto-enable audit chain recovery when a
            // stable issuer secret is available (production posture).
            // `insecure_for_testing()` itself never flips this on when the
            // caller passed `None` — and `::new()`/`::secure()` forward the
            // caller's secret, so production constructors that DO configure
            // one start with recovery enabled.
            audit_chain_recovery: auto_recovery,
            dropped_audit_autoack: None,
        }
    }

    /// Phase 4: run this daemon's gate pipeline on an explicit
    /// [`SaacpContext`] instead of the process-wide shared default. See the
    /// `context` field doc.
    pub fn with_context(mut self, context: std::sync::Arc<crate::context::SaacpContext>) -> Self {
        self.context = Some(context);
        self
    }

    /// Plan item 2b: enable a lightweight standalone health/metrics HTTP
    /// server alongside the main MEASC listener.
    ///
    /// - `bind` — the address the health server listens on. The default
    ///   recommendation is a loopback address (e.g. `127.0.0.1:9091`).
    ///   When `bind` resolves to a non-loopback IP, the operator MUST
    ///   also pass a `bearer_token` — otherwise the health server
    ///   refuses to start (fail-closed: we never expose audit-derived
    ///   metrics on a public address without a token).
    /// - `bearer_token` — token required on `/metrics` for non-loopback
    ///   binds. `/healthz` and `/readyz` are always unauthenticated
    ///   because that is the Kubernetes probe contract. Constant-time
    ///   compared. Pass `None` to allow a loopback bind (Kubernetes
    ///   `livenessProbe` can reach the pod's `127.0.0.1`).
    ///
    /// Requires the `health-endpoint` Cargo feature. Calling this method
    /// without the feature enabled is a *no-op* (the field stays `None`)
    /// so a deployment that toggles the feature never breaks the daemon.
    pub fn with_health_endpoint(
        mut self,
        bind: std::net::SocketAddr,
        bearer_token: Option<String>,
    ) -> Self {
        // Refuse a non-loopback bind without a token at configuration
        // time, BEFORE start(). The health server itself also re-checks
        // this in start_with_shutdown — defense in depth.
        let needs_token = !bind.ip().is_loopback();
        let token_is_empty = bearer_token.as_ref().is_some_and(|t| t.is_empty());
        if needs_token && bearer_token.is_none() {
            eprintln!(
                "[SAACP Daemon] with_health_endpoint: non-loopback bind {bind} requires a \
                 bearer token; ignoring the request. Call with Some(token) or bind 127.0.0.1."
            );
            return self;
        }
        if needs_token && token_is_empty {
            eprintln!(
                "[SAACP Daemon] with_health_endpoint: non-loopback bind {bind} requires a \
                 non-empty bearer token; ignoring the request."
            );
            return self;
        }
        self.health_bind = Some(bind);
        self.health_bearer_token = bearer_token.map(Arc::from);
        self
    }

    /// Override the plain-mode ECDH handshake timeout (seconds). See the
    /// `handshake_timeout_secs` field doc for guidance.
    pub fn with_handshake_timeout(mut self, secs: f64) -> Self {
        self.handshake_timeout_secs = Some(secs.max(0.1));
        self
    }

    /// Enable server-side Ed25519 authentication for the ECDH handshake.
    ///
    /// `seed` must be 32 bytes (Ed25519 signing key seed). The corresponding
    /// verifying key should be distributed out-of-band to all connecting clients
    /// via FAITF TrustStore or configuration.
    ///
    /// When enabled, the server handshake wire format changes from
    /// `[x25519_pub(32)]` to
    /// `[x25519_pub(32)] || [ed25519_sig(64)] || [ed25519_vk(32)]` = 128 bytes.
    ///
    /// Clients MUST verify the signature before accepting the DH exchange.
    pub fn with_server_auth(mut self, seed: [u8; 32]) -> Self {
        self.server_ed25519_seed = Some(seed);
        self
    }

    /// Opt in to C-3 identity binding (`identity_binding.rs`): every connecting client
    /// must present an `AgentIdentityCertificate` signed by one of `ca_keys` and prove
    /// possession of the certified private key during the ECDH handshake, before any
    /// packet is processed. Implies `with_server_auth(seed)` — a `TranscriptBoundSession`
    /// needs a server identity key on both sides of the transcript, so the two cannot be
    /// configured independently.
    ///
    /// Registers `ca_keys` into the process-wide `DEFAULT_IDENTITY_VERIFIER` (keyed by
    /// `ca_kid`) so the handshake can validate certificates against them.
    ///
    /// When enabled, the client handshake message grows from
    /// `[client_nonce(32)] || [client_x25519_pub(32)]` to additionally carry
    /// `[session_id(16)] || [cert_len(u32 LE)] || [cert_json(cert_len)] || [pop_sig(64)]`,
    /// where `pop_sig` is an Ed25519 signature — made with the certified private key —
    /// over `client_nonce || client_x25519_pub || session_id`. A client not configured to
    /// send this extended message will fail to complete the handshake against a daemon
    /// built with `with_identity_binding`.
    pub fn with_identity_binding(
        mut self,
        seed: [u8; 32],
        server_agent_id: &str,
        ca_keys: &[(&str, ed25519_dalek::VerifyingKey)],
    ) -> Self {
        for (kid, vk) in ca_keys {
            crate::identity_binding::DEFAULT_IDENTITY_VERIFIER.register_ca_key(kid, *vk);
        }
        self.server_ed25519_seed = Some(seed);
        self.server_agent_id = Some(server_agent_id.to_string());
        self
    }

    /// F3 fix (SECURE-BY-DEFAULT): one-call hardened daemon profile.
    ///
    /// Composes every opt-in protection this daemon supports —
    /// [`with_identity_binding`] (mutually-authenticated ECDH: server signs its
    /// X25519 share, every client presents a CA-signed
    /// `AgentIdentityCertificate` + proof-of-possession),
    /// [`with_encrypted_transport`] (real AEAD Gate 0 via `measc::parse_frame`)
    /// and [`with_gateway`] (real Gate 1.0 token signature verification) — so a
    /// production deployment cannot silently miss one.
    ///
    /// `supported_suites` is this daemon's configured suite list and is
    /// validated against the active PRODUCTION crypto-governance policy at
    /// construction time via
    /// [`crate::crypto_governance::SuiteNegotiator::negotiate`] (downgrade
    /// guard): a list missing the mandatory `ed25519` baseline, or naming a
    /// non-approved algorithm, refuses to construct. The negotiation transcript
    /// is recorded in a `CryptoTransparencyLedger`. Peer-advertised suite
    /// negotiation requires a future wire version — this check governs the
    /// daemon's OWN configuration.
    ///
    /// # Errors
    /// `Err` iff `supported_suites` violates the production policy.
    ///
    /// Nine explicit parameters is deliberate for a security-profile
    /// constructor: every protection-relevant input is named at the call site,
    /// visible in review, and impossible to inherit silently from a default.
    #[allow(clippy::too_many_arguments)]
    pub fn secure(
        host: &str,
        port: u16,
        token_issuer_secret: Option<Vec<u8>>,
        server_ed25519_seed: [u8; 32],
        server_agent_id: &str,
        ca_keys: &[(&str, ed25519_dalek::VerifyingKey)],
        supported_suites: &[&str],
        gateway: Arc<crate::gateway::ZeroTrustGateway>,
        epoch_manager: Arc<SessionEpochManager>,
    ) -> Result<Self, String> {
        use crate::crypto_governance::{CryptoTransparencyLedger, SuiteNegotiator};

        // Config-time downgrade guard — refuses to construct a "secure" daemon
        // whose suite configuration the production policy rejects. The
        // all-zeros session anchor marks this as a validation transcript, not a
        // live session; it is what the ledger entry hangs off.
        let ledger = CryptoTransparencyLedger::new();
        SuiteNegotiator::negotiate(
            supported_suites,
            supported_suites,
            &[0u8; 16],
            None,
            None,
            &ledger,
            None, // security_tier — accept any PQC floor in `secure()` mode
        )
        .map_err(|e| {
            format!(
                "SAACPNetworkDaemon::secure: suite configuration rejected by \
                 crypto governance: {e}"
            )
        })?;

        Ok(Self::new(host, port, token_issuer_secret)
            .with_identity_binding(server_ed25519_seed, server_agent_id, ca_keys)
            .with_gateway(gateway)
            .with_encrypted_transport(epoch_manager))
    }

    /// Opt in to real Gate 1.0 capability-token signature verification
    /// (`ZeroTrustGateway::validate_lateral_movement`) instead of the structural-only
    /// presence check every connection gets by default. See the `gateway` field doc comment.
    pub fn with_gateway(mut self, gateway: Arc<crate::gateway::ZeroTrustGateway>) -> Self {
        self.gateway = Some(gateway);
        self
    }

    /// Opt in to real AES-256-GCM decryption + replay-window enforcement of incoming
    /// packets via `measc::MEASCFrame::parse_frame`, instead of the structural-only Gate 0.
    /// See the `epoch_manager` field doc comment.
    pub fn with_encrypted_transport(mut self, epoch_manager: Arc<SessionEpochManager>) -> Self {
        self.epoch_manager = Some(epoch_manager);
        self
    }

    /// Observe every successfully-verified `ParsedPacket` (see the `on_delivered` field doc
    /// comment).
    pub fn with_on_delivered(mut self, callback: Arc<dyn Fn(ParsedPacket) + Send + Sync>) -> Self {
        self.on_delivered = Some(callback);
        self
    }

    /// R-5 / L-12 fix: opt in to a circuit-breaker map shared with other transport
    /// daemons (e.g. `SAACPWebSocketDaemon`, `SAACPTlsDaemon`) — see
    /// [`SharedCircuitBreakers`]. Not calling this preserves today's exact behavior:
    /// each daemon tracks per-IP lockouts independently.
    pub fn with_circuit_breakers(mut self, shared: SharedCircuitBreakers) -> Self {
        self.circuit_breakers = shared;
        self
    }

    /// M4 (R2 / opusreview.md): set the global in-flight payload byte budget.
    /// `Some(bytes)` makes every packet's `payload_length` reserve that many
    /// bytes from a shared `Semaphore` before its buffer is assembled — bounding
    /// AGGREGATE in-flight payload memory across ALL connections; an exhausted
    /// budget rejects the packet with `PayloadTooLarge` (fail closed). `None`
    /// (the default) preserves the unbounded behavior. See
    /// [`MAX_INFLIGHT_PAYLOAD_BYTES`] for the documented default ceiling.
    pub fn with_inflight_payload_budget(mut self, max_bytes: Option<usize>) -> Self {
        self.inflight_payload_semaphore = max_bytes.map(|n| Arc::new(Semaphore::new(n)));
        self
    }

    /// M12 (R3 / opusreview.md): set the maximum number of concurrent
    /// gate-pipeline executions dispatched to `spawn_blocking`. `Some(n)` makes
    /// each packet acquire one permit before its gate run, so a saturated
    /// pipeline applies backpressure at the connection instead of growing the
    /// unbounded tokio blocking-pool queue. `None` (the default) preserves the
    /// unbounded behavior.
    pub fn with_pipeline_concurrency(mut self, max_concurrent: Option<usize>) -> Self {
        self.pipeline_semaphore = max_concurrent.map(|n| Arc::new(Semaphore::new(n)));
        self
    }

    /// M11 (R7 / opusreview.md): set a fleet-unique node identifier for this
    /// daemon and enable session-affinity tracking. Once enabled, every packet's
    /// header session_id is recorded/checked against the node that first
    /// accepted it: a mismatch proves a non-affine load balancer is silently
    /// degrading the node-local replay-window guarantee. Enforcement is
    /// AlertOnly (log once per connection + feed the per-IP error counter so a
    /// persistently mis-routed peer trips the existing IP circuit breaker).
    pub fn with_node_id(mut self, node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        let tracker = crate::session_affinity::SessionAffinityTracker::new();
        self.node_id = Some(node_id);
        self.session_affinity_tracker = Some(Arc::new(tracker));
        self
    }

    /// M11 hardening (Phase 3): set the enforcement policy applied when the
    /// session-affinity tracker reports a violation.
    ///
    /// - [`AffinityViolationPolicy::AlertOnly`] (the default) preserves
    ///   today's behavior exactly: once-per-connection log, per-IP error
    ///   counter (feeding the existing IP circuit breaker), packet processed.
    /// - [`AffinityViolationPolicy::HardDrop`] additionally terminates the
    ///   connection with a hard drop (fail closed) — for fleets that have
    ///   verified LB affinity and want mis-routing to be loud.
    ///
    /// No-op when no tracker is configured (`with_node_id` never called):
    /// without tracking there is nothing to enforce, and the default remains
    /// byte-identical.
    pub fn affinity_violation_policy(
        mut self,
        policy: crate::session_affinity::AffinityViolationPolicy,
    ) -> Self {
        self.affinity_violation_policy = policy;
        self
    }

    /// M11 hardening (Phase 3): like [`Self::with_node_id`], but accepts a
    /// caller-constructed tracker. Needed when the tracker's state is shared
    /// across daemon instances (in-process fleets, tests, or a future shared
    /// state backend): a violation is only detectable when the tracker has
    /// already seen the session under a DIFFERENT node id, which a fresh
    /// per-daemon tracker can never observe.
    pub fn with_affinity_tracker(
        mut self,
        node_id: impl Into<String>,
        tracker: Arc<crate::session_affinity::SessionAffinityTracker>,
    ) -> Self {
        self.node_id = Some(node_id.into());
        self.session_affinity_tracker = Some(tracker);
        self
    }

    /// R8 (finding H): mark this process as the fleet's designated audit-chain
    /// node (the node holding the chain of record and serving the operator
    /// `POST /api/audit/ack` acknowledgement). Visibility only — one-time
    /// startup log + the `saacp_audit_chain_designated_node` gauge + the
    /// `audit_chain_role` field on `/healthz`. No consensus or routing logic
    /// keys off this (documented scope, finding H). The `SAACP_AUDIT_NODE=1`
    /// environment variable sets the same flag at construction; this builder
    /// overrides it explicitly.
    pub fn audit_node(mut self, designated: bool) -> Self {
        self.audit_node_designated = designated;
        self
    }

    /// M-A remediation (production audit G1/R1): adopt + verify the persisted
    /// audit chain before the listener binds.
    ///
    /// **Default (v0.2.2+):** auto-enabled when `token_issuer_secret` is
    /// `Some` — the caller-provided option is forwarded to
    /// `insecure_for_testing`, which computes `is_some()` on it, so any
    /// constructor path that actually sets a secret also turns recovery on.
    /// The environment variables `SAACP_AUDIT_RECOVER=1` (force on)
    /// and `SAACP_AUDIT_NO_RECOVER=1` (force off) override both this builder
    /// and the auto-detect.
    ///
    /// When enabled, `start_with_shutdown` calls
    /// `ImmutableAuditLog::initialize_chain` on the process-global log with
    /// this daemon's `token_issuer_secret` — the same secret the gate
    /// pipeline HMAC-binds chain entries with — so a restarted process
    /// continues the on-disk chain instead of silently starting from genesis.
    ///
    /// Fail-closed semantics (deliberate): if the on-disk chain fails
    /// verification (H-6 — the tail is untrusted input; a crash-torn final
    /// line is indistinguishable from tampering), `start` returns `Err` and
    /// the listener never binds. There is no automatic quarantine: the
    /// operator preserves the file for forensics, moves it aside, and
    /// restarts. Recovery is skipped with a startup note when no stable
    /// issuer secret is configured — entries written under the per-connection
    /// fallback key cannot be verified against any single secret.
    pub fn with_audit_chain_recovery(mut self, enabled: bool) -> Self {
        self.audit_chain_recovery = enabled;
        self
    }

    /// longcat.md Step 4: opt-in auto-acknowledgement of dropped audit events
    /// after a quiet window with no new drops (see
    /// [`crate::security::ImmutableAuditLog::spawn_dropped_audit_autoack`]).
    /// The task is spawned in `start_with_shutdown`, bound to the same
    /// shutdown token, and joined during the drain phase. `None` (the default)
    /// keeps the operator-ack-only fail-closed posture — see the
    /// `dropped_audit_autoack` field doc for the availability-cliff tradeoff.
    pub fn with_dropped_audit_autoack(mut self, quiet_window: Duration) -> Self {
        self.dropped_audit_autoack = Some(quiet_window);
        self
    }

    /// M-A recovery body — see [`Self::with_audit_chain_recovery`]. Operates on
    /// THIS daemon's audit log (Gap B / longcat.md Step 2): the context's chain
    /// when a context is configured, else the shared default — which aliases the
    /// exact instance the gate pipeline and the health/audit-ack paths use.
    /// Blocking disk I/O, but only at startup, before the listener binds.
    fn recover_audit_chain(
        log: &crate::security::ImmutableAuditLog,
        issuer_secret: &Option<Vec<u8>>,
    ) -> std::io::Result<()> {
        let Some(secret) = issuer_secret else {
            eprintln!(
                "[SAACP Daemon] audit-chain recovery requested (SAACP_AUDIT_RECOVER) but no \
                 stable token_issuer_secret is configured — entries written under the \
                 per-connection fallback key cannot be verified against any single secret. \
                 Recovery SKIPPED; starting with an empty in-memory chain."
            );
            return Ok(());
        };
        match log.initialize_chain(secret) {
            Ok(()) => {
                eprintln!(
                    "[SAACP Daemon] audit chain verified against the configured issuer secret \
                     and adopted from disk — this process continues the persisted chain."
                );
                Ok(())
            }
            Err(detail) => {
                // Fail closed: never accept traffic on top of an unverifiable
                // chain, and never auto-quarantine (an operator must preserve
                // the file for forensics and decide).
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!(
                        "audit-chain recovery failed and SAACP_AUDIT_RECOVER is enabled: \
                         {detail}. Preserve the file (SAACP_AUDIT_LOG or the default \
                         saacp_audit.log) for forensics, move it aside, and restart — or \
                         unset SAACP_AUDIT_RECOVER to start without recovery."
                    ),
                ))
            }
        }
    }

    /// Opt in to the revocation gossip mesh (Phase 6 / item 4, see the `gossip` field doc
    /// comment). The caller constructs the `GossipEngine` itself (wiring its own
    /// `GossipTransport`, `DistributedRevocationInfrastructure`, and `TrustStore` — see
    /// `gossip.rs`'s module docs) since those are deployment-specific; this daemon only
    /// needs to know where to hand off an inbound schema_id=11 envelope once it clears the
    /// gate pipeline. Does not itself start `GossipEngine::start_sweep` — call that
    /// separately on the same `Arc<GossipEngine>` if periodic `SeenSet` maintenance is
    /// wanted (mirrors `klms::KeyLifecycleManager::start_auto_rotation` being a distinct
    /// opt-in call from the engine's construction).
    pub fn with_gossip_engine(mut self, engine: Arc<crate::gossip::GossipEngine>) -> Self {
        self.gossip = Some(engine);
        self
    }

    /// Opt in to the Active-Active cluster membership mesh (see the `cluster` field doc
    /// comment). The caller constructs the `ClusterEngine` itself (wiring its own
    /// `ClusterTransport`, `AgentIdentity`, and `TrustStore` — see `cluster.rs`'s module
    /// docs) since those are deployment-specific; this daemon only needs to know where to
    /// hand off an inbound schema_id=12 envelope once it clears the gate pipeline.
    ///
    /// Does not itself start the failure detector — call `ClusterEngine::start` separately
    /// on the same `Arc<ClusterEngine>`, mirroring `with_gossip_engine`'s split of engine
    /// construction from background-thread startup. Without it this daemon accepts
    /// membership messages but never detects a dead peer or elects a leader.
    pub fn with_cluster_engine(mut self, engine: Arc<crate::cluster::ClusterEngine>) -> Self {
        self.cluster = Some(engine);
        self
    }

    /// Start listening for connections. Runs forever (until the process is killed) —
    /// equivalent to `start_with_shutdown` with a token that's never cancelled. M-37
    /// fix: returns `Result` (propagates a bind failure) instead of panicking.
    pub async fn start(&self) -> std::io::Result<()> {
        self.start_with_shutdown(tokio_util::sync::CancellationToken::new())
            .await
    }

    /// Plan item 2b: spawn the standalone health/metrics HTTP server.
    ///
    /// Returns `Some(JoinHandle)` when the server is started (so the
    /// caller can `await` it for graceful shutdown) or `None` when no
    /// health endpoint is configured. The server re-checks the
    /// loopback policy here (defense in depth — see
    /// `with_health_endpoint`); if the bind is non-loopback and no
    /// bearer token was provided, the function returns `Ok(None)` and
    /// logs the refusal, leaving the daemon running normally on the
    /// main listener.
    #[cfg(feature = "health-endpoint")]
    async fn spawn_health_server(
        &self,
        bind: std::net::SocketAddr,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> std::io::Result<Option<tokio::task::JoinHandle<std::io::Result<()>>>> {
        use std::sync::atomic::AtomicU64;

        if !bind.ip().is_loopback() && self.health_bearer_token.is_none() {
            eprintln!(
                "[SAACP Daemon] spawn_health_server: refusing non-loopback bind {bind} \
                 without a bearer token."
            );
            return Ok(None);
        }

        let audit = self.audit_log_for_health();
        let telemetry_arc = self.telemetry_for_health();
        // Phase 3: the alert feed the audit-ack endpoint records its
        // SecurityAlert into (per-tenant when a context is configured,
        // process-global otherwise — mirrors the two helpers above).
        let ctx_alerts_for_health =
            crate::context::SaacpContext::or_shared_default(self.context.as_deref())
                .alerts
                .clone();
        // TODO(2b-followup): wire a real per-daemon connection counter.
        // The current `AtomicU64(0)` is honest about its scope — the
        // value is process-wide-zero until a future change passes the
        // actual `ConnectionCountGuard`-backed gauge from `telemetry`
        // here.
        let _connection_count = Arc::new(AtomicU64::new(0));

        let mut state = crate::health::HealthState::new(audit, telemetry_arc);
        if let Some(tok) = &self.health_bearer_token {
            state = state.with_bearer_token(tok.as_ref());
        }
        // Phase 3: surface session-affinity health on /readyz, the audit-chain
        // designation role on /healthz, and hand the audit-ack endpoint the
        // stable issuer secret it needs to append its acknowledgement record
        // to the audit chain (same secret the gate pipeline HMAC-binds
        // audit entries with — see handle_client's `gate_secret`).
        if let Some(tracker) = &self.session_affinity_tracker {
            state = state.with_session_affinity_tracker(Arc::clone(tracker));
        }
        state = state.with_audit_node_designated(self.audit_node_designated);
        state = state.with_alerts_feed(ctx_alerts_for_health.clone());
        if let Some(secret) = &self.token_issuer_secret {
            state = state.with_audit_issuer_secret(Arc::new(secret.clone()));
        }

        let router = crate::health::health_router(state);
        let listener = tokio::net::TcpListener::bind(bind).await?;
        eprintln!(
            "[SAACP Daemon] Health/metrics endpoint listening on http://{bind} \
             (/healthz, /readyz, /metrics{})",
            if self.health_bearer_token.is_some() {
                " — bearer-token-gated"
            } else {
                ""
            }
        );

        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, router);
            let shutdown_fut = async move {
                shutdown.cancelled().await;
            };
            tokio::select! {
                result = server => result,
                _ = shutdown_fut => Ok(()),
            }
        });
        Ok(Some(handle))
    }

    /// Return the audit log to expose on `/healthz` and `/readyz`.
    /// Per-tenant work can return the context's `audit` field instead.
    #[cfg(feature = "health-endpoint")]
    fn audit_log_for_health(&self) -> std::sync::Arc<crate::security::ImmutableAuditLog> {
        match &self.context {
            Some(c) => c.audit.clone(),
            None => crate::context::SaacpContext::shared_default_arc()
                .audit
                .clone(),
        }
    }

    /// Return the telemetry collector to expose on `/metrics`. Mirrors
    /// [`audit_log_for_health`].
    #[cfg(feature = "health-endpoint")]
    fn telemetry_for_health(&self) -> std::sync::Arc<crate::telemetry::TelemetryCollector> {
        match &self.context {
            Some(c) => c.telemetry.clone(),
            None => crate::context::SaacpContext::shared_default_arc()
                .telemetry
                .clone(),
        }
    }

    /// M-15/R-2 fix: same as `start`, but stops accepting new connections as soon as
    /// `shutdown` is cancelled, then drains in-flight connections (bounded by
    /// `SHUTDOWN_DRAIN_TIMEOUT_SECS`, after which any still-open connections are
    /// hard-aborted) before flushing the audit-log WAL (L-10) and returning.
    pub async fn start_with_shutdown(
        &self,
        shutdown: tokio_util::sync::CancellationToken,
    ) -> std::io::Result<()> {
        // S7 fix: auto-start the cluster failure detector. Pre-fix, a
        // deployment that configured `with_cluster_engine` but forgot the
        // separate manual `ClusterEngine::start` call accepted membership
        // messages without ever detecting a dead peer or electing a leader.
        // `start` is idempotent (engine-level guard), so a caller that still
        // starts it manually cannot double-spawn. Tick interval: the suspect
        // timeout / 2, so a failed peer is detected within roughly one
        // suspect window (SWIM convention).
        if let Some(cluster) = self.cluster.clone() {
            let interval = cluster.suspect_timeout_interval_hint();
            cluster.start(interval);
        }
        // M-A remediation (M1 upgrade): audit-chain recovery runs BEFORE the
        // listener binds — a verification failure refuses startup (`Err`) so
        // the node never accepts traffic while its chain of record is
        // unverifiable.
        //
        // Priority (highest to lowest):
        //   1. SAACP_AUDIT_NO_RECOVER=1  → force off (operator escape hatch)
        //   2. SAACP_AUDIT_RECOVER=1     → force on  (legacy env compat)
        //   3. self.audit_chain_recovery → auto-detected from constructor
        //      (true when token_issuer_secret is Some, false for insecure)
        let no_recover = matches!(
            std::env::var("SAACP_AUDIT_NO_RECOVER").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE")
        );
        let force_recover = matches!(
            std::env::var("SAACP_AUDIT_RECOVER").ok().as_deref(),
            Some("1") | Some("true") | Some("TRUE")
        );
        let recovery_requested = if no_recover {
            eprintln!(
                "[SAACP Daemon] SAACP_AUDIT_NO_RECOVER=1 — audit chain recovery \
                 explicitly disabled. The on-disk chain (if any) is NOT verified; \
                 the process starts with an empty in-memory chain."
            );
            false
        } else {
            force_recover || self.audit_chain_recovery
        };
        if recovery_requested {
            let recovery_ctx =
                crate::context::SaacpContext::or_shared_default(self.context.as_deref());
            Self::recover_audit_chain(recovery_ctx.audit.as_ref(), &self.token_issuer_secret)?;
        }
        // M-B remediation: optional external alert sink. When
        // SAACP_ALERT_SYSLOG=<host:port> is set, every SecurityAlert recorded
        // by this process is forwarded best-effort as an RFC 5424 syslog
        // datagram (see `alert_sink.rs`). Installation failures are loud but
        // fail-open — an unreachable collector never blocks startup.
        if let Ok(target) = std::env::var("SAACP_ALERT_SYSLOG") {
            if !target.trim().is_empty() {
                match crate::alert_sink::SyslogAlertSink::install_global(target.trim()) {
                    Ok(()) => eprintln!(
                        "[SAACP Daemon] security alerts will be forwarded to syslog \
                         collector at {target} (RFC 5424 over UDP, best-effort)"
                    ),
                    Err(e) => eprintln!(
                        "[SAACP Daemon] WARNING: could not install syslog alert sink \
                         ({e}) — security alerts stay process-local (Prometheus / dashboard)"
                    ),
                }
            }
        }
        // M5 remediation: optional webhook alert sink. When
        // SAACP_ALERT_WEBHOOK=<url> is set, every SecurityAlert is POSTed as
        // JSON to the URL (best-effort, bounded channel, 5s timeout). Both
        // sinks can be active simultaneously (syslog + webhook).
        #[cfg(feature = "webhook-alerts")]
        if let Ok(url) = std::env::var("SAACP_ALERT_WEBHOOK") {
            if !url.trim().is_empty() {
                match crate::alert_sink::WebhookAlertSink::install_global(url.trim()) {
                    Ok(()) => eprintln!(
                        "[SAACP Daemon] security alerts will be forwarded to webhook \
                         at {url} (JSON POST, best-effort)"
                    ),
                    Err(e) => eprintln!(
                        "[SAACP Daemon] WARNING: could not install webhook alert sink \
                         ({e}) — security alerts stay process-local (Prometheus / dashboard)"
                    ),
                }
            }
        }
        let addr = format!("{}:{}", self.host, self.port);
        let listener = TcpListener::bind(&addr).await?;

        // Plan item 2b: optionally spawn the standalone health/metrics
        // HTTP server. The server is bound to a *separate* TcpListener
        // (so its lifecycle is independent and its address can be on
        // a different network namespace / port). The server is opt-in
        // via `with_health_endpoint`; if no bind is set (the default)
        // the feature is dormant and adds no overhead.
        #[cfg(feature = "health-endpoint")]
        let health_handle = if let Some(hb) = self.health_bind {
            self.spawn_health_server(hb, shutdown.clone()).await?
        } else {
            None
        };
        #[cfg(not(feature = "health-endpoint"))]
        let _health_handle: Option<tokio::task::JoinHandle<std::io::Result<()>>> = None;

        // longcat.md Step 4: opt-in dropped-audit auto-acknowledgement task —
        // spawned only when `with_dropped_audit_autoack` set a quiet window,
        // bound to the same shutdown token, and joined during the drain phase
        // (mirroring the health-server handle above). The default `None`
        // preserves the operator-ack-only fail-closed posture exactly.
        let autoack_handle = self.dropped_audit_autoack.map(|quiet_window| {
            let audit = std::sync::Arc::clone(
                &crate::context::SaacpContext::or_shared_default(self.context.as_deref()).audit,
            );
            audit.spawn_dropped_audit_autoack(quiet_window, shutdown.clone())
        });

        let auth_mode = if self.server_ed25519_seed.is_some() {
            "authenticated"
        } else {
            "unauthenticated"
        };
        eprintln!(
            "[SAACP Daemon] Listening on {} ({} handshake)",
            addr, auth_mode
        );

        // R8 (finding H): audit-chain designation visibility. One-time
        // startup log + the `saacp_audit_chain_designated_node` gauge.
        // Visibility ONLY — no consensus or routing logic keys off this
        // (documented scope, finding H).
        {
            let ctx_startup =
                crate::context::SaacpContext::or_shared_default(self.context.as_deref());
            ctx_startup
                .telemetry
                .set_audit_chain_designated_node(self.audit_node_designated);
        }
        if self.audit_node_designated {
            eprintln!(
                "[SAACP Daemon] This node IS the audit-chain designated node — the chain of \
                 record and operator audit acknowledgements (POST /api/audit/ack) live here."
            );
        } else {
            eprintln!(
                "[SAACP Daemon] This node is NOT the audit-chain designated node (visibility \
                 only, no consensus impact — R8/finding H). Set SAACP_AUDIT_NODE=1 or call \
                 .audit_node(true) on exactly one fleet node."
            );
        }

        // F3 fix (SECURE-BY-DEFAULT nudge): the legacy builder leaves every
        // protection opt-in, so a deployment can silently miss one. Enumerate
        // exactly what is OFF, every single start, until the operator has seen
        // it — and point at the one-call hardened profile.
        if self.server_ed25519_seed.is_none()
            || self.epoch_manager.is_none()
            || self.gateway.is_none()
        {
            eprintln!("[SAACP Daemon] ══════════ SECURITY WARNING ══════════");
            eprintln!("[SAACP Daemon]  This daemon is running with protections DISABLED:");
            if self.server_ed25519_seed.is_none() {
                eprintln!("[SAACP Daemon]   - Server authentication OFF: the ECDH handshake is unauthenticated (active MITM can substitute its key)");
            }
            if self.epoch_manager.is_none() {
                eprintln!("[SAACP Daemon]   - Encrypted transport OFF: Gate 0 is structural-only, incoming packets are not AEAD-decrypted or replay-checked");
            }
            if self.gateway.is_none() {
                eprintln!("[SAACP Daemon]   - No ZeroTrustGateway configured: Gate 1.0 is FAIL-CLOSED in this build — every token-bearing packet is rejected with LateralMovementBlocked (the unauthenticated READ_ONLY grant exists only in `dangerously-skip-gateway` builds)");
            }
            eprintln!(
                "[SAACP Daemon]  Use SAACPNetworkDaemon::secure(...) for the hardened profile."
            );
            eprintln!("[SAACP Daemon] ════════════════════════════════════");
        }

        let mut tasks = tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => {
                    eprintln!("[SAACP Daemon] Shutdown signal received — no longer accepting new connections");
                    break;
                }
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((stream, peer_addr)) => {
                            // CRIT-9 fix: bound total and per-IP concurrent connections before
                            // spawning a handler task, so an unbounded flood of slow-feed
                            // connections cannot exhaust memory (each connection can be forced
                            // to hold up to MAX_PAYLOAD_SIZE via a crafted header).
                            let permit = match Arc::clone(&self.connection_semaphore).try_acquire_owned() {
                                Ok(permit) => permit,
                                Err(_) => {
                                    eprintln!(
                                        "[SAACP Daemon] Connection limit ({}) reached — rejecting {}",
                                        MAX_CONNECTIONS, peer_addr,
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };
                            let per_ip_guard = match PerIpConnectionGuard::acquire(
                                &self.per_ip_connections, peer_addr.ip(), MAX_CONNECTIONS_PER_IP,
                            ) {
                                Some(guard) => guard,
                                None => {
                                    eprintln!(
                                        "[SAACP Daemon] Per-IP connection limit ({}) reached for {} — rejecting",
                                        MAX_CONNECTIONS_PER_IP, peer_addr.ip(),
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            let cbs    = Arc::clone(&self.circuit_breakers);
                            let secret = self.token_issuer_secret.clone();
                            let seed   = self.server_ed25519_seed;
                            let gateway       = self.gateway.clone();
                            let epoch_manager = self.epoch_manager.clone();
                            let on_delivered  = self.on_delivered.clone();
                            let server_agent_id = self.server_agent_id.clone();
                            let gossip        = self.gossip.clone();
                            let cluster       = self.cluster.clone();
                            let handshake_timeout_override = self.handshake_timeout_secs;
                            let daemon_context = self.context.clone();
                            let inflight_payload_semaphore = self.inflight_payload_semaphore.clone();
                            let pipeline_semaphore = self.pipeline_semaphore.clone();
                            let node_id = self.node_id.clone();
                            let session_affinity_tracker = self.session_affinity_tracker.clone();
                            let affinity_violation_policy = self.affinity_violation_policy;
                            tasks.spawn(async move {
                                let _permit = permit; // released on drop when this task ends
                                let _per_ip_guard = per_ip_guard;
                                // O-4 fix: pair this connection's lifetime with the live
                                // `saacp_active_connections{transport="tcp"}` gauge, mirroring
                                // the `_permit`/`_per_ip_guard` RAII idiom above — dropped on
                                // every exit path (normal return, early return, or
                                // `JoinSet::abort_all()` during shutdown drain-timeout).
                                let _conn_count_guard = crate::telemetry::ConnectionCountGuard::tcp();
                                handle_client(
                                    stream, peer_addr, cbs, secret, seed,
                                    gateway, epoch_manager, on_delivered, server_agent_id, gossip, cluster,
                                    handshake_timeout_override, daemon_context,
                                    inflight_payload_semaphore, pipeline_semaphore, node_id, session_affinity_tracker,
                                    affinity_violation_policy,
                                ).await;
                            });
                        }
                        Err(e) => {
                            eprintln!("[SAACP Daemon] Accept error: {}", e);
                        }
                    }
                }
            }
        }

        // Drain: let in-flight connections finish naturally, bounded by
        // SHUTDOWN_DRAIN_TIMEOUT_SECS, then hard-abort whatever's left.
        let drained =
            tokio::time::timeout(Duration::from_secs(SHUTDOWN_DRAIN_TIMEOUT_SECS), async {
                while tasks.join_next().await.is_some() {}
            })
            .await;
        if drained.is_err() {
            eprintln!(
                "[SAACP Daemon] Drain timeout ({}s) exceeded — aborting {} in-flight connection(s)",
                SHUTDOWN_DRAIN_TIMEOUT_SECS,
                tasks.len(),
            );
            tasks.abort_all();
            while tasks.join_next().await.is_some() {}
        }

        // Plan item 2b: wait for the health/metrics server to shut
        // down. The health server is bound to the same `shutdown`
        // token, so it will return on its own within microseconds of
        // the cancel; this await just joins the task so we don't leave
        // a zombie task on the runtime.
        #[cfg(feature = "health-endpoint")]
        if let Some(h) = health_handle {
            let _ = h.await;
        }

        // longcat.md Step 4: join the opt-in auto-ack task — it returned on
        // the same shutdown token cancel; awaiting it here keeps the
        // no-task-outlives-`start_with_shutdown` invariant.
        if let Some(h) = autoack_handle {
            let _ = h.await;
        }

        // Terminal step (R-2's stated sequence: "stop accepting → drain → flush WAL → exit").
        // `ImmutableAuditLog::flush` is a std blocking call — run it off the async executor.
        // Gap B / longcat.md Step 2: flush THIS daemon's audit chain (the
        // context's log when configured; the shared default — which aliases the
        // legacy process global — otherwise).
        let audit_for_flush = std::sync::Arc::clone(
            &crate::context::SaacpContext::or_shared_default(self.context.as_deref()).audit,
        );
        let flushed = tokio::task::spawn_blocking(move || {
            audit_for_flush.flush(Duration::from_secs(
                crate::security::AUDIT_FLUSH_ON_SHUTDOWN_TIMEOUT_SECS,
            ))
        })
        .await
        .unwrap_or(false);
        if !flushed {
            eprintln!("[SAACP Daemon] WAL flush on shutdown did not confirm in time");
        }

        Ok(())
    }

    /// Derive the server's Ed25519 verifying key from the seed (32 bytes → 32-byte VK).
    /// Returns `None` if server auth is not configured.
    pub fn server_verifying_key(&self) -> Option<[u8; 32]> {
        use ed25519_dalek::SigningKey;
        self.server_ed25519_seed
            .map(|seed| SigningKey::from_bytes(&seed).verifying_key().to_bytes())
    }
}

// ─── handle_client ───────────────────────────────────────────────────────────

/// Per-connection async handler (mirrors Python SAACPNetworkDaemon.handle_client).
///
/// Generic over any duplex byte stream (`AsyncRead + AsyncWrite`), not just
/// `TcpStream`. This lets the same handshake/framing/gate-pipeline logic run
/// unmodified over a tunneled transport (e.g. `transport::ws::WsByteStream`
/// behind the `transport-ws` feature) — only the byte source/sink differs; the
/// MEASC header parsing, MTU assembly, and gate dispatch below are identical.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_client<S>(
    mut stream: S,
    peer_addr: SocketAddr,
    circuit_breakers: SharedCircuitBreakers,
    // DAEMON-NO-TOKEN-VERIFY fix: previously received but never read (hence the leading
    // underscore) — the structural default path still ignores it (matching today's exact
    // behavior), but the `gateway`-opted-in branches below now use it as the stable,
    // out-of-band Gate 1.0 issuer-secret fallback instead of the ephemeral per-connection
    // ECDH `session_key`, since coupling token validity to a key that changes every
    // reconnect would be a fragile, unintended design.
    token_issuer_secret: Option<Vec<u8>>,
    server_ed25519_seed: Option<[u8; 32]>,
    gateway: Option<Arc<crate::gateway::ZeroTrustGateway>>,
    epoch_manager: Option<Arc<SessionEpochManager>>,
    on_delivered: Option<Arc<dyn Fn(ParsedPacket) + Send + Sync>>,
    // C-3 fix: `Some(server_agent_id)` requires the connecting client to present an
    // `AgentIdentityCertificate` + proof-of-possession during the ECDH handshake (see
    // `SAACPNetworkDaemon::with_identity_binding`). `None` preserves today's exact
    // handshake wire format and behavior.
    server_agent_id: Option<String>,
    // Phase 6 / item 4: see the `gossip` field doc comment on `SAACPNetworkDaemon`.
    gossip: Option<Arc<crate::gossip::GossipEngine>>,
    // Active-Active clustering: see the `cluster` field doc comment on `SAACPNetworkDaemon`.
    cluster: Option<Arc<crate::cluster::ClusterEngine>>,
    // F12: per-deployment handshake-timeout override; `None` = const defaults.
    handshake_timeout_override: Option<f64>,
    // Phase 4: explicit pipeline context; `None` = shared default.
    context: Option<Arc<crate::context::SaacpContext>>,
    // M4 (R2 / opusreview.md): optional global in-flight payload byte budget
    // (permits = bytes). `None` = unbounded (pre-M4 behavior).
    inflight_payload_semaphore: Option<Arc<Semaphore>>,
    // M12 (R3 / opusreview.md): optional bound on concurrent gate-pipeline
    // executions. `None` = unbounded tokio blocking pool (pre-M12 behavior).
    pipeline_semaphore: Option<Arc<Semaphore>>,
    // M11 (R7 / opusreview.md): this node's fleet-unique id; read together with
    // the affinity tracker below (both `Some` = tracking enabled).
    node_id: Option<String>,
    // M11 (R7 / opusreview.md): session-affinity tracker (AlertOnly enforcement).
    session_affinity_tracker: Option<Arc<crate::session_affinity::SessionAffinityTracker>>,
    // M11 hardening (Phase 3): what to do when the tracker reports a violation.
    affinity_violation_policy: crate::session_affinity::AffinityViolationPolicy,
) where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send,
{
    let ip_key = peer_addr.ip().to_string();
    let ip_trust_key = ip_trust_key(&ip_key);

    // Gap B completion (longcat.md Step 2): resolve this connection's context
    // ONCE and route every per-connection security decision through it —
    // IP-level trust gating, revocation-epoch pinning, hard-drop penalties,
    // and C-3 identity-gate bookkeeping. `None` resolves to the shared
    // default, whose fields alias the exact legacy process globals, so an
    // unconfigured daemon is byte-identical to the pre-context behavior; a
    // hermetic `with_context` daemon now stays strictly on its own tenant's
    // engines. Previously the sites below silently hit the process globals —
    // including the IP-trust penalize on the hard-drop path, which was a
    // cross-tenant leak (one tenant's abusive peer polluted every other
    // tenant's trust state in the same process).
    let conn_ctx: &crate::context::SaacpContext =
        crate::context::SaacpContext::or_shared_default(context.as_deref());
    // The gateway Gate 1.0 will actually consult for this connection: the
    // daemon-injected one when configured, else the context's revocation
    // fallback. Revocation-epoch bookkeeping must observe the same gateway the
    // gate pipeline validates tokens against, not always the process global.
    let connection_gateway: &crate::gateway::ZeroTrustGateway = gateway
        .as_deref()
        .unwrap_or_else(|| conn_ctx.gateway.as_ref());

    // ── Step 0: Circuit breaker check ────────────────────────────────────────
    {
        // L-18 fix: `parking_lot::Mutex` never poisons, so the H-22 poison-recovery
        // dance this call site used to need (`.unwrap_or_else(|e| e.into_inner())`) is
        // gone — a panic elsewhere while holding this lock can no longer cascade into
        // every future connection's Step 0 check panicking too.
        let cbs = circuit_breakers.lock();
        if let Some(entry) = cbs.get(&ip_key) {
            if entry.is_locked() {
                // Silent drop — no response, no logging (DDoS defence)
                return;
            }
        }
    }

    // ── Step 0b: IP-level behavioral trust check (identity-rotation defense) ──
    // `TrustDecayEngine` (trust_decay.rs) is keyed by the packet's claimed
    // agent identity (`current_agent_name` / capability-token `iss`), by
    // design — it tracks *behavior*, not identity, and assumes identity
    // itself is already stable. But a connection's `pinned_agent` resets to
    // `None` on every hard drop (see below), so a caller that holds (or has
    // compromised) signing credentials for more than one agent identity —
    // or is simply relying on a single shared issuer secret with no
    // per-issuer registry configured, in which case `iss` is a free-form
    // self-chosen claim — can "launder" its accumulated trust penalty by
    // claiming a fresh identity on its next packet, resetting straight back
    // to `TRUST_SCORE_INITIAL`. That defeats the entire point of a
    // *continuous* behavioral signal. The one thing that can't be rotated
    // away for free is the underlying network endpoint, so this tracks a
    // second, independent trust bucket keyed by IP (namespaced via
    // `ip_trust_key` so it can never collide with a real agent_id in the same
    // map) and rejects new connection attempts from an IP whose accumulated
    // distrust has crossed the reauth floor — regardless of what identity it
    // claims next. Checked once per connection (mirroring the IP circuit
    // breaker's own check above, which is likewise only evaluated at connect
    // time, not per-packet) and penalized on every hard drop below.
    if conn_ctx.trust.requires_reauth(&ip_trust_key) {
        // Silent drop — no response, no logging (same DDoS-defence rationale
        // as the circuit breaker check above: don't give a probing attacker
        // a distinguishable signal for which defense tripped).
        return;
    }

    // ── Step 1: X25519 ECDH handshake with a DDoS timeout ─────────────────────
    let handshake_timeout_secs = match handshake_timeout_override {
        Some(t) if server_agent_id.is_none() => t,
        _ if server_agent_id.is_some() => IDENTITY_BINDING_HANDSHAKE_TIMEOUT_SECS,
        _ => HANDSHAKE_TIMEOUT_SECS,
    };
    let (session_key, verified_identity) = match timeout(
        Duration::from_secs_f64(handshake_timeout_secs),
        ecdh_handshake(
            &mut stream,
            server_ed25519_seed,
            server_agent_id.as_deref(),
            conn_ctx.identity_gate.as_ref(),
        ),
    )
    .await
    {
        Ok(Ok(k)) => k,
        _ => {
            record_error(&circuit_breakers, &ip_key);
            return;
        }
    };

    // C-3: the session_id every subsequent packet header on this connection must carry.
    // `None` unless this daemon opted into identity binding (`with_identity_binding`).
    let bound_session_id: Option<[u8; 16]> = verified_identity.as_ref().map(|v| v.session_id);
    if let Some(ref v) = verified_identity {
        eprintln!(
            "[SAACP Daemon] {peer_addr}: C-3 identity-bound as agent '{}'",
            v.agent_id
        );
    }

    // Identity pinning state (VULN-04) — deliberately NOT pre-seeded from
    // `verified_identity`, even though the agent is already cryptographically known at
    // this point. `pinned_agent` doubles as `target_agent` fed into Gate 1.0's
    // `validate_lateral_movement` (`current_agent_name` below), which enforces a
    // self-issue guard rejecting any token whose `iss` equals `target_agent`. Pre-pinning
    // to the proven agent_id would make a well-behaved agent's own correctly-self-named
    // token collide with that guard on its very first packet. Identity binding is instead
    // enforced independently and unconditionally in `handler.rs`'s Gate 1.0 — by comparing
    // the token's claimed `source_agent` against the `TranscriptBoundSession` registered
    // for this connection's session_id — so bootstrap pinning here is untouched.
    let mut pinned_agent: Option<String> = None;
    let mut last_validated_at: Option<Instant> = None;
    // M11 (R7): first-affinity-violation-only log guard — while a mis-routed
    // session keeps arriving, every packet still feeds `record_error`, but the
    // human-readable alert fires at most once per connection.
    let mut affinity_violation_reported = false;
    // Track the revocation epoch at the time of last successful validation.
    // If the global epoch advances (i.e. all tokens are revoked), this connection
    // must be disconnected — continuing would accept a revoked token.
    let mut pinned_revocation_epoch: u64 = connection_gateway.get_revocation_epoch();

    // ── C-3 Identity Gate ──────────────────────────────────────────────────────
    // NOTE: no phase is advanced here at connection-init time beyond what
    // `ecdh_handshake` itself already advanced (IDENTITY_VERIFIED, only when identity
    // binding is configured). A previous version of this code called
    // `GLOBAL_IDENTITY_GATE.advance("unknown", ..., "connection_init")`, but
    // `"connection_init"` is not one of the six canonical `IDENTITY_GATE_PHASES`
    // (`identity_binding.rs`) — `advance()` rejects unknown phase names and returns
    // `Err`, which the `let _ = ...` silently discarded. That call had done nothing,
    // ever, since it was written: recording "unknown" as having completed a phase
    // before any authentication has even happened would itself be a false security
    // signal, not a fix, so it is removed outright rather than patched to a real phase
    // name. AUTHORIZED is advanced below, once Gate 1.0 has actually validated a
    // capability token for this connection (`handler.rs`).

    // ── Step 2: Persistent connection loop ────────────────────────────────────
    // Phase 3 / P-6 fix: `payload_buf` used to be freshly allocated
    // (`vec![0u8; n]`) on every single iteration of this loop — one heap
    // allocation per packet, for the lifetime of a persistent connection that
    // may carry thousands of packets. It is now allocated once per connection
    // and reused: `.clear()` drops the logical length to 0 (capacity is
    // retained, no deallocation), and the subsequent `.resize(n, 0)` call only
    // grows the backing allocation if a later packet needs more capacity than
    // any prior one on this connection — reallocating strictly less often
    // than "always". `.resize(n, 0)` after `.clear()` explicitly zero-fills
    // every byte up to the new length, so no stale data from a previous
    // packet on this connection can ever be read through the reused buffer
    // (Part 12 principle 9, "Monotonic Security" — no cross-packet
    // information leak via a dirty buffer).
    //
    // `full_packet` is NOT reused the same way: it is moved into
    // `tokio::task::spawn_blocking`'s `'static` closure below (required since
    // that closure may run on a different OS thread), so ownership must
    // transfer out of this loop's scope every iteration — a persistent
    // outer-scope binding would be moved-from after the first iteration and
    // fail to compile on the next `.clear()`. It keeps its original
    // fresh-per-iteration allocation.
    let mut payload_buf: Vec<u8> = Vec::new();
    // S1 fix: per-connection cap on DISTINCT header session_ids this
    // connection may auto-create in the epoch manager. A legitimate
    // connection multiplexes very few sessions; one that presents a new
    // random session_id per packet is filling the global session table with
    // pre-authentication junk (the unbounded-growth DoS). Exceeding the cap
    // closes the connection — the correct response to header spam. The
    // global cap (`MEASC_MAX_TRACKED_SESSIONS`) and the idle reaper bound
    // the process as a whole.
    let mut created_session_ids: std::collections::HashSet<[u8; 16]> =
        std::collections::HashSet::new();
    const MAX_SESSIONS_PER_CONNECTION: usize = 16;
    loop {
        // 2a. Read 128-byte header with 2s timeout
        let mut header_buf = [0u8; HEADER_SIZE];
        match timeout(Duration::from_secs(2), stream.read_exact(&mut header_buf)).await {
            Ok(Ok(_)) => {}
            _ => break, // Connection closed or timeout
        }

        // 2b. Parse payload_length from header bytes [12..16]
        let payload_length =
            u32::from_be_bytes(header_buf[12..16].try_into().unwrap_or([0u8; 4])) as usize;

        if payload_length > MAX_PAYLOAD_SIZE {
            send_hard_drop(
                &mut stream,
                SAACPBytecodes::PayloadTooLarge,
                "Payload exceeds 10MB MTU",
            )
            .await;
            record_error(&circuit_breakers, &ip_key);
            break;
        }

        // M4 (R2): reserve this packet's `payload_length` bytes from the global
        // in-flight payload budget BEFORE allocating the assembly buffer. `None`
        // (no budget configured) preserves the unbounded behavior exactly. The
        // permit is held to the end of this loop iteration (packet fully
        // assembled and dispatched), so the semaphore bounds AGGREGATE in-flight
        // payload memory across ALL connections. Budget exhausted ⇒ reject with
        // `PayloadTooLarge` (fail closed) and feed the per-IP error counter.
        // `try_acquire_many_owned` (non-blocking) matches M4's "reject, don't
        // queue" design: waiting would let one connection stall all others.
        let _inflight_permit: Option<tokio::sync::OwnedSemaphorePermit> =
            match inflight_payload_semaphore.as_ref() {
                Some(sem) => match sem.clone().try_acquire_many_owned(payload_length as u32) {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        send_hard_drop(
                            &mut stream,
                            SAACPBytecodes::PayloadTooLarge,
                            "Global in-flight payload budget exhausted",
                        )
                        .await;
                        record_error(&circuit_breakers, &ip_key);
                        break;
                    }
                },
                None => None,
            };

        // 2c. MTU chunking assembly with MAX_ASSEMBLY_TIME aggregate timeout
        // payload_length <= MAX_PAYLOAD_SIZE (10 MB); +16 for auth tag is safe.
        let assembly_start = Instant::now();
        payload_buf.clear();
        // opusplan.md 6.6 fix: release an oversized allocation left behind by a prior
        // outlier-large packet on this connection, but only when the buffer is already
        // over the steady-state ceiling AND this packet doesn't need that much room —
        // so ordinary traffic never reallocates and P-6's buffer-reuse win is preserved.
        let needed_len = payload_length.saturating_add(16);
        if payload_buf.capacity() > CONNECTION_BUFFER_STEADY_STATE_CAP
            && needed_len <= CONNECTION_BUFFER_STEADY_STATE_CAP
        {
            payload_buf.shrink_to(CONNECTION_BUFFER_STEADY_STATE_CAP);
        }
        payload_buf.resize(needed_len, 0);
        let mut bytes_read = 0usize;

        while bytes_read < payload_buf.len() {
            if assembly_start.elapsed().as_secs_f64() > MAX_ASSEMBLY_TIME {
                send_hard_drop(
                    &mut stream,
                    SAACPBytecodes::TemporalTimeout,
                    "MTU assembly timeout",
                )
                .await;
                record_error(&circuit_breakers, &ip_key);
                return;
            }
            match timeout(
                Duration::from_secs(1),
                stream.read(&mut payload_buf[bytes_read..]),
            )
            .await
            {
                Ok(Ok(0)) => break, // EOF
                Ok(Ok(n)) => bytes_read += n,
                _ => break,
            }
        }

        // Assemble full frame: header || auth_tag || ciphertext
        let mut full_packet = Vec::with_capacity(HEADER_SIZE + bytes_read);
        full_packet.extend_from_slice(&header_buf);
        full_packet.extend_from_slice(&payload_buf[..bytes_read]);

        // 2d0. C-3 session-splice defense: when this connection is identity-bound, every
        // packet's header session_id (bytes 16..32) must equal the one committed — and
        // proof-of-possession signed — during the handshake. Without this check, a
        // connection that proved identity X at handshake time could present a different
        // session_id per packet, silently bypassing the Gate 1.0 identity cross-check in
        // `handler.rs` (which looks up the registered `TranscriptBoundSession` by
        // session_id: an unregistered session_id simply skips the check).
        if let Some(bound_sid) = bound_session_id {
            let packet_sid: Option<[u8; 16]> =
                full_packet.get(16..32).and_then(|s| s.try_into().ok());
            if packet_sid != Some(bound_sid) {
                send_hard_drop(
                    &mut stream,
                    SAACPBytecodes::SessionSpliceDetected,
                    "Packet session_id does not match identity-bound handshake session_id",
                )
                .await;
                record_error(&circuit_breakers, &ip_key);
                break;
            }
        }

        // M11 (R7): session-affinity record/check — policy per
        // `AffinityViolationPolicy` (Phase 3). When this node has a node_id +
        // tracker configured (fleet deployment), every packet's header
        // session_id (bytes 16..32) is checked against the node that first
        // recorded it. A mismatch proves a non-affine load balancer is
        // silently degrading replay protection (the 4096-entry PSN window is
        // node-local BY DESIGN — see state_backend.rs's "out of scope"
        // section).
        // AlertOnly (default): log once per connection + feed the per-IP
        // error counter so a persistently mis-routed peer trips the existing
        // IP circuit breaker; the packet itself is still processed (detection
        // must not become a self-inflicted outage before the operator has
        // seen the signal). HardDrop: additionally terminate the connection
        // (fail closed).
        if let (Some(tracker), Some(node)) = (session_affinity_tracker.as_ref(), node_id.as_deref())
        {
            if let Some(sid_bytes) = full_packet.get(16..32) {
                if let Ok(sid) = <[u8; 16]>::try_from(sid_bytes) {
                    if let Err(violation) = tracker.record_session(&sid, node) {
                        // Count + alert under BOTH policies (Phase 3): the
                        // policy only decides whether the connection is
                        // additionally hard-dropped, never whether the
                        // detection is counted or surfaced.
                        conn_ctx.telemetry.record_session_affinity_violation();
                        conn_ctx.alerts.record(crate::telemetry::SecurityAlert {
                            timestamp: crate::clock::now_secs_f64(),
                            agent_id: peer_addr.to_string(),
                            gate: "session_affinity",
                            bytecode: SAACPBytecodes::SessionSpliceDetected.to_string(),
                            estimated_cost: None,
                        });
                        if !affinity_violation_reported {
                            affinity_violation_reported = true;
                            eprintln!("[SAACP Daemon] {peer_addr}: {violation}");
                        }
                        record_error(&circuit_breakers, &ip_key);
                        if affinity_violation_policy
                            == crate::session_affinity::AffinityViolationPolicy::HardDrop
                        {
                            // Reuses the existing SessionSpliceDetected
                            // bytecode (same PECF external class: session
                            // terminated) — no wire-format surface changes.
                            send_hard_drop(
                                &mut stream,
                                SAACPBytecodes::SessionSpliceDetected,
                                "Session affinity violation — this node did not create the \
                                 session; reconnect via the session-affine entry node",
                            )
                            .await;
                            break;
                        }
                    }
                }
            }
        }

        // 2d. Revocation epoch pinning check (C1 fix).
        // If the global revocation epoch has advanced since this connection last
        // validated, all previously-accepted tokens are revoked. Force disconnect
        // so the client must re-authenticate with a fresh token.
        {
            let current_rev = connection_gateway.get_revocation_epoch();
            if pinned_agent.is_some() && current_rev > pinned_revocation_epoch {
                send_hard_drop(
                    &mut stream,
                    SAACPBytecodes::KeyRevoked,
                    "Global token revocation — reconnect and re-authenticate",
                )
                .await;
                break;
            }
            // Periodic re-validation timestamp update
            if let Some(validated_at) = last_validated_at {
                if validated_at.elapsed().as_secs_f64() >= TOKEN_REVALIDATION_INTERVAL_SECS {
                    last_validated_at = Some(Instant::now());
                    pinned_revocation_epoch = current_rev;
                }
            }
        }

        // 2e. Route to handler pipeline — H-1 fix: run CPU-bound gate work on the
        // blocking thread pool so we don't starve tokio I/O workers.
        // AES-GCM, SHA-256, Ed25519 verify, NFKC normalization, DFS graph traversal,
        // and the injection scanner (up to 3.1ms at 50KB) are all synchronous CPU work.
        let start = Instant::now();
        let agent_name = pinned_agent.as_deref().unwrap_or("unknown").to_string();
        let is_pinned = pinned_agent.is_some();

        // DAEMON-NO-AEAD / DAEMON-NO-TOKEN-VERIFY fix: when the daemon was built with
        // `.with_encrypted_transport(...)`/`.with_gateway(...)`, lazily create the epoch-0
        // session for this packet's session_id (bytes [16..32] of the header) on first
        // sight, then route through the real-AEAD `intercept_packet_encrypted` /
        // `intercept_packet_full` instead of the structural-only `intercept_packet`.
        // `epoch_manager`/`gateway` both `None` (the default) preserves today's exact
        // existing behavior byte-for-byte.
        //
        // `gate_secret` is the stable, out-of-band `token_issuer_secret` this daemon was
        // constructed with, used as Gate 1.0's issuer-secret fallback and to HMAC-bind audit
        // entries — deliberately NOT the ephemeral per-connection ECDH `session_key`, which
        // changes every reconnect and would make token validity fragile if coupled to it.
        // Falls back to `session_key` only if the daemon has no configured issuer secret
        // (keeps `with_gateway`-without-a-configured-secret at least self-consistent rather
        // than panicking on an empty slice).
        let gate_secret: Vec<u8> = token_issuer_secret
            .clone()
            .unwrap_or_else(|| session_key.to_vec());
        // L-16 fix: `session_key` itself is `Zeroizing<[u8; 32]>` and lives for the whole
        // connection, so it must never be moved into a per-iteration `move` closure (that
        // would drop-and-zeroize it after the first packet, breaking every later packet on
        // this same connection). Take a plain `Copy` snapshot of the raw bytes instead —
        // ephemeral per-packet copies handed to the short-lived gate pipeline below are the
        // same exposure this codebase already accepts for e.g. `KeyEvolutionEngine`'s
        // per-epoch derived keys; what L-16 protects is the long-lived top-level binding.
        let session_key_bytes: [u8; 32] = *session_key;

        // M-18 fix: `on_delivered` is invoked from INSIDE the `spawn_blocking`
        // closures below (immediately after a successful intercept, still on
        // the blocking-pool thread), not after `.await` back on the async
        // executor as it was previously. The field doc comment on
        // `SAACPNetworkDaemon::on_delivered` has always documented "called
        // from inside spawn_blocking, so implementations must not .await" —
        // this makes that contract true instead of aspirational. Previously,
        // any `on_delivered` implementation that did even a small blocking
        // operation (the doc comment's own stated allowance) would have
        // stalled a tokio worker thread rather than a dedicated blocking-pool
        // thread. `sidecar.rs`'s implementation (`tx.try_send(msg)`) already
        // relied on exactly this non-blocking guarantee; this fix makes the
        // guarantee real for any future implementation too.
        let on_delivered_for_task = on_delivered.clone();

        // M12 (R3): bound concurrent gate-pipeline executions. `None` (unset)
        // preserves the unbounded tokio blocking-pool behavior exactly. The
        // permit is held across the `spawn_blocking(...).await` below (to the
        // end of this loop iteration), so the semaphore caps how many packets
        // execute gates concurrently instead of growing an unbounded blocking
        // queue. A closed semaphore (runtime shutdown) hard-drops — fail closed.
        let _pipeline_permit: Option<tokio::sync::OwnedSemaphorePermit> =
            match pipeline_semaphore.as_ref() {
                Some(sem) => match sem.clone().acquire_owned().await {
                    Ok(permit) => Some(permit),
                    Err(_) => {
                        send_hard_drop(
                            &mut stream,
                            SAACPBytecodes::CircuitBreakerOpen,
                            "Gate pipeline closed",
                        )
                        .await;
                        break;
                    }
                },
                None => None,
            };

        let intercept_result = if let Some(epoch_mgr) = epoch_manager.clone() {
            let session_id: [u8; 16] = full_packet
                .get(16..32)
                .and_then(|s| <[u8; 16]>::try_from(s).ok())
                .unwrap_or([0u8; 16]);
            if epoch_mgr.get_current_epoch_id(&session_id).is_none() {
                // S1 fix: bound distinct auto-created sessions per connection
                // (see `created_session_ids` above) — exceeding the cap means
                // header spam, so close the connection.
                if created_session_ids.contains(&session_id) {
                    // Prior auto-create raced/failed; do not grow the set.
                } else if created_session_ids.len() >= MAX_SESSIONS_PER_CONNECTION {
                    send_hard_drop(
                        &mut stream,
                        SAACPBytecodes::CircuitBreakerOpen,
                        "Too many distinct session_ids from one connection",
                    )
                    .await;
                    record_error(&circuit_breakers, &ip_key);
                    break;
                } else {
                    // Idempotent: ignore "already exists" races from concurrent packets on
                    // the same not-yet-registered session_id — the loser just reuses the
                    // winner's session.
                    let _ = epoch_mgr.create_session(
                        session_id,
                        session_key_bytes,
                        crate::measc::MEASC_DEFAULT_EPOCH_PACKET_THRESHOLD,
                        crate::measc::MEASC_DEFAULT_EPOCH_TIME_SECONDS as f64,
                        None,
                    );
                    created_session_ids.insert(session_id);
                }
            }
            let gw_for_task = gateway.clone();
            let ctx_for_task = context.clone().unwrap_or_else(|| {
                std::sync::Arc::clone(crate::context::SaacpContext::shared_default_arc())
            });
            tokio::task::spawn_blocking(move || {
                let result = SAACPProtocolHandler::intercept_packet_encrypted_with_ctx(
                    &ctx_for_task,
                    &full_packet,
                    &epoch_mgr,
                    &gate_secret,
                    &agent_name,
                    is_pinned,
                    gw_for_task.as_deref(),
                    None,
                    None,
                );
                if let Ok(parsed) = &result {
                    if let Some(cb) = on_delivered_for_task.as_ref() {
                        cb(parsed.clone());
                    }
                }
                result
            })
            .await
        } else {
            let gw_for_task = gateway.clone();
            let ctx_for_task = context.clone().unwrap_or_else(|| {
                std::sync::Arc::clone(crate::context::SaacpContext::shared_default_arc())
            });
            tokio::task::spawn_blocking(move || {
                // Phase 4: both structural arms run on the daemon's context.
                // The `None`-gateway arm passes all-None injection params,
                // which is exactly `intercept_packet`'s contract, so no
                // separate `intercept_packet_with_ctx` shim is needed.
                let result = match gw_for_task.as_deref() {
                    Some(gw) => SAACPProtocolHandler::intercept_packet_full_with_ctx(
                        &ctx_for_task,
                        &full_packet,
                        &gate_secret,
                        &agent_name,
                        is_pinned,
                        Some(gw),
                        None,
                        None,
                        None,
                        None,
                    ),
                    None => SAACPProtocolHandler::intercept_packet_full_with_ctx(
                        &ctx_for_task,
                        &full_packet,
                        &session_key_bytes,
                        &agent_name,
                        is_pinned,
                        None,
                        None,
                        None,
                        None,
                        None,
                    ),
                };
                if let Ok(parsed) = &result {
                    if let Some(cb) = on_delivered_for_task.as_ref() {
                        cb(parsed.clone());
                    }
                }
                result
            })
            .await
        };
        // Flatten JoinError (panic in gate pipeline) into SAACPHardDrop
        let intercept_result = match intercept_result {
            Ok(inner) => inner,
            Err(_join_err) => Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "Gate pipeline task panicked",
            )),
        };
        match intercept_result {
            Ok(parsed) => {
                // Phase 6 / item 4: a schema_id=11 packet that cleared the full gate
                // pipeline (so it's a genuinely authenticated, non-cover-traffic frame) is
                // a Gossip Envelope — hand it to the configured `GossipEngine` instead of
                // (there is no further "application" handling for this schema; it carries
                // no task/action for an agent to execute). See the `gossip` field doc
                // comment for why this dispatches here rather than inside `handler.rs`.
                if let Some(engine) = gossip.as_ref() {
                    if parsed.schema_id == 11 {
                        if let Some(envelope) = decode_gossip_envelope(&parsed.payload_dict) {
                            engine.receive(envelope);
                        }
                    }
                }
                // Phase 6 / item 3 (IEVL, `ievl.rs`, Part 8.1): a schema_id=10 packet
                // that cleared the full gate pipeline is an `ExecutionReceipt` — hand
                // it to IEVL for verification against its matching `IntentDeclaration`
                // instead of further "application" handling (this schema carries no
                // task/action for an agent to execute). Mirrors the schema_id=11
                // gossip dispatch immediately above for the same reason: the
                // verification/enforcement decision needs the fully-authenticated
                // `ParsedPacket`, which only exists after Gate 0 through Gate 12.0
                // have all already passed. Unlike gossip, always active (no opt-in
                // engine to configure) — see `ievl::handle_execution_receipt`'s doc
                // comment.
                if parsed.schema_id == 10 {
                    crate::ievl::handle_execution_receipt(&parsed);
                }
                // Active-Active clustering (`cluster.rs`): a schema_id=12 packet that
                // cleared the full gate pipeline is a `Cluster Envelope` — hand it to the
                // configured `ClusterEngine`. Mirrors the schema_id=11 gossip dispatch
                // above; see the `cluster` field doc comment for why clearing the gate
                // pipeline is necessary but not sufficient here (the engine re-verifies
                // the message's own signature, roster membership, freshness, and replay
                // window independently).
                if let Some(engine) = cluster.as_ref() {
                    if parsed.schema_id == crate::cluster::CLUSTER_SCHEMA_ID {
                        if let Some((blob, sender, epoch, kind)) =
                            decode_cluster_envelope(&parsed.payload_dict)
                        {
                            if let Err(reason) =
                                engine.receive_envelope(&blob, &sender, epoch, &kind)
                            {
                                // Rejections are logged, never answered — replying would
                                // give an attacker an oracle for which defense fired, and
                                // the sender is not a trusted party by definition. The
                                // `cluster_messages_rejected` counter is incremented by
                                // `receive_envelope` itself, so every transport gets it.
                                eprintln!(
                                    "[SAACP Daemon] Cluster message from '{}' rejected: {}",
                                    sender,
                                    reason.as_str(),
                                );
                            }
                        }
                    }
                }
                // Update pinning state
                if pinned_agent.is_none() && !parsed.source_agent.is_empty() {
                    // `parsed.source_agent` is `Arc<str>` (Phase 3 / M-13-style fix); this
                    // event fires at most once per connection (guarded by `pinned_agent.is_none()`),
                    // so a `.to_string()` here is a one-time allocation, not a per-packet cost.
                    pinned_agent = Some(parsed.source_agent.to_string());
                    last_validated_at = Some(Instant::now());
                    // Snapshot the current revocation epoch so future revocations
                    // trigger disconnect (C1 fix).
                    pinned_revocation_epoch = connection_gateway.get_revocation_epoch();
                    // C-3 Identity Gate bookkeeping: by the time `intercept_packet`
                    // returns `Ok`, Gate 1.0 (capability token validation) through
                    // Gate 12.0 have all already passed for this packet, so both
                    // "identity verified" and "authorized" are true facts about
                    // this (agent, session) pair. Use the real phase names from
                    // `IDENTITY_GATE_PHASES` — a prior version of this call used
                    // `"authenticated"`, which is not one of the six canonical
                    // phases and silently failed every single time (see the
                    // removed connection-init call above for the same bug).
                    let _ = conn_ctx.identity_gate.advance(
                        &parsed.source_agent,
                        &parsed.session_uuid,
                        "IDENTITY_VERIFIED",
                    );
                    let _ = conn_ctx.identity_gate.advance(
                        &parsed.source_agent,
                        &parsed.session_uuid,
                        "AUTHORIZED",
                    );
                }

                // Route response by status code
                let response = if parsed.is_cover_traffic {
                    WIRE_SUCCESS
                } else {
                    match parsed.status_code {
                        0x17 => WIRE_STREAM_ACK, // STREAM_START / CONTINUATION
                        0x18 => WIRE_STREAM_ACK,
                        0x19 => WIRE_STREAM_END_ACK, // STREAM_END
                        0x08 => {
                            // INPUT_REQUIRED → yield + close. M3-authenticated like
                            // every other ack (see the authed write below).
                            let mut authed =
                                Vec::with_capacity(WIRE_YIELD_ASYNC.len() + RESPONSE_MAC_LEN);
                            authed.extend_from_slice(WIRE_YIELD_ASYNC);
                            authed.extend_from_slice(&compute_response_mac(
                                &session_key_bytes,
                                WIRE_YIELD_ASYNC,
                            ));
                            let _ = stream.write_all(&authed).await;
                            break;
                        }
                        _ => WIRE_SUCCESS,
                    }
                };

                // M3 (R1): response authentication — the plaintext ack is
                // forgeable by an active MITM. Append an HMAC-SHA256 tag over
                // the ack, keyed by the ECDH session root key, so only a peer
                // that completed the handshake can produce/verify a valid ack
                // (the sidecar verifies this — see sidecar.rs's ack read).
                let mut authed = Vec::with_capacity(response.len() + RESPONSE_MAC_LEN);
                authed.extend_from_slice(response);
                authed.extend_from_slice(&compute_response_mac(&session_key_bytes, response));
                if stream.write_all(&authed).await.is_err() {
                    break;
                }
            }
            Err(drop) => {
                // PECF error translation + SREL timing equalization
                SREL::equalize_timing(start).await;
                let ext = internal_to_external_raw(drop.bytecode as u8);
                // Wire format requires a real 32-hex-char correlation ID (spec §9.3);
                // an empty string both violates that contract and previously produced
                // a zero-filled correlation_id region on the wire (silently in release
                // builds, via a debug_assert panic in debug/test builds).
                let wire = SREL::normalize_response(ext, &generate_correlation_id());
                let _ = stream.write_all(&wire).await;
                // Clear pinned state on hard drops
                pinned_agent = None;
                last_validated_at = None;
                record_error(&circuit_breakers, &ip_key);
                // IP-level trust penalty (identity-rotation defense — see the
                // Step 0b comment above): applied unconditionally on every
                // hard drop, independent of whatever identity this packet
                // claimed, so switching identities cannot reset it.
                // Gap B: penalize THIS context's trust engine — penalizing the
                // process global was the longcat.md cross-tenant leak (one
                // hermetic tenant's hostile peer poisoned every tenant's IP
                // trust bucket in the same process).
                let _ = conn_ctx.trust.penalize(
                    &ip_trust_key,
                    crate::trust_decay::PenaltyKind::GenericHardDrop,
                );
                // Most hard drops are non-fatal; loop continues.
                // Fatal drops (epoch expired, etc.) close the connection.
                match drop.bytecode {
                    SAACPBytecodes::EpochExpired
                    | SAACPBytecodes::InvalidSignature
                    | SAACPBytecodes::PsnReplayDetected => break,
                    _ => {}
                }
            }
        }
    }
}

// ─── X25519 ECDH handshake ───────────────────────────────────────────────────

/// Perform X25519 ECDH key exchange and derive a 32-byte AES-GCM session key.
///
/// ## Unauthenticated mode (server_ed25519_seed = None)
/// Classic ECDH — no peer authentication. Vulnerable to active MITM.
///   Client → Server: [x25519_pub(32)]
///   Server → Client: [x25519_pub(32)]
///
/// ## Authenticated mode (server_ed25519_seed = Some(seed))
/// Server signs `client_nonce || server_x25519_pub` with its Ed25519 identity key.
/// The nonce ensures every handshake signature is unique — capturing a previous
/// server message and replaying it against a new connection will fail because the
/// nonce the server signs won't match what the client sent this time.
///
/// Wire protocol (C2 fix — nonce added for freshness):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] || [ed25519_sig(64)] || [ed25519_vk(32)] = 128B
///     where sig = Ed25519.sign(client_nonce || server_x25519_pub)
///
/// Unauthenticated mode (no seed):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
///
/// The client nonce is also mixed into HKDF as the salt so every session key
/// is unique even if the X25519 shared secret is somehow repeated.
///
/// ## C-3 identity binding mode (`identity_binding_server_agent_id = Some(..)`)
/// Requires `with_identity_binding` on the daemon (which also forces
/// `server_ed25519_seed = Some`). The client message grows to additionally carry:
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] || [session_id(16)]
///                    || [cert_len(u32 LE, 4)] || [cert_json(cert_len)] || [pop_sig(64)]
/// where `pop_sig` = Ed25519.sign(client_nonce || client_x25519_pub || session_id) made
/// with the private key certified in `cert_json` (an `AgentIdentityCertificate`). This
/// proves possession of the agent's long-term identity key — something a stolen bearer
/// capability token alone can never produce — closing the gap where any holder of a
/// leaked token could otherwise impersonate the agent it names. On success, a
/// `TranscriptBoundSession` is registered in `identity_binding::DEFAULT_IDENTITY_REGISTRY`
/// keyed by this `session_id`, and `IDENTITY_VERIFIED` is advanced for
/// (agent_id, session_id) in the caller-supplied identity gate (Gap B /
/// longcat.md Step 2 — per-connection context scoping; the shared default
/// continues to alias the legacy `GLOBAL_IDENTITY_GATE` instance). The
/// session registry itself stays process-global: `handler.rs`'s Gate 1.0
/// cross-check reads the same registry, so scoping it per context would
/// sever that cross-check from this connection-init registration path. See
/// `handler.rs`'s Gate 1.0 for the corresponding capability-token cross-check.
async fn ecdh_handshake<S>(
    stream: &mut S,
    server_ed25519_seed: Option<[u8; 32]>,
    identity_binding_server_agent_id: Option<&str>,
    identity_gate: &crate::identity_binding::IdentityGate,
) -> Result<(Zeroizing<[u8; 32]>, Option<VerifiedClientIdentity>), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    // Step 1: Read client's nonce (32B) + X25519 public key (32B)
    let mut client_msg = [0u8; 64];
    stream.read_exact(&mut client_msg).await.map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader,
            "Handshake read (nonce+key) failed",
        )
    })?;
    let client_nonce: [u8; 32] = client_msg[0..32].try_into().unwrap();
    let peer_pub_bytes: [u8; 32] = client_msg[32..64].try_into().unwrap();

    // Step 1b: When identity binding is required, read the extended identity block and
    // verify the certificate + proof-of-possession before proceeding with the DH exchange.
    let pending_identity = if let Some(server_agent_id) = identity_binding_server_agent_id {
        let mut fixed = [0u8; 16 + 4];
        stream.read_exact(&mut fixed).await.map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing,
                "Identity handshake block (session_id + cert_len) missing",
            )
        })?;
        let session_id: [u8; 16] = fixed[0..16].try_into().unwrap();
        let cert_len = u32::from_le_bytes(fixed[16..20].try_into().unwrap()) as usize;

        // Bound the certificate size to prevent unbounded allocation from a malicious peer.
        const MAX_CERT_JSON_BYTES: usize = 16_384;
        if cert_len == 0 || cert_len > MAX_CERT_JSON_BYTES {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing,
                "Identity certificate length out of bounds",
            ));
        }

        let mut cert_buf = vec![0u8; cert_len];
        stream.read_exact(&mut cert_buf).await.map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing,
                "Identity certificate read failed",
            )
        })?;
        let mut pop_sig_buf = [0u8; 64];
        stream.read_exact(&mut pop_sig_buf).await.map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing,
                "Proof-of-possession signature read failed",
            )
        })?;

        let cert_json = std::str::from_utf8(&cert_buf).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityBindingMissing,
                "Identity certificate is not valid UTF-8",
            )
        })?;
        let cert = crate::identity_binding::AgentIdentityCertificate::from_json(cert_json)
            .map_err(|_| {
                SAACPHardDrop::new(
                    SAACPBytecodes::IdentityBindingMissing,
                    "Identity certificate is malformed",
                )
            })?;

        // Verify the CA signature, expiry, and revocation status.
        crate::identity_binding::DEFAULT_IDENTITY_VERIFIER.verify_certificate(&cert)?;

        // Verify proof-of-possession: the peer must sign this exact handshake's
        // (client_nonce || client_x25519_pub || session_id) with the certified key. Since
        // client_nonce is fresh random per connection, this cannot be precomputed or
        // replayed from a captured transcript — only possession of the actual private key
        // (never present in a bearer capability token) can produce a valid signature here.
        let cert_pk_bytes: [u8; 32] = hex::decode(&cert.public_key_hex)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| {
                SAACPHardDrop::new(
                    SAACPBytecodes::IdentityMisbinding,
                    "Identity certificate public key malformed",
                )
            })?;
        let cert_vk = VerifyingKey::from_bytes(&cert_pk_bytes).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "Identity certificate public key invalid",
            )
        })?;
        let mut pop_transcript = Vec::with_capacity(64 + 16);
        pop_transcript.extend_from_slice(&client_nonce);
        pop_transcript.extend_from_slice(&peer_pub_bytes);
        pop_transcript.extend_from_slice(&session_id);
        let pop_sig = Signature::from_bytes(&pop_sig_buf);
        if cert_vk.verify(&pop_transcript, &pop_sig).is_err() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "Proof-of-possession signature verification failed",
            ));
        }

        Some((cert, session_id, server_agent_id.to_string()))
    } else {
        None
    };

    // Step 2: Generate our ephemeral X25519 keypair
    let local_secret = EphemeralSecret::random_from_rng(OsRng);
    let local_pub = PublicKey::from(&local_secret);

    // Step 3: Send server's public key (with optional Ed25519 authentication)
    if let Some(seed) = server_ed25519_seed {
        // Sign client_nonce || server_x25519_pub so the signature is fresh and
        // bound to this specific client interaction (replay resistance).
        let signing_key = SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key();
        let mut to_sign = Vec::with_capacity(64);
        to_sign.extend_from_slice(&client_nonce);
        to_sign.extend_from_slice(local_pub.as_bytes());
        let sig = signing_key.sign(&to_sign);

        let mut auth_msg = Vec::with_capacity(128);
        auth_msg.extend_from_slice(local_pub.as_bytes());
        auth_msg.extend_from_slice(&sig.to_bytes());
        auth_msg.extend_from_slice(verifying_key.as_bytes());

        stream.write_all(&auth_msg).await.map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "Authenticated handshake write failed",
            )
        })?;
    } else {
        stream.write_all(local_pub.as_bytes()).await.map_err(|_| {
            SAACPHardDrop::new(SAACPBytecodes::MalformedHeader, "Handshake write failed")
        })?;
    }

    // Step 4: X25519 key agreement
    let peer_pub = PublicKey::from(peer_pub_bytes);
    let shared = local_secret.diffie_hellman(&peer_pub);

    // F5 fix (contributory check): an all-zero shared secret means the peer's
    // X25519 public key was a degenerate/low-order point (e.g. the identity).
    // HKDF over an all-zero IKM derives a key the ATTACKER can compute without
    // holding any discrete log — silently downgrading the exchange to no
    // secrecy at all. Reject instead of deriving from it.
    if !shared.was_contributory() {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "X25519 shared secret was not contributory (degenerate peer public key)",
        ));
    }

    // Step 5: HKDF-SHA256 key derivation.
    // Use the client nonce as salt so that even if the DH shared secret were
    // somehow repeated across sessions, each session derives a distinct key.
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;

    // Step 6: On successful identity binding, establish and register the
    // TranscriptBoundSession, then advance IDENTITY_VERIFIED. This runs only after the DH
    // exchange (and thus the handshake write above) has completed, but the certificate +
    // proof-of-possession were already verified in Step 1b before any server secret was
    // committed to the wire.
    let verified_identity = if let Some((cert, session_id, server_agent_id)) = pending_identity {
        let server_pub_hex = server_ed25519_seed
            .map(|seed| {
                let vk = SigningKey::from_bytes(&seed).verifying_key();
                hex::encode(vk.as_bytes())
            })
            .unwrap_or_default();
        let server_nonce: [u8; 32] = rand::random();

        let mut session = crate::identity_binding::TranscriptBoundSession::establish(
            session_id.to_vec(),
            &cert.agent_id,
            &server_agent_id,
            &cert.public_key_hex,
            &server_pub_hex,
            &hex::encode(client_nonce),
            &hex::encode(server_nonce),
            "SAACP/0.1-beta2",
            "Ed25519-AES256GCM",
            None,
        );
        session.mark_identity_verified();

        let agent_id = cert.agent_id.clone();
        let session_id_hex = hex::encode(session_id);
        crate::identity_binding::DEFAULT_IDENTITY_REGISTRY.register(session);
        let _ = identity_gate.advance(&agent_id, &session_id_hex, "IDENTITY_VERIFIED");

        Some(VerifiedClientIdentity {
            agent_id,
            session_id,
        })
    } else {
        None
    };

    // L-16 fix: wrap the raw handshake session key in `Zeroizing` so it's wiped from
    // memory the moment the caller's binding drops out of scope, instead of the 32
    // live key bytes lingering in freed heap/stack memory (recoverable via a core
    // dump, swap, or an unrelated use-after-free elsewhere in the process).
    Ok((Zeroizing::new(session_key), verified_identity))
}

/// Result of a successful C-3 identity-bound handshake (see `ecdh_handshake`'s doc
/// comment). `agent_id` is the certified identity proven via proof-of-possession;
/// `session_id` is the client-committed session identifier that every subsequent packet
/// header on this connection must match (enforced in `handle_client`).
pub(crate) struct VerifiedClientIdentity {
    pub agent_id: String,
    pub session_id: [u8; 16],
}

/// Client-side (initiator) counterpart of `ecdh_handshake`, unauthenticated mode only —
/// promotes the hand-rolled logic already proven correct in
/// `tests/test_transport_ws_rs.rs`'s `ws_client_handshake` (and this crate's own
/// `tests/test_daemon_encrypted_rs.rs::tcp_client_handshake`) into real library code, so
/// callers that need to dial *out* to a SAACP daemon (e.g. `sidecar.rs`) don't have to
/// hand-roll the wire protocol themselves. `daemon.rs` itself only ever plays the responder
/// role (`ecdh_handshake`); this is the first initiator-side implementation in the crate.
///
/// Ed25519 server-authentication mode (mirroring `ecdh_handshake`'s `server_ed25519_seed`
/// path) is only implemented when `identity` (below) is supplied — a client not opting into
/// C-3 identity binding still gets the plain unauthenticated read, matching today's exact
/// behavior byte-for-byte.
///
/// Wire protocol (unauthenticated mode, `identity = None` — must match `ecdh_handshake`'s
/// unauthenticated mode exactly):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] = 64B
///   Server → Client: [server_x25519_pub(32)] = 32B
///
/// Wire protocol (C-3 identity-bound mode, `identity = Some(..)` — must match
/// `ecdh_handshake`'s identity-binding mode exactly, and requires the target daemon be
/// built with `SAACPNetworkDaemon::with_identity_binding`):
///   Client → Server: [client_nonce(32)] || [client_x25519_pub(32)] || [session_id(16)]
///                    || [cert_len(u32 LE, 4)] || [cert_json(cert_len)] || [pop_sig(64)]
///   Server → Client: [server_x25519_pub(32)] || [ed25519_sig(64)] || [ed25519_vk(32)] = 128B
///
/// Returns `(session_key, session_id)` — `session_id` is `Some` only in identity-bound mode,
/// and is the value the caller must place in every subsequent MEASC packet header's
/// session_id field (bytes 16..32) — the daemon rejects any mismatch as a session-splice
/// attempt.
pub async fn client_handshake<S>(
    stream: &mut S,
    identity: Option<&ClientIdentityConfig>,
) -> Result<(Zeroizing<[u8; 32]>, Option<[u8; 16]>), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    client_handshake_inner(stream, identity, None).await
}

/// S5: `client_handshake` plus optional server-key PINNING for the plain
/// (non-identity-bound) mode. When `pinned_server_verifying_key` is `Some`
/// and `identity` is `None`, the target daemon must have been built with
/// `with_server_auth` (its server response is the full 128-byte
/// `[pub || sig || vk]` form): the signature is verified AND the verifying
/// key is compared against the pinned expectation — closing the
/// unauthenticated-server-pubkey gap for clients that do not use C-3
/// identity binding (e.g. pinned-appliance deployments, or a TLS tunnel
/// whose inner SAACP handshake should still authenticate the server key).
///
/// Mirrors exactly what the identity-bound path already does (see the
/// `vk_bytes != cfg.expected_server_verifying_key` check in
/// `client_handshake_inner`), so the two modes cannot drift.
pub async fn client_handshake_with_pinned_server<S>(
    stream: &mut S,
    identity: Option<&ClientIdentityConfig>,
    pinned_server_verifying_key: Option<[u8; 32]>,
) -> Result<(Zeroizing<[u8; 32]>, Option<[u8; 16]>), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    if identity.is_some() && pinned_server_verifying_key.is_some() {
        // Identity mode already pins via ClientIdentityConfig; refuse the
        // ambiguous both-set call rather than silently preferring one.
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding,
            "client_handshake: pass either identity (pins via its config) or \
             pinned_server_verifying_key, not both",
        ));
    }
    client_handshake_inner(stream, identity, pinned_server_verifying_key).await
}

/// S5 "prefer-pinned" client handshake: attempt the authenticated pinned-server
/// exchange, and transparently fall back to the plain (v1) ECDH handshake when
/// the responder speaks only the legacy 32-byte wire format.
///
/// Wire detection: both formats share the same 64-byte client hello and the
/// same first 32 response bytes (the server's X25519 public key). The
/// authenticated format appends `[ed25519_sig(64) || ed25519_vk(32)]`; the
/// plain format sends nothing further. After reading the shared 32 bytes, the
/// remaining 96 bytes are awaited with a short timeout — if they arrive, the
/// Ed25519 signature is verified AND the verifying key is pinned exactly like
/// [`client_handshake_with_pinned_server`]; if they do not, the plain
/// derivation (byte-identical to `client_handshake_inner`'s `None` branch,
/// including the F5 contributory check) runs on the bytes already read.
///
/// SECURITY (documented downgrade posture): a responder that suppresses the
/// authenticated suffix forces the plain fallback — an active attacker CAN do
/// this. `PreferPinned` is therefore a migration-window mode only: it guards
/// against passive eavesdropping against pinned peers while remaining
/// interoperable with legacy peers, and callers MUST surface a WARN + fallback
/// counter per connection (the sidecar does). `RequirePinned`
/// ([`client_handshake_with_pinned_server`], no fallback) is the production
/// posture once every peer speaks the authenticated format.
///
/// Returns `(session_key, peer_authenticated)` — `peer_authenticated == false`
/// means the plain fallback was exercised (see the downgrade posture above).
///
/// # Format-detection window
/// How long this function waits for the authenticated response's remaining 96
/// bytes before concluding the responder speaks only the legacy plain wire
/// format. A legacy plain server sends exactly 32 bytes and nothing more, so
/// the timeout is the format detector; a real authenticated server
/// reassembles the 96-byte suffix well inside it on any LAN-class link.
/// Tunable const, not config: a value too small would mis-detect
/// slow-but-honest authed peers into the WEAKER plain fallback.
const HANDSHAKE_AUTH_RESPONSE_DETECT_MS: u64 = 500;

pub async fn client_handshake_with_pinned_server_or_plain<S>(
    stream: &mut S,
    pinned_server_verifying_key: &[u8; 32],
) -> Result<(Zeroizing<[u8; 32]>, bool), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    use rand::rngs::OsRng;

    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());
    stream.write_all(&client_msg).await.map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader,
            "client_handshake: write failed",
        )
    })?;

    // The 32 bytes both wire formats share: the server's X25519 public key.
    let mut server_pub_bytes = [0u8; 32];
    stream
        .read_exact(&mut server_pub_bytes)
        .await
        .map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                "client_handshake: read server pubkey failed",
            )
        })?;

    // Format detection: does the authenticated 96-byte suffix arrive in time?
    let mut suffix = [0u8; 96];
    let authed = match timeout(
        Duration::from_millis(HANDSHAKE_AUTH_RESPONSE_DETECT_MS),
        stream.read_exact(&mut suffix),
    )
    .await
    {
        Ok(Ok(_)) => true,
        Ok(Err(e)) => {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!("client_handshake: read authenticated response failed: {e}"),
            ));
        }
        Err(_) => false, // elapsed — plain-format responder, fall back
    };

    if authed {
        // Reassemble the full 128-byte authenticated response from the two
        // reads and run the exact same verification discipline as
        // `read_and_verify_authed_server_response` (pin check + Ed25519 over
        // `client_nonce || server_x25519_pub`) so the two paths cannot drift.
        let mut auth_msg = [0u8; 128];
        auth_msg[..32].copy_from_slice(&server_pub_bytes);
        auth_msg[32..].copy_from_slice(&suffix);
        let sig_bytes: [u8; 64] = auth_msg[32..96].try_into().expect("64-byte sig slice");
        let vk_bytes: [u8; 32] = auth_msg[96..128].try_into().expect("32-byte vk slice");
        if vk_bytes != *pinned_server_verifying_key {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "client_handshake: server verifying key does not match pinned expectation",
            ));
        }
        let server_vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| {
            SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "client_handshake: server verifying key invalid",
            )
        })?;
        let mut to_verify = Vec::with_capacity(64);
        to_verify.extend_from_slice(&client_nonce);
        to_verify.extend_from_slice(&server_pub_bytes);
        let sig = Signature::from_bytes(&sig_bytes);
        if server_vk.verify(&to_verify, &sig).is_err() {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::IdentityMisbinding,
                "client_handshake: server signature verification failed",
            ));
        }
    }

    // Identical derivation for both branches: the plain path uses the legacy
    // responder's key, the authenticated path the (verified, pinned) server's
    // key — which is the same X25519 share either way.
    let server_pub = PublicKey::from(server_pub_bytes);
    let shared = client_secret.diffie_hellman(&server_pub);
    // F5 contributory check — see `client_handshake_inner`'s matching comment.
    if !shared.was_contributory() {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "client_handshake: X25519 shared secret was not contributory (degenerate server public key)",
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;
    Ok((Zeroizing::new(session_key), authed))
}

async fn client_handshake_inner<S>(
    stream: &mut S,
    identity: Option<&ClientIdentityConfig>,
    pinned_server_verifying_key: Option<[u8; 32]>,
) -> Result<(Zeroizing<[u8; 32]>, Option<[u8; 16]>), SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use ed25519_dalek::Signer;
    use rand::rngs::OsRng;

    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());

    let session_id: Option<[u8; 16]> = if let Some(cfg) = identity {
        let sid: [u8; 16] = rand::random();

        // Proof-of-possession: sign this exact handshake's transcript with the
        // certificate's private key. Fresh per connection (client_nonce/sid), so it
        // cannot be replayed from a captured transcript by anyone who only holds a
        // bearer capability token, not the actual identity private key.
        let mut pop_transcript = Vec::with_capacity(64 + 16);
        pop_transcript.extend_from_slice(&client_nonce);
        pop_transcript.extend_from_slice(client_pub.as_bytes());
        pop_transcript.extend_from_slice(&sid);
        let pop_sig = cfg.signing_key.sign(&pop_transcript);

        let cert_json = cfg.certificate.to_json();
        let cert_bytes = cert_json.as_bytes();
        client_msg.extend_from_slice(&sid);
        client_msg.extend_from_slice(&(cert_bytes.len() as u32).to_le_bytes());
        client_msg.extend_from_slice(cert_bytes);
        client_msg.extend_from_slice(&pop_sig.to_bytes());

        Some(sid)
    } else {
        None
    };

    stream.write_all(&client_msg).await.map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader,
            "client_handshake: write failed",
        )
    })?;

    let server_pub_bytes: [u8; 32] = if let Some(cfg) = identity {
        // Identity-bound mode implies the daemon was built with `with_identity_binding`,
        // which always enables server auth — read and verify the full authenticated
        // response rather than silently trusting an unauthenticated server pubkey.
        read_and_verify_authed_server_response(
            stream,
            &client_nonce,
            &cfg.expected_server_verifying_key,
        )
        .await?
    } else if let Some(pinned_vk) = pinned_server_verifying_key {
        // S5: plain-mode server-key pinning — same authenticated-response
        // discipline as identity mode, for daemons built with
        // `with_server_auth` (not necessarily `with_identity_binding`).
        read_and_verify_authed_server_response(stream, &client_nonce, &pinned_vk).await?
    } else {
        let mut server_pub_bytes = [0u8; 32];
        stream
            .read_exact(&mut server_pub_bytes)
            .await
            .map_err(|_| {
                SAACPHardDrop::new(
                    SAACPBytecodes::MalformedHeader,
                    "client_handshake: read server pubkey failed",
                )
            })?;
        server_pub_bytes
    };
    let server_pub = PublicKey::from(server_pub_bytes);

    let shared = client_secret.diffie_hellman(&server_pub);
    // F5 fix (contributory check): see `ecdh_handshake`'s Step 4 — a server
    // public key that yields an all-zero shared secret means the "server" is
    // a degenerate/low-order point an attacker substituted; deriving a key
    // from it would hand the attacker the session. Reject.
    if !shared.was_contributory() {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::InvalidSignature,
            "client_handshake: X25519 shared secret was not contributory (degenerate server public key)",
        ));
    }
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key)
        .map_err(|_| SAACPHardDrop::new(SAACPBytecodes::InvalidSignature, "HKDF expand failed"))?;

    // L-16 fix: see `ecdh_handshake`'s matching doc comment — same rationale applies to
    // the client-initiator side of the handshake.
    Ok((Zeroizing::new(session_key), session_id))
}

/// Read the 128-byte authenticated server response
/// `[server_x25519_pub(32) || ed25519_sig(64) || ed25519_vk(32)]`, verify the
/// Ed25519 signature over `client_nonce || server_x25519_pub`, and PIN the
/// verifying key against `expected_vk`. Shared by the identity-bound path and
/// the S5 plain-mode pinning path so the two cannot drift.
async fn read_and_verify_authed_server_response<S>(
    stream: &mut S,
    client_nonce: &[u8; 32],
    expected_vk: &[u8; 32],
) -> Result<[u8; 32], SAACPHardDrop>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};
    let mut auth_msg = [0u8; 128];
    stream.read_exact(&mut auth_msg).await.map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::MalformedHeader,
            "client_handshake: read authenticated server response failed",
        )
    })?;
    let server_pub_bytes: [u8; 32] = auth_msg[0..32].try_into().unwrap();
    let sig_bytes: [u8; 64] = auth_msg[32..96].try_into().unwrap();
    let vk_bytes: [u8; 32] = auth_msg[96..128].try_into().unwrap();

    if vk_bytes != *expected_vk {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding,
            "client_handshake: server verifying key does not match pinned expectation",
        ));
    }
    let server_vk = VerifyingKey::from_bytes(&vk_bytes).map_err(|_| {
        SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding,
            "client_handshake: server verifying key invalid",
        )
    })?;
    let mut to_verify = Vec::with_capacity(64);
    to_verify.extend_from_slice(client_nonce);
    to_verify.extend_from_slice(&server_pub_bytes);
    let sig = Signature::from_bytes(&sig_bytes);
    if server_vk.verify(&to_verify, &sig).is_err() {
        return Err(SAACPHardDrop::new(
            SAACPBytecodes::IdentityMisbinding,
            "client_handshake: server signature verification failed",
        ));
    }
    Ok(server_pub_bytes)
}

/// Client-side configuration for C-3 identity binding (see `client_handshake`'s doc
/// comment and `ecdh_handshake`'s server-side counterpart). Constructing one requires an
/// `AgentIdentityCertificate` already issued by a CA the target daemon trusts.
pub struct ClientIdentityConfig {
    /// This agent's CA-issued identity certificate.
    pub certificate: crate::identity_binding::AgentIdentityCertificate,
    /// Ed25519 signing key corresponding to `certificate.public_key_hex` — used to prove
    /// possession via the handshake's proof-of-possession signature.
    pub signing_key: ed25519_dalek::SigningKey,
    /// The target daemon's expected Ed25519 verifying key (from
    /// `SAACPNetworkDaemon::server_verifying_key`), distributed out-of-band. Required
    /// because `with_identity_binding` always enables server authentication — an
    /// identity-bound client must never accept an unauthenticated server response.
    pub expected_server_verifying_key: [u8; 32],
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Namespaced `TrustDecayEngine` key for an IP address — distinct prefix so
/// it can never collide with a real agent_id sharing the same process-wide
/// map (see the Step 0b comment in `handle_client` for the full rationale).
fn ip_trust_key(ip: &str) -> String {
    format!("ip:{ip}")
}

fn record_error(cbs: &SharedCircuitBreakers, ip: &str) {
    // L-18 fix: `parking_lot::Mutex::lock()` returns the guard directly (no poison
    // `Result` to unwrap) — see the matching Step 0 check's doc comment above.
    let mut map = cbs.lock();
    // OOM guard: drop oldest 10% when at capacity.
    //
    // M-16 fix: candidates are chosen by (1) lockout-expired-or-absent first —
    // an entry with no active lockout provides zero remaining protective
    // value, so it is always safe to drop ahead of one still actively
    // blocking a misbehaving IP — then (2) oldest-`last_activity`-first
    // within each group, instead of relying on `HashMap::keys()`'s arbitrary
    // hash-bucket iteration order (which could just as easily drop an IP
    // that's actively mid-lockout while leaving long-idle, already-expired
    // entries in place).
    if map.len() >= MAX_CIRCUIT_BREAKER_IPS && !map.contains_key(ip) {
        let drop_count = MAX_CIRCUIT_BREAKER_IPS / 10;
        let mut candidates: Vec<(String, bool, Instant)> = map
            .iter()
            .map(|(k, v)| (k.clone(), v.lockout_expired_or_absent(), v.last_activity))
            .collect();
        candidates.sort_by(|a, b| {
            // Expired-or-absent-lockout entries (true) sort before still-locked
            // ones (false) — Rust's bool ordering is false < true, so reverse it.
            b.1.cmp(&a.1).then_with(|| a.2.cmp(&b.2))
        });
        for (k, _, _) in candidates.into_iter().take(drop_count) {
            map.remove(&k);
        }
    }
    map.entry(ip.to_string())
        .or_insert_with(CircuitBreakerEntry::new)
        .record_error();
}

/// Decode a schema_id=11 (`Gossip Envelope`, `schemas.rs`) packet's already-validated
/// `payload_dict` into a `gossip::GossipEnvelope`. `PreCompiledSchemas::validate_payload`
/// has already confirmed `gossip_record`/`hop_count`/`origin_id`/`revocation_id` are all
/// present by the time this runs (schema validation happens inside `handler.rs`'s gate
/// pipeline, before `Ok(parsed)` is ever returned) — this only handles the type coercion
/// from loosely-typed `JsonValue`s to the envelope's concrete field types, and the
/// base64 + `SignedRevocationRecord::from_wire` decode of `gossip_record`. Returns `None`
/// (silently dropped, matching `GossipTransport::send_to_peer`'s "drop and log" philosophy
/// for malformed/adversarial peer traffic) on any decode failure rather than propagating an
/// error — a malformed gossip envelope from a misbehaving or malicious peer must never be
/// able to disrupt this connection's otherwise-successful packet delivery.
fn decode_gossip_envelope(
    payload_dict: &HashMap<String, JsonValue>,
) -> Option<crate::gossip::GossipEnvelope> {
    use base64::Engine;

    let gossip_record_b64 = match payload_dict.get("gossip_record") {
        Some(JsonValue::String(s)) => s,
        _ => return None,
    };
    let hop_count = match payload_dict.get("hop_count") {
        Some(JsonValue::Number(n)) if *n >= 0.0 && *n <= u8::MAX as f64 => *n as u8,
        _ => return None,
    };
    let origin_id = match payload_dict.get("origin_id") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };
    let revocation_id = match payload_dict.get("revocation_id") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };

    let wire = base64::engine::general_purpose::STANDARD
        .decode(gossip_record_b64)
        .ok()?;
    let record = crate::faitf::SignedRevocationRecord::from_wire(&wire).ok()?;

    Some(crate::gossip::GossipEnvelope {
        record,
        hop_count,
        origin_id,
        revocation_id,
    })
}

/// Decode a schema_id=12 (`Cluster Envelope`, `schemas.rs`) packet's already-validated
/// `payload_dict` into `(cluster_message, sender_id, leader_epoch, message_kind)`.
///
/// Like `decode_gossip_envelope` above, `PreCompiledSchemas::validate_payload` has already
/// confirmed all four keys are present by the time this runs, so this only handles type
/// coercion from loosely-typed `JsonValue`s. Returns `None` on any type mismatch — a
/// malformed envelope from a misbehaving or malicious peer must never disrupt this
/// connection's otherwise-successful packet delivery.
///
/// The signed blob is deliberately **not** decoded here: `sender_id`/`leader_epoch`/
/// `message_kind` are plaintext routing hints only, and `ClusterEngine::receive_envelope`
/// rejects the message outright if they disagree with the signed body.
fn decode_cluster_envelope(
    payload_dict: &HashMap<String, JsonValue>,
) -> Option<(String, String, u64, String)> {
    let cluster_message = match payload_dict.get("cluster_message") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };
    let sender_id = match payload_dict.get("sender_id") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };
    let leader_epoch = match payload_dict.get("leader_epoch") {
        Some(JsonValue::Number(n)) if *n >= 0.0 && *n <= u64::MAX as f64 => *n as u64,
        _ => return None,
    };
    let message_kind = match payload_dict.get("message_kind") {
        Some(JsonValue::String(s)) => s.clone(),
        _ => return None,
    };

    Some((cluster_message, sender_id, leader_epoch, message_kind))
}

async fn send_hard_drop<S>(stream: &mut S, bc: SAACPBytecodes, _msg: &str)
where
    S: tokio::io::AsyncWrite + Unpin,
{
    let ext = internal_to_external_raw(bc as u8);
    // Wire format requires a real 32-hex-char correlation ID (spec §9.3); see the
    // matching fix in the main connection-loop error arm above for the full rationale.
    let wire = SREL::normalize_response(ext, &generate_correlation_id());
    let _ = stream.write_all(&wire).await;
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_breaker_lockout() {
        let mut entry = CircuitBreakerEntry::new();
        assert!(!entry.is_locked());
        for _ in 0..CIRCUIT_BREAKER_ERROR_THRESHOLD {
            entry.record_error();
        }
        assert!(entry.is_locked(), "Should be locked after threshold errors");
    }

    #[test]
    fn test_circuit_breaker_oom_guard() {
        let cbs: SharedCircuitBreakers = new_shared_circuit_breakers();
        // Fill to capacity
        {
            let mut map = cbs.lock();
            for i in 0..MAX_CIRCUIT_BREAKER_IPS {
                map.insert(
                    format!("10.0.{}.{}", i / 256, i % 256),
                    CircuitBreakerEntry::new(),
                );
            }
        }
        assert_eq!(cbs.lock().len(), MAX_CIRCUIT_BREAKER_IPS);
        // Adding a new IP should trigger eviction
        record_error(&cbs, "192.168.1.1");
        assert!(
            cbs.lock().len() < MAX_CIRCUIT_BREAKER_IPS + 1,
            "OOM guard must prevent unbounded growth"
        );
    }

    /// M-16 regression: an entry with an ACTIVE (not-yet-expired) lockout
    /// must survive eviction as long as an entry with no lockout at all is
    /// available to drop instead — proving eviction no longer relies on
    /// arbitrary `HashMap` iteration order, which could just as easily have
    /// dropped the actively-locked entry.
    #[test]
    fn test_circuit_breaker_eviction_prefers_unlocked_over_actively_locked() {
        let cbs: SharedCircuitBreakers = new_shared_circuit_breakers();
        const LOCKED_IP: &str = "203.0.113.42"; // TEST-NET-3 (RFC 5737) — never generated by the fill loop below
        {
            let mut map = cbs.lock();
            // One entry with an ACTIVE lockout — must be protected from eviction.
            let mut locked_entry = CircuitBreakerEntry::new();
            for _ in 0..CIRCUIT_BREAKER_ERROR_THRESHOLD {
                locked_entry.record_error();
            }
            assert!(
                locked_entry.is_locked(),
                "test setup: entry must actually be locked"
            );
            map.insert(LOCKED_IP.to_string(), locked_entry);

            // Fill the rest of capacity with plain, never-errored (no lockout)
            // entries — all strictly safer to evict than the locked one above.
            for i in 1..MAX_CIRCUIT_BREAKER_IPS {
                map.insert(
                    format!("10.0.{}.{}", i / 256, i % 256),
                    CircuitBreakerEntry::new(),
                );
            }
        }
        assert_eq!(cbs.lock().len(), MAX_CIRCUIT_BREAKER_IPS);

        // Trigger eviction by recording an error for a brand-new IP.
        record_error(&cbs, "192.168.1.1");

        let map = cbs.lock();
        assert!(
            map.contains_key(LOCKED_IP),
            "M-16: the actively-locked entry must survive eviction while \
             unlocked entries are still available to drop"
        );
        assert!(
            map.len() < MAX_CIRCUIT_BREAKER_IPS + 1,
            "OOM guard must still bound growth"
        );
    }

    #[test]
    fn test_ip_trust_key_namespaced() {
        // Namespaced distinctly from a bare agent_id of the same string, so
        // the shared TrustDecayEngine map can never confuse an IP bucket
        // with a real agent identity bucket.
        assert_eq!(ip_trust_key("127.0.0.1"), "ip:127.0.0.1");
        assert_ne!(ip_trust_key("agent-a"), "agent-a");
    }

    #[test]
    fn test_ip_trust_key_evasion_resistance() {
        // Simulates the exact scenario Step 0b defends against: an attacker
        // rotates its claimed agent identity on every request (resetting its
        // own per-agent TrustDecayEngine bucket each time), but the shared
        // IP-level bucket still accumulates penalties across every identity
        // it ever claimed and eventually requires reauth regardless.
        use crate::trust_decay::{PenaltyKind, TrustDecayEngine};
        let engine = TrustDecayEngine::new();
        let ip_key = ip_trust_key("203.0.113.7");

        for i in 0..5 {
            let rotating_identity = format!("agent-rotating-{i}");
            // Per-agent bucket resets fresh every time (fully trusted) —
            // rotating identity alone is a successful evasion of it.
            assert_eq!(engine.score(&rotating_identity), 1.0);
            engine.penalize(&rotating_identity, PenaltyKind::ReplaySuspicion);
            // But the IP-level bucket accumulates regardless of identity.
            engine.penalize(&ip_key, PenaltyKind::ReplaySuspicion);
        }
        // Five ReplaySuspicion penalties (0.40 each) on the same IP bucket
        // drive it below TRUST_REAUTH_THRESHOLD (0.25), forcing reauth even
        // though no single rotating identity ever crossed it.
        assert!(engine.requires_reauth(&ip_key));
    }

    #[test]
    fn test_daemon_new() {
        let d = SAACPNetworkDaemon::new("127.0.0.1", 9900, None);
        assert_eq!(d.host, "127.0.0.1");
        assert_eq!(d.port, 9900);
        assert!(d.token_issuer_secret.is_none());
    }

    #[test]
    fn test_daemon_with_secret() {
        let secret = vec![0u8; 32];
        let d = SAACPNetworkDaemon::new("0.0.0.0", 9901, Some(secret.clone()));
        assert_eq!(d.token_issuer_secret.unwrap(), secret);
    }

    /// S2 (SECURE-BY-DEFAULT) regression: `new()` must return the hardened
    /// profile — an authenticated handshake key (exposed for pinning) AND an
    /// AEAD epoch manager — with no builder calls required. The permissive
    /// pre-S2 shape lives only in `insecure_for_testing`.
    #[test]
    fn s2_new_is_hardened_by_default() {
        let d = SAACPNetworkDaemon::new("127.0.0.1", 9902, None);
        assert!(
            d.server_verifying_key().is_some(),
            "new() must enable the Ed25519-authenticated handshake"
        );
        assert!(
            d.epoch_manager.is_some(),
            "new() must enable AEAD encrypted transport"
        );

        let p = SAACPNetworkDaemon::insecure_for_testing("127.0.0.1", 9903, None);
        assert!(
            p.server_verifying_key().is_none() && p.epoch_manager.is_none(),
            "insecure_for_testing preserves the pre-S2 permissive shape"
        );
    }

    /// F3 (SECURE-BY-DEFAULT): the one-call hardened profile must compose
    /// server authentication + identity binding + AEAD Gate 0 + real Gate 1.0
    /// token verification — no protection left to forget.
    #[test]
    fn test_secure_profile_enables_all_protections() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use std::sync::Arc as StdArc;

        let server_sk = SigningKey::from_bytes(&[0x5Eu8; 32]);
        let ca_vk: VerifyingKey = SigningKey::from_bytes(&[0x7Fu8; 32]).verifying_key();

        let d = SAACPNetworkDaemon::secure(
            "127.0.0.1",
            9902,
            Some(vec![0x33u8; 32]),
            server_sk.to_bytes(),
            "server-1",
            &[("ca-1", ca_vk)],
            &["ed25519", "AES-256-GCM-HKDF-SHA256"],
            StdArc::new(crate::gateway::ZeroTrustGateway::new()),
            StdArc::new(SessionEpochManager::new()),
        )
        .expect("secure() must accept the mandatory production suites");

        assert!(d.server_ed25519_seed.is_some(), "server auth must be on");
        assert_eq!(
            d.server_agent_id.as_deref(),
            Some("server-1"),
            "identity binding must be on"
        );
        assert!(d.gateway.is_some(), "gateway token verification must be on");
        assert!(
            d.epoch_manager.is_some(),
            "AEAD encrypted transport must be on"
        );
    }

    /// F3 (SECURE-BY-DEFAULT): the construction-time downgrade guard — a suite
    /// configuration without the mandatory `ed25519` baseline must refuse to
    /// construct rather than start silently weakened.
    #[test]
    fn test_secure_profile_rejects_downgraded_suite_config() {
        use ed25519_dalek::{SigningKey, VerifyingKey};
        use std::sync::Arc as StdArc;

        let server_sk = SigningKey::from_bytes(&[0x5Eu8; 32]);
        let ca_vk: VerifyingKey = SigningKey::from_bytes(&[0x7Fu8; 32]).verifying_key();

        let err = SAACPNetworkDaemon::secure(
            "127.0.0.1",
            9903,
            None,
            server_sk.to_bytes(),
            "server-1",
            &[("ca-1", ca_vk)],
            &["AES-256-GCM-HKDF-SHA256"], // missing the mandatory ed25519 baseline
            StdArc::new(crate::gateway::ZeroTrustGateway::new()),
            StdArc::new(SessionEpochManager::new()),
        );
        assert!(
            err.is_err(),
            "suite config missing the mandatory baseline must be rejected"
        );
    }

    /// F5 (contributory check): a client presenting the all-zero X25519 public
    /// key (the identity point) must be rejected — pre-fix, HKDF over the
    /// resulting all-zero shared secret derived a session key the attacker can
    /// compute without holding any key at all.
    #[tokio::test]
    async fn test_ecdh_handshake_rejects_all_zero_peer_key() {
        use tokio::io::AsyncWriteExt;
        let (mut client, mut server) = tokio::io::duplex(4096);
        // Client sends a 32-byte nonce followed by the all-zero "public key".
        client.write_all(&[0x11u8; 32]).await.unwrap();
        client.write_all(&[0u8; 32]).await.unwrap();
        // Fresh throwaway gate: this test exercises the contributory-key
        // rejection, which never reaches the identity-gate advance.
        let gate = crate::identity_binding::IdentityGate::new();
        let result = ecdh_handshake(&mut server, None, None, &gate).await;
        assert!(
            result.is_err(),
            "all-zero peer public key must be rejected (contributory check)"
        );
    }

    /// F5 (contributory check), initiator side: an "server" whose X25519 public
    /// key is the identity point must be rejected by `client_handshake`.
    #[tokio::test]
    async fn test_client_handshake_rejects_all_zero_server_key() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut client, mut server) = tokio::io::duplex(4096);
        let client_task = tokio::spawn(async move { client_handshake(&mut client, None).await });
        // Consume the client's nonce+pubkey, then answer with the all-zero key.
        let mut sink = [0u8; 64];
        server.read_exact(&mut sink).await.unwrap();
        server.write_all(&[0u8; 32]).await.unwrap();
        let result = client_task.await.expect("client task must not panic");
        assert!(
            result.is_err(),
            "all-zero server public key must be rejected (contributory check)"
        );
    }
}
