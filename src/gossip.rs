//! gossip.rs — Revocation gossip protocol (Phase 5, item 3 / Part 8.6).
//!
//! Fans a [`crate::faitf::SignedRevocationRecord`] out to a bounded set of peers so a
//! revocation created anywhere in a federation propagates without every caller having to
//! remember to invoke `TrustMeshFederation::propagate_revocation()` (which only computes
//! *which* members should receive a record — it explicitly leaves network delivery to the
//! caller) by hand.
//!
//! Design constants match Part 8.6 of the plan doc: fanout=3, max_hops=5, 1h dedup TTL,
//! schema_id=11. The actual peer transport is a trait seam ([`GossipTransport`]) — building
//! a real multi-node peer-discovery mesh (membership, retry/backoff) is a distinct,
//! multi-week distributed-systems project outside what this module specifies concretely
//! enough to build correctly in one pass. [`StaticPeerListTransport`] ships as a real,
//! working reference implementation (fixed operator-configured peer list, fire-and-forget
//! delivery over a short-lived `TcpStream`), so `GossipTransport` is not left as a pure
//! interface with zero working implementation.
//!
//! Reliability comes from fanout + multi-hop redundancy, not per-send retries — a dropped
//! gossip message is expected to reach the same peer via a different path on a subsequent
//! hop, matching gossip protocols' inherent unreliable-delivery design.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rand::seq::SliceRandom;

use crate::faitf::{DistributedRevocationInfrastructure, SignedRevocationRecord, TrustStore};

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

/// Maximum number of peers a single revocation is forwarded to per hop (Part 8.6).
pub const GOSSIP_FANOUT: usize = 3;

/// Maximum number of hops a gossip envelope may travel before it is no longer
/// re-forwarded (Part 8.6) — bounds propagation blast radius and prevents infinite
/// re-forwarding in a cyclic peer topology.
pub const GOSSIP_MAX_HOPS: u8 = 5;

/// De-duplication window: a `revocation_id` seen within this many seconds of its first
/// sighting is dropped without re-forwarding (Part 8.6: 1h dedup TTL).
pub const GOSSIP_DEDUP_TTL_SECONDS: f64 = 3_600.0;

/// Upper bound on how many distinct revocation ids [`SeenSet`] tracks at once — same
/// bounded-map idiom used by `faitf::IdentityProver::used_challenges`
/// (`IDENTITY_PROVER_MAX_CHALLENGES`) and `trust_decay`'s bounded maps: an attacker flooding
/// distinct fabricated ids must not grow this map without bound between TTL sweeps.
pub const SEEN_SET_MAX_ENTRIES: usize = 100_000;

/// R9 (Phase 4): optional bounded retry on the gossip SEND path. `0` (the
/// default) preserves fire-and-forget delivery byte-for-byte; an operator
/// raising it to `1` re-sends every fanout payload once after
/// [`GOSSIP_RETRY_DELAY_MS`].
///
/// The `GossipTransport` seam is ack-less (`send_to_peer` returns `()`), so a
/// retry is an unconditional at-least-once redelivery, not a failure-triggered
/// retransmission — receiver-side [`SeenSet`] de-duplication makes the
/// duplicate safe and free. Revocation is the one message class where
/// eventual delivery is a security property rather than a convenience (R9),
/// which is why the knob exists at all; regular gossip traffic needs no retry
/// (fanout + multi-hop redundancy already covers it). Touches the gossip send
/// path ONLY — zero default-behavior change elsewhere.
pub const GOSSIP_SEND_RETRIES: u32 = 0;

/// Delay before each bounded retry re-send (see [`GOSSIP_SEND_RETRIES`]).
pub const GOSSIP_RETRY_DELAY_MS: u64 = 100;

// ---------------------------------------------------------------------------
// GossipEnvelope
// ---------------------------------------------------------------------------

/// Wire envelope for one gossiped revocation record. Corresponds to schema id 11
/// (`src/schemas.rs`) — `gossip_record` carries `record.to_wire()`'s base64 bytes as a
/// string, with `hop_count`/`origin_id`/`revocation_id` alongside it as plain fields.
#[derive(Debug, Clone)]
pub struct GossipEnvelope {
    pub record: SignedRevocationRecord,
    pub hop_count: u8,
    pub origin_id: String,
    pub revocation_id: String,
}

impl GossipEnvelope {
    /// Derive a stable revocation id for a record: the same (agent_id, credential_fingerprint,
    /// revoked_at) triple always yields the same id, so the same revocation gossiped along
    /// different paths de-duplicates correctly regardless of which peer forwarded it first.
    pub fn derive_revocation_id(record: &SignedRevocationRecord) -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(record.agent_id.as_bytes());
        hasher.update(record.credential_fingerprint.as_bytes());
        hasher.update(record.revoked_at.to_bits().to_be_bytes());
        hex::encode(hasher.finalize())
    }
}

// ---------------------------------------------------------------------------
// SeenSet
// ---------------------------------------------------------------------------

/// Bounded, TTL-swept de-duplication set keyed by `revocation_id`. Mirrors the
/// oldest-first-eviction-under-capacity idiom already used by
/// `faitf::IdentityProver::used_challenges` and `trust_decay`'s bounded maps
/// (Architecture Principle #5, Bounded Everything).
pub struct SeenSet {
    /// revocation_id -> expiry timestamp (seconds since epoch).
    seen: Mutex<HashMap<String, f64>>,
}

impl SeenSet {
    pub fn new() -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
        }
    }

    /// Returns `true` if `revocation_id` was already present (and thus should not be
    /// re-forwarded); otherwise records it with a fresh TTL and returns `false`.
    pub fn check_and_insert(&self, revocation_id: &str) -> bool {
        let now = now_f64();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        Self::evict_expired(&mut seen, now);

        if seen.contains_key(revocation_id) {
            return true;
        }

        if seen.len() >= SEEN_SET_MAX_ENTRIES {
            let evict_count = seen.len() + 1 - SEEN_SET_MAX_ENTRIES;
            let mut by_expiry: Vec<(String, f64)> =
                seen.iter().map(|(k, exp)| (k.clone(), *exp)).collect();
            by_expiry.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (k, _) in by_expiry.into_iter().take(evict_count) {
                seen.remove(&k);
            }
        }

        seen.insert(revocation_id.to_string(), now + GOSSIP_DEDUP_TTL_SECONDS);
        false
    }

    fn evict_expired(seen: &mut HashMap<String, f64>, now: f64) {
        seen.retain(|_, exp| *exp >= now);
    }

    /// Remove expired entries without requiring a `check_and_insert` call — lets a
    /// background maintenance sweep reclaim memory even during a quiet period with no
    /// new revocations (mirrors `IdentityProver::sweep_expired_challenges`).
    pub fn sweep_expired(&self) -> usize {
        let now = now_f64();
        let mut seen = self.seen.lock().unwrap_or_else(|e| e.into_inner());
        let before = seen.len();
        Self::evict_expired(&mut seen, now);
        before - seen.len()
    }

    /// Number of revocation ids currently tracked (for observability/tests).
    pub fn tracked_count(&self) -> usize {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

impl Default for SeenSet {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// GossipTransport
// ---------------------------------------------------------------------------

/// Seam between gossip fanout logic and actual network delivery. A real multi-node
/// peer-discovery mesh (membership, retry/backoff) is out of scope for this module — see
/// the module doc — so implementations are expected to be as simple as
/// [`StaticPeerListTransport`], or supplied by the operator's own deployment tooling.
pub trait GossipTransport: Send + Sync {
    /// Return the peer identifiers currently known to this transport.
    fn known_peers(&self) -> Vec<String>;
    /// Best-effort, fire-and-forget send of `bytes` to `peer_id`. Implementations MUST NOT
    /// block indefinitely and SHOULD treat send failures as drop-and-log — reliability
    /// comes from fanout + multi-hop redundancy, not per-send retries.
    fn send_to_peer(&self, peer_id: &str, bytes: &[u8]);
}

// ---------------------------------------------------------------------------
// GossipEngine
// ---------------------------------------------------------------------------

/// Orchestrates revocation fanout: verifies inbound gossip against a [`TrustStore`], stores
/// newly-seen valid revocations via [`DistributedRevocationInfrastructure`], and re-forwards
/// to up to [`GOSSIP_FANOUT`] peers while `hop_count < GOSSIP_MAX_HOPS`.
pub struct GossipEngine {
    seen: SeenSet,
    transport: Arc<dyn GossipTransport>,
    dri: Arc<DistributedRevocationInfrastructure>,
    trust_store: Arc<TrustStore>,
    node_id: String,
}

impl GossipEngine {
    pub fn new(
        transport: Arc<dyn GossipTransport>,
        dri: Arc<DistributedRevocationInfrastructure>,
        trust_store: Arc<TrustStore>,
        node_id: impl Into<String>,
    ) -> Self {
        Self {
            seen: SeenSet::new(),
            transport,
            dri,
            trust_store,
            node_id: node_id.into(),
        }
    }

    /// Local-origin entry point: a revocation just created on this node. Does not
    /// re-verify the record's signature (it was just signed locally) — only fans it out.
    pub fn broadcast(&self, record: SignedRevocationRecord) {
        let revocation_id = GossipEnvelope::derive_revocation_id(&record);
        // A locally-originated broadcast must always fan out, even if (implausibly) the
        // same id was already gossiped in from elsewhere — insert unconditionally rather
        // than gating on `check_and_insert`'s dedup semantics, then still record it so a
        // subsequent inbound copy of the same id is correctly deduped.
        self.seen.check_and_insert(&revocation_id);
        let envelope = GossipEnvelope {
            record,
            hop_count: 0,
            origin_id: self.node_id.clone(),
            revocation_id,
        };
        self.fanout(&envelope);
    }

    /// Inbound entry point: a gossip envelope arrived from a peer. Verifies the record's
    /// signature against `trust_store` (reusing
    /// `DistributedRevocationInfrastructure::propagate`'s verify-and-store step via the
    /// record's wire form), and if new and under the hop ceiling, re-forwards.
    ///
    /// Returns `true` if the record was accepted (verified and newly stored or already
    /// known-valid), `false` if the signature failed verification — an invalid record is
    /// never stored or forwarded regardless of hop count (Fail-Closed by Default).
    pub fn receive(&self, envelope: GossipEnvelope) -> bool {
        let wire = envelope.record.to_wire();
        if !self.dri.propagate(&wire, &self.trust_store) {
            return false;
        }

        // R9 (Phase 4): a verified-and-stored revocation updates this node's
        // last-received-revocation timestamp, from which the
        // `saacp_revocation_lag_seconds` gauge (telemetry snapshot /
        // `/metrics`) derives its revocation-convergence lag. Alert guidance
        // is documented on the Prometheus series: sustained lag > 300s in a
        // gossiped fleet means propagation stalled.
        crate::telemetry::global_telemetry().record_revocation_received(now_f64() as u64);

        if self.seen.check_and_insert(&envelope.revocation_id) {
            // Already seen — accepted (it verified), but not re-forwarded.
            return true;
        }

        if envelope.hop_count < GOSSIP_MAX_HOPS {
            let forwarded = GossipEnvelope {
                record: envelope.record,
                hop_count: envelope.hop_count + 1,
                origin_id: envelope.origin_id,
                revocation_id: envelope.revocation_id,
            };
            self.fanout(&forwarded);
        }

        true
    }

    fn fanout(&self, envelope: &GossipEnvelope) {
        let peers = self.transport.known_peers();
        if peers.is_empty() {
            return;
        }
        let mut rng = rand::thread_rng();
        let chosen: Vec<&String> = peers.choose_multiple(&mut rng, GOSSIP_FANOUT).collect();
        let payload = envelope.record.to_wire();
        for peer_id in chosen {
            self.send_with_bounded_retries(peer_id, &payload);
        }
    }

    /// R9 (Phase 4): send once, then (only when the operator raised
    /// [`GOSSIP_SEND_RETRIES`] above 0) re-send up to that many times with a
    /// [`GOSSIP_RETRY_DELAY_MS`] pause between attempts. With the default `0`
    /// this is exactly one `send_to_peer` call — the pre-R9 fire-and-forget
    /// behavior, unchanged. See [`GOSSIP_SEND_RETRIES`]'s doc for why the
    /// retry is unconditional (the transport seam is ack-less) and why that
    /// is safe (receiver-side SeenSet dedup).
    fn send_with_bounded_retries(&self, peer_id: &str, payload: &[u8]) {
        self.transport.send_to_peer(peer_id, payload);
        let mut remaining = GOSSIP_SEND_RETRIES;
        while remaining > 0 {
            std::thread::sleep(std::time::Duration::from_millis(GOSSIP_RETRY_DELAY_MS));
            self.transport.send_to_peer(peer_id, payload);
            remaining -= 1;
        }
    }

    /// Number of revocation ids currently tracked in the de-duplication set (for
    /// observability/tests).
    pub fn seen_count(&self) -> usize {
        self.seen.tracked_count()
    }

    /// Remove expired `SeenSet` entries — see [`SeenSet::sweep_expired`].
    pub fn sweep_expired(&self) -> usize {
        self.seen.sweep_expired()
    }

    /// Spawn a background OS thread that calls [`Self::sweep_expired`] every 60 seconds
    /// (Phase 6 / item 4 daemon wiring — matches `klms::KeyLifecycleManager::
    /// start_auto_rotation`'s and the Phase-7 "background maintenance sweep" 60s-cadence
    /// idiom). Returns the thread's `JoinHandle` — the thread runs for the lifetime of the
    /// process, matching every other global background worker in this codebase (there is
    /// no explicit stop signal since a `GossipEngine` is expected to live for the daemon's
    /// lifetime).
    pub fn start_sweep(self: Arc<Self>) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("gossip-sweep".to_string())
            .spawn(move || loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                self.sweep_expired();
            })
            .expect("failed to spawn gossip-sweep thread")
    }
}

// ---------------------------------------------------------------------------
// StaticPeerListTransport — reference GossipTransport implementation
// ---------------------------------------------------------------------------

/// A concrete, working [`GossipTransport`]: a fixed, operator-configured list of peer
/// addresses, sent to by opening a short-lived `TcpStream` per send (the same primitive
/// `sidecar.rs::connect_with_retry` already uses safely for its single outbound relay
/// target). Send failures are logged and dropped (fire-and-forget) rather than retried —
/// gossip's reliability comes from fanout + multi-hop redundancy, not per-send retries.
///
/// M-E remediation (production audit G5/R5): sends flow through a small fixed
/// worker pool with a bounded queue ([`GOSSIP_SEND_POOL_WORKERS`] /
/// [`GOSSIP_SEND_QUEUE_CAP`]) instead of one detached OS thread per send —
/// a revocation storm previously meant unbounded thread creation. When the
/// queue is momentarily full the send is DROPPED and counted
/// (`saacp_security_events_total{event="gossip_send_failures_total"}`);
/// fire-and-forget semantics are preserved.
pub const GOSSIP_SEND_POOL_WORKERS: usize = 4;
/// Bounded job-queue capacity shared by the send-pool workers.
pub const GOSSIP_SEND_QUEUE_CAP: usize = 1024;

struct SendJob {
    addr: SocketAddr,
    bytes: Vec<u8>,
}

pub struct StaticPeerListTransport {
    peers: Mutex<HashMap<String, SocketAddr>>,
    /// Lazily-initialized bounded send pool (first `send_to_peer` starts the
    /// workers). Construction stays side-effect-free for tests.
    pool: std::sync::OnceLock<std::sync::mpsc::SyncSender<SendJob>>,
}

impl StaticPeerListTransport {
    /// Construct a transport from a fixed `(peer_id, address)` list.
    pub fn new(peers: Vec<(String, SocketAddr)>) -> Self {
        Self {
            peers: Mutex::new(peers.into_iter().collect()),
            pool: std::sync::OnceLock::new(),
        }
    }

    /// Start the fixed worker pool once and return its job sender.
    fn pool_sender(&self) -> &std::sync::mpsc::SyncSender<SendJob> {
        self.pool.get_or_init(|| {
            let (tx, rx) = std::sync::mpsc::sync_channel::<SendJob>(GOSSIP_SEND_QUEUE_CAP);
            let rx = std::sync::Arc::new(std::sync::Mutex::new(rx));
            for worker in 0..GOSSIP_SEND_POOL_WORKERS {
                let rx = std::sync::Arc::clone(&rx);
                let spawned = std::thread::Builder::new()
                    .name(format!("gossip-send-{worker}"))
                    .spawn(move || loop {
                        let Ok(job) = rx.lock().unwrap_or_else(|e| e.into_inner()).recv() else {
                            return; // all senders dropped — transport is gone
                        };
                        deliver_gossip_payload(&job.addr, &job.bytes);
                    });
                if spawned.is_err() {
                    // Thread spawn refused (resource exhaustion) — degrade to
                    // fewer workers rather than panicking; fewer workers only
                    // means the bounded queue fills sooner and drops get
                    // counted, which is the same fire-and-forget posture.
                    eprintln!(
                        "[saacp gossip] send-pool worker {worker} failed to spawn; \
                         continuing with fewer workers"
                    );
                }
            }
            tx
        })
    }
}

/// One delivery attempt (blocking connect + write, failures counted). Runs on
/// the send-pool workers — never on the caller's thread.
fn deliver_gossip_payload(addr: &SocketAddr, bytes: &[u8]) {
    use std::io::Write;
    match std::net::TcpStream::connect_timeout(addr, std::time::Duration::from_secs(2)) {
        Ok(mut stream) => {
            let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(2)));
            if stream.write_all(bytes).is_err() {
                crate::telemetry::global_telemetry().record_gossip_send_failure();
            }
        }
        Err(_) => {
            crate::telemetry::global_telemetry().record_gossip_send_failure();
        }
    }
}

impl GossipTransport for StaticPeerListTransport {
    fn known_peers(&self) -> Vec<String> {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    fn send_to_peer(&self, peer_id: &str, bytes: &[u8]) {
        let addr = {
            let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            match peers.get(peer_id) {
                Some(a) => *a,
                None => return,
            }
        };
        // Bounded hand-off: when the queue is full (all workers busy on a
        // 2s-timeout backlog) the send is dropped and COUNTED instead of
        // blocking the caller or spawning an unbounded thread.
        if self
            .pool_sender()
            .try_send(SendJob {
                addr,
                bytes: bytes.to_vec(),
            })
            .is_err()
        {
            crate::telemetry::global_telemetry().record_gossip_send_failure();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::faitf::{AgentIdentity, AttestationType, TrustAnchor};

    fn make_identity(id: &str) -> AgentIdentity {
        AgentIdentity::generate(
            id,
            "issuer-gossip-test",
            86_400,
            None,
            None,
            "",
            AttestationType::None,
        )
    }

    struct FakeTransport {
        peers: Vec<String>,
        sent: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FakeTransport {
        fn new(peers: Vec<&str>) -> Self {
            Self {
                peers: peers.into_iter().map(String::from).collect(),
                sent: Mutex::new(Vec::new()),
            }
        }

        fn sent_peer_ids(&self) -> Vec<String> {
            self.sent
                .lock()
                .unwrap()
                .iter()
                .map(|(p, _)| p.clone())
                .collect()
        }
    }

    impl GossipTransport for FakeTransport {
        fn known_peers(&self) -> Vec<String> {
            self.peers.clone()
        }
        fn send_to_peer(&self, peer_id: &str, bytes: &[u8]) {
            self.sent
                .lock()
                .unwrap()
                .push((peer_id.to_string(), bytes.to_vec()));
        }
    }

    fn make_revoked_record(anchor: &AgentIdentity, agent_id: &str) -> SignedRevocationRecord {
        crate::faitf::DistributedRevocationInfrastructure::new()
            .revoke(agent_id, "test-revocation", anchor, "fp-1")
            .unwrap()
    }

    fn make_trust_store_with_anchor(anchor: &AgentIdentity) -> TrustStore {
        let store = TrustStore::new();
        store.register_anchor(TrustAnchor::new(&anchor.agent_id, anchor.verifying_key));
        store
    }

    #[test]
    fn fresh_revocation_fans_out_to_exactly_fanout_distinct_peers_when_enough_known() {
        let anchor = make_identity("anchor-a");
        let record = make_revoked_record(&anchor, "victim-1");
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec!["p1", "p2", "p3", "p4", "p5"]));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-x");

        engine.broadcast(record);

        let sent = transport.sent_peer_ids();
        assert_eq!(sent.len(), GOSSIP_FANOUT);
        let unique: std::collections::HashSet<_> = sent.iter().collect();
        assert_eq!(
            unique.len(),
            GOSSIP_FANOUT,
            "fanout targets must be distinct peers"
        );
    }

    #[test]
    fn fanout_uses_fewer_peers_when_fewer_are_known() {
        let anchor = make_identity("anchor-b");
        let record = make_revoked_record(&anchor, "victim-2");
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec!["only-peer"]));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-x");

        engine.broadcast(record);

        assert_eq!(transport.sent_peer_ids().len(), 1);
    }

    #[test]
    fn duplicate_revocation_id_is_dropped_without_reforwarding() {
        let anchor = make_identity("anchor-c");
        let record = make_revoked_record(&anchor, "victim-3");
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec!["p1", "p2", "p3"]));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-x");

        let revocation_id = GossipEnvelope::derive_revocation_id(&record);
        let envelope = GossipEnvelope {
            record: record.clone(),
            hop_count: 1,
            origin_id: "peer-1".to_string(),
            revocation_id: revocation_id.clone(),
        };

        assert!(engine.receive(envelope.clone()));
        let first_send_count = transport.sent.lock().unwrap().len();
        assert!(first_send_count > 0, "first sighting must forward");

        assert!(engine.receive(envelope));
        let second_send_count = transport.sent.lock().unwrap().len();
        assert_eq!(
            first_send_count, second_send_count,
            "duplicate revocation_id must not trigger additional forwards"
        );
    }

    #[test]
    fn hop_count_at_max_is_not_forwarded_further() {
        let anchor = make_identity("anchor-d");
        let record = make_revoked_record(&anchor, "victim-4");
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec!["p1", "p2", "p3"]));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-x");

        let envelope = GossipEnvelope {
            record,
            hop_count: GOSSIP_MAX_HOPS,
            origin_id: "peer-1".to_string(),
            revocation_id: "rev-at-max-hops".to_string(),
        };

        assert!(
            engine.receive(envelope),
            "record still verifies and is accepted"
        );
        assert!(
            transport.sent.lock().unwrap().is_empty(),
            "must not forward once hop_count == GOSSIP_MAX_HOPS"
        );
    }

    #[test]
    fn invalid_signature_is_rejected_never_stored_or_forwarded() {
        let anchor = make_identity("anchor-e");
        let untrusted_signer = make_identity("attacker");
        // Sign with a key the trust_store does NOT recognize as an anchor.
        let record = crate::faitf::DistributedRevocationInfrastructure::new()
            .revoke("victim-5", "forged", &untrusted_signer, "fp-x")
            .unwrap();

        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec!["p1", "p2", "p3"]));
        let engine = GossipEngine::new(transport.clone(), dri.clone(), trust_store, "node-x");

        let envelope = GossipEnvelope {
            record,
            hop_count: 0,
            origin_id: "attacker-node".to_string(),
            revocation_id: "rev-forged".to_string(),
        };

        assert!(
            !engine.receive(envelope),
            "unverifiable record must be rejected"
        );
        assert!(
            transport.sent.lock().unwrap().is_empty(),
            "rejected record must never be forwarded"
        );
        assert!(
            !dri.is_revoked("victim-5", "fp-x"),
            "rejected record must never be stored"
        );
    }

    #[test]
    fn seen_set_ttl_sweep_evicts_old_entries() {
        let seen = SeenSet::new();
        // Directly manipulate the internal map to simulate an entry whose TTL has already
        // elapsed, without a real sleep.
        {
            let mut map = seen.seen.lock().unwrap();
            map.insert("stale-id".to_string(), now_f64() - 1.0);
        }
        assert_eq!(seen.tracked_count(), 1);
        let evicted = seen.sweep_expired();
        assert_eq!(evicted, 1);
        assert_eq!(seen.tracked_count(), 0);
    }

    #[test]
    fn seen_set_bounded_under_capacity_flood() {
        let seen = SeenSet::new();
        for i in 0..(SEEN_SET_MAX_ENTRIES + 500) {
            seen.check_and_insert(&format!("id-{i}"));
        }
        assert!(
            seen.tracked_count() <= SEEN_SET_MAX_ENTRIES,
            "SeenSet must not grow past SEEN_SET_MAX_ENTRIES under sustained flooding"
        );
    }

    #[test]
    fn no_known_peers_is_a_safe_no_op() {
        let anchor = make_identity("anchor-f");
        let record = make_revoked_record(&anchor, "victim-6");
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec![]));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-x");

        engine.broadcast(record);
        assert!(transport.sent.lock().unwrap().is_empty());
    }

    #[test]
    fn derive_revocation_id_is_stable_for_same_record_fields() {
        let anchor = make_identity("anchor-g");
        let record1 = make_revoked_record(&anchor, "victim-7");
        let id1a = GossipEnvelope::derive_revocation_id(&record1);
        let id1b = GossipEnvelope::derive_revocation_id(&record1);
        assert_eq!(id1a, id1b);
    }

    /// R9 (Phase 4): an accepted (verified + stored) revocation must refresh
    /// the last-received-revocation timestamp so the
    /// `saacp_revocation_lag_seconds` gauge stays near zero while gossip is
    /// healthy. A fleet operator alerts on sustained lag > 300s (documented
    /// on the Prometheus series).
    #[test]
    fn accepted_revocation_updates_revocation_lag_gauge() {
        let anchor = make_identity("anchor-lag");
        let record = make_revoked_record(&anchor, "victim-lag");
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let transport = Arc::new(FakeTransport::new(vec!["p1", "p2", "p3"]));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-lag");

        let envelope = GossipEnvelope {
            record,
            hop_count: 0,
            origin_id: "origin-node".to_string(),
            revocation_id: "rev-lag".to_string(),
        };
        assert!(engine.receive(envelope), "signed record must be accepted");

        let lag = crate::telemetry::global_telemetry().revocation_lag_seconds();
        assert!(
            lag < 60,
            "a just-received revocation must leave the lag gauge near zero, got {lag}s"
        );
    }

    /// R9 (Phase 4): the bounded-retry send helper sends exactly
    /// `1 + GOSSIP_SEND_RETRIES` times. With the default const (`0`) this is
    /// exactly one send — the pre-R9 fire-and-forget behavior, unchanged.
    /// (The transport seam is ack-less, so a raised retry count is an
    /// unconditional at-least-once redelivery; receiver SeenSet dedup makes
    /// duplicates safe.)
    #[test]
    fn bounded_retry_helper_sends_once_plus_retries() {
        assert_eq!(
            GOSSIP_SEND_RETRIES, 0,
            "the default must preserve fire-and-forget (zero behavior change)"
        );
        let anchor = make_identity("anchor-retry");
        let transport = Arc::new(FakeTransport::new(vec!["p1"]));
        let dri = Arc::new(DistributedRevocationInfrastructure::new());
        let trust_store = Arc::new(make_trust_store_with_anchor(&anchor));
        let engine = GossipEngine::new(transport.clone(), dri, trust_store, "node-retry");

        engine.send_with_bounded_retries("p1", b"payload");
        assert_eq!(
            transport.sent.lock().unwrap().len(),
            1 + GOSSIP_SEND_RETRIES as usize,
            "the helper must send exactly 1 + GOSSIP_SEND_RETRIES times"
        );
    }

    /// M-E regression (single sequential fn — the telemetry counter is
    /// process-global and this binary's tests run in parallel): an unknown
    /// peer is a no-op (no count), and a send to an unreachable peer lands on
    /// the send pool and IS counted (`gossip_send_failures_total`) instead of
    /// being dropped silently — the audit's "fires but nobody sees it" gap.
    #[test]
    fn send_pool_counts_failures_and_ignores_unknown_peers() {
        use std::net::SocketAddr;
        let snapshot =
            || crate::telemetry::global_telemetry().snapshot()["gossip_send_failures_total"];
        let before = snapshot();

        // Port 1 on loopback: connection refused immediately, deterministically.
        let addr: SocketAddr = "127.0.0.1:1".parse().expect("static addr");
        let transport = StaticPeerListTransport::new(vec![("dead".to_string(), addr)]);

        // 1) Unknown peer: no pool job, no counter movement.
        transport.send_to_peer("nobody", b"payload");
        std::thread::sleep(std::time::Duration::from_millis(100));
        assert_eq!(
            snapshot(),
            before,
            "unknown peer must not touch the failure counter"
        );

        // 2) Known-but-unreachable peer: the pool worker's refused connect
        //    must be counted. Poll with a deadline instead of assuming
        //    scheduling.
        transport.send_to_peer("dead", b"payload");
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if snapshot() > before {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "refused connect must increment gossip_send_failures_total within 5s"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
