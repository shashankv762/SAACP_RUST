//! cluster.rs — Active-Active Clustering & Failover.
//!
//! Cluster membership gossip plus quorum-gated leader election, so a fleet of SAACP
//! daemons keeps serving when one instance dies. Three cooperating mechanisms:
//!
//! 1. **Membership** — every node holds a view of every other node's
//!    [`NodeState`] (`Alive`/`Suspect`/`Dead`/`Left`). Views are disseminated by
//!    piggybacking the full member list onto every outbound message and merged with
//!    SWIM's incarnation-number rules, so a node wrongly suspected can *refute* the
//!    suspicion by bumping its own incarnation.
//! 2. **Failure detection** — [`ClusterEngine::tick`] promotes a member not heard from
//!    within [`ClusterConfig::suspect_timeout`] to `Suspect`, and a member `Suspect` for
//!    longer than [`ClusterConfig::dead_timeout`] to `Dead`.
//! 3. **Leader election + failover** — leadership is a pure function of the alive set
//!    (lowest `SHA256(node_id)` wins), so every node that agrees on membership agrees on
//!    the leader with no voting round. When the leader dies, the next tick recomputes it
//!    and fires the registered [`ClusterEngine::on_leadership_change`] hooks.
//!
//! # Why this is not just "gossip.rs with more message types"
//!
//! [`crate::gossip`] fans out revocations and explicitly disclaims membership: *"a real
//! multi-node peer-discovery mesh (membership, retry/backoff) is out of scope for this
//! module"*. That's exactly this module. The two are independent — a deployment can run
//! either, both, or neither.
//!
//! # Split-brain: fail closed
//!
//! A node only claims leadership while it can see a **strict majority** of
//! [`ClusterConfig::expected_cluster_size`]. Partition 5 nodes into 3+2 and the minority
//! side has no leader at all rather than a second one. This is the single most important
//! property here: [`ClusterEngine::is_leader`] returning `false` on both sides of a
//! partition is a correct, safe answer; returning `true` on both is data corruption.
//!
//! Membership consensus alone is still only as timely as gossip convergence, so during
//! the seconds after a partition two nodes *can* transiently both believe they hold
//! leadership. Two independent mechanisms bound the damage:
//!
//! - **Fencing epoch** — [`ClusterEngine::leader_epoch`] increases monotonically on every
//!   leadership change and never decreases. A downstream resource that records the epoch
//!   of the writer it last accepted can reject a stale leader's late-arriving write, the
//!   standard fencing-token pattern.
//! - **Optional CAS lease** ([`ClusterEngine::with_lease_backend`]) — when a
//!   [`StateBackend`] is configured, winning the election is necessary but *not
//!   sufficient*: the node must also win a `compare_and_swap` lease on a shared key.
//!   `state_backend.rs` already documents CAS as the primitive for exactly this. With a
//!   backend configured, mutual exclusion is enforced by the backend rather than inferred
//!   from gossip convergence, which is what a deployment that cannot tolerate even a
//!   transient double-leader should use.
//!
//! # Every message is signed
//!
//! This is a security protocol, so unauthenticated membership messages would be a
//! critical vulnerability — anyone able to reach the port could declare the leader dead
//! and trigger an endless failover storm. Every [`ClusterMessage`] is Ed25519-signed over
//! a canonical serialization of its body and verified against a [`TrustStore`] before any
//! field is read. Beyond the signature, a message is rejected unless it is fresh
//! (bounded clock-skew window) and strictly newer than the last accepted message from
//! that sender, so a captured message cannot be replayed.
//!
//! # Transport
//!
//! [`ClusterTransport`] is a trait seam mirroring [`crate::gossip::GossipTransport`] —
//! fire-and-forget, never blocking its caller. [`StaticClusterTransport`] ships as a
//! working reference implementation. Because the transport is one-way, failure detection
//! is heartbeat-plus-suspicion with gossip dissemination rather than SWIM's
//! ping/ping-req indirection (which needs request/response); this detects a dead node
//! just as reliably, but cannot distinguish "node is dead" from "the path between us is
//! dead" as sharply as indirect probing would.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::faitf::{AgentIdentity, TrustStore};
use crate::state_backend::StateBackend;

fn now_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema id of the wire envelope carrying a [`ClusterMessage`] (`src/schemas.rs`).
pub const CLUSTER_SCHEMA_ID: u16 = 12;

/// A member not heard from for this long is promoted to [`NodeState::Suspect`].
pub const DEFAULT_SUSPECT_TIMEOUT: Duration = Duration::from_secs(5);

/// A member that has been [`NodeState::Suspect`] for this long is declared
/// [`NodeState::Dead`], triggering failover if it held leadership. Must exceed
/// [`DEFAULT_SUSPECT_TIMEOUT`] so a node always gets a refutation window.
pub const DEFAULT_DEAD_TIMEOUT: Duration = Duration::from_secs(15);

/// Messages older than this (by their signed `sent_at`) are rejected as stale/replayed.
pub const DEFAULT_MESSAGE_MAX_AGE: Duration = Duration::from_secs(10);

/// Tolerance for a peer's clock running ahead of ours. Matches `faitf::MAX_CLOCK_SKEW`.
pub const CLUSTER_MAX_CLOCK_SKEW: f64 = 5.0;

/// Upper bound on tracked members — bounded-map idiom (Architecture Principle #5).
/// An authenticated peer flooding fabricated node ids must not grow the view unboundedly.
pub const CLUSTER_MAX_MEMBERS: usize = 1_024;

/// TTL of the optional leadership CAS lease. `RedisBackend` expresses TTLs in whole
/// seconds with a floor of 1, so sub-second lease TTLs are not representable.
pub const DEFAULT_LEASE_TTL: Duration = Duration::from_secs(5);

/// Key prefix for the leadership lease when a [`StateBackend`] is configured.
pub const LEASE_KEY_PREFIX: &str = "saacp:cluster:leader:";

// ---------------------------------------------------------------------------
// NodeState
// ---------------------------------------------------------------------------

/// Lifecycle state of one cluster member.
///
/// The `u8` discriminants define *merge precedence* at equal incarnation: a higher value
/// overrides a lower one. Only a strictly higher incarnation (i.e. the node itself
/// refuting) can move a member back down toward `Alive`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum NodeState {
    Alive = 0,
    Suspect = 1,
    Dead = 2,
    /// Voluntary, graceful departure ([`ClusterEngine::leave`]) — terminal, and never
    /// refuted, which is what distinguishes it from `Dead`.
    Left = 3,
}

impl NodeState {
    pub fn as_str(self) -> &'static str {
        match self {
            NodeState::Alive => "alive",
            NodeState::Suspect => "suspect",
            NodeState::Dead => "dead",
            NodeState::Left => "left",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "alive" => Some(NodeState::Alive),
            "suspect" => Some(NodeState::Suspect),
            "dead" => Some(NodeState::Dead),
            "left" => Some(NodeState::Left),
            _ => None,
        }
    }

    /// Whether a member in this state counts toward quorum and leader candidacy.
    pub fn counts_for_quorum(self) -> bool {
        matches!(self, NodeState::Alive)
    }
}

// ---------------------------------------------------------------------------
// MemberRecord / MemberUpdate
// ---------------------------------------------------------------------------

/// This node's local view of one cluster member.
#[derive(Debug, Clone)]
pub struct MemberRecord {
    pub node_id: String,
    /// Advertised address, carried for operator diagnostics and transport hints. Never
    /// used to decide trust — that is the signature check alone.
    pub addr: String,
    pub incarnation: u64,
    pub state: NodeState,
    /// Wall-clock time this record last changed state (drives the dead-timeout).
    pub state_changed_at: f64,
    /// Wall-clock time a signed message from this member was last accepted.
    pub last_seen: f64,
}

/// One member's status as disseminated inside a [`ClusterMessage`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberUpdate {
    pub node_id: String,
    pub addr: String,
    pub incarnation: u64,
    pub state: NodeState,
}

// ---------------------------------------------------------------------------
// ClusterMessage
// ---------------------------------------------------------------------------

/// Message kinds. All carry the same piggybacked membership payload; the kind is
/// advisory (it records *why* the message was sent) and never grants authority.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterMessageKind {
    /// Periodic liveness beacon emitted by [`ClusterEngine::tick`].
    Heartbeat,
    /// Immediate out-of-band push (refutation, leadership change, departure).
    Sync,
}

impl ClusterMessageKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterMessageKind::Heartbeat => "heartbeat",
            ClusterMessageKind::Sync => "sync",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "heartbeat" => Some(ClusterMessageKind::Heartbeat),
            "sync" => Some(ClusterMessageKind::Sync),
            _ => None,
        }
    }
}

/// A signed cluster-membership message.
///
/// `signature` covers [`Self::body_bytes`] — every field except `signature` and
/// `sender_key_id` itself. `sender_key_id` is excluded following
/// `faitf::SignedRevocationRecord`'s convention: it only selects *which* key to verify
/// against, so tampering with it makes verification fail rather than succeed.
#[derive(Debug, Clone)]
pub struct ClusterMessage {
    pub kind: ClusterMessageKind,
    pub sender_id: String,
    /// The sender's own incarnation at send time — the SWIM refutation counter.
    pub sender_incarnation: u64,
    /// Strictly increasing per-sender counter. Combined with `sender_incarnation` into
    /// the `(incarnation, sequence)` replay high-water mark.
    pub sequence: u64,
    pub sent_at: f64,
    /// The sender's current fencing epoch (0 when it knows of no leader).
    pub leader_epoch: u64,
    /// The sender's believed leader, or empty when it believes there is none.
    pub leader_id: String,
    /// The sender's configured [`ClusterConfig::expected_cluster_size`]. Carried purely
    /// so a misconfiguration (two nodes disagreeing on cluster size, which would give
    /// them different quorum thresholds) is detectable rather than silent.
    pub cluster_size: usize,
    pub updates: Vec<MemberUpdate>,
    pub signature: Vec<u8>,
    pub sender_key_id: String,
}

impl ClusterMessage {
    /// Canonical, signature-covered serialization.
    ///
    /// Built through a `BTreeMap` projection (via `serde_json`'s already-`BTreeMap`-backed
    /// `Map`, made explicit here) so byte-stability does not silently depend on
    /// `serde_json`'s key ordering — the same reasoning as
    /// `faitf::sorted_json_bytes`/`acsvaf::serialize_sorted_json`.
    pub fn body_bytes(&self) -> Vec<u8> {
        let updates: Vec<serde_json::Value> = self
            .updates
            .iter()
            .map(|u| {
                json!({
                    "node_id": u.node_id,
                    "addr": u.addr,
                    "incarnation": u.incarnation,
                    "state": u.state.as_str(),
                })
            })
            .collect();
        let body = json!({
            "kind": self.kind.as_str(),
            "sender_id": self.sender_id,
            "sender_incarnation": self.sender_incarnation,
            "sequence": self.sequence,
            "sent_at": self.sent_at,
            "leader_epoch": self.leader_epoch,
            "leader_id": self.leader_id,
            "cluster_size": self.cluster_size,
            "updates": updates,
        });
        sorted_json_bytes(&body)
    }

    /// Serialize to the wire form used by every signed record in this crate
    /// (`faitf::SignedRevocationRecord::to_wire`):
    /// `B64(u32_be(body_len) || body || signature[64] || sender_key_id)`.
    pub fn to_wire(&self) -> Vec<u8> {
        let body = self.body_bytes();
        let mut raw = Vec::with_capacity(4 + body.len() + 64 + self.sender_key_id.len());
        raw.extend_from_slice(&(body.len() as u32).to_be_bytes());
        raw.extend_from_slice(&body);
        raw.extend_from_slice(&self.signature);
        raw.extend_from_slice(self.sender_key_id.as_bytes());
        B64.encode(raw).into_bytes()
    }

    /// Parse a wire message. **Does not verify the signature** — that is
    /// [`ClusterEngine::receive_wire`]'s job, matching
    /// `faitf::SignedRevocationRecord::from_wire`'s split of parsing from verification.
    pub fn from_wire(wire: &[u8]) -> Result<Self, String> {
        let raw = B64
            .decode(wire)
            .map_err(|e| format!("cluster message base64 decode failed: {e}"))?;
        if raw.len() < 4 {
            return Err("cluster message truncated (no length prefix)".to_string());
        }
        let body_len = u32::from_be_bytes([raw[0], raw[1], raw[2], raw[3]]) as usize;
        if body_len == 0 {
            return Err("cluster message has empty body".to_string());
        }
        // Checked arithmetic: a crafted `body_len` near u32::MAX would otherwise
        // overflow this sum on a 32-bit target and let the bounds check pass.
        let min_len = 4usize
            .checked_add(body_len)
            .and_then(|n| n.checked_add(64))
            .ok_or_else(|| "cluster message length overflow".to_string())?;
        if raw.len() < min_len {
            return Err("cluster message truncated (body/signature)".to_string());
        }
        let body = &raw[4..4 + body_len];
        let signature = raw[4 + body_len..4 + body_len + 64].to_vec();
        let sender_key_id = String::from_utf8_lossy(&raw[4 + body_len + 64..]).to_string();

        let parsed: serde_json::Value = serde_json::from_slice(body)
            .map_err(|e| format!("cluster message body is not valid JSON: {e}"))?;

        let kind = ClusterMessageKind::from_str(parsed["kind"].as_str().unwrap_or(""))
            .ok_or_else(|| "cluster message has unknown kind".to_string())?;
        let sender_id = parsed["sender_id"].as_str().unwrap_or("").to_string();
        if sender_id.is_empty() {
            return Err("cluster message has empty sender_id".to_string());
        }

        let mut updates = Vec::new();
        if let Some(arr) = parsed["updates"].as_array() {
            if arr.len() > CLUSTER_MAX_MEMBERS {
                return Err("cluster message carries more updates than CLUSTER_MAX_MEMBERS".to_string());
            }
            for entry in arr {
                let node_id = entry["node_id"].as_str().unwrap_or("").to_string();
                if node_id.is_empty() {
                    return Err("cluster message update has empty node_id".to_string());
                }
                let state = NodeState::from_str(entry["state"].as_str().unwrap_or(""))
                    .ok_or_else(|| "cluster message update has unknown state".to_string())?;
                updates.push(MemberUpdate {
                    node_id,
                    addr: entry["addr"].as_str().unwrap_or("").to_string(),
                    incarnation: entry["incarnation"].as_u64().unwrap_or(0),
                    state,
                });
            }
        }

        Ok(Self {
            kind,
            sender_id,
            sender_incarnation: parsed["sender_incarnation"].as_u64().unwrap_or(0),
            sequence: parsed["sequence"].as_u64().unwrap_or(0),
            sent_at: parsed["sent_at"].as_f64().unwrap_or(0.0),
            leader_epoch: parsed["leader_epoch"].as_u64().unwrap_or(0),
            leader_id: parsed["leader_id"].as_str().unwrap_or("").to_string(),
            cluster_size: parsed["cluster_size"].as_u64().unwrap_or(0) as usize,
            updates,
            signature,
            sender_key_id,
        })
    }
}

/// Explicit `BTreeMap` projection before serializing — see [`ClusterMessage::body_bytes`].
fn sorted_json_bytes(value: &serde_json::Value) -> Vec<u8> {
    match value {
        serde_json::Value::Object(map) => {
            let sorted: std::collections::BTreeMap<&String, &serde_json::Value> =
                map.iter().collect();
            serde_json::to_vec(&sorted).unwrap_or_default()
        }
        other => serde_json::to_vec(other).unwrap_or_default(),
    }
}

// ---------------------------------------------------------------------------
// Rejection reasons
// ---------------------------------------------------------------------------

/// Why an inbound cluster message was refused. Returned rather than logged-and-swallowed
/// so tests can assert the *specific* defense that fired, and so a caller can feed
/// precise telemetry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClusterRejection {
    /// Wire bytes were unparseable.
    Malformed,
    /// Sender is not a configured peer of this cluster.
    UnknownSender,
    /// No verifying key for `sender_key_id` in the `TrustStore`.
    UntrustedKey,
    /// Ed25519 verification failed.
    BadSignature,
    /// `sent_at` outside the accepted freshness window.
    Stale,
    /// `(incarnation, sequence)` not strictly greater than the last accepted pair.
    Replay,
    /// A field outside the signed body disagreed with the signed body.
    EnvelopeMismatch,
    /// Sender addressed a different cluster.
    WrongCluster,
}

impl ClusterRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            ClusterRejection::Malformed => "malformed",
            ClusterRejection::UnknownSender => "unknown_sender",
            ClusterRejection::UntrustedKey => "untrusted_key",
            ClusterRejection::BadSignature => "bad_signature",
            ClusterRejection::Stale => "stale",
            ClusterRejection::Replay => "replay",
            ClusterRejection::EnvelopeMismatch => "envelope_mismatch",
            ClusterRejection::WrongCluster => "wrong_cluster",
        }
    }
}

// ---------------------------------------------------------------------------
// ClusterTransport
// ---------------------------------------------------------------------------

/// Seam between cluster logic and network delivery, mirroring
/// [`crate::gossip::GossipTransport`]. Implementations MUST NOT block indefinitely and
/// SHOULD drop-and-log on failure: a missed heartbeat is recovered by the next tick, so
/// per-send retries only add latency to the failure detector.
pub trait ClusterTransport: Send + Sync {
    /// Node ids of every configured peer (excluding self).
    fn peers(&self) -> Vec<String>;
    /// Best-effort, fire-and-forget delivery of an already-signed wire message.
    fn send_to(&self, node_id: &str, bytes: &[u8]);
}

/// A working [`ClusterTransport`] over a fixed operator-configured peer list, sending via
/// a short-lived `TcpStream` per message — the same primitive
/// [`crate::gossip::StaticPeerListTransport`] uses.
pub struct StaticClusterTransport {
    peers: Mutex<HashMap<String, SocketAddr>>,
}

impl StaticClusterTransport {
    pub fn new(peers: Vec<(String, SocketAddr)>) -> Self {
        Self {
            peers: Mutex::new(peers.into_iter().collect()),
        }
    }
}

impl ClusterTransport for StaticClusterTransport {
    fn peers(&self) -> Vec<String> {
        self.peers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .keys()
            .cloned()
            .collect()
    }

    fn send_to(&self, node_id: &str, bytes: &[u8]) {
        let addr = {
            let peers = self.peers.lock().unwrap_or_else(|e| e.into_inner());
            match peers.get(node_id) {
                Some(a) => *a,
                None => return,
            }
        };
        let bytes = bytes.to_vec();
        std::thread::spawn(move || {
            use std::io::Write;
            if let Ok(mut stream) =
                std::net::TcpStream::connect_timeout(&addr, Duration::from_secs(2))
            {
                let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
                let _ = stream.write_all(&bytes);
            }
        });
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Tunables for one [`ClusterEngine`].
#[derive(Debug, Clone)]
pub struct ClusterConfig {
    /// Logical cluster name. Nodes reject messages from a differently-named cluster, so
    /// a staging node pointed at production cannot join it.
    pub cluster_name: String,
    /// Total nodes the operator intends to run. **Quorum is derived from this, not from
    /// the number of nodes currently visible** — deriving it from the live view would let
    /// a shrinking partition keep lowering its own bar and elect a leader, which is the
    /// classic split-brain bug this design exists to prevent.
    pub expected_cluster_size: usize,
    pub suspect_timeout: Duration,
    pub dead_timeout: Duration,
    pub message_max_age: Duration,
    pub lease_ttl: Duration,
}

impl ClusterConfig {
    pub fn new(cluster_name: impl Into<String>, expected_cluster_size: usize) -> Self {
        Self {
            cluster_name: cluster_name.into(),
            expected_cluster_size: expected_cluster_size.max(1),
            suspect_timeout: DEFAULT_SUSPECT_TIMEOUT,
            dead_timeout: DEFAULT_DEAD_TIMEOUT,
            message_max_age: DEFAULT_MESSAGE_MAX_AGE,
            lease_ttl: DEFAULT_LEASE_TTL,
        }
    }

    /// Strict majority of [`Self::expected_cluster_size`].
    pub fn quorum(&self) -> usize {
        self.expected_cluster_size / 2 + 1
    }

    pub fn with_timeouts(mut self, suspect: Duration, dead: Duration) -> Self {
        self.suspect_timeout = suspect;
        // A dead-timeout at or below the suspect-timeout would declare a node dead before
        // its refutation could plausibly arrive, so hold the invariant here rather than
        // trusting every call site to respect it.
        self.dead_timeout = dead.max(suspect + Duration::from_millis(1));
        self
    }

    pub fn with_message_max_age(mut self, max_age: Duration) -> Self {
        self.message_max_age = max_age;
        self
    }

    pub fn with_lease_ttl(mut self, ttl: Duration) -> Self {
        self.lease_ttl = ttl;
        self
    }
}

// ---------------------------------------------------------------------------
// Leadership
// ---------------------------------------------------------------------------

/// Emitted to every hook registered via [`ClusterEngine::on_leadership_change`].
#[derive(Debug, Clone)]
pub struct LeadershipChange {
    pub previous_leader: Option<String>,
    pub new_leader: Option<String>,
    /// Fencing token — strictly greater than the epoch of any prior change on this node.
    pub epoch: u64,
    /// Whether *this* node now holds leadership.
    pub self_is_leader: bool,
    pub at: f64,
}

/// What one [`ClusterEngine::tick`] did, for observability and tests.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickOutcome {
    pub newly_suspect: usize,
    pub newly_dead: usize,
    pub heartbeats_sent: usize,
    pub leadership_changed: bool,
}

type LeadershipHook = Box<dyn Fn(&LeadershipChange) + Send + Sync>;

// ---------------------------------------------------------------------------
// ClusterEngine
// ---------------------------------------------------------------------------

/// Owns this node's membership view, failure detector, and leadership state.
///
/// # Lock discipline
///
/// Four independent `Mutex`es. No method ever holds two at once — each takes a lock,
/// extracts or mutates what it needs, drops it, then proceeds. This makes deadlock
/// unrepresentable rather than merely avoided by a documented ordering, and keeps
/// Ed25519 verification off the critical section entirely.
pub struct ClusterEngine {
    node_id: String,
    identity: Arc<AgentIdentity>,
    trust_store: Arc<TrustStore>,
    transport: Arc<dyn ClusterTransport>,
    config: ClusterConfig,

    members: Mutex<HashMap<String, MemberRecord>>,
    /// `sender_id -> (incarnation, sequence)` replay high-water mark.
    replay_high_water: Mutex<HashMap<String, (u64, u64)>>,
    leader: Mutex<Option<String>>,
    hooks: Mutex<Vec<LeadershipHook>>,

    /// This node's SWIM incarnation. Seeded from wall-clock seconds so it is strictly
    /// greater after a process restart than before it — otherwise a restarted node would
    /// re-emit `(incarnation=0, sequence=0)` and every peer's replay high-water mark
    /// would silently reject it until the entry aged out.
    incarnation: AtomicU64,
    sequence: AtomicU64,
    leader_epoch: AtomicU64,

    lease_backend: Mutex<Option<Arc<dyn StateBackend>>>,
}

impl ClusterEngine {
    /// Construct an engine for `identity.agent_id`.
    ///
    /// `identity` signs every outbound message; `trust_store` must already hold each
    /// peer's verifying key (via `TrustStore::pin_identity` or
    /// `register_key_by_fingerprint`) or messages from that peer are refused as
    /// [`ClusterRejection::UntrustedKey`] — fail-closed, so an unconfigured cluster
    /// forms no membership at all rather than trusting whoever connects first.
    pub fn new(
        identity: Arc<AgentIdentity>,
        trust_store: Arc<TrustStore>,
        transport: Arc<dyn ClusterTransport>,
        config: ClusterConfig,
        addr: impl Into<String>,
    ) -> Self {
        let node_id = identity.agent_id.clone();
        let now = now_f64();
        let addr = addr.into();

        let mut members = HashMap::new();
        members.insert(
            node_id.clone(),
            MemberRecord {
                node_id: node_id.clone(),
                addr: addr.clone(),
                incarnation: now as u64,
                state: NodeState::Alive,
                state_changed_at: now,
                last_seen: now,
            },
        );

        Self {
            node_id,
            identity,
            trust_store,
            transport,
            config,
            members: Mutex::new(members),
            replay_high_water: Mutex::new(HashMap::new()),
            leader: Mutex::new(None),
            hooks: Mutex::new(Vec::new()),
            incarnation: AtomicU64::new(now as u64),
            sequence: AtomicU64::new(0),
            leader_epoch: AtomicU64::new(0),
            lease_backend: Mutex::new(None),
        }
    }

    /// Require a `compare_and_swap` lease, in addition to winning the election, before
    /// this node reports itself leader — see the module doc's split-brain section.
    ///
    /// Use a backend whose `compare_and_swap` is genuinely atomic
    /// (`InMemoryBackend`/`RedisBackend` both override the non-atomic default body); a
    /// process-local `InMemoryBackend` provides no cross-node exclusion and is only
    /// meaningful in tests.
    pub fn with_lease_backend(self, backend: Arc<dyn StateBackend>) -> Self {
        *self.lease_backend.lock().unwrap_or_else(|e| e.into_inner()) = Some(backend);
        self
    }

    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    pub fn config(&self) -> &ClusterConfig {
        &self.config
    }

    /// Register a callback fired on every leadership change — the failover hook. Called
    /// synchronously from [`Self::tick`]/[`Self::receive_wire`], so it must not block or
    /// re-enter this engine.
    pub fn on_leadership_change(&self, hook: impl Fn(&LeadershipChange) + Send + Sync + 'static) {
        self.hooks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(Box::new(hook));
    }

    /// The node this one currently believes is leader, or `None` when quorum is lost.
    pub fn leader(&self) -> Option<String> {
        self.leader.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Whether this node currently holds leadership. `false` on both sides of a
    /// quorum-losing partition, by design.
    pub fn is_leader(&self) -> bool {
        self.leader
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_deref()
            == Some(self.node_id.as_str())
    }

    /// Current fencing token. Monotonically non-decreasing for the life of the process.
    pub fn leader_epoch(&self) -> u64 {
        self.leader_epoch.load(Ordering::Relaxed)
    }

    pub fn incarnation(&self) -> u64 {
        self.incarnation.load(Ordering::Relaxed)
    }

    /// Number of members currently `Alive`, including this node when it is.
    pub fn alive_count(&self) -> usize {
        self.members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|m| m.state.counts_for_quorum())
            .count()
    }

    /// Whether this node can currently see a strict majority of the cluster.
    pub fn has_quorum(&self) -> bool {
        self.alive_count() >= self.config.quorum()
    }

    pub fn member_count(&self) -> usize {
        self.members.lock().unwrap_or_else(|e| e.into_inner()).len()
    }

    pub fn state_of(&self, node_id: &str) -> Option<NodeState> {
        self.members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(node_id)
            .map(|m| m.state)
    }

    /// Snapshot of the full membership view, sorted by node id for stable output.
    pub fn members(&self) -> Vec<MemberRecord> {
        let mut v: Vec<MemberRecord> = self
            .members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .cloned()
            .collect();
        v.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        v
    }

    /// Seed a peer into the membership view before any message has been received, so a
    /// freshly started node knows who it is waiting for.
    pub fn add_peer(&self, node_id: &str, addr: &str) {
        if node_id == self.node_id {
            return;
        }
        let now = now_f64();
        let mut members = self.members.lock().unwrap_or_else(|e| e.into_inner());
        if members.contains_key(node_id) || members.len() >= CLUSTER_MAX_MEMBERS {
            return;
        }
        members.insert(
            node_id.to_string(),
            MemberRecord {
                node_id: node_id.to_string(),
                addr: addr.to_string(),
                incarnation: 0,
                // Seeded as Suspect, not Alive: a peer we have never heard a signed
                // message from must not count toward quorum, or a single node could
                // reach quorum purely from its own static config.
                state: NodeState::Suspect,
                state_changed_at: now,
                last_seen: now,
            },
        );
    }

    // -----------------------------------------------------------------------
    // Outbound
    // -----------------------------------------------------------------------

    /// Build and sign a message carrying this node's current membership view.
    pub fn build_message(&self, kind: ClusterMessageKind) -> ClusterMessage {
        let updates: Vec<MemberUpdate> = self
            .members
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .map(|m| MemberUpdate {
                node_id: m.node_id.clone(),
                addr: m.addr.clone(),
                incarnation: m.incarnation,
                state: m.state,
            })
            .collect();

        let leader_id = self.leader().unwrap_or_default();

        let mut msg = ClusterMessage {
            kind,
            sender_id: self.node_id.clone(),
            sender_incarnation: self.incarnation.load(Ordering::Relaxed),
            sequence: self.sequence.fetch_add(1, Ordering::Relaxed) + 1,
            sent_at: now_f64(),
            leader_epoch: self.leader_epoch.load(Ordering::Relaxed),
            leader_id,
            cluster_size: self.config.expected_cluster_size,
            updates,
            signature: Vec::new(),
            sender_key_id: self.identity.fingerprint(),
        };
        msg.signature = sign_data(&self.identity.signing_key, &msg.body_bytes());
        msg
    }

    /// Sign and fan a message out to every configured peer. Returns how many sends were
    /// attempted (delivery itself is fire-and-forget).
    pub fn broadcast(&self, kind: ClusterMessageKind) -> usize {
        let msg = self.build_message(kind);
        let wire = msg.to_wire();
        let peers = self.transport.peers();
        for peer in &peers {
            if peer == &self.node_id {
                continue;
            }
            self.transport.send_to(peer, &wire);
        }
        peers.iter().filter(|p| *p != &self.node_id).count()
    }

    /// Announce a graceful departure so peers record [`NodeState::Left`] immediately
    /// instead of waiting out the dead-timeout. Call before shutting the daemon down.
    pub fn leave(&self) {
        {
            let now = now_f64();
            let mut members = self.members.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(me) = members.get_mut(&self.node_id) {
                me.state = NodeState::Left;
                me.state_changed_at = now;
                me.incarnation += 1;
            }
        }
        self.incarnation.fetch_add(1, Ordering::Relaxed);
        self.broadcast(ClusterMessageKind::Sync);
        self.recompute_leader();
    }

    // -----------------------------------------------------------------------
    // Inbound
    // -----------------------------------------------------------------------

    /// Verify and apply an inbound wire message.
    ///
    /// Order matters and is deliberately cheapest-and-most-decisive first: parse, confirm
    /// the sender is a configured peer, resolve its key, verify the signature, *then*
    /// apply freshness and replay checks against the now-authenticated fields. No field
    /// of the message influences state before its signature has been verified.
    pub fn receive_wire(&self, wire: &[u8]) -> Result<(), ClusterRejection> {
        let msg = ClusterMessage::from_wire(wire).map_err(|_| {
            crate::telemetry::global_telemetry().record_cluster_message_rejected();
            ClusterRejection::Malformed
        })?;
        self.receive_message(msg)
    }

    /// Same as [`Self::receive_wire`] for an already-parsed message.
    pub fn receive_message(&self, msg: ClusterMessage) -> Result<(), ClusterRejection> {
        let outcome = self.receive_message_inner(msg);
        if outcome.is_err() {
            crate::telemetry::global_telemetry().record_cluster_message_rejected();
        }
        outcome
    }

    fn receive_message_inner(&self, msg: ClusterMessage) -> Result<(), ClusterRejection> {
        if msg.sender_id == self.node_id {
            // Our own message echoed back (e.g. a peer list that includes us). Applying it
            // would corrupt our own incarnation bookkeeping.
            return Err(ClusterRejection::UnknownSender);
        }

        // Only configured peers may speak. `transport.peers()` is the operator's explicit
        // roster; combined with the TrustStore key check below, an attacker must both be
        // on the roster and hold a pinned key.
        if !self.transport.peers().iter().any(|p| p == &msg.sender_id) {
            return Err(ClusterRejection::UnknownSender);
        }

        let key = self
            .trust_store
            .get_key_by_fingerprint(&msg.sender_key_id)
            .ok_or(ClusterRejection::UntrustedKey)?;

        if !verify_data(&key, &msg.body_bytes(), &msg.signature) {
            return Err(ClusterRejection::BadSignature);
        }

        // ── Everything below reads only signature-covered fields. ──

        if msg.cluster_size != self.config.expected_cluster_size {
            // Divergent quorum thresholds across nodes would let the two sides of a
            // partition both believe they hold a majority.
            return Err(ClusterRejection::WrongCluster);
        }

        let now = now_f64();
        let age = now - msg.sent_at;
        if age > self.config.message_max_age.as_secs_f64() || age < -CLUSTER_MAX_CLOCK_SKEW {
            return Err(ClusterRejection::Stale);
        }

        {
            let mut hw = self.replay_high_water.lock().unwrap_or_else(|e| e.into_inner());
            let incoming = (msg.sender_incarnation, msg.sequence);
            if let Some(prev) = hw.get(&msg.sender_id) {
                if incoming <= *prev {
                    return Err(ClusterRejection::Replay);
                }
            }
            if hw.len() >= CLUSTER_MAX_MEMBERS && !hw.contains_key(&msg.sender_id) {
                // Bounded: a roster is finite, so this only triggers under a
                // misconfiguration, but it must not grow without bound regardless.
                return Err(ClusterRejection::UnknownSender);
            }
            hw.insert(msg.sender_id.clone(), incoming);
        }

        self.apply_message(&msg, now);
        self.absorb_epoch(msg.leader_epoch);
        self.recompute_leader();
        Ok(())
    }

    /// Verify a message delivered inside a schema-12 envelope, cross-checking the
    /// envelope's plaintext fields against the signed body.
    ///
    /// The envelope duplicates `sender_id`/`leader_epoch`/`message_kind` outside the
    /// signature so the daemon can route without parsing the blob. Any disagreement is a
    /// tampering attempt (or a broken sender) and is rejected as
    /// [`ClusterRejection::EnvelopeMismatch`] — the plaintext copies are never *used*,
    /// only checked, so an attacker rewriting them cannot change what this node applies.
    pub fn receive_envelope(
        &self,
        cluster_message_b64: &str,
        declared_sender: &str,
        declared_epoch: u64,
        declared_kind: &str,
    ) -> Result<(), ClusterRejection> {
        let msg = ClusterMessage::from_wire(cluster_message_b64.as_bytes())
            .map_err(|_| {
                crate::telemetry::global_telemetry().record_cluster_message_rejected();
                ClusterRejection::Malformed
            })?;
        if msg.sender_id != declared_sender
            || msg.leader_epoch != declared_epoch
            || msg.kind.as_str() != declared_kind
        {
            crate::telemetry::global_telemetry().record_cluster_message_rejected();
            return Err(ClusterRejection::EnvelopeMismatch);
        }
        self.receive_message(msg)
    }

    /// The four schema-12 envelope fields for `msg`, in the order
    /// `(cluster_message, sender_id, leader_epoch, message_kind)`.
    pub fn envelope_fields(msg: &ClusterMessage) -> (String, String, u64, String) {
        (
            String::from_utf8_lossy(&msg.to_wire()).to_string(),
            msg.sender_id.clone(),
            msg.leader_epoch,
            msg.kind.as_str().to_string(),
        )
    }

    // -----------------------------------------------------------------------
    // Membership merge
    // -----------------------------------------------------------------------

    fn apply_message(&self, msg: &ClusterMessage, now: f64) {
        // A verified, fresh, non-replayed message is itself proof the sender is reachable,
        // and outranks whatever any *third party* claims about it. The one thing it cannot
        // override is the sender declaring its own graceful departure: `Left` is
        // self-declared and terminal, so a `leave()` announcement must record `Left` even
        // though the very message carrying it proves the sender is still up. Any other
        // self-declared state (a node calling itself Suspect/Dead) is nonsensical and
        // collapses to `Alive` — we just heard from it.
        let declared_self = msg
            .updates
            .iter()
            .find(|u| u.node_id == msg.sender_id)
            .map(|u| u.state);
        let sender_state = match declared_self {
            Some(NodeState::Left) => NodeState::Left,
            _ => NodeState::Alive,
        };

        let mut refute = false;
        {
            let mut members = self.members.lock().unwrap_or_else(|e| e.into_inner());
            Self::merge_one(
                &mut members,
                &MemberUpdate {
                    node_id: msg.sender_id.clone(),
                    addr: String::new(),
                    incarnation: msg.sender_incarnation,
                    state: sender_state,
                },
                now,
                true,
            );

            for update in &msg.updates {
                if update.node_id == self.node_id {
                    // SWIM refutation: someone believes we are not alive. Handled below,
                    // outside the lock, because it mutates our own incarnation counter.
                    if update.state != NodeState::Alive
                        && update.incarnation >= self.incarnation.load(Ordering::Relaxed)
                    {
                        refute = true;
                    }
                    continue;
                }
                if update.node_id == msg.sender_id {
                    // Already handled above with authoritative liveness.
                    continue;
                }
                Self::merge_one(&mut members, update, now, false);
            }
        }

        if refute {
            self.refute_suspicion();
        }
    }

    /// Merge one update into the view under SWIM's incarnation rules.
    ///
    /// `authoritative` marks a fact we established ourselves (a verified message from
    /// that very node), which refreshes `last_seen` even when the state does not change.
    fn merge_one(
        members: &mut HashMap<String, MemberRecord>,
        update: &MemberUpdate,
        now: f64,
        authoritative: bool,
    ) {
        match members.get_mut(&update.node_id) {
            Some(existing) => {
                if existing.state == NodeState::Left {
                    // Terminal: a departed node rejoins only by restarting, which gives it
                    // a wall-clock-seeded incarnation strictly above the one it left with.
                    if update.incarnation <= existing.incarnation {
                        return;
                    }
                }
                let supersedes = update.incarnation > existing.incarnation
                    || (update.incarnation == existing.incarnation && update.state > existing.state);
                if supersedes {
                    if existing.state != update.state {
                        existing.state_changed_at = now;
                    }
                    existing.incarnation = update.incarnation;
                    existing.state = update.state;
                    if !update.addr.is_empty() {
                        existing.addr = update.addr.clone();
                    }
                }
                if authoritative {
                    existing.last_seen = now;
                    if existing.state != NodeState::Alive && update.state == NodeState::Alive {
                        existing.state = NodeState::Alive;
                        existing.state_changed_at = now;
                    }
                }
            }
            None => {
                if members.len() >= CLUSTER_MAX_MEMBERS {
                    return;
                }
                members.insert(
                    update.node_id.clone(),
                    MemberRecord {
                        node_id: update.node_id.clone(),
                        addr: update.addr.clone(),
                        incarnation: update.incarnation,
                        state: update.state,
                        state_changed_at: now,
                        last_seen: now,
                    },
                );
            }
        }
    }

    /// Bump our incarnation above the suspicion and immediately re-announce liveness.
    fn refute_suspicion(&self) {
        let now = now_f64();
        let new_incarnation = self.incarnation.fetch_add(1, Ordering::Relaxed) + 1;
        {
            let mut members = self.members.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(me) = members.get_mut(&self.node_id) {
                if me.state != NodeState::Left {
                    me.incarnation = new_incarnation;
                    me.state = NodeState::Alive;
                    me.state_changed_at = now;
                    me.last_seen = now;
                }
            }
        }
        self.broadcast(ClusterMessageKind::Sync);
    }

    // -----------------------------------------------------------------------
    // Failure detection + election
    // -----------------------------------------------------------------------

    /// One failure-detector cycle: age out silent members, broadcast liveness, and
    /// recompute leadership. Safe to call from [`crate::maintenance::MaintenanceCoordinator`]
    /// or a dedicated thread; see [`Self::start`] for the cadence caveat.
    pub fn tick(&self) -> TickOutcome {
        let now = now_f64();
        let suspect_after = self.config.suspect_timeout.as_secs_f64();
        let dead_after = self.config.dead_timeout.as_secs_f64();

        let mut outcome = TickOutcome::default();
        {
            let mut members = self.members.lock().unwrap_or_else(|e| e.into_inner());
            for member in members.values_mut() {
                if member.node_id == self.node_id || member.state == NodeState::Left {
                    continue;
                }
                match member.state {
                    NodeState::Alive => {
                        if now - member.last_seen > suspect_after {
                            member.state = NodeState::Suspect;
                            member.state_changed_at = now;
                            outcome.newly_suspect += 1;
                        }
                    }
                    NodeState::Suspect => {
                        // Measured from last_seen, not state_changed_at: a node seeded as
                        // Suspect by `add_peer` that never speaks must still become Dead.
                        if now - member.last_seen > dead_after {
                            member.state = NodeState::Dead;
                            member.state_changed_at = now;
                            outcome.newly_dead += 1;
                        }
                    }
                    NodeState::Dead | NodeState::Left => {}
                }
            }
        }

        for _ in 0..outcome.newly_dead {
            crate::telemetry::global_telemetry().record_cluster_member_failed();
        }

        outcome.heartbeats_sent = self.broadcast(ClusterMessageKind::Heartbeat);
        outcome.leadership_changed = self.recompute_leader();
        outcome
    }

    /// Raise our fencing epoch to at least `seen`, so a node rejoining after a partition
    /// never re-issues an epoch a peer has already acted on.
    fn absorb_epoch(&self, seen: u64) {
        self.leader_epoch.fetch_max(seen, Ordering::Relaxed);
    }

    /// Recompute the leader from the current alive set. Returns whether it changed.
    ///
    /// Deterministic: given identical membership views, every node picks the same leader
    /// with no message exchange, so failover costs exactly one detection interval rather
    /// than an election round-trip.
    fn recompute_leader(&self) -> bool {
        let quorum = self.config.quorum();
        let alive: Vec<String> = {
            let members = self.members.lock().unwrap_or_else(|e| e.into_inner());
            members
                .values()
                .filter(|m| m.state.counts_for_quorum())
                .map(|m| m.node_id.clone())
                .collect()
        };

        let candidate = if alive.len() < quorum {
            // Fail closed. A minority partition has no leader at all.
            None
        } else {
            alive
                .iter()
                .min_by_key(|id| hex::encode(Sha256::digest(id.as_bytes())))
                .cloned()
        };

        // Winning the deterministic election is necessary but not sufficient when a lease
        // backend is configured — see `with_lease_backend`.
        let candidate = match candidate {
            Some(id) if id == self.node_id => {
                if self.acquire_or_renew_lease() {
                    Some(id)
                } else {
                    None
                }
            }
            other => other,
        };

        let previous = {
            let mut leader = self.leader.lock().unwrap_or_else(|e| e.into_inner());
            if *leader == candidate {
                return false;
            }
            std::mem::replace(&mut *leader, candidate.clone())
        };

        let epoch = self.leader_epoch.fetch_add(1, Ordering::Relaxed) + 1;
        let change = LeadershipChange {
            previous_leader: previous,
            new_leader: candidate.clone(),
            epoch,
            self_is_leader: candidate.as_deref() == Some(self.node_id.as_str()),
            at: now_f64(),
        };

        let hooks = self.hooks.lock().unwrap_or_else(|e| e.into_inner());
        for hook in hooks.iter() {
            hook(&change);
        }
        crate::telemetry::global_telemetry().record_cluster_leadership_change();
        true
    }

    /// Try to take or renew the shared leadership lease. Returns `true` when no backend
    /// is configured (the lease is then simply not part of the decision).
    ///
    /// A backend error yields `false`: if we cannot prove we hold the lease, we must not
    /// claim leadership.
    fn acquire_or_renew_lease(&self) -> bool {
        let backend = {
            let guard = self.lease_backend.lock().unwrap_or_else(|e| e.into_inner());
            match guard.as_ref() {
                Some(b) => Arc::clone(b),
                None => return true,
            }
        };

        let key = format!("{}{}", LEASE_KEY_PREFIX, self.config.cluster_name);
        let me = self.node_id.as_bytes();
        let ttl = Some(self.config.lease_ttl);

        match backend.get(&key) {
            // Vacant (or expired): claim it. CAS against `None` so two nodes racing here
            // cannot both succeed.
            Ok(None) => backend
                .compare_and_swap(&key, None, me, ttl)
                .unwrap_or(false),
            // Already ours: renew, extending the TTL.
            Ok(Some(current)) if current == me => backend
                .compare_and_swap(&key, Some(&current), me, ttl)
                .unwrap_or(false),
            // Held by another node — it has not expired yet, so we do not take over.
            Ok(Some(_)) => false,
            Err(_) => false,
        }
    }

    /// Remove `Dead`/`Left` members whose state has been terminal for longer than
    /// `dead_timeout`, and drop their replay high-water entries. Returns how many were
    /// removed. Registered by [`crate::maintenance::MaintenanceCoordinator::with_cluster`].
    pub fn sweep_expired(&self) -> usize {
        let now = now_f64();
        let cutoff = self.config.dead_timeout.as_secs_f64();
        let removed: Vec<String> = {
            let mut members = self.members.lock().unwrap_or_else(|e| e.into_inner());
            let doomed: Vec<String> = members
                .values()
                .filter(|m| {
                    m.node_id != self.node_id
                        && matches!(m.state, NodeState::Dead | NodeState::Left)
                        && now - m.state_changed_at > cutoff
                })
                .map(|m| m.node_id.clone())
                .collect();
            for id in &doomed {
                members.remove(id);
            }
            doomed
        };

        if !removed.is_empty() {
            let mut hw = self.replay_high_water.lock().unwrap_or_else(|e| e.into_inner());
            for id in &removed {
                hw.remove(id);
            }
        }
        removed.len()
    }

    /// Spawn the failure-detector thread, ticking every `interval`.
    ///
    /// Deliberately a named OS thread, not `tokio::spawn`, for the reason
    /// `maintenance.rs` documents: most of this crate is exercised from synchronous
    /// tests with no reactor running.
    ///
    /// Do **not** register [`Self::tick`] on [`crate::maintenance::MaintenanceCoordinator`]
    /// — that runs on a 60s cadence, far slower than a failure detector needs. Register
    /// [`Self::sweep_expired`] there (via `with_cluster`) and run `tick` here.
    pub fn start(self: Arc<Self>, interval: Duration) -> std::thread::JoinHandle<()> {
        std::thread::Builder::new()
            .name("saacp-cluster".to_string())
            .spawn(move || loop {
                std::thread::sleep(interval);
                self.tick();
            })
            .expect("failed to spawn saacp-cluster thread")
    }
}

// ---------------------------------------------------------------------------
// Crypto helpers (module-private, matching faitf.rs's convention)
// ---------------------------------------------------------------------------

fn sign_data(signing_key: &SigningKey, message: &[u8]) -> Vec<u8> {
    signing_key.sign(message).to_bytes().to_vec()
}

fn verify_data(verifying_key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying_key.verify(message, &sig).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::faitf::AttestationType;
    use std::sync::atomic::AtomicUsize;

    fn make_identity(id: &str) -> Arc<AgentIdentity> {
        Arc::new(AgentIdentity::generate(
            id,
            "issuer-cluster-test",
            86_400,
            None,
            None,
            "",
            AttestationType::None,
        ))
    }

    /// Records every send so a test can assert fanout, and can be told to name peers that
    /// never actually respond.
    struct FakeTransport {
        peers: Vec<String>,
        sent: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl FakeTransport {
        fn new(peers: &[&str]) -> Self {
            Self {
                peers: peers.iter().map(|s| s.to_string()).collect(),
                sent: Mutex::new(Vec::new()),
            }
        }
        fn sent_count(&self) -> usize {
            self.sent.lock().unwrap().len()
        }
        fn last_payload(&self) -> Option<Vec<u8>> {
            self.sent.lock().unwrap().last().map(|(_, b)| b.clone())
        }
        fn clear(&self) {
            self.sent.lock().unwrap().clear();
        }
    }

    impl ClusterTransport for FakeTransport {
        fn peers(&self) -> Vec<String> {
            self.peers.clone()
        }
        fn send_to(&self, node_id: &str, bytes: &[u8]) {
            self.sent
                .lock()
                .unwrap()
                .push((node_id.to_string(), bytes.to_vec()));
        }
    }

    /// Build a node plus a trust store that trusts every identity in `all`.
    fn make_node(
        me: &Arc<AgentIdentity>,
        peers: &[&str],
        all: &[&Arc<AgentIdentity>],
        cluster_size: usize,
    ) -> (Arc<ClusterEngine>, Arc<FakeTransport>) {
        let trust_store = Arc::new(TrustStore::new());
        for ident in all {
            trust_store.pin_identity(&ident.agent_id, ident.verifying_key);
        }
        let transport = Arc::new(FakeTransport::new(peers));
        let config = ClusterConfig::new("test-cluster", cluster_size);
        let engine = Arc::new(ClusterEngine::new(
            Arc::clone(me),
            trust_store,
            Arc::clone(&transport) as Arc<dyn ClusterTransport>,
            config,
            "127.0.0.1:9000",
        ));
        (engine, transport)
    }

    #[test]
    fn signed_message_round_trips_through_the_wire_format() {
        let a = make_identity("node-a");
        let (engine, _t) = make_node(&a, &["node-b"], &[&a], 2);
        let msg = engine.build_message(ClusterMessageKind::Heartbeat);
        let wire = msg.to_wire();
        let parsed = ClusterMessage::from_wire(&wire).expect("must parse");

        assert_eq!(parsed.sender_id, "node-a");
        assert_eq!(parsed.kind, ClusterMessageKind::Heartbeat);
        assert_eq!(parsed.sequence, msg.sequence);
        assert_eq!(parsed.sender_key_id, msg.sender_key_id);
        assert_eq!(parsed.body_bytes(), msg.body_bytes(), "body must be byte-stable");
        assert!(verify_data(&a.verifying_key, &parsed.body_bytes(), &parsed.signature));
    }

    #[test]
    fn peer_message_marks_sender_alive_and_is_accepted() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(node_a.receive_wire(&msg.to_wire()), Ok(()));
        assert_eq!(node_a.state_of("node-b"), Some(NodeState::Alive));
    }

    #[test]
    fn forged_signature_is_rejected_and_never_applied() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let attacker = make_identity("node-b"); // same id, different key
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);

        // Sign with a key the trust store does not associate with this fingerprint.
        let (node_evil, _te) = make_node(&attacker, &["node-a"], &[&attacker], 2);
        let mut msg = node_evil.build_message(ClusterMessageKind::Heartbeat);
        // Claim node-b's real key id while retaining the attacker's signature.
        msg.sender_key_id = b.fingerprint();

        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::BadSignature)
        );
        assert_eq!(node_a.state_of("node-b"), None, "rejected message must not create state");
    }

    #[test]
    fn untrusted_key_is_rejected() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        // node-a's trust store deliberately does NOT pin node-b.
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::UntrustedKey)
        );
    }

    #[test]
    fn sender_outside_the_configured_roster_is_rejected() {
        let a = make_identity("node-a");
        let c = make_identity("node-c");
        // Roster names only node-b, so node-c must not be able to join.
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &c], 2);
        let (node_c, _tc) = make_node(&c, &["node-a"], &[&a, &c], 2);

        let msg = node_c.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::UnknownSender)
        );
    }

    #[test]
    fn replayed_message_is_rejected() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        let wire = msg.to_wire();
        assert_eq!(node_a.receive_wire(&wire), Ok(()));
        assert_eq!(
            node_a.receive_wire(&wire),
            Err(ClusterRejection::Replay),
            "a captured message must not be replayable"
        );
    }

    #[test]
    fn stale_message_outside_the_freshness_window_is_rejected() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let mut msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        msg.sent_at = now_f64() - DEFAULT_MESSAGE_MAX_AGE.as_secs_f64() - 60.0;
        msg.signature = sign_data(&b.signing_key, &msg.body_bytes()); // validly re-signed

        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::Stale)
        );
    }

    #[test]
    fn tampered_body_fails_verification() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let mut msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        // Claim node-a is dead, without re-signing.
        msg.updates.push(MemberUpdate {
            node_id: "node-a".to_string(),
            addr: String::new(),
            incarnation: 999_999,
            state: NodeState::Dead,
        });

        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::BadSignature)
        );
    }

    #[test]
    fn envelope_field_mismatch_is_rejected() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        let (blob, sender, epoch, kind) = ClusterEngine::envelope_fields(&msg);
        assert_eq!(node_a.receive_envelope(&blob, &sender, epoch, &kind), Ok(()));

        // A second, fresh message whose plaintext sender is rewritten in transit.
        let msg2 = node_b.build_message(ClusterMessageKind::Heartbeat);
        let (blob2, _, epoch2, kind2) = ClusterEngine::envelope_fields(&msg2);
        assert_eq!(
            node_a.receive_envelope(&blob2, "node-impostor", epoch2, &kind2),
            Err(ClusterRejection::EnvelopeMismatch)
        );
    }

    #[test]
    fn mismatched_cluster_size_is_rejected() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 3);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::WrongCluster)
        );
    }

    #[test]
    fn single_node_cluster_elects_itself() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &[], &[&a], 1);
        node_a.tick();
        assert!(node_a.is_leader());
        assert_eq!(node_a.leader().as_deref(), Some("node-a"));
    }

    #[test]
    fn leader_choice_is_deterministic_across_nodes() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        // Exchange one message each way so both see a full alive set.
        let m_b = node_b.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(node_a.receive_wire(&m_b.to_wire()), Ok(()));
        let m_a = node_a.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(node_b.receive_wire(&m_a.to_wire()), Ok(()));

        assert!(node_a.has_quorum());
        assert!(node_b.has_quorum());
        assert_eq!(
            node_a.leader(),
            node_b.leader(),
            "identical membership views must yield identical leaders"
        );
        assert!(node_a.leader().is_some());
    }

    #[test]
    fn minority_partition_has_no_leader() {
        // 5-node cluster, this node can only see itself and one peer → 2 < quorum(3).
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 5);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 5);

        let m_b = node_b.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(node_a.receive_wire(&m_b.to_wire()), Ok(()));

        assert_eq!(node_a.alive_count(), 2);
        assert_eq!(node_a.config().quorum(), 3);
        assert!(!node_a.has_quorum());
        assert!(!node_a.is_leader(), "minority partition must not elect a leader");
        assert_eq!(node_a.leader(), None);
    }

    #[test]
    fn dead_leader_triggers_failover_to_a_new_leader() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let c = make_identity("node-c");
        let (node_a, _ta) = make_node(&a, &["node-b", "node-c"], &[&a, &b, &c], 3);
        let (node_b, _tb) = make_node(&b, &["node-a", "node-c"], &[&a, &b, &c], 3);
        let (node_c, _tc) = make_node(&c, &["node-a", "node-b"], &[&a, &b, &c], 3);

        let changes = Arc::new(Mutex::new(Vec::<LeadershipChange>::new()));
        let sink = Arc::clone(&changes);
        node_a.on_leadership_change(move |ch| sink.lock().unwrap().push(ch.clone()));

        assert_eq!(node_a.receive_wire(&node_b.build_message(ClusterMessageKind::Heartbeat).to_wire()), Ok(()));
        assert_eq!(node_a.receive_wire(&node_c.build_message(ClusterMessageKind::Heartbeat).to_wire()), Ok(()));
        assert_eq!(node_a.alive_count(), 3);

        let first_leader = node_a.leader().expect("quorum reached, leader must exist");
        let epoch_before = node_a.leader_epoch();

        // Kill whichever node was elected (unless it is us — then kill another, since a
        // node never times its own record out).
        let victim = if first_leader == "node-a" {
            if node_a.leader().as_deref() == Some("node-a") { "node-b".to_string() } else { first_leader.clone() }
        } else {
            first_leader.clone()
        };

        // Force the victim's record past the dead-timeout, exactly as a real silent node
        // would drift, then run the detector.
        {
            let mut members = node_a.members.lock().unwrap();
            let m = members.get_mut(&victim).expect("victim must be a known member");
            m.last_seen = now_f64() - DEFAULT_DEAD_TIMEOUT.as_secs_f64() - 60.0;
            m.state = NodeState::Suspect;
        }
        node_a.tick();

        assert_eq!(node_a.state_of(&victim), Some(NodeState::Dead));
        if first_leader == victim {
            assert_ne!(node_a.leader().as_deref(), Some(victim.as_str()), "dead node must not remain leader");
            assert!(
                node_a.leader_epoch() > epoch_before,
                "failover must advance the fencing epoch"
            );
            let recorded = changes.lock().unwrap();
            assert!(!recorded.is_empty(), "failover must fire the leadership hook");
        }
    }

    #[test]
    fn losing_quorum_steps_down_an_existing_leader() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let c = make_identity("node-c");
        let (node_a, _ta) = make_node(&a, &["node-b", "node-c"], &[&a, &b, &c], 3);
        let (node_b, _tb) = make_node(&b, &["node-a", "node-c"], &[&a, &b, &c], 3);
        let (node_c, _tc) = make_node(&c, &["node-a", "node-b"], &[&a, &b, &c], 3);

        assert_eq!(node_a.receive_wire(&node_b.build_message(ClusterMessageKind::Heartbeat).to_wire()), Ok(()));
        assert_eq!(node_a.receive_wire(&node_c.build_message(ClusterMessageKind::Heartbeat).to_wire()), Ok(()));
        assert!(node_a.leader().is_some());

        // Both peers go silent → alive_count drops to 1, below quorum(3) = 2.
        {
            let mut members = node_a.members.lock().unwrap();
            for id in ["node-b", "node-c"] {
                let m = members.get_mut(id).unwrap();
                m.last_seen = now_f64() - DEFAULT_DEAD_TIMEOUT.as_secs_f64() - 60.0;
            }
        }
        node_a.tick();
        node_a.tick();

        assert!(!node_a.has_quorum());
        assert_eq!(node_a.leader(), None, "a node without quorum must step down");
        assert!(!node_a.is_leader());
    }

    #[test]
    fn fencing_epoch_never_decreases() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &[], &[&a], 1);
        node_a.tick();
        let e1 = node_a.leader_epoch();
        node_a.absorb_epoch(e1 + 500);
        assert_eq!(node_a.leader_epoch(), e1 + 500);
        node_a.absorb_epoch(1);
        assert_eq!(node_a.leader_epoch(), e1 + 500, "a lower peer epoch must never lower ours");
    }

    #[test]
    fn suspected_node_refutes_and_returns_to_alive() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);

        let incarnation_before = node_a.incarnation();
        ta.clear();

        // node-b wrongly believes node-a is Suspect.
        let mut msg = node_b.build_message(ClusterMessageKind::Heartbeat);
        msg.updates.push(MemberUpdate {
            node_id: "node-a".to_string(),
            addr: String::new(),
            incarnation: incarnation_before,
            state: NodeState::Suspect,
        });
        msg.signature = sign_data(&b.signing_key, &msg.body_bytes());

        assert_eq!(node_a.receive_wire(&msg.to_wire()), Ok(()));

        assert!(
            node_a.incarnation() > incarnation_before,
            "refutation must bump our incarnation above the suspicion"
        );
        assert_eq!(node_a.state_of("node-a"), Some(NodeState::Alive));
        assert!(ta.sent_count() > 0, "refutation must be broadcast immediately");

        // The refutation node-b receives must actually clear the suspicion.
        let refutation = ta.last_payload().expect("a refutation was sent");
        assert_eq!(node_b.receive_wire(&refutation), Ok(()));
        assert_eq!(node_b.state_of("node-a"), Some(NodeState::Alive));
    }

    #[test]
    fn higher_incarnation_alive_overrides_a_dead_record() {
        let mut members = HashMap::new();
        let now = now_f64();
        members.insert(
            "n1".to_string(),
            MemberRecord {
                node_id: "n1".to_string(),
                addr: String::new(),
                incarnation: 5,
                state: NodeState::Dead,
                state_changed_at: now,
                last_seen: now,
            },
        );
        ClusterEngine::merge_one(
            &mut members,
            &MemberUpdate { node_id: "n1".into(), addr: String::new(), incarnation: 6, state: NodeState::Alive },
            now,
            false,
        );
        assert_eq!(members["n1"].state, NodeState::Alive);

        // ...but an equal-incarnation Alive must NOT override Dead.
        ClusterEngine::merge_one(
            &mut members,
            &MemberUpdate { node_id: "n1".into(), addr: String::new(), incarnation: 6, state: NodeState::Dead },
            now,
            false,
        );
        assert_eq!(members["n1"].state, NodeState::Dead);
        ClusterEngine::merge_one(
            &mut members,
            &MemberUpdate { node_id: "n1".into(), addr: String::new(), incarnation: 6, state: NodeState::Alive },
            now,
            false,
        );
        assert_eq!(members["n1"].state, NodeState::Dead, "state precedence must hold at equal incarnation");
    }

    #[test]
    fn membership_view_is_bounded() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &[], &[&a], 1);
        for i in 0..(CLUSTER_MAX_MEMBERS + 100) {
            node_a.add_peer(&format!("peer-{i}"), "127.0.0.1:1");
        }
        assert!(
            node_a.member_count() <= CLUSTER_MAX_MEMBERS,
            "membership view must not grow past CLUSTER_MAX_MEMBERS"
        );
    }

    #[test]
    fn seeded_peer_does_not_count_toward_quorum_until_it_speaks() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a], 2);
        node_a.add_peer("node-b", "127.0.0.1:9001");
        assert_eq!(node_a.member_count(), 2);
        assert_eq!(
            node_a.alive_count(),
            1,
            "a peer we have never heard from must not be counted alive"
        );
        assert!(!node_a.is_leader(), "quorum(2)=2 is unmet with one alive node");
    }

    #[test]
    fn sweep_removes_long_dead_members_and_their_replay_state() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);
        assert_eq!(node_a.receive_wire(&node_b.build_message(ClusterMessageKind::Heartbeat).to_wire()), Ok(()));
        assert_eq!(node_a.member_count(), 2);

        {
            let mut members = node_a.members.lock().unwrap();
            let m = members.get_mut("node-b").unwrap();
            m.state = NodeState::Dead;
            m.state_changed_at = now_f64() - DEFAULT_DEAD_TIMEOUT.as_secs_f64() - 60.0;
        }

        assert_eq!(node_a.sweep_expired(), 1);
        assert_eq!(node_a.member_count(), 1);
        assert!(
            !node_a.replay_high_water.lock().unwrap().contains_key("node-b"),
            "replay state for a removed member must be reclaimed"
        );
    }

    #[test]
    fn leave_marks_self_left_and_announces() {
        let a = make_identity("node-a");
        let b = make_identity("node-b");
        let (node_a, ta) = make_node(&a, &["node-b"], &[&a, &b], 2);
        let (node_b, _tb) = make_node(&b, &["node-a"], &[&a, &b], 2);
        ta.clear();

        node_a.leave();
        assert_eq!(node_a.state_of("node-a"), Some(NodeState::Left));
        assert!(ta.sent_count() > 0, "departure must be announced");

        let announcement = ta.last_payload().expect("an announcement was sent");
        assert_eq!(node_b.receive_wire(&announcement), Ok(()));
        assert_eq!(
            node_b.state_of("node-a"),
            Some(NodeState::Left),
            "peers must record the departure immediately, not wait out the dead-timeout"
        );
    }

    #[test]
    fn lease_backend_blocks_leadership_when_another_node_holds_it() {
        use crate::state_backend::InMemoryBackend;

        let a = make_identity("node-a");
        let backend: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::default());
        // Another node already holds the lease.
        backend
            .set(
                &format!("{}{}", LEASE_KEY_PREFIX, "test-cluster"),
                b"node-z",
                Some(Duration::from_secs(60)),
            )
            .unwrap();

        let trust_store = Arc::new(TrustStore::new());
        trust_store.pin_identity(&a.agent_id, a.verifying_key);
        let transport = Arc::new(FakeTransport::new(&[]));
        let engine = ClusterEngine::new(
            Arc::clone(&a),
            trust_store,
            transport as Arc<dyn ClusterTransport>,
            ClusterConfig::new("test-cluster", 1),
            "127.0.0.1:9000",
        )
        .with_lease_backend(Arc::clone(&backend));

        engine.tick();
        assert!(
            !engine.is_leader(),
            "winning the deterministic election must not grant leadership while another node holds the lease"
        );
    }

    #[test]
    fn lease_backend_grants_leadership_when_lease_is_free() {
        use crate::state_backend::InMemoryBackend;

        let a = make_identity("node-a");
        let backend: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::default());
        let trust_store = Arc::new(TrustStore::new());
        trust_store.pin_identity(&a.agent_id, a.verifying_key);
        let transport = Arc::new(FakeTransport::new(&[]));
        let engine = ClusterEngine::new(
            Arc::clone(&a),
            trust_store,
            transport as Arc<dyn ClusterTransport>,
            ClusterConfig::new("test-cluster", 1),
            "127.0.0.1:9000",
        )
        .with_lease_backend(Arc::clone(&backend));

        engine.tick();
        assert!(engine.is_leader());
        // Renewal on a subsequent tick must keep, not lose, leadership.
        engine.tick();
        assert!(engine.is_leader(), "the lease holder must be able to renew");
    }

    #[test]
    fn only_one_of_two_racing_nodes_wins_the_lease() {
        use crate::state_backend::InMemoryBackend;

        let backend: Arc<dyn StateBackend> = Arc::new(InMemoryBackend::default());
        let a = make_identity("node-a");
        let b = make_identity("node-b");

        let mut leaders = 0;
        for ident in [&a, &b] {
            let trust_store = Arc::new(TrustStore::new());
            trust_store.pin_identity(&ident.agent_id, ident.verifying_key);
            let engine = ClusterEngine::new(
                Arc::clone(ident),
                trust_store,
                Arc::new(FakeTransport::new(&[])) as Arc<dyn ClusterTransport>,
                ClusterConfig::new("race-cluster", 1),
                "127.0.0.1:9000",
            )
            .with_lease_backend(Arc::clone(&backend));
            engine.tick();
            if engine.is_leader() {
                leaders += 1;
            }
        }
        assert_eq!(leaders, 1, "the CAS lease must admit exactly one leader");
    }

    #[test]
    fn leadership_hook_fires_exactly_once_per_change() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &[], &[&a], 1);
        let calls = Arc::new(AtomicUsize::new(0));
        let c = Arc::clone(&calls);
        node_a.on_leadership_change(move |_| {
            c.fetch_add(1, Ordering::Relaxed);
        });

        node_a.tick();
        assert_eq!(calls.load(Ordering::Relaxed), 1);
        node_a.tick();
        node_a.tick();
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "a stable leader must not re-fire the hook"
        );
    }

    #[test]
    fn malformed_wire_input_is_rejected_without_panicking() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &["node-b"], &[&a], 2);

        for bad in [
            &b""[..],
            &b"not-base64!!!"[..],
            B64.encode([0u8; 2]).as_bytes(),
            B64.encode([0xFFu8; 8]).as_bytes(),
            B64.encode({
                let mut v = 10u32.to_be_bytes().to_vec();
                v.extend_from_slice(b"not-json!!");
                v.extend_from_slice(&[0u8; 64]);
                v
            })
            .as_bytes(),
        ] {
            assert_eq!(
                node_a.receive_wire(bad),
                Err(ClusterRejection::Malformed),
                "malformed input must be rejected, never panic"
            );
        }
    }

    #[test]
    fn own_message_echoed_back_is_ignored() {
        let a = make_identity("node-a");
        let (node_a, _ta) = make_node(&a, &["node-a", "node-b"], &[&a], 2);
        let msg = node_a.build_message(ClusterMessageKind::Heartbeat);
        assert_eq!(
            node_a.receive_wire(&msg.to_wire()),
            Err(ClusterRejection::UnknownSender),
            "a node must not apply its own echoed message"
        );
    }
}
