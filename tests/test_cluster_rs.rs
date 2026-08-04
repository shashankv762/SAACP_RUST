//! test_cluster_rs.rs — Active-Active Clustering & Failover (`src/cluster.rs`).
//!
//! Covers the properties that only hold across a whole cluster, which `cluster.rs`'s own
//! unit tests cannot exercise:
//!
//! - a three-node cluster converging on one leader, then **failing over** when the leader
//!   dies, with every survivor agreeing on the replacement;
//! - **split-brain**: a 3+2 partition of a 5-node cluster must leave the minority side with
//!   no leader at all, and must not produce two leaders;
//! - the **fencing epoch** advancing monotonically across a failover;
//! - **daemon wiring**: a schema_id=12 `Cluster Envelope` arriving over a real loopback TCP
//!   connection reaches the configured `ClusterEngine` through the real gate pipeline
//!   (mirrors `test_gossip_daemon_wiring_rs.rs`);
//! - a **forged** membership message delivered over that same real connection changing
//!   nothing.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use saacp::cluster::{
    ClusterConfig, ClusterEngine, ClusterMessageKind, ClusterRejection, ClusterTransport,
    NodeState,
};
use saacp::faitf::{AgentIdentity, AttestationType, TrustStore};
use saacp::framing::MEASCFrame as StructuralFrame;
use saacp::{SAACPNetworkDaemon, ZeroTrustGateway};

// ---------------------------------------------------------------------------
// In-process cluster harness
// ---------------------------------------------------------------------------

/// Routes messages between engines in-process, with an operator-controllable partition so
/// a test can sever links without any real sockets.
///
/// `send_to` only enqueues; [`Cluster::deliver_all`] drains the queues. Delivery is
/// therefore explicit and deterministic — no sleeps, no flaky timing.
#[derive(Default)]
struct Switchboard {
    /// `node_id -> pending inbound wire messages`
    inboxes: Mutex<HashMap<String, Vec<Vec<u8>>>>,
    /// Unordered `{a, b}` links that are currently severed.
    severed: Mutex<Vec<(String, String)>>,
}

impl Switchboard {
    fn is_severed(&self, a: &str, b: &str) -> bool {
        self.severed
            .lock()
            .unwrap()
            .iter()
            .any(|(x, y)| (x == a && y == b) || (x == b && y == a))
    }

    fn sever(&self, a: &str, b: &str) {
        self.severed.lock().unwrap().push((a.to_string(), b.to_string()));
    }

    fn take_inbox(&self, node: &str) -> Vec<Vec<u8>> {
        self.inboxes
            .lock()
            .unwrap()
            .get_mut(node)
            .map(std::mem::take)
            .unwrap_or_default()
    }
}

/// One node's view of the switchboard.
struct SwitchboardPort {
    me: String,
    peers: Vec<String>,
    board: Arc<Switchboard>,
}

impl ClusterTransport for SwitchboardPort {
    fn peers(&self) -> Vec<String> {
        self.peers.clone()
    }

    fn send_to(&self, node_id: &str, bytes: &[u8]) {
        if self.board.is_severed(&self.me, node_id) {
            return;
        }
        self.board
            .inboxes
            .lock()
            .unwrap()
            .entry(node_id.to_string())
            .or_default()
            .push(bytes.to_vec());
    }
}

/// Failure-detector timeouts compressed so a test detects a dead node in well under a
/// second instead of the 5s/15s production defaults. Everything else — the merge rules,
/// the election, the quorum gate — is exercised exactly as it ships.
const TEST_SUSPECT_TIMEOUT: Duration = Duration::from_millis(120);
const TEST_DEAD_TIMEOUT: Duration = Duration::from_millis(300);

struct Cluster {
    engines: Vec<Arc<ClusterEngine>>,
    board: Arc<Switchboard>,
}

impl Cluster {
    /// Build `node_ids.len()` engines that all trust each other, sized for
    /// `expected_cluster_size` (which is what quorum is derived from — deliberately not
    /// the number of nodes currently reachable).
    fn new(node_ids: &[&str], expected_cluster_size: usize) -> Self {
        let board = Arc::new(Switchboard::default());
        let identities: Vec<Arc<AgentIdentity>> = node_ids
            .iter()
            .map(|id| {
                Arc::new(AgentIdentity::generate(
                    id,
                    "issuer-cluster-integration",
                    86_400,
                    None,
                    None,
                    "",
                    AttestationType::None,
                ))
            })
            .collect();

        let engines = identities
            .iter()
            .map(|me| {
                let trust_store = Arc::new(TrustStore::new());
                for other in &identities {
                    trust_store.pin_identity(&other.agent_id, other.verifying_key);
                }
                let peers: Vec<String> = node_ids
                    .iter()
                    .filter(|id| **id != me.agent_id)
                    .map(|id| id.to_string())
                    .collect();
                let port = SwitchboardPort {
                    me: me.agent_id.clone(),
                    peers,
                    board: Arc::clone(&board),
                };
                Arc::new(ClusterEngine::new(
                    Arc::clone(me),
                    trust_store,
                    Arc::new(port) as Arc<dyn ClusterTransport>,
                    ClusterConfig::new("integration-cluster", expected_cluster_size)
                        .with_timeouts(TEST_SUSPECT_TIMEOUT, TEST_DEAD_TIMEOUT),
                    "127.0.0.1:0",
                ))
            })
            .collect();

        Self { engines, board }
    }

    fn get(&self, node_id: &str) -> &Arc<ClusterEngine> {
        self.engines
            .iter()
            .find(|e| e.node_id() == node_id)
            .expect("node must exist in this cluster")
    }

    /// Deliver every queued message. Returns how many were accepted.
    fn deliver_all(&self) -> usize {
        let mut accepted = 0;
        for engine in &self.engines {
            for wire in self.board.take_inbox(engine.node_id()) {
                if engine.receive_wire(&wire).is_ok() {
                    accepted += 1;
                }
            }
        }
        accepted
    }

    /// Tick every node, then deliver — one full convergence round.
    fn round(&self) {
        for engine in &self.engines {
            engine.tick();
        }
        self.deliver_all();
    }

    /// Run enough rounds for membership to converge, without letting the suspect-timeout
    /// elapse in between.
    fn converge(&self) {
        for _ in 0..4 {
            self.round();
        }
    }

    fn leaders(&self) -> Vec<Option<String>> {
        self.engines.iter().map(|e| e.leader()).collect()
    }

    /// Every node that currently claims leadership.
    fn self_declared_leaders(&self) -> Vec<String> {
        self.engines
            .iter()
            .filter(|e| e.is_leader())
            .map(|e| e.node_id().to_string())
            .collect()
    }

    /// Run rounds until `predicate` holds, or fail once the budget is exhausted.
    fn run_until(&self, what: &str, predicate: impl Fn() -> bool) {
        let deadline = std::time::Instant::now() + TEST_DEAD_TIMEOUT * 20;
        while std::time::Instant::now() < deadline {
            self.round();
            if predicate() {
                return;
            }
            std::thread::sleep(TEST_SUSPECT_TIMEOUT / 2);
        }
        panic!("timed out waiting for: {what}");
    }
}

impl Switchboard {
    fn sever_all(&self, node_id: &str, engines: &[Arc<ClusterEngine>]) {
        for engine in engines {
            if engine.node_id() != node_id {
                self.sever(node_id, engine.node_id());
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Cluster-level behavior
// ---------------------------------------------------------------------------

fn fast_cluster(node_ids: &[&str], expected_cluster_size: usize) -> Cluster {
    Cluster::new(node_ids, expected_cluster_size)
}

#[test]
fn three_node_cluster_converges_on_exactly_one_leader() {
    let cluster = fast_cluster(&["node-alpha", "node-beta", "node-gamma"], 3);
    cluster.converge();

    for engine in &cluster.engines {
        assert_eq!(engine.alive_count(), 3, "every node must see all three members alive");
        assert!(engine.has_quorum());
    }

    let leaders = cluster.leaders();
    assert!(leaders.iter().all(|l| l.is_some()), "every node must know a leader");
    assert!(
        leaders.windows(2).all(|w| w[0] == w[1]),
        "all nodes must agree on the same leader, got {leaders:?}"
    );
    assert_eq!(
        cluster.self_declared_leaders().len(),
        1,
        "exactly one node may claim leadership"
    );
}

#[test]
fn leader_death_fails_over_to_a_surviving_node() {
    let cluster = fast_cluster(&["node-alpha", "node-beta", "node-gamma"], 3);
    cluster.converge();

    let original_leader = cluster.engines[0].leader().expect("a leader must be elected");
    let survivor = cluster
        .engines
        .iter()
        .find(|e| e.node_id() != original_leader)
        .expect("a survivor must exist");
    let epoch_before = survivor.leader_epoch();

    // Sever the leader from everyone, then let the failure detector run to completion.
    cluster.board.sever_all(&original_leader, &cluster.engines);
    let watched = Arc::clone(survivor);
    let target = original_leader.clone();
    cluster.run_until("the dead leader to be detected", || {
        watched.state_of(&target) == Some(NodeState::Dead)
    });

    assert_eq!(
        survivor.state_of(&original_leader),
        Some(NodeState::Dead),
        "the failure detector must declare the unreachable leader dead"
    );

    let new_leader = survivor.leader();
    assert!(new_leader.is_some(), "surviving quorum must elect a replacement");
    assert_ne!(
        new_leader.as_deref(),
        Some(original_leader.as_str()),
        "failover must not re-elect the dead node"
    );
    assert!(
        survivor.leader_epoch() > epoch_before,
        "failover must advance the fencing epoch monotonically"
    );
}

#[test]
fn split_brain_leaves_the_minority_partition_with_no_leader() {
    // 5 nodes, quorum = 3. Partition into {a,b,c} | {d,e}.
    let cluster = fast_cluster(&["node-a", "node-b", "node-c", "node-d", "node-e"], 5);
    cluster.converge();
    assert_eq!(cluster.self_declared_leaders().len(), 1, "healthy cluster has one leader");

    for majority in ["node-a", "node-b", "node-c"] {
        for minority in ["node-d", "node-e"] {
            cluster.board.sever(majority, minority);
        }
    }

    // Age both sides out until each has fully detected the other side as gone.
    cluster.run_until("the minority to detect full isolation", || {
        ["node-d", "node-e"].iter().all(|m| {
            ["node-a", "node-b", "node-c"]
                .iter()
                .all(|maj| cluster.get(m).state_of(maj) == Some(NodeState::Dead))
        })
    });

    for minority in ["node-d", "node-e"] {
        let node = cluster.get(minority);
        assert!(!node.has_quorum(), "{minority} must not believe it has quorum");
        assert_eq!(
            node.leader(),
            None,
            "{minority} is in a 2-of-5 minority and must have NO leader (fail closed)"
        );
        assert!(!node.is_leader());
    }

    assert!(
        cluster.self_declared_leaders().len() <= 1,
        "a partition must never yield two simultaneous leaders, got {:?}",
        cluster.self_declared_leaders()
    );
}

#[test]
fn majority_partition_keeps_serving_after_the_split() {
    let cluster = fast_cluster(&["node-a", "node-b", "node-c", "node-d", "node-e"], 5);
    cluster.converge();

    for majority in ["node-a", "node-b", "node-c"] {
        for minority in ["node-d", "node-e"] {
            cluster.board.sever(majority, minority);
        }
    }

    cluster.run_until("the majority to detect the partition", || {
        ["node-a", "node-b", "node-c"].iter().all(|maj| {
            ["node-d", "node-e"]
                .iter()
                .all(|m| cluster.get(maj).state_of(m) == Some(NodeState::Dead))
        })
    });

    for majority in ["node-a", "node-b", "node-c"] {
        let node = cluster.get(majority);
        assert_eq!(node.alive_count(), 3);
        assert!(node.has_quorum(), "{majority} retains a 3-of-5 majority");
        assert!(node.leader().is_some(), "{majority} must still have a leader");
    }

    let majority_leaders: Vec<Option<String>> = ["node-a", "node-b", "node-c"]
        .iter()
        .map(|id| cluster.get(id).leader())
        .collect();
    assert!(
        majority_leaders.windows(2).all(|w| w[0] == w[1]),
        "the surviving majority must agree on one leader, got {majority_leaders:?}"
    );
}

#[test]
fn a_node_outside_the_roster_cannot_join_the_cluster() {
    let cluster = fast_cluster(&["node-a", "node-b"], 2);
    cluster.converge();

    // An intruder with a perfectly valid, well-formed, correctly-signed message — but a
    // node id nobody rostered.
    let intruder = Arc::new(AgentIdentity::generate(
        "node-intruder",
        "issuer-cluster-integration",
        86_400,
        None,
        None,
        "",
        AttestationType::None,
    ));
    let trust_store = Arc::new(TrustStore::new());
    trust_store.pin_identity(&intruder.agent_id, intruder.verifying_key);
    let engine = ClusterEngine::new(
        Arc::clone(&intruder),
        trust_store,
        Arc::new(SwitchboardPort {
            me: "node-intruder".to_string(),
            peers: vec!["node-a".to_string()],
            board: Arc::clone(&cluster.board),
        }) as Arc<dyn ClusterTransport>,
        ClusterConfig::new("integration-cluster", 2),
        "127.0.0.1:0",
    );

    let msg = engine.build_message(ClusterMessageKind::Heartbeat);
    let victim = cluster.get("node-a");
    let before = victim.member_count();

    assert_eq!(
        victim.receive_wire(&msg.to_wire()),
        Err(ClusterRejection::UnknownSender),
        "an unrostered node must be refused even with a valid signature"
    );
    assert_eq!(victim.member_count(), before, "a refused node must not enter the view");
    assert_eq!(victim.state_of("node-intruder"), None);
}

// ---------------------------------------------------------------------------
// Daemon wiring over a real TCP connection
// ---------------------------------------------------------------------------

async fn free_port() -> u16 {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    l.local_addr().unwrap().port()
}

/// Client-side mirror of `daemon::ecdh_handshake` in unauthenticated mode — see
/// `test_gossip_daemon_wiring_rs.rs` for the canonical copy this duplicates (those helpers
/// are private to their own test binary).
async fn tcp_client_handshake(stream: &mut TcpStream) -> [u8; 32] {
    use hkdf::Hkdf;
    use sha2::Sha256;
    use x25519_dalek::{EphemeralSecret, PublicKey};

    let client_nonce: [u8; 32] = rand::random();
    let client_secret = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let client_pub = PublicKey::from(&client_secret);

    let mut client_msg = Vec::with_capacity(64);
    client_msg.extend_from_slice(&client_nonce);
    client_msg.extend_from_slice(client_pub.as_bytes());
    stream.write_all(&client_msg).await.expect("send handshake");

    let mut server_pub_bytes = [0u8; 32];
    stream.read_exact(&mut server_pub_bytes).await.expect("read server pubkey");
    let server_pub = PublicKey::from(server_pub_bytes);

    let shared = client_secret.diffie_hellman(&server_pub);
    let hk = Hkdf::<Sha256>::new(Some(&client_nonce), shared.as_bytes());
    let mut session_key = [0u8; 32];
    hk.expand(b"SAACP-daemon-handshake-v1", &mut session_key).expect("HKDF expand");
    session_key
}

async fn read_response(stream: &mut TcpStream, max_len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; max_len];
    let n = tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .expect("read timed out")
        .expect("read failed");
    buf.truncate(n);
    buf
}

/// A transport with a named peer that never actually receives anything — the daemon-wiring
/// tests only exercise the inbound path.
struct RosterOnlyTransport(Vec<String>);
impl ClusterTransport for RosterOnlyTransport {
    fn peers(&self) -> Vec<String> {
        self.0.clone()
    }
    fn send_to(&self, _node_id: &str, _bytes: &[u8]) {}
}

/// Build a daemon wired to a `ClusterEngine` that rosters and trusts `peer`, plus a
/// standalone engine for `peer` used to mint genuine messages.
fn daemon_cluster_pair(
    daemon_node: &str,
    peer_node: &str,
) -> (Arc<ClusterEngine>, Arc<ClusterEngine>) {
    let daemon_identity = Arc::new(AgentIdentity::generate(
        daemon_node, "issuer-cluster-daemon", 86_400, None, None, "", AttestationType::None,
    ));
    let peer_identity = Arc::new(AgentIdentity::generate(
        peer_node, "issuer-cluster-daemon", 86_400, None, None, "", AttestationType::None,
    ));

    let daemon_store = Arc::new(TrustStore::new());
    daemon_store.pin_identity(&daemon_identity.agent_id, daemon_identity.verifying_key);
    daemon_store.pin_identity(&peer_identity.agent_id, peer_identity.verifying_key);

    let daemon_engine = Arc::new(ClusterEngine::new(
        Arc::clone(&daemon_identity),
        daemon_store,
        Arc::new(RosterOnlyTransport(vec![peer_node.to_string()])) as Arc<dyn ClusterTransport>,
        ClusterConfig::new("daemon-cluster", 2),
        "127.0.0.1:0",
    ));

    let peer_store = Arc::new(TrustStore::new());
    peer_store.pin_identity(&peer_identity.agent_id, peer_identity.verifying_key);
    let peer_engine = Arc::new(ClusterEngine::new(
        peer_identity,
        peer_store,
        Arc::new(RosterOnlyTransport(vec![daemon_node.to_string()])) as Arc<dyn ClusterTransport>,
        ClusterConfig::new("daemon-cluster", 2),
        "127.0.0.1:0",
    ));

    (daemon_engine, peer_engine)
}

/// Encode a schema-12 payload the way a real peer daemon would.
fn cluster_payload(
    blob: &str,
    sender: &str,
    epoch: u64,
    kind: &str,
    token_b64: &str,
) -> String {
    serde_json::json!({
        "cluster_message": blob,
        "sender_id": sender,
        "leader_epoch": epoch,
        "message_kind": kind,
        "_capability_token": token_b64,
    })
    .to_string()
}

/// Encode a schema-12 frame. `session_tag` must be unique per test: these tests run
/// concurrently against separate daemons but share this process's global AEGF/session
/// state, and two live connections presenting the same `session_id` are (correctly)
/// treated as a session splice and terminated.
fn schema_12_frame(payload: &str, mesh_secret: &[u8; 32], session_tag: u8) -> Vec<u8> {
    StructuralFrame {
        schema_id: 12,
        status_code: 0x10,
        flags: 0,
        action_class: 0,
        payload_length: 0,
        session_id: [session_tag; 16],
        epoch_id: 0,
        psn: 1,
        context_ref_id: [0u8; 32],
        context_version: 0,
        w3c_traceparent: [0u8; 24],
    }
    .encode_encrypted(payload.as_bytes(), mesh_secret)
    .expect("encode_encrypted")
}

#[tokio::test]
async fn inbound_schema_12_packet_reaches_the_wired_cluster_engine() {
    let mesh_secret = [0x62u8; 32];
    let port = free_port().await;

    let (daemon_engine, peer_engine) = daemon_cluster_pair("daemon-node", "peer-node");
    let msg = peer_engine.build_message(ClusterMessageKind::Heartbeat);
    let (blob, sender, epoch, kind) = ClusterEngine::envelope_fields(&msg);

    assert_eq!(
        daemon_engine.state_of("peer-node"),
        None,
        "precondition: the peer is not yet known"
    );

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_cluster_engine(Arc::clone(&daemon_engine));
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let _session_key = tcp_client_handshake(&mut stream).await;

    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        &mesh_secret, "peer-daemon-agent", &["unknown"], &[], 60, None, 0, None,
    );
    let token_b64 = String::from_utf8(token).expect("token utf8");

    let payload = cluster_payload(&blob, &sender, epoch, &kind, &token_b64);
    stream
        .write_all(&schema_12_frame(&payload, &mesh_secret, 0xC1))
        .await
        .expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(
        &response, b"SUCCESS",
        "a well-formed cluster envelope must clear the gate pipeline"
    );

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        daemon_engine.state_of("peer-node"),
        Some(NodeState::Alive),
        "the daemon must have handed the envelope to its wired ClusterEngine"
    );
}

#[tokio::test]
async fn forged_cluster_message_over_a_real_connection_changes_nothing() {
    let mesh_secret = [0x63u8; 32];
    let port = free_port().await;

    let (daemon_engine, _peer_engine) = daemon_cluster_pair("daemon-node-2", "peer-node-2");

    // An attacker that holds a valid SAACP capability token (so the packet clears the gate
    // pipeline) but no cluster identity the daemon trusts.
    let attacker = Arc::new(AgentIdentity::generate(
        "peer-node-2", "issuer-attacker", 86_400, None, None, "", AttestationType::None,
    ));
    let attacker_store = Arc::new(TrustStore::new());
    attacker_store.pin_identity(&attacker.agent_id, attacker.verifying_key);
    let attacker_engine = ClusterEngine::new(
        attacker,
        attacker_store,
        Arc::new(RosterOnlyTransport(vec!["daemon-node-2".to_string()])) as Arc<dyn ClusterTransport>,
        ClusterConfig::new("daemon-cluster", 2),
        "127.0.0.1:0",
    );
    let forged = attacker_engine.build_message(ClusterMessageKind::Heartbeat);
    let (blob, sender, epoch, kind) = ClusterEngine::envelope_fields(&forged);

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_cluster_engine(Arc::clone(&daemon_engine));
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let _session_key = tcp_client_handshake(&mut stream).await;

    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        &mesh_secret, "attacker-agent", &["unknown"], &[], 60, None, 0, None,
    );
    let token_b64 = String::from_utf8(token).expect("token utf8");

    let payload = cluster_payload(&blob, &sender, epoch, &kind, &token_b64);
    stream
        .write_all(&schema_12_frame(&payload, &mesh_secret, 0xC2))
        .await
        .expect("send frame");

    // The packet itself is well-formed SAACP, so the gate pipeline accepts it...
    let response = read_response(&mut stream, 128).await;
    assert_eq!(&response, b"SUCCESS");

    tokio::time::sleep(Duration::from_millis(100)).await;
    // ...but the cluster layer independently refuses it: the signing key is not the one
    // pinned for `peer-node-2`, so membership is untouched.
    assert_eq!(
        daemon_engine.state_of("peer-node-2"),
        None,
        "a cluster message signed by an untrusted key must never alter membership, \
         even when the carrying packet clears the gate pipeline"
    );
    assert!(!daemon_engine.has_quorum());
}

#[tokio::test]
async fn tampered_envelope_routing_fields_are_rejected_over_a_real_connection() {
    let mesh_secret = [0x64u8; 32];
    let port = free_port().await;

    let (daemon_engine, peer_engine) = daemon_cluster_pair("daemon-node-3", "peer-node-3");
    let msg = peer_engine.build_message(ClusterMessageKind::Heartbeat);
    let (blob, _sender, epoch, kind) = ClusterEngine::envelope_fields(&msg);

    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()))
        .with_cluster_engine(Arc::clone(&daemon_engine));
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let _session_key = tcp_client_handshake(&mut stream).await;

    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        &mesh_secret, "mitm-agent", &["unknown"], &[], 60, None, 0, None,
    );
    let token_b64 = String::from_utf8(token).expect("token utf8");

    // Rewrite the plaintext `sender_id` in transit, leaving the signed blob intact.
    let payload = cluster_payload(&blob, "some-other-node", epoch, &kind, &token_b64);
    stream
        .write_all(&schema_12_frame(&payload, &mesh_secret, 0xC3))
        .await
        .expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(&response, b"SUCCESS");

    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(
        daemon_engine.state_of("peer-node-3"),
        None,
        "an envelope whose plaintext routing fields disagree with the signed body must be \
         rejected outright, not applied using the signed values"
    );
    assert_eq!(daemon_engine.state_of("some-other-node"), None);
}

#[tokio::test]
async fn daemon_without_a_cluster_engine_ignores_schema_12_packets() {
    let mesh_secret = [0x65u8; 32];
    let port = free_port().await;

    let (_unused, peer_engine) = daemon_cluster_pair("daemon-node-4", "peer-node-4");
    let msg = peer_engine.build_message(ClusterMessageKind::Heartbeat);
    let (blob, sender, epoch, kind) = ClusterEngine::envelope_fields(&msg);

    // No `.with_cluster_engine(...)` — the opt-in default must be a safe no-op.
    let daemon = SAACPNetworkDaemon::new("127.0.0.1", port, Some(mesh_secret.to_vec()))
        .with_gateway(Arc::new(ZeroTrustGateway::new()));
    tokio::spawn(async move {
        let _ = daemon.start().await;
    });
    tokio::time::sleep(Duration::from_millis(150)).await;

    let mut stream = TcpStream::connect(("127.0.0.1", port)).await.expect("connect");
    let _session_key = tcp_client_handshake(&mut stream).await;

    let gw = ZeroTrustGateway::new();
    let token = gw.issue_capability_token(
        &mesh_secret, "peer-daemon-agent", &["unknown"], &[], 60, None, 0, None,
    );
    let token_b64 = String::from_utf8(token).expect("token utf8");

    let payload = cluster_payload(&blob, &sender, epoch, &kind, &token_b64);
    stream
        .write_all(&schema_12_frame(&payload, &mesh_secret, 0xC4))
        .await
        .expect("send frame");

    let response = read_response(&mut stream, 128).await;
    assert_eq!(
        &response, b"SUCCESS",
        "schema 12 is a registered schema, so the packet must still clear the pipeline \
         even with no engine wired"
    );
}

#[test]
fn schema_12_rejects_a_payload_missing_required_fields() {
    use saacp::PreCompiledSchemas;

    let complete = serde_json::json!({
        "cluster_message": "abc",
        "sender_id": "node-a",
        "leader_epoch": 3,
        "message_kind": "heartbeat",
    });
    assert!(PreCompiledSchemas::validate_payload(12, &complete).is_ok());

    let missing = serde_json::json!({
        "cluster_message": "abc",
        "sender_id": "node-a",
    });
    assert!(
        PreCompiledSchemas::validate_payload(12, &missing).is_err(),
        "an incomplete cluster envelope must be rejected at the schema gate"
    );

    let extra = serde_json::json!({
        "cluster_message": "abc",
        "sender_id": "node-a",
        "leader_epoch": 3,
        "message_kind": "heartbeat",
        "surprise": true,
    });
    assert!(
        PreCompiledSchemas::validate_payload(12, &extra).is_err(),
        "an unexpected field must be rejected"
    );
}

#[test]
fn maintenance_coordinator_wires_the_cluster_sweep() {
    use saacp::maintenance::MaintenanceCoordinator;

    let cluster = fast_cluster(&["node-a", "node-b"], 2);
    let engine = Arc::clone(cluster.get("node-a"));

    let coordinator = MaintenanceCoordinator::new().with_cluster(Arc::clone(&engine));
    assert_eq!(coordinator.sweeper_count(), 1);
    coordinator.run_once(); // must not panic against real state
    assert_eq!(
        engine.member_count(),
        1,
        "only this node is known before any message is exchanged"
    );
}
