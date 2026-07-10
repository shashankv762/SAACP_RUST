//! Agent Execution Governance Framework (AEGF)
//!
//! Transforms agent safety from heuristic phrase matching into deterministic
//! protocol governance. Five interlocking subsystems:
//!
//! - `AEGFMetadata`: CID/RID/PRID/OAID/HC/ED/TTL request metadata packed into 120-byte binary.
//! - `ExecutionState` / `ExecutionStateMachine`: 10-state deterministic FSM.
//! - `DistributedExecutionGraph` (DEG): Directed graph with cycle detection.
//! - `AEGFPolicy`: Configurable global safety limits.
//! - `AEGFGovernor`: Central coordinator — DEG + ESM + policy.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::errors::{SAACPBytecodes, SAACPHardDrop};

// ─── Sentinel values ───────────────────────────────────────────────────────────

/// Sentinel: request has no parent (conversation originator). 32 hex-zero chars.
pub const RID_ROOT: &str = "00000000000000000000000000000000";
/// Sentinel: no conversation assigned yet.
pub const CID_NONE: &str = "00000000000000000000000000000000";

/// Binary size of packed AEGFMetadata (bytes).
pub const AEGF_META_SIZE: usize = 120;

/// Format version — increment when binary layout changes.
pub const AEGF_META_FORMAT_VERSION: u32 = 1;

/// Field offsets in the 120-byte packed AEGFMetadata binary layout (§4.2).
/// Each tuple is (byte_offset, field_size_in_bytes).
pub const AEGF_META_FIELD_OFFSETS: &[(&str, usize, usize)] = &[
    ("cid", 0, 16),
    ("rid", 16, 16),
    ("prid", 32, 16),
    ("sid", 48, 16),
    ("oaid", 64, 32),
    ("hc", 96, 2),
    ("ed", 98, 2),
    ("ttl", 100, 8),
    ("reserved", 108, 12),
];

/// Canonical test vector for AEGFMetadata binary serialization (§4.2).
/// Input parameters:
///   - cid  = "00000000000000000000000000000001"
///   - rid  = "00000000000000000000000000000002"
///   - prid = "00000000000000000000000000000000"
///   - sid  = "00000000000000000000000000000003"
///   - oaid = "test-agent"
///   - hc   = 0
///   - ed   = 0
///   - ttl  = 0.0
///
/// Expected packed output (120 bytes hex):
pub const AEGF_TEST_VECTOR_BYTES: &str = concat!(
    "00000000000000000000000000000001",  // CID [0:16]
    "00000000000000000000000000000002",  // RID [16:32]
    "00000000000000000000000000000000",  // PRID [32:48]
    "00000000000000000000000000000003",  // SID [48:64]
    "746573742d6167656e74000000000000",  // OAID [64:96] = "test-agent" padded
    "00000000000000000000000000000000",  // (continuation of OAID padding)
    "0000",                              // HC [96:98]
    "0000",                              // ED [98:100]
    "0000000000000000",                  // TTL [100:108] (f64 = 0.0)
    "000000000000000000000000",          // reserved [108:120]
);

/// Maximum value for HC and ED fields (uint16).
const MAX_HC: u16 = 0xFFFF;
const MAX_ED: u16 = 0xFFFF;

/// Same (parent_oaid, child_oaid) pair repetition threshold.
const REPEATED_PATH_THRESHOLD: u32 = 2;

fn now_epoch_f64() -> f64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64()
}

fn new_uuid_hex() -> String {
    uuid::Uuid::new_v4().to_string().replace('-', "")
}

// ─── Governance Decision ────────────────────────────────────────────────────────

/// Outcome of `AEGFGovernor::submit_request()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GovernanceDecision {
    /// Proceed normally.
    Allow,
    /// Recoverable hold — retry after resolution.
    Pause,
    /// Escalate to human review queue.
    Review,
    /// Unrecoverable — terminate request (not session).
    Terminate,
}

// ─── Execution State ────────────────────────────────────────────────────────────

/// Ten deterministic execution states.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionState {
    Created,
    Processing,
    WaitingAgentResponse,
    WaitingExternalResource,
    WaitingHumanReview,
    Paused,
    Completed,
    Failed,
    Terminated,
    Expired,
}

impl ExecutionState {
    /// Terminal states — no further transitions allowed.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            ExecutionState::Completed
                | ExecutionState::Failed
                | ExecutionState::Terminated
                | ExecutionState::Expired
        )
    }
}

/// Returns the set of allowed target states for a given source state.
fn allowed_transitions(state: ExecutionState) -> &'static [ExecutionState] {
    use ExecutionState::*;
    match state {
        Created => &[
            Processing, WaitingHumanReview, Paused, Completed, Failed, Terminated, Expired,
        ],
        Processing => &[
            WaitingAgentResponse, WaitingExternalResource, WaitingHumanReview, Paused,
            Completed, Failed, Terminated, Expired,
        ],
        WaitingAgentResponse => &[
            Processing, WaitingHumanReview, Paused, Completed, Failed, Terminated, Expired,
        ],
        WaitingExternalResource => &[
            Processing, WaitingHumanReview, Paused, Completed, Failed, Terminated, Expired,
        ],
        WaitingHumanReview => &[
            Processing, Paused, Completed, Failed, Terminated, Expired,
        ],
        Paused => &[
            Processing, WaitingHumanReview, Completed, Failed, Terminated, Expired,
        ],
        // Terminal states: no outgoing transitions.
        Completed | Failed | Terminated | Expired => &[],
    }
}

// ─── AEGFMetadata ───────────────────────────────────────────────────────────────

/// Authenticated request metadata — all governance decisions derive from these fields.
/// Packed into 120 bytes (big-endian) for inclusion in MEASC AAD.
///
/// Binary layout (120 bytes, big-endian):
///   Offset  0: CID   (16 bytes)  Conversation ID
///   Offset 16: RID   (16 bytes)  Request ID
///   Offset 32: PRID  (16 bytes)  Parent RID (all-zeros = root)
///   Offset 48: SID   (16 bytes)  Session ID
///   Offset 64: OAID  (32 bytes)  Origin Agent ID (UTF-8, null-padded)
///   Offset 96: HC    (2 bytes)   Hop Count (uint16 BE)
///   Offset 98: ED    (2 bytes)   Execution Depth (uint16 BE)
///   Offset100: TTL   (8 bytes)   Expiry (float64 BE, Unix epoch seconds)
///   Offset108: reserved (12 bytes, must be zero)
#[derive(Debug, Clone)]
pub struct AEGFMetadata {
    /// Phase 3 / M-13 fix: `Arc<str>` (not `String`) — this field is set from the
    /// same session identifier on every packet in a session, and cloning an
    /// `Arc<str>` is an atomic refcount bump rather than a heap allocation +
    /// byte copy. `rid`/`prid`/`oaid` stay `String`: `rid` is a fresh UUID
    /// minted per request (nothing to share), `prid` mirrors a parent's `rid`
    /// for the same reason, and `oaid` is an agent identifier, not a session one.
    pub cid: Arc<str>,
    pub rid: String,
    pub prid: String,
    pub sid: Arc<str>,
    pub oaid: String,
    pub hc: u16,
    pub ed: u16,
    pub ttl: f64,
}

fn str_to_16(s: &str) -> [u8; 16] {
    let clean: String = s.replace('-', "");
    let padded = format!("{:0<32}", &clean[..clean.len().min(32)]);
    let bytes = hex::decode(&padded).unwrap_or_else(|_| vec![0u8; 16]);
    let mut out = [0u8; 16];
    out.copy_from_slice(&bytes[..16]);
    out
}

fn bytes16_to_hex(b: &[u8; 16]) -> String {
    hex::encode(b)
}

fn oaid_to_32(oaid: &str) -> [u8; 32] {
    let raw = oaid.as_bytes();
    let len = raw.len().min(32);
    let mut out = [0u8; 32];
    out[..len].copy_from_slice(&raw[..len]);
    out
}

fn bytes32_to_oaid(b: &[u8; 32]) -> String {
    let end = b.iter().rposition(|&x| x != 0).map_or(0, |p| p + 1);
    String::from_utf8_lossy(&b[..end]).into_owned()
}

impl AEGFMetadata {
    /// Create a fresh metadata record (new conversation or new request).
    pub fn new(
        oaid: &str,
        sid: &str,
        cid: Option<&str>,
        prid: Option<&str>,
        ttl_seconds: f64,
        hc: u16,
        ed: u16,
    ) -> Self {
        Self {
            cid: match cid {
                Some(s) => Arc::from(s),
                None => Arc::from(new_uuid_hex()),
            },
            rid: new_uuid_hex(),
            prid: prid.map_or_else(|| RID_ROOT.to_string(), |s| s.to_string()),
            sid: Arc::from(sid),
            oaid: oaid.to_string(),
            hc,
            ed,
            ttl: now_epoch_f64() + ttl_seconds,
        }
    }

    /// Derive a child request from a parent (increments HC and ED).
    pub fn derive(parent: &AEGFMetadata, new_oaid: Option<&str>) -> Result<Self, SAACPHardDrop> {
        if parent.hc == MAX_HC {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AegfHopLimitExceeded,
                format!("Hop count {} already at maximum {}.", parent.hc, MAX_HC),
            ));
        }
        if parent.ed == MAX_ED {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AegfDepthLimitExceeded,
                format!("Execution depth {} already at maximum {}.", parent.ed, MAX_ED),
            ));
        }
        Ok(Self {
            cid: parent.cid.clone(),
            rid: new_uuid_hex(),
            prid: parent.rid.clone(),
            sid: parent.sid.clone(),
            oaid: new_oaid.unwrap_or(&parent.oaid).to_string(),
            hc: parent.hc.checked_add(1).expect("hc bounded by MAX_HC check above"),
            ed: parent.ed.checked_add(1).expect("ed bounded by MAX_ED check above"),
            ttl: parent.ttl,
        })
    }

    /// Serialize to 120-byte binary (big-endian).
    pub fn pack(&self) -> [u8; AEGF_META_SIZE] {
        let mut buf = [0u8; AEGF_META_SIZE];
        let cid_b = str_to_16(&self.cid);
        let rid_b = str_to_16(&self.rid);
        let prid_b = str_to_16(&self.prid);
        let sid_b = str_to_16(&self.sid);
        let oaid_b = oaid_to_32(&self.oaid);

        buf[0..16].copy_from_slice(&cid_b);
        buf[16..32].copy_from_slice(&rid_b);
        buf[32..48].copy_from_slice(&prid_b);
        buf[48..64].copy_from_slice(&sid_b);
        buf[64..96].copy_from_slice(&oaid_b);
        buf[96..98].copy_from_slice(&self.hc.to_be_bytes());
        buf[98..100].copy_from_slice(&self.ed.to_be_bytes());
        buf[100..108].copy_from_slice(&self.ttl.to_be_bytes());
        // bytes 108..120 remain zero (reserved)
        buf
    }

    /// Deserialize from 120-byte binary.
    pub fn unpack(data: &[u8]) -> Result<Self, SAACPHardDrop> {
        if data.len() < AEGF_META_SIZE {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::MalformedHeader,
                format!(
                    "AEGFMetadata requires {} bytes, got {}.",
                    AEGF_META_SIZE,
                    data.len()
                ),
            ));
        }
        let mut cid_b = [0u8; 16];
        let mut rid_b = [0u8; 16];
        let mut prid_b = [0u8; 16];
        let mut sid_b = [0u8; 16];
        let mut oaid_b = [0u8; 32];

        cid_b.copy_from_slice(&data[0..16]);
        rid_b.copy_from_slice(&data[16..32]);
        prid_b.copy_from_slice(&data[32..48]);
        sid_b.copy_from_slice(&data[48..64]);
        oaid_b.copy_from_slice(&data[64..96]);

        let hc = u16::from_be_bytes([data[96], data[97]]);
        let ed = u16::from_be_bytes([data[98], data[99]]);
        let ttl = f64::from_be_bytes([
            data[100], data[101], data[102], data[103],
            data[104], data[105], data[106], data[107],
        ]);

        Ok(Self {
            cid: Arc::from(bytes16_to_hex(&cid_b)),
            rid: bytes16_to_hex(&rid_b),
            prid: bytes16_to_hex(&prid_b),
            sid: Arc::from(bytes16_to_hex(&sid_b)),
            oaid: bytes32_to_oaid(&oaid_b),
            hc,
            ed,
            ttl,
        })
    }

    /// True if the TTL has passed.
    pub fn is_expired(&self) -> bool {
        now_epoch_f64() > self.ttl
    }

    /// True if this request originated the conversation (no parent).
    pub fn is_root(&self) -> bool {
        self.prid == RID_ROOT || self.prid == CID_NONE
    }
}

// ─── Execution State Machine ────────────────────────────────────────────────────

/// Internal record for `ExecutionStateMachine`.
#[derive(Debug, Clone)]
pub struct StateRecord {
    pub state: ExecutionState,
    pub reason: String,
    pub updated_at: f64,
    pub created_at: f64,
}

/// Thread-safe per-request state registry with allowed-transition enforcement.
pub struct ExecutionStateMachine {
    states: Mutex<HashMap<String, StateRecord>>,
}

/// Maximum ESM entries before eviction kicks in.
const ESM_MAX_ENTRIES: usize = 100_000;

impl ExecutionStateMachine {
    pub fn new() -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
        }
    }

    /// Register a new request in CREATED state.
    /// Returns `Err` if the RID is already registered.
    pub fn create(&self, rid: &str, reason: &str) -> Result<ExecutionState, String> {
        let mut states = self.states.lock().unwrap();
        if states.contains_key(rid) {
            return Err(format!("RID {}… already registered in ESM.", &rid[..8.min(rid.len())]));
        }
        Self::evict_if_needed(&mut states);
        let now = now_epoch_f64();
        states.insert(
            rid.to_string(),
            StateRecord {
                state: ExecutionState::Created,
                reason: reason.to_string(),
                updated_at: now,
                created_at: now,
            },
        );
        Ok(ExecutionState::Created)
    }

    /// Transition `rid` to `new_state` if the transition is allowed.
    pub fn transition(
        &self,
        rid: &str,
        new_state: ExecutionState,
        reason: &str,
    ) -> Result<ExecutionState, SAACPHardDrop> {
        let mut states = self.states.lock().unwrap();
        let rec = states.get_mut(rid).ok_or_else(|| {
            SAACPHardDrop::new(
                SAACPBytecodes::AegfInvalidTransition,
                format!(
                    "RID {}… not found in ESM — cannot transition to {:?}.",
                    &rid[..8.min(rid.len())],
                    new_state
                ),
            )
        })?;

        let current = rec.state;
        let allowed = allowed_transitions(current);
        if !allowed.contains(&new_state) {
            return Err(SAACPHardDrop::new(
                SAACPBytecodes::AegfInvalidTransition,
                format!(
                    "Illegal ESM transition: {:?} → {:?} for RID {}…",
                    current,
                    new_state,
                    &rid[..8.min(rid.len())]
                ),
            ));
        }
        rec.state = new_state;
        rec.reason = reason.to_string();
        rec.updated_at = now_epoch_f64();
        Ok(new_state)
    }

    /// Return current state, or `None` if not found.
    pub fn get_state(&self, rid: &str) -> Option<ExecutionState> {
        let states = self.states.lock().unwrap();
        states.get(rid).map(|r| r.state)
    }

    /// Return full record, or `None` if not found.
    pub fn get_record(&self, rid: &str) -> Option<StateRecord> {
        let states = self.states.lock().unwrap();
        states.get(rid).cloned()
    }

    /// Remove a request from the registry. Returns true if found.
    pub fn remove(&self, rid: &str) -> bool {
        let mut states = self.states.lock().unwrap();
        states.remove(rid).is_some()
    }

    /// Evict terminal states older than `max_age_seconds`. Returns eviction count.
    pub fn expire_old(&self, max_age_seconds: f64) -> usize {
        let cutoff = now_epoch_f64() - max_age_seconds;
        let mut states = self.states.lock().unwrap();
        let to_remove: Vec<String> = states
            .iter()
            .filter(|(_, rec)| rec.state.is_terminal() && rec.updated_at < cutoff)
            .map(|(rid, _)| rid.clone())
            .collect();
        let count = to_remove.len();
        for rid in to_remove {
            states.remove(&rid);
        }
        count
    }

    /// Current entry count.
    pub fn count(&self) -> usize {
        self.states.lock().unwrap().len()
    }

    /// Must be called with the lock held (via mutable ref to HashMap).
    fn evict_if_needed(states: &mut HashMap<String, StateRecord>) {
        if states.len() < ESM_MAX_ENTRIES {
            return;
        }
        // Evict terminal states first (up to 10,000)
        let terminal: Vec<String> = states
            .iter()
            .filter(|(_, rec)| rec.state.is_terminal())
            .map(|(rid, _)| rid.clone())
            .take(10_000)
            .collect();
        for rid in terminal {
            states.remove(&rid);
        }
        if states.len() >= ESM_MAX_ENTRIES {
            // Evict 1000 oldest entries regardless of state
            let mut entries: Vec<(String, f64)> = states
                .iter()
                .map(|(rid, rec)| (rid.clone(), rec.updated_at))
                .collect();
            entries.sort_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal));
            for (rid, _) in entries.into_iter().take(1000) {
                states.remove(&rid);
            }
        }
    }
}

impl Default for ExecutionStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Distributed Execution Graph (DEG) ──────────────────────────────────────────

#[allow(dead_code)]
struct DEGNode {
    rid: String,
    prid: String,
    meta: AEGFMetadata,
    children: HashSet<String>,
}

/// Combined DEG state. `nodes` and `path_counts` are always read/written
/// together by every non-trivial DEG operation, so they are protected by a
/// single `Mutex` rather than two separately-locked fields (H-16). Two
/// independently-locked maps require callers to acquire both in a
/// consistent order to avoid deadlock, and create a TOCTOU window between
/// the two acquisitions unless every call site is audited to hold both
/// locks continuously across check-then-act sequences (see the CRIT-7 fix
/// below, which had to hand-inline that invariant). A single lock makes
/// that invariant structural instead of a convention every future edit
/// must remember to preserve.
struct DegState {
    nodes: HashMap<String, DEGNode>,
    path_counts: HashMap<(String, String), u32>,
}

/// Directed graph of active agent interactions.
///
/// Invariants (checked before processing every request):
/// 1. Hop Count ≤ policy.max_hop_count
/// 2. Execution Depth ≤ policy.max_execution_depth
/// 3. No cycle (DFS)
/// 4. No repeated unresolved (parent_oaid, child_oaid) path beyond threshold
/// 5. TTL not expired
pub struct DistributedExecutionGraph {
    state: Mutex<DegState>,
}

impl DistributedExecutionGraph {
    pub fn new() -> Self {
        Self {
            state: Mutex::new(DegState {
                nodes: HashMap::new(),
                path_counts: HashMap::new(),
            }),
        }
    }

    /// Register a new request in the graph (does NOT validate).
    pub fn add_node(&self, meta: &AEGFMetadata) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let DegState { nodes, path_counts } = &mut *guard;
        let rid = meta.rid.clone();
        let prid = meta.prid.clone();

        if prid != RID_ROOT {
            if let Some(parent) = nodes.get_mut(&prid) {
                parent.children.insert(rid.clone());
            }
            if let Some(parent) = nodes.get(&prid) {
                let parent_oaid = parent.meta.oaid.clone();
                *path_counts
                    .entry((parent_oaid, meta.oaid.clone()))
                    .or_insert(0) += 1;
            }
        }

        nodes.insert(
            rid,
            DEGNode {
                rid: meta.rid.clone(),
                prid: meta.prid.clone(),
                meta: meta.clone(),
                children: HashSet::new(),
            },
        );
    }

    /// Remove a request from the graph.
    pub fn remove_request(&self, rid: &str) {
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let DegState { nodes, path_counts } = &mut *guard;
        if let Some(node) = nodes.remove(rid) {
            if node.prid != RID_ROOT {
                if let Some(parent) = nodes.get_mut(&node.prid) {
                    parent.children.remove(rid);
                }
                if let Some(parent) = nodes.get(&node.prid) {
                    let key = (parent.meta.oaid.clone(), node.meta.oaid.clone());
                    if let Some(count) = path_counts.get_mut(&key) {
                        *count = count.saturating_sub(1);
                    }
                }
            }
        }
    }

    /// Return ancestor RIDs from root to the given node.
    pub fn get_ancestors(&self, rid: &str) -> Vec<String> {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let nodes = &guard.nodes;
        let mut ancestors = Vec::new();
        let mut current = rid.to_string();
        let mut visited = HashSet::new();
        while let Some(node) = nodes.get(&current) {
            if node.prid == RID_ROOT || visited.contains(&node.prid) {
                break;
            }
            visited.insert(current.clone());
            ancestors.push(node.prid.clone());
            current = node.prid.clone();
        }
        ancestors
    }

    /// Current node count.
    pub fn node_count(&self) -> usize {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).nodes.len()
    }

    /// Return true if `rid` has a cycle in its ancestor chain (DFS).
    pub fn detect_cycle(&self, rid: &str) -> bool {
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        Self::has_cycle_inner(&guard.nodes, rid)
    }

    fn has_cycle_inner(nodes: &HashMap<String, DEGNode>, start: &str) -> bool {
        let node = match nodes.get(start) {
            Some(n) => n,
            None => return false,
        };
        let mut current = node.prid.clone();
        let mut path = HashSet::new();
        while current != RID_ROOT {
            if current == start {
                return true;
            }
            if !path.insert(current.clone()) {
                return true;
            }
            match nodes.get(&current) {
                Some(parent_node) => current = parent_node.prid.clone(),
                None => break,
            }
        }
        false
    }

    /// True if hop count exceeds the limit.
    pub fn detect_excessive_hops(meta: &AEGFMetadata, max_hc: u16) -> bool {
        meta.hc > max_hc
    }

    /// True if execution depth exceeds the limit.
    pub fn detect_excessive_depth(meta: &AEGFMetadata, max_ed: u16) -> bool {
        meta.ed > max_ed
    }

    /// True if the (parent_oaid, child_oaid) pair exceeds the repetition threshold.
    pub fn detect_repeated_path(&self, meta: &AEGFMetadata) -> bool {
        if meta.prid == RID_ROOT {
            return false;
        }
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let parent_oaid = match guard.nodes.get(&meta.prid) {
            Some(p) => p.meta.oaid.clone(),
            None => return false,
        };
        let count = guard
            .path_counts
            .get(&(parent_oaid, meta.oaid.clone()))
            .copied()
            .unwrap_or(0);
        count >= REPEATED_PATH_THRESHOLD
    }

    /// Validate all graph invariants atomically and add the node if ALLOW.
    ///
    /// Guard order (cheapest first):
    /// 0. Total graph size cap (O(1))
    /// 1. TTL check (O(1))
    /// 2. Hop count (O(1))
    /// 3. Execution depth (O(1))
    /// 4. Repeated path (O(1))
    /// 5. Cycle detection DFS (O(V+E))
    pub fn validate_and_add(
        &self,
        meta: &AEGFMetadata,
        policy: &AEGFPolicy,
    ) -> GovernanceDecision {
        // 0. Graph node cap — cheap early-exit pre-check (not authoritative;
        // see the re-check below held under the same lock as the insert).
        {
            let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
            if guard.nodes.len() >= policy.max_graph_nodes as usize {
                return GovernanceDecision::Pause;
            }
        }

        // 1. TTL check
        if meta.is_expired() {
            return GovernanceDecision::Terminate;
        }

        // 2. Hop count
        if Self::detect_excessive_hops(meta, policy.max_hop_count) {
            return GovernanceDecision::Pause;
        }

        // 3. Execution depth
        if Self::detect_excessive_depth(meta, policy.max_execution_depth) {
            return GovernanceDecision::Pause;
        }

        // 4 & 5. Repeated-path check, cap re-check, and insert all happen
        // under ONE continuous hold of the combined state lock below.
        //
        // SECURITY FIX (CRIT-7): previously `detect_repeated_path` acquired
        // and released `nodes`/`path_counts` on its own, then this function
        // re-acquired both locks separately to perform the insert. Between
        // the release and the re-acquisition, concurrent callers sharing the
        // same (parent_oaid, child_oaid) pair could all observe a count below
        // `REPEATED_PATH_THRESHOLD`, all pass, and all insert — bypassing the
        // repeated-path governance control under load. The check is now
        // inlined here, using the same lock guard held for the insert, so
        // there is no window between "check" and "act".
        //
        // SECURITY FIX (H-16): `nodes` and `path_counts` used to be two
        // separately-locked `Mutex` fields, acquired in sequence here. That
        // required every call site combining both to acquire them in a
        // fixed order to avoid deadlock, and offered no compiler-enforced
        // guarantee that a future edit wouldn't reorder them or acquire one
        // without the other mid-critical-section. They are now one
        // `Mutex<DegState>`, acquired once, so the ordering invariant is
        // structural rather than a convention to remember.
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let DegState { nodes, path_counts } = &mut *guard;

        // SECURITY FIX (FINDING-7): the step-0 cap check above releases the
        // state lock before this point, so concurrent callers can all pass
        // it and then all insert, exceeding `max_graph_nodes` by up to
        // (thread count - 1). Re-check the cap here, atomically with the
        // insert, under the single lock acquisition that performs it.
        if nodes.len() >= policy.max_graph_nodes as usize {
            return GovernanceDecision::Pause;
        }

        if meta.prid != RID_ROOT {
            if let Some(parent) = nodes.get(&meta.prid) {
                let count = path_counts
                    .get(&(parent.meta.oaid.clone(), meta.oaid.clone()))
                    .copied()
                    .unwrap_or(0);
                if count >= REPEATED_PATH_THRESHOLD {
                    return GovernanceDecision::Review;
                }
            }
        }

        let rid = meta.rid.clone();
        let prid = meta.prid.clone();

        nodes.insert(
            rid.clone(),
            DEGNode {
                rid: rid.clone(),
                prid: prid.clone(),
                meta: meta.clone(),
                children: HashSet::new(),
            },
        );
        if prid != RID_ROOT {
            if let Some(parent) = nodes.get_mut(&prid) {
                parent.children.insert(rid.clone());
            }
        }

        let has_cycle = Self::has_cycle_inner(nodes, &rid);
        if has_cycle {
            nodes.remove(&rid);
            if prid != RID_ROOT {
                if let Some(parent) = nodes.get_mut(&prid) {
                    parent.children.remove(&rid);
                }
            }
            return GovernanceDecision::Review;
        }

        // Commit path counter
        if prid != RID_ROOT {
            if let Some(parent) = nodes.get(&prid) {
                let parent_oaid = parent.meta.oaid.clone();
                *path_counts
                    .entry((parent_oaid, meta.oaid.clone()))
                    .or_insert(0) += 1;
            }
        }

        GovernanceDecision::Allow
    }

    /// Phase 3 / P-2 fast path: validate a **root** request (`meta.prid ==
    /// RID_ROOT`) that the caller will immediately discard (never inserted,
    /// so nothing to remove afterward) — see `AEGFGovernor::submit_and_complete`,
    /// which is the only intended caller.
    ///
    /// This is provably equivalent, for a root request only, to calling
    /// `validate_and_add` followed immediately by `remove_request` on the
    /// same rid with no other operation interleaved:
    ///   - `has_cycle_inner` walks `node.prid` while `current != RID_ROOT` —
    ///     a node whose OWN `prid` already equals `RID_ROOT` makes that loop
    ///     never execute, so a root request can never be part of a cycle.
    ///     The DFS `validate_and_add` would otherwise run is therefore
    ///     always a no-op for this case.
    ///   - Both the read and write sides of `path_counts` are gated on
    ///     `prid != RID_ROOT` (`detect_repeated_path` returns `false`
    ///     immediately for a root request; the commit step in
    ///     `validate_and_add` is skipped the same way) — so a root request
    ///     never touches `path_counts` either.
    ///   - Since nothing is inserted here, no other caller can observe this
    ///     request as a parent in the window between "add" and "remove" the
    ///     way the full `validate_and_add`+`remove_request` pair briefly
    ///     allows — there is no window at all, which is strictly *more*
    ///     atomic than the general case, not less (Part 12 principle 8 is
    ///     preserved, not weakened).
    ///
    /// The only genuinely observable effect `validate_and_add` has for a
    /// root request is the graph-size cap check, so that is the only check
    /// this function performs under the lock — one acquisition total,
    /// instead of `validate_and_add`'s two plus `remove_request`'s one.
    ///
    /// Panics in debug builds if called with a non-root request — callers
    /// must route those through `validate_and_add`/`remove_request` instead,
    /// since a non-root request's cycle/repeated-path checks and its
    /// availability as a future parent are genuinely observable and must
    /// not be skipped.
    pub fn validate_transient_root(
        &self,
        meta: &AEGFMetadata,
        policy: &AEGFPolicy,
    ) -> GovernanceDecision {
        debug_assert_eq!(
            meta.prid, RID_ROOT,
            "validate_transient_root is only valid for root requests (prid == RID_ROOT)"
        );

        // TTL / hop / depth are pure metadata checks — identical to the
        // first three guards in `validate_and_add`, no lock needed.
        if meta.is_expired() {
            return GovernanceDecision::Terminate;
        }
        if Self::detect_excessive_hops(meta, policy.max_hop_count) {
            return GovernanceDecision::Pause;
        }
        if Self::detect_excessive_depth(meta, policy.max_execution_depth) {
            return GovernanceDecision::Pause;
        }

        // Single lock acquisition: the graph-size cap is the only check
        // that depends on shared state for a root request that is never
        // actually inserted.
        let guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if guard.nodes.len() >= policy.max_graph_nodes as usize {
            return GovernanceDecision::Pause;
        }

        GovernanceDecision::Allow
    }

    /// Remove all nodes whose TTL has passed. Returns eviction count.
    pub fn evict_expired(&self) -> usize {
        let now = now_epoch_f64();
        let mut guard = self.state.lock().unwrap_or_else(|e| e.into_inner());
        let DegState { nodes, path_counts } = &mut *guard;
        let expired: Vec<String> = nodes
            .iter()
            .filter(|(_, node)| node.meta.ttl < now)
            .map(|(rid, _)| rid.clone())
            .collect();
        let count = expired.len();
        for rid in &expired {
            if let Some(node) = nodes.remove(rid) {
                if node.prid != RID_ROOT {
                    if let Some(parent) = nodes.get_mut(&node.prid) {
                        parent.children.remove(rid);
                    }
                }
            }
        }
        // Clean up path counts for evicted nodes
        path_counts.retain(|_, v| *v > 0);
        count
    }
}

impl Default for DistributedExecutionGraph {
    fn default() -> Self {
        Self::new()
    }
}

// ─── AEGF Policy ────────────────────────────────────────────────────────────────

/// Global safety limits, configurable per deployment.
#[derive(Debug, Clone)]
pub struct AEGFPolicy {
    pub max_hop_count: u16,
    pub max_execution_depth: u16,
    pub max_conversation_lifetime: f64,
    pub max_delegation_depth: u32,
    pub max_capability_lifetime: f64,
    pub max_unresolved_deps: usize,
    pub esm_gc_age_seconds: f64,
    /// Hard cap on DEG node count. DFS on an unbounded graph is a CPU
    /// exhaustion attack vector.
    pub max_graph_nodes: u32,
}

impl Default for AEGFPolicy {
    fn default() -> Self {
        Self {
            max_hop_count: 16,
            max_execution_depth: 8,
            max_conversation_lifetime: 3600.0,
            max_delegation_depth: 5,
            max_capability_lifetime: 300.0,
            max_unresolved_deps: 50,
            esm_gc_age_seconds: 7200.0,
            max_graph_nodes: 10_000,
        }
    }
}

// ─── AEGF Governor ──────────────────────────────────────────────────────────────

/// Central coordinator: DEG + ESM + policy.
///
/// All governance decisions flow through `submit_request()`.
/// Violations transition states instead of terminating sessions.
/// Thread-safe.
pub struct AEGFGovernor {
    policy: Mutex<AEGFPolicy>,
    deg: DistributedExecutionGraph,
    esm: ExecutionStateMachine,
}

impl AEGFGovernor {
    pub fn new(policy: Option<AEGFPolicy>) -> Self {
        Self {
            policy: Mutex::new(policy.unwrap_or_default()),
            deg: DistributedExecutionGraph::new(),
            esm: ExecutionStateMachine::new(),
        }
    }

    pub fn deg(&self) -> &DistributedExecutionGraph {
        &self.deg
    }

    pub fn esm(&self) -> &ExecutionStateMachine {
        &self.esm
    }

    pub fn set_policy(&self, policy: AEGFPolicy) {
        *self.policy.lock().unwrap() = policy;
    }

    pub fn get_policy(&self) -> AEGFPolicy {
        self.policy.lock().unwrap().clone()
    }

    /// Validate metadata, run DEG governance, update ESM.
    /// Returns `GovernanceDecision` (never panics for policy violations).
    ///
    /// Security ordering:
    /// 1. TTL check
    /// 2. Hop / depth bounds
    /// 3. DEG cycle + repeated-path detection
    /// 4. ESM registration + transition
    pub fn submit_request(&self, meta: &AEGFMetadata) -> GovernanceDecision {
        let policy = self.policy.lock().unwrap().clone();

        // Step 1: TTL
        if meta.is_expired() {
            let _ = self.esm.create(&meta.rid, "expired_on_arrival");
            let _ = self
                .esm
                .transition(&meta.rid, ExecutionState::Expired, "TTL expired");
            return GovernanceDecision::Terminate;
        }

        // Steps 2-3: DEG validation (atomic validate-and-add)
        let decision = self.deg.validate_and_add(meta, &policy);

        // Step 4: ESM — register and update state based on decision
        match self.esm.create(&meta.rid, "submitted") {
            Ok(_) => {}
            Err(_) => {
                // Already registered (idempotent submit)
                if let Some(current) = self.esm.get_state(&meta.rid) {
                    if current.is_terminal() {
                        return GovernanceDecision::Terminate;
                    }
                }
                return GovernanceDecision::Allow;
            }
        }

        match decision {
            GovernanceDecision::Allow => {
                let _ = self
                    .esm
                    .transition(&meta.rid, ExecutionState::Processing, "governance_allow");
            }
            GovernanceDecision::Pause => {
                let _ = self
                    .esm
                    .transition(&meta.rid, ExecutionState::Paused, "governance_pause");
            }
            GovernanceDecision::Review => {
                let _ = self.esm.transition(
                    &meta.rid,
                    ExecutionState::WaitingHumanReview,
                    "governance_review",
                );
            }
            GovernanceDecision::Terminate => {
                let _ = self.esm.transition(
                    &meta.rid,
                    ExecutionState::Terminated,
                    "governance_terminate",
                );
            }
        }

        decision
    }

    /// Phase 3 / P-2 fast path: fuses `submit_request` + an immediate
    /// unconditional `complete_request(rid, None)` into a single call — the
    /// exact pattern `handler.rs`'s Gate 11.0 uses for every non-exempt
    /// packet (packets are processed synchronously; nothing keeps a DEG
    /// entry alive across packets, so every submission is immediately
    /// discarded again).
    ///
    /// For a **root** request (`meta.prid == RID_ROOT` — true for every
    /// call `handler.rs` makes, since the handler layer has no hop-chain
    /// context) this uses [`DistributedExecutionGraph::validate_transient_root`]
    /// instead of `validate_and_add`, cutting the DEG lock acquisitions for
    /// this call from 3 (validate_and_add's two + remove_request's one) down
    /// to 1. This is observably identical to the original two-call sequence:
    /// `validate_and_add` never leaves a node inserted for a root request in
    /// any of the four `GovernanceDecision` outcomes (`Allow` inserts and
    /// immediately keeps it — matched by `validate_transient_root` computing
    /// the same decision without ever inserting, since a root request can
    /// never fail cycle/repeated-path checks in the first place — see that
    /// method's doc comment for the proof), so the `remove_request` call
    /// `complete_request` would have made afterward is *always* a
    /// documented no-op for this call site and is safely skipped entirely.
    ///
    /// Non-root requests (not produced by any current call site, but
    /// supported for API completeness / future callers) fall back to the
    /// exact original `validate_and_add` + `complete_request` sequence,
    /// unchanged.
    ///
    /// ESM bookkeeping (`create`/`transition`) is untouched in both paths —
    /// this optimizes DEG lock traffic only, per Part 6.2 row P-2 / Part 6.4
    /// step 7 ("DEG fast-path... eliminate 3 lock acquisitions"); ESM's own
    /// lock traffic is a separate concern not in this pass's scope.
    pub fn submit_and_complete(&self, meta: &AEGFMetadata) -> GovernanceDecision {
        let policy = self.policy.lock().unwrap().clone();
        let is_root = meta.prid == RID_ROOT;

        // Step 1: TTL — identical to submit_request's early-return path.
        // `complete_request` is unconditionally called by the caller after
        // `submit_request` returns (see `handler.rs`'s Gate 11.0 call site),
        // but on this branch it is a guaranteed no-op: `transition` to
        // `Completed` fails silently (the entry is already in the terminal
        // `Expired` state, which has no outgoing transitions — see
        // `allowed_transitions`), and `remove_request` is a no-op lookup
        // since neither `validate_and_add` nor `validate_transient_root` was
        // ever reached on this branch, so nothing was ever inserted into the
        // DEG. Safe to return directly with no further work.
        if meta.is_expired() {
            let _ = self.esm.create(&meta.rid, "expired_on_arrival");
            let _ = self.esm.transition(&meta.rid, ExecutionState::Expired, "TTL expired");
            return GovernanceDecision::Terminate;
        }

        // Steps 2-3: DEG validation — fast path for root requests, full
        // validate_and_add otherwise. `deg_may_have_inserted` tracks whether
        // this call could possibly have left a node in the DEG that the
        // cleanup step below must remove — `validate_transient_root` never
        // inserts under any circumstance (see its doc comment), so the root
        // case is always `false`; `validate_and_add` may or may not have
        // inserted depending on which of its own guards fired, so the
        // non-root case conservatively assumes `true` (an unconditional
        // `remove_request` call on a key that was never inserted is a safe,
        // cheap no-op — this fallback path isn't the one Phase 3 targets for
        // lock-count reduction; no current caller in this crate produces a
        // non-root request here — see this method's doc comment).
        let (decision, deg_may_have_inserted) = if is_root {
            (self.deg.validate_transient_root(meta, &policy), false)
        } else {
            (self.deg.validate_and_add(meta, &policy), true)
        };

        // Step 4: ESM — register and update state based on decision.
        // Identical branching to submit_request's own Step 4: on an
        // idempotent resubmit (rid already registered), submit_request
        // returns immediately WITHOUT running the transition-by-decision
        // match block below — `final_decision` captures that same override,
        // and `skip_transition_match` suppresses that block accordingly.
        let mut final_decision = decision;
        let mut skip_transition_match = false;
        if self.esm.create(&meta.rid, "submitted").is_err() {
            final_decision = match self.esm.get_state(&meta.rid) {
                Some(current) if current.is_terminal() => GovernanceDecision::Terminate,
                _ => GovernanceDecision::Allow,
            };
            skip_transition_match = true;
        }

        if !skip_transition_match {
            match decision {
                GovernanceDecision::Allow => {
                    let _ = self.esm.transition(&meta.rid, ExecutionState::Processing, "governance_allow");
                }
                GovernanceDecision::Pause => {
                    let _ = self.esm.transition(&meta.rid, ExecutionState::Paused, "governance_pause");
                }
                GovernanceDecision::Review => {
                    let _ = self.esm.transition(&meta.rid, ExecutionState::WaitingHumanReview, "governance_review");
                }
                GovernanceDecision::Terminate => {
                    let _ = self.esm.transition(&meta.rid, ExecutionState::Terminated, "governance_terminate");
                }
            }
        }

        // complete_request(rid, None)'s body, inlined — called
        // unconditionally on this path, exactly as `handler.rs` unconditionally
        // calls `complete_request` after `submit_request` returns regardless
        // of which internal branch fired (including the idempotent-resubmit
        // branch above, matching that same unconditional-call behavior).
        let _ = self.esm.transition(&meta.rid, ExecutionState::Completed, "completed");
        if deg_may_have_inserted {
            self.deg.remove_request(&meta.rid);
        }

        final_decision
    }

    /// Mark a request as completed (or with specified terminal outcome).
    pub fn complete_request(&self, rid: &str, outcome: Option<ExecutionState>) {
        let terminal = match outcome {
            Some(s) if s.is_terminal() => s,
            _ => ExecutionState::Completed,
        };
        let _ = self.esm.transition(rid, terminal, "completed");
        self.deg.remove_request(rid);
    }

    /// Transition to PAUSED state (recoverable).
    pub fn pause_request(&self, rid: &str, reason: &str) {
        let _ = self.esm.transition(rid, ExecutionState::Paused, reason);
    }

    /// Transition to WAITING_HUMAN_REVIEW state.
    pub fn escalate_to_review(&self, rid: &str, reason: &str) {
        let _ = self
            .esm
            .transition(rid, ExecutionState::WaitingHumanReview, reason);
    }

    /// Return current execution state, or None.
    pub fn get_request_state(&self, rid: &str) -> Option<ExecutionState> {
        self.esm.get_state(rid)
    }

    /// GC terminal ESM states + expired DEG nodes. Returns total evicted.
    pub fn expire_stale_requests(&self) -> usize {
        let gc_age = self.policy.lock().unwrap().esm_gc_age_seconds;
        let esm_evicted = self.esm.expire_old(gc_age);
        let deg_evicted = self.deg.evict_expired();
        esm_evicted + deg_evicted
    }
}

use std::sync::LazyLock;

/// Process-wide distributed execution graph singleton.
/// Shared between AEGF governor and CSCS loop detector.
pub static GLOBAL_DAEG: LazyLock<std::sync::Arc<DistributedExecutionGraph>> =
    LazyLock::new(|| std::sync::Arc::new(DistributedExecutionGraph::new()));

/// Process-wide AEGFGovernor singleton.
///
/// Used by Gate 11.0 in `SAACPProtocolHandler::_intercept_packet_inner()` when
/// no AEGFGovernor is explicitly injected. Shares `GLOBAL_DAEG` with the CSCS
/// loop detector so both see the same causal graph state.
pub static GLOBAL_AEGF_GOVERNOR: LazyLock<AEGFGovernor> =
    LazyLock::new(|| AEGFGovernor::new(None));

#[cfg(test)]
mod tests {
    use super::*;

    /// README §4.2 canonical test vector.
    /// Input:  cid="0"*30+"01", rid="0"*30+"02", prid="0"*32,
    ///         sid="0"*30+"03", oaid="test-agent", hc=0, ed=0, ttl=0.0
    /// Output: 120 bytes with known hex layout.
    #[test]
    fn test_aegf_meta_canonical_pack() {
        // AEGF_META_FORMAT_VERSION must be 1
        assert_eq!(AEGF_META_FORMAT_VERSION, 1, "AEGF_META_FORMAT_VERSION must be 1");
        assert_eq!(AEGF_META_SIZE, 120, "AEGF_META_SIZE must be 120 bytes");

        let meta = AEGFMetadata {
            cid:  Arc::from("0".repeat(30) + "01"),
            rid:  "0".repeat(30) + "02",
            prid: "0".repeat(32),
            sid:  Arc::from("0".repeat(30) + "03"),
            oaid: "test-agent".to_string(),
            hc:   0,
            ed:   0,
            ttl:  0.0,
        };

        let packed = meta.pack();
        assert_eq!(packed.len(), 120);

        // CID: offset 0..16 → 0x00..0x00, 0x00, 0x01
        assert_eq!(&packed[0..15], &[0u8; 15]);
        assert_eq!(packed[15], 0x01, "CID last byte must be 0x01");

        // RID: offset 16..32 → 0x00..0x00, 0x00, 0x02
        assert_eq!(&packed[16..31], &[0u8; 15]);
        assert_eq!(packed[31], 0x02, "RID last byte must be 0x02");

        // PRID: offset 32..48 → all zeros (RID_ROOT)
        assert_eq!(&packed[32..48], &[0u8; 16], "PRID must be all-zero for RID_ROOT");

        // SID: offset 48..64 → 0x00..0x00, 0x00, 0x03
        assert_eq!(&packed[48..63], &[0u8; 15]);
        assert_eq!(packed[63], 0x03, "SID last byte must be 0x03");

        // OAID: offset 64..96 → "test-agent" UTF-8, rest zeros
        const OAID_STR: &[u8] = b"test-agent";
        const OAID_LEN: usize = 10; // b"test-agent".len()
        assert_eq!(&packed[64..64 + OAID_LEN], OAID_STR, "OAID prefix must match");
        assert_eq!(&packed[64 + OAID_LEN..96], &[0u8; 32 - OAID_LEN], "OAID padding must be zero");

        // HC: offset 96..98 → 0x0000
        assert_eq!(&packed[96..98], &[0x00, 0x00], "HC must be 0x0000");

        // ED: offset 98..100 → 0x0000
        assert_eq!(&packed[98..100], &[0x00, 0x00], "ED must be 0x0000");

        // TTL: offset 100..108 → IEEE 754 f64 BE of 0.0 = all zeros
        assert_eq!(&packed[100..108], &[0u8; 8], "TTL 0.0 must be all-zero bytes");

        // Reserved: offset 108..120 → all zeros
        assert_eq!(&packed[108..120], &[0u8; 12], "Reserved bytes must be zero");

        // Round-trip test
        let unpacked = AEGFMetadata::unpack(&packed).expect("unpack must succeed");
        assert_eq!(unpacked.oaid, "test-agent");
        assert_eq!(unpacked.hc, 0);
        assert_eq!(unpacked.ed, 0);
        assert_eq!(unpacked.ttl, 0.0);
    }

    #[test]
    fn test_aegf_meta_format_version() {
        assert_eq!(AEGF_META_FORMAT_VERSION, 1);
    }

    #[test]
    fn test_aegf_meta_size() {
        assert_eq!(AEGF_META_SIZE, 120);
    }

    #[test]
    fn test_deg_max_graph_nodes_cap() {
        // N-7 fix: validate_and_add returns Pause when graph is full
        let gov = AEGFGovernor::new(None);
        gov.set_policy(AEGFPolicy { max_graph_nodes: 2, ..Default::default() });

        let make_meta = |suffix: &str| -> AEGFMetadata {
            AEGFMetadata {
                cid: Arc::from("aaa"),
                rid: format!("rid{}", suffix),
                prid: RID_ROOT.to_string(),
                sid: Arc::from("sid1"),
                oaid: "agent".to_string(),
                hc: 0,
                ed: 0,
                ttl: now_epoch_f64() + 3600.0,
            }
        };

        assert_eq!(gov.submit_request(&make_meta("1")), GovernanceDecision::Allow);
        assert_eq!(gov.submit_request(&make_meta("2")), GovernanceDecision::Allow);
        // Graph now has 2 nodes = max_graph_nodes; next must be Pause
        assert_eq!(gov.submit_request(&make_meta("3")), GovernanceDecision::Pause);
    }

    // ── Phase 3 / P-2: submit_and_complete fast-path equivalence ────────────

    fn root_meta(rid: &str) -> AEGFMetadata {
        AEGFMetadata {
            cid: Arc::from("cid-fastpath"),
            rid: rid.to_string(),
            prid: RID_ROOT.to_string(),
            sid: Arc::from("sid-fastpath"),
            oaid: "agent-fastpath".to_string(),
            hc: 0,
            ed: 0,
            ttl: now_epoch_f64() + 3600.0,
        }
    }

    #[test]
    fn submit_and_complete_allows_root_request_and_leaves_no_deg_residue() {
        let gov = AEGFGovernor::new(None);
        let meta = root_meta("fp-allow-1");
        assert_eq!(gov.submit_and_complete(&meta), GovernanceDecision::Allow);
        // A root request never gets inserted by the fast path, so the DEG
        // node count must be unaffected — matching submit_request +
        // complete_request's net-zero effect on node_count for a root rid.
        assert_eq!(gov.deg().node_count(), 0);
        // ESM ends in Completed, exactly as complete_request would leave it.
        assert_eq!(gov.get_request_state("fp-allow-1"), Some(ExecutionState::Completed));
    }

    #[test]
    fn submit_and_complete_matches_submit_then_complete_for_ttl_expired() {
        let gov_fast = AEGFGovernor::new(None);
        let gov_slow = AEGFGovernor::new(None);
        let mut meta = root_meta("fp-expired");
        meta.ttl = now_epoch_f64() - 10.0; // already expired

        let fast_decision = gov_fast.submit_and_complete(&meta);

        let slow_decision = gov_slow.submit_request(&meta);
        gov_slow.complete_request(&meta.rid, None);

        assert_eq!(fast_decision, slow_decision);
        assert_eq!(fast_decision, GovernanceDecision::Terminate);
        assert_eq!(
            gov_fast.get_request_state(&meta.rid),
            gov_slow.get_request_state(&meta.rid),
        );
    }

    #[test]
    fn submit_and_complete_matches_submit_then_complete_for_graph_cap_pause() {
        let gov_fast = AEGFGovernor::new(None);
        let gov_slow = AEGFGovernor::new(None);
        let policy = AEGFPolicy { max_graph_nodes: 1, ..Default::default() };
        gov_fast.set_policy(policy.clone());
        gov_slow.set_policy(policy);

        // Fill each governor's DEG to the cap with a non-root node that
        // stays resident (root requests never stay resident under the
        // fast path, so a non-root filler is required to actually exercise
        // the cap for both governors identically).
        let filler_parent = AEGFMetadata {
            cid: Arc::from("cid-cap"),
            rid: "cap-filler-parent".to_string(),
            prid: RID_ROOT.to_string(),
            sid: Arc::from("sid-cap"),
            oaid: "agent-cap".to_string(),
            hc: 0,
            ed: 0,
            ttl: now_epoch_f64() + 3600.0,
        };
        gov_fast.deg().add_node(&filler_parent);
        gov_slow.deg().add_node(&filler_parent);
        assert_eq!(gov_fast.deg().node_count(), 1);
        assert_eq!(gov_slow.deg().node_count(), 1);

        let meta = root_meta("fp-cap-overflow");
        let fast_decision = gov_fast.submit_and_complete(&meta);
        let slow_decision = gov_slow.submit_request(&meta);
        gov_slow.complete_request(&meta.rid, None);

        assert_eq!(fast_decision, GovernanceDecision::Pause);
        assert_eq!(fast_decision, slow_decision);
    }

    #[test]
    fn submit_and_complete_matches_submit_then_complete_for_idempotent_resubmit() {
        let gov_fast = AEGFGovernor::new(None);
        let gov_slow = AEGFGovernor::new(None);
        let meta = root_meta("fp-idempotent");

        // First submission on each governor.
        assert_eq!(gov_fast.submit_and_complete(&meta), GovernanceDecision::Allow);
        let first_slow = gov_slow.submit_request(&meta);
        gov_slow.complete_request(&meta.rid, None);
        assert_eq!(first_slow, GovernanceDecision::Allow);

        // Resubmitting the SAME rid a second time exercises the
        // idempotent-resubmit branch (esm.create returns Err) on both.
        let second_fast = gov_fast.submit_and_complete(&meta);
        let second_slow = gov_slow.submit_request(&meta);
        gov_slow.complete_request(&meta.rid, None);

        assert_eq!(second_fast, second_slow);
        assert_eq!(
            gov_fast.get_request_state(&meta.rid),
            gov_slow.get_request_state(&meta.rid),
        );
    }

    #[test]
    fn submit_and_complete_matches_submit_then_complete_for_non_root_review_cycle() {
        let gov_fast = AEGFGovernor::new(None);
        let gov_slow = AEGFGovernor::new(None);

        // Build an identical resident non-root parent chain on both
        // governors, then submit a child whose prid points back at itself
        // (a manufactured cycle) via submit_and_complete's non-root
        // fallback path (full validate_and_add), matching submit_request
        // exactly.
        let parent = AEGFMetadata {
            cid: Arc::from("cid-cycle"),
            rid: "cycle-parent".to_string(),
            prid: RID_ROOT.to_string(),
            sid: Arc::from("sid-cycle"),
            oaid: "agent-cycle".to_string(),
            hc: 0,
            ed: 0,
            ttl: now_epoch_f64() + 3600.0,
        };
        gov_fast.deg().add_node(&parent);
        gov_slow.deg().add_node(&parent);

        // A node whose own prid equals its own rid is a self-cycle,
        // detected by has_cycle_inner's `current == start` check.
        let cyclic = AEGFMetadata {
            cid: Arc::from("cid-cycle"),
            rid: "cycle-self".to_string(),
            prid: "cycle-self".to_string(),
            sid: Arc::from("sid-cycle"),
            oaid: "agent-cycle-child".to_string(),
            hc: 0,
            ed: 0,
            ttl: now_epoch_f64() + 3600.0,
        };

        let fast_decision = gov_fast.submit_and_complete(&cyclic);
        let slow_decision = gov_slow.submit_request(&cyclic);
        gov_slow.complete_request(&cyclic.rid, None);

        assert_eq!(fast_decision, GovernanceDecision::Review);
        assert_eq!(fast_decision, slow_decision);
        // Both governors must have rolled back the rejected insert — the
        // resident parent is the only node left in each DEG.
        assert_eq!(gov_fast.deg().node_count(), 1);
        assert_eq!(gov_slow.deg().node_count(), 1);
    }

    #[test]
    fn validate_transient_root_never_leaves_a_node_behind() {
        let deg = DistributedExecutionGraph::new();
        let policy = AEGFPolicy::default();
        let meta = root_meta("transient-check");
        assert_eq!(deg.validate_transient_root(&meta, &policy), GovernanceDecision::Allow);
        assert_eq!(deg.node_count(), 0, "validate_transient_root must never insert a node");
    }

    #[test]
    #[should_panic(expected = "validate_transient_root is only valid for root requests")]
    fn validate_transient_root_rejects_non_root_in_debug() {
        let deg = DistributedExecutionGraph::new();
        let policy = AEGFPolicy::default();
        let non_root = AEGFMetadata {
            cid: Arc::from("cid"),
            rid: "child".to_string(),
            prid: "some-parent".to_string(),
            sid: Arc::from("sid"),
            oaid: "agent".to_string(),
            hc: 0,
            ed: 0,
            ttl: now_epoch_f64() + 3600.0,
        };
        let _ = deg.validate_transient_root(&non_root, &policy);
    }

    #[test]
    fn test_gc_expired_proposals_factf() {
        // Verify gc_expired_proposals() alias is accessible
        use crate::factf::ThresholdAuthorityIssuer;
        let tai = ThresholdAuthorityIssuer::new(
            1,
            vec!["auth-1".to_string()],
            0.001, // 1ms TTL so it expires immediately
        ).unwrap();
        let _req_id = tai.create_request(serde_json::json!({"test": true}));
        // Wait briefly for TTL to elapse
        std::thread::sleep(std::time::Duration::from_millis(5));
        let purged = tai.gc_expired_proposals();
        assert_eq!(purged, 1, "gc_expired_proposals must have purged the expired proposal");
    }

    #[test]
    fn test_aegf_test_vector_canonical_output() {
        // README §4.2 test vector: validates pack() produces exact canonical bytes
        let meta = AEGFMetadata {
            cid: Arc::from("00000000000000000000000000000001"),
            rid: "00000000000000000000000000000002".to_string(),
            prid: "00000000000000000000000000000000".to_string(),
            sid: Arc::from("00000000000000000000000000000003"),
            oaid: "test-agent".to_string(),
            hc: 0,
            ed: 0,
            ttl: 0.0,
        };
        let packed = meta.pack();
        let packed_hex = hex::encode(packed);

        // Remove whitespace from AEGF_TEST_VECTOR_BYTES for comparison
        let expected = AEGF_TEST_VECTOR_BYTES.chars().filter(|c| !c.is_whitespace()).collect::<String>();
        assert_eq!(
            packed_hex, expected,
            "AEGF test vector mismatch — pack() output must match AEGF_TEST_VECTOR_BYTES canonical hex"
        );
    }
}
