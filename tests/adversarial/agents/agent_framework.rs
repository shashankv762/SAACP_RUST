//! Realistic AI Agent Simulation Framework
//!
//! Simulates four agent archetypes found in real AI pipelines:
//! - OrchestratorAgent: root authority, issues tokens, delegates tasks
//! - PlannerAgent: receives tasks, breaks into subtasks, delegates further
//! - ExecutorAgent: performs actual operations (DB reads, API calls)
//! - MemoryAgent: manages shared context and conversation state
//!
//! Every agent maps directly to SAACP protocol components:
//!   ZeroTrustGateway (token issuance/validation)
//!   AgentRateLimiter (circuit breaker, cover traffic)
//!   SAACPProtocolHandler (gate pipeline)
//!   FederatedMemory (context store)
//!   DeadMansSwitch (heartbeat)
//!   CSCS (loop detection)
//!   AEGF (execution governance)

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

// ─── Agent task types ─────────────────────────────────────────────

/// A realistic task that flows through the agent pipeline.
#[derive(Debug, Clone)]
pub struct AgentTask {
    pub task_id:       String,
    pub task_type:     TaskType,
    pub payload:       String,
    pub requester:     String,
    pub budget_tokens: u32,
    pub deadline:      Duration,
}

#[derive(Debug, Clone)]
pub enum TaskType {
    DataAnalysis  { query: String, dataset: String },
    PlanExecution { plan_steps: Vec<String> },
    MemoryRead    { key: String },
    MemoryWrite   { key: String, value: String },
    ToolCall      { tool: String, args: HashMap<String, String> },
    ChainedTask   { subtasks: Vec<AgentTask> },
}

// ─── Per-agent metrics ────────────────────────────────────────────

/// Collected during a simulation run.
#[derive(Debug, Default)]
pub struct AgentMetrics {
    pub tasks_received:   u64,
    pub tasks_completed:  u64,
    pub tasks_rejected:   u64,
    pub packets_sent:     u64,
    pub packets_received: u64,
    pub auth_failures:    u64,
    pub injection_blocks: u64,
    pub replay_blocks:    u64,
    pub budget_overruns:  u64,
    pub loop_detections:  u64,
    pub latency_samples:  Vec<Duration>,
    pub recovery_events:  u64,
}

impl AgentMetrics {
    pub fn p99_latency(&self) -> Duration {
        if self.latency_samples.is_empty() { return Duration::ZERO; }
        let mut s = self.latency_samples.clone();
        s.sort();
        s[(s.len() as f64 * 0.99) as usize]
    }
    pub fn mean_latency(&self) -> Duration {
        if self.latency_samples.is_empty() { return Duration::ZERO; }
        let total: Duration = self.latency_samples.iter().sum();
        total / self.latency_samples.len() as u32
    }
}

// ─── The four production agent archetypes ─────────────────────────

/// Root authority. Issues tokens, delegates tasks, owns the session.
pub struct OrchestratorAgent {
    pub id:      String,
    pub metrics: Arc<std::sync::RwLock<AgentMetrics>>,
}

/// Receives tasks, plans them into subtasks, delegates to Executors.
pub struct PlannerAgent {
    pub id:      String,
    pub metrics: Arc<std::sync::RwLock<AgentMetrics>>,
}

/// Performs concrete operations: DB queries, API calls, tool use.
pub struct ExecutorAgent {
    pub id:      String,
    pub metrics: Arc<std::sync::RwLock<AgentMetrics>>,
}

/// Manages FederatedMemory: stores/retrieves shared context.
pub struct MemoryAgent {
    pub id:      String,
    pub metrics: Arc<std::sync::RwLock<AgentMetrics>>,
    pub store:   Arc<std::sync::RwLock<HashMap<String, String>>>,
}

// ─── Attack injection hooks ───────────────────────────────────────

/// Adversary interception points. Implement for each attack class.
pub trait AttackHook: Send + Sync {
    fn on_packet_send    (&self, packet: &[u8]) -> Vec<u8>;
    fn on_packet_receive (&self, packet: &[u8]) -> Vec<u8>;
    fn on_handshake_syn  (&self, syn:    &[u8]) -> Vec<u8>;
    fn on_token          (&self, token:  &[u8]) -> Vec<u8>;
    fn name(&self) -> &'static str;
}

/// Baseline: no tampering. Used for clean throughput measurements.
pub struct NoOpHook;
impl AttackHook for NoOpHook {
    fn on_packet_send    (&self, p: &[u8]) -> Vec<u8> { p.to_vec() }
    fn on_packet_receive (&self, p: &[u8]) -> Vec<u8> { p.to_vec() }
    fn on_handshake_syn  (&self, s: &[u8]) -> Vec<u8> { s.to_vec() }
    fn on_token          (&self, t: &[u8]) -> Vec<u8> { t.to_vec() }
    fn name(&self) -> &'static str { "NoOp (baseline)" }
}
