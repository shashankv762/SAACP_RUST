"use client";

// store.tsx — one shared client-side store for the whole Command Center.
//
// Why this exists: the old dashboard opened a separate EventSource in every
// component that needed live data (agent list, alert feed, mesh graph), so the
// Overview page alone held three duplicate SSE connections. This provider opens
// exactly ONE `/events` connection and one set of REST pollers, then fans the
// data out through fine-grained `useSyncExternalStore` selectors so a burst of
// terminal-log events doesn't force the force-directed graph to re-render.
//
// Everything here is real backend data (see ../../src/command_center.rs). There
// is no simulation path — when the backend is unreachable, slices stay empty and
// the connection pill shows OFFLINE.

import { createContext, useContext, useEffect, useRef, useSyncExternalStore } from "react";
import {
  api,
  openEventSource,
  AgentTrustSnapshot,
  DashboardEvent,
  TrustMeshEdge,
  TrustEventJson,
} from "./api";

export type ConnectionStatus = "connecting" | "live" | "offline";
export type HealthLevel = "nominal" | "degraded" | "critical";
export type LogKind = "attack" | "loop" | "delegation" | "trust";

export interface LogEntry {
  id: number;
  ts: string;
  kind: LogKind;
  tag: string;
  body: string;
  agent?: string;
  gate?: string;
  bytecode?: string;
  estimatedCost?: number | null;
}

export interface FinancialSample {
  t: number;
  tokens: number;
  dollars: number;
  dollarsPerToken: number;
}

export interface MeshData {
  nodes: string[];
  edges: TrustMeshEdge[];
}

interface StoreState {
  agents: AgentTrustSnapshot[];
  mesh: MeshData;
  log: LogEntry[];
  financial: FinancialSample[];
  connection: ConnectionStatus;
  health: HealthLevel;
  /** monotonically bumped whenever a live attack-class event arrives, so the
   *  screen-flash element can fire without the store re-classifying anything. */
  flashSignal: number;
  /** the (source,target) of the most recent delegation edge + a nonce, so the
   *  graph can animate a pulse along it. */
  lastPulse: { source: string; target: string; nonce: number } | null;
  /** an agent id that just dropped to critical trust, for a shockwave anim. */
  lastShock: { agent: string; nonce: number } | null;
}

const MAX_LOG = 240;
const MAX_FINANCIAL_SAMPLES = 300;
const FINANCIAL_POLL_MS = 4000;
const HEALTH_POLL_MS = 8000;
const AGENTS_REFRESH_MS = 12000;
const MESH_REFRESH_MS = 15000;

function nowClock(): string {
  return new Date().toTimeString().slice(0, 8);
}

function trustEventLabel(ev: TrustEventJson): string {
  if (typeof ev === "string") return ev;
  if ("Penalized" in ev) return `Penalized(${ev.Penalized})`;
  if ("Rewarded" in ev) return `Rewarded(${ev.Rewarded})`;
  return "signal";
}

function isCritical(score: number, requiresReauth: boolean): boolean {
  return requiresReauth || score <= 0.3;
}

class DashboardStore {
  private state: StoreState = {
    agents: [],
    mesh: { nodes: [], edges: [] },
    log: [],
    financial: [],
    connection: "connecting",
    health: "nominal",
    flashSignal: 0,
    lastPulse: null,
    lastShock: null,
  };
  private listeners = new Set<() => void>();
  private logSeq = 0;

  subscribe = (fn: () => void): (() => void) => {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  };

  getState = (): StoreState => this.state;

  private set(patch: Partial<StoreState>) {
    this.state = { ...this.state, ...patch };
    this.listeners.forEach((l) => l());
  }

  setConnection(c: ConnectionStatus) {
    if (this.state.connection !== c) this.set({ connection: c });
  }

  setAgents(agents: AgentTrustSnapshot[]) {
    this.set({ agents });
  }

  setMesh(mesh: MeshData) {
    this.set({ mesh });
  }

  setHealth(health: HealthLevel) {
    if (this.state.health !== health) this.set({ health });
  }

  pushFinancial(sample: FinancialSample) {
    const financial = [...this.state.financial, sample];
    if (financial.length > MAX_FINANCIAL_SAMPLES) financial.shift();
    this.set({ financial });
  }

  private pushLog(entry: Omit<LogEntry, "id" | "ts">) {
    const log = [...this.state.log, { ...entry, id: this.logSeq++, ts: nowClock() }];
    if (log.length > MAX_LOG) log.shift();
    this.set({ log });
  }

  private patchAgentFromSignal(agentId: string, score: number, event: TrustEventJson) {
    const idx = this.state.agents.findIndex((a) => a.agent_id === agentId);
    const requiresReauth = event === "ReauthRequired";
    let agents: AgentTrustSnapshot[];
    if (idx >= 0) {
      agents = this.state.agents.slice();
      agents[idx] = {
        ...agents[idx],
        score,
        requires_reauth: requiresReauth || agents[idx].requires_reauth,
      };
    } else {
      agents = [...this.state.agents, { agent_id: agentId, score, requires_reauth: requiresReauth }];
    }
    this.set({ agents });
    if (isCritical(score, requiresReauth)) {
      this.set({ lastShock: { agent: agentId, nonce: Date.now() } });
    }
  }

  private addEdge(source: string, target: string, depth: number) {
    if (source === target) return;
    const nodes = new Set(this.state.mesh.nodes);
    nodes.add(source);
    nodes.add(target);
    const edges = this.state.mesh.edges.filter((e) => !(e.source === source && e.target === target));
    edges.push({ source, target, depth, last_seen: Date.now() / 1000 });
    this.set({
      mesh: { nodes: Array.from(nodes), edges },
      lastPulse: { source, target, nonce: Date.now() },
    });
  }

  /** Route a live SSE event into every slice it touches. */
  ingest(ev: DashboardEvent) {
    switch (ev.type) {
      case "InjectionAlert": {
        const gate = ev.gate ?? "";
        const agent = ev.agent_id;
        if (gate.startsWith("gate_12_0")) {
          this.pushLog({
            kind: "loop",
            tag: "[INTERCEPT]",
            body: `Gate 12.0 (CSCS Loop Detector) stopped ${ev.bytecode} from ${agent}`,
            agent,
            gate,
            bytecode: ev.bytecode,
          });
        } else if (gate.startsWith("gate_0_5")) {
          const cost = ev.estimated_cost;
          const costTxt = cost != null ? ` · est. exposure blocked $${cost.toFixed(2)}` : "";
          this.pushLog({
            kind: "attack",
            tag: "[BLOCKED]",
            body: `Gate 0.5 (Financial Circuit Breaker) blocked ${agent}${costTxt}`,
            agent,
            gate,
            bytecode: ev.bytecode,
            estimatedCost: cost,
          });
          this.set({ flashSignal: this.state.flashSignal + 1 });
        } else {
          this.pushLog({
            kind: "attack",
            tag: "[BLOCKED]",
            body: `${gate || "gate"} intercepted ${ev.bytecode} from ${agent}`,
            agent,
            gate,
            bytecode: ev.bytecode,
          });
          this.set({ flashSignal: this.state.flashSignal + 1 });
        }
        break;
      }
      case "DelegationEdge": {
        this.addEdge(ev.source, ev.target, ev.depth);
        this.pushLog({
          kind: "delegation",
          tag: "[DELEGATE]",
          body: `${ev.source} → ${ev.target} · capability grant · depth ${ev.depth}`,
        });
        break;
      }
      case "TrustSignal": {
        this.patchAgentFromSignal(ev.agent_id, ev.score, ev.event);
        this.pushLog({
          kind: "trust",
          tag: "[TRUST]",
          body: `${ev.agent_id} · score ${ev.score.toFixed(3)} · ${trustEventLabel(ev.event)}`,
          agent: ev.agent_id,
        });
        break;
      }
      case "AuditEntry": {
        this.pushLog({
          kind: "trust",
          tag: "[AUDIT]",
          body: `${ev.source} → ${ev.target} · ${ev.intent_prefix}`,
        });
        break;
      }
    }
  }
}

const StoreContext = createContext<DashboardStore | null>(null);

export function DashboardStoreProvider({ children }: { children: React.ReactNode }) {
  const storeRef = useRef<DashboardStore | null>(null);
  if (storeRef.current === null) storeRef.current = new DashboardStore();
  const store = storeRef.current;

  useEffect(() => {
    let cancelled = false;

    // ── initial REST seed ────────────────────────────────────────────────
    api.agents().then((a) => !cancelled && store.setAgents(a)).catch(() => {});
    api
      .trustMesh()
      .then((r) => !cancelled && store.setMesh({ nodes: r.nodes, edges: r.edges }))
      .catch(() => {});

    // ── one SSE connection ───────────────────────────────────────────────
    // S-7 fix: opening the stream is now async (POST for a one-time ticket, then
    // connect EventSource with it) so the bearer token never lands in the URL.
    // `source` is assigned once the ticket resolves; the cleanup below closes it
    // whether or not the connect has completed yet.
    let source: EventSource | null = null;
    openEventSource()
      .then((es) => {
        if (cancelled) {
          es.close();
          return;
        }
        source = es;
        es.onopen = () => store.setConnection("live");
        es.onerror = () => store.setConnection("offline");
        es.onmessage = (msg) => {
          try {
            store.ingest(JSON.parse(msg.data) as DashboardEvent);
          } catch {
            /* malformed/partial event — ignore rather than crash the feed */
          }
        };
      })
      .catch(() => {
        if (!cancelled) store.setConnection("offline");
      });

    // ── pollers ──────────────────────────────────────────────────────────
    const pollFinancial = () =>
      api
        .financial()
        .then((f) => {
          if (cancelled) return;
          store.pushFinancial({
            t: Date.now(),
            tokens: f.tokens_rejected,
            dollars: f.dollars_saved,
            dollarsPerToken: f.dollars_per_token,
          });
        })
        .catch(() => {});
    pollFinancial();
    const finId = setInterval(pollFinancial, FINANCIAL_POLL_MS);

    const pollHealth = () =>
      api
        .readyz()
        .then((r) => {
          if (cancelled) return;
          const audit = r.audit_health.status;
          let level: HealthLevel = "nominal";
          if (audit === "fatal" || audit === "saturated") level = "critical";
          else if (audit === "degraded" || r.trust_stats.agents_requiring_reauth > 0) level = "degraded";
          store.setHealth(level);
        })
        .catch(() => {});
    pollHealth();
    const healthId = setInterval(pollHealth, HEALTH_POLL_MS);

    const agentsId = setInterval(
      () => api.agents().then((a) => !cancelled && store.setAgents(a)).catch(() => {}),
      AGENTS_REFRESH_MS
    );
    const meshId = setInterval(
      () =>
        api
          .trustMesh()
          .then((r) => !cancelled && store.setMesh({ nodes: r.nodes, edges: r.edges }))
          .catch(() => {}),
      MESH_REFRESH_MS
    );

    return () => {
      cancelled = true;
      if (source) source.close();
      clearInterval(finId);
      clearInterval(healthId);
      clearInterval(agentsId);
      clearInterval(meshId);
    };
  }, [store]);

  return <StoreContext.Provider value={store}>{children}</StoreContext.Provider>;
}

function useStore(): DashboardStore {
  const store = useContext(StoreContext);
  if (!store) throw new Error("useStore must be used within <DashboardStoreProvider>");
  return store;
}

function useSlice<T>(selector: (s: StoreState) => T): T {
  const store = useStore();
  return useSyncExternalStore(
    store.subscribe,
    () => selector(store.getState()),
    () => selector(store.getState())
  );
}

export const useAgents = () => useSlice((s) => s.agents);
export const useTrustMesh = () => useSlice((s) => s.mesh);
export const useTerminalLog = () => useSlice((s) => s.log);
export const useFinancialHistory = () => useSlice((s) => s.financial);
export const useConnectionStatus = () => useSlice((s) => s.connection);
export const useHealth = () => useSlice((s) => s.health);
export const useFlashSignal = () => useSlice((s) => s.flashSignal);
export const useLastPulse = () => useSlice((s) => s.lastPulse);
export const useLastShock = () => useSlice((s) => s.lastShock);
