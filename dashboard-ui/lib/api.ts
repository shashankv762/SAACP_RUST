// api.ts — typed client for the SAACP Command Center backend (see
// ../../src/command_center.rs). All endpoints except /healthz require the shared
// dashboard bearer token, presented as its hex encoding (see command_center.rs's
// CommandCenterState::dashboard_token_hex doc comment for why hex, not raw bytes).

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE?.replace(/\/$/, "") || "http://127.0.0.1:9090";

export const DASHBOARD_TOKEN = process.env.NEXT_PUBLIC_DASHBOARD_TOKEN || "";

// NOTE (v1 scope, matches command_center.rs's own honesty convention): this token is
// baked into the client bundle via NEXT_PUBLIC_*, same tradeoff the backend already makes
// by accepting the token as an SSE `?token=` query parameter. Fine for a local/operator-
// only dashboard; not meant for a multi-tenant public deployment as-is.

export interface AgentTrustSnapshot {
  agent_id: string;
  score: number;
  requires_reauth: boolean;
}

export interface TrustMeshEdge {
  source: string;
  target: string;
  depth: number;
  last_seen: number;
}

export interface TrustMeshResponse {
  nodes: string[];
  edges: TrustMeshEdge[];
}

export interface SecurityAlert {
  timestamp: number;
  agent_id: string;
  gate: string;
  bytecode: string;
  /** Real claimed dollar/token cost blocked — present only on Gate 0.5
   * (gate_0_5_financial) rejections; `null`/absent for every other gate.
   * See command_center.rs / telemetry::report_financial_rejection. */
  estimated_cost?: number | null;
}

export interface FinancialResponse {
  tokens_rejected: number;
  dollars_per_token: number;
  dollars_saved: number;
}

// Mirrors command_center.rs's ReadyzResponse / its nested structs.
export interface ReadyzResponse {
  audit_health: {
    status: "healthy" | "degraded" | "saturated" | "fatal";
    wal_queue_depth: number;
    wal_dropped_total: number;
    wal_write_failures_total: number;
  };
  connections: { tcp_active: number; ws_active: number };
  trust_stats: { agents_tracked: number; agents_requiring_reauth: number };
  gate_latencies: { gate: string; avg_seconds: number; count: number }[];
}

export interface ReloadedConfig {
  dollars_per_token: number;
  max_recent_alerts: number;
  max_agents: number;
}

export type TrustEventJson =
  | { Penalized: string }
  | { Rewarded: string }
  | "Downgraded"
  | "ReauthRequired"
  | "Recovered";

export type DashboardEvent =
  | ({ type: "InjectionAlert" } & SecurityAlert)
  | { type: "DelegationEdge"; source: string; target: string; depth: number }
  | { type: "TrustSignal"; agent_id: string; score: number; event: TrustEventJson }
  | { type: "AuditEntry"; source: string; target: string; intent_prefix: string };

function authHeaders(): HeadersInit {
  return DASHBOARD_TOKEN ? { Authorization: `Bearer ${DASHBOARD_TOKEN}` } : {};
}

async function getJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, { headers: authHeaders(), cache: "no-store" });
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

async function postJson<T>(path: string): Promise<T> {
  const res = await fetch(`${API_BASE}${path}`, {
    method: "POST",
    headers: authHeaders(),
    cache: "no-store",
  });
  if (!res.ok) {
    throw new Error(`${path} -> HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export const api = {
  healthz: () => getJson<{ status: string }>("/healthz"),
  agents: () => getJson<AgentTrustSnapshot[]>("/api/agents"),
  trustMesh: () => getJson<TrustMeshResponse>("/api/trust-mesh"),
  alerts: (limit = 200) => getJson<SecurityAlert[]>(`/api/alerts?limit=${limit}`),
  financial: () => getJson<FinancialResponse>("/api/financial"),
  readyz: () => getJson<ReadyzResponse>("/api/readyz"),
  reloadConfig: () => postJson<ReloadedConfig>("/api/config/reload"),
};

/** SSE endpoint URL, token passed as a query param since EventSource can't set headers. */
export function eventsUrl(): string {
  const url = new URL(`${API_BASE}/events`);
  if (DASHBOARD_TOKEN) url.searchParams.set("token", DASHBOARD_TOKEN);
  return url.toString();
}
