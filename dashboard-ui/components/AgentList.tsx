"use client";

import { useEffect, useState } from "react";
import { api, AgentTrustSnapshot } from "@/lib/api";
import { useDashboardEvents } from "@/lib/useDashboardEvents";
import { trustStatus, trustStatusLabel } from "@/lib/trust";

export function AgentList() {
  const [agents, setAgents] = useState<AgentTrustSnapshot[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.agents().then(setAgents).catch((e) => setError(String(e)));
  }, []);

  // Live updates: a TrustSignal event means this agent's score just changed.
  // Re-fetch the snapshot rather than hand-merging partial state client-side —
  // the endpoint is cheap and this keeps sort order/requires_reauth correct.
  useDashboardEvents((event) => {
    if (event.type === "TrustSignal") {
      api.agents().then(setAgents).catch(() => {});
    }
  });

  if (error) return <p className="empty-state">Failed to load agents: {error}</p>;
  if (!agents) return <p className="empty-state">Loading…</p>;
  if (agents.length === 0) return <p className="empty-state">No agents tracked yet — trust scoring begins once traffic flows.</p>;

  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Agent</th>
          <th>Trust Score</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        {agents.map((a) => {
          const status = trustStatus(a.score, a.requires_reauth);
          return (
            <tr key={a.agent_id}>
              <td>{a.agent_id}</td>
              <td className="tabular">{a.score.toFixed(3)}</td>
              <td>
                <span className={`badge badge-${status}`}>{trustStatusLabel(status)}</span>
              </td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
}
