"use client";

import { useMemo, useState } from "react";
import { useAgents } from "@/lib/store";
import { trustStatus, trustStatusLabel } from "@/lib/trust";

type SortKey = "id" | "status" | "score";

const STATUS_COLOR: Record<string, string> = {
  good: "var(--safe)",
  warning: "var(--warn)",
  serious: "oklch(72% 0.18 45)",
  critical: "var(--crit)",
};

interface Props {
  compact?: boolean;
}

export function AgentList({ compact = false }: Props) {
  const agents = useAgents();
  const [query, setQuery] = useState("");
  const [sortKey, setSortKey] = useState<SortKey>("score");
  const [sortDir, setSortDir] = useState<number>(-1);

  const rows = useMemo(() => {
    const q = query.toLowerCase();
    const filtered = agents.filter((a) => a.agent_id.toLowerCase().includes(q));
    const sorted = filtered.slice().sort((a, b) => {
      let av: number | string;
      let bv: number | string;
      if (sortKey === "id") {
        av = a.agent_id.toLowerCase();
        bv = b.agent_id.toLowerCase();
      } else {
        av = a.score;
        bv = b.score;
      }
      return av < bv ? -1 * sortDir : av > bv ? 1 * sortDir : 0;
    });
    return compact ? sorted.slice(0, 8) : sorted;
  }, [agents, query, sortKey, sortDir, compact]);

  const toggleSort = (key: SortKey) => {
    if (sortKey === key) setSortDir((d) => d * -1);
    else {
      setSortKey(key);
      setSortDir(key === "score" ? -1 : 1);
    }
  };

  const arrow = (key: SortKey) => (sortKey === key ? (sortDir < 0 ? " ▾" : " ▴") : "");

  if (agents.length === 0) {
    return (
      <p className="empty-state">
        No agents tracked yet — behavioral trust scoring begins once traffic flows.
      </p>
    );
  }

  return (
    <>
      {!compact && (
        <div className="table-tools">
          <input
            className="search"
            placeholder="Search agents by ID…"
            autoComplete="off"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
          />
          <span className="panel-meta">
            {rows.length} of {agents.length} agents
          </span>
        </div>
      )}
      <div style={{ overflowX: "auto" }}>
        <table className="tbl">
          <thead>
            <tr>
              <th onClick={() => toggleSort("id")}>Agent ID{arrow("id")}</th>
              <th className="no-sort">Reauth</th>
              <th onClick={() => toggleSort("status")}>Status{arrow("status")}</th>
              <th onClick={() => toggleSort("score")}>Trust Score{arrow("score")}</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((a) => {
              const status = trustStatus(a.score, a.requires_reauth);
              const color = STATUS_COLOR[status];
              return (
                <tr key={a.agent_id}>
                  <td>
                    <span className="agent-id">
                      <span className="d" style={{ background: color, boxShadow: `0 0 7px ${color}` }} />
                      {a.agent_id}
                    </span>
                  </td>
                  <td
                    style={{
                      fontFamily: "var(--font-jetbrains-mono, monospace)",
                      fontSize: "0.76rem",
                      color: a.requires_reauth ? "var(--crit)" : "var(--ink-faint)",
                    }}
                  >
                    {a.requires_reauth ? "REQUIRED" : "—"}
                  </td>
                  <td>
                    <span className={`badge ${status}`}>{trustStatusLabel(status)}</span>
                  </td>
                  <td>
                    <span className="score-cell">
                      {a.score.toFixed(3)}
                      <span className="score-bar">
                        <i style={{ width: `${Math.max(0, Math.min(1, a.score)) * 100}%`, background: color }} />
                      </span>
                    </span>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </>
  );
}
