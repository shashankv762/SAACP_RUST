"use client";

import { useEffect, useState } from "react";
import { api, SecurityAlert } from "@/lib/api";
import { useDashboardEvents } from "@/lib/useDashboardEvents";

const MAX_SHOWN = 200;

function formatTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString();
}

export function AlertFeed() {
  const [alerts, setAlerts] = useState<SecurityAlert[] | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.alerts(MAX_SHOWN).then(setAlerts).catch((e) => setError(String(e)));
  }, []);

  useDashboardEvents((event) => {
    if (event.type === "InjectionAlert") {
      setAlerts((prev) => [event, ...(prev ?? [])].slice(0, MAX_SHOWN));
    }
  });

  if (error) return <p className="empty-state">Failed to load alerts: {error}</p>;
  if (!alerts) return <p className="empty-state">Loading…</p>;
  if (alerts.length === 0) return <p className="empty-state">No security alerts yet — this list fills as gates reject traffic.</p>;

  return (
    <ul style={{ listStyle: "none", margin: 0, padding: 0 }}>
      {alerts.map((a, i) => (
        <li
          key={`${a.timestamp}-${i}`}
          style={{
            display: "flex",
            gap: 16,
            alignItems: "flex-start",
            padding: "12px 0",
            borderBottom: i === alerts.length - 1 ? "none" : "1px solid var(--gridline)",
          }}
        >
          <span className="badge badge-critical tabular" style={{ flexShrink: 0 }}>
            {a.gate}
          </span>
          <div style={{ flex: 1, minWidth: 0 }}>
            {/* Plain text node only — never dangerouslySetInnerHTML. `message` and
                `bytecode` can carry attacker-influenced content (this is exactly what
                Gate 4.0 flagged), so React's default escaping is the mitigation. */}
            <div style={{ fontSize: 13, color: "var(--text-primary)" }}>{a.message}</div>
            <div style={{ fontSize: 12, color: "var(--text-muted)", marginTop: 2 }}>
              {a.agent_id} · {a.bytecode}
            </div>
          </div>
          <span className="tabular" style={{ fontSize: 12, color: "var(--text-muted)", flexShrink: 0 }}>
            {formatTime(a.timestamp)}
          </span>
        </li>
      ))}
    </ul>
  );
}
