"use client";

import { useState } from "react";
import { api } from "@/lib/api";
import { useFinancialHistory, useTerminalLog, FinancialSample, LogEntry } from "@/lib/store";
import { RoiPanel } from "@/components/RoiPanel";

const fmt = (n: number) => n.toLocaleString("en-US");

function SessionChart({ samples }: { samples: FinancialSample[] }) {
  const W = 600;
  const H = 280;
  const pad = 30;

  if (samples.length < 2) {
    return (
      <p className="empty-state">
        Collecting live samples from /api/financial… the curve fills in as the session runs.
      </p>
    );
  }

  const data = samples.map((s) => s.tokens);
  const max = Math.max(...data) * 1.1 || 1;
  const x = (i: number) => pad + (i / (data.length - 1)) * (W - pad * 2);
  const y = (v: number) => H - pad - (v / max) * (H - pad * 1.8);
  const line = data.map((v, i) => `${i === 0 ? "M" : "L"}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(" ");
  const area = `${line} L ${x(data.length - 1).toFixed(1)} ${H - pad} L ${x(0).toFixed(1)} ${H - pad} Z`;
  const grid = [0, 0.25, 0.5, 0.75, 1].map((f) => {
    const yy = H - pad - f * (H - pad * 1.8);
    return (
      <g key={f}>
        <line x1={pad} y1={yy} x2={W - pad} y2={yy} stroke="oklch(100% 0 0 / 0.05)" />
        <text x={4} y={yy + 3} fill="var(--ink-faint)" fontSize={8} fontFamily="var(--font-jetbrains-mono, monospace)">
          {Math.round((max * f) / 1000)}k
        </text>
      </g>
    );
  });

  return (
    <svg className="fin-chart-svg" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="none">
      <defs>
        <linearGradient id="fg" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor="var(--safe)" stopOpacity="0.28" />
          <stop offset="100%" stopColor="var(--safe)" stopOpacity="0" />
        </linearGradient>
      </defs>
      {grid}
      <path d={area} fill="url(#fg)" />
      <path
        d={line}
        fill="none"
        stroke="var(--safe)"
        strokeWidth={2}
        vectorEffect="non-scaling-stroke"
        style={{ filter: "drop-shadow(0 0 4px var(--safe-glow))" }}
      />
    </svg>
  );
}

function blockedTransactions(log: LogEntry[]): LogEntry[] {
  // Any live gate rejection that carries a gate/bytecode counts as a "blocked
  // transaction". Newest first.
  return log
    .filter((l) => (l.kind === "attack" || l.kind === "loop") && l.gate)
    .slice()
    .reverse();
}

export function FinancialView() {
  const samples = useFinancialHistory();
  const log = useTerminalLog();
  const latest = samples[samples.length - 1];
  const txns = blockedTransactions(log);

  const [reloadState, setReloadState] = useState<"idle" | "loading" | "done" | "error">("idle");
  const onReload = async () => {
    setReloadState("loading");
    try {
      await api.reloadConfig();
      setReloadState("done");
      setTimeout(() => setReloadState("idle"), 1800);
    } catch {
      setReloadState("error");
      setTimeout(() => setReloadState("idle"), 2400);
    }
  };

  const totalTokens = latest?.tokens ?? 0;
  const totalDollars = latest?.dollars ?? 0;

  return (
    <div className="fin-grid">
      <div className="panel fin-chart">
        <div className="panel-title" style={{ marginBottom: 4 }}>
          Tokens Rejected · This Session
        </div>
        <div className="panel-meta mono" style={{ marginBottom: 12 }}>
          {fmt(totalTokens)} tokens rejected · ${totalDollars.toFixed(2)} est. exposure prevented
        </div>
        <SessionChart samples={samples} />
      </div>

      <div className="panel">
        <div className="panel-head">
          <span className="panel-title">Financial Circuit Breaker · Gate 0.5</span>
        </div>
        <RoiPanel compact />
        <div className="fin-actions">
          <button className="btn" onClick={onReload} disabled={reloadState === "loading"}>
            <span
              className="ic"
              style={{
                background: reloadState === "done" ? "var(--safe)" : reloadState === "error" ? "var(--crit)" : "var(--info)",
                boxShadow: `0 0 8px ${reloadState === "done" ? "var(--safe-glow)" : reloadState === "error" ? "var(--crit-glow)" : "var(--info-glow)"}`,
              }}
            />
            {reloadState === "loading"
              ? "Reloading…"
              : reloadState === "done"
                ? "Config reloaded"
                : reloadState === "error"
                  ? "Reload failed"
                  : "Reload Config"}
          </button>
        </div>
      </div>

      <div className="panel" style={{ gridColumn: "1 / -1" }}>
        <div className="panel-head">
          <span className="panel-title">Blocked Transactions</span>
          <span className="panel-meta">{txns.length ? `${txns.length} this session` : "none yet"}</span>
        </div>
        <div style={{ overflowX: "auto" }}>
          <table className="tbl">
            <thead>
              <tr>
                <th className="no-sort">Time</th>
                <th className="no-sort">Gate</th>
                <th className="no-sort">Agent</th>
                <th className="no-sort">Bytecode</th>
                <th className="no-sort" style={{ textAlign: "right" }}>
                  Est. Cost Blocked
                </th>
              </tr>
            </thead>
            <tbody>
              {txns.length === 0 ? (
                <tr>
                  <td colSpan={5} style={{ textAlign: "center", color: "var(--ink-faint)", padding: 34 }}>
                    No transactions blocked this session yet — the ledger fills as gates reject live traffic.
                  </td>
                </tr>
              ) : (
                txns.map((t) => (
                  <tr key={t.id}>
                    <td className="mono" style={{ color: "var(--ink-faint)", fontSize: "0.76rem" }}>
                      {t.ts}
                    </td>
                    <td className="mono" style={{ fontSize: "0.76rem" }}>
                      {t.gate}
                    </td>
                    <td style={{ fontFamily: "var(--font-jetbrains-mono, monospace)", fontSize: "0.76rem" }}>
                      {t.agent ?? "—"}
                    </td>
                    <td style={{ color: "var(--ink-dim)" }}>{t.bytecode ?? "—"}</td>
                    <td style={{ textAlign: "right" }}>
                      {t.estimatedCost != null ? (
                        <span className="tx-amount">${t.estimatedCost.toFixed(2)}</span>
                      ) : (
                        <span style={{ color: "var(--ink-faint)" }}>—</span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
