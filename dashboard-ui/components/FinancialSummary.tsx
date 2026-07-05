"use client";

import { useEffect, useState } from "react";
import { api, FinancialResponse } from "@/lib/api";
import { StatTile } from "./StatTile";

const POLL_INTERVAL_MS = 10_000;

const currencyFormatter = new Intl.NumberFormat("en-US", {
  style: "currency",
  currency: "USD",
  minimumFractionDigits: 2,
});

export function FinancialSummary() {
  const [data, setData] = useState<FinancialResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    const fetchOnce = () => api.financial().then((d) => !cancelled && setData(d)).catch((e) => !cancelled && setError(String(e)));
    fetchOnce();
    const id = setInterval(fetchOnce, POLL_INTERVAL_MS);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, []);

  if (error) return <p className="empty-state">Failed to load financial data: {error}</p>;
  if (!data) return <p className="empty-state">Loading…</p>;

  return (
    <div>
      <div className="kpi-row">
        <StatTile label="Tokens Blocked" value={data.tokens_rejected.toLocaleString()} sub="Sum of estimated_cost across every Gate 0.5 rejection" />
        <StatTile
          label="Estimated Exposure Prevented"
          value={currencyFormatter.format(data.dollars_saved)}
          sub={`at ${data.dollars_per_token} $/token (operator-configured)`}
        />
        <StatTile label="$ / Token" value={currencyFormatter.format(data.dollars_per_token)} />
      </div>
      <p className="empty-state" style={{ textAlign: "left", padding: 0, marginTop: 4 }}>
        This measures claimed cost the Financial Circuit Breaker prevented from being spent
        — not observed actual spend avoided, which this system has no way to measure.
      </p>
    </div>
  );
}
