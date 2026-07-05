import { FinancialSummary } from "@/components/FinancialSummary";
import { AgentList } from "@/components/AgentList";
import { AlertFeed } from "@/components/AlertFeed";
import Link from "next/link";

export default function OverviewPage() {
  return (
    <main className="page">
      <p className="page-title">
        <span className="live-dot" />
        Live Overview
      </p>

      <FinancialSummary />

      <div style={{ display: "grid", gridTemplateColumns: "1.1fr 1fr", gap: 16, marginTop: 8 }}>
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 12 }}>
            <p className="page-title" style={{ margin: 0 }}>Agent Trust</p>
            <Link href="/agents" className="nav-link" style={{ fontSize: 12 }}>View all →</Link>
          </div>
          <AgentList />
        </div>
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", marginBottom: 12 }}>
            <p className="page-title" style={{ margin: 0 }}>Security Alerts</p>
            <Link href="/alerts" className="nav-link" style={{ fontSize: 12 }}>View all →</Link>
          </div>
          <AlertFeed />
        </div>
      </div>
    </main>
  );
}
