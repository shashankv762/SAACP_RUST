import { Terminal } from "@/components/Terminal";

export default function AlertsPage() {
  return (
    <main className="stage">
      <p className="stage-title">Security Alerts · Blocked Gate Activity</p>
      <p className="stage-note">
        Live feed of gate rejections (Gate 4.0 prompt-injection, Gate 12.0 CSCS loop
        detection, Gate 0.5 financial circuit breaker, and more) pushed over Server-Sent
        Events from the audit log.
      </p>
      <div className="panel" id="term-panel">
        <div className="panel-head">
          <span className="panel-title">
            <span className="dot" style={{ background: "var(--crit)", boxShadow: "0 0 8px var(--crit-glow)" }} />
            Attack Feed
          </span>
          <span className="panel-meta">streaming</span>
        </div>
        <Terminal attacksOnly />
      </div>
    </main>
  );
}
