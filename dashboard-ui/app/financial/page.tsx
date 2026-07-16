import { FinancialView } from "@/components/FinancialView";

export default function FinancialPage() {
  return (
    <main className="stage">
      <p className="stage-title">Financial Circuit Breaker</p>
      <p className="stage-note">
        &quot;Estimated exposure prevented&quot; is the claimed token cost the Gate 0.5 Financial
        Circuit Breaker rejected — not observed actual spend avoided, which this system has no
        way to measure. History is accumulated live this session (there is no server-side 24h
        store).
      </p>
      <FinancialView />
    </main>
  );
}
