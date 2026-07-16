import { AgentList } from "@/components/AgentList";

export default function AgentsPage() {
  return (
    <main className="stage">
      <p className="stage-title">Agents · Behavioral Trust</p>
      <div className="panel">
        <AgentList />
      </div>
    </main>
  );
}
