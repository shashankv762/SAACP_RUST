import { AgentList } from "@/components/AgentList";

export default function AgentsPage() {
  return (
    <main className="page">
      <p className="page-title">Agents</p>
      <div className="card">
        <AgentList />
      </div>
    </main>
  );
}
