import { TrustMeshGraph } from "@/components/TrustMeshGraph";

export default function MeshPage() {
  return (
    <main className="page">
      <p className="page-title">Trust Mesh</p>
      <p style={{ fontSize: 13, color: "var(--text-secondary)", marginTop: -8, marginBottom: 16 }}>
        Capability-grant edges — who has delegated what to whom. Not a full multi-hop
        lineage (see the backend&apos;s v1 scope notes); nodes are agent identities, edges are
        delegation events observed on the audit log.
      </p>
      <div className="card">
        <TrustMeshGraph />
      </div>
    </main>
  );
}
