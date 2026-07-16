import { TrustMeshGraph } from "@/components/TrustMeshGraph";

export default function MeshPage() {
  return (
    <main className="stage">
      <p className="stage-title">Trust Mesh · Operator View</p>
      <p className="stage-note">
        Capability-grant edges — who has delegated what to whom, observed on the audit log.
        Not a full multi-hop lineage (see the backend&apos;s v1 scope notes); nodes are agent
        identities colored by live behavioral trust score.
      </p>
      <TrustMeshGraph showControls />
    </main>
  );
}
