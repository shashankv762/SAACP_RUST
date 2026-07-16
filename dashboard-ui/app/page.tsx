import { TrustMeshGraph } from "@/components/TrustMeshGraph";
import { Terminal } from "@/components/Terminal";
import { RoiPanel } from "@/components/RoiPanel";

export default function OverviewPage() {
  return (
    <main className="stage">
      <div className="grid-overview">
        <div className="panel" id="overview-graph">
          <div className="panel-head">
            <span className="panel-title">
              <span className="dot" />
              Trust Mesh
            </span>
          </div>
          <TrustMeshGraph compact />
        </div>

        <div className="panel" id="term-panel">
          <div className="panel-head">
            <span className="panel-title">
              <span className="dot" style={{ background: "var(--crit)", boxShadow: "0 0 8px var(--crit-glow)" }} />
              Live Attack Feed
            </span>
            <span className="panel-meta">streaming</span>
          </div>
          <Terminal />
        </div>

        <RoiPanel />
      </div>
    </main>
  );
}
