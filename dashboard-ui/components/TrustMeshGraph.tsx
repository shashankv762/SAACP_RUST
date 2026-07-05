"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import dynamic from "next/dynamic";
import { api, TrustMeshEdge } from "@/lib/api";
import { useDashboardEvents } from "@/lib/useDashboardEvents";

// Canvas-based force-directed graph — must be client-only (no SSR), matching this
// package's own guidance (it touches `window`/canvas at import time).
const ForceGraph2D = dynamic(() => import("react-force-graph-2d"), { ssr: false });

interface GraphNode {
  id: string;
}
interface GraphLink {
  source: string;
  target: string;
  depth: number;
}
interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

function toGraphData(nodes: string[], edges: TrustMeshEdge[]): GraphData {
  return {
    nodes: nodes.map((id) => ({ id })),
    links: edges.map((e) => ({ source: e.source, target: e.target, depth: e.depth })),
  };
}

export function TrustMeshGraph() {
  const [graph, setGraph] = useState<GraphData | null>(null);
  const [error, setError] = useState<string | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(800);

  useEffect(() => {
    api.trustMesh().then((r) => setGraph(toGraphData(r.nodes, r.edges))).catch((e) => setError(String(e)));
  }, []);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const observer = new ResizeObserver(([entry]) => setWidth(entry.contentRect.width));
    observer.observe(el);
    return () => observer.disconnect();
  }, []);

  // Live edges: merge in place (dedupe by source->target), same shape as the
  // server's own TrustMeshStore dedup behavior.
  useDashboardEvents((event) => {
    if (event.type !== "DelegationEdge") return;
    setGraph((prev) => {
      const nodes = new Map((prev?.nodes ?? []).map((n) => [n.id, n]));
      nodes.set(event.source, { id: event.source });
      nodes.set(event.target, { id: event.target });
      const links = (prev?.links ?? []).filter(
        (l) => !(l.source === event.source && l.target === event.target)
      );
      links.push({ source: event.source, target: event.target, depth: event.depth });
      return { nodes: Array.from(nodes.values()), links };
    });
  });

  if (error) return <p className="empty-state">Failed to load trust mesh: {error}</p>;
  if (!graph) return <p className="empty-state">Loading…</p>;
  if (graph.nodes.length === 0) {
    return <p className="empty-state">No delegation edges recorded yet — the mesh populates as agents delegate capability to one another.</p>;
  }

  return (
    <div ref={containerRef} style={{ width: "100%" }}>
      <ForceGraph2D
        graphData={graph as any}
        width={width}
        height={520}
        nodeId="id"
        nodeLabel="id"
        nodeColor={() => "#2a78d6" /* categorical series-1 (blue) — canvas can't read CSS custom properties directly */}
        nodeRelSize={5}
        linkColor={() => "rgba(137,135,129,0.55)"}
        linkDirectionalArrowLength={5}
        linkDirectionalArrowRelPos={1}
        linkWidth={1.2}
        cooldownTicks={100}
      />
    </div>
  );
}
