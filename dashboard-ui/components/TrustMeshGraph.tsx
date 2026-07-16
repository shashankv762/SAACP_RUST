"use client";

import { useEffect, useRef, useState } from "react";
import * as d3 from "d3";
import { AgentTrustSnapshot } from "@/lib/api";
import { useAgents, useTrustMesh, useLastPulse, useLastShock } from "@/lib/store";

type SimNode = d3.SimulationNodeDatum & {
  id: string;
  score: number;
  known: boolean;
  requiresReauth: boolean;
};
type SimLink = d3.SimulationLinkDatum<SimNode> & { key: string; depth: number };

const SAFE = "var(--safe)";
const WARN = "var(--warn)";
const CRIT = "var(--crit)";

function scoreColor(n: SimNode): string {
  if (!n.known) return "var(--info)";
  if (n.requiresReauth || n.score <= 0.3) return CRIT;
  if (n.score < 0.8) return WARN;
  return SAFE;
}
function scoreGlow(n: SimNode): string {
  if (!n.known) return "var(--info-glow)";
  if (n.requiresReauth || n.score <= 0.3) return "var(--crit-glow)";
  if (n.score < 0.8) return "var(--warn-glow)";
  return "var(--safe-glow)";
}
function statusLabel(n: SimNode): string {
  if (!n.known) return "OBSERVED";
  if (n.requiresReauth || n.score <= 0.3) return "QUARANTINED";
  if (n.score < 0.8) return "DEGRADED";
  return "AUTHORIZED";
}
function statusClass(n: SimNode): string {
  if (!n.known) return "authorized";
  if (n.requiresReauth || n.score <= 0.3) return "quarantined";
  if (n.score < 0.8) return "degraded";
  return "authorized";
}
const idOf = (x: string | SimNode): string => (typeof x === "object" ? x.id : x);

interface Props {
  compact?: boolean;
  showControls?: boolean;
}

export function TrustMeshGraph({ compact = false, showControls = false }: Props) {
  const mesh = useTrustMesh();
  const agents = useAgents();
  const lastPulse = useLastPulse();
  const lastShock = useLastShock();

  const containerRef = useRef<HTMLDivElement>(null);
  const apiRef = useRef<{
    sync: (mesh: { nodes: string[]; edges: { source: string; target: string; depth: number }[] }, agents: AgentTrustSnapshot[]) => void;
    pulse: (s: string, t: string, color?: string) => void;
    shockwave: (id: string) => void;
    setForces: (f: { charge?: number; link?: number; friction?: number }) => void;
    resize: () => void;
    findNode: (id: string) => SimNode | undefined;
    destroy: () => void;
  } | null>(null);

  const [charge, setCharge] = useState(-260);
  const [link, setLink] = useState(90);
  const [friction, setFriction] = useState(0.4);
  const [counts, setCounts] = useState({ nodes: 0, edges: 0 });

  // ── build the d3 machinery exactly once ─────────────────────────────────
  useEffect(() => {
    const container = containerRef.current;
    if (!container) return;
    const tip = document.getElementById("node-tip");
    const width = () => container.clientWidth || 800;
    const height = () => container.clientHeight || 480;

    const svg = d3.select(container).append("svg");
    const g = svg.append("g");
    const gEdges = g.append("g");
    const gPulse = g.append("g");
    const gNodes = g.append("g");
    let focusId: string | null = null;

    const zoom = d3
      .zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.4, 3])
      .on("zoom", (e) => g.attr("transform", e.transform.toString()));
    svg.call(zoom as any).on("dblclick.zoom", null);

    let nodes: SimNode[] = [];
    let links: SimLink[] = [];

    const sim = d3
      .forceSimulation<SimNode>()
      .force("link", d3.forceLink<SimNode, SimLink>().id((d) => d.id).distance(90).strength(0.4))
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(width() / 2, height() / 2))
      .force("collide", d3.forceCollide(26))
      .velocityDecay(0.4);

    function dimNode(id: string): boolean {
      if (!focusId) return false;
      if (id === focusId) return false;
      return !links.some(
        (l) =>
          (idOf(l.source as any) === focusId && idOf(l.target as any) === id) ||
          (idOf(l.target as any) === focusId && idOf(l.source as any) === id)
      );
    }
    function dimEdge(s: string | SimNode, t: string | SimNode): boolean {
      if (!focusId) return false;
      return idOf(s) !== focusId && idOf(t) !== focusId;
    }

    function draw() {
      const linkSel = gEdges.selectAll<SVGLineElement, SimLink>("line").data(links, (d) => d.key);
      linkSel.exit().remove();
      linkSel
        .enter()
        .append("line")
        .attr("stroke-width", 1.2)
        .merge(linkSel)
        .attr("stroke", (d) => {
          const target = nodes.find((n) => n.id === idOf(d.target as any));
          return target && (target.requiresReauth || target.score <= 0.3) ? CRIT : "var(--info)";
        })
        .attr("stroke-opacity", (d) => (dimEdge(d.source as any, d.target as any) ? 0.08 : 0.35));

      const nodeSel = gNodes.selectAll<SVGGElement, SimNode>("g.node").data(nodes, (d) => d.id);
      nodeSel.exit().remove();
      const enter = nodeSel
        .enter()
        .append("g")
        .attr("class", "node")
        .style("cursor", "pointer")
        .call(
          d3
            .drag<SVGGElement, SimNode>()
            .on("start", (e, d) => {
              if (!e.active) sim.alphaTarget(0.3).restart();
              d.fx = d.x;
              d.fy = d.y;
            })
            .on("drag", (e, d) => {
              d.fx = e.x;
              d.fy = e.y;
            })
            .on("end", (e, d) => {
              if (!e.active) sim.alphaTarget(0);
              d.fx = null;
              d.fy = null;
            }) as any
        )
        .on("mousemove", (e: MouseEvent, d) => showTip(e, d))
        .on("mouseleave", () => tip?.classList.remove("show"))
        .on("dblclick", (_e, d) => {
          focusId = focusId === d.id ? null : d.id;
          draw();
        });
      enter.append("circle").attr("class", "halo");
      enter.append("circle").attr("class", "core");
      enter
        .append("text")
        .attr("class", "lbl")
        .attr("text-anchor", "middle")
        .attr("dy", 26)
        .attr("fill", "var(--ink-dim)")
        .attr("font-size", "9.5px")
        .attr("font-family", "var(--font-jetbrains-mono, monospace)")
        .style("pointer-events", "none");

      const all = enter.merge(nodeSel);
      all
        .select<SVGCircleElement>("circle.core")
        .attr("r", (d) => (d.score >= 0.97 && d.known ? 13 : 10))
        .attr("fill", (d) => scoreColor(d))
        .attr("stroke", "oklch(14% 0.012 264)")
        .attr("stroke-width", 2)
        .style("filter", (d) => `drop-shadow(0 0 ${d.known && (d.requiresReauth || d.score <= 0.3) ? 12 : 7}px ${scoreGlow(d)})`)
        .attr("opacity", (d) => (dimNode(d.id) ? 0.25 : 1));
      all
        .select<SVGCircleElement>("circle.halo")
        .attr("r", (d) => (d.known && (d.requiresReauth || d.score <= 0.3) ? 22 : 0))
        .attr("fill", "none")
        .attr("stroke", (d) => scoreColor(d))
        .attr("stroke-width", 1.5)
        .attr("opacity", (d) => (d.known && (d.requiresReauth || d.score <= 0.3) ? 0.6 : 0))
        .attr("class", (d) => (d.known && (d.requiresReauth || d.score <= 0.3) ? "halo pulsing" : "halo"));
      all
        .select<SVGTextElement>("text.lbl")
        .text((d) => d.id)
        .attr("opacity", (d) => (dimNode(d.id) ? 0.2 : 0.85));

      setCounts({ nodes: nodes.length, edges: links.length });
    }

    function showTip(e: MouseEvent, d: SimNode) {
      if (!tip) return;
      tip.innerHTML =
        `<div class="nt-id">${d.id}</div>` +
        `<div class="nt-row">Status <span class="badge ${statusClass(d)}">${statusLabel(d)}</span></div>` +
        `<div class="nt-row">Trust Score <b>${d.known ? d.score.toFixed(3) : "—"}</b></div>`;
      tip.style.left = Math.min(e.clientX + 16, window.innerWidth - 220) + "px";
      tip.style.top = e.clientY + 14 + "px";
      tip.classList.add("show");
    }

    sim.on("tick", () => {
      gEdges
        .selectAll<SVGLineElement, SimLink>("line")
        .attr("x1", (d) => (d.source as SimNode).x ?? 0)
        .attr("y1", (d) => (d.source as SimNode).y ?? 0)
        .attr("x2", (d) => (d.target as SimNode).x ?? 0)
        .attr("y2", (d) => (d.target as SimNode).y ?? 0);
      gNodes.selectAll<SVGGElement, SimNode>("g.node").attr("transform", (d) => `translate(${d.x},${d.y})`);
    });

    function findNode(id: string): SimNode | undefined {
      return nodes.find((n) => n.id === id);
    }

    apiRef.current = {
      sync(meshData, agentList) {
        const scoreById = new Map(agentList.map((a) => [a.agent_id, a]));
        const prev = new Map(nodes.map((n) => [n.id, n]));
        nodes = meshData.nodes.map((id) => {
          const a = scoreById.get(id);
          const base = prev.get(id) || ({ id } as SimNode);
          return Object.assign(base, {
            id,
            score: a ? a.score : base.score ?? 1,
            known: !!a,
            requiresReauth: a ? a.requires_reauth : false,
          });
        });
        const nodeById = new Map(nodes.map((n) => [n.id, n]));
        links = meshData.edges
          .filter((e) => nodeById.has(e.source) && nodeById.has(e.target))
          .map((e) => ({
            source: e.source,
            target: e.target,
            depth: e.depth,
            key: e.source + "|" + e.target,
          })) as unknown as SimLink[];
        sim.nodes(nodes);
        (sim.force("link") as d3.ForceLink<SimNode, SimLink>).links(links);
        sim.alpha(0.5).restart();
        draw();
      },
      pulse(sourceId, targetId, color) {
        const s = findNode(sourceId);
        const t = findNode(targetId);
        if (!s || !t) return;
        const p = gPulse
          .append("circle")
          .attr("r", 3.5)
          .attr("fill", color || "var(--info)")
          .style("filter", `drop-shadow(0 0 6px ${color || "var(--info-glow)"})`);
        p.attr("cx", s.x ?? 0)
          .attr("cy", s.y ?? 0)
          .transition()
          .duration(750)
          .ease(d3.easeCubicInOut)
          .attr("cx", t.x ?? 0)
          .attr("cy", t.y ?? 0)
          .transition()
          .duration(120)
          .attr("r", 7)
          .style("opacity", 0)
          .remove();
      },
      shockwave(id) {
        const n = findNode(id);
        if (!n) return;
        gPulse
          .append("circle")
          .attr("cx", n.x ?? 0)
          .attr("cy", n.y ?? 0)
          .attr("r", 8)
          .attr("fill", "none")
          .attr("stroke", CRIT)
          .attr("stroke-width", 3)
          .transition()
          .duration(900)
          .ease(d3.easeCubicOut)
          .attr("r", 70)
          .attr("stroke-width", 0.5)
          .style("opacity", 0)
          .remove();
      },
      setForces(f) {
        if (f.charge != null) (sim.force("charge") as d3.ForceManyBody<SimNode>).strength(f.charge);
        if (f.link != null) (sim.force("link") as d3.ForceLink<SimNode, SimLink>).distance(f.link);
        if (f.friction != null) sim.velocityDecay(f.friction);
        sim.alpha(0.5).restart();
      },
      resize() {
        sim.force("center", d3.forceCenter(width() / 2, height() / 2));
        sim.alpha(0.3).restart();
      },
      findNode,
      destroy() {
        sim.stop();
        d3.select(container).select("svg").remove();
      },
    };

    // heartbeat for quarantined-halo pulse (SVG attr can't be CSS-animated easily)
    const halo = setInterval(() => {
      container.querySelectorAll<SVGCircleElement>("circle.halo.pulsing").forEach((el) => {
        const cur = parseFloat(el.getAttribute("opacity") || "0.6");
        el.setAttribute("opacity", cur > 0.35 ? "0.25" : "0.6");
      });
    }, 700);

    const onResize = () => apiRef.current?.resize();
    window.addEventListener("resize", onResize);

    return () => {
      clearInterval(halo);
      window.removeEventListener("resize", onResize);
      apiRef.current?.destroy();
      apiRef.current = null;
    };
  }, []);

  // ── keep data in sync ───────────────────────────────────────────────────
  useEffect(() => {
    apiRef.current?.sync(mesh, agents);
  }, [mesh, agents]);

  // ── live animations ─────────────────────────────────────────────────────
  useEffect(() => {
    if (lastPulse) apiRef.current?.pulse(lastPulse.source, lastPulse.target);
  }, [lastPulse]);
  useEffect(() => {
    if (lastShock) {
      apiRef.current?.shockwave(lastShock.agent);
    }
  }, [lastShock]);

  // ── controls ────────────────────────────────────────────────────────────
  useEffect(() => {
    apiRef.current?.setForces({ charge, link, friction });
  }, [charge, link, friction]);

  const canvas = (
    <div className="graph-canvas" ref={containerRef} style={compact ? undefined : { minHeight: 560 }}>
      <div className="legend">
        <div className="row">
          <span className="swatch" style={{ background: SAFE, boxShadow: "0 0 8px var(--safe-glow)" }} />
          Authorized · trust ≥ 0.80
        </div>
        <div className="row">
          <span className="swatch" style={{ background: WARN, boxShadow: "0 0 8px var(--warn-glow)" }} />
          Degraded · 0.30–0.80
        </div>
        <div className="row">
          <span className="swatch" style={{ background: CRIT, boxShadow: "0 0 8px var(--crit-glow)" }} />
          Quarantined · ≤ 0.30
        </div>
      </div>
    </div>
  );

  if (!showControls) {
    return (
      <>
        <span className="panel-meta" data-mesh-meta style={{ display: "none" }}>
          {counts.nodes} agents · {counts.edges} edges
        </span>
        {canvas}
      </>
    );
  }

  return (
    <div className="mesh-layout">
      <div className="panel" style={{ display: "flex", flexDirection: "column" }}>
        <div className="panel-head">
          <span className="panel-title">
            <span className="dot" />
            Trust Mesh · Operator View
          </span>
          <span className="panel-meta">
            {counts.nodes} agents · {counts.edges} edges
          </span>
        </div>
        {canvas}
      </div>
      <div className="panel controls">
        <div className="panel-title" style={{ marginBottom: 18 }}>
          Force Layout
        </div>
        <div className="control">
          <label>
            Gravity (charge) <b>{charge}</b>
          </label>
          <input type="range" min={-800} max={-40} value={charge} onChange={(e) => setCharge(+e.target.value)} />
        </div>
        <div className="control">
          <label>
            Link distance <b>{link}</b>
          </label>
          <input type="range" min={30} max={220} value={link} onChange={(e) => setLink(+e.target.value)} />
        </div>
        <div className="control">
          <label>
            Friction (decay) <b>{friction.toFixed(2)}</b>
          </label>
          <input
            type="range"
            min={5}
            max={90}
            value={Math.round(friction * 100)}
            onChange={(e) => setFriction(+e.target.value / 100)}
          />
        </div>
        <div
          style={{
            fontSize: "0.68rem",
            color: "var(--ink-faint)",
            lineHeight: 1.5,
            marginTop: 8,
            borderTop: "1px solid var(--border)",
            paddingTop: 14,
          }}
        >
          Double-click any node to isolate its delegation lineage. Drag to reposition. Scroll to zoom.
        </div>
      </div>
    </div>
  );
}
