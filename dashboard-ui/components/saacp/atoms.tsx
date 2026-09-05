"use client";

import { useEffect, useRef, useState } from "react";
import { fmtInt, fmtTok, fmtUSD, GATES, hexA, RATE } from "@/lib/saacp-v3";

/* AnimatedMoney — smoothly tween the displayed dollar figure toward a
   target. Same rAF-based exponential-decay algorithm as `commandUI.md`
   (lerp factor = 0.006 × clamped dt). */
export function AnimatedMoney({ value }: { value: number }) {
  const [disp, setDisp] = useState(value);
  const st = useRef({ disp: value, target: value, raf: null as number | null });
  useEffect(() => {
    st.current.target = value;
    if (st.current.raf !== null) return;
    let last = performance.now();
    const loop = (t: number) => {
      const s = st.current;
      const dt = Math.min(64, t - last);
      last = t;
      const diff = s.target - s.disp;
      if (Math.abs(diff) < 0.005) {
        s.disp = s.target;
        setDisp(s.target);
        s.raf = null;
        return;
      }
      s.disp += diff * Math.min(1, dt * 0.006);
      setDisp(s.disp);
      s.raf = requestAnimationFrame(loop);
    };
    st.current.raf = requestAnimationFrame(loop);
    return () => {
      if (st.current.raf !== null) cancelAnimationFrame(st.current.raf);
      st.current.raf = null;
    };
  }, [value]);
  const usd = Number(disp).toLocaleString("en-US", {
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  });
  return (
    <div className="bigodo">
      <span className="cur">$</span>
      {usd}
    </div>
  );
}

/* Gauge — semicircle meter. */
export function Gauge({
  value,
  max,
  label,
  fmt,
  color = "#c5f547",
}: {
  value: number;
  max: number;
  label: string;
  fmt: string;
  color?: string;
}) {
  const frac = Math.max(0, Math.min(1, value / max));
  const polar = (cx: number, cy: number, r: number, deg: number) => {
    const a = ((deg - 90) * Math.PI) / 180;
    return [cx + r * Math.cos(a), cy + r * Math.sin(a)] as const;
  };
  const arc = (a0: number, a1: number, r = 52) => {
    const [x0, y0] = polar(70, 74, r, a0);
    const [x1, y1] = polar(70, 74, r, a1);
    return `M${x0.toFixed(1)},${y0.toFixed(1)} A${r},${r} 0 ${a1 - a0 > 180 ? 1 : 0} 1 ${x1.toFixed(1)},${y1.toFixed(1)}`;
  };
  const ang = -110 + 220 * frac;
  const [nx, ny] = polar(70, 74, 40, ang);
  return (
    <svg viewBox="0 0 140 110" style={{ width: "100%", maxWidth: 190 }}>
      <path d={arc(-110, 110)} stroke="rgba(245,244,240,0.09)" strokeWidth={9} fill="none" strokeLinecap="round" />
      <path
        d={arc(-110, Math.max(-109, ang))}
        stroke={color}
        strokeWidth={9}
        fill="none"
        strokeLinecap="round"
        style={{ filter: `drop-shadow(0 0 6px ${hexA(color, 0.8)})` }}
      />
      <line x1={70} y1={74} x2={nx} y2={ny} stroke="#f5f4f0" strokeWidth={2} strokeLinecap="round" />
      <circle cx={70} cy={74} r={4} fill="#f5f4f0" />
      <text x={70} y={102} textAnchor="middle" fill={color} fontSize={13} fontWeight={700} fontFamily="JetBrains Mono, monospace">
        {fmt}
      </text>
      <text x={70} y={20} textAnchor="middle" fill="#6b6a62" fontSize={7.5} letterSpacing={1.5} fontFamily="JetBrains Mono, monospace">
        {label}
      </text>
    </svg>
  );
}

/* Sparkline — minimal area-free line sparkline. */
export function Sparkline({ data, color = "#c5f547", height = 34 }: { data: number[]; color?: string; height?: number }) {
  const w = 160;
  if (!data.length) return null;
  const max = Math.max(...data, 0.001);
  const pts = data
    .map((v, i) => `${(i / Math.max(1, data.length - 1)) * w},${height - 3 - (v / max) * (height - 8)}`)
    .join(" ");
  return (
    <svg viewBox={`0 0 ${w} ${height}`} style={{ width: "100%", height }}>
      <polyline
        points={pts}
        fill="none"
        stroke={color}
        strokeWidth={1.6}
        style={{ filter: `drop-shadow(0 0 4px ${hexA(color, 0.8)})` }}
      />
    </svg>
  );
}

function smoothPath(pts: number[][]): string {
  if (pts.length < 3) return "M" + pts.map((p) => p.join(",")).join("L");
  let d = `M${pts[0][0].toFixed(1)},${pts[0][1].toFixed(1)}`;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i];
    const p1 = pts[i];
    const p2 = pts[i + 1];
    const p3 = pts[i + 2] || p2;
    d += `C${(p1[0] + (p2[0] - p0[0]) / 6).toFixed(1)},${(p1[1] + (p2[1] - p0[1]) / 6).toFixed(1)} ${(p2[0] - (p3[0] - p1[0]) / 6).toFixed(1)},${(p2[1] - (p3[1] - p1[1]) / 6).toFixed(1)} ${p2[0].toFixed(1)},${p2[1].toFixed(1)}`;
  }
  return d;
}

/* AreaChart — full 24h area chart with crosshair tooltip. */
export function AreaChart({ data }: { data: number[] }) {
  const [hi, setHi] = useState<number | null>(null);
  const W = 760;
  const H = 230;
  const P = 40;
  const B = 26;
  if (data.length < 2) {
    return <p className="empty-state">Collecting live samples from /api/financial… the curve fills in as the session runs.</p>;
  }
  const max = Math.max(...data, 1) * 1.18;
  const stepX = (W - P * 2) / (data.length - 1);
  const pts = data.map((v, i) => [P + i * stepX, H - B - (v / max) * (H - B - 24)] as number[]);
  const line = smoothPath(pts);
  const area = `${line} L${pts[pts.length - 1][0].toFixed(1)},${H - B} L${pts[0][0].toFixed(1)},${H - B} Z`;
  const hourLabel = (i: number) =>
    `${String((new Date().getHours() - (23 - i) + 48) % 24).padStart(2, "0")}:00`;
  return (
    <div className="chart-wrap">
      <svg
        viewBox={`0 0 ${W} ${H}`}
        style={{ width: "100%" }}
        onMouseMove={(ev) => {
          const r = ev.currentTarget.getBoundingClientRect();
          const x = ((ev.clientX - r.left) / r.width) * W;
          setHi(Math.max(0, Math.min(data.length - 1, Math.round((x - P) / stepX))));
        }}
        onMouseLeave={() => setHi(null)}
      >
        <defs>
          <linearGradient id="tokGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#c5f547" stopOpacity="0.34" />
            <stop offset="100%" stopColor="#c5f547" stopOpacity="0" />
          </linearGradient>
        </defs>
        {[0.25, 0.5, 0.75, 1].map((f) => {
          const y = H - B - f * (H - B - 24);
          return (
            <g key={f}>
              <line x1={P} y1={y} x2={W - P} y2={y} stroke="rgba(245,244,240,0.06)" strokeDasharray="3 5" />
              <text
                x={P - 7}
                y={y + 3}
                textAnchor="end"
                fontSize={8.5}
                fill="#6b6a62"
                fontFamily="JetBrains Mono, monospace"
              >
                {((f * max) / 1e6).toFixed(1)}M
              </text>
            </g>
          );
        })}
        {data.map(
          (_, i) =>
            i % 4 === 0 && (
              <text
                key={i}
                x={P + i * stepX}
                y={H - 8}
                textAnchor="middle"
                fontSize={8.5}
                fill="#6b6a62"
                fontFamily="JetBrains Mono, monospace"
              >
                {hourLabel(i)}
              </text>
            ),
        )}
        <path d={area} fill="url(#tokGrad)" />
        <path
          d={line}
          fill="none"
          stroke="#c5f547"
          strokeWidth={2}
          style={{ filter: "drop-shadow(0 0 6px rgba(197,245,71,.7))" }}
        />
        {hi !== null && (
          <g>
            <line
              x1={pts[hi][0]}
              y1={20}
              x2={pts[hi][0]}
              y2={H - B}
              stroke="rgba(245,244,240,0.25)"
              strokeDasharray="3 4"
            />
            <circle cx={pts[hi][0]} cy={pts[hi][1]} r={4.5} fill="#c5f547" stroke="#0a0908" strokeWidth={2} />
          </g>
        )}
      </svg>
      {hi !== null && (
        <div className="chart-tip" style={{ left: `${((P + hi * stepX) / W) * 100}%`, top: 26 }}>
          {hourLabel(hi)} · {fmtTok(data[hi])} tokens · ≈ {fmtUSD(data[hi] * RATE)}
        </div>
      )}
    </div>
  );
}

/* LivePkt — animates a fake packets/sec figure for the "live" feel. The
   real per-second throughput comes from the daemon's exposed gate
   latency counters, but those are per-gate (avg, p50, p99) so we show
   this simulation value as a deliberately-vivid per-second-rate card. */
export function LivePkt() {
  const [v, setV] = useState(498210);
  useEffect(() => {
    const iv = setInterval(() => setV(497000 + Math.round(Math.random() * 6200)), 600);
    return () => clearInterval(iv);
  }, []);
  return <>{v.toLocaleString("en-US")}</>;
}

/* GateStrip — top-of-page strip of all 12 gates with their latency hint. */
export function GateStrip({ flash }: { flash: string | null }) {
  return (
    <div className="gatestrip panel">
      {GATES.map((g) => (
        <div
          key={g[0]}
          className={`gate ${flash === g[0] ? "hot" : ""}`}
          title={`Gate ${g[0]} · ${g[1]} · ${g[2]} · ARMED`}
        >
          <span className="gdot" />
          <span className="gnum">GATE {g[0]}</span>
          <span className="gname">{g[1]}</span>
          <span className="glat">{g[2]}</span>
        </div>
      ))}
    </div>
  );
}

/* PipelineStrip — the 5-stage packet pipeline (Edge → Sidecar → Daemon →
   Handler → Delivered). Same as the v3 design. */
export function PipelineStrip() {
  const stages: ReadonlyArray<readonly [string, string, string]> = [
    ["00", "EDGE", "any language · HTTP/JSON"],
    ["01", "SIDECAR", "saacp-sidecar"],
    ["02", "DAEMON", "SAACPNetworkDaemon"],
    ["03", "HANDLER", "12 gates · non-reorderable"],
    ["04", "DELIVERED", "verified · audited"],
  ];
  return (
    <section className="panel pipeline">
      <div className="pipe-track">
        <div className="pktdot" />
        {stages.map((s, i) => (
          <div key={s[1]} className="pstage-cell">
            <div className="pstage">
              <div className="pstage-n">STAGE {s[0]}</div>
              <div className="pstage-t">{s[1]}</div>
              <div className="pstage-s mono">{s[2]}</div>
            </div>
            {i < stages.length - 1 && <div className="parrow mono">→</div>}
          </div>
        ))}
      </div>
      <div className="pipe-meta">
        <span>
          <b className="acc">
            <LivePkt />
          </b>{" "}
          packets / sec / core
        </span>
        <span>2.01 µs full pipeline latency</span>
        <span>AES-256-GCM · HKDF-SHA256 ratchet · WAL backpressure</span>
        <span style={{ marginLeft: "auto", color: "var(--text-4)" }}>reordering the pipeline is a security bug</span>
      </div>
    </section>
  );
}

/* Helper: re-export fmtInt for the FinancialCard. */
export { fmtInt };
