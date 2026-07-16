"use client";

import { useEffect, useRef, useState } from "react";
import { FinancialSample, useFinancialHistory } from "@/lib/store";

const fmt = (n: number) => n.toLocaleString("en-US");

/** Smoothly tween a displayed dollar figure toward a target. */
function useOdometer(target: number): string {
  const [shown, setShown] = useState(0);
  const shownRef = useRef(0);
  const targetRef = useRef(0);
  const rafRef = useRef<number | null>(null);
  targetRef.current = target;

  useEffect(() => {
    const step = () => {
      const diff = targetRef.current - shownRef.current;
      if (Math.abs(diff) < 0.005) {
        shownRef.current = targetRef.current;
        rafRef.current = null;
      } else {
        shownRef.current += diff * 0.12;
        rafRef.current = requestAnimationFrame(step);
      }
      setShown(shownRef.current);
    };
    if (rafRef.current === null) rafRef.current = requestAnimationFrame(step);
    return () => {
      if (rafRef.current !== null) cancelAnimationFrame(rafRef.current);
      rafRef.current = null;
    };
  }, [target]);

  const whole = Math.floor(shown);
  const cents = Math.round((shown - whole) * 100)
    .toString()
    .padStart(2, "0");
  return `$${fmt(whole)}.${cents}`;
}

/** dollars/min over the last 60s window, from real financial samples. */
function velocityPerMin(samples: FinancialSample[]): number {
  if (samples.length < 2) return 0;
  const now = Date.now();
  const cutoff = now - 60_000;
  const recent = samples.filter((s) => s.t >= cutoff);
  if (recent.length < 2) {
    // fall back to overall rate across whatever window we have
    const first = samples[0];
    const last = samples[samples.length - 1];
    const dtMin = (last.t - first.t) / 60_000;
    return dtMin > 0 ? (last.dollars - first.dollars) / dtMin : 0;
  }
  const first = recent[0];
  const last = recent[recent.length - 1];
  const dtMin = (last.t - first.t) / 60_000;
  return dtMin > 0 ? (last.dollars - first.dollars) / dtMin : 0;
}

function Sparkline({ samples }: { samples: FinancialSample[] }) {
  if (samples.length < 2) return <svg className="spark" preserveAspectRatio="none" viewBox="0 0 100 26" />;
  const vals = samples.slice(-40).map((s) => s.tokens);
  const min = Math.min(...vals);
  const max = Math.max(...vals);
  const rng = max - min || 1;
  const pts = vals
    .map((v, i) => `${(i / (vals.length - 1)) * 100},${26 - ((v - min) / rng) * 24 - 1}`)
    .join(" ");
  return (
    <svg className="spark" preserveAspectRatio="none" viewBox="0 0 100 26">
      <polyline
        points={pts}
        fill="none"
        stroke="var(--safe)"
        strokeWidth={1.5}
        vectorEffect="non-scaling-stroke"
        style={{ filter: "drop-shadow(0 0 3px var(--safe-glow))" }}
      />
    </svg>
  );
}

function Gauge({ velocity }: { velocity: number }) {
  const v = Math.min(1, velocity / 50);
  const a = Math.PI * (1 - v);
  const x = 30 + 24 * Math.cos(a);
  const y = 33 - 24 * Math.sin(a);
  return (
    <svg className="gauge" viewBox="0 0 60 36">
      <path d="M6 33 A24 24 0 0 1 54 33" fill="none" stroke="oklch(30% 0.02 264)" strokeWidth={4} strokeLinecap="round" />
      <path
        d={`M6 33 A24 24 0 0 1 ${x.toFixed(1)} ${y.toFixed(1)}`}
        fill="none"
        stroke="var(--safe)"
        strokeWidth={4}
        strokeLinecap="round"
        style={{ filter: "drop-shadow(0 0 4px var(--safe-glow))" }}
      />
    </svg>
  );
}

interface Props {
  compact?: boolean;
}

export function RoiPanel({ compact = false }: Props) {
  const samples = useFinancialHistory();
  const latest = samples[samples.length - 1];
  const dollars = latest?.dollars ?? 0;
  const tokens = latest?.tokens ?? 0;
  const perToken = latest?.dollarsPerToken ?? 0.00002;
  const odo = useOdometer(dollars);
  const [whole, cents] = odo.split(".");
  const velocity = velocityPerMin(samples);

  if (compact) {
    return (
      <div className="roi-panel" style={{ paddingBottom: 6 }}>
        <div className="roi-caption" style={{ fontSize: "0.66rem" }}>
          Estimated Exposure Prevented
        </div>
        <div className="odometer compact">
          {whole}
          <span className="cents">.{cents}</span>
        </div>
      </div>
    );
  }

  return (
    <div className="panel roi-panel" style={{ gridColumn: "1 / -1" }}>
      <div className="roi-lead">
        <span className="roi-caption">Estimated Exposure Prevented · Live</span>
        <span className="roi-note">
          Rejected claimed token cost (Gate 0.5 + gate rejections). Not observed spend. Est. @ ${perToken}/token.
        </span>
      </div>
      <div className="odometer">
        {whole}
        <span className="cents">.{cents}</span>
      </div>
      <div className="roi-sub">
        <div className="metric">
          <div className="k">Tokens Rejected</div>
          <div className="v">{fmt(tokens)}</div>
          <Sparkline samples={samples} />
        </div>
        <div className="metric">
          <div className="k">Conversion Rate</div>
          <div className="v">
            ${perToken}
            <span style={{ fontSize: "0.62rem", color: "var(--ink-faint)" }}> /tok</span>
          </div>
          <div style={{ fontSize: "0.64rem", color: "var(--ink-faint)", marginTop: 9 }}>
            operator-configured (/api/financial)
          </div>
        </div>
        <div className="metric">
          <div className="k">Averted Spend Velocity</div>
          <div className="gauge-wrap">
            <Gauge velocity={velocity} />
            <div className="v green" style={{ fontSize: "1rem" }}>
              ${velocity.toFixed(2)}
              <span style={{ fontSize: "0.6rem", color: "var(--ink-faint)" }}> /min</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
