"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import { clamp, FinState, fmtInt, fmtUSD, uid, velocityOf } from "@/lib/saacp-v3";
import { AnimatedMoney } from "./atoms";

/* FinancialCard — v3's "Token dollars saved" odometer card. Re-used on the
   Overview page (compact mode) and the Financial page (full). */

export function FinancialCard({ fin, compact = false }: { fin: FinState; compact?: boolean }) {
  const prev = useRef(fin.saved);
  const [delta, setDelta] = useState<{ v: number; k: string } | null>(null);
  useEffect(() => {
    const d = fin.saved - prev.current;
    if (d > 0.05) {
      setDelta({ v: d, k: uid() });
      const to = setTimeout(() => setDelta(null), 2400);
      prev.current = fin.saved;
      return () => clearTimeout(to);
    }
    prev.current = fin.saved;
  }, [fin.saved]);
  const capFrac = clamp(fin.saved / 5000, 0, 1);
  const velocity = velocityOf(fin);

  if (compact) {
    return (
      <section className="panel fin-card">
        <div className="fin-lbl">Token dollars saved — today · Financial circuit breaker</div>
        <div className="odo-wrap">
          <AnimatedMoney value={fin.saved} />
          <AnimatePresence>
            {delta && (
              <motion.div
                key={delta.k}
                className="delta-chip"
                initial={{ opacity: 0, y: 10, scale: 0.85 }}
                animate={{ opacity: 1, y: 0, scale: 1 }}
                exit={{ opacity: 0, y: -14 }}
              >
                +{fmtUSD(delta.v)}
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        <div style={{ font: "400 10px var(--mono)", color: "var(--text-3)", marginTop: -4 }}>
          SAACP saved you {fmtUSD(fin.saved)} today · daily cap {fmtUSD(5000)}
        </div>
        <div className="minibar capbar">
          <i style={{ width: `${capFrac * 100}%` }} />
        </div>
      </section>
    );
  }

  return (
    <section className="panel panel-hi fin-card">
      <div className="fin-lbl">Token dollars saved — today · Financial circuit breaker</div>
      <div className="odo-wrap">
        <AnimatedMoney value={fin.saved} />
        <AnimatePresence>
          {delta && (
            <motion.div
              key={delta.k}
              className="delta-chip"
              initial={{ opacity: 0, y: 10, scale: 0.85 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: -14 }}
            >
              +{fmtUSD(delta.v)}
            </motion.div>
          )}
        </AnimatePresence>
      </div>
      <div style={{ font: "400 10px var(--mono)", color: "var(--text-3)", marginTop: -4 }}>
        SAACP saved you {fmtUSD(fin.saved)} today · daily cap {fmtUSD(5000)}
      </div>
      <div className="minibar capbar">
        <i style={{ width: `${capFrac * 100}%` }} />
      </div>
      <div className="fin-sub">
        <div className="fs">
          <div className="l">TOKENS SAVED</div>
          <div className="v" style={{ color: "var(--accent)" }}>
            {fmtInt(fin.tokensSaved)}
          </div>
          <div className="minibar">
            <i style={{ width: `${clamp((fin.tokensSaved % 3e7) / 3e7, 0.06, 1) * 100}%` }} />
          </div>
        </div>
        <div className="fs">
          <div className="l">CONVERSION RATE</div>
          <div className="v" style={{ color: "var(--text)" }}>
            $0.00002
          </div>
          <div style={{ font: "400 8.5px var(--mono)", color: "var(--text-3)", marginTop: 5 }}>
            per token · GPT-4o tier
          </div>
        </div>
        <div className="fs">
          <div className="l">SAVE VELOCITY</div>
          <div className="v" style={{ color: "var(--amber)" }}>
            {fmtUSD(velocity)}
            <span style={{ fontSize: 9, color: "var(--text-3)" }}> /min</span>
          </div>
          <div className="minibar">
            <i
              style={{
                width: `${clamp(velocity / 200, 0.05, 1) * 100}%`,
                background: "linear-gradient(90deg,#a06f1d,var(--amber))",
              }}
            />
          </div>
        </div>
      </div>
    </section>
  );
}
