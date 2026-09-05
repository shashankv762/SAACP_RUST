"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import type { FeedEntry } from "@/lib/saacp-feed";
import { fmtTok, fmtUSD } from "@/lib/saacp-v3";

/* FeedPanel — v3's live attack log. The same filtered, auto-scrolling
   feed the v3 design uses, with `[ ALL ] / [ ATTACKS ] / [ DELEGATIONS ] /
   [ TRUST DECAY ]` filters. Source is the world-owned `feed` array (the v3
   `App.pushFeed`). */

const FILTERS: ReadonlyArray<{ key: "all" | "attacks" | "delegations" | "trust"; label: string }> = [
  { key: "all", label: "[ ALL ]" },
  { key: "attacks", label: "[ ATTACKS ]" },
  { key: "delegations", label: "[ DELEGATIONS ]" },
  { key: "trust", label: "[ TRUST DECAY ]" },
];

function visible(feed: FeedEntry[], f: "all" | "attacks" | "delegations" | "trust"): FeedEntry[] {
  if (f === "all") return feed;
  if (f === "attacks") return feed.filter((e) => e.kind === "attack" || e.kind === "loop");
  if (f === "delegations") return feed.filter((e) => e.kind === "delegation");
  return feed.filter((e) => e.kind === "trust");
}

const TAG_CLASS: Record<string, string> = {
  BLOCKED: "t-BLOCKED",
  REVOKED: "t-REVOKED",
  MANUAL: "t-MANUAL",
  INTERCEPT: "t-INTERCEPT",
  DECAY: "t-DECAY",
  WARNING: "t-WARNING",
  DELEGATE: "t-DELEGATE",
  SPAWN: "t-SPAWN",
  AUDIT: "t-AUDIT",
  REAUTH: "t-REAUTH",
  BREAKER: "t-BREAKER",
  BOOT: "t-BOOT",
  SSE: "t-SSE",
  SYSTEM: "t-SYSTEM",
  CONFIG: "t-CONFIG",
  RESET: "t-RESET",
  INTRUSION: "t-INTRUSION",
};

const TAG_BRACKET: Record<string, string> = {
  "[BLOCKED]": "t-BLOCKED",
  "[REVOKED]": "t-REVOKED",
  "[MANUAL]": "t-MANUAL",
  "[INTERCEPT]": "t-INTERCEPT",
  "[DECAY]": "t-DECAY",
  "[WARNING]": "t-WARNING",
  "[DELEGATE]": "t-DELEGATE",
  "[SPAWN]": "t-SPAWN",
  "[AUDIT]": "t-AUDIT",
  "[REAUTH]": "t-REAUTH",
  "[BREAKER]": "t-BREAKER",
  "[BOOT]": "t-BOOT",
  "[SSE]": "t-SSE",
  "[SYSTEM]": "t-SYSTEM",
  "[CONFIG]": "t-CONFIG",
  "[RESET]": "t-RESET",
  "[INTRUSION]": "t-INTRUSION",
  "[TRUST]": "t-TRUST",
};

function levelClass(level: FeedEntry["level"]): string {
  return level === "crit" ? "l-crit" : level === "warn" ? "l-warn" : level === "ok" ? "l-ok" : "l-info";
}

function extractTag(s: string): { tag: string; rest: string } {
  const m = s.match(/^(\[[^\]]+\])\s*(.*)$/);
  if (m) return { tag: m[1], rest: m[2] };
  return { tag: "", rest: s };
}

export function FeedPanel({
  feed,
  height = 360,
}: {
  feed: FeedEntry[];
  height?: number;
}) {
  const [fi, setFi] = useState(0);
  const bodyRef = useRef<HTMLDivElement | null>(null);
  const shown = visible(feed, FILTERS[fi].key);

  useEffect(() => {
    const el = bodyRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [shown.length, fi]);

  // `feed` is already a v3 `FeedEntry[]` (the orchestrator owns the
  // conversion from the store's `LogEntry` shape). Rendering is direct.
  const rows: FeedEntry[] = shown;

  return (
    <section className="panel feed">
      <div className="phead">
        <div className="ptitle">
          <span className="dot red" />
          LIVE ATTACK LOG
        </div>
        <div className="psub">tail -f ImmutableAuditLog</div>
      </div>
      <div className="feedfilters">
        {FILTERS.map((f, i) => (
          <button key={f.key} className={`ff ${fi === i ? "on" : ""}`} onClick={() => setFi(i)}>
            {f.label}
          </button>
        ))}
      </div>
      <div className="feedbody" ref={bodyRef} style={{ minHeight: 80, maxHeight: height }}>
        <AnimatePresence initial={false}>
          {rows.length === 0 && (
            <div className="fentry l-info" key="__empty">
              <div className="fhead">
                <span className="ftime">--:--:--</span>
                <span className="ftag t-SYSTEM">[SYSTEM]</span>
                <span className="ftitle">Awaiting live events from /events…</span>
              </div>
            </div>
          )}
          {rows.map((e) => {
            const { tag, rest } = extractTag(e.tag);
            const klass = TAG_BRACKET[tag] || TAG_CLASS[tag.replace(/[[\]]/g, "")] || "t-SYSTEM";
            return (
              <motion.div
                key={e.id}
                className={`fentry ${levelClass(e.level)}`}
                initial={{ opacity: 0, y: 14 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ duration: 0.22 }}
              >
                <div className="fhead">
                  <span className="ftime">{e.time}</span>
                  <span className={`ftag ${klass}`}>{tag || e.tag}</span>
                  <span className="ftitle">{rest || e.title}</span>
                </div>
                {e.lines.length > 0 && (
                  <div className="fbody">
                    {e.lines.map((l, i) => (
                      <div key={i}>{l}</div>
                    ))}
                  </div>
                )}
                {/* surface known numeric facts for operator scanning */}
                {e.estimatedCost != null && (
                  <div className="fbody" style={{ marginTop: 4 }}>
                    est. exposure blocked: <b style={{ color: "var(--accent)" }}>{fmtUSD(e.estimatedCost)}</b>
                  </div>
                )}
                {e.tokenAmount != null && (
                  <div className="fbody" style={{ marginTop: 4 }}>
                    tokens involved: <b style={{ color: "var(--info)" }}>{fmtTok(e.tokenAmount)}</b>
                  </div>
                )}
              </motion.div>
            );
          })}
        </AnimatePresence>
      </div>
      <div className="cursorline">
        saacp-gateway ▸ stream /events · ring 0 <span className="cursor">▊</span>
      </div>
    </section>
  );
}
