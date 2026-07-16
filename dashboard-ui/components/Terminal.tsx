"use client";

import { useEffect, useRef, useState } from "react";
import { LogKind, useTerminalLog, LogEntry } from "@/lib/store";

type Filter = "all" | "attack" | "delegation" | "trust";

const FILTERS: { key: Filter; label: string; match?: LogKind[] }[] = [
  { key: "all", label: "[ ALL ]" },
  { key: "attack", label: "[ ATTACKS ]", match: ["attack", "loop"] },
  { key: "delegation", label: "[ DELEGATIONS ]", match: ["delegation"] },
  { key: "trust", label: "[ TRUST DECAY ]", match: ["trust"] },
];

function visible(log: LogEntry[], filter: Filter): LogEntry[] {
  if (filter === "all") return log;
  const spec = FILTERS.find((f) => f.key === filter);
  const match = spec?.match ?? [];
  return log.filter((l) => match.includes(l.kind));
}

interface Props {
  /** restrict to attack/loop entries (used by the Alerts page) */
  attacksOnly?: boolean;
}

export function Terminal({ attacksOnly = false }: Props) {
  const log = useTerminalLog();
  const [filter, setFilter] = useState<Filter>(attacksOnly ? "attack" : "all");
  const termRef = useRef<HTMLDivElement>(null);

  const rows = visible(log, filter).slice(-160);

  // keep the view pinned to the newest line
  useEffect(() => {
    const el = termRef.current;
    if (el) el.scrollTop = el.scrollHeight;
  }, [rows.length]);

  return (
    <>
      {!attacksOnly && (
        <div className="term-filters">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              className={`filter-btn${filter === f.key ? " active" : ""}`}
              onClick={() => setFilter(f.key)}
            >
              {f.label}
            </button>
          ))}
        </div>
      )}
      <div className="term mono" ref={termRef}>
        {rows.length === 0 ? (
          <div className="log">
            <span className="body" style={{ color: "var(--ink-faint)" }}>
              Awaiting live events from /events… gate rejections, delegations and trust
              signals will stream here as traffic flows.
            </span>
          </div>
        ) : (
          rows.map((l) => (
            <div key={l.id} className={`log ${l.kind}`}>
              <span className="ts">{l.ts}</span> <span className="tag">{l.tag}</span>{" "}
              <span className="body">{l.body}</span>
            </div>
          ))
        )}
        <div className="cursor-line">SAACP//monitor </div>
      </div>
    </>
  );
}
