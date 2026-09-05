// saacp-feed.ts — v3 feed entry shape + live-LogEntry adapter.
//
// The v3 design's `App` component stores a `feed` array on the `App`'s
// own state (one push per event from `pushFeed`). When the dashboard is
// wired to the real backend via the `DashboardStore`, we map the store's
// `LogEntry[]` to this `FeedEntry` shape so the `FeedPanel` can render
// without caring where the events came from.

import type { LogEntry } from "./store";

/* V3-shape feed entry — what the `FeedPanel` consumes. */
export interface FeedEntry {
  id: number;
  time: string;
  kind: "attack" | "loop" | "delegation" | "trust" | "system";
  tag: string;
  level: "crit" | "warn" | "ok" | "info";
  title: string;
  body: string;
  lines: string[];
  estimatedCost: number | null | undefined;
  tokenAmount: number | null | undefined;
  gate: string | null | undefined;
  agent: string | null | undefined;
}

const levelFor = (k: LogEntry["kind"]): FeedEntry["level"] => {
  switch (k) {
    case "attack":
      return "crit";
    case "loop":
      return "crit";
    case "delegation":
      return "info";
    case "trust":
    default:
      return "ok";
  }
};

/* Map a backend `LogEntry` (the shape the DashboardStore already exposes)
   to the v3 `FeedEntry` shape. Idempotent and pure. */
export function feedEntryFor(e: LogEntry): FeedEntry {
  // The store's `tag` is already bracket-wrapped ([BLOCKED], [DELEGATE], ...).
  // Extract the bracketed prefix as a display tag and put the remainder into
  // `title` so the `FeedPanel` can render them as separate spans.
  const m = e.tag.match(/^(\[[^\]]+\])\s*(.*)$/);
  const tag = m ? m[1] : e.tag;
  const title = m ? m[2] : e.body;
  const lines: string[] = [];
  if (e.gate) lines.push(`gate: ${e.gate}`);
  if (e.bytecode) lines.push(`bytecode: ${e.bytecode}`);
  if (e.estimatedCost != null) lines.push(`est. cost blocked: $${e.estimatedCost.toFixed(2)}`);
  if (lines.length === 0) lines.push(e.body);
  // The store keeps `body` as the full event text. The `FeedPanel` displays
  // `title` as the bold event line, so split off the leading agent phrase.
  return {
    id: e.id,
    time: e.ts,
    kind: e.kind,
    tag,
    level: levelFor(e.kind),
    title,
    body: e.body,
    lines,
    estimatedCost: e.estimatedCost,
    tokenAmount: undefined,
    gate: e.gate,
    agent: e.agent,
  };
}

/* Build a v3 feed entry from scratch — used by the synthetic-tick
   path (when the backend is offline / in DEMO mode) so the FeedPanel
   renders the same shape regardless of source. */
export function makeFeedEntry(
  id: number,
  time: string,
  kind: FeedEntry["kind"],
  tag: string,
  level: FeedEntry["level"],
  title: string,
  body: string,
  extra: { lines?: string[]; estimatedCost?: number; tokenAmount?: number; gate?: string; agent?: string } = {},
): FeedEntry {
  return {
    id,
    time,
    kind,
    tag,
    level,
    title,
    body,
    lines: extra.lines ?? [],
    estimatedCost: extra.estimatedCost,
    tokenAmount: extra.tokenAmount,
    gate: extra.gate,
    agent: extra.agent,
  };
}
