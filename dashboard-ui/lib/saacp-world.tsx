"use client";

import { createContext, useContext } from "react";
import type { World, FinState, FinEntry, TxnsEntry } from "./saacp-v3";
import type { FeedEntry } from "./saacp-feed";

/* WorldContext — per-page object bag. Each `<CommandCenter>` page renders
   `<WorldProvider value={...}>` and the children use the v3 components
   (MeshCanvas, FeedPanel, FinancialCard, etc.) which read from this
   context.

   The provider is intentionally not stateful: the page component owns the
   state via `useState` + `useRef` and simply passes the current world/feed/
   fin into the context. This keeps the world simulation reproducible and
   lets the per-page provider (e.g. for the mesh view) hand a focused world
   to its children. */

export interface WorldContextValue {
  world: World;
  feed: FeedEntry[];
  fin: FinState;
  mode: "live" | "sim";
  sseOk: boolean;
  focusId: string | null;
  setFocusId: (id: string | null) => void;
  pushFeed: (
    kind: FeedEntry["kind"],
    tag: string,
    level: FeedEntry["level"],
    title: string,
    lines?: string[],
  ) => void;
  addSavings: (amount: number, opts: { tokens: number; gate: string; agent: string; fast?: boolean }) => void;
  triggerInjection: () => void;
  triggerLoop: () => void;
  resetMesh: () => void;
  quarantine: (id: string) => void;
  restore: (id: string) => void;
  gateFlash: string | null;
}

const Ctx = createContext<WorldContextValue | null>(null);

export const WorldProvider = Ctx.Provider;

export function useWorld(): WorldContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useWorld() must be used within <WorldProvider>");
  return v;
}

/* Helper to satisfy unused imports until later file wiring. */
export type { FinEntry, TxnsEntry };
