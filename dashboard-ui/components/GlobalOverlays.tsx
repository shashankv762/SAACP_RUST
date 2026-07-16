"use client";

import { useEffect, useRef } from "react";
import { useFlashSignal } from "@/lib/store";

// Global, always-mounted overlay nodes:
//   #node-tip — the graph tooltip (positioned imperatively by TrustMeshGraph)
//   #flash    — the red screen-flash vignette, fired on a real InjectionAlert
export function GlobalOverlays() {
  const flashSignal = useFlashSignal();
  const flashRef = useRef<HTMLDivElement>(null);
  const first = useRef(true);

  useEffect(() => {
    // don't fire on initial mount, only on a genuine new attack event
    if (first.current) {
      first.current = false;
      return;
    }
    const el = flashRef.current;
    if (!el) return;
    el.classList.remove("fire");
    // force reflow so the animation restarts even on back-to-back events
    void el.offsetWidth;
    el.classList.add("fire");
  }, [flashSignal]);

  return (
    <>
      <div className="flash" id="flash" ref={flashRef} />
      <div className="node-tip" id="node-tip" />
    </>
  );
}
