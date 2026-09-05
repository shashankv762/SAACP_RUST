"use client";

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";
import {
  clamp,
  clampCam,
  drawWorld,
  fmtTok,
  nodeRadius,
  STATUS_COLOR,
  stepWorld,
  World,
} from "@/lib/saacp-v3";

/* MeshCanvas — hand-rolled 2D canvas for the v3 trust-mesh graph.
   Faithful to the original `commandUI.md` MeshCanvas — same camera, drag,
   wheel-zoom, dblclick-isolate, hover-tooltip semantics — but stripped of
   the page-level state machine (no `useState` for feed/log/fin) so the
   component can be reused on every page that wants a mesh panel. */
export function MeshCanvas({
  world,
  focusId,
  onFocus,
}: {
  world: World;
  focusId: string | null;
  onFocus: (id: string | null) => void;
}) {
  const wrapRef = useRef<HTMLDivElement | null>(null);
  const cvsRef = useRef<HTMLCanvasElement | null>(null);
  const camRef = useRef({ x: 0, y: 0, s: 1 });
  const camTRef = useRef({ x: 0, y: 0, s: 1 });
  const apiRef = useRef<{ zoomBy: (f: number) => void; reset: () => void }>({ zoomBy: () => {}, reset: () => {} });
  const [hover, setHover] = useState<{ id: string; cx: number; cy: number } | null>(null);
  const hoverIdRef = useRef<string | null>(null);
  const lastHpRef = useRef<{ x: number; y: number } | null>(null);
  const dragRef = useRef<null | { type: "node"; id: string } | { type: "pan"; sx: number; sy: number; cx: number; cy: number }>(null);
  const [zoomPct, setZoomPct] = useState(100);

  useEffect(() => {
    world.focus = focusId || null;
  }, [focusId, world]);

  useEffect(() => {
    const wrap = wrapRef.current;
    const cvs = cvsRef.current;
    if (!wrap || !cvs) return;
    const ctx = cvs.getContext("2d");
    if (!ctx) return;
    const dpr = Math.min(2, window.devicePixelRatio || 1);
    const resize = () => {
      const r = wrap.getBoundingClientRect();
      world._w = Math.max(1, r.width);
      world._h = Math.max(1, r.height);
      cvs.width = world._w * dpr;
      cvs.height = world._h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      clampCam(camRef.current, world._w, world._h, world._w, world._h);
      clampCam(camTRef.current, world._w, world._h, world._w, world._h);
    };
    resize();
    const ro = new ResizeObserver(resize);
    ro.observe(wrap);
    if (![...world.agents.values()].every((a) => a.x !== undefined)) {
      const arr = [...world.agents.values()];
      arr.forEach((a, i) => {
        const ang = (i / arr.length) * Math.PI * 2;
        a.x = world._w / 2 + Math.cos(ang) * Math.min(world._w, world._h) * 0.33;
        a.y = world._h / 2 + Math.sin(ang) * Math.min(world._w, world._h) * 0.33;
      });
    }
    let raf = 0;
    let last = performance.now();
    const frame = (tm: number) => {
      const dt = Math.min(34, tm - last);
      last = tm;
      const cam = camRef.current;
      const camT = camTRef.current;
      cam.x += (camT.x - cam.x) * 0.18;
      cam.y += (camT.y - cam.y) * 0.18;
      cam.s += (camT.s - cam.s) * 0.22;
      stepWorld(world, dt, tm);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, world._w, world._h);
      ctx.setTransform(dpr * cam.s, 0, 0, dpr * cam.s, dpr * cam.x, dpr * cam.y);
      drawWorld(world, ctx, tm, cam, world._w, world._h);
      raf = requestAnimationFrame(frame);
    };
    raf = requestAnimationFrame(frame);

    const screenPt = (ev: MouseEvent) => {
      const r = cvs.getBoundingClientRect();
      return { x: ev.clientX - r.left, y: ev.clientY - r.top };
    };
    const worldPt = (ev: MouseEvent) => {
      const p = screenPt(ev);
      const c = camRef.current;
      return { x: (p.x - c.x) / c.s, y: (p.y - c.y) / c.s };
    };
    const hit = (p: { x: number; y: number }) => {
      let best: typeof world.agents extends Map<infer _, infer V> ? V | null : never = null;
      let bd = Infinity;
      const c = camRef.current;
      for (const a of world.agents.values()) {
        const d = Math.hypot(a.x - p.x, a.y - p.y);
        if (d < nodeRadius(world, a) + 8 / c.s && d < bd) {
          bd = d;
          best = a;
        }
      }
      return best;
    };
    const applyZoom = (mx: number, my: number, f: number) => {
      const c = camTRef.current;
      const wx = (mx - c.x) / c.s;
      const wy = (my - c.y) / c.s;
      c.s = clamp(c.s * f, 0.4, 3);
      c.x = mx - wx * c.s;
      c.y = my - wy * c.s;
      clampCam(c, world._w, world._h, world._w, world._h);
      setZoomPct(Math.round(c.s * 100));
    };
    apiRef.current = {
      zoomBy: (f) => applyZoom(world._w / 2, world._h / 2, f),
      reset: () => {
        camTRef.current = { x: 0, y: 0, s: 1 };
        setZoomPct(100);
      },
    };
    const wheel = (ev: WheelEvent) => {
      ev.preventDefault();
      const p = screenPt(ev);
      applyZoom(p.x, p.y, ev.deltaY < 0 ? 1.13 : 1 / 1.13);
    };
    const mm = (ev: MouseEvent) => {
      const d = dragRef.current;
      if (d && d.type === "node") {
        const p = worldPt(ev);
        const a = world.agents.get(d.id);
        if (a) {
          a.x = p.x;
          a.y = p.y;
          a.vx = 0;
          a.vy = 0;
        }
        return;
      }
      if (d && d.type === "pan") {
        const nx = d.cx + (ev.clientX - d.sx);
        const ny = d.cy + (ev.clientY - d.sy);
        const c = camTRef.current;
        c.x = nx;
        c.y = ny;
        clampCam(c, world._w, world._h, world._w, world._h);
        camRef.current.x = c.x;
        camRef.current.y = c.y;
        return;
      }
      const p = worldPt(ev);
      const h = hit(p);
      cvs.style.cursor = h ? "pointer" : "grab";
      const c = camRef.current;
      if (h) {
        const sx = h.x * c.s + c.x;
        const sy = h.y * c.s + c.y;
        const lp = lastHpRef.current;
        if (hoverIdRef.current !== h.id || !lp || Math.abs(sx - lp.x) > 1.5 || Math.abs(sy - lp.y) > 1.5) {
          hoverIdRef.current = h.id;
          lastHpRef.current = { x: sx, y: sy };
          setHover({ id: h.id, cx: sx, cy: sy });
        }
      } else if (hoverIdRef.current) {
        hoverIdRef.current = null;
        lastHpRef.current = null;
        setHover(null);
      }
    };
    const md = (ev: MouseEvent) => {
      const p = worldPt(ev);
      const h = hit(p);
      if (h) {
        dragRef.current = { type: "node", id: h.id };
        world.dragId = h.id;
        cvs.style.cursor = "grabbing";
      } else {
        dragRef.current = {
          type: "pan",
          sx: ev.clientX,
          sy: ev.clientY,
          cx: camTRef.current.x,
          cy: camTRef.current.y,
        };
        cvs.style.cursor = "grabbing";
      }
    };
    const mu = () => {
      if (dragRef.current && dragRef.current.type === "node") world.dragId = null;
      dragRef.current = null;
      cvs.style.cursor = "grab";
    };
    const ml = () => {
      hoverIdRef.current = null;
      lastHpRef.current = null;
      setHover(null);
      if (!dragRef.current) cvs.style.cursor = "grab";
    };
    const dbl = (ev: MouseEvent) => {
      const h = hit(worldPt(ev));
      if (h && onFocus) onFocus(world.focus === h.id ? null : h.id);
    };
    cvs.addEventListener("wheel", wheel, { passive: false });
    cvs.addEventListener("mousemove", mm);
    cvs.addEventListener("mousedown", md);
    window.addEventListener("mouseup", mu);
    cvs.addEventListener("mouseleave", ml);
    cvs.addEventListener("dblclick", dbl);
    return () => {
      world.dragId = null;
      cancelAnimationFrame(raf);
      ro.disconnect();
      cvs.removeEventListener("wheel", wheel);
      cvs.removeEventListener("mousemove", mm);
      cvs.removeEventListener("mousedown", md);
      window.removeEventListener("mouseup", mu);
      cvs.removeEventListener("mouseleave", ml);
      cvs.removeEventListener("dblclick", dbl);
    };
  }, [world, onFocus]);

  const ha = hover ? world.agents.get(hover.id) : null;
  const wrapW = wrapRef.current ? wrapRef.current.clientWidth : 600;

  return (
    <div ref={wrapRef} className="mesh-wrap">
      <canvas ref={cvsRef} style={{ cursor: "grab" }} />
      <div className="zoomctl">
        <button title="Zoom in" onClick={() => apiRef.current.zoomBy(1.28)}>
          +
        </button>
        <div className="zoomval">{zoomPct}%</div>
        <button title="Zoom out" onClick={() => apiRef.current.zoomBy(1 / 1.28)}>
          −
        </button>
        <button title="Reset view" onClick={() => apiRef.current.reset()} style={{ fontSize: 12 }}>
          ⌖
        </button>
      </div>
      <div className="legend">
        <span>
          <span className="sw" style={{ background: "#c5f547" }} />
          AUTHORIZED ≥0.8
        </span>
        <span>
          <span className="sw" style={{ background: "#f5b047" }} />
          DEGRADED
        </span>
        <span>
          <span className="sw" style={{ background: "#ff6b47" }} />
          QUARANTINED
        </span>
        <span>
          <span className="sw" style={{ background: "#c5f547", boxShadow: "0 0 6px #c5f547" }} />
          DELEGATION PULSE
        </span>
      </div>
      <div className="hint">dbl-click: isolate lineage · drag node: reposition · drag canvas: pan · scroll: zoom</div>
      <AnimatePresence>
        {ha && hover && (
          <motion.div
            className="hovercard"
            initial={{ opacity: 0, scale: 0.94 }}
            animate={{ opacity: 1, scale: 1 }}
            exit={{ opacity: 0 }}
            style={{ left: clamp(hover.cx + 16, 8, wrapW - 244), top: Math.max(8, hover.cy + 14) }}
          >
            <div className="hn">
              <span
                className="avat"
                style={{ background: STATUS_COLOR[ha.status], boxShadow: `0 0 8px ${STATUS_COLOR[ha.status]}` }}
              />
              {ha.name}
            </div>
            <div className="hid">
              id: {ha.id} · {ha.role}
            </div>
            <div className="hrow">
              <span>STATUS</span>
              <b style={{ color: STATUS_COLOR[ha.status] }}>
                {ha.status}
                {ha.locked ? " · REAUTH REQ" : ""}
              </b>
            </div>
            <div className="hrow">
              <span>TRUST</span>
              <b>{ha.trust.toFixed(3)}</b>
            </div>
            <div className="hrow">
              <span>SPAWNED BY</span>
              <b>{ha.parent ? world.agents.get(ha.parent)?.name || ha.parent : "GENESIS"}</b>
            </div>
            <div className="hrow">
              <span>TOKENS USED</span>
              <b>{fmtTok(ha.tokens)}</b>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
