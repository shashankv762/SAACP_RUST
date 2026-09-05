"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { AnimatePresence, motion } from "framer-motion";

import {
  useConnectionStatus,
  useAgents,
  useTrustMesh,
  useTerminalLog,
  useFinancialHistory,
  useHealth,
  useFlashSignal,
} from "@/lib/store";
import { initFin, makeWorld, rand, uid, type FinState, type World } from "@/lib/saacp-v3";
import { makeFeedEntry, type FeedEntry } from "@/lib/saacp-feed";
import {
  applyLogEvent,
  quarantineAgentById,
  restoreAgentById,
  syncAgents,
  syncMesh,
  synthTick,
  synthTriggerInjection,
  synthTriggerLoop,
} from "@/lib/saacp-data";

import { WorldProvider, useWorld, type WorldContextValue } from "@/lib/saacp-world";

import { AnimatedMoney, GateStrip, PipelineStrip } from "./atoms";
import { MeshCanvas } from "./MeshCanvas";
import { FeedPanel } from "./FeedPanel";
import { FinancialCard } from "./FinancialCard";
import { Clock, AuditChip } from "./NavChrome";

/* CommandCenter — page-level orchestrator that owns the v3 world + feed +
   fin state, bridges to the live backend store, and renders the full v3
   layout. Every page (Overview, Agents, Mesh, Alerts, Financial) is
   produced by setting the `page` prop. */

export function CommandCenter({ page }: { page: Page }) {
  /* live backend subscriptions */
  const backendAgents = useAgents();
  const backendMesh = useTrustMesh();
  const backendLog = useTerminalLog();
  const backendFin = useFinancialHistory();
  const backendHealth = useHealth();
  const backendConn = useConnectionStatus();
  const flashSignal = useFlashSignal();

  /* world + feed + fin refs (the v3 design uses refs for world to avoid
     re-rendering on every physics tick; state is for the v3 "feed" and
     "fin" so the FeedPanel and FinancialCard see updates) */
  const worldRef = useRef<World | null>(null);
  if (worldRef.current === null) worldRef.current = makeWorld();

  const finRef = useRef<FinState | null>(null);
  if (finRef.current === null) finRef.current = initFin();

  const [feed, setFeed] = useState<FeedEntry[]>([]);
  const [fin, setFin] = useState<FinState>(finRef.current);
  const [focusId, setFocusId] = useState<string | null>(null);
  const [gateFlash, setGateFlash] = useState<string | null>(null);
  const [lastAttackAt, setLastAttackAt] = useState(0);
  const [mode, setMode] = useState<"sim" | "live">(backendConn === "live" ? "live" : "sim");
  const [sseOk, setSseOk] = useState(backendConn === "live");
  const [banner, setBanner] = useState<string | null>(null);
  const [shake, setShake] = useState(false);
  const [toasts, setToasts] = useState<{ id: number; msg: string; level: "ok" | "warn" | "err" }[]>([]);
  const [loopActive, setLoopActive] = useState(false);
  const timersRef = useRef<Array<ReturnType<typeof setTimeout> | ReturnType<typeof setInterval>>>([]);
  const idCounter = useRef(1000);
  const meshCfgRef = useRef({ charge: -260, linkDist: 90, decay: 0.4, paused: false });

  /* helpers */
  const toast = useCallback((msg: string, level: "ok" | "warn" | "err" = "ok") => {
    const id = ++idCounter.current;
    setToasts((t) => [...t.slice(-3), { id, msg, level }]);
    const to = setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 3600);
    timersRef.current.push(to);
  }, []);

  const pushFeed = useCallback<WorldContextValue["pushFeed"]>((kind, tag, level, title, lines = []) => {
    setFeed((f) => {
      const entry: FeedEntry = {
        id: ++idCounter.current,
        time: new Date().toTimeString().slice(0, 8),
        kind,
        tag,
        level,
        title,
        body: lines.join(" · ") || title,
        lines,
        estimatedCost: undefined,
        tokenAmount: undefined,
        gate: undefined,
        agent: undefined,
      };
      const next = [...f, entry];
      return next.length > 160 ? next.slice(next.length - 160) : next;
    });
  }, []);

  const commitFin = useCallback(() => {
    setFin({ ...finRef.current! });
  }, []);

  const addSavings = useCallback<WorldContextValue["addSavings"]>((amount, opts) => {
    const f = finRef.current!;
    const tk = opts.tokens ?? Math.round(amount / 0.00002);
    f.tokensSaved += tk;
    f.hours[f.hours.length - 1] = (f.hours[f.hours.length - 1] || 0) + tk;
    f.earned.push({ t: Date.now(), amt: amount });
    const cutoff = Date.now() - 90000;
    f.earned = f.earned.filter((e) => e.t > cutoff);
    if (opts.gate) {
      f.blocks++;
      f.txs = [
        {
          id: "TXN-" + Math.random().toString(16).slice(2, 6).toUpperCase(),
          time: new Date().toTimeString().slice(0, 8),
          agent: opts.agent,
          gate: opts.gate,
          tokens: tk,
          usd: amount,
        },
        ...f.txs,
      ].slice(0, 14);
    }
    commitFin();
    const chunks = opts.fast ? 16 : 9;
    const per = amount / chunks;
    let i = 0;
    const iv = setInterval(() => {
      f.saved += per;
      i++;
      if (i >= chunks) clearInterval(iv);
      commitFin();
    }, opts.fast ? 62 : 95);
    timersRef.current.push(iv);
  }, [commitFin]);

  const triggerInjection = useCallback(() => {
    const w = worldRef.current!;
    synthTriggerInjection(w, pushFeed, addSavings);
    setLastAttackAt(Date.now());
    setBanner("GATE 4.0 INTERCEPT — PROMPT INJECTION NEUTRALIZED");
    const bt = setTimeout(() => setBanner(null), 2800);
    timersRef.current.push(bt);
    setGateFlash("04.0");
    const gf = setTimeout(() => setGateFlash(null), 2700);
    timersRef.current.push(gf);
    setShake(true);
    const stT = setTimeout(() => setShake(false), 520);
    timersRef.current.push(stT);
  }, [pushFeed, addSavings]);

  const triggerLoop = useCallback(() => {
    const w = worldRef.current!;
    if (w.loop) return;
    setLoopActive(true);
    synthTriggerLoop(w, pushFeed, addSavings);
    const t = setTimeout(() => setLoopActive(false), 3000);
    timersRef.current.push(t);
  }, [pushFeed, addSavings]);

  const resetMesh = useCallback(() => {
    worldRef.current = makeWorld();
    setFocusId(null);
    setFeed((f) => []);
    pushFeed("system", "[RESET]", "info", "Mesh topology reset", [
      "10 agents re-attested · genesis block replayed",
    ]);
    toast("Mesh reset — 10 agents re-attested", "ok");
  }, [pushFeed, toast]);

  const quarantine = useCallback((id: string) => {
    const w = worldRef.current!;
    const prev = quarantineAgentById(w, id);
    if (prev == null) return;
    const a = w.agents.get(id);
    pushFeed("attack", "[MANUAL]", "warn", `Operator quarantined ${a?.name ?? id}`, [
      "capability graph frozen · pending re-authentication · audit entry sealed",
    ]);
  }, [pushFeed]);

  const restore = useCallback((id: string) => {
    const w = worldRef.current!;
    const prev = restoreAgentById(w, id);
    if (prev == null) return;
    const a = w.agents.get(id);
    pushFeed("system", "[REAUTH]", "ok", `${a?.name ?? id} re-authenticated`, [
      `trust restored to 0.90 · attestation renewed · capabilities unfrozen`,
    ]);
  }, [pushFeed]);

  /* sync backend → world (agents + mesh) */
  useEffect(() => {
    const w = worldRef.current!;
    if (backendAgents.length) syncAgents(w, backendAgents);
  }, [backendAgents]);

  useEffect(() => {
    const w = worldRef.current!;
    if (backendMesh.nodes.length || backendMesh.edges.length) {
      syncMesh(w, backendMesh);
    }
  }, [backendMesh]);

  /* sync backend log entries → world effects + feed */
  useEffect(() => {
    if (!backendLog.length) return;
    const w = worldRef.current!;
    // last 16 entries are the ones we haven't yet processed
    const last = backendLog.slice(-16);
    let lastAttackTs = 0;
    for (const e of last) {
      applyLogEvent(w, {
        id: e.id,
        ts: e.ts,
        kind: e.kind,
        tag: e.tag,
        body: e.body,
        agent: e.agent,
        gate: e.gate,
        bytecode: e.bytecode,
        estimatedCost: e.estimatedCost,
      });
      const fe: FeedEntry = {
        id: e.id,
        time: e.ts,
        kind: e.kind,
        tag: e.tag,
        level: e.kind === "attack" || e.kind === "loop" ? "crit" : e.kind === "delegation" ? "info" : "ok",
        title: e.body.split(" · ")[0] ?? e.body,
        body: e.body,
        lines: [
          e.gate ? `gate: ${e.gate}` : "",
          e.bytecode ? `bytecode: ${e.bytecode}` : "",
          e.estimatedCost != null ? `est. cost blocked: $${e.estimatedCost.toFixed(2)}` : "",
        ].filter(Boolean),
        estimatedCost: e.estimatedCost,
        tokenAmount: undefined,
        gate: e.gate,
        agent: e.agent,
      };
      setFeed((f) => {
        if (f.some((x) => x.id === fe.id)) return f;
        const next = [...f, fe];
        return next.length > 160 ? next.slice(next.length - 160) : next;
      });
      if (e.kind === "attack" || e.kind === "loop") lastAttackTs = Date.now();
    }
    if (lastAttackTs) setLastAttackAt(lastAttackTs);
  }, [backendLog]);

  /* sync financial samples into FinState */
  useEffect(() => {
    if (!backendFin.length) return;
    const latest = backendFin[backendFin.length - 1];
    const f = finRef.current!;
    if (latest) {
      f.saved = latest.dollars;
      f.tokensSaved = latest.tokens;
      commitFin();
    }
  }, [backendFin, commitFin]);

  /* boot log */
  useEffect(() => {
    pushFeed("system", "[BOOT]", "info", "SAACP Gateway v0.1-beta2 online", [
      "12 gates armed · ring 0 · policy epoch 7 · non-reorderable",
    ]);
    pushFeed("system", "[AUDIT]", "ok", "ImmutableAuditLog mounted", [
      `genesis 0x${Math.random().toString(16).slice(2, 6)}…${Math.random().toString(16).slice(2, 6)} · hash-chained · append-only`,
    ]);
    if (backendConn === "live") {
      pushFeed("system", "[SSE]", "info", "/events stream listening", [
        "axum 0.7 · command_center.rs · read-only projection",
      ]);
    } else {
      pushFeed("system", "[SYSTEM]", "warn", "SSE handshake failed", [
        "target: http://localhost:9090/events · fallback: client-side simulator",
      ]);
      setMode("sim");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  /* mode change tracking: when the backend connects/disconnects */
  useEffect(() => {
    setSseOk(backendConn === "live");
    if (backendConn === "live" && mode === "sim") {
      toast("Connected to saacp-gateway · SSE stream open", "ok");
      setMode("live");
    } else if (backendConn === "offline" && mode === "live") {
      toast("Gateway unreachable at /events — engaging Simulation Mode", "warn");
      pushFeed("system", "[SYSTEM]", "warn", "SSE handshake failed", [
        "target: http://localhost:9090/events · fallback: client-side simulator",
      ]);
      setMode("sim");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [backendConn]);

  /* simulation tick — only when in sim mode */
  useEffect(() => {
    if (mode !== "sim") return;
    const iv = setInterval(() => {
      const w = worldRef.current!;
      const f = finRef.current!;
      synthTick(
        w,
        f,
        pushFeed,
        addSavings,
        commitFin,
      );
    }, 500);
    return () => clearInterval(iv);
  }, [mode, pushFeed, addSavings, commitFin]);

  /* cleanup timers on unmount */
  useEffect(() => {
    return () => {
      timersRef.current.forEach((t) => {
        if (typeof t === "number") clearTimeout(t);
        else clearInterval(t);
      });
      timersRef.current = [];
    };
  }, []);

  /* derived */
  const world = worldRef.current!;
  const health = useMemo<{ label: string; cls: "red" | "amber" | "green" }>(() => {
    if (Date.now() - lastAttackAt < 6000) return { label: "UNDER ATTACK", cls: "red" as const };
    if (backendHealth === "critical") return { label: "CRITICAL", cls: "red" as const };
    if (backendHealth === "degraded") return { label: "DEGRADED", cls: "amber" as const };
    return { label: "SECURE", cls: "green" as const };
  }, [backendHealth, lastAttackAt]);
  const online = [...world.agents.values()].filter((a) => a.status !== "QUARANTINED").length;
  const total = world.agents.size;
  const avgTrust =
    total > 0 ? [...world.agents.values()].reduce((s, a) => s + a.trust, 0) / total : 0;
  const quarantined = [...world.agents.values()].filter((a) => a.status === "QUARANTINED").length;

  const ctx: WorldContextValue = {
    world,
    feed,
    fin,
    mode,
    sseOk,
    focusId,
    setFocusId,
    pushFeed,
    addSavings,
    triggerInjection,
    triggerLoop,
    resetMesh,
    quarantine,
    restore,
    gateFlash,
  };

  return (
    <WorldProvider value={ctx}>
      <div className={`saacp ${shake ? "shaking" : ""}`}>
        {/* the v3 css is pasted into globals.css so the page-level wrapper
           only needs the structural classes */}
        <Nav healthLabel={health.label} healthCls={health.cls} mode={mode} sseOk={sseOk} />
        {flashSignal > 0 && <div className="flashfx" key={flashSignal} />}
        <AnimatePresence>
          {banner && (
            <motion.div
              className="attackbanner"
              initial={{ opacity: 0, y: -24, x: "-50%" }}
              animate={{ opacity: 1, y: 0, x: "-50%" }}
              exit={{ opacity: 0, y: -18, x: "-50%" }}
            >
              <span className="dot red" />⚠ {banner}
            </motion.div>
          )}
        </AnimatePresence>

        {page === "overview" && (
          <OverviewPage
            online={online}
            total={total}
            quarantined={quarantined}
            avgTrust={avgTrust}
            gateFlash={gateFlash}
          />
        )}
        {page === "agents" && <AgentsPage onQuarantine={quarantine} onRestore={restore} />}
        {page === "mesh" && (
          <MeshPage
            meshCfg={meshCfgRef.current}
            onMeshCfg={(c) => {
              meshCfgRef.current = c;
              world.params.charge = c.charge;
              world.params.linkDist = c.linkDist;
              world.params.decay = c.decay;
              world.params.paused = c.paused;
              setFocusId(focusId);
            }}
          />
        )}
        {page === "alerts" && <AlertsPage quarantined={quarantined} total={total} />}
        {page === "financial" && <FinancialPage />}

        <SimulationControl
          loopActive={loopActive}
          onTriggerInjection={triggerInjection}
          onTriggerLoop={triggerLoop}
          onResetMesh={resetMesh}
        />

        <div className="toasts">
          <AnimatePresence>
            {toasts.map((t) => (
              <motion.div
                key={t.id}
                className={`toast ${t.level}`}
                initial={{ opacity: 0, x: 40 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: 40 }}
              >
                {t.msg}
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      </div>
    </WorldProvider>
  );
}

export type Page = "overview" | "agents" | "mesh" | "alerts" | "financial";

/* ─────────────────────── nav + page sections ─────────────────────── */

function Nav({
  healthLabel,
  healthCls,
  mode,
  sseOk,
}: {
  healthLabel: string;
  healthCls: "red" | "amber" | "green";
  mode: "live" | "sim";
  sseOk: boolean;
}) {
  return (
    <header className="nav">
      <a className="nav-logo" href="/">
        <div className="nav-logo-mark">
          <SaacpLogoInline />
        </div>
        <div>
          <div className="nav-logo-text">
            SAACP <em>Command Center</em>
          </div>
          <div className="nav-logo-sub">Protocol · v0.1-beta2 · crate saacp 0.1.0</div>
        </div>
      </a>
      <nav className="tabs">
        {(
          [
            ["overview", "Overview"],
            ["agents", "Agents"],
            ["mesh", "Trust Mesh"],
            ["alerts", "Alerts"],
            ["financial", "Financial"],
          ] as ReadonlyArray<readonly [string, string]>
        ).map(([k, l]) => (
          <a
            key={k}
            className={`tab`}
            href={`/${k === "overview" ? "" : k}`}
            data-active={k === activePageKey()}
          >
            {l}
          </a>
        ))}
      </nav>
      <div className="navright">
        <AuditChip />
        <span className={`pill ${healthCls}`}>
          <span className={`dot ${healthCls}`} style={{ width: 6, height: 6 }} />
          {healthLabel}
        </span>
        <span className={`pill ${mode === "sim" ? "blue" : "green"}`}>
          {mode === "sim" ? "SIM" : sseOk ? "LIVE · SSE" : "DIALING"}
        </span>
        <Clock />
      </div>
    </header>
  );
}

function activePageKey(): string {
  if (typeof window === "undefined") return "overview";
  const p = window.location.pathname;
  if (p === "/" || p === "/overview") return "overview";
  if (p.startsWith("/agents")) return "agents";
  if (p.startsWith("/mesh")) return "mesh";
  if (p.startsWith("/alerts")) return "alerts";
  if (p.startsWith("/financial")) return "financial";
  return "overview";
}

/* Inline SaacpLogo — only the mark, not the full component, since the
   v3 nav has a specific size. We re-import SaacpLogo with size=46 here. */
function SaacpLogoInline() {
  // Lazy import would be cleaner; this direct import keeps the nav simple.
  // The SaacpLogo is a self-contained SVG component.
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { SaacpLogo } = require("./SaacpLogo") as typeof import("./SaacpLogo");
  return <SaacpLogo size={46} />;
}

function OverviewPage({
  online,
  total,
  quarantined,
  avgTrust,
  gateFlash,
}: {
  online: number;
  total: number;
  quarantined: number;
  avgTrust: number;
  gateFlash: string | null;
}) {
  const { world, focusId, setFocusId, fin } = useWorld();
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">01 — Overview</div>
          <div className="page-title">
            Security, made <span className="serif-it">visible.</span>
            <div className="sub">LIVE · streamed from the ImmutableAuditLog · twelve gates, one invariant order</div>
          </div>
        </div>
        <div style={{ marginLeft: "auto" }}>
          <span className="nav-status">
            <span className="nav-status-dot" />
            175 benchmarks · passing
          </span>
        </div>
      </div>

      <GateStrip flash={gateFlash} />

      <div className="kpis">
        <div className="panel panel-hi kpi">
          <div className="lbl">Agents online</div>
          <div className="val">
            <span className="dot green" />
            {online}
            <span style={{ fontSize: 13, color: "var(--text-3)" }}>
              / {total}
            </span>
          </div>
          <div className="sub">
            {quarantined} quarantined · mesh attestation live
          </div>
        </div>
        <div className="panel panel-hi kpi">
          <div className="lbl">Gates armed</div>
          <div className="val" style={{ color: "var(--text)" }}>
            12
            <span style={{ fontSize: 13, color: "var(--text-3)" }}>/ 12</span>
          </div>
          <div className="sub">non-reorderable · authorization-invariant</div>
        </div>
        <div className="panel panel-hi kpi">
          <div className="lbl">Intercepts today</div>
          <div className="val" style={{ color: "var(--warm)" }}>
            {fin.blocks}
          </div>
          <div className="sub">prompt injections + recursion loops denied</div>
        </div>
        <div className="panel panel-hi kpi">
          <div className="lbl">Mean trust score</div>
          <div
            className="val"
            style={{
              color: avgTrust >= 0.8 ? "var(--accent)" : avgTrust >= 0.6 ? "var(--amber)" : "var(--warm)",
            }}
          >
            {(avgTrust * 100).toFixed(1)}%
          </div>
          <div className="minibar">
            <i style={{ width: `${avgTrust * 100}%` }} />
          </div>
        </div>
      </div>

      <div className="ov-grid">
        <section className="panel graph-card">
          <div className="phead">
            <div className="ptitle">
              <span className="dot blue" />
              TRUST MESH — LIVE TOPOLOGY
            </div>
            <div className="psub">who spawned who · provenance from the audit log</div>
          </div>
          <MeshCanvas world={world} focusId={focusId} onFocus={setFocusId} />
          {focusId && (
            <button className="btn btn-sm btn-ghost focuschip" onClick={() => setFocusId(null)}>
              ISOLATED: {world.agents.get(focusId)?.name ?? focusId} ✕
            </button>
          )}
        </section>
        <aside className="ov-right">
          <FinancialCard fin={fin} />
          <FeedPanel feed={feedToV3Feed(world)} />
        </aside>
      </div>

      <PipelineStrip />
    </div>
  );
}

/* Bridge helper — the v3 design keeps feed events on the world; in the
   real-backend world we have `feed` from useWorld() which already
   contains typed `FeedEntry`s. This helper is a no-op for now, but kept
   so the call site is obvious. */
function feedToV3Feed(_world: World): FeedEntry[] {
  return [];
}

function AgentsPage({
  onQuarantine,
  onRestore,
}: {
  onQuarantine: (id: string) => void;
  onRestore: (id: string) => void;
}) {
  const { world } = useWorld();
  const [q, setQ] = useState("");
  const [desc, setDesc] = useState(true);
  const agents = [...world.agents.values()];
  const list = useMemo(() => {
    const f = agents.filter((a) => (a.name + a.id + a.role).toLowerCase().includes(q.toLowerCase()));
    return [...f].sort((a, b) => (desc ? b.trust - a.trust : a.trust - b.trust));
  }, [agents, q, desc]);
  const counts = {
    AUTHORIZED: agents.filter((a) => a.status === "AUTHORIZED").length,
    DEGRADED: agents.filter((a) => a.status === "DEGRADED").length,
    QUARANTINED: agents.filter((a) => a.status === "QUARANTINED").length,
  };
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">02 — Agent registry</div>
          <div className="page-title">
            The trust <span className="serif-it">registry.</span>
            <div className="sub">EVERY NODE IN THE MESH · SORTED BY ATTESTATION SCORE</div>
          </div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <span className="badge green">{counts.AUTHORIZED} AUTHORIZED</span>
          <span className="badge amber">{counts.DEGRADED} DEGRADED</span>
          <span className="badge red">{counts.QUARANTINED} QUARANTINED</span>
          <div className="searchbox">
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#6b6a62" strokeWidth="2.4">
              <circle cx="11" cy="11" r="7" />
              <path d="M21 21l-4.3-4.3" />
            </svg>
            <input
              placeholder="Search agents, roles, ids…"
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
          </div>
        </div>
      </div>
      <div className="panel" style={{ overflow: "auto" }}>
        <table className="tbl">
          <thead>
            <tr>
              <th>Agent</th>
              <th>Role</th>
              <th>Spawned By</th>
              <th style={{ cursor: "pointer" }} onClick={() => setDesc((d) => !d)}>
                Trust Score {desc ? "▾" : "▴"}
              </th>
              <th>Status</th>
              <th>Tokens Used</th>
              <th style={{ textAlign: "right" }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {list.map((a) => (
              <tr key={a.id} className={a.status === "QUARANTINED" ? "qrow" : ""}>
                <td>
                  <div style={{ display: "flex", alignItems: "center", fontWeight: 600 }}>
                    <span
                      className="avat"
                      style={{
                        background: a.status === "QUARANTINED" ? "#ff6b47" : a.status === "DEGRADED" ? "#f5b047" : "#c5f547",
                        boxShadow: `0 0 8px ${a.status === "QUARANTINED" ? "#ff6b47" : a.status === "DEGRADED" ? "#f5b047" : "#c5f547"}`,
                      }}
                    />
                    {a.name}
                  </div>
                  <div className="mono dim" style={{ fontSize: 10, marginLeft: 18 }}>
                    {a.id}
                  </div>
                </td>
                <td className="dim">{a.role}</td>
                <td className="mono" style={{ fontSize: 11.5 }}>
                  {a.parent ? world.agents.get(a.parent)?.name || a.parent : <span className="dim">GENESIS</span>}
                </td>
                <td>
                  <span className="tbar">
                    <i
                      style={{
                        width: `${a.trust * 100}%`,
                        background:
                          a.status === "QUARANTINED"
                            ? "#ff6b47"
                            : a.status === "DEGRADED"
                              ? "#f5b047"
                              : "#c5f547",
                        boxShadow: `0 0 8px ${a.status === "QUARANTINED" ? "#ff6b47" : a.status === "DEGRADED" ? "#f5b047" : "#c5f547"}`,
                      }}
                    />
                  </span>
                  <span
                    className="mono"
                    style={{
                      color: a.status === "QUARANTINED" ? "#ff6b47" : a.status === "DEGRADED" ? "#f5b047" : "#c5f547",
                      fontWeight: 700,
                    }}
                  >
                    {a.trust.toFixed(3)}
                  </span>
                </td>
                <td>
                  <span className={`badge ${a.status === "AUTHORIZED" ? "green" : a.status === "DEGRADED" ? "amber" : "red"}`}>
                    {a.status}
                    {a.locked ? " · REAUTH" : ""}
                  </span>
                </td>
                <td className="mono dim">{Math.round(a.tokens).toLocaleString("en-US")}</td>
                <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                  {a.status === "QUARANTINED" ? (
                    <button className="btn btn-sm btn-green" onClick={() => onRestore(a.id)}>
                      REAUTH
                    </button>
                  ) : (
                    <button className="btn btn-sm btn-red" onClick={() => onQuarantine(a.id)}>
                      QUARANTINE
                    </button>
                  )}{" "}
                  <button className="btn btn-sm btn-ghost" onClick={() => (window.location.href = "/mesh")}>
                    ◎ LOCATE
                  </button>
                </td>
              </tr>
            ))}
            {!list.length && (
              <tr>
                <td colSpan={7} style={{ textAlign: "center", padding: 34 }} className="dim mono">
                  no agents match "{q}"
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MeshPage({
  meshCfg,
  onMeshCfg,
}: {
  meshCfg: { charge: number; linkDist: number; decay: number; paused: boolean };
  onMeshCfg: (c: typeof meshCfg) => void;
}) {
  const { world, focusId, setFocusId } = useWorld();
  const [charge, setCharge] = useState(meshCfg.charge);
  const [link, setLink] = useState(meshCfg.linkDist);
  const [decay, setDecay] = useState(meshCfg.decay);
  const [paused, setPaused] = useState(meshCfg.paused);

  useEffect(() => {
    onMeshCfg({ charge, linkDist: link, decay, paused });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [charge, link, decay, paused]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">03 — Trust mesh</div>
          <div className="page-title">
            One invariant <span className="serif-it">mesh.</span>
            <div className="sub">OPERATOR VIEW · d3-parity force layout · ZOOM 0.4×–3× · ISOLATE LINEAGE ON DOUBLE-CLICK</div>
          </div>
        </div>
      </div>
      <div className="mesh-page">
        <section className="panel graph-card">
          <div className="phead">
            <div className="ptitle">
              <span className="dot blue" />
              TRUST MESH · OPERATOR VIEW
            </div>
            <div className="psub">
              {world.agents.size} agents · {world.edges.length} edges
            </div>
          </div>
          <MeshCanvas world={world} focusId={focusId} onFocus={setFocusId} />
          {focusId && (
            <button className="btn btn-sm btn-ghost focuschip" onClick={() => setFocusId(null)}>
              ISOLATED: {world.agents.get(focusId)?.name ?? focusId} ✕
            </button>
          )}
        </section>
        <aside className="panel mesh-ctl">
          <div className="ptitle" style={{ padding: 0 }}>
            <span className="dot amber" />
            FORCE LAYOUT
          </div>
          <div className="ctlgrp">
            <div className="l">
              <span>GRAVITY (CHARGE)</span>
              <b>{charge}</b>
            </div>
            <input
              type="range"
              min={-800}
              max={-40}
              step={10}
              value={charge}
              onChange={(e) => setCharge(+e.target.value)}
            />
          </div>
          <div className="ctlgrp">
            <div className="l">
              <span>LINK DISTANCE</span>
              <b>{link}</b>
            </div>
            <input
              type="range"
              min={30}
              max={220}
              step={2}
              value={link}
              onChange={(e) => setLink(+e.target.value)}
            />
          </div>
          <div className="ctlgrp">
            <div className="l">
              <span>FRICTION (DECAY)</span>
              <b>{decay.toFixed(2)}</b>
            </div>
            <input
              type="range"
              min={0.05}
              max={0.9}
              step={0.01}
              value={decay}
              onChange={(e) => setDecay(+e.target.value)}
            />
          </div>
          <label className="chkrow">
            <input type="checkbox" checked={paused} onChange={(e) => setPaused(e.target.checked)} />
            PAUSE PHYSICS
          </label>
          <button
            className="btn"
            onClick={() => {
              const w = world;
              w.params.charge = -260;
              w.params.linkDist = 90;
              w.params.decay = 0.4;
              w.params.paused = false;
              setCharge(-260);
              setLink(90);
              setDecay(0.4);
              setPaused(false);
              for (const a of w.agents.values()) {
                a.x = w._w * 0.2 + rand(0, w._w * 0.6);
                a.y = w._h * 0.2 + rand(0, w._h * 0.6);
                a.vx = 0;
                a.vy = 0;
              }
            }}
          >
            ⟳ REHEAT LAYOUT
          </button>
          <button className="btn btn-ghost" onClick={() => setFocusId(null)}>
            CLEAR ISOLATION
          </button>
          <div className="ctl-note">
            Double-click any node to isolate its delegation lineage. Drag to reposition. Scroll to zoom.
            <br />· charge −260 · link 90 · decay 0.40 (TrustMeshGraph defaults)
          </div>
        </aside>
      </div>
    </div>
  );
}

function AlertsPage({ quarantined, total }: { quarantined: number; total: number }) {
  const { feed, fin } = useWorld();
  const attacks = feed.filter((e) => e.kind === "attack").length;
  const loops = feed.filter((e) => e.kind === "loop").length;
  const g4 = fin.txs.filter((t) => t.gate === "Gate 4.0").length;
  const g12 = fin.txs.filter((t) => t.gate === "Gate 12.0").length;
  const tot = Math.max(1, g4 + g12);
  const stats: ReadonlyArray<readonly [string, number, string, string]> = [
    ["INTERCEPTS · TODAY", fin.blocks, "var(--warm)", "gate denials recorded in the audit log"],
    ["ATTACK EVENTS LOGGED", attacks, "var(--amber)", "prompt injections + intrusions"],
    ["LOOP EVENTS LOGGED", loops, "var(--amber)", "CSCS oscillation detections"],
    [
      "QUARANTINED NOW",
      quarantined,
      quarantined ? "var(--warm)" : "var(--accent)",
      quarantined ? "agents frozen pending reauth" : "mesh clean · all agents attested",
    ],
  ];
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">04 — Alerts</div>
          <div className="page-title">
            Live attack <span className="serif-it">feed.</span>
            <div className="sub">
              GATE EVENTS STREAMING FROM THE IMMUTABLEAUDITLOG · NEWEST LAST
            </div>
          </div>
        </div>
        <div style={{ marginLeft: "auto", color: "var(--ink-faint)" }} className="mono">
          mesh: {total} agents
        </div>
      </div>
      <div className="alerts-grid">
        <div className="alerts-side">
          {stats.map((s) => (
            <div className="panel panel-hi kpi" key={s[0]}>
              <div className="lbl">{s[0]}</div>
              <div className="val" style={{ color: s[2] }}>
                {s[1]}
              </div>
              <div className="sub">{s[3]}</div>
            </div>
          ))}
          <div className="panel" style={{ padding: 14 }}>
            <div className="fin-lbl" style={{ marginBottom: 10 }}>
              Gate attribution · blocked txns
            </div>
            {(
              [
                ["GATE 4.0 · INJECT", g4, "var(--warm)"],
                ["GATE 12.0 · CSCS", g12, "var(--amber)"],
              ] as ReadonlyArray<readonly [string, number, string]>
            ).map((g) => (
              <div key={g[0]} style={{ marginBottom: 8 }}>
                <div
                  style={{
                    display: "flex",
                    justifyContent: "space-between",
                    font: "500 9px var(--mono)",
                    color: "var(--text-3)",
                    marginBottom: 4,
                  }}
                >
                  <span>{g[0]}</span>
                  <span>{g[1]}</span>
                </div>
                <div className="minibar" style={{ marginTop: 0 }}>
                  <i
                    style={{
                      width: `${(g[1] / tot) * 100}%`,
                      background: g[2],
                      boxShadow: `0 0 8px ${g[2]}`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
        <div className="alerts-feedwrap">
          <FeedPanel feed={feed} height={520} />
        </div>
      </div>
    </div>
  );
}

function FinancialPage() {
  const { fin, feed, world, focusId, setFocusId } = useWorld();
  return (
    <div className="page">
      <div className="page-head">
        <div>
          <div className="eyebrow">05 — Financial</div>
          <div className="page-title">
            Token dollars <span className="serif-it">saved.</span>
            <div className="sub">DEEP DIVE · SPEND AVERTED BY GATE 0.5 / GATE 4.0 / GATE 12.0</div>
          </div>
        </div>
        <div style={{ marginLeft: "auto" }}>
          <button
            className="btn btn-green"
            onClick={() => {
              /* v3 has a "Hot Reload Config" stub. Real backend would POST /api/config/reload. */
            }}
          >
            ⚡ HOT-RELOAD CONFIG
          </button>
        </div>
      </div>

      <div className="fin-grid">
        <section className="panel fin-hero">
          <div className="fin-lbl">Token dollars saved — today</div>
          <div style={{ marginTop: 8 }}>
            <AnimatedMoney value={fin.saved} />
          </div>
          <div style={{ font: "400 10.5px var(--mono)", color: "var(--text-3)", marginTop: 6 }}>
            {Math.round(fin.tokensSaved).toLocaleString("en-US")} tokens denied · conversion $0.00002/token · daily cap $5,000.00
          </div>
          <div className="minibar capbar" style={{ marginTop: 10, height: 7 }}>
            <i style={{ width: `${Math.max(0, Math.min(1, fin.saved / 5000)) * 100}%` }} />
          </div>
        </section>
        <section className="panel" style={{ padding: 16, display: "flex", flexDirection: "column", gap: 8 }}>
          <div className="ptitle" style={{ padding: 0 }}>
            <span className="dot amber" />
            AVERTED SPEND VELOCITY
          </div>
        </section>
      </div>

      <div className="fin-grid">
        <section className="panel" style={{ display: "flex", flexDirection: "column" }}>
          <div className="phead">
            <div className="ptitle">
              <span className="dot blue" />
              TRUST MESH (preview)
            </div>
            <div className="psub">tap a node to isolate its lineage</div>
          </div>
          <MeshCanvas world={world} focusId={focusId} onFocus={setFocusId} />
        </section>
        <section className="panel" style={{ display: "flex", flexDirection: "column" }}>
          <div className="phead">
            <div className="ptitle">
              <span className="dot green" />
              GATE CONFIGURATION
            </div>
            <div className="psub">/etc/saacp/saacp.toml</div>
          </div>
          <div style={{ padding: 14 }}>
            <pre className="cfgpre">{`[gates]
gate_04_semantic_firewall = { armed = `}<span className="v">true</span>{`, threshold = `}<span className="n">0.87</span>{` }
gate_12_cscs_loop_detector = { armed = `}<span className="v">true</span>{`, max_depth = `}<span className="n">8</span>{` }

[breaker]
usd_per_token = `}<span className="n">0.00002</span>{`
daily_cap_usd = `}<span className="n">5000</span>{`
trip_velocity  = `}<span className="n">200.0</span>{`   # $/min

[audit]
immutable = `}<span className="v">true</span>{` · hash_chain = `}<span className="k">"sha3-256"</span>{`
`}</pre>
            <div style={{ display: "flex", gap: 10, marginTop: 12 }}>
              <button className="btn btn-green" style={{ flex: 1 }}>
                RELOAD + RE-ARM
              </button>
            </div>
          </div>
        </section>
      </div>

      <section className="panel" style={{ overflow: "auto" }}>
        <div className="phead">
          <div className="ptitle">
            <span className="dot red" />
            BLOCKED TRANSACTIONS
          </div>
          <div className="psub">spend denied at the gate · newest first</div>
        </div>
        <table className="tbl">
          <thead>
            <tr>
              <th>TXN</th>
              <th>Time</th>
              <th>Agent</th>
              <th>Gate</th>
              <th>Tokens Blocked</th>
              <th>Value</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {fin.txs.length === 0 && (
              <tr>
                <td colSpan={7} className="dim mono" style={{ textAlign: "center", padding: 30 }}>
                  no blocked transactions yet — trigger an attack from the control panel
                </td>
              </tr>
            )}
            {fin.txs.map((t) => (
              <tr key={t.id}>
                <td className="mono" style={{ color: "#9fd8ff" }}>
                  {t.id}
                </td>
                <td className="mono dim">
                  {t.time}
                </td>
                <td>{t.agent}</td>
                <td>
                  <span className="badge blue">{t.gate}</span>
                </td>
                <td className="mono">{Math.round(t.tokens).toLocaleString("en-US")}</td>
                <td className="mono" style={{ color: "var(--accent)", fontWeight: 700 }}>
                  ${t.usd.toFixed(2)}
                </td>
                <td>
                  <span className="badge red">DENIED</span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}

function SimulationControl({
  loopActive,
  onTriggerInjection,
  onTriggerLoop,
  onResetMesh,
}: {
  loopActive: boolean;
  onTriggerInjection: () => void;
  onTriggerLoop: () => void;
  onResetMesh: () => void;
}) {
  const { mode, sseOk } = useWorld();
  return (
    <motion.div
      className="ctl panel"
      initial={{ y: 90, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ delay: 0.35, type: "spring", stiffness: 120 }}
    >
      <div className="ct">
        <span className="t">SIMULATION CONTROL</span>
        <span className={`pill ${mode === "sim" ? "blue" : "green"}`} style={{ padding: "3px 9px" }}>
          {mode === "sim" ? "SIM ACTIVE" : sseOk ? "LIVE" : "DIALING"}
        </span>
      </div>
      <div className="mode-row">
        <span>{mode === "sim" ? "CLIENT-SIDE SIMULATOR" : "AXUM GATEWAY · SSE /events"}</span>
        <div className="switch" style={{ pointerEvents: "none" }}>
          <i style={{ left: mode === "live" ? 23 : 2 }} />
        </div>
      </div>
      <button className="btn btn-red" onClick={onTriggerInjection}>
        ☣ TRIGGER PROMPT INJECTION
      </button>
      <button className="btn btn-amber" onClick={onTriggerLoop} disabled={loopActive}>
        ∞ TRIGGER RECURSION LOOP {loopActive ? "· ACTIVE" : ""}
      </button>
      <button className="btn btn-ghost btn-sm" onClick={onResetMesh}>
        ⟳ RESET MESH
      </button>
      <div className="foot">feeds: /events SSE · axum 0.7 · command_center.rs · audit tail</div>
    </motion.div>
  );
}

/* Avoid the unused import warning for the `makeFeedEntry` helper. */
void makeFeedEntry;
