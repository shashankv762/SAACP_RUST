"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useConnectionStatus, useHealth } from "@/lib/store";

const LINKS = [
  { href: "/", label: "Overview" },
  { href: "/agents", label: "Agents" },
  { href: "/mesh", label: "Trust Mesh" },
  { href: "/alerts", label: "Alerts" },
  { href: "/financial", label: "Financial" },
];

const HEALTH_LABEL: Record<string, string> = {
  nominal: "NOMINAL",
  degraded: "DEGRADED",
  critical: "CRITICAL",
};

const HEALTH_COLOR: Record<string, string> = {
  nominal: "var(--safe)",
  degraded: "var(--warn)",
  critical: "var(--crit)",
};

const CONN_LABEL: Record<string, string> = {
  connecting: "CONNECTING…",
  live: "LIVE",
  offline: "OFFLINE",
};

export function Nav() {
  const pathname = usePathname();
  const health = useHealth();
  const connection = useConnectionStatus();

  return (
    <nav className="nav">
      <div className="brand">
        <div className="brand-mark" />
        <div>
          <div className="brand-name">SAACP</div>
          <div className="brand-sub mono">COMMAND CENTER</div>
        </div>
      </div>

      <div className="tabs" role="tablist">
        {LINKS.map((l) => {
          const active = l.href === "/" ? pathname === "/" : pathname.startsWith(l.href);
          return (
            <Link key={l.href} href={l.href} className={`tab${active ? " active" : ""}`}>
              {l.label}
            </Link>
          );
        })}
      </div>

      <div className="nav-right">
        <div className="health">
          <span className={`ring${health === "nominal" ? "" : " " + health}`} />
          <span className="health-label">Network</span>
          <span className="health-state" style={{ color: HEALTH_COLOR[health] }}>
            {HEALTH_LABEL[health]}
          </span>
        </div>
        <span
          className={`conn${connection === "live" ? " live" : connection === "offline" ? " offline" : ""}`}
        >
          {CONN_LABEL[connection]}
        </span>
      </div>
    </nav>
  );
}
