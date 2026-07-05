// Trust-score -> status mapping, shared across the agent list and mesh graph.
// Status colors are the dataviz skill's fixed, never-themed status palette
// (good/warning/serious/critical) — see dashboard-ui/app/globals.css's
// --status-* custom properties.

export type TrustStatus = "good" | "warning" | "serious" | "critical";

export function trustStatus(score: number, requiresReauth: boolean): TrustStatus {
  if (requiresReauth || score < 0.25) return "critical";
  if (score < 0.5) return "serious";
  if (score < 0.75) return "warning";
  return "good";
}

export function trustStatusLabel(status: TrustStatus): string {
  switch (status) {
    case "good": return "Trusted";
    case "warning": return "Watch";
    case "serious": return "Degraded";
    case "critical": return "Reauth Required";
  }
}
