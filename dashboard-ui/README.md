# SAACP Command Center — dashboard-ui

Next.js (App Router) + TypeScript frontend for the SAACP Command Center backend
(`../src/command_center.rs`, `command-center` Cargo feature). Entirely separate from the
Rust build — nothing here is referenced by `Cargo.toml`, and this directory has zero
effect on `cargo build`/`cargo test`.

## What it shows

- **Overview** — the live trust mesh, a scrolling attack-feed terminal, and the ROI
  odometer ("estimated exposure prevented") on one screen.
- **Agents** — live agent list with continuous behavioral trust scores (`TrustDecayEngine`),
  searchable and sortable, with a real `requires_reauth` column.
- **Trust Mesh** — a D3 force-directed graph of capability-grant edges (who has delegated
  what to whom), fed by `sidecar.rs::send_message`'s delegation-logging, nodes colored by
  live trust score with animated delegation pulses and quarantine shockwaves.
- **Alerts** — a live feed of gate rejections (Gate 4.0 prompt-injection blocks, Gate 12.0
  CSCS loop detection, Gate 0.5 financial circuit breaker, etc.), pushed over Server-Sent
  Events.
- **Financial** — "Tokens Rejected" / estimated exposure prevented by the Gate 0.5 Financial
  Circuit Breaker, a live session chart, a real per-event Blocked Transactions ledger
  (Gate 0.5 rejections carry a real `estimated_cost`), and a **Reload Config** button wired
  to the real `POST /api/config/reload` endpoint.

There is **no simulation mode** — every number and event on screen comes from the real
backend. When the backend is unreachable the connection pill shows `OFFLINE` and the views
stay empty rather than inventing data.

## Running it

1. Start the backend (from the repo root):
   ```sh
   SAACP_DASHBOARD_TOKEN=<base64 32 bytes> cargo run --bin saacp-command-center --features command-center
   ```
   This also starts a bare demo `SAACPNetworkDaemon` on `127.0.0.1:7444` and a synthetic
   activity generator (`command_center_demo.rs`) that drives live agents, trust-mesh edges,
   gate rejections and Gate 0.5 financial blocks through the same global engines a real
   gateway drives — so every panel is populated the moment you open the dashboard. Both are
   demo-only and share one opt-out: `SAACP_DISABLE_DEMO_DAEMON=1` runs the dashboard alone
   against a real gateway process's shared state, with zero synthetic data. See
   `src/bin/saacp_command_center.rs`'s doc comment for all environment variables.

2. Configure this frontend:
   ```sh
   cp .env.local.example .env.local
   # fill in NEXT_PUBLIC_DASHBOARD_TOKEN with the hex encoding of the same 32 bytes
   # SAACP_DASHBOARD_TOKEN decoded to (see .env.local.example for the one-liner)
   ```

3. Run it:
   ```sh
   npm install
   npm run dev
   ```
   Then open http://localhost:3000.

## Notes

- The dashboard runs on a **different origin** than the backend (this app on
  `http://localhost:3000`, the backend on `http://127.0.0.1:9090`), so the backend
  must allow this origin via CORS or the browser blocks every `fetch`/`EventSource`
  call. `src/command_center.rs` allowlists `http://localhost:3000` and
  `http://127.0.0.1:3000` by default; override with the backend's
  `SAACP_DASHBOARD_ALLOWED_ORIGINS` env var (comma-separated, exact-match) if you
  serve this UI from a different host/port. The allowlist is exact-match and
  fail-closed — no wildcard.
- The dashboard token is compiled into the client bundle via `NEXT_PUBLIC_*` — the same
  "operator-only, not multi-tenant-public" tradeoff the backend itself makes by accepting
  the token as an SSE `?token=` query parameter (browsers' `EventSource` can't set custom
  headers). Fine for a local/internal ops dashboard; not meant for public deployment as-is.
- Live updates ride entirely on **one** `/events` Server-Sent-Events connection per open
  tab (auto-reconnecting, native `EventSource` behavior), opened once by the shared
  `lib/store.tsx` provider and fanned out to every view — no per-component connections, no
  WebSocket. A handful of REST endpoints are polled on a low cadence (financial every ~4s,
  deep-health `/api/readyz` every ~8s, agents/mesh snapshots every ~12–15s) to correct any
  drift and drive the network-health indicator.
