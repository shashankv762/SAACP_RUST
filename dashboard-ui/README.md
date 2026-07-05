# SAACP Command Center — dashboard-ui

Next.js (App Router) + TypeScript frontend for the SAACP Command Center backend
(`../src/command_center.rs`, `command-center` Cargo feature). Entirely separate from the
Rust build — nothing here is referenced by `Cargo.toml`, and this directory has zero
effect on `cargo build`/`cargo test`.

## What it shows

- **Agents** — live agent list with continuous behavioral trust scores (`TrustDecayEngine`).
- **Trust Mesh** — a force-directed graph of capability-grant edges (who has delegated
  what to whom), fed by `sidecar.rs::send_message`'s delegation-logging.
- **Alerts** — a live feed of gate rejections (Gate 4.0 prompt-injection blocks, Gate 3.0
  lateral-movement blocks, etc.), pushed over Server-Sent Events.
- **Financial** — "Tokens Blocked" / estimated exposure prevented by the Gate 0.5
  Financial Circuit Breaker.

## Running it

1. Start the backend (from the repo root):
   ```sh
   SAACP_DASHBOARD_TOKEN=<base64 32 bytes> cargo run --bin saacp-command-center --features command-center
   ```
   This also starts a bare demo `SAACPNetworkDaemon` on `127.0.0.1:7444` by default so
   there's traffic to look at (`SAACP_DISABLE_DEMO_DAEMON=1` to skip). See
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

- The dashboard token is compiled into the client bundle via `NEXT_PUBLIC_*` — the same
  "operator-only, not multi-tenant-public" tradeoff the backend itself makes by accepting
  the token as an SSE `?token=` query parameter (browsers' `EventSource` can't set custom
  headers). Fine for a local/internal ops dashboard; not meant for public deployment as-is.
- Live updates ride entirely on one `/events` Server-Sent-Events connection per open tab
  (auto-reconnecting, native `EventSource` behavior) — no WebSocket, no polling loop except
  the Financial tile (which refreshes every 10s, since it doesn't need per-event precision).
