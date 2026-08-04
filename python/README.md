# saacp-client

A thin Python HTTP client for `saacp-sidecar` — a local Rust process that gives any
HTTP-capable agent (LangChain, AutoGen, plain scripts) SAACP's security guarantees
without any SAACP protocol knowledge on the Python side.

```
Python agent  <-- plain HTTP/JSON -->  saacp-sidecar  <-- real SAACP wire protocol -->  peer's saacp-sidecar
                                        (X25519 ECDH, AES-256-GCM,
                                         HMAC capability tokens,
                                         16-gate pipeline)
```

Your agent never sees a capability token, a session key, or a gate rejection code — it
sends a task string and gets back `success` or `rejected`.

## 1. Build the sidecar

From the repository root (requires the `sidecar` Cargo feature):

```sh
cargo build --release --features sidecar --bin saacp-sidecar
```

`saacp.wrap()` (below) finds this binary automatically (via a dev-relative search from
the installed package, `SAACP_SIDECAR_BIN`, or `PATH`) and spawns it for you — you don't
need to run it by hand unless you want full manual control (see section 4).

Every sidecar in a mesh must share the same 32-byte `SAACP_TOKEN_SECRET` (base64-encoded)
by default, or use per-peer secrets (see "Production hardening" below). Generate one:

```sh
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

To run one by hand instead of letting `wrap()` manage it:

```sh
SAACP_AGENT_ID=agent-a SAACP_TOKEN_SECRET=<shared secret> \
  SAACP_LISTEN_ADDR=127.0.0.1:7443 SAACP_HTTP_ADDR=127.0.0.1:8787 \
  ./target/release/saacp-sidecar
```

| Env var | Meaning |
|---|---|
| `SAACP_AGENT_ID` | This sidecar's agent identity (required) |
| `SAACP_TOKEN_SECRET` | Base64 32-byte shared mesh secret (required unless `SAACP_TOKEN_SECRET_FILE` is set). Held by **every** sidecar in the mesh, so any holder can forge any agent's messages — prefer `SAACP_PEER_SECRETS_FILE` |
| `SAACP_TOKEN_SECRET_FILE` | Path to a file holding the base64 secret instead of the env var directly (keeps it out of `/proc/<pid>/environ`) |
| `SAACP_PEER_SECRETS_FILE` | **Recommended.** Path to a JSON file of per-peer pairwise secrets — confines forgery to one compromised pair instead of the whole mesh. See "Production hardening" below |
| `SAACP_REQUIRE_PEER_SECRETS` | `1` = refuse to start without per-peer secrets, turning the shared-secret warning into a hard failure (fail-closed; recommended in production) |
| `SAACP_LISTEN_ADDR` | Address the real SAACP listener binds — what peers dial (default `127.0.0.1:7443`) |
| `SAACP_HTTP_ADDR` | Address the local plain-HTTP API binds — what your Python agent talks to (default `127.0.0.1:8787`) |
| `SAACP_HTTP_BEARER_TOKEN` | Bearer token required on every `/send` and `/receive` request (constant-time compared). **Mandatory** when `SAACP_HTTP_ADDR` binds a non-loopback interface — the binary refuses to start an unauthenticated message-issuance API on a reachable address |
| `SAACP_HTTP_BEARER_TOKEN_FILE` | Path to a file holding the bearer token instead of the env var (same hygiene as `SAACP_TOKEN_SECRET_FILE`). Takes precedence over `SAACP_HTTP_BEARER_TOKEN` |
| `SAACP_HTTP_TOKEN_OUT_FILE` | Path the sidecar **writes** a freshly generated bearer token to when none was supplied, for the co-located agent to read (created `0600` on POSIX). Never exposed over HTTP |
| `SAACP_ALLOW_UNAUTHENTICATED_HTTP` | `1` = run the loopback HTTP API with no auth at all and silence the warning. Any process on the host can then issue messages as this agent and drain its inbox |
| `SAACP_MAX_CONCURRENT_SENDS` | Bound on concurrent outbound `/send` dispatches (default 64) |
| `SAACP_SEND_RETRY_ATTEMPTS` | Retries for a transient TCP-connect failure only (default 2) |

### Local HTTP API authentication

The sidecar's `/send` and `/receive` endpoints can issue messages as this agent and
drain its inbox, so they are authenticated with a bearer token (`/healthz` never is).
There are three ways this resolves, in order:

1. **You supply one** — `SAACP_HTTP_BEARER_TOKEN(_FILE)`. Required for a non-loopback
   bind; the binary refuses to start otherwise.
2. **The sidecar generates one** — set `SAACP_HTTP_TOKEN_OUT_FILE` and it writes a fresh
   token there for the co-located agent to read. This is what `wrap()`'s managed spawn
   uses (via `SAACP_HTTP_BEARER_TOKEN_FILE`), so you never see it.
3. **Nothing set** — the loopback API runs unauthenticated and logs a warning on every
   start. Set `SAACP_ALLOW_UNAUTHENTICATED_HTTP=1` to accept that and silence it.

When talking to a sidecar you did *not* start, pass its token as
`wrap(..., http_bearer_token=...)` or `SaacpClient(..., bearer_token=...)`.

## 2. Install the Python client

```sh
pip install -e .
```

## 3. Use it — the one-liner

```python
from saacp_client import wrap

# secure your existing AutoGen-style agent (has .send()/.receive()) in one line:
agent = wrap(
    agent,
    agent_id="agent-a",
    secret=b"...32 bytes, shared with agent-b out of band...",
    peers={"agent-b": "127.0.0.1:7444"},  # agent-b's SAACP_LISTEN_ADDR
)
agent.send("Execute the quarterly report", "agent-b")  # now routed through SAACP
```

`wrap()` finds (or spawns) a local `saacp-sidecar` process for you. All keyword
arguments are optional and fall back to `SAACP_AGENT_ID` / `SAACP_TOKEN_SECRET` /
`SAACP_LISTEN_ADDR` / `SAACP_HTTP_ADDR` environment variables, so with those set,
`agent = wrap(agent)` alone is real. With no secret available at all, `wrap()` raises
`SaacpError` rather than silently generating a throwaway one — an ephemeral secret
yields an agent that looks secured but can never reach a separately-started peer. For
single-process demos and tests, opt in with `allow_ephemeral_secret=True` (or
`SAACP_ALLOW_EPHEMERAL_SECRET=1`) to generate one and get a `RuntimeWarning`.

`wrap()` duck-types what you pass it:

- **`.send()`/`.receive()`-shaped objects** (matches AutoGen's `ConversableAgent`):
  outbound `.send(message, recipient)` is monkey-patched to route through SAACP when
  `recipient` is a name in `peers`; a background thread delivers incoming messages to
  the *original* `.receive()`. Returns the same object — keep using `agent` exactly as
  before.
- **Callables / `.run()`/`.invoke()`-shaped objects** (matches a LangChain tool/chain):
  returns a `SecuredCallable`. Calling it delivers the input securely to `default_peer`
  and returns a `SendResult` — this is fire-and-forget delivery, **not** a synchronous
  RPC with a return value, since that's what SAACP's Task message actually is. Because
  that changes the return contract for every existing caller of the tool, you must pass
  `fire_and_forget=True` to accept it; otherwise `wrap()` raises `TypeError` instead of
  silently rewiring the call.
- Anything else raises `TypeError` naming the two supported shapes.

See `examples/demo_wrap.py` for a complete runnable two-agent demo using the one-liner.

## 4. Or drive it manually, for full control

```python
from saacp_client import SaacpClient

client = SaacpClient("http://127.0.0.1:8787")  # this agent's own sidecar

result = client.send(
    to_agent="agent-b",
    target_addr="127.0.0.1:7444",  # agent-b's SAACP_LISTEN_ADDR, not its HTTP address
    task="Execute the quarterly report",
)
if result.ok:
    print("delivered and gate-verified")
elif result.status == "saturated":
    print("this sidecar's outbound concurrency limit was hit — retry shortly")
else:
    print("rejected:", result.detail)

message = client.receive(wait_secs=5.0)  # long-polls agent-b's sidecar for incoming work
```

See `examples/demo_two_agents.py` for the equivalent manual two-agent round trip.

## Production hardening

- **Per-peer issuer secrets** — *the most important one*. Capability tokens are symmetric
  HMAC, so whoever can verify a token can also mint one: on the single shared mesh secret,
  **every** sidecar can forge messages from **any** agent, and the audit trail can't tell
  a forgery from the real sender. Give the sidecar binary a `SAACP_PEER_SECRETS_FILE`
  (JSON `{"peer-agent-id": "<base64 32 bytes>", ...}`) to move to a real allowlist of
  known peers, each with their own pairwise secret — see `src/sidecar.rs`'s module doc for
  the full model (once any entry is registered, the registry becomes authoritative: only
  named peers are accepted). Running without it logs a startup warning; set
  `SAACP_REQUIRE_PEER_SECRETS=1` to make it a hard startup failure instead.
- **Local HTTP API auth**: `/send`/`/receive` sit behind a bearer token — see "Local HTTP
  API authentication" above. Mandatory on a non-loopback bind.
- **Bounded outbound concurrency**: `SAACP_MAX_CONCURRENT_SENDS` caps concurrent `/send`
  dispatches; a saturated sidecar returns `status: "saturated"` (also surfaced as
  `SendResult.status == "saturated"` in Python) rather than queuing without bound.
- **Bounded retry**: `SAACP_SEND_RETRY_ATTEMPTS` retries a transient TCP-connect failure
  only (never a handshake/protocol error, which would mask a real problem).
- **Secret hygiene**: `SAACP_TOKEN_SECRET_FILE` keeps the mesh secret out of the process
  environment.
- **Real `/healthz`**: reports live `inbox_depth` / `inbox_capacity` / `inbox_dropped` /
  `peers_configured`.

## Message delivery guarantees (`receive()`)

Message order is a correctness property for a multi-hop delegation chain, so these are
contract rather than incidental behavior (authoritative statement:
`SIDECAR_INBOX_CAPACITY` in `src/sidecar.rs`):

- **Strict FIFO** — messages come back in the exact order the sidecar's gate pipeline
  delivered them. This orders deliveries *into* the sidecar, not end-to-end: each `send()`
  opens its own one-shot connection, so a peer's concurrent sends can arrive in any order.
- **Single consumer** — only one `receive()` may be in flight per sidecar; a concurrent
  second call gets `409 CONFLICT` rather than silently interleaving, so two pollers can
  never reorder the stream between them.
- **Bounded, newest-dropped** — at most 1000 undelivered messages are queued. Past that,
  *newly arriving* messages are dropped and the existing backlog is preserved. Stop
  polling long enough and you permanently miss messages; check
  `healthz()["inbox_dropped"]` to detect it.

## Scope (v1)

- One-shot outbound connections (no pooling) — a real latency cost under high throughput,
  not solved here (see `src/sidecar.rs`'s module doc for why this is harder than it looks
  given the daemon's identity-pinning model).
- Messages are `{task, priority}` (SAACP schema 1, "Task") only.
- `wrap()`'s duck-typed dispatch matches AutoGen's/LangChain's common shapes closely
  enough to work in practice — it is not a tested deep integration against either
  library's actual package.

See `src/sidecar.rs`'s module doc comment for the full rationale behind each of these.
