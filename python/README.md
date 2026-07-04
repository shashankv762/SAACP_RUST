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
| `SAACP_TOKEN_SECRET` | Base64 32-byte shared mesh secret (required unless `SAACP_TOKEN_SECRET_FILE` is set) |
| `SAACP_TOKEN_SECRET_FILE` | Path to a file holding the base64 secret instead of the env var directly (keeps it out of `/proc/<pid>/environ`) |
| `SAACP_PEER_SECRETS_FILE` | Optional path to a JSON file of per-peer pairwise secrets — see "Production hardening" below |
| `SAACP_LISTEN_ADDR` | Address the real SAACP listener binds — what peers dial (default `127.0.0.1:7443`) |
| `SAACP_HTTP_ADDR` | Address the local plain-HTTP API binds — what your Python agent talks to (default `127.0.0.1:8787`) |
| `SAACP_MAX_CONCURRENT_SENDS` | Bound on concurrent outbound `/send` dispatches (default 64) |
| `SAACP_SEND_RETRY_ATTEMPTS` | Retries for a transient TCP-connect failure only (default 2) |

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
`agent = wrap(agent)` alone is real. With no secret available at all, an ephemeral one
is generated with a printed warning (fine standalone; won't match a separately-started
peer unless shared out-of-band).

`wrap()` duck-types what you pass it:

- **`.send()`/`.receive()`-shaped objects** (matches AutoGen's `ConversableAgent`):
  outbound `.send(message, recipient)` is monkey-patched to route through SAACP when
  `recipient` is a name in `peers`; a background thread delivers incoming messages to
  the *original* `.receive()`. Returns the same object — keep using `agent` exactly as
  before.
- **Callables / `.run()`/`.invoke()`-shaped objects** (matches a LangChain tool/chain):
  returns a `SecuredCallable`. Calling it delivers the input securely to `default_peer`
  and returns a `SendResult` — this is fire-and-forget delivery, **not** a synchronous
  RPC with a return value, since that's what SAACP's Task message actually is.
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

- **Per-peer issuer secrets**: give the sidecar binary a `SAACP_PEER_SECRETS_FILE` (JSON
  `{"peer-agent-id": "<base64 32 bytes>", ...}`) to move from one shared mesh secret to a
  real allowlist of known peers, each with their own pairwise secret — see
  `src/sidecar.rs`'s module doc for the full model (once any entry is registered, the
  registry becomes authoritative: only named peers are accepted).
- **Bounded outbound concurrency**: `SAACP_MAX_CONCURRENT_SENDS` caps concurrent `/send`
  dispatches; a saturated sidecar returns `status: "saturated"` (also surfaced as
  `SendResult.status == "saturated"` in Python) rather than queuing without bound.
- **Bounded retry**: `SAACP_SEND_RETRY_ATTEMPTS` retries a transient TCP-connect failure
  only (never a handshake/protocol error, which would mask a real problem).
- **Secret hygiene**: `SAACP_TOKEN_SECRET_FILE` keeps the mesh secret out of the process
  environment.
- **Real `/healthz`**: reports live `inbox_depth` / `inbox_capacity` / `peers_configured`.

## Scope (v1)

- One-shot outbound connections (no pooling) — a real latency cost under high throughput,
  not solved here (see `src/sidecar.rs`'s module doc for why this is harder than it looks
  given the daemon's identity-pinning model).
- Messages are `{task, priority}` (SAACP schema 1, "Task") only.
- `wrap()`'s duck-typed dispatch matches AutoGen's/LangChain's common shapes closely
  enough to work in practice — it is not a tested deep integration against either
  library's actual package.

See `src/sidecar.rs`'s module doc comment for the full rationale behind each of these.
