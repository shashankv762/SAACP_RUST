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

## 1. Build and run the sidecar

From the repository root (requires the `sidecar` Cargo feature):

```sh
cargo build --release --features sidecar --bin saacp-sidecar
```

Every sidecar in a mesh must share the same 32-byte `SAACP_TOKEN_SECRET` (base64-encoded)
— this is a deliberate v1 simplification (see `src/sidecar.rs`'s module doc comment).
Generate one:

```sh
python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"
```

Run one sidecar per agent:

```sh
SAACP_AGENT_ID=agent-a SAACP_TOKEN_SECRET=<shared secret> \
  SAACP_LISTEN_ADDR=127.0.0.1:7443 SAACP_HTTP_ADDR=127.0.0.1:8787 \
  ./target/release/saacp-sidecar
```

| Env var | Meaning |
|---|---|
| `SAACP_AGENT_ID` | This sidecar's agent identity (required) |
| `SAACP_TOKEN_SECRET` | Base64 32-byte shared mesh secret (required) |
| `SAACP_LISTEN_ADDR` | Address the real SAACP listener binds — what peers dial (default `127.0.0.1:7443`) |
| `SAACP_HTTP_ADDR` | Address the local plain-HTTP API binds — what your Python agent talks to (default `127.0.0.1:8787`) |

## 2. Install the Python client

```sh
pip install -e .
```

## 3. Use it

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
else:
    print("rejected:", result.detail)

message = client.receive(wait_secs=5.0)  # long-polls agent-b's sidecar for incoming work
```

See `examples/demo_two_agents.py` for a complete runnable two-agent round trip.

## Scope (v1)

- One shared mesh secret, not a per-peer key registry.
- One-shot outbound connections (no pooling) — a real latency cost under high throughput,
  not solved here.
- Messages are `{task, priority}` (SAACP schema 1, "Task") only.

See `src/sidecar.rs`'s module doc comment for the full rationale behind each of these.
