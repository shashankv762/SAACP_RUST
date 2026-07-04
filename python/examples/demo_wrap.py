"""Runnable demo of the literal "one line of code" pitch: `saacp.wrap(agent)`.

Unlike `demo_two_agents.py`, this does NOT require you to hand-start any
`saacp-sidecar` processes first — `wrap()` finds (or spawns) them itself. Just build the
binary once:

    cargo build --release --features sidecar --bin saacp-sidecar

then, from this directory:

    pip install -e ..
    python demo_wrap.py
"""

from __future__ import annotations

import time

from saacp_client import wrap

# A shared out-of-band secret both agents' sidecars trust. In real use this is generated
# once and distributed to every agent in the mesh out of band (see ../README.md) — never
# hardcoded like this outside of a demo.
SHARED_SECRET = b"\x42" * 32


class DemoAgent:
    """Duck-types AutoGen's ConversableAgent shape closely enough for `wrap()`:
    .send(message, recipient) and .receive(message, sender).
    """

    def __init__(self, name: str):
        self.name = name

    def send(self, message, recipient):
        raise AssertionError("send() should have been monkey-patched by wrap()")

    def receive(self, message, sender):
        print(f"[{self.name}] received from {sender!r}: {message!r}")


def main() -> None:
    agent_a = DemoAgent("agent-a")
    agent_b = DemoAgent("agent-b")

    # The one-liner: each agent gets SAACP's real crypto/gate-pipeline guarantees, with
    # `wrap()` locating/spawning the sidecar process behind the scenes.
    agent_a = wrap(
        agent_a,
        agent_id="agent-a",
        secret=SHARED_SECRET,
        peers={"agent-b": "127.0.0.1:7443"},
        saacp_listen_addr="127.0.0.1:7442",
        http_listen_addr="127.0.0.1:8786",
    )
    agent_b = wrap(
        agent_b,
        agent_id="agent-b",
        secret=SHARED_SECRET,
        peers={"agent-a": "127.0.0.1:7442"},
        saacp_listen_addr="127.0.0.1:7443",
        http_listen_addr="127.0.0.1:8787",
    )

    print("sending securely from agent-a to agent-b...")
    agent_a.send("Execute the quarterly report", "agent-b")

    # agent_b's background poll thread delivers to `receive()` asynchronously.
    time.sleep(2.0)


if __name__ == "__main__":
    main()
