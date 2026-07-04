"""Runnable demo: two already-running saacp-sidecar processes exchange one message.

Start two sidecars first, from the repo root (each in its own terminal), sharing the
SAME token secret — see ../../src/sidecar.rs's module doc comment for why a single
shared mesh secret is a deliberate v1 simplification:

    # generate one shared secret, reuse it for both sidecars below
    python -c "import secrets, base64; print(base64.b64encode(secrets.token_bytes(32)).decode())"

    # terminal 1
    SAACP_AGENT_ID=agent-a SAACP_TOKEN_SECRET=<paste secret> \\
      SAACP_LISTEN_ADDR=127.0.0.1:7443 SAACP_HTTP_ADDR=127.0.0.1:8787 \\
      cargo run --features sidecar --bin saacp-sidecar

    # terminal 2
    SAACP_AGENT_ID=agent-b SAACP_TOKEN_SECRET=<paste same secret> \\
      SAACP_LISTEN_ADDR=127.0.0.1:7444 SAACP_HTTP_ADDR=127.0.0.1:8788 \\
      cargo run --features sidecar --bin saacp-sidecar

Then, from this directory:

    pip install -e ..
    python demo_two_agents.py
"""

from __future__ import annotations

from saacp_client import SaacpClient


def main() -> None:
    agent_a = SaacpClient("http://127.0.0.1:8787")
    agent_b = SaacpClient("http://127.0.0.1:8788")

    print("agent-a health:", agent_a.healthz())
    print("agent-b health:", agent_b.healthz())

    result = agent_a.send(
        to_agent="agent-b",
        target_addr="127.0.0.1:7444",
        task="Execute the quarterly report",
        priority=3,
    )
    print("send result:", result)
    if not result.ok:
        print("send was not accepted by the peer — aborting")
        return

    message = agent_b.receive(wait_secs=5.0)
    print("agent-b received:", message)


if __name__ == "__main__":
    main()
