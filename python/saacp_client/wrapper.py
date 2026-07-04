"""Example wrapper matching the "secure your agent in one line of code" pitch.

This is a *pattern*, not a tested integration with any specific framework's internals —
LangChain/AutoGen expose different message-hook points across versions, so wiring this
into a real agent's send/receive path is left to the caller. What's demonstrated here is
the shape: an existing agent object gains secure send/receive without knowing SAACP
exists, by delegating all of it to the local sidecar via ``SaacpClient``.
"""

from __future__ import annotations

from typing import Any, Protocol

from . import SaacpClient, SendResult


class ProcessesMessages(Protocol):
    def process(self, message: dict) -> Any: ...


class SaacpAgentWrapper:
    """Wraps any object exposing ``.process(message: dict)`` with secure send/receive.

    Example::

        secure_agent = SaacpAgentWrapper(
            my_agent, agent_id="agent-a", peer_addr="127.0.0.1:7444", peer_agent_id="agent-b",
        )
        secure_agent.send("do the thing")
        secure_agent.poll_and_dispatch()  # hands any received message to my_agent.process()
    """

    def __init__(
        self,
        agent: ProcessesMessages,
        agent_id: str,
        peer_addr: str,
        peer_agent_id: str = "peer",
        sidecar_url: str = "http://127.0.0.1:8787",
    ):
        self.agent = agent
        self.agent_id = agent_id
        self.peer_addr = peer_addr
        self.peer_agent_id = peer_agent_id
        self.client = SaacpClient(sidecar_url)

    def send(self, task: str, priority: int = 1, action_class: int = 0) -> SendResult:
        return self.client.send(self.peer_agent_id, self.peer_addr, task, priority, action_class)

    def poll_and_dispatch(self, wait_secs: float = 5.0) -> bool:
        """Poll once for an incoming message and hand it to ``agent.process()`` if one
        arrived. Returns whether a message was dispatched."""
        message = self.client.receive(wait_secs=wait_secs)
        if message is None:
            return False
        self.agent.process(message)
        return True
