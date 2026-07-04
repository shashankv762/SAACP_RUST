"""Thin HTTP client for a locally-running ``saacp-sidecar`` process.

The sidecar (a Rust binary — see ``../../src/sidecar.rs``) does all SAACP protocol work:
the X25519 ECDH handshake, AES-256-GCM framing, capability-token issuance/verification,
and the full 16-gate pipeline dispatch. This module only ever speaks plain HTTP/JSON to
``http://127.0.0.1:<port>`` — it has no SAACP-specific cryptography of its own, and never
needs to.
"""

from __future__ import annotations

from typing import Any, Optional

import requests

DEFAULT_SIDECAR_URL = "http://127.0.0.1:8787"

__all__ = ["SaacpClient", "SendResult", "SaacpError", "DEFAULT_SIDECAR_URL"]


class SaacpError(RuntimeError):
    """A transport-level failure talking to the *local* sidecar (connection refused, sidecar
    itself errored out). Not raised for a peer-side rejection — see ``SendResult.status``.
    """


class SendResult:
    """Outcome of one ``SaacpClient.send()`` call."""

    def __init__(self, status: str, detail: Optional[str]):
        self.status = status  # "success" | "rejected" | "error"
        self.detail = detail

    @property
    def ok(self) -> bool:
        return self.status == "success"

    def __repr__(self) -> str:
        return f"SendResult(status={self.status!r}, detail={self.detail!r})"


class SaacpClient:
    """Talks to one locally-running ``saacp-sidecar`` instance over plain HTTP."""

    def __init__(self, sidecar_url: str = DEFAULT_SIDECAR_URL, timeout: float = 15.0):
        self.sidecar_url = sidecar_url.rstrip("/")
        self.timeout = timeout

    def send(
        self,
        to_agent: str,
        target_addr: str,
        task: str,
        priority: int = 1,
        action_class: int = 0,
    ) -> SendResult:
        """Send a task-shaped message to a peer agent's SAACP listener.

        ``target_addr`` is the *peer's* SAACP protocol address (``host:port`` — the
        ``SAACP_LISTEN_ADDR`` that peer's sidecar was started with), not that peer's HTTP
        API address. Raises ``SaacpError`` only for a transport-level failure talking to
        *this* sidecar; a peer-side rejection (bad token, tampered frame, scope violation,
        ...) is reported via ``SendResult.status``, never as an exception — the caller
        decides how to handle "the network worked but the message wasn't accepted."
        """
        resp = requests.post(
            f"{self.sidecar_url}/send",
            json={
                "to_agent": to_agent,
                "target_addr": target_addr,
                "task": task,
                "priority": priority,
                "action_class": action_class,
            },
            timeout=self.timeout,
        )
        if resp.status_code >= 500:
            raise SaacpError(f"sidecar reported a transport error: {resp.text}")
        body = resp.json()
        return SendResult(status=body.get("status", "error"), detail=body.get("detail"))

    def receive(self, wait_secs: float = 5.0) -> Optional[dict[str, Any]]:
        """Long-poll for the next verified, decrypted message.

        Returns ``None`` if nothing arrived within ``wait_secs`` (the sidecar responds
        ``204 No Content``). The returned dict has ``from_agent``, ``task``, ``priority``,
        ``action_class``, ``session_uuid`` keys.
        """
        resp = requests.get(
            f"{self.sidecar_url}/receive",
            params={"wait_secs": wait_secs},
            timeout=wait_secs + 5.0,
        )
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        return resp.json()

    def healthz(self) -> dict[str, Any]:
        resp = requests.get(f"{self.sidecar_url}/healthz", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()
