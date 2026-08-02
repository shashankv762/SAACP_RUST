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

from ._errors import SaacpError

DEFAULT_SIDECAR_URL = "http://127.0.0.1:8787"

__all__ = [
    "SaacpClient",
    "SendResult",
    "SaacpError",
    "DEFAULT_SIDECAR_URL",
    "wrap",
    "SecuredCallable",
]


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

    def __init__(
        self,
        sidecar_url: str = DEFAULT_SIDECAR_URL,
        timeout: float = 15.0,
        bearer_token: Optional[str] = None,
    ):
        self.sidecar_url = sidecar_url.rstrip("/")
        self.timeout = timeout
        # S-5 fix: when the sidecar's local HTTP API requires a bearer token
        # (the managed-spawn path in sidecar_manager.get_or_start now generates
        # one by default), every /send and /receive call must carry it. None =
        # no header (talking to an unauthenticated sidecar, e.g. a manually
        # started one), preserving prior behavior.
        self._auth_headers = (
            {"Authorization": f"Bearer {bearer_token}"} if bearer_token else {}
        )

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
        API address. Raises ``SaacpError`` only when this sidecar couldn't be reached at
        all, or responded with something that isn't the expected JSON body. A peer-side
        rejection (bad token, tampered frame, scope violation, ...) *or* this sidecar
        reporting its own outbound concurrency limit is saturated (``status="saturated"``)
        are both reported via ``SendResult.status``, never as an exception — the caller
        decides how to handle "the request completed but wasn't a plain success."
        """
        try:
            resp = requests.post(
                f"{self.sidecar_url}/send",
                json={
                    "to_agent": to_agent,
                    "target_addr": target_addr,
                    "task": task,
                    "priority": priority,
                    "action_class": action_class,
                },
                headers=self._auth_headers,
                timeout=self.timeout,
            )
        except requests.RequestException as e:
            raise SaacpError(f"could not reach the local sidecar at {self.sidecar_url}: {e}") from e
        try:
            body = resp.json()
        except ValueError as e:
            raise SaacpError(
                f"sidecar returned a non-JSON response (status {resp.status_code}): {resp.text}"
            ) from e
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
            headers=self._auth_headers,
            timeout=wait_secs + 5.0,
        )
        if resp.status_code == 204:
            return None
        resp.raise_for_status()
        return resp.json()

    def healthz(self) -> dict[str, Any]:
        # /healthz is intentionally never gated on the sidecar, so it needs no
        # Authorization header (sending one anyway would be harmless).
        resp = requests.get(f"{self.sidecar_url}/healthz", timeout=self.timeout)
        resp.raise_for_status()
        return resp.json()


# Imported at the bottom, after `SaacpClient`/`SendResult`/`SaacpError` are already
# defined on this module — `wrap.py` and `sidecar_manager.py` both do
# `from ._errors import SaacpError` directly (not `from . import SaacpError`) precisely
# so this ordering isn't load-bearing, but keeping the import here regardless.
from .wrap import wrap, SecuredCallable  # noqa: E402
