"""``saacp.wrap(agent)`` — "secure your agent in one line of code."

Auto-manages a local ``saacp-sidecar`` process (spawns one if none is running, reuses one
that's already healthy — see ``sidecar_manager.py``) and duck-types the passed ``agent``
into a secured version of itself:

- **Has both ``.send`` and ``.receive``** (matches AutoGen's ``ConversableAgent`` shape):
  outbound ``.send(message, recipient, ...)`` is monkey-patched so that when
  ``recipient``'s name is a key in ``peers``, the message is routed through the sidecar
  instead — any other recipient falls through to the *original* ``.send`` untouched. A
  background daemon thread long-polls ``/receive`` and calls the original, unwrapped
  ``.receive(task, sender=from_agent)`` for anything that arrives. Returns the same
  (mutated) ``agent`` object — the whole point is that you keep using ``agent`` exactly
  as before.
- **Callable, or has ``.run``/``.invoke``** (LangChain tool/chain shape): returns a
  ``SecuredCallable``. Calling it sends the argument as a task to a peer and returns a
  ``SendResult`` — this is secure **fire-and-forget delivery**, not a synchronous RPC
  with a return value, because that's what SAACP's schema-1 "Task" message actually is
  (see ``../../src/sidecar.rs``'s module doc). Not overclaiming a request/response bridge
  the protocol doesn't have.

Anything else raises ``TypeError`` naming the two supported shapes, rather than silently
doing nothing.

This duck-typed dispatch is a *pattern* that matches AutoGen's and LangChain's common
shapes closely enough to work in practice — it is not a tested deep integration against
either library's actual package (this package depends on nothing but ``requests``), the
same honesty convention already used elsewhere in this client.
"""

from __future__ import annotations

import base64
import os
import secrets
import threading
from typing import Any, Dict, Optional

from . import SaacpClient
from ._errors import SaacpError
from .sidecar_manager import get_or_start

DEFAULT_SAACP_LISTEN_ADDR = "127.0.0.1:7443"
DEFAULT_HTTP_LISTEN_ADDR = "127.0.0.1:8787"

# How long each background `/receive` long-poll waits before looping again — bounds how
# quickly the poll thread notices `auto_start`-managed sidecar issues without hammering it.
_POLL_WAIT_SECS = 5.0
# Backoff after a poll-loop error (sidecar transiently unreachable) before retrying.
_POLL_ERROR_BACKOFF_SECS = 1.0

__all__ = ["wrap", "SecuredCallable"]


class SecuredCallable:
    """Wraps a plain callable / LangChain-tool-shaped object with secure, fire-and-forget
    task delivery. Calling it sends the input to a peer through the sidecar and returns a
    `SendResult` — it does NOT invoke the original callable or return its output (see
    module doc for why: SAACP's Task message has no request/response channel to bridge).
    """

    def __init__(self, client: SaacpClient, peers: Dict[str, str], default_peer: Optional[str]):
        self._client = client
        self._peers = peers
        self._default_peer = default_peer

    def _resolve_peer(self, to_agent: Optional[str]) -> str:
        name = to_agent or self._default_peer
        if name is None:
            raise SaacpError(
                "no target peer for this send: pass default_peer= to wrap(), or "
                "to_agent= to this call"
            )
        if name not in self._peers:
            raise SaacpError(
                f"unknown peer {name!r} — not present in the peers= mapping passed to wrap()"
            )
        return name

    def __call__(
        self,
        *args: Any,
        to_agent: Optional[str] = None,
        priority: int = 1,
        action_class: int = 0,
        **kwargs: Any,
    ):
        if args:
            task_value = args[0]
        elif "task" in kwargs:
            task_value = kwargs["task"]
        else:
            raise SaacpError(
                "SecuredCallable requires one positional argument (the task) or task="
            )
        name = self._resolve_peer(to_agent)
        return self._client.send(name, self._peers[name], str(task_value), priority, action_class)

    def __repr__(self) -> str:
        return f"SecuredCallable(peers={list(self._peers)!r}, default_peer={self._default_peer!r})"


def _looks_like_conversable(agent: Any) -> bool:
    return (
        hasattr(agent, "send")
        and hasattr(agent, "receive")
        and callable(agent.send)
        and callable(agent.receive)
    )


def _looks_like_tool(agent: Any) -> bool:
    return callable(agent) or hasattr(agent, "run") or hasattr(agent, "invoke")


def _wrap_conversable(agent: Any, client: SaacpClient, peers: Dict[str, str]) -> Any:
    original_send = agent.send
    original_receive = agent.receive

    def secured_send(message: Any, recipient: Any, *args: Any, **kwargs: Any):
        name = recipient if isinstance(recipient, str) else getattr(recipient, "name", None)
        if isinstance(name, str) and name in peers:
            task = message if isinstance(message, str) else str(message)
            return client.send(name, peers[name], task)
        return original_send(message, recipient, *args, **kwargs)

    agent.send = secured_send

    stop_event = threading.Event()

    def poll_loop() -> None:
        while not stop_event.is_set():
            try:
                message = client.receive(wait_secs=_POLL_WAIT_SECS)
            except Exception:
                stop_event.wait(_POLL_ERROR_BACKOFF_SECS)
                continue
            if message is not None:
                original_receive(message["task"], sender=message["from_agent"])

    thread = threading.Thread(target=poll_loop, daemon=True, name="saacp-wrap-receive-poll")
    thread.start()
    return agent


def wrap(
    agent: Any,
    *,
    agent_id: Optional[str] = None,
    peers: Optional[Dict[str, str]] = None,
    secret: Optional[bytes] = None,
    default_peer: Optional[str] = None,
    saacp_listen_addr: Optional[str] = None,
    http_listen_addr: Optional[str] = None,
    http_bearer_token: Optional[str] = None,
    auto_start: bool = True,
) -> Any:
    """Secure `agent` with SAACP — the literal one-liner: `agent = saacp.wrap(agent)`.

    All keyword arguments are optional and fall back to environment variables matching
    `src/bin/saacp_sidecar.rs`'s own config (`SAACP_AGENT_ID`, `SAACP_TOKEN_SECRET`,
    `SAACP_LISTEN_ADDR`, `SAACP_HTTP_ADDR`) — with those set, `saacp.wrap(agent)` alone
    is enough.

    `peers` maps a peer's `agent_id` to *their* SAACP listen address (`host:port` — the
    `SAACP_LISTEN_ADDR` their sidecar was started with, not their HTTP address), so the
    wrapped agent can address peers by name instead of raw sockets.

    If `secret` is omitted and `SAACP_TOKEN_SECRET` isn't set, an ephemeral secret is
    generated for this process and a warning is printed — it won't match any separately
    started peer unless shared out-of-band. Set `secret=` or `SAACP_TOKEN_SECRET` for
    real multi-process use.

    `http_bearer_token` (falling back to `SAACP_HTTP_BEARER_TOKEN`) authorizes calls to
    a sidecar this call did *not* start — a reused or manually-started one whose local
    HTTP API requires a token. When `auto_start` spawns a fresh sidecar, a token is
    generated automatically and this argument is unnecessary.
    """
    resolved_agent_id = agent_id or os.environ.get("SAACP_AGENT_ID")
    if not resolved_agent_id:
        raise SaacpError("agent_id is required: pass agent_id=, or set SAACP_AGENT_ID")

    resolved_secret = secret
    if resolved_secret is None:
        env_secret = os.environ.get("SAACP_TOKEN_SECRET")
        if env_secret:
            resolved_secret = base64.b64decode(env_secret)
        else:
            resolved_secret = secrets.token_bytes(32)
            print(
                "[saacp.wrap] no secret provided and SAACP_TOKEN_SECRET is unset — "
                "generated an ephemeral one for this process only. It will not match any "
                "separately-started peer unless shared out-of-band; pass secret= or set "
                "SAACP_TOKEN_SECRET for real multi-process use.",
            )
    if len(resolved_secret) != 32:
        raise SaacpError(f"secret must be exactly 32 bytes, got {len(resolved_secret)}")

    resolved_saacp_addr = saacp_listen_addr or os.environ.get("SAACP_LISTEN_ADDR", DEFAULT_SAACP_LISTEN_ADDR)
    resolved_http_addr = http_listen_addr or os.environ.get("SAACP_HTTP_ADDR", DEFAULT_HTTP_LISTEN_ADDR)
    # S-5 fix: only needed when talking to a sidecar this call did NOT start (a
    # reused or manually-started one that has SAACP_HTTP_BEARER_TOKEN set). For a
    # sidecar we start ourselves, get_or_start generates the token and returns it
    # on the handle, which takes precedence over this value.
    resolved_bearer_token = http_bearer_token or os.environ.get("SAACP_HTTP_BEARER_TOKEN")

    if auto_start:
        handle = get_or_start(
            agent_id=resolved_agent_id,
            secret=resolved_secret,
            saacp_listen_addr=resolved_saacp_addr,
            http_listen_addr=resolved_http_addr,
        )
        http_url = handle.http_url
        # S-5 fix: use the auto-generated local HTTP API bearer token when we
        # started the sidecar, so /send and /receive are authorized. When the
        # sidecar was *reused* (started by someone else) `handle.bearer_token`
        # is None, so fall back to the explicitly-supplied one.
        bearer_token = handle.bearer_token or resolved_bearer_token
    else:
        http_url = f"http://{resolved_http_addr}"
        bearer_token = resolved_bearer_token

    client = SaacpClient(http_url, bearer_token=bearer_token)
    resolved_peers = peers or {}

    if _looks_like_conversable(agent):
        return _wrap_conversable(agent, client, resolved_peers)
    if _looks_like_tool(agent):
        return SecuredCallable(client, resolved_peers, default_peer)
    raise TypeError(
        "saacp.wrap() supports objects with both .send()/.receive() methods "
        "(AutoGen-style agents), or callables / objects with .run()/.invoke() "
        f"(LangChain-style tools/chains); got {type(agent)!r}"
    )
