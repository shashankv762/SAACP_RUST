"""End-to-end tests for ``saacp_client.wrap`` against real ``saacp-sidecar`` subprocesses.

Uses only the stdlib ``unittest`` (no pytest dependency), consistent with this package's
"nothing but ``requests``" dependency footprint. Skipped with a clear message if the
``saacp-sidecar`` binary can't be located (e.g. the Rust crate hasn't been built locally
yet) rather than failing the whole suite — matching this project's general convention of
not hard-failing on missing build artifacts in a dev environment.

Run from the ``python/`` directory: ``python -m unittest tests.test_wrap -v``
"""

from __future__ import annotations

import os
import socket
import sys
import time
import unittest
import warnings
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from saacp_client import SecuredCallable, SaacpError, wrap
from saacp_client.sidecar_manager import _locate_binary

_ROUND_TRIP_DEADLINE_SECS = 10.0
_ROUND_TRIP_POLL_INTERVAL_SECS = 0.1


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _skip_if_binary_missing() -> None:
    try:
        _locate_binary()
    except SaacpError as e:
        raise unittest.SkipTest(f"saacp-sidecar binary not found: {e}")


def _wait_until(predicate, deadline_secs: float = _ROUND_TRIP_DEADLINE_SECS) -> bool:
    deadline = time.monotonic() + deadline_secs
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(_ROUND_TRIP_POLL_INTERVAL_SECS)
    return predicate()


class FakeConversableAgent:
    """Duck-types AutoGen's ``ConversableAgent`` shape closely enough for `wrap()`:
    both `.send(message, recipient)` and `.receive(message, sender)`.
    """

    def __init__(self):
        self.received = []

    def send(self, message, recipient):
        raise AssertionError("send() should have been monkey-patched by wrap()")

    def receive(self, message, sender):
        self.received.append((message, sender))


class WrapEndToEndTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _skip_if_binary_missing()

    def test_conversable_agent_round_trip(self):
        """Two real sidecars, two `.send`/`.receive`-shaped objects wrapped with
        `wrap()`, one real message delivered end to end through the actual gate
        pipeline — proving the literal `agent = saacp.wrap(agent)` pitch works.
        """
        secret = b"\x11" * 32
        a_saacp_port, a_http_port = _free_port(), _free_port()
        b_saacp_port, b_http_port = _free_port(), _free_port()

        agent_a = FakeConversableAgent()
        wrapped_a = wrap(
            agent_a,
            agent_id="py-agent-a",
            secret=secret,
            peers={"py-agent-b": f"127.0.0.1:{b_saacp_port}"},
            saacp_listen_addr=f"127.0.0.1:{a_saacp_port}",
            http_listen_addr=f"127.0.0.1:{a_http_port}",
        )
        self.assertIs(wrapped_a, agent_a, "wrap() must return the same mutated object")

        agent_b = FakeConversableAgent()
        wrap(
            agent_b,
            agent_id="py-agent-b",
            secret=secret,
            peers={"py-agent-a": f"127.0.0.1:{a_saacp_port}"},
            saacp_listen_addr=f"127.0.0.1:{b_saacp_port}",
            http_listen_addr=f"127.0.0.1:{b_http_port}",
        )

        wrapped_a.send("do the real thing", "py-agent-b")

        self.assertTrue(
            _wait_until(lambda: bool(agent_b.received)),
            "agent-b never received the message",
        )
        self.assertEqual(agent_b.received, [("do the real thing", "py-agent-a")])

    def test_callable_secured_delivery(self):
        """A plain function wrapped with `wrap()` becomes a `SecuredCallable` that
        delivers securely (fire-and-forget) and reports a real `SendResult`.
        """
        secret = b"\x22" * 32
        peer_saacp_port, peer_http_port = _free_port(), _free_port()
        tool_saacp_port, tool_http_port = _free_port(), _free_port()

        peer_agent = FakeConversableAgent()
        wrap(
            peer_agent,
            agent_id="py-tool-peer",
            secret=secret,
            saacp_listen_addr=f"127.0.0.1:{peer_saacp_port}",
            http_listen_addr=f"127.0.0.1:{peer_http_port}",
        )

        def my_tool(x):
            raise AssertionError("SecuredCallable must not invoke the original callable")

        secured = wrap(
            my_tool,
            agent_id="py-tool-caller",
            secret=secret,
            peers={"py-tool-peer": f"127.0.0.1:{peer_saacp_port}"},
            default_peer="py-tool-peer",
            saacp_listen_addr=f"127.0.0.1:{tool_saacp_port}",
            http_listen_addr=f"127.0.0.1:{tool_http_port}",
            # SC-6: wrapping a tool-shaped object replaces its return value with a
            # SendResult, so the caller must acknowledge those semantics explicitly.
            fire_and_forget=True,
        )
        self.assertIsInstance(secured, SecuredCallable)

        result = secured("please do the task")
        self.assertTrue(result.ok, f"send was not accepted by the peer: {result}")

        self.assertTrue(
            _wait_until(lambda: bool(peer_agent.received)),
            "peer never received the task",
        )
        self.assertEqual(peer_agent.received, [("please do the task", "py-tool-caller")])


class WrapContractTests(unittest.TestCase):
    """SC-2 / SC-6: the two places `wrap()` used to silently downgrade something.

    These need no sidecar binary — they assert `wrap()` refuses *before* it would
    reach out to one, which is exactly the point of both fixes.
    """

    def setUp(self):
        self._saved = {
            k: os.environ.pop(k, None)
            for k in (
                "SAACP_TOKEN_SECRET",
                "SAACP_ALLOW_EPHEMERAL_SECRET",
                "SAACP_FIRE_AND_FORGET",
            )
        }

    def tearDown(self):
        for k, v in self._saved.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_missing_secret_raises_instead_of_generating_ephemeral(self):
        """SC-2: an ephemeral secret silently isolates the agent from every
        separately-started peer. A `print()` is not a signal a container runtime or
        unattended deployment is guaranteed to surface, so this must fail closed.
        """
        with self.assertRaises(SaacpError) as ctx:
            wrap(lambda x: x, agent_id="a", auto_start=False, fire_and_forget=True)
        self.assertIn("ephemeral", str(ctx.exception))

    def test_ephemeral_secret_opt_in_warns_through_warnings_module(self):
        """SC-2: when explicitly opted into, the downgrade is still signalled — but
        via `warnings` (capturable, routable to logs), not a bare print to stdout.
        """
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            wrap(
                lambda x: x,
                agent_id="a",
                allow_ephemeral_secret=True,
                auto_start=False,
                fire_and_forget=True,
            )
        self.assertTrue(
            any(issubclass(w.category, RuntimeWarning) for w in caught),
            "the ephemeral-secret downgrade must emit a capturable RuntimeWarning",
        )

    def test_tool_shape_requires_explicit_fire_and_forget(self):
        """SC-6: wrapping a tool swaps its return value for a `SendResult`. Code
        doing `answer = tool(q)` would keep running against a value the tool never
        produced, so the caller must acknowledge the changed contract.
        """
        with self.assertRaises(TypeError) as ctx:
            wrap(lambda x: x, agent_id="a", secret=b"\x33" * 32, auto_start=False)
        self.assertIn("fire_and_forget=True", str(ctx.exception))

    def test_conversable_shape_is_unaffected_by_fire_and_forget(self):
        """SC-6 applies only to tool-shaped inputs — `.send()/.receive()` agents are
        already message-passing, so their contract is unchanged and they must not be
        forced to pass the flag.
        """
        agent = FakeConversableAgent()
        # `auto_start=False` avoids needing a real sidecar; no send is issued here.
        result = wrap(agent, agent_id="a", secret=b"\x44" * 32, auto_start=False)
        self.assertIs(result, agent)


if __name__ == "__main__":
    unittest.main()
