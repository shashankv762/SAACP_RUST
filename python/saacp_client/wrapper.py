"""Superseded by :func:`saacp_client.wrap`.

This module previously held ``SaacpAgentWrapper``, a hand-built example wrapper that
still required the caller to already have a running sidecar and to know its own/peer's
addresses up front — its own docstring called it "a pattern, not a tested integration."

``saacp_client.wrap.wrap`` (``from saacp_client import wrap``) replaces it: it auto-
manages the local sidecar process (spawns one if none is running) and duck-types the
wrapped object instead of requiring a specific ``.process(message)`` shape, covering both
AutoGen-style (``.send``/``.receive``) and LangChain-style (callable / ``.run``/
``.invoke``) objects. See ``wrap.py`` for the real implementation.
"""

from __future__ import annotations

from .wrap import wrap  # noqa: F401  (re-exported for anyone still importing from here)
