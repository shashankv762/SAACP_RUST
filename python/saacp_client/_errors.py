"""Shared exception type, kept in its own tiny module so `__init__.py`, `wrap.py`, and
`sidecar_manager.py` can all import it without a circular-import dependency on each
other.
"""

from __future__ import annotations

__all__ = ["SaacpError"]


class SaacpError(RuntimeError):
    """A transport-level failure talking to the *local* sidecar, or a sidecar lifecycle
    problem (binary not found, never became healthy). Not raised for a peer-side
    rejection — see ``SendResult.status``.
    """
