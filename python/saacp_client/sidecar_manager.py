"""Locates and manages a local ``saacp-sidecar`` process.

This is what makes ``saacp.wrap(agent)`` a real one-liner (see ``wrap.py``): rather than
requiring the caller to build and hand-run the Rust binary themselves, ``get_or_start``
finds it, spawns it with the right environment variables, and waits for it to report
healthy — or reuses one that's already running and healthy at the requested address.

A sidecar this process started itself is registered for `atexit` cleanup. A sidecar that
was merely *reused* (already healthy when we looked) is never terminated here — it may be
serving other callers.
"""

from __future__ import annotations

import atexit
import base64
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

import requests

from ._errors import SaacpError

_BINARY_NAMES = ("saacp-sidecar", "saacp-sidecar.exe")
_HEALTHZ_POLL_INTERVAL_SECS = 0.1
_HEALTHZ_POLL_DEADLINE_SECS = 5.0
_HEALTHZ_PROBE_TIMEOUT_SECS = 0.5
_STOP_WAIT_TIMEOUT_SECS = 3.0

__all__ = ["SidecarHandle", "get_or_start"]


@dataclass
class SidecarHandle:
    """A sidecar this call can talk to — either one we just started, or one we found
    already healthy and reused. ``process`` is ``None`` in the reused case."""

    http_url: str
    agent_id: str
    process: Optional[subprocess.Popen] = None


def _locate_binary() -> str:
    """Find the `saacp-sidecar` executable, or raise a clear `SaacpError` with build
    instructions. Checked in order: `SAACP_SIDECAR_BIN` env var, a dev-relative search
    for a `target/{release,debug}/saacp-sidecar[.exe]` walking up from this file, then
    `PATH`.
    """
    env_path = os.environ.get("SAACP_SIDECAR_BIN")
    if env_path:
        if not Path(env_path).is_file():
            raise SaacpError(f"SAACP_SIDECAR_BIN={env_path!r} does not point to an existing file")
        return env_path

    here = Path(__file__).resolve()
    for ancestor in (here, *here.parents):
        for profile in ("release", "debug"):
            for name in _BINARY_NAMES:
                candidate = ancestor / "target" / profile / name
                if candidate.is_file():
                    return str(candidate)

    found = shutil.which("saacp-sidecar")
    if found:
        return found

    raise SaacpError(
        "could not find the `saacp-sidecar` binary anywhere. Build it with "
        "`cargo build --release --features sidecar --bin saacp-sidecar` from the "
        "saacp-rs repository root, or set SAACP_SIDECAR_BIN to its full path."
    )


def _is_healthy(http_url: str) -> bool:
    try:
        resp = requests.get(f"{http_url}/healthz", timeout=_HEALTHZ_PROBE_TIMEOUT_SECS)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def _stop_process(process: subprocess.Popen) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_STOP_WAIT_TIMEOUT_SECS)
    except subprocess.TimeoutExpired:
        process.kill()


def get_or_start(
    *,
    agent_id: str,
    secret: bytes,
    saacp_listen_addr: str,
    http_listen_addr: str,
) -> SidecarHandle:
    """Reuse an already-healthy sidecar at `http_listen_addr`, or locate the binary and
    spawn a new one configured via environment variables (matching
    `src/bin/saacp_sidecar.rs`'s own env-var-driven config).

    Raises `SaacpError` if the binary can't be found, if the spawned process exits
    immediately (most likely `saacp_listen_addr`/`http_listen_addr` already in use by a
    non-SAACP process), or if it never reports healthy within the poll deadline.
    """
    http_url = f"http://{http_listen_addr}"

    if _is_healthy(http_url):
        return SidecarHandle(http_url=http_url, agent_id=agent_id, process=None)

    binary = _locate_binary()
    env = dict(os.environ)
    env["SAACP_AGENT_ID"] = agent_id
    env["SAACP_TOKEN_SECRET"] = base64.b64encode(secret).decode()
    env["SAACP_LISTEN_ADDR"] = saacp_listen_addr
    env["SAACP_HTTP_ADDR"] = http_listen_addr

    process = subprocess.Popen(
        [binary],
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    deadline = time.monotonic() + _HEALTHZ_POLL_DEADLINE_SECS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise SaacpError(
                f"saacp-sidecar exited immediately (exit code {process.returncode}) — "
                f"check that SAACP_LISTEN_ADDR={saacp_listen_addr} and "
                f"SAACP_HTTP_ADDR={http_listen_addr} aren't already bound by a "
                "non-SAACP process."
            )
        if _is_healthy(http_url):
            atexit.register(_stop_process, process)
            return SidecarHandle(http_url=http_url, agent_id=agent_id, process=process)
        time.sleep(_HEALTHZ_POLL_INTERVAL_SECS)

    _stop_process(process)
    raise SaacpError(
        f"saacp-sidecar did not report healthy at {http_url} within "
        f"{_HEALTHZ_POLL_DEADLINE_SECS}s"
    )
