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
import secrets
import shutil
import subprocess
import tempfile
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
    already healthy and reused. ``process`` is ``None`` in the reused case.

    ``bearer_token`` (S-5 fix) is the auto-generated local HTTP API token when this
    call *started* the sidecar — callers must pass it to ``SaacpClient`` so
    ``/send``/``/receive`` are authorized. It is ``None`` for a *reused* sidecar (we
    didn't start it, so we don't hold its token; a reused sidecar we started earlier
    in the same process is matched by health probe only)."""

    http_url: str
    agent_id: str
    process: Optional[subprocess.Popen] = None
    bearer_token: Optional[str] = None


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


def _write_private_text_file(contents: str, *, prefix: str) -> str:
    """Write ``contents`` to a fresh owner-only temp file and return its path.

    Used for both the token secret (S-8) and the auto-generated HTTP bearer token
    (S-5). ``mkstemp`` creates the file with ``O_EXCL`` and owner-only permissions,
    so the value is never briefly world-readable between create and write. The
    caller owns cleanup (register the path with ``_unlink_quietly`` via ``atexit``).

    On POSIX the explicit ``chmod`` pins this to 0600. On Windows POSIX mode bits
    are not honored (``os.stat`` will report 0666 regardless) — confidentiality
    there rests on the per-user temp directory's ACL, which is what ``mkstemp``
    already inherits. Either way this is strictly better than the environment
    variable it replaces, which is readable by any same-UID process.
    """
    fd, path = tempfile.mkstemp(prefix=prefix, suffix=".tmp")
    try:
        # No-op on Windows (see docstring); meaningful on POSIX.
        os.chmod(path, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(contents)
    except BaseException:
        # Never leave a partially-written secret behind on failure.
        _unlink_quietly(path)
        raise
    return path


def _write_secret_file(secret: bytes) -> str:
    """S-8 fix: persist the base64 token secret to a private temp file instead of
    passing it in the child's environment.

    Passing a secret via ``env`` exposes it to any same-UID process through
    ``/proc/<pid>/environ`` on Linux. The Rust sidecar already prefers
    ``SAACP_TOKEN_SECRET_FILE`` over ``SAACP_TOKEN_SECRET`` (see
    ``src/bin/saacp_sidecar.rs::read_token_secret``), so we write the secret to an
    owner-only file (see ``_write_private_text_file``) and hand the sidecar the path.

    Returns the absolute path to the secret file; the caller is responsible for
    registering it for ``atexit`` cleanup.
    """
    return _write_private_text_file(base64.b64encode(secret).decode(), prefix="saacp_secret_")


def _unlink_quietly(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


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
    # S-8 fix: pass the token secret via a private owner-only file (SAACP_TOKEN_SECRET_FILE)
    # rather than SAACP_TOKEN_SECRET in the environment, which is readable by any
    # same-UID process via /proc/<pid>/environ. Also strip SAACP_TOKEN_SECRET from
    # the child's inherited environment so a value in the parent's env can't shadow
    # the file (read_token_secret prefers the file, but defense in depth).
    secret_file = _write_secret_file(secret)
    env.pop("SAACP_TOKEN_SECRET", None)
    env["SAACP_TOKEN_SECRET_FILE"] = secret_file

    # S-5 fix: the sidecar's local HTTP API (/send, /receive) defaults to
    # unauthenticated on loopback, so any same-host process could issue messages
    # as this agent or drain its inbox. Since we're the one starting the sidecar,
    # generate a strong bearer token, hand it to the sidecar via an owner-only file
    # (SAACP_HTTP_BEARER_TOKEN_FILE — read_http_bearer_token already prefers the
    # file form), and return it on the handle so this process's SaacpClient can
    # authorize. The token is never placed in the child environment nor exposed on
    # the unauthenticated /healthz endpoint, so no other local process can read it.
    bearer_token = secrets.token_hex(32)
    bearer_file = _write_private_text_file(bearer_token, prefix="saacp_http_token_")
    env.pop("SAACP_HTTP_BEARER_TOKEN", None)
    env["SAACP_HTTP_BEARER_TOKEN_FILE"] = bearer_file

    env["SAACP_LISTEN_ADDR"] = saacp_listen_addr
    env["SAACP_HTTP_ADDR"] = http_listen_addr

    def _cleanup_secret_files() -> None:
        _unlink_quietly(secret_file)
        _unlink_quietly(bearer_file)

    try:
        process = subprocess.Popen(
            [binary],
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except BaseException:
        _cleanup_secret_files()
        raise

    deadline = time.monotonic() + _HEALTHZ_POLL_DEADLINE_SECS
    while time.monotonic() < deadline:
        if process.poll() is not None:
            _cleanup_secret_files()
            raise SaacpError(
                f"saacp-sidecar exited immediately (exit code {process.returncode}) — "
                f"check that SAACP_LISTEN_ADDR={saacp_listen_addr} and "
                f"SAACP_HTTP_ADDR={http_listen_addr} aren't already bound by a "
                "non-SAACP process."
            )
        if _is_healthy(http_url):
            # The sidecar has read both secret files by the time it reports healthy,
            # but keep them until process exit (the sidecar may re-read on internal
            # restart) and unlink them in the same atexit path that stops the process.
            atexit.register(_cleanup_secret_files)
            atexit.register(_stop_process, process)
            return SidecarHandle(
                http_url=http_url,
                agent_id=agent_id,
                process=process,
                bearer_token=bearer_token,
            )
        time.sleep(_HEALTHZ_POLL_INTERVAL_SECS)

    _stop_process(process)
    _cleanup_secret_files()
    raise SaacpError(
        f"saacp-sidecar did not report healthy at {http_url} within "
        f"{_HEALTHZ_POLL_DEADLINE_SECS}s"
    )
