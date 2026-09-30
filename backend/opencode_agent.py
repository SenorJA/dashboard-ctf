"""
opencode_agent.py -- MIRV Module

Code Agent bridge: drives the headless ``opencode run`` CLI (open-source AI
coding agent, https://opencode.ai) from MIRV. Lets the operator ask a coding
agent to analyse / plan / auto-fix a codebase on the host running the backend
(the repository root by default, configurable via ``MIRV_OPENCODE_ROOT``).

Design
------
* Opt-in: when ``opencode`` is not on PATH the module reports
  ``installed=False`` and ``run()`` returns an "not available" error (the API
  answers 503), same graceful degradation as ``kali_mcp_client``.
  The binary path can be overridden with ``MIRV_OPENCODE_BIN``.
* ``run()`` uses ``subprocess.run`` with a list argv (never ``shell=True``),
  a hard timeout and a module-level non-blocking lock so only one agent runs
  at a time (``busy``).
* The working directory is constrained to the repository root: relative or
  absolute paths escaping it are rejected.
* Every command output is passed through ``redact.redact_text`` before being
  returned to callers and is truncated to ``MAX_OUTPUT`` characters.
* No ``--auto`` flag is ever passed (auto-approving everything is dangerous);
  you get the agent's finished reply, not interactive autonomy.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from backend.redact import redact_string

logger = logging.getLogger("vulnforge.opencode_agent")

ALLOWED_AGENTS = ("build", "plan", "general")
DEFAULT_TIMEOUT = 600
MAX_OUTPUT = 400_000
_LOCK = threading.Lock()
_VERSION_CACHE: Dict[str, Optional[str]] = {}


def _root() -> Path:
    """Allowed working directory (repository root unless overridden)."""
    override = os.getenv("MIRV_OPENCODE_ROOT")
    if override:
        return Path(override).resolve()
    return Path(__file__).resolve().parent.parent


def _binary() -> Optional[str]:
    """Location of the opencode binary (env override first)."""
    override = os.getenv("MIRV_OPENCODE_BIN")
    if override:
        return override
    return shutil.which("opencode")


def is_installed() -> bool:
    return _binary() is not None


def version() -> Optional[str]:
    """Cached ``opencode --version`` output (per binary path)."""
    binary = _binary()
    if not binary:
        return None
    if binary in _VERSION_CACHE:
        return _VERSION_CACHE[binary]
    try:
        out = subprocess.run(
            [binary, "--version"],
            capture_output=True, text=True, timeout=10,
        )
        ver = (out.stdout or out.stderr or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover
        ver = None
    _VERSION_CACHE[binary] = ver
    return ver


def status() -> dict:
    """Feature status for the frontend (401-free, lightweight)."""
    binary = _binary()
    return {
        "ok": True,
        "installed": binary is not None,
        "version": version() if binary else None,
        "path": binary,
        "agents": list(ALLOWED_AGENTS),
        "root": str(_root()),
        "busy": _LOCK.locked(),
    }


def _clean(text: str) -> str:
    text = text or ""
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT] + "\n…[truncated]"
    return redact_string(text)


def _resolve_cwd(cwd: Optional[str]) -> Optional[Path]:
    """Validate and resolve the requested working directory."""
    root = _root()
    if not cwd:
        return root
    candidate = Path(cwd).expanduser().resolve()
    if candidate == root or root in candidate.parents:
        return candidate
    return None


def run(
    prompt: str,
    agent: str = "plan",
    cwd: Optional[str] = None,
    model: Optional[str] = None,
    pure: bool = False,
    timeout: Optional[int] = None,
) -> dict:
    """Run a headless ``opencode run`` session and return the agent reply.

    Returns a dict with ``ok`` + ``exit_code``/``stdout``/``stderr`` or
    ``error``; fields are already redacted and truncated.
    """
    started = time.monotonic()
    workdir = _resolve_cwd(cwd)
    if workdir is None:
        return {
            "ok": False, "error": "cwd escapes MIRV_OPENCODE_ROOT",
            "available": is_installed(), "busy": _LOCK.locked(),
        }
    if agent not in ALLOWED_AGENTS:
        return {
            "ok": False,
            "error": f"agent must be one of {', '.join(ALLOWED_AGENTS)}",
            "available": is_installed(), "busy": _LOCK.locked(),
        }
    binary = _binary()
    base = {
        "available": binary is not None,
        "busy": _LOCK.locked(),
        "agent": agent,
        "cwd": str(workdir),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
    if not binary:
        base.update({"ok": False, "error": "opencode not available"})
        return base
    if not _LOCK.acquire(blocking=False):
        base.update({"ok": False, "error": "another agent run is in progress"})
        return base
    try:
        argv = [binary, "run", "--agent", agent, "--dir", str(workdir)]
        if model:
            argv += ["--model", model]
        if pure:
            argv.append("--pure")
        argv.append(prompt)
        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout or DEFAULT_TIMEOUT,
                cwd=str(workdir),
            )
            base.update({
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "stdout": _clean(proc.stdout or ""),
                "stderr": _clean(proc.stderr or ""),
            })
        except subprocess.TimeoutExpired as exc:
            base.update({
                "ok": False,
                "error": f"opencode run timed out after {timeout or DEFAULT_TIMEOUT}s",
                "stdout": _clean((exc.stdout or "") if isinstance(exc.stdout, str) else ""),
                "stderr": _clean((exc.stderr or "") if isinstance(exc.stderr, str) else ""),
            })
        except OSError as exc:  # pragma: no cover - defensive
            base.update({"ok": False, "error": f"opencode run failed: {exc}"})
    finally:
        _LOCK.release()
        base["duration_ms"] = int((time.monotonic() - started) * 1000)
    return base