"""
agent_bridge.py -- MIRV Module

**Pack 12** — multi-provider Code Agent bridge.

Unifies several headless AI coding-agent CLIs behind one interface so the
frontend can pick a provider:

  * ``opencode`` — delegated to ``backend.opencode_agent`` (already installed
    in the backend Docker image).
  * ``claude``   — Claude Code CLI (``claude -p``) in safe non-interactive
    mode: tools disabled, single turn, MCP disabled, JSON output.
  * ``codex``    — reserved (reported as not installed until implemented).

Security / operational guardrails (shared with ``opencode_agent``):
  * Never ``shell=True``; argv is always a list.
  * Working directory constrained to ``MIRV_OPENCODE_ROOT`` (repo root).
  * Per-provider non-blocking lock (only one run at a time per provider).
  * Hard timeout; every output is redacted + truncated.
  * No auto-approve / dangerous permission flags.
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
import time
from pathlib import Path
from typing import Dict, Optional

from backend import opencode_agent as _oc
from backend.redact import redact_string

logger = logging.getLogger("vulnforge.agent_bridge")

PROVIDERS = ("opencode", "claude", "codex")
DEFAULT_PROVIDER = "opencode"
DEFAULT_TIMEOUT = 600
MAX_OUTPUT = 400_000

_CLAUDE_LOCK = threading.Lock()
_CODEX_LOCK = threading.Lock()
_CLAUDE_VERSION_CACHE: Dict[str, Optional[str]] = {}


# ── generic helpers (reuse the opencode root/clean semantics) ──────────────

def _root() -> Path:
    return _oc._root()


def _resolve_cwd(cwd: Optional[str]) -> Optional[Path]:
    return _oc._resolve_cwd(cwd)


def _clean(text: str) -> str:
    text = text or ""
    if len(text) > MAX_OUTPUT:
        text = text[:MAX_OUTPUT] + "\n…[truncated]"
    return redact_string(text)


def _base(provider: str, workdir: Path, agent: str, started: float, busy: bool) -> dict:
    return {
        "provider": provider,
        "available": _is_available(provider),
        "busy": busy,
        "agent": agent,
        "cwd": str(workdir),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }


# ── claude / codex binaries ────────────────────────────────────────────────

def _claude_binary() -> Optional[str]:
    override = os.getenv("MIRV_CLAUDE_BIN")
    if override:
        return override
    return shutil.which("claude")


def _codex_binary() -> Optional[str]:
    override = os.getenv("MIRV_CODEX_BIN")
    if override:
        return override
    return shutil.which("codex")


def _is_available(provider: str) -> bool:
    if provider == "opencode":
        return _oc.is_installed()
    if provider == "claude":
        return _claude_binary() is not None
    if provider == "codex":
        return _codex_binary() is not None
    return False


def _claude_version() -> Optional[str]:
    binary = _claude_binary()
    if not binary:
        return None
    if binary in _CLAUDE_VERSION_CACHE:
        return _CLAUDE_VERSION_CACHE[binary]
    ver: Optional[str] = None
    try:
        out = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10)
        ver = (out.stdout or out.stderr or "").strip() or None
    except (OSError, subprocess.TimeoutExpired):  # pragma: no cover - defensive
        ver = None
    _CLAUDE_VERSION_CACHE[binary] = ver
    return ver


# ── status ─────────────────────────────────────────────────────────────────

def status(provider: str) -> dict:
    """Status of a single provider (lightweight, 401-free)."""
    if provider == "opencode":
        st = _oc.status()
        st["provider"] = "opencode"
        st["label"] = "opencode"
        return st
    if provider == "claude":
        binary = _claude_binary()
        return {
            "ok": True,
            "provider": "claude",
            "label": "Claude Code",
            "installed": binary is not None,
            "version": _claude_version() if binary else None,
            "path": binary,
            "root": str(_root()),
            "busy": _CLAUDE_LOCK.locked(),
            "safe_mode": True,
        }
    if provider == "codex":
        binary = _codex_binary()
        return {
            "ok": True,
            "provider": "codex",
            "label": "Codex CLI",
            "installed": binary is not None,
            "version": None,
            "path": binary,
            "root": str(_root()),
            "busy": _CODEX_LOCK.locked(),
            "implemented": False,
        }
    return {"ok": False, "provider": provider, "error": f"unknown provider '{provider}'"}


def status_all() -> dict:
    """Status of every provider plus the default."""
    return {
        "ok": True,
        "default": DEFAULT_PROVIDER,
        "providers": {p: status(p) for p in PROVIDERS},
    }


# ── claude run ─────────────────────────────────────────────────────────────

def _claude_argv(binary: str, prompt: str) -> list:
    """Safe, non-interactive Claude Code argv (tools + MCP disabled)."""
    return [
        binary,
        "-p", prompt,
        "--output-format", "json",
        "--max-turns", "1",
        "--tools", "",
        "--disallowedTools", "mcp__*",
        "--strict-mcp-config",
        "--mcp-config", '{"mcpServers":{}}',
        "--setting-sources", "",
    ]


def _extract_claude_text(stdout: str) -> str:
    """Best-effort extraction of the assistant text from a Claude JSON envelope."""
    raw = (stdout or "").strip()
    if not raw:
        return ""
    try:
        data = json.loads(raw)
    except (ValueError, TypeError):
        return raw
    if isinstance(data, dict):
        if data.get("is_error"):
            return str(data.get("result") or data.get("error") or raw)
        for key in ("result", "structured_output", "content", "text"):
            value = data.get(key)
            if isinstance(value, str) and value.strip():
                return value
            if isinstance(value, (dict, list)):
                return json.dumps(value, ensure_ascii=False, indent=2)
    return raw


def _run_claude(prompt: str, agent: str, workdir: Path, model: Optional[str], timeout: Optional[int]) -> dict:
    started = time.monotonic()
    binary = _claude_binary()
    base = _base("claude", workdir, agent, started, _CLAUDE_LOCK.locked())
    if not binary:
        base.update({"ok": False, "error": "claude not available"})
        return base
    if not _CLAUDE_LOCK.acquire(blocking=False):
        base.update({"ok": False, "error": "another Claude run is in progress"})
        return base
    try:
        argv = _claude_argv(binary, prompt)
        if model:
            argv += ["--model", model]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True,
                timeout=timeout or DEFAULT_TIMEOUT, cwd=str(workdir),
            )
            text = _extract_claude_text(proc.stdout or "")
            base.update({
                "ok": proc.returncode == 0,
                "exit_code": proc.returncode,
                "stdout": _clean(text),
                "stderr": _clean(proc.stderr or ""),
            })
        except subprocess.TimeoutExpired as exc:
            base.update({
                "ok": False,
                "error": f"claude run timed out after {timeout or DEFAULT_TIMEOUT}s",
                "stdout": _clean((exc.stdout or "") if isinstance(exc.stdout, str) else ""),
                "stderr": _clean((exc.stderr or "") if isinstance(exc.stderr, str) else ""),
            })
        except OSError as exc:  # pragma: no cover - defensive
            base.update({"ok": False, "error": f"claude run failed: {exc}"})
    finally:
        _CLAUDE_LOCK.release()
        base["duration_ms"] = int((time.monotonic() - started) * 1000)
    return base


# ── public run ─────────────────────────────────────────────────────────────

def run(
    provider: str,
    prompt: str,
    agent: str = "plan",
    cwd: Optional[str] = None,
    model: Optional[str] = None,
    pure: bool = False,
    timeout: Optional[int] = None,
) -> dict:
    """Run a headless agent session with the selected provider.

    Returns a dict (redacted/truncated) with ``ok`` + provider output, or
    ``error``. Unknown providers and cwd escapes are rejected.
    """
    provider = (provider or DEFAULT_PROVIDER).strip().lower()
    started = time.monotonic()
    workdir = _resolve_cwd(cwd)
    if workdir is None:
        return {
            "provider": provider, "ok": False, "available": _is_available(provider),
            "error": "cwd escapes MIRV_OPENCODE_ROOT",
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    if provider == "opencode":
        result = _oc.run(prompt, agent=agent, cwd=cwd, model=model, pure=pure, timeout=timeout)
        result["provider"] = "opencode"
        return result
    if provider == "claude":
        return _run_claude(prompt, agent, workdir, model, timeout)
    if provider == "codex":
        return {
            "provider": "codex", "ok": False,
            "error": "codex provider not implemented yet",
            "available": _is_available("codex"),
            "busy": _CODEX_LOCK.locked(), "cwd": str(workdir),
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    return {
        "provider": provider, "ok": False,
        "error": f"unknown provider '{provider}'. Allowed: {', '.join(PROVIDERS)}",
        "available": False, "cwd": str(workdir),
        "duration_ms": int((time.monotonic() - started) * 1000),
    }
