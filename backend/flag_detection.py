"""
flag_detection.py -- MIRV Module

Deterministic flag (user/root) detection for lab / HTB-style sessions.

Ported and adapted from afsh4ck/exploitpath (``server/db.ts``) — MIT-style
educational project. Pure, dependency-free functions:

  * ``detect_flag(command, output, prior_history="")`` — inspects the newest
    step but uses the accumulated prior history only to infer the *type*.
  * ``derive_session_state(detections, latest_analysis_phase=None)`` — folds a
    chronologically ordered list of detections into capture flags + phase.

Design goals: no false positives from unrelated hashes, no flag capture from a
mere ``root.txt`` path reference, ANSI/CR stripping, and tolerance of pasted
interactive SSH transcripts.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, TypedDict

MAX_FLAG_VALUE_LENGTH = 128

# 20..128 alphanumeric characters (HTB flags may exceed strict 32-hex).
FLAG_TOKEN = r"[A-Za-z0-9]{20,128}"

_ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

_ROOT_MARKERS = ("root.txt", "administrator\\desktop", "uid=0", "nt authority\\system")
_USER_MARKERS = ("user.txt",)

_EXPLICIT_FILE_RE = re.compile(
    r"(?:cat|type|get-content|gc)\s+[^\n]*?(user|root)\.txt[^\n]*(?:\n\s*)+(" + FLAG_TOKEN + r")(?=\s|$)",
    re.IGNORECASE,
)
_LABELED_RE = re.compile(
    r"\b(user|root)(?:\s+flag)?\s*[:=]\s*(" + FLAG_TOKEN + r")\b",
    re.IGNORECASE,
)
_CONTENT_RE = re.compile(
    r"(?:^|\n)\s*content\s*:\s*(?:\n\s*)?(" + FLAG_TOKEN + r")(?=\s|$)",
    re.IGNORECASE,
)
_STRICT_HEX_RE = re.compile(r"\b[a-f0-9]{32}\b", re.IGNORECASE)


class FlagDetection(TypedDict, total=False):
    """Result of a single-step detection. ``value`` may be absent."""

    type: str  # "none" | "user" | "root"
    value: str


class SessionState(TypedDict):
    """Folded state for a session."""

    userFlagCaptured: bool
    rootFlagCaptured: bool
    userFlagValue: Optional[str]
    rootFlagValue: Optional[str]
    phase: str


def _clean_terminal_text(value: str) -> str:
    """Strip ANSI escape sequences and carriage returns from terminal text."""
    return _ANSI_RE.sub("", (value or "").replace("\r", ""))


def _latest_flag_context_type(source: str) -> str:
    """Infer whether the latest root/user marker in ``source`` is root or user."""
    context = source.lower()
    root_index = max((context.rfind(m) for m in _ROOT_MARKERS), default=-1)
    user_index = max((context.rfind(m) for m in _USER_MARKERS), default=-1)
    if root_index < 0 and user_index < 0:
        return "none"
    return "root" if root_index > user_index else "user"


def detect_flag(command: str, output: str, prior_history: str = "") -> FlagDetection:
    """Detect a user/root flag in the newest step.

    Prior history is only used to disambiguate the type of an otherwise
    context-free token (e.g. a ``Content:`` value or a bare 32-hex string).
    """
    current = _clean_terminal_text(f"{command}\n{output}")
    context = _clean_terminal_text(f"{prior_history}\n{current}")

    explicit = _EXPLICIT_FILE_RE.search(current)
    if explicit:
        return {"type": explicit.group(1).lower(), "value": explicit.group(2)}

    labeled = _LABELED_RE.search(current)
    if labeled:
        return {"type": labeled.group(1).lower(), "value": labeled.group(2)}

    content_value = _CONTENT_RE.search(output or "")
    if content_value:
        ctype = _latest_flag_context_type(context)
        if ctype != "none":
            return {"type": ctype, "value": content_value.group(1)}

    strict = _STRICT_HEX_RE.search(current)
    if not strict:
        return {"type": "none"}
    ctype = _latest_flag_context_type(context)
    if ctype == "none":
        return {"type": "none", "value": strict.group(0)}
    return {"type": ctype, "value": strict.group(0)}


def derive_session_state(
    detections: List[FlagDetection],
    latest_analysis_phase: Optional[str] = None,
) -> SessionState:
    """Fold chronologically ordered detections into capture flags + phase.

    Root capture wins (phase ``complete``); otherwise a captured user flag
    yields ``foothold``, an AI-derived phase is honored, and the default is
    ``recon``. Recomputing on every edit/delete keeps state honest.
    """
    last = lambda t: next((d for d in reversed(detections) if d.get("type") == t), None)

    user = last("user")
    root = last("root")
    analysis_phase = (
        latest_analysis_phase
        if latest_analysis_phase in ("recon", "foothold", "privesc")
        else None
    )
    if root:
        phase = "complete"
    elif analysis_phase:
        phase = analysis_phase
    elif user:
        phase = "foothold"
    else:
        phase = "recon"
    return {
        "userFlagCaptured": user is not None,
        "rootFlagCaptured": root is not None,
        "userFlagValue": user.get("value") if user else None,
        "rootFlagValue": root.get("value") if root else None,
        "phase": phase,
    }


def normalize_detection(detection: Dict[str, object]) -> FlagDetection:
    """Coerce an arbitrary dict into a safe, length-bounded detection."""
    dtype = str(detection.get("type") or "none").lower()
    if dtype not in ("none", "user", "root"):
        dtype = "none"
    value = detection.get("value")
    out: FlagDetection = {"type": dtype}
    if isinstance(value, str) and value:
        out["value"] = value[:MAX_FLAG_VALUE_LENGTH]
    return out
