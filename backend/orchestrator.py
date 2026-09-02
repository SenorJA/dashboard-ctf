"""
M.I.R.V. — Multi-Agent Orchestrator
===================================
Routes security tasks to specialist agents, each grounded in a skill playbook.
Inspired by OpenExecutive's orchestrator pattern (adapted for cybersecurity).

Architecture:
    User task → Orchestrator.route(task) → Specialist.execute(task, context) → LLM → structured response

Each specialist's system prompt is built from its corresponding skill playbook
(via skill_playbooks.render_skill_for_prompt, aliased here as ``sp_render``),
which serves as the grounding knowledge — the MIRV equivalent of
OpenExecutive's ChromaDB RAG.

The orchestrator is **prepared** for two future enhancements (Ronda 6b):

* **Episodic memory** — ``execute()`` accepts an opaque ``context`` string;
  future rounds may splice mission history there without API change.
* **Prompt caching** — messages are structured with the (large, stable)
  system prompt *first*, so providers that cache prefixes benefit immediately.

The module is import-safe: importing it never performs network I/O and never
raises.  Every public function returns a structured dict and swallows
exceptions so callers (FastAPI routes, tests, other agents) can rely on a
uniform ``{"ok": bool, ...}`` contract.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
import urllib.error
import uuid
from typing import Any

# ════════════════════════════════════════════════════════════════
#  Logger
# ════════════════════════════════════════════════════════════════

_logger = logging.getLogger("vulnforge.orchestrator")

# ════════════════════════════════════════════════════════════════
#  Specialists — each grounded in a skill playbook
# ════════════════════════════════════════════════════════════════

_SPECIALISTS: dict[str, dict[str, str]] = {
    "recon": {
        "skill": "recon",
        "description": "Reconnaissance & attack-surface mapping",
    },
    "webvuln": {
        "skill": "webvuln",
        "description": "Web vulnerability testing (OWASP Top 10)",
    },
    "osint": {
        "skill": "osint",
        "description": "Open-source intelligence",
    },
    "forensics": {
        "skill": "memory-forensics",
        "description": "Digital forensics & memory analysis",
    },
    "password-audit": {
        "skill": "password-audit",
        "description": "Password auditing & hash recovery",
    },
}

# Intent → specialist routing (keyword matching, case-insensitive substring)
_INTENT_KEYWORDS: dict[str, list[str]] = {
    "recon": ["recon", "enumerate", "discover", "subdomain", "port scan", "nmap", "fingerprint"],
    "webvuln": ["web", "sql", "xss", "ssrf", "jwt", "ssti", "deserializ", "owasp", "vulnerability", "injection"],
    "osint": ["osint", "email", "username", "phone", "instagram", "github", "wayback", "dork"],
    "forensics": ["forensic", "memory", "volatility", "disk", "artifact", "evidence", "incident"],
    "password-audit": ["password", "hash", "crack", "hashcat", "john", "brute", "ntlm", "kerberoast"],
}

# Vulnerability class → hunt-* skill specialization (ordered for precedence).
# Used by the ``webvuln`` specialist to load a deep-dive playbook for the
# specific class detected in the task. Exact multi-word phrases are listed
# first so substring collisions (e.g. "nosql" vs "sql") resolve correctly.
_HUNT_BY_CLASS: tuple[tuple[str, str], ...] = (
    # ── multi-word / high-specificity (checked first) ─────────────
    ("request smuggling", "hunt-http-smuggling"),
    ("http smuggling", "hunt-http-smuggling"),
    ("host header", "hunt-host-header"),
    ("open redirect", "hunt-open-redirect"),
    ("file upload", "hunt-file-upload"),
    ("account takeover", "hunt-ato"),
    ("business logic", "hunt-business-logic"),
    ("cache poisoning", "hunt-cache-poison"),
    ("cache poison", "hunt-cache-poison"),
    ("html injection", "hunt-html-injection"),
    ("race condition", "hunt-race-condition"),
    ("shadow api", "hunt-shadow-api"),
    ("auth bypass", "hunt-auth-bypass"),
    ("forgot password", "hunt-forgot-password"),
    ("mfa bypass", "hunt-mfa-bypass"),
    ("command injection", "hunt-rce"),
    ("template injection", "hunt-ssti"),
    ("source leak", "hunt-source-leak"),
    ("session fixation", "hunt-session"),
    ("brute force", "hunt-brute-force"),
    # ── single-word classes ───────────────────────────────────────
    ("nosql", "hunt-nosqli"),
    ("sql injection", "hunt-sqli"),
    ("sqli", "hunt-sqli"),
    ("graphql", "hunt-graphql"),
    ("ssti", "hunt-ssti"),
    ("xss", "hunt-xss"),
    ("csrf", "hunt-csrf"),
    ("cors", "hunt-cors"),
    ("ssrf", "hunt-ssrf"),
    ("xxe", "hunt-xxe"),
    ("lfi", "hunt-lfi"),
    ("idor", "hunt-idor"),
    ("jwt", "hunt-jwt-crypto"),
    ("oauth", "hunt-oauth"),
    ("saml", "hunt-saml"),
    ("rce", "hunt-rce"),
    ("websocket", "hunt-websocket"),
    ("subdomain", "hunt-subdomain"),
    ("k8s", "hunt-k8s"),
    ("kube", "hunt-k8s"),
    ("ldap", "hunt-ldap"),
    ("ntlm", "hunt-ntlm-info"),
    ("cicd", "hunt-cicd"),
    ("2fa", "hunt-mfa-bypass"),
    ("mfa", "hunt-mfa-bypass"),
    ("captcha", "hunt-captcha-bypass"),
    ("iot", "hunt-misc"),
)

# Fallback prompt when a specialist's skill playbook is missing/unavailable.
_GENERIC_PROMPT_TEMPLATE = (
    "You are a MIRV {specialist} specialist. "
    "Analyze the task and provide step-by-step guidance. "
    "Respond with a structured JSON array of steps."
)


# ════════════════════════════════════════════════════════════════
#  Skill playbook rendering (RAG-equivalent grounding)
# ════════════════════════════════════════════════════════════════

def _render_skill(skill_name: str) -> str:
    """Return the rendered markdown body of a skill playbook, or "" on failure.

    Imports lazily so a broken ``skill_playbooks`` module never prevents
    the orchestrator from booting.  The skill must be enabled/loaded to
    yield a body — callers that want raw discovery should use
    ``skill_playbooks`` directly.
    """
    try:
        from backend.skill_playbooks import render_skill_for_prompt as sp_render
        return sp_render(skill_name) or ""
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[orchestrator] sp_render('%s') failed: %s", skill_name, exc)
        return ""


def _safe_render_skill(skill_name: str) -> str:
    """Render a skill playbook for prompt injection, never raising."""
    try:
        return _render_skill(skill_name) if skill_name else ""
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[orchestrator] skill render raised: %s", exc)
        return ""


def _build_system_prompt(
    specialist: str,
    target: str,
    context: str,
    hunt_skill: str = "",
) -> str:
    """Build the specialist's system prompt from skill playbook + context.

    Layers (top → bottom):
      1. Role wrapper  ("You are a MIRV <specialist> specialist. ...")
      2. Skill playbook body  (the grounding knowledge — RAG equivalent)
      3. Dynamic context  (target + current findings)

    When ``hunt_skill`` names a specialized hunt-* playbook (e.g. the
    ``webvuln`` specialist detecting a specific vulnerability class), that
    deep-dive methodology *replaces* the generic base playbook so the LLM is
    grounded on the most relevant knowledge for the detected class.
    """
    spec_info = _SPECIALISTS.get(specialist, {})
    skill_name = spec_info.get("skill", "")

    # Specialized hunt-* methodology takes priority over the base playbook.
    hunt_body = _safe_render_skill(hunt_skill) if hunt_skill else ""
    if hunt_body:
        label = hunt_skill[len("hunt-"):].replace("-", " ") if hunt_skill.startswith("hunt-") else hunt_skill
        parts: list[str] = [
            f"You are a MIRV {specialist} specialist hunting {label}. "
            f"Use the specialized methodology below to complete the task. "
            f"Respond with a structured JSON array of steps.\n\n"
            f"{hunt_body}"
        ]
    else:
        skill_body = _safe_render_skill(skill_name)
        if skill_body:
            parts = [
                f"You are a MIRV {specialist} specialist. "
                f"Follow the methodology below to complete the task. "
                f"Respond with a structured JSON array of steps.\n\n"
                f"{skill_body}"
            ]
        else:
            # No playbook available — fall back to a generic prompt so the
            # specialist can still operate (no crash, degraded grounding).
            parts = [_GENERIC_PROMPT_TEMPLATE.format(specialist=specialist)]

    # Dynamic context block (always present so the LLM knows the target).
    ctx_lines = [
        "Context:",
        f"- Target: {target or 'unspecified'}",
        f"- Current findings: {context or 'none'}",
    ]
    parts.append("\n".join(ctx_lines))

    return "\n\n".join(parts)


# ════════════════════════════════════════════════════════════════
#  Routing
# ════════════════════════════════════════════════════════════════

def route(task: str) -> str:
    """Identify the best specialist for ``task`` via keyword matching.

    * Case-insensitive substring matching against ``_INTENT_KEYWORDS``.
    * Multiple matches → the specialist with the **most** keyword hits wins.
    * No match → ``"recon"`` (recon is always a sensible default).
    * Never raises — bad input yields the default.
    """
    if not task or not isinstance(task, str):
        return "recon"

    lowered = task.lower()
    scores: dict[str, int] = {}
    for specialist, keywords in _INTENT_KEYWORDS.items():
        hits = sum(1 for kw in keywords if kw in lowered)
        if hits > 0:
            scores[specialist] = hits

    if not scores:
        return "recon"

    # Highest hit count wins; ties broken by dict insertion order (stable).
    return max(scores, key=lambda s: scores[s])


def route_hunt(task: str) -> str:
    """Identify the best hunt-* skill for a web vulnerability task.

    * Case-insensitive substring matching against ``_HUNT_BY_CLASS``.
    * Multiple matches → the skill with the **most** keyword hits wins.
      Ties are broken by the precedence order in ``_HUNT_BY_CLASS``.
    * No match → ``""`` (the base ``webvuln`` playbook is used instead).
    * Never raises — bad input yields ``""``.
    """
    if not task or not isinstance(task, str):
        return ""

    lowered = task.lower()
    scores: dict[str, int] = {}
    for keyword, skill in _HUNT_BY_CLASS:
        if keyword in lowered:
            scores[skill] = scores.get(skill, 0) + 1

    return max(scores, key=lambda s: scores[s]) if scores else ""


def list_hunt_skills() -> list[dict]:
    """Return the hunt-* specialization map as ``[{"skill", "keywords"}, ...]``."""
    grouped: dict[str, list[str]] = {}
    for keyword, skill in _HUNT_BY_CLASS:
        grouped.setdefault(skill, []).append(keyword)
    return [
        {"skill": skill, "keywords": keywords}
        for skill, keywords in grouped.items()
    ]


# ════════════════════════════════════════════════════════════════
#  LLM call (local helper — avoids importing main.py to prevent cycles)
# ════════════════════════════════════════════════════════════════

def _resolve_provider_config(provider: str, api_key: str, model: str) -> tuple[str, str, str]:
    """Resolve (provider, api_key, model) from explicit args + env vars.

    Env fallbacks (set by the operator or frontend):
        MIRV_AI_PROVIDER  — default provider  (default "local")
        MIRV_AI_KEY       — default API key   (default "")
        MIRV_AI_MODEL     — default model     (default "")

    Explicit non-empty arguments always win over env.
    """
    p = provider or (os.getenv("MIRV_AI_PROVIDER") or "") or "local"
    k = api_key if api_key else (os.getenv("MIRV_AI_KEY") or "")
    m = model if model else (os.getenv("MIRV_AI_MODEL") or "")
    return p, k, m


def _call_llm(
    provider: str,
    api_key: str,
    model: str,
    messages: list[dict],
    timeout: float = 240.0,
) -> str:
    """Call an OpenAI-compatible LLM endpoint synchronously.

    This is a **self-contained** helper (no import of ``backend.main``) so
    the orchestrator never risks an import cycle with the FastAPI app.  It
    supports the ``local`` (Ollama / LM Studio) provider out of the box
    and the common OpenAI-compatible cloud providers.

    Raises on failure — callers wrap in try/except.
    """
    p, k, m = _resolve_provider_config(provider, api_key, model)

    if p == "local":
        base = (os.getenv("OLLAMA_URL") or "http://localhost:11434").strip() or "http://localhost:11434"
        if not m:
            m = "llama3"
        url = f"{base.rstrip('/')}/v1/chat/completions"
    else:
        base_map = {
            "openai": "https://api.openai.com/v1",
            "openrouter": "https://openrouter.ai/api/v1",
            "deepseek": "https://api.deepseek.com/v1",
            "groq": "https://api.groq.com/openai/v1",
        }
        default_model_map = {
            "openai": "gpt-4o-mini",
            "openrouter": "gpt-4o-mini",
            "deepseek": "deepseek-chat",
            "groq": "llama-3.3-70b-versatile",
        }
        if p not in base_map:
            raise ValueError(f"Unknown provider: {p}")
        if not m:
            m = default_model_map.get(p, "gpt-4o-mini")
        url = f"{base_map[p]}/chat/completions"

    body = json.dumps({
        "model": m,
        "messages": messages,
        "temperature": 0.3,
        "max_tokens": 1024,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json; charset=utf-8")
    if k:
        req.add_header("Authorization", f"Bearer {k}")
    req.add_header("User-Agent", "MIRV-Orchestrator/1.0")

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            data = json.loads(raw.decode("utf-8"))
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", str(data))
            return str(data)
    except UnicodeDecodeError as exc:
        raise RuntimeError(f"Encoding error from {p}: {exc}") from exc
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")[:500]
        raise RuntimeError(f"API error {exc.code} (provider={p}, model={m}): {err_body}") from exc


# ════════════════════════════════════════════════════════════════
#  Scope gate (defensive — initial 5 specialists do not require scope)
# ════════════════════════════════════════════════════════════════

def _skill_requires_scope(skill_name: str) -> bool:
    """Return True if a skill playbook is flagged ``requires_scope``.

    Defensive: defaults to False on any error so the orchestrator never
    hard-blocks a task because of a missing skill manifest.
    """
    try:
        from backend.skill_playbooks import get_skill_info
        if not skill_name:
            return False
        info = get_skill_info(skill_name)
        if not info:
            return False
        return bool(info.get("requires_scope"))
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[orchestrator] scope-flag lookup failed: %s", exc)
        return False


def _specialist_requires_scope(specialist: str) -> bool:
    """Return True if the specialist's skill playbook is flagged ``requires_scope``."""
    spec_info = _SPECIALISTS.get(specialist, {})
    return _skill_requires_scope(spec_info.get("skill", ""))


def _scope_authorized() -> bool:
    """Return True if an authorized scope is currently configured."""
    try:
        from backend.scope_guard import get_config as _get_scope_config
        cfg = _get_scope_config() or {}
        return bool(cfg.get("targets"))
    except Exception as exc:  # pragma: no cover — defensive
        _logger.debug("[orchestrator] scope config lookup failed: %s", exc)
        return False


# ════════════════════════════════════════════════════════════════
#  Execution
# ════════════════════════════════════════════════════════════════

def execute(
    task: str,
    context: str = "",
    specialist: str = "",
    target: str = "",
    timeout: float = 240.0,
    provider: str = "",
    api_key: str = "",
    model: str = "",
    session_id: str = "",
) -> dict:
    """Route ``task`` to a specialist and call the LLM grounded in its playbook.

    Parameters
    ----------
    task : str
        The user's security task (free text). Redacted before LLM call.
    context : str
        Dynamic context (current findings, mission memory, ...). Redacted.
    specialist : str
        Force a specialist; empty → auto-route via :func:`route`.
    target : str
        Target host/scope (informational, added to the prompt context).
    timeout : float
        LLM request timeout in seconds.
    provider / api_key / model : str
        Optional LLM provider override; fall back to env / ``local``.
    session_id : str
        Optional episodic-memory session id. When set, past decisions
        for this session are injected into the system prompt; after the
        call, the new interaction is appended to the episodic store.

    Returns
    -------
    dict
        ``{"ok": True, "specialist": str, "response": str, "task": str,
        "session_id": str}`` on success, or ``{"ok": False, "error": str}``
        on any failure. Never raises.
    """
    try:
        # ── Resolve / mint session id (for episodic memory) ──────────
        session_id = session_id or str(uuid.uuid4())

        # ── Resolve specialist ─────────────────────────────────────
        if not specialist:
            specialist = route(task)
        if specialist not in _SPECIALISTS:
            return {
                "ok": False,
                "error": f"Unknown specialist: {specialist}",
            }

        # ── Scope gate (defensive — current specialists don't need it) ──
        if _specialist_requires_scope(specialist) and not _scope_authorized():
            return {
                "ok": False,
                "error": "This specialist requires an authorized scope.",
            }

        # ── Hunt-skill specialization (webvuln → hunt-<class>) ──────────
        # When the webvuln specialist is tasked, detect the vulnerability
        # class and ground the agent on the matching deep-dive hunt-* skill.
        # Offensive hunt skills flagged ``requires_scope`` are skipped (with
        # graceful degradation to the base webvuln playbook) unless an
        # authorized scope is configured.
        hunt_skill = ""
        if specialist == "webvuln":
            try:
                hunt_skill = route_hunt(task or "")
                if hunt_skill and _skill_requires_scope(hunt_skill) and not _scope_authorized():
                    hunt_skill = ""
            except Exception as exc:  # pragma: no cover — defensive
                _logger.debug("[orchestrator] hunt detection failed: %s", exc)
                hunt_skill = ""

        # ── Redact sensitive data before crossing the trust boundary ──
        try:
            from backend.redact import redact_string
            safe_task = redact_string(task or "")
            safe_context = redact_string(context or "")
        except Exception as exc:  # pragma: no cover — defensive
            _logger.debug("[orchestrator] redact unavailable: %s", exc)
            safe_task = task or ""
            safe_context = context or ""

        # ── Build grounded system prompt ───────────────────────────
        system_prompt = _build_system_prompt(
            specialist, target, safe_context, hunt_skill=hunt_skill
        )

        # ── Inject episodic memory for this session (if any) ───────
        # Past decisions ground the LLM on what was already recommended,
        # the MIRV equivalent of OpenExecutive's episodic recall. Wrapped
        # defensively — a memory failure must never break execution.
        try:
            from backend import episodic_memory
            past = episodic_memory.get_episodic_context(session_id)
            if past:
                system_prompt = f"{system_prompt}\n\n{past}"
        except Exception as exc:  # pragma: no cover — defensive
            _logger.debug("[orchestrator] episodic recall failed: %s", exc)

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": safe_task},
        ]

        # ── Call LLM ───────────────────────────────────────────────
        response = _call_llm(
            provider=provider,
            api_key=api_key,
            model=model,
            messages=messages,
            timeout=timeout,
        )

        # ── Persist episodic memory (best-effort, never crashes) ───
        try:
            from backend import episodic_memory
            episodic_memory.save_episodic_memory(
                session_id=session_id,
                specialist=specialist,
                task=task,
                response=response,
            )
        except Exception as exc:  # pragma: no cover — defensive
            _logger.debug("[orchestrator] episodic save failed: %s", exc)

        return {
            "ok": True,
            "specialist": specialist,
            "hunt_skill": hunt_skill,
            "response": response,
            "task": task,
            "session_id": session_id,
        }
    except Exception as exc:
        _logger.warning("[orchestrator] execute failed: %s", exc, exc_info=False)
        return {"ok": False, "error": str(exc)}


# ════════════════════════════════════════════════════════════════
#  Introspection
# ════════════════════════════════════════════════════════════════

def list_specialists() -> list[dict]:
    """Return all specialists as ``[{"name", "skill", "description"}, ...]``."""
    return [
        {"name": name, "skill": spec["skill"], "description": spec["description"]}
        for name, spec in _SPECIALISTS.items()
    ]


def get_specialist(name: str) -> dict | None:
    """Return info for a single specialist, or ``None`` if unknown."""
    spec = _SPECIALISTS.get(name)
    if not spec:
        return None
    return {"name": name, "skill": spec["skill"], "description": spec["description"]}
