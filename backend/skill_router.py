"""
skill_router.py — MIRV Skill Router

Deterministic, testable router that maps a free-text analyst task
("reverse this APK", "hay malware en memoria", "dame las cabeceras de X")
to a PRIMARY skill playbook (or internal module) plus the tools/artifacts
that fit that workflow.

Format inspired by the open-source ``reverse-skill`` routing pack (MIT):
a single ``routing.json`` is the source of truth.  Each rule expresses
keyword triggers (``must`` / ``exclude`` / ``mustAll``) as regexes; the
``priority`` array breaks scoring ties; an unmatched task falls back to
``meta.fallbackId``.

Config discovery (first match wins):

    1. file at env ``MIRV_ROUTER_CONFIG``
    2. shipped ``backend/skills/router/routing.json``
    3. embedded :data:`_DEFAULT_CONFIG` (never lets the router 500)

Config is hot-reloaded on mtime change (same contract as the skill
playbooks / plugin watcher). Invalid documents fail closed to the
embedded default.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import threading
from pathlib import Path
from typing import Any, Callable

_logger = logging.getLogger("vulnforge.router")

_BACKEND_DIR = Path(__file__).resolve().parent
_SHIPPED_CONFIG = _BACKEND_DIR / "skills" / "router" / "routing.json"

_LOCK = threading.Lock()
_CACHE: dict[str, Any] = {"mtime": None, "data": None, "source": None}

# =====================================================================
#  Tool index (used by detect_tools and suggested per-route tools)
# =====================================================================

DEFAULT_TOOL_INDEX: list[str] = [
    # recon / scanning
    "nmap", "masscan", "gobuster", "dirb", "ffuf", "wfuzz", "feroxbuster",
    "nikto", "whatweb", "wpscan", "sqlmap", "curl", "whois", "dnsrecon",
    "exiftool",
    # mobile / APK
    "jadx", "apktool", "frida", "adb", "apksigner", "mobsf", "objection",
    "java", "node", "python3",
    # reverse / binary
    "ghidra", "radare2", "r2", "gdb", "objdump", "strings", "angr",
    # malware / firmware / forensics
    "yara", "binwalk", "volatility3", "vol3", "plaso", "autopsy",
    "hashcat", "john", "hydra", "cewl", "pwntools", "checksec", "ropper",
]

# =====================================================================
#  Embedded fallback config (guaranteed to load even with no files)
# =====================================================================

_DEFAULT_CONFIG: dict[str, Any] = {
    "schemaVersion": "1.0",
    "meta": {
        "description": "MIRV skill router — built-in fallback config.",
        "fallbackId": "R0",
        "scoring": (
            "Each keyword block that matches adds 1 point to its route; "
            "the highest-scoring route on the priority order wins."
        ),
        "maintainers": [],
    },
    "routes": {
        "R1": {
            "label": {"en": "Recon / scanning", "es": "Reconocimiento / escaneo"},
            "skill": "recon",
            "module": "automation",
            "tools": ["nmap", "gobuster", "curl"],
            "keywords": [
                {"must": "nmap|portscan|port.?scan|recon|descubri|explor",
                 "note": "Generic recon / port scanning vocabulary."}
            ],
        },
        "R0": {
            "label": {
                "en": "General analysis (fallback)",
                "es": "Análisis general (respaldo)",
            },
            "skill": None,
            "module": "automation",
            "tools": [],
            "keywords": [
                {"must": "analy|analiz|task|hint|scan|probe", "note": "Catch-all."}
            ],
        },
    },
    "priority": ["R1", "R0"],
}

# =====================================================================
#  Validation
# =====================================================================

def _validate_config(cfg: Any) -> str | None:
    """Return an error string if ``cfg`` is not a valid routing config."""
    if not isinstance(cfg, dict):
        return "config is not a JSON object"
    if "schemaVersion" not in cfg:
        return "missing schemaVersion"
    meta = cfg.get("meta") or {}
    routes = cfg.get("routes")
    priority = cfg.get("priority")
    if not isinstance(routes, dict) or not routes:
        return "routes must be a non-empty object"
    if not isinstance(priority, list) or not priority:
        return "priority must be a non-empty list"
    if not isinstance(meta, dict) or not meta.get("fallbackId"):
        return "meta.fallbackId is required"
    unknown = [rid for rid in priority if rid not in routes]
    if unknown:
        return f"priority references unknown routes: {unknown}"
    for rid, route in routes.items():
        if not isinstance(route, dict):
            return f"route {rid}: not an object"
        if not route.get("label"):
            return f"route {rid}: missing label"
        label = route["label"]
        if isinstance(label, dict) and not label.get("en"):
            return f"route {rid}: label.en missing"
        kws = route.get("keywords")
        if not isinstance(kws, list) or not kws:
            return f"route {rid}: keywords must be a non-empty list"
        for kw in kws:
            if not isinstance(kw, dict) or not isinstance(kw.get("must"), str) or not kw["must"]:
                return f"route {rid}: keyword 'must' is required"
    return None


def _load_raw(path: Path) -> dict[str, Any] | None:
    """Load + validate a routing JSON file. Returns None on any failure."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        _logger.warning("[router] cannot read %s: %s", path, exc)
        return None
    err = _validate_config(raw)
    if err:
        _logger.warning("[router] invalid config %s: %s", path, err)
        return None
    return raw


# =====================================================================
#  Config loading (hot-reload on mtime)
# =====================================================================

def _config_path() -> Path:
    override = os.getenv("MIRV_ROUTER_CONFIG", "").strip()
    return Path(override) if override else _SHIPPED_CONFIG


def load_config(*, force: bool = False) -> dict[str, Any]:
    """
    Return the active routing config.

    Hot-reloads when the config file mtime changes (or when ``force``).
    Falls back to the shipped file, then to the embedded default.
    """
    global _CACHE
    path = _config_path()
    with _LOCK:
        if force:
            _CACHE = {"mtime": None, "data": None, "source": None}
        try:
            mtime = path.stat().st_mtime
        except OSError:
            mtime = None
        if _CACHE["data"] is not None and _CACHE["mtime"] == mtime and not force:
            return _CACHE["data"]

        if mtime is not None:
            raw = _load_raw(path)
            if raw is not None:
                _CACHE = {"mtime": mtime, "data": raw, "source": f"file:{path}"}
                return raw

        # Fall back to the file-less default (still validate it).
        err = _validate_config(_DEFAULT_CONFIG)
        if err:
            _logger.error("[router] embedded default invalid: %s", err)
            raise RuntimeError(f"skill router default config invalid: {err}")
        _logger.warning(
            "[router] no valid config at %s — using embedded default", path
        )
        _CACHE = {"mtime": mtime, "data": _DEFAULT_CONFIG, "source": "embedded"}
        return _DEFAULT_CONFIG


def reload_config() -> dict[str, Any]:
    """Force a config reload (used by the wrapper endpoint/tests)."""
    return load_config(force=True)


def config_source() -> str:
    """Forced reload + report where the active config came from."""
    cfg = load_config(force=True)
    return _CACHE.get("source", "embedded")


# =====================================================================
#  Matching engine
# =====================================================================

def _kw_matches(kw: dict[str, Any], text: str) -> bool:
    """Does one keyword block match ``text``? (must + exclude + mustAll)."""
    must = kw.get("must")
    if not must:
        return False
    if not re.search(must, text, re.IGNORECASE):
        return False
    if kw.get("exclude") and re.search(kw["exclude"], text, re.IGNORECASE):
        return False
    for sub in kw.get("mustAll") or []:
        if sub and not re.search(sub, text, re.IGNORECASE):
            return False
    return True


def _label(route: dict[str, Any], lang: str) -> str:
    raw = route.get("label", "")
    if isinstance(raw, dict):
        return str(raw.get(lang) or raw.get("en") or raw.get("es") or "")
    return str(raw)


def route_priority(rid: str, cfg: dict[str, Any] | None = None) -> int:
    """Priority index for a route id (lower = higher priority)."""
    cfg = cfg or load_config()
    priority = cfg.get("priority") or []
    try:
        return priority.index(rid)
    except ValueError:
        return len(priority) + 1


def _route_hits(route: dict[str, Any], text: str) -> list[dict[str, str]]:
    """Return matched keyword blocks (with their notes) for a route."""
    hits: list[dict[str, str]] = []
    for kw in route.get("keywords") or []:
        if _kw_matches(kw, text):
            hits.append({"note": kw.get("note") or ""})
    return hits


def route_task(hint: str, lang: str = "en") -> dict[str, Any]:
    """
    Route a free-text task to a PRIMARY skill/module.

    Scoring: every keyword block that matches adds 1 hit to its route.
    The PRIMARY is the highest-scoring route; ties are broken by the
    ``priority`` order.  No matches → ``meta.fallbackId``.
    """
    cfg = load_config()
    text = (hint or "").strip()
    if not text:
        text = " "
    fallback_id = (cfg.get("meta") or {}).get("fallbackId", "R0")
    priority = cfg.get("priority") or []
    routes = cfg.get("routes") or {}

    scored: list[tuple[int, int, str, list[dict[str, str]]]] = []
    for pos, rid in enumerate(priority):
        route = routes.get(rid)
        if not isinstance(route, dict):
            continue
        hits = _route_hits(route, text)
        if hits:
            scored.append((len(hits), pos, rid, hits))

    if not scored:
        rid = fallback_id
        route = routes.get(rid) or {}
        hits = []
        used_fallback = True
        pos = route_priority(rid, cfg)
        reason = (
            "No rule matched — using the fallback route (general analysis)."
            if lang != "es" else
            "Ninguna regla coincidió — se usa la ruta de respaldo (análisis general)."
        )
    else:
        counted = sorted(scored, key=lambda x: (-x[0], x[1]))
        hits_count, pos, rid, hits = counted[0]
        route = routes[rid]
        used_fallback = False
        reason = _rationale(len(hits), pos, _label(route, lang), route.get("skill"), lang)

    skill = route.get("skill") or None
    module = route.get("module") or None
    tools = list(route.get("tools") or [])

    primary = {
        "id": rid,
        "label": _label(route, lang),
        "skill": skill,
        "module": module,
        "tools": tools,
        "hits": len(hits),
        "priority": pos,
        "rationale": reason,
        "matched": [h["note"] for h in hits if h.get("note")],
        "keywords_count": len(route.get("keywords") or []),
    }

    alternatives = []
    if not used_fallback:
        for cnt, pos_, rid_, hits_ in sorted(scored, key=lambda x: (-x[0], x[1])):
            if rid_ == rid:
                continue
            r = routes[rid_]
            alternatives.append({
                "id": rid_,
                "label": _label(r, lang),
                "skill": r.get("skill") or None,
                "module": r.get("module") or None,
                "hits": cnt,
                "priority": pos_,
            })
            if len(alternatives) >= 5:
                break

    return {
        "ok": True,
        "hint": (hint or "").strip(),
        "primary": primary,
        "alternatives": alternatives,
        "fallback_used": used_fallback,
        "routes_scored": len(scored),
        "config_source": _CACHE.get("source") or "embedded",
    }


def _rationale(hits: int, pos: int, label: str, skill: Any, lang: str) -> str:
    skill_txt = skill if skill else "—"
    if lang == "es":
        base = f"Coinciden {hits} regla(s) de palabras clave en la ruta prioritaria «{label}»."
    else:
        base = f"Matched {hits} keyword rule(s) on priority route “{label}”."
    if skill:
        if lang == "es":
            return f"{base} Abre la skill «{skill}»."
        return f"{base} Opens skill “{skill}”."
    if lang == "es":
        return f"{base} Mapea al módulo «{skill_txt}»."
    return f"{base} Maps to module “{skill_txt}”."


# =====================================================================
#  Introspection
# =====================================================================

def list_routes(lang: str = "en") -> dict[str, Any]:
    """Summarize every configured route for the UI."""
    cfg = load_config()
    routes = cfg.get("routes") or {}
    priority = cfg.get("priority") or []
    items = []
    for pos, rid in enumerate(priority):
        r = routes.get(rid)
        if not isinstance(r, dict):
            continue
        items.append({
            "id": rid,
            "label": _label(r, lang),
            "skill": r.get("skill") or None,
            "module": r.get("module") or None,
            "tools": list(r.get("tools") or []),
            "keywords_count": len(r.get("keywords") or []),
            "priority": pos,
            "fallback": rid == (cfg.get("meta") or {}).get("fallbackId"),
        })
    return {
        "ok": True,
        "meta": cfg.get("meta") or {},
        "routes": items,
        "priority": list(priority),
        "fallbackId": (cfg.get("meta") or {}).get("fallbackId"),
        "config_source": _CACHE.get("source") or "embedded",
    }


def route_by_id(rid: str, lang: str = "en") -> dict[str, Any]:
    """Detail for a single route id."""
    cfg = load_config()
    routes = cfg.get("routes") or {}
    route = routes.get(rid)
    if not isinstance(route, dict):
        return {"ok": False, "error": f"Route {rid!r} not found"}
    return {
        "ok": True,
        "route_id": rid,
        "label": _label(route, lang),
        "skill": route.get("skill") or None,
        "module": route.get("module") or None,
        "tools": list(route.get("tools") or []),
        "keywords": route.get("keywords") or [],
        "priority": route_priority(rid, cfg),
        "fallback": rid == (cfg.get("meta") or {}).get("fallbackId"),
        "config_source": _CACHE.get("source") or "embedded",
    }


# =====================================================================
#  Tool detection
# =====================================================================

def detect_tools(
    which_fn: Callable[[str], str | None] = shutil.which,
    tools: list[str] | None = None,
) -> dict[str, Any]:
    """
    Detect which router-relevant tools are installed on the current host.

    ``which_fn`` defaults to :func:`shutil.which`; callers (e.g. the API)
    may inject a remote ``which`` (SSH to Kali) instead.  Missing tools
    are reported but never raise.
    """
    tools = tools if tools is not None else DEFAULT_TOOL_INDEX
    result: dict[str, bool] = {}
    try:
        for tool in tools:
            try:
                result[tool] = bool(which_fn(tool))
            except Exception:
                result[tool] = False
    except Exception as exc:
        _logger.warning("[router] detect_tools failed: %s", exc)
    present = sorted(t for t, ok in result.items() if ok)
    missing = sorted(t for t, ok in result.items() if not ok)
    return {
        "ok": True,
        "tools": result,
        "detected": present,
        "missing": missing,
        "total": len(result),
        "detected_count": len(present),
    }