"""agency_agents.py — MIRV AI Persona Registry (Pack 17)

Third extensibility layer, next to ``plugin_manager.py`` (Python hooks) and
``skill_playbooks.py`` (Markdown playbooks). Where a **skill** packages
*methodology* for a task, an **agent persona** packages an *identity*: a
specialised expert with a voice, a mission, deliverables and hard rules
that can be injected as the system prompt of any AI call.

Each persona is a single Markdown file with a tiny YAML frontmatter::

    backend/agents/<division>/<slug>.md

Vendored personas are adapted from `agency-agents
<https://github.com/msitarzewski/agency-agents>`_ (MIT, © msitarzewski);
see ``backend/agents/ATTRIBUTION.md``.

Discovery order (later wins on slug collision):

    1. ``backend/agents/``       (vendored curated set, read-only)
    2. ``./.mirv/agents/``       (project — the only writable target)
    3. ``~/.mirv/agents/``       (personal)
    4. env ``MIRV_AGENTS_DIRS``  (comma-separated, highest priority)

Personas are advisory prompt material only: they never execute anything,
and the caller stays responsible for scope validation, redaction and
human approval of any AI-produced output.
"""

from __future__ import annotations

import logging
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_logger = logging.getLogger("vulnforge.agents")

# ════════════════════════════════════════════════════════════════
#  Constants
# ════════════════════════════════════════════════════════════════

_BACKEND_DIR = Path(__file__).resolve().parent           # backend/
_BUILTIN_AGENTS_DIR = _BACKEND_DIR / "agents"             # backend/agents
_PROJECT_AGENTS_DIR = Path(".mirv") / "agents"            # <cwd>/.mirv/agents
_PERSONAL_AGENTS_DIR = Path.home() / ".mirv" / "agents"   # ~/.mirv/agents

FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)$", re.DOTALL)
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_DIVISION_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")

_NAME_MAX_LEN = 96
_DESC_MAX_LEN = 600
_VIBE_MAX_LEN = 240
_EMOJI_MAX_LEN = 16
_BODY_MAX_CHARS = 60_000
DEFAULT_PROMPT_CHARS = 6_000
MAX_PROMPT_CHARS = 40_000

#: Known divisions with bilingual labels. Unknown divisions are accepted
#: (custom personas) and fall back to a generic label.
DIVISIONS: dict[str, dict[str, str]] = {
    "security": {
        "label": {"en": "Security", "es": "Seguridad"},
        "color": "#dc2626",
    },
    "testing": {
        "label": {"en": "Testing / QA", "es": "Testing / QA"},
        "color": "#0ea5e9",
    },
    "engineering": {
        "label": {"en": "Engineering", "es": "Ingeniería"},
        "color": "#22c55e",
    },
    "specialized": {
        "label": {"en": "Specialized", "es": "Especializado"},
        "color": "#a855f7",
    },
    "custom": {
        "label": {"en": "Custom", "es": "Personalizado"},
        "color": "#64748b",
    },
}

_NAMED_COLORS = {
    "red": "#dc2626", "orange": "#ea580c", "yellow": "#eab308",
    "green": "#22c55e", "blue": "#3b82f6", "purple": "#a855f7",
    "pink": "#ec4899", "teal": "#14b8a6", "cyan": "#06b6d4",
    "indigo": "#6366f1", "gray": "#6b7280", "grey": "#6b7280",
    "black": "#111827", "white": "#f9fafb",
}


# ════════════════════════════════════════════════════════════════
#  Dataclasses
# ════════════════════════════════════════════════════════════════

@dataclass
class AgentPersona:
    """A parsed agent persona (frontmatter + Markdown body)."""
    slug: str
    division: str
    name: str
    description: str = ""
    emoji: str = ""
    color: str = "#64748b"
    vibe: str = ""
    body: str = ""
    path: str = ""
    editable: bool = False
    mtime: float = 0.0

    def to_dict(self, include_body: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "slug": self.slug,
            "division": self.division,
            "name": self.name,
            "description": self.description,
            "emoji": self.emoji,
            "color": self.color,
            "vibe": self.vibe,
            "chars": len(self.body),
            "path": self.path,
            "editable": self.editable,
        }
        if include_body:
            data["body"] = self.body
        return data


@dataclass
class _Registry:
    """Discovery cache — rebuilt when any source file's mtime changes."""
    agents: dict[str, AgentPersona] = field(default_factory=dict)
    signature: tuple = ()
    dirs: list[str] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)


_registry = _Registry()


# ════════════════════════════════════════════════════════════════
#  Parsing helpers
# ════════════════════════════════════════════════════════════════

def _parse_frontmatter(content: str) -> tuple[dict[str, str], str]:
    """Split ``---`` frontmatter from the Markdown body (never raises)."""
    m = FRONTMATTER_RE.match(content)
    if not m:
        return {}, content
    raw, body = m.group(1), m.group(2)
    fm: dict[str, str] = {}
    key = None
    for line in raw.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if line[:1] in (" ", "\t") and key:
            fm[key] = (fm[key] + " " + line.strip()).strip()
            continue
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip().strip('"').strip("'")
        if key:
            fm[key] = value
    return fm, body


def _clean(value: Any, limit: int) -> str:
    """Collapse whitespace and bound the length of a frontmatter value."""
    text = " ".join(str(value or "").split())
    return text[:limit]


def _normalize_color(value: str) -> str:
    """Map named colours (``blue``) or hex to a safe ``#rrggbb`` value."""
    text = _clean(value, 32).lower()
    if text in _NAMED_COLORS:
        return _NAMED_COLORS[text]
    if re.fullmatch(r"#[0-9a-f]{6}", text):
        return text
    if re.fullmatch(r"[0-9a-f]{6}", text):
        return "#" + text
    return DIVISIONS["custom"]["color"]


def _truncate_body(body: str, limit: int) -> str:
    """Bound a persona body on a section boundary, keeping the head.

    Personas start with identity + mission, which is what makes the voice
    useful; the tail is usually reference material. A mid-word cut is
    avoided so the prompt stays readable.
    """
    if limit <= 0 or len(body) <= limit:
        return body
    head = body[:limit]
    cut = max(head.rfind("\n## "), head.rfind("\n### "))
    if cut > limit // 3:
        return head[:cut].rstrip() + "\n\n[… persona truncated …]"
    return head.rstrip() + "\n\n[… persona truncated …]"


def _parse_persona_file(path: Path, division: str, editable: bool) -> AgentPersona | None:
    """Read and validate one persona file (``None`` when unusable)."""
    try:
        content = path.read_text(encoding="utf-8")
    except Exception as exc:
        _logger.warning("Cannot read agent %s: %s", path, exc)
        return None
    fm, body = _parse_frontmatter(content)
    name = _clean(fm.get("name", ""), _NAME_MAX_LEN) or path.stem.replace("-", " ").title()
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = 0.0
    return AgentPersona(
        slug=path.stem,
        division=division,
        name=name,
        description=_clean(fm.get("description", ""), _DESC_MAX_LEN),
        emoji=_clean(fm.get("emoji", ""), _EMOJI_MAX_LEN),
        color=_normalize_color(fm.get("color", "")),
        vibe=_clean(fm.get("vibe", ""), _VIBE_MAX_LEN),
        body=body[:_BODY_MAX_CHARS],
        path=str(path),
        editable=editable,
        mtime=mtime,
    )


def _agents_dirs() -> list[Path]:
    """Resolve the discovery directories (later wins; write dir last)."""
    env = os.environ.get("MIRV_AGENTS_DIRS", "").strip()
    dirs: list[Path] = []
    if env:
        dirs.extend(Path(p).expanduser() for p in env.split(",") if p.strip())
    dirs.extend([_BUILTIN_AGENTS_DIR, _PROJECT_AGENTS_DIR, _PERSONAL_AGENTS_DIR])
    # The write directory is always searched last so custom personas
    # created at runtime win over bundled ones on slug collision.
    write_override = os.environ.get("MIRV_AGENTS_WRITE_DIR", "").strip()
    if write_override:
        dirs.append(Path(write_override).expanduser())
    seen: set[str] = set()
    unique: list[Path] = []
    for d in dirs:
        key = str(d)
        if key not in seen:
            seen.add(key)
            unique.append(d)
    return unique


def _writable_dir() -> Path:
    """Directory used by :func:`create_agent` (never the vendored tree)."""
    override = os.environ.get("MIRV_AGENTS_WRITE_DIR", "").strip()
    if override:
        return Path(override).expanduser()
    return _PROJECT_AGENTS_DIR


# ════════════════════════════════════════════════════════════════
#  Discovery
# ════════════════════════════════════════════════════════════════

def _signature(dirs: list[Path]) -> tuple:
    """Cheap change-detector: (dir, file, mtime) triples."""
    sig: list[tuple] = []
    for base in dirs:
        try:
            entries = sorted(base.glob("*/*.md"))
        except Exception:
            entries = []
        for p in entries:
            try:
                sig.append((str(base), p.name, p.stat().st_mtime))
            except OSError:
                continue
    return tuple(sig)


def discover(force: bool = False) -> dict[str, AgentPersona]:
    """Walk every discovery directory and (re)build the registry.

    Cheap on repeat calls: the cache is only rebuilt when a file's mtime
    or the set of source directories changed (or ``force=True``).
    """
    dirs = _agents_dirs()
    with _registry.lock:
        sig = _signature(dirs)
        if not force and sig == _registry.signature and _registry.agents:
            return dict(_registry.agents)

        builtin = str(_BUILTIN_AGENTS_DIR)
        agents: dict[str, AgentPersona] = {}
        for base in dirs:
            if not base.is_dir():
                continue
            try:
                entries = sorted(base.iterdir())
            except Exception as exc:
                _logger.warning("Cannot list agents dir %s: %s", base, exc)
                continue
            for div_dir in entries:
                if not div_dir.is_dir():
                    continue
                division = div_dir.name
                if not _DIVISION_RE.match(division):
                    _logger.warning("Skipping invalid division dir: %s", div_dir)
                    continue
                for md in sorted(div_dir.glob("*.md")):
                    if not _SLUG_RE.match(md.stem):
                        _logger.warning("Skipping invalid agent slug: %s", md.stem)
                        continue
                    persona = _parse_persona_file(md, division, str(base) != builtin)
                    if persona is None:
                        continue
                    agents[persona.slug] = persona

        _registry.agents = agents
        _registry.signature = sig
        _registry.dirs = [str(d) for d in dirs]
        return dict(agents)


# ════════════════════════════════════════════════════════════════
#  Read API
# ════════════════════════════════════════════════════════════════

def list_agents(division: str | None = None, q: str = "") -> list[dict[str, Any]]:
    """List personas (metadata only), optionally filtered.

    ``division`` matches the division directory; ``q`` is a case-insensitive
    substring searched across name, description and vibe.
    """
    agents = discover()
    div = (division or "").strip().lower()
    needle = (q or "").strip().lower()
    out: list[dict[str, Any]] = []
    for persona in agents.values():
        if div and persona.division.lower() != div:
            continue
        if needle:
            haystack = " ".join([persona.name, persona.description, persona.vibe, persona.slug]).lower()
            if needle not in haystack:
                continue
        out.append(persona.to_dict())
    out.sort(key=lambda d: (d["division"], d["name"].lower()))
    return out


def get_agent(slug: str) -> dict[str, Any] | None:
    """Return one persona including its Markdown body, or ``None``."""
    key = (slug or "").strip().lower()
    persona = discover().get(key)
    return persona.to_dict(include_body=True) if persona else None


def list_divisions() -> list[dict[str, Any]]:
    """Divisions with their agent counts (empty divisions are kept)."""
    agents = discover()
    counts: dict[str, int] = {}
    for persona in agents.values():
        counts[persona.division] = counts.get(persona.division, 0) + 1
    known = set(DIVISIONS) | set(counts)
    out = []
    for name in sorted(known):
        meta = DIVISIONS.get(name, {})
        out.append({
            "id": name,
            "label": meta.get("label", {"en": name.title(), "es": name.title()}),
            "color": meta.get("color", DIVISIONS["custom"]["color"]),
            "count": counts.get(name, 0),
        })
    return out


def summary() -> dict[str, Any]:
    """Counts and discovery sources, for dashboards."""
    agents = discover()
    return {
        "total": len(agents),
        "divisions": len({p.division for p in agents.values()}),
        "editable": sum(1 for p in agents.values() if p.editable),
        "chars": sum(len(p.body) for p in agents.values()),
        "dirs": list(_registry.dirs),
    }


# ════════════════════════════════════════════════════════════════
#  Prompt building
# ════════════════════════════════════════════════════════════════

def build_persona_prompt(
    slug: str,
    task: str = "",
    context: str = "",
    body_limit: int = DEFAULT_PROMPT_CHARS,
) -> str | None:
    """Compose the system prompt for a persona (``None`` if unknown slug).

    ``task`` / ``context`` are appended as explicit sections so the model
    keeps the identity and the assignment separate. Callers are expected
    to run the result through :func:`redact.redact_string` (the
    ``/api/ai/chat`` endpoint already redacts every message it forwards).
    """
    key = (slug or "").strip().lower()
    persona = discover().get(key)
    if persona is None:
        return None
    limit = max(0, min(int(body_limit or 0), MAX_PROMPT_CHARS))
    parts = [
        "You are acting as the MIRV AI persona **{name}** ({slug}, division: {division}).".format(
            name=persona.name, slug=persona.slug, division=persona.division,
        ),
    ]
    if persona.vibe:
        parts.append("Vibe: " + persona.vibe)
    if persona.description:
        parts.append("Mandate: " + persona.description)
    parts.append("")
    parts.append(_truncate_body(persona.body, limit).strip())
    if context.strip():
        parts.append("")
        parts.append("## Context\n" + context.strip())
    if task.strip():
        parts.append("")
        parts.append("## Assignment\n" + task.strip())
    return "\n".join(parts).strip()


# ════════════════════════════════════════════════════════════════
#  Write API (project dir only — vendored personas stay read-only)
# ════════════════════════════════════════════════════════════════

def _validate_slug(slug: str) -> str | None:
    cleaned = (slug or "").strip().lower()
    if not _SLUG_RE.match(cleaned):
        return "slug must match [a-z0-9][a-z0-9._-]{0,63}"
    return None


def _validate_division(division: str) -> str | None:
    cleaned = (division or "").strip().lower()
    if not cleaned:
        return "division is required"
    if not _DIVISION_RE.match(cleaned):
        return "division must match [a-z0-9][a-z0-9_-]{0,31}"
    return None


def create_agent(payload: dict[str, Any]) -> tuple[dict[str, Any] | None, str | None]:
    """Create a custom persona. Returns ``(agent, error)``.

    Writes into the project directory (``./.mirv/agents/<division>/<slug>.md``)
    so shipped personas are never mutated.
    """
    payload = payload if isinstance(payload, dict) else {}
    err = _validate_slug(payload.get("slug", ""))
    if err:
        return None, err
    slug = payload["slug"].strip().lower()
    err = _validate_division(payload.get("division", ""))
    if err:
        return None, err
    division = payload["division"].strip().lower()

    name = _clean(payload.get("name", ""), _NAME_MAX_LEN) or slug.replace("-", " ").title()
    description = _clean(payload.get("description", ""), _DESC_MAX_LEN)
    emoji = _clean(payload.get("emoji", ""), _EMOJI_MAX_LEN)
    vibe = _clean(payload.get("vibe", ""), _VIBE_MAX_LEN)
    body = str(payload.get("body", "") or "")
    if not body.strip():
        return None, "body is required"
    if len(body) > _BODY_MAX_CHARS:
        return None, "body exceeds %d chars" % _BODY_MAX_CHARS

    target_dir = _writable_dir() / division
    target = target_dir / (slug + ".md")
    if target.exists():
        return None, "agent '%s' already exists" % slug

    fm = ["---", "name: %s" % name]
    if description:
        fm.append('description: "%s"' % description.replace('"', "'"))
    if emoji:
        fm.append('emoji: "%s"' % emoji)
    fm.append("color: %s" % _normalize_color(payload.get("color", "")))
    if vibe:
        fm.append('vibe: "%s"' % vibe.replace('"', "'"))
    fm.append("---")

    try:
        target_dir.mkdir(parents=True, exist_ok=True)
        target.write_text("\n".join(fm) + "\n\n" + body.strip() + "\n", encoding="utf-8")
    except Exception as exc:
        _logger.warning("Cannot write agent %s: %s", target, exc)
        return None, "cannot write agent: %s" % exc

    discover(force=True)
    return get_agent(slug), None


def delete_agent(slug: str) -> tuple[bool, str | None]:
    """Delete a **custom** persona. Vendored personas are protected."""
    key = (slug or "").strip().lower()
    persona = discover().get(key)
    if persona is None:
        return False, "unknown agent"
    if not persona.editable:
        return False, "'%s' is a bundled persona and cannot be deleted" % key
    try:
        Path(persona.path).unlink()
    except Exception as exc:
        _logger.warning("Cannot delete agent %s: %s", persona.path, exc)
        return False, "cannot delete agent: %s" % exc
    discover(force=True)
    return True, None


# ════════════════════════════════════════════════════════════════
#  Export / import (metadata + body, for portable workspaces)
# ════════════════════════════════════════════════════════════════

def export_registry(division: str | None = None, include_body: bool = True) -> dict[str, Any]:
    """Export personas as JSON-safe data (optionally one division only).

    With ``include_body=True`` each entry carries its Markdown body, so the
    result can be fed straight back to :func:`import_registry`.
    """
    meta = list_agents(division=division)
    agents = meta
    if include_body:
        agents = [full for full in (get_agent(a["slug"]) for a in meta) if full]
    return {
        "schemaVersion": "1.0",
        "exported": len(meta),
        "agents": agents,
    }


def import_registry(data: dict[str, Any], overwrite: bool = False) -> dict[str, Any]:
    """Import personas exported by :func:`export_registry`.

    Bundled personas are skipped (they ship with the repo); only custom
    ones are written. Returns ``{"imported": n, "skipped": n, "errors": [...]}``.
    """
    data = data if isinstance(data, dict) else {}
    agents = data.get("agents")
    if not isinstance(agents, list):
        return {"imported": 0, "skipped": 0, "errors": ["agents must be a list"]}
    imported = skipped = 0
    errors: list[str] = []
    known = discover()
    for item in agents:
        if not isinstance(item, dict):
            errors.append("entry is not an object")
            continue
        slug = str(item.get("slug", "")).strip().lower()
        if slug and slug in known and not overwrite:
            skipped += 1
            continue
        if slug and slug in known and overwrite:
            ok, err = delete_agent(slug)
            if not ok and err:
                errors.append(err)
                continue
        agent, err = create_agent(item)
        if agent is None:
            errors.append("%s: %s" % (slug or "?", err))
            continue
        imported += 1
    discover(force=True)
    return {"imported": imported, "skipped": skipped, "errors": errors}
