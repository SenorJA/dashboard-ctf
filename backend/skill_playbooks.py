"""
skill_playbooks.py — MIRV Skill Playbooks System

A second extensibility layer on top of ``plugin_manager.py``.
Where plugins require writing Python, **Skill Playbooks** are lightweight
Markdown files (``SKILL.md``) with a tiny YAML frontmatter that package
methodology, payloads and ``allowed_tools`` constraints so analysts can
codify their tradecraft without writing any code.

Each skill lives in a directory::

    backend/skills/<name>/
        SKILL.md          # frontmatter + methodology (markdown body)
        payloads/         # optional *.txt payload files

Discovery order (later wins on name collision):

    1. ``backend/skills/``      (shipped built-ins)
    2. ``./.mirv/skills/``       (project)
    3. ``~/.mirv/skills/``       (personal)
    4. config ``skills_dirs``    (env ``MIRV_SKILLS_DIRS`` comma-separated)

Discovered skills default to **disabled** — they must be explicitly
enabled (``load_skill`` / ``enable_skill``) before their body is
injected into AI chat context via ``render_skill_for_prompt``.
"""

from __future__ import annotations

import os
import re
import threading
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# ════════════════════════════════════════════════════════════════
#  Logger
# ════════════════════════════════════════════════════════════════

_logger = logging.getLogger("vulnforge.skills")

# ════════════════════════════════════════════════════════════════
#  Constants
# ════════════════════════════════════════════════════════════════

_BACKEND_DIR = Path(__file__).resolve().parent          # backend/
_BUILTIN_SKILLS_DIR = _BACKEND_DIR / "skills"            # backend/skills
_PROJECT_SKILLS_DIR = Path(".mirv") / "skills"           # <cwd>/.mirv/skills
_PERSONAL_SKILLS_DIR = Path.home() / ".mirv" / "skills"  # ~/.mirv/skills

_SKILL_FILENAME = "SKILL.md"
_PAYLOADS_SUBDIR = "payloads"

_NAME_RE = re.compile(r"^[a-z0-9_-]+$")
_NAME_MAX_LEN = 64
_DESC_MAX_LEN = 1024
_DEFAULT_VERSION = "1.0.0"

# Accepted categories. Empty / unknown category falls back to "custom".
VALID_CATEGORIES = {
    "recon", "webvuln", "ssrf", "ssti", "jwt", "graphql", "race",
    "takeover", "supabase", "deserialize", "custom",
}

# Frontmatter: ---\n<yaml-ish>\n---\n<body>
FRONTMATTER_RE = re.compile(r'^---\s*\n(.*?)\n---\s*\n(.*)$', re.DOTALL)

# ════════════════════════════════════════════════════════════════
#  Dataclasses
# ════════════════════════════════════════════════════════════════

@dataclass
class SkillManifest:
    """Structured frontmatter of a ``SKILL.md`` file."""
    name: str                   # ≤64 chars, must match dir name
    description: str            # ≤1024 chars — tells agent when to load
    category: str               # one of VALID_CATEGORIES (or "custom")
    allowed_tools: list[str]    # MIRV tool IDs from arsenal (may be empty = all)
    disable_model_invocation: bool = False  # if True, only reachable via manual /skill <name>
    version: str = _DEFAULT_VERSION
    author: str = ""


@dataclass
class SkillInfo:
    """Runtime state for a single discovered skill."""
    name: str
    manifest: SkillManifest
    dir_path: str               # absolute path
    body: str                   # markdown body content
    enabled: bool = True        # whether the skill should be injected
    loaded_at: str | None = None
    payloads: dict = field(default_factory=dict)  # {filename: content}


# ════════════════════════════════════════════════════════════════
#  Module-level state
# ════════════════════════════════════════════════════════════════

_registry: dict[str, SkillInfo] = {}
_skills_dirs: list[Path] = []
_lock = threading.Lock()


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _skills_dirs_resolved() -> list[Path]:
    """Return the ordered list of discovery directories."""
    dirs: list[Path] = [
        _BUILTIN_SKILLS_DIR,
        _PROJECT_SKILLS_DIR,
        _PERSONAL_SKILLS_DIR,
    ]
    env_dirs = os.getenv("MIRV_SKILLS_DIRS", "")
    for piece in env_dirs.split(","):
        piece = piece.strip()
        if piece:
            dirs.append(Path(piece))
    return dirs


def _parse_skill_md(content: str) -> tuple[dict, str]:
    """
    Parse ``SKILL.md`` content into ``(frontmatter_dict, body)``.

    The frontmatter is a *tiny* YAML subset — only ``key: value`` lines
    and ``key:`` followed by a bulleted list (``- item``).  No nested
    mappings, no anchors, no flow collections.  This keeps the parser
    dependency-free.

    Lists can be expressed either inline (``key: [a, b, c]``) or
    block-style (``key:\\n  - a\\n  - b``).  Quoted strings are
    stripped of surrounding quotes.
    """
    m = FRONTMATTER_RE.match(content)
    if not m:
        return {}, content

    fm_text = m.group(1)
    body = m.group(2)
    frontmatter: dict[str, Any] = {}

    lines = fm_text.split("\n")
    i = 0
    while i < len(lines):
        line = lines[i]
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            i += 1
            continue

        if ":" not in line:
            i += 1
            continue

        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()

        if value == "":
            # Look ahead for a block list
            items: list[str] = []
            j = i + 1
            while j < len(lines):
                nxt = lines[j]
                if not nxt.strip():
                    j += 1
                    continue
                if re.match(r"^\s*-\s+", nxt):
                    item = re.sub(r"^\s*-\s+", "", nxt).strip()
                    items.append(_unquote(item))
                    j += 1
                else:
                    break
            if items:
                frontmatter[key] = items
                i = j
                continue
            # No list found — keep empty string
            frontmatter[key] = ""
            i += 1
            continue

        # Inline value
        if value.startswith("[") and value.endswith("]"):
            inner = value[1:-1]
            frontmatter[key] = [
                _unquote(x.strip())
                for x in inner.split(",") if x.strip()
            ]
        else:
            frontmatter[key] = _unquote(value)
        i += 1

    return frontmatter, body


def _unquote(v: str) -> str:
    """Strip surrounding single/double quotes from a scalar value."""
    if len(v) >= 2 and ((v.startswith('"') and v.endswith('"')) or
                        (v.startswith("'") and v.endswith("'"))):
        return v[1:-1]
    return v


def _to_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, str):
        return v.strip().lower() in {"true", "yes", "1", "on"}
    return bool(v)


def _validate_manifest(fm: dict, dir_name: str) -> tuple[SkillManifest | None, str | None]:
    """Validate parsed frontmatter and build a SkillManifest."""
    name = str(fm.get("name", dir_name)).strip()
    if not name:
        return None, "Manifest missing required field: 'name'"
    if not _NAME_RE.match(name):
        return None, f"Invalid skill name '{name}' (allowed: ^[a-z0-9_-]+$ )"
    if len(name) > _NAME_MAX_LEN:
        return None, f"Skill name too long (max {_NAME_MAX_LEN} chars)"
    if name != dir_name:
        return None, f"Skill name '{name}' does not match directory name '{dir_name}'"

    description = str(fm.get("description", "")).strip()
    if not description:
        return None, "Manifest missing required field: 'description'"
    if len(description) > _DESC_MAX_LEN:
        return None, f"Description too long (max {_DESC_MAX_LEN} chars)"

    category = str(fm.get("category", "")).strip()
    if not category or category not in VALID_CATEGORIES:
        category = "custom"

    raw_tools = fm.get("allowed_tools", [])
    if isinstance(raw_tools, str):
        # inline list string fallback
        raw_tools = [t.strip() for t in raw_tools.split(",") if t.strip()]
    elif isinstance(raw_tools, list):
        raw_tools = [str(t).strip() for t in raw_tools if str(t).strip()]
    else:
        raw_tools = []

    version = str(fm.get("version", _DEFAULT_VERSION)).strip() or _DEFAULT_VERSION
    author = str(fm.get("author", "")).strip()
    disable_model = _to_bool(fm.get("disable_model_invocation", False))

    manifest = SkillManifest(
        name=name,
        description=description,
        category=category,
        allowed_tools=raw_tools,
        disable_model_invocation=disable_model,
        version=version,
        author=author,
    )
    return manifest, None


def _load_payloads(skill_dir: Path) -> dict[str, str]:
    """Read ``payloads/*.txt`` files from a skill directory."""
    payloads: dict[str, str] = {}
    pdir = skill_dir / _PAYLOADS_SUBDIR
    if not pdir.is_dir():
        return payloads
    try:
        for entry in sorted(pdir.iterdir()):
            if entry.is_file() and entry.suffix == ".txt":
                try:
                    payloads[entry.name] = entry.read_text(encoding="utf-8")
                except Exception as exc:
                    _logger.warning("Failed to read payload %s: %s", entry, exc)
    except Exception as exc:
        _logger.warning("Failed to scan payloads in %s: %s", pdir, exc)
    return payloads


def _info_dict(info: SkillInfo) -> dict:
    """Build a JSON-safe dict from a SkillInfo."""
    return {
        "name": info.name,
        "description": info.manifest.description,
        "category": info.manifest.category,
        "allowed_tools": list(info.manifest.allowed_tools),
        "disable_model_invocation": info.manifest.disable_model_invocation,
        "version": info.manifest.version,
        "author": info.manifest.author,
        "dir_path": info.dir_path,
        "enabled": info.enabled,
        "loaded_at": info.loaded_at,
        "body_length": len(info.body),
        "payloads": list(info.payloads.keys()),
    }


# ════════════════════════════════════════════════════════════════
#  1. discover_skills
# ════════════════════════════════════════════════════════════════

def discover_skills() -> list[str]:
    """
    Walk all discovery directories in order and populate ``_registry``.

    On name collision, the *later* directory in the discovery order wins
    (project overrides built-in, personal overrides project, etc.).

    Discovered skills default to ``enabled=False`` — they must be
    explicitly enabled via :func:`load_skill` or :func:`enable_skill`.

    Returns
    -------
    list[str] : Names of discovered skills (sorted).
    """
    global _skills_dirs
    _skills_dirs = _skills_dirs_resolved()
    discovered: list[str] = []

    for base in _skills_dirs:
        if not base.is_dir():
            continue
        try:
            entries = sorted(base.iterdir())
        except Exception as exc:
            _logger.warning("Cannot list skills dir %s: %s", base, exc)
            continue

        for entry in entries:
            if not entry.is_dir():
                continue
            skill_file = entry / _SKILL_FILENAME
            if not skill_file.is_file():
                continue

            try:
                content = skill_file.read_text(encoding="utf-8")
            except Exception as exc:
                _logger.warning("Cannot read %s: %s", skill_file, exc)
                continue

            fm, body = _parse_skill_md(content)
            manifest, err = _validate_manifest(fm, entry.name)
            if manifest is None:
                _logger.warning("Invalid skill '%s': %s", entry.name, err)
                continue

            payloads = _load_payloads(entry)
            info = SkillInfo(
                name=manifest.name,
                manifest=manifest,
                dir_path=str(entry.resolve()),
                body=body,
                enabled=False,                # default: disabled
                loaded_at=None,
                payloads=payloads,
            )

            with _lock:
                existing = _registry.get(manifest.name)
                # Preserve runtime state across re-discovery so callers like
                # ``reload_skill`` don't accidentally disable other skills.
                if existing is not None:
                    info.enabled = existing.enabled
                    info.loaded_at = existing.loaded_at
                _registry[manifest.name] = info  # later dir wins
            discovered.append(manifest.name)
            _logger.debug("Discovered skill '%s' from %s", manifest.name, entry)

    return sorted(discovered)


# ════════════════════════════════════════════════════════════════
#  2. load_skill
# ════════════════════════════════════════════════════════════════

def load_skill(name: str) -> dict:
    """
    Load a discovered skill: mark enabled, refresh payloads, set timestamp.

    Returns
    -------
    dict : ``{"ok": bool, "skill": dict | None, "error": str | None}``
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        # try discover first
        discover_skills()
        with _lock:
            info = _registry.get(name)

    if info is None:
        return {"ok": False, "skill": None, "error": f"Skill '{name}' not found"}

    # Refresh body & payloads from disk in case they changed
    skill_dir = Path(info.dir_path)
    skill_file = skill_dir / _SKILL_FILENAME
    try:
        content = skill_file.read_text(encoding="utf-8")
        _, body = _parse_skill_md(content)
        info.body = body
    except Exception as exc:
        _logger.warning("Failed to refresh body for '%s': %s", name, exc)

    info.payloads = _load_payloads(skill_dir)
    info.enabled = True
    info.loaded_at = _now_iso()

    _logger.info("Loaded skill '%s'", name)
    return {"ok": True, "skill": _info_dict(info), "error": None}


# ════════════════════════════════════════════════════════════════
#  3. unload_skill
# ════════════════════════════════════════════════════════════════

def unload_skill(name: str) -> dict:
    """
    Unload a skill: mark disabled and clear loaded_at.

    Returns
    -------
    dict : ``{"ok": bool, "skill": dict | None, "error": str | None}``
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        return {"ok": False, "skill": None, "error": f"Skill '{name}' not found"}

    info.enabled = False
    info.loaded_at = None
    _logger.info("Unloaded skill '%s'", name)
    return {"ok": True, "skill": _info_dict(info), "error": None}


# ════════════════════════════════════════════════════════════════
#  4. enable_skill / disable_skill
# ════════════════════════════════════════════════════════════════

def enable_skill(name: str) -> dict:
    """Enable a discovered skill (does not set loaded_at)."""
    with _lock:
        info = _registry.get(name)
    if info is None:
        return {"ok": False, "skill": None, "error": f"Skill '{name}' not found"}
    info.enabled = True
    return {"ok": True, "skill": _info_dict(info), "error": None}


def disable_skill(name: str) -> dict:
    """Disable a skill — its body will not be injected into prompts."""
    with _lock:
        info = _registry.get(name)
    if info is None:
        return {"ok": False, "skill": None, "error": f"Skill '{name}' not found"}
    info.enabled = False
    return {"ok": True, "skill": _info_dict(info), "error": None}


# ════════════════════════════════════════════════════════════════
#  5. list_skills
# ════════════════════════════════════════════════════════════════

def list_skills() -> list[dict]:
    """Return all discovered skills as JSON-safe dicts."""
    with _lock:
        snapshot = list(_registry.values())
    return [_info_dict(i) for i in snapshot]


# ════════════════════════════════════════════════════════════════
#  6. get_skill_info
# ════════════════════════════════════════════════════════════════

def get_skill_info(name: str) -> dict | None:
    """Return info dict for a single skill or ``None`` if not found."""
    with _lock:
        info = _registry.get(name)
    if info is None:
        return None
    return _info_dict(info)


# ════════════════════════════════════════════════════════════════
#  7. render_skill_for_prompt
# ════════════════════════════════════════════════════════════════

def render_skill_for_prompt(name: str) -> str:
    """
    Return the markdown body of a skill, wrapped for AI injection.

    Disabled skills return an empty string.
    """
    with _lock:
        info = _registry.get(name)
    if info is None:
        return ""
    if not info.enabled:
        return ""

    header = f"# Skill: {info.name} ({info.manifest.category})\n"
    if info.manifest.description:
        header += f"_{info.manifest.description}_\n\n"
    if info.manifest.allowed_tools:
        header += (
            "**Allowed tools:** "
            + ", ".join(info.manifest.allowed_tools)
            + "\n\n"
        )
    return header + info.body.strip() + "\n"


# ════════════════════════════════════════════════════════════════
#  8. call_skill_hook
# ════════════════════════════════════════════════════════════════

def call_skill_hook(skill_name: str, hook_name: str, *args: Any) -> Any | None:
    """
    Placeholder hook dispatcher for skills.

    A skill playbook is documentation-only, so this does not actually
    execute tools — that is handled elsewhere in the pipeline (SSH /
    arsenal dispatcher).  Here we only *gate* the call:

        - If the skill is not registered or disabled → None
        - If the skill defines ``allowed_tools`` and ``hook_name`` is
          not in that list → None
        - Otherwise return ``{"skill": skill_name, "hook": hook_name,
          "args": list(args)}`` so callers (AI agent / orchestrator)
          can decide whether to actually run the named tool.

    This keeps the contract symmetric with ``plugin_manager.call_hook``
    while remaining side-effect free for non-code playbooks.
    """
    with _lock:
        info = _registry.get(skill_name)
    if info is None or not info.enabled:
        return None

    if info.manifest.allowed_tools and hook_name not in info.manifest.allowed_tools:
        _logger.debug(
            "Skill '%s' rejected hook '%s' (not in allowed_tools)",
            skill_name, hook_name,
        )
        return None

    return {
        "skill": skill_name,
        "hook": hook_name,
        "args": list(args),
        "allowed": True,
    }


# ════════════════════════════════════════════════════════════════
#  9. create_skill_template
# ════════════════════════════════════════════════════════════════

def create_skill_template(
    name: str,
    category: str = "custom",
    description: str = "",
    allowed_tools: list[str] | None = None,
) -> dict:
    """
    Scaffold a new skill in ``~/.mirv/skills/{name}/SKILL.md``.

    Returns
    -------
    dict : ``{"ok": bool, "path": str, "error": str | None}``
    """
    if not name or not _NAME_RE.match(name):
        return {"ok": False, "path": "", "error": f"Invalid skill name '{name}'"}
    if len(name) > _NAME_MAX_LEN:
        return {"ok": False, "path": "", "error": f"Skill name too long (max {_NAME_MAX_LEN} chars)"}

    if category and category not in VALID_CATEGORIES:
        category = "custom"

    desc = description.strip() or f"Describe when to load the '{name}' skill."
    tools = allowed_tools or []

    target_dir = _PERSONAL_SKILLS_DIR / name
    try:
        target_dir.mkdir(parents=True, exist_ok=True)
    except Exception as exc:
        return {"ok": False, "path": "", "error": f"Cannot create dir: {exc}"}

    # Build frontmatter
    fm_lines = [
        "---",
        f'name: {name}',
        f'description: "{desc}"',
        f'category: {category}',
    ]
    if tools:
        fm_lines.append("allowed_tools:")
        for t in tools:
            fm_lines.append(f"  - {t}")
    else:
        fm_lines.append("allowed_tools: []")
    fm_lines += [
        'version: "1.0.0"',
        'author: ""',
        'disable_model_invocation: false',
        "---",
    ]

    body = f"""
# {name} Playbook

> Replace this body with the methodology for the **{name}** skill.

## 1. Objective
- Describe the goal of this skill (when to load it).

## 2. Methodology
- Step-by-step procedure.

## 3. Payloads
- Reference files in `payloads/` if any.

## 4. Allowed tools
- {", ".join(tools) if tools else "(none restricted)"}

## 5. Validation
- Every finding must include a concrete PoC + observed response impact.
"""

    skill_file = target_dir / _SKILL_FILENAME
    try:
        skill_file.write_text("\n".join(fm_lines) + body, encoding="utf-8")
    except Exception as exc:
        return {"ok": False, "path": "", "error": f"Cannot write file: {exc}"}

    _logger.info("Created skill template '%s' at %s", name, target_dir)
    return {"ok": True, "path": str(skill_file.resolve()), "error": None}


# ════════════════════════════════════════════════════════════════
#  10. reload_skill
# ════════════════════════════════════════════════════════════════

def reload_skill(name: str) -> dict:
    """
    Re-discover, unload then re-load a skill.

    Re-discovery is performed first so edits to ``SKILL.md`` (frontmatter
    or body) take effect.  The skill ends up enabled with a fresh
    ``loaded_at`` timestamp.
    """
    _logger.info("Reloading skill '%s'", name)
    discover_skills()           # re-scan so edits to SKILL.md are picked up
    unload_skill(name)          # mark disabled (no-op if not registered)
    return load_skill(name)     # final load leaves it enabled


# ════════════════════════════════════════════════════════════════
#  reset (for tests)
# ════════════════════════════════════════════════════════════════

def reset() -> None:
    """Clear registry & skills_dirs — primarily for tests."""
    with _lock:
        _registry.clear()
        _skills_dirs.clear()


# ════════════════════════════════════════════════════════════════
#  Automatic discovery on import
# ════════════════════════════════════════════════════════════════

try:
    discover_skills()
except Exception as _exc:  # pragma: no cover — best-effort on import
    _logger.debug("Initial skill discovery failed: %s", _exc)