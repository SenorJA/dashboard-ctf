"""
Coverage-gap tests for backend/skill_playbooks.py.

Covers:
  - create_skill_template: write failure branch
  - requires_scope frontmatter field: parser, list/info exposure,
    discovery (no filtering) and the /api/skills/{name}/render scope gate.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

import backend.skill_playbooks as sp
from backend.skill_playbooks import SkillManifest, SkillInfo


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_registry():
    """Reset the skill registry before & after each test."""
    sp.reset()
    yield
    sp.reset()


@pytest.fixture
def client():
    """FastAPI TestClient fixture (local — mirrors test_skill_playbooks.py)."""
    from main import app
    from fastapi.testclient import TestClient
    with TestClient(app) as c:
        yield c


def _make_skill(tmp_path: Path, name: str, requires_scope=None) -> Path:
    """Scaffold a minimal skill directory with optional requires_scope."""
    d = tmp_path / name
    d.mkdir(parents=True)
    fm_lines = [
        "---",
        f"name: {name}",
        f'description: "test skill {name}"',
        "category: custom",
        "allowed_tools: []",
        'version: "1.0.0"',
        'author: ""',
        "disable_model_invocation: false",
    ]
    if requires_scope is not None:
        fm_lines.append(f"requires_scope: {str(requires_scope).lower()}")
    fm_lines += ["---", "", f"# {name} body", "", "methodology here"]
    (d / "SKILL.md").write_text("\n".join(fm_lines), encoding="utf-8")
    return d


# ════════════════════════════════════════════════════════════════
#  Original gap test
# ════════════════════════════════════════════════════════════════

class TestCreateTemplateWriteError:
    def test_write_failure_returns_error(self, tmp_path, monkeypatch):
        fake_home_skills = tmp_path / "home" / ".mirv" / "skills"
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", fake_home_skills)
        with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
            r = sp.create_skill_template(
                "boomskill", category="custom", description="test",
                allowed_tools=None,
            )
        assert r["ok"] is False
        assert r["path"] == ""
        assert "Cannot write file" in r["error"]
        # Ensure the directory still got created before the write attempt.
        assert (fake_home_skills / "boomskill").exists()


# ════════════════════════════════════════════════════════════════
#  requires_scope — parser / dataclass
# ════════════════════════════════════════════════════════════════

class TestRequiresScopeParser:
    def test_default_false_when_absent(self, tmp_path, monkeypatch):
        d = _make_skill(tmp_path, "noscope")  # no requires_scope field
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        info = sp.get_skill_info("noscope")
        assert info is not None
        assert info["requires_scope"] is False

    def test_true_when_set_true(self, tmp_path, monkeypatch):
        _make_skill(tmp_path, "scoped", requires_scope=True)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        info = sp.get_skill_info("scoped")
        assert info["requires_scope"] is True

    def test_false_when_set_false_explicit(self, tmp_path, monkeypatch):
        _make_skill(tmp_path, "explicitfalse", requires_scope=False)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        assert sp.get_skill_info("explicitfalse")["requires_scope"] is False

    def test_truthy_string_yes(self, tmp_path, monkeypatch):
        d = tmp_path / "yes-skill"
        d.mkdir()
        (d / "SKILL.md").write_text(
            "---\nname: yes-skill\ndescription: d\ncategory: custom\n"
            "allowed_tools: []\nrequires_scope: yes\n---\n\nbody",
            encoding="utf-8",
        )
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        assert sp.get_skill_info("yes-skill")["requires_scope"] is True

    def test_manifest_dataclass_field_default(self):
        m = SkillManifest(name="x", description="d", category="custom",
                          allowed_tools=[])
        assert m.requires_scope is False


# ════════════════════════════════════════════════════════════════
#  requires_scope — list_skills / get_skill_info exposure
# ════════════════════════════════════════════════════════════════

class TestRequiresScopeExposure:
    def test_list_skills_includes_field(self, tmp_path, monkeypatch):
        _make_skill(tmp_path, "a", requires_scope=True)
        _make_skill(tmp_path, "b", requires_scope=False)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        listed = {s["name"]: s for s in sp.list_skills()}
        assert "requires_scope" in listed["a"]
        assert listed["a"]["requires_scope"] is True
        assert listed["b"]["requires_scope"] is False

    def test_get_skill_info_includes_field(self, tmp_path, monkeypatch):
        _make_skill(tmp_path, "solo", requires_scope=True)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        info = sp.get_skill_info("solo")
        assert "requires_scope" in info
        assert info["requires_scope"] is True


# ════════════════════════════════════════════════════════════════
#  discover_skills — must NOT filter by requires_scope
# ════════════════════════════════════════════════════════════════

class TestDiscoverNoFilter:
    def test_discovers_both_scoped_and_unscoped(self, tmp_path, monkeypatch):
        _make_skill(tmp_path, "scoped", requires_scope=True)
        _make_skill(tmp_path, "unscoped", requires_scope=False)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        discovered = set(sp.discover_skills())
        assert discovered == {"scoped", "unscoped"}


# ════════════════════════════════════════════════════════════════
#  /api/skills/{name}/render — scope gate
# ════════════════════════════════════════════════════════════════

class TestRenderScopeGate:
    def test_scoped_skill_no_scope_returns_403(self, client, tmp_path, monkeypatch):
        _make_skill(tmp_path, "gated", requires_scope=True)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        client.post("/api/skills/gated/load")  # enable it
        with patch("backend.scope_guard.get_config",
                   return_value={"enabled": True, "targets": []}):
            r = client.get("/api/skills/gated/render")
        assert r.status_code == 403
        d = r.json()
        assert d["ok"] is False
        assert "scope" in d["error"].lower()

    def test_scoped_skill_with_scope_returns_200(self, client, tmp_path, monkeypatch):
        _make_skill(tmp_path, "gated", requires_scope=True)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        client.post("/api/skills/gated/load")
        with patch("backend.scope_guard.get_config",
                   return_value={"enabled": True, "targets": ["10.0.0.0/24"]}):
            r = client.get("/api/skills/gated/render")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["enabled"] is True
        assert "gated body" in d["body"]

    def test_unscoped_skill_returns_200_without_scope(self, client, tmp_path, monkeypatch):
        _make_skill(tmp_path, "free", requires_scope=False)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        client.post("/api/skills/free/load")
        with patch("backend.scope_guard.get_config",
                   return_value={"enabled": True, "targets": []}):
            r = client.get("/api/skills/free/render")
        assert r.status_code == 200
        assert r.json()["enabled"] is True

    def test_unscoped_skill_returns_200_with_scope(self, client, tmp_path, monkeypatch):
        _make_skill(tmp_path, "free", requires_scope=False)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        client.post("/api/skills/free/load")
        with patch("backend.scope_guard.get_config",
                   return_value={"enabled": True, "targets": ["10.0.0.0/24"]}):
            r = client.get("/api/skills/free/render")
        assert r.status_code == 200
        assert r.json()["enabled"] is True

    def test_scoped_skill_disabled_still_gated(self, client, tmp_path, monkeypatch):
        # requires_scope gate runs BEFORE the body/disabled check, so a
        # disabled scoped skill with no authorized scope → 403 (not 200-empty).
        _make_skill(tmp_path, "gated", requires_scope=True)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        # do NOT load → disabled
        with patch("backend.scope_guard.get_config",
                   return_value={"enabled": True, "targets": []}):
            r = client.get("/api/skills/gated/render")
        # Gate runs before body check; skill exists & requires_scope, no scope → 403
        assert r.status_code == 403

    def test_scoped_skill_scope_check_error_returns_500(self, client, tmp_path, monkeypatch):
        _make_skill(tmp_path, "gated", requires_scope=True)
        monkeypatch.setattr(sp, "_skills_dirs_resolved", lambda: [tmp_path])
        sp.discover_skills()
        client.post("/api/skills/gated/load")
        with patch("backend.scope_guard.get_config",
                   side_effect=RuntimeError("db down")):
            r = client.get("/api/skills/gated/render")
        assert r.status_code == 500
        assert r.json()["ok"] is False
