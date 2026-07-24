"""
Tests for skill_playbooks.py — MIRV Skill Playbooks System.

Covers:
  - Discovery of the 10 built-in skills (5 original + 5 added later)
  - load / unload / enable / disable / reload
  - list / info / render for prompt
  - Frontmatter parsing (inline lists, block lists, quotes, empty)
  - create_skill_template scaffolding
  - Malformed manifests (missing description, invalid name)
  - Endpoint smoke tests via FastAPI TestClient
"""

import os
import sys
from pathlib import Path
from datetime import datetime

import pytest

# Ensure backend/ AND project root are importable.
# IMPORTANT: main.py imports skill_playbooks as `backend.skill_playbooks`,
# so we must reset / patch the SAME module object, otherwise the
# endpoint fixtures operate on a different registry than the unit tests.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import backend.skill_playbooks as sp


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_registry():
    """Reset registry before each test."""
    sp.reset()
    yield
    sp.reset()


@pytest.fixture
def builtin_only(monkeypatch):
    """
    Pin discovery to ONLY the built-in skills dir, ignoring project /
    personal / env dirs so tests don't pick up stray skills from the
    developer machine.
    """
    monkeypatch.setenv("MIRV_SKILLS_DIRS", "")
    monkeypatch.setattr(sp, "_PROJECT_SKILLS_DIR", Path("__disabled__") / "skills")
    monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", Path("__disabled__") / "skills")
    yield


# 10 built-in skill playbooks (5 original + 5 added in the PentesterFlow-inspired round)
BUILTIN_NAMES = {
    "recon", "webvuln", "ssrf", "jwt", "supabase",          # original 5
    "graphql", "race", "takeover", "deserialize", "ssti",    # added 5
}


# ════════════════════════════════════════════════════════════════
#  Discovery
# ════════════════════════════════════════════════════════════════

class TestDiscovery:
    def test_discover_finds_all_ten_builtins(self, builtin_only):
        names = sp.discover_skills()
        assert set(names) == BUILTIN_NAMES

    def test_discover_returns_sorted(self, builtin_only):
        names = sp.discover_skills()
        assert names == sorted(names)

    def test_discover_defaults_disabled(self, builtin_only):
        sp.discover_skills()
        for info in sp.list_skills():
            assert info["enabled"] is False
            assert info["loaded_at"] is None

    def test_discover_idempotent(self, builtin_only):
        a = sp.discover_skills()
        b = sp.discover_skills()
        assert a == b

    def test_rediscover_preserves_enabled_state(self, builtin_only):
        sp.discover_skills()
        sp.load_skill("recon")
        assert sp.get_skill_info("recon")["enabled"] is True
        # rediscover should NOT wipe the enabled state
        sp.discover_skills()
        assert sp.get_skill_info("recon")["enabled"] is True


# ════════════════════════════════════════════════════════════════
#  Load / Unload
# ════════════════════════════════════════════════════════════════

class TestLoadUnload:
    def test_load_existing(self, builtin_only):
        sp.discover_skills()
        r = sp.load_skill("recon")
        assert r["ok"] is True
        assert r["error"] is None
        assert r["skill"]["name"] == "recon"
        assert r["skill"]["enabled"] is True
        assert r["skill"]["loaded_at"] is not None

    def test_load_sets_iso_timestamp(self, builtin_only):
        sp.discover_skills()
        r = sp.load_skill("ssrf")
        ts = r["skill"]["loaded_at"]
        # ISO 8601 must be parseable
        datetime.fromisoformat(ts)

    def test_load_nonexistent_returns_error(self, builtin_only):
        sp.discover_skills()
        r = sp.load_skill("doesnotexist")
        assert r["ok"] is False
        assert r["skill"] is None
        assert "not found" in r["error"].lower()

    def test_load_nonexistent_autodiscovers(self, builtin_only):
        # Even without explicit discover_skills() call, load should
        # auto-discover first.
        r = sp.load_skill("recon")
        assert r["ok"] is True

    def test_unload_after_load(self, builtin_only):
        sp.discover_skills()
        sp.load_skill("recon")
        r = sp.unload_skill("recon")
        assert r["ok"] is True
        info = sp.get_skill_info("recon")
        assert info["enabled"] is False
        assert info["loaded_at"] is None

    def test_unload_nonexistent(self, builtin_only):
        sp.discover_skills()
        r = sp.unload_skill("ghost")
        assert r["ok"] is False
        assert "not found" in r["error"].lower()

    def test_unload_without_load(self, builtin_only):
        sp.discover_skills()
        # recon was discovered but never loaded → still discoverable, just disabled
        r = sp.unload_skill("recon")
        assert r["ok"] is True
        assert sp.get_skill_info("recon")["enabled"] is False


# ════════════════════════════════════════════════════════════════
#  Enable / Disable
# ════════════════════════════════════════════════════════════════

class TestEnableDisable:
    def test_enable(self, builtin_only):
        sp.discover_skills()
        r = sp.enable_skill("webvuln")
        assert r["ok"] is True
        assert sp.get_skill_info("webvuln")["enabled"] is True

    def test_enable_does_not_set_loaded_at(self, builtin_only):
        sp.discover_skills()
        sp.enable_skill("webvuln")
        assert sp.get_skill_info("webvuln")["loaded_at"] is None

    def test_disable(self, builtin_only):
        sp.discover_skills()
        sp.enable_skill("webvuln")
        r = sp.disable_skill("webvuln")
        assert r["ok"] is True
        assert sp.get_skill_info("webvuln")["enabled"] is False

    def test_enable_nonexistent(self, builtin_only):
        sp.discover_skills()
        r = sp.enable_skill("ghost")
        assert r["ok"] is False

    def test_disable_nonexistent(self, builtin_only):
        sp.discover_skills()
        r = sp.disable_skill("ghost")
        assert r["ok"] is False


# ════════════════════════════════════════════════════════════════
#  Info / List
# ════════════════════════════════════════════════════════════════

class TestInfoList:
    def test_get_skill_info_fields(self, builtin_only):
        sp.discover_skills()
        sp.load_skill("jwt")
        info = sp.get_skill_info("jwt")
        assert info is not None
        for key in (
            "name", "description", "category", "allowed_tools",
            "disable_model_invocation", "version", "author",
            "dir_path", "enabled", "loaded_at", "body_length",
            "payloads",
        ):
            assert key in info
        assert info["name"] == "jwt"
        assert info["category"] in sp.VALID_CATEGORIES

    def test_get_skill_info_none_for_missing(self, builtin_only):
        sp.discover_skills()
        assert sp.get_skill_info("ghost") is None

    def test_list_returns_all_regardless_of_enabled(self, builtin_only):
        sp.discover_skills()
        sp.enable_skill("recon")
        # disable a couple
        sp.disable_skill("webvuln")
        lst = sp.list_skills()
        names = {i["name"] for i in lst}
        assert names == BUILTIN_NAMES

    def test_list_returns_copy(self, builtin_only):
        sp.discover_skills()
        a = sp.list_skills()
        b = sp.list_skills()
        assert a == b
        # mutating one list must not affect the registry / other list
        a[0]["enabled"] = "tampered"
        assert sp.list_skills()[0]["enabled"] is False


# ════════════════════════════════════════════════════════════════
#  Reload
# ════════════════════════════════════════════════════════════════

class TestReload:
    def test_reload_keeps_enabled_and_refreshes_timestamp(self, builtin_only):
        sp.discover_skills()
        first = sp.load_skill("recon")
        ts1 = first["skill"]["loaded_at"]
        # Force a tiny delay so ISO timestamps differ
        import time
        time.sleep(0.01)
        second = sp.reload_skill("recon")
        assert second["ok"] is True
        assert second["skill"]["enabled"] is True
        assert second["skill"]["loaded_at"] is not None
        assert second["skill"]["loaded_at"] != ts1

    def test_reload_nonexistent(self, builtin_only):
        sp.discover_skills()
        r = sp.reload_skill("ghost")
        assert r["ok"] is False

    def test_reload_picks_up_edits(self, builtin_only, tmp_path, monkeypatch):
        # Use MIRV_SKILLS_DIRS to inject an override copy of 'recon'
        # whose body is different (later dir wins).
        override_dir = tmp_path / "override" / "recon"
        override_dir.mkdir(parents=True)
        (override_dir / "SKILL.md").write_text(
            "---\n"
            "name: recon\n"
            'description: "override recon"\n'
            "category: recon\n"
            "allowed_tools: [curl]\n"
            "version: \"2.0.0\"\n"
            "author: \"tester\"\n"
            "---\n"
            "# Override body\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("MIRV_SKILLS_DIRS", str(tmp_path / "override"))
        sp.discover_skills()
        sp.load_skill("recon")
        r = sp.reload_skill("recon")
        assert r["ok"] is True
        assert "Override body" in sp.render_skill_for_prompt("recon")
        assert r["skill"]["version"] == "2.0.0"


# ════════════════════════════════════════════════════════════════
#  Render for prompt
# ════════════════════════════════════════════════════════════════

class TestRender:
    def test_render_disabled_returns_empty(self, builtin_only):
        sp.discover_skills()
        # not enabled by default
        assert sp.render_skill_for_prompt("recon") == ""

    def test_render_after_load_returns_body(self, builtin_only):
        sp.discover_skills()
        sp.load_skill("recon")
        out = sp.render_skill_for_prompt("recon")
        assert out
        assert "Recon Methodology" in out
        assert "Skill: recon" in out
        # frontmatter must NOT be present in render output
        assert "description:" not in out.split("\n")[0]

    def test_render_includes_allowed_tools_header(self, builtin_only):
        sp.discover_skills()
        sp.load_skill("recon")
        out = sp.render_skill_for_prompt("recon")
        assert "Allowed tools" in out
        assert "nmap" in out

    def test_render_unknown_skill(self, builtin_only):
        sp.discover_skills()
        assert sp.render_skill_for_prompt("ghost") == ""


# ════════════════════════════════════════════════════════════════
#  Frontmatter parsing (private but stable)
# ════════════════════════════════════════════════════════════════

class TestFrontmatterParsing:
    def test_parse_inline_list(self):
        content = (
            "---\n"
            "name: foo\n"
            "description: \"d\"\n"
            "allowed_tools: [nmap, gobuster]\n"
            "category: custom\n"
            "---\n"
            "body text\n"
        )
        fm, body = sp._parse_skill_md(content)
        assert fm["allowed_tools"] == ["nmap", "gobuster"]
        assert fm["name"] == "foo"
        assert fm["description"] == "d"
        assert body.strip() == "body text"

    def test_parse_block_list(self):
        content = (
            "---\n"
            "name: foo\n"
            "allowed_tools:\n"
            "  - nmap\n"
            "  - gobuster\n"
            "description: \"d\"\n"
            "---\n"
            "body\n"
        )
        fm, _ = sp._parse_skill_md(content)
        assert fm["allowed_tools"] == ["nmap", "gobuster"]

    def test_parse_empty_frontmatter(self):
        # An empty frontmatter block (only the --- delimiters).
        content = "---\n\n---\nbody line\n"
        fm, body = sp._parse_skill_md(content)
        assert fm == {}
        assert "body line" in body

    def test_parse_no_frontmatter(self):
        content = "just plain markdown\n## hi\n"
        fm, body = sp._parse_skill_md(content)
        assert fm == {}
        assert "just plain markdown" in body

    def test_parse_strips_quotes(self):
        content = '---\nname: "f"\ndescription: \'d\'\n---\nbody\n'
        fm, _ = sp._parse_skill_md(content)
        assert fm["name"] == "f"
        assert fm["description"] == "d"

    def test_parse_multiline_description_resilient(self):
        """
        The lightweight parser does not join multi-line quoted strings.
        This test documents that it does not crash and still extracts
        a non-empty description string from the first line.
        """
        content = (
            "---\n"
            'description: "first line of a\n'
            'second line of the description"\n'
            "name: foo\n"
            "---\n"
            "body\n"
        )
        fm, _ = sp._parse_skill_md(content)
        # parser must not raise; description is a string (resilience test)
        assert isinstance(fm["description"], str)
        assert "first line" in fm["description"]

    def test_parse_comment_line_ignored(self):
        content = (
            "---\n"
            "# this is a comment\n"
            "name: foo\n"
            "description: d\n"
            "---\n"
            "body\n"
        )
        fm, _ = sp._parse_skill_md(content)
        assert fm.get("# this is a comment") is None
        assert fm["name"] == "foo"


# ════════════════════════════════════════════════════════════════
#  Manifest validation edge cases
# ════════════════════════════════════════════════════════════════

class TestValidation:
    def test_invalid_name_rejected_by_validate(self):
        manifest, err = sp._validate_manifest({"name": "Bad Name!", "description": "d"}, "bad")
        assert manifest is None
        assert "Invalid skill name" in err

    def test_name_dir_mismatch_rejected(self):
        manifest, err = sp._validate_manifest(
            {"name": "alice", "description": "d"}, "bob"
        )
        assert manifest is None
        assert "does not match directory" in err

    def test_missing_description_rejected(self):
        manifest, err = sp._validate_manifest({"name": "alice"}, "alice")
        assert manifest is None
        assert "description" in err

    def test_unknown_category_falls_back_to_custom(self):
        manifest, err = sp._validate_manifest(
            {"name": "alice", "description": "d", "category": "bogus"}, "alice"
        )
        assert manifest is not None
        assert manifest.category == "custom"

    def test_tools_string_fallback(self):
        manifest, _ = sp._validate_manifest(
            {"name": "alice", "description": "d",
             "allowed_tools": "nmap, gobuster"}, "alice"
        )
        assert manifest.allowed_tools == ["nmap", "gobuster"]


class TestDiscoverEdgeCases:
    def test_invalid_name_dir_skipped(self, tmp_path, monkeypatch):
        """
        A SKILL.md whose declared name contains invalid characters
        must NOT be loaded into the registry.
        """
        bad_dir = tmp_path / "skills" / "badname"
        bad_dir.mkdir(parents=True)
        (bad_dir / "SKILL.md").write_text(
            "---\nname: Bad Name!\ndescription: d\ncategory: custom\n---\nbody\n",
            encoding="utf-8",
        )
        # disable builtins / personal so only our dir is scanned
        monkeypatch.setenv("MIRV_SKILLS_DIRS", str(tmp_path / "skills"))
        monkeypatch.setattr(sp, "_BUILTIN_SKILLS_DIR", Path("__disabled__"))
        monkeypatch.setattr(sp, "_PROJECT_SKILLS_DIR", Path("__disabled__"))
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", Path("__disabled__"))
        names = sp.discover_skills()
        assert names == []
        assert sp.get_skill_info("Bad Name!") is None

    def test_missing_description_dir_skipped(self, tmp_path, monkeypatch):
        bad_dir = tmp_path / "skills" / "nodesc"
        bad_dir.mkdir(parents=True)
        (bad_dir / "SKILL.md").write_text(
            "---\nname: nodesc\ncategory: custom\n---\nbody\n",
            encoding="utf-8",
        )
        monkeypatch.setenv("MIRV_SKILLS_DIRS", str(tmp_path / "skills"))
        monkeypatch.setattr(sp, "_BUILTIN_SKILLS_DIR", Path("__disabled__"))
        monkeypatch.setattr(sp, "_PROJECT_SKILLS_DIR", Path("__disabled__"))
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", Path("__disabled__"))
        names = sp.discover_skills()
        assert names == []
        # load should also fail
        assert sp.load_skill("nodesc")["ok"] is False


# ════════════════════════════════════════════════════════════════
#  create_skill_template
# ════════════════════════════════════════════════════════════════

class TestCreateTemplate:
    def test_create_template_writes_file(self, tmp_path, monkeypatch):
        fake_home_skills = tmp_path / "home" / ".mirv" / "skills"
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", fake_home_skills)
        r = sp.create_skill_template(
            "mytest", category="custom", description="test desc",
            allowed_tools=["nmap", "gobuster"],
        )
        assert r["ok"] is True
        p = Path(r["path"])
        assert p.exists()
        assert p.name == "SKILL.md"
        assert p.parent.name == "mytest"
        # parent's grandparent should be `skills`
        assert p.parent.parent.name == "skills"
        content = p.read_text(encoding="utf-8")
        assert "name: mytest" in content
        assert "description: \"test desc\"" in content
        assert "category: custom" in content
        assert "- nmap" in content
        assert "- gobuster" in content
        # body
        assert "# mytest Playbook" in content

    def test_create_template_invalid_name(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", tmp_path / "h")
        r = sp.create_skill_template("Bad Name!")
        assert r["ok"] is False
        assert "Invalid" in r["error"]

    def test_create_template_custom_category_when_unknown(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", tmp_path / "h")
        r = sp.create_skill_template("okskill", category="boguscat", description="d")
        assert r["ok"] is True
        content = Path(r["path"]).read_text(encoding="utf-8")
        assert "category: custom" in content

    def test_create_template_idempotent_dir_exists(self, tmp_path, monkeypatch):
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", tmp_path / "h")
        r1 = sp.create_skill_template("dupe", description="d")
        r2 = sp.create_skill_template("dupe", description="d")
        assert r1["ok"] is True
        assert r2["ok"] is True


# ════════════════════════════════════════════════════════════════
#  call_skill_hook
# ════════════════════════════════════════════════════════════════

class TestHook:
    def test_hook_disabled_returns_none(self, builtin_only):
        sp.discover_skills()
        # not enabled → None
        assert sp.call_skill_hook("recon", "nmap", "10.0.0.1") is None

    def test_hook_allowed(self, builtin_only):
        sp.discover_skills()
        sp.enable_skill("recon")
        out = sp.call_skill_hook("recon", "nmap", "10.0.0.1")
        assert out is not None
        assert out["skill"] == "recon"
        assert out["hook"] == "nmap"
        assert out["allowed"] is True
        assert out["args"] == ["10.0.0.1"]

    def test_hook_blocked_when_tool_not_allowed(self, builtin_only):
        sp.discover_skills()
        sp.enable_skill("recon")
        # 'metasploit' is not in recon.allowed_tools
        assert sp.call_skill_hook("recon", "metasploit", "x") is None


# ════════════════════════════════════════════════════════════════
#  FastAPI endpoint smoke tests
# ════════════════════════════════════════════════════════════════

from main import app
from fastapi.testclient import TestClient


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


class TestSkillsEndpoints:
    def test_list_skills(self, client):
        r = client.get("/api/skills")
        assert r.status_code == 200
        d = r.json()
        assert d.get("ok") is True
        assert isinstance(d.get("skills"), list)
        names = {s["name"] for s in d["skills"]}
        assert BUILTIN_NAMES.issubset(names)

    def test_get_existing_skill(self, client):
        client.get("/api/skills")  # populate registry (cold-start safe)
        r = client.get("/api/skills/recon")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["skill"]["name"] == "recon"
        assert d["skill"]["category"] == "recon"

    def test_get_missing_skill(self, client):
        r = client.get("/api/skills/doesnotexist")
        assert r.status_code == 404
        d = r.json()
        assert d.get("ok") is False

    def test_load_endpoint(self, client):
        r = client.post("/api/skills/recon/load")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["skill"]["enabled"] is True
        assert d["skill"]["loaded_at"] is not None

    def test_unload_endpoint(self, client):
        client.post("/api/skills/recon/load")
        r = client.post("/api/skills/recon/unload")
        assert r.status_code == 200
        assert r.json()["skill"]["enabled"] is False

    def test_enable_endpoint(self, client):
        client.get("/api/skills")  # populate registry
        r = client.post("/api/skills/webvuln/enable")
        assert r.status_code == 200
        assert r.json()["skill"]["enabled"] is True

    def test_disable_endpoint(self, client):
        client.get("/api/skills")  # populate registry
        client.post("/api/skills/webvuln/enable")
        r = client.post("/api/skills/webvuln/disable")
        assert r.status_code == 200
        assert r.json()["skill"]["enabled"] is False

    def test_reload_endpoint(self, client):
        client.post("/api/skills/recon/load")
        r = client.post("/api/skills/recon/reload")
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert r.json()["skill"]["enabled"] is True

    def test_load_missing_endpoint(self, client):
        r = client.post("/api/skills/ghost/load")
        assert r.status_code == 400
        assert r.json()["ok"] is False

    def test_render_endpoint_loaded(self, client):
        client.post("/api/skills/recon/load")
        r = client.get("/api/skills/recon/render")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["enabled"] is True
        assert "Recon Methodology" in d["body"]

    def test_render_endpoint_disabled(self, client):
        # discover but never enable → empty body, enabled False
        client.get("/api/skills")
        r = client.get("/api/skills/webvuln/render")
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert d["enabled"] is False
        assert d["body"] == ""

    def test_render_missing_endpoint(self, client):
        r = client.get("/api/skills/ghost/render")
        assert r.status_code == 404

    def test_create_endpoint(self, client, tmp_path, monkeypatch):
        # redirect personal skills dir so we don't pollute the dev machine
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", tmp_path / "h")
        r = client.post("/api/skills/create", json={
            "name": "myendpointskill",
            "category": "webvuln",
            "description": "endpoint-created",
            "allowed_tools": ["nmap"],
        })
        assert r.status_code == 200
        d = r.json()
        assert d["ok"] is True
        assert Path(d["path"]).exists()
        assert "myendpointskill" in d["path"]

    def test_create_endpoint_invalid_name(self, client, tmp_path, monkeypatch):
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", tmp_path / "h")
        r = client.post("/api/skills/create", json={
            "name": "Bad Name!",
            "category": "custom",
            "description": "x",
        })
        assert r.status_code == 400
        assert r.json()["ok"] is False

    def test_create_endpoint_missing_name(self, client):
        r = client.post("/api/skills/create", json={"description": "x"})
        assert r.status_code == 400

    def test_full_lifecycle_workflow(self, client, tmp_path, monkeypatch):
        """
        Discover → load → render → disable → render (empty) → enable → reload.
        """
        # list present
        d = client.get("/api/skills").json()
        assert "recon" in {s["name"] for s in d["skills"]}
        # initial render empty (disabled)
        assert client.get("/api/skills/recon/render").json()["body"] == ""
        # load → render non-empty
        client.post("/api/skills/recon/load")
        assert client.get("/api/skills/recon/render").json()["enabled"] is True
        # disable → render empty
        client.post("/api/skills/recon/disable")
        assert client.get("/api/skills/recon/render").json()["body"] == ""
        # enable → render non-empty (enable alone suffices for render)
        client.post("/api/skills/recon/enable")
        assert client.get("/api/skills/recon/render").json()["body"] != ""
        # reload → still enabled
        client.post("/api/skills/recon/reload")
        info = client.get("/api/skills/recon").json()["skill"]
        assert info["enabled"] is True


# ════════════════════════════════════════════════════════════════
#  Payloads loading
# ════════════════════════════════════════════════════════════════

class TestPayloads:
    def test_load_payloads(self, tmp_path, monkeypatch):
        skill_dir = tmp_path / "skills" / "loader"
        skill_dir.mkdir(parents=True)
        (skill_dir / "SKILL.md").write_text(
            "---\nname: loader\ndescription: d\ncategory: custom\n---\nbody\n",
            encoding="utf-8",
        )
        pdir = skill_dir / "payloads"
        pdir.mkdir()
        (pdir / "p1.txt").write_text("payload1", encoding="utf-8")
        (pdir / "p2.txt").write_text("payload2", encoding="utf-8")
        (pdir / "ignore.md").write_text("ignore", encoding="utf-8")

        monkeypatch.setenv("MIRV_SKILLS_DIRS", str(tmp_path / "skills"))
        monkeypatch.setattr(sp, "_BUILTIN_SKILLS_DIR", Path("__disabled__"))
        monkeypatch.setattr(sp, "_PROJECT_SKILLS_DIR", Path("__disabled__"))
        monkeypatch.setattr(sp, "_PERSONAL_SKILLS_DIR", Path("__disabled__"))
        sp.discover_skills()
        info = sp.get_skill_info("loader")
        assert info is not None
        assert set(info["payloads"]) == {"p1.txt", "p2.txt"}

    def test_load_payloads_no_dir(self, builtin_only):
        sp.discover_skills()
        # builtins have no payloads/ dir
        for name in BUILTIN_NAMES:
            assert sp.get_skill_info(name)["payloads"] == []