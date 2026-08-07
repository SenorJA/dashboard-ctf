"""
Coverage-gap tests for backend/skill_playbooks.py.

Covers error/edge branches of the markdown frontmatter parser, manifest
validation, payload loading, discovery and scaffolding that the main suite
does not exercise.

Branches:
  - _parse_skill_md: blank lines inside a block list; empty value w/o list
  - _to_bool: non-str/non-bool value
  - _validate_manifest: empty name, too-long name, too-long description,
    non-str/non-list allowed_tools
  - _load_payloads: read failure, scan failure
  - discover_skills: iterdir failure, non-dir entry, missing SKILL.md,
    unreadable SKILL.md
  - load_skill: body refresh failure
  - create_skill_template: too-long name, mkdir failure
"""

from pathlib import Path
from unittest.mock import patch

import backend.skill_playbooks as sp


def _parse(frontmatter_body: str):
    """Build a SKILL.md string from a bare frontmatter-body snippet."""
    return f"---\n{frontmatter_body}---\n\nbody here\n"


class TestParseSkillMd:
    def test_block_list_skips_blank_lines(self):
        fm, body = sp._parse_skill_md(_parse("tools:\n\n- a\n\n- b\n"))
        assert fm["tools"] == ["a", "b"]
        assert body.strip() == "body here"

    def test_empty_value_without_list(self):
        fm, _ = sp._parse_skill_md(_parse("empty_key:\n"))
        assert fm["empty_key"] == ""


class TestToBool:
    def test_non_string_non_bool(self):
        assert sp._to_bool(1) is True
        assert sp._to_bool(0) is False


class TestValidateManifest:
    def test_empty_name(self):
        manifest, err = sp._validate_manifest({}, "")
        assert manifest is None
        assert "name" in err

    def test_name_too_long(self):
        manifest, err = sp._validate_manifest({"name": "x" * 100}, "dir")
        assert manifest is None
        assert "too long" in err

    def test_description_too_long(self):
        fm = {"name": "ok", "description": "y" * 5000}
        manifest, err = sp._validate_manifest(fm, "ok")
        assert manifest is None
        assert "too long" in err

    def test_non_list_allowed_tools(self):
        fm = {"name": "ok", "description": "desc", "allowed_tools": 123}
        manifest, err = sp._validate_manifest(fm, "ok")
        assert manifest is not None
        assert manifest.allowed_tools == []


class TestLoadPayloadsFailures:
    def test_payload_read_failure(self, tmp_path):
        pdir = tmp_path / "payloads"
        pdir.mkdir()
        (pdir / "p.txt").write_text("data", encoding="utf-8")
        with patch.object(Path, "read_text", side_effect=OSError("denied")):
            res = sp._load_payloads(tmp_path)
        assert res == {}

    def test_payload_scan_failure(self, tmp_path):
        pdir = tmp_path / "payloads"
        pdir.mkdir()
        with patch.object(Path, "iterdir", side_effect=OSError("denied")):
            res = sp._load_payloads(tmp_path)
        assert res == {}


class TestDiscoverSkillsErrors:
    def _run_discover(self, base: Path):
        with patch.object(sp, "_skills_dirs_resolved", return_value=[base]):
            return sp.discover_skills()

    def test_iterdir_failure(self, tmp_path):
        with patch.object(Path, "iterdir", side_effect=OSError("denied")):
            assert self._run_discover(tmp_path) == []

    def test_non_dir_entry_skipped(self, tmp_path):
        (tmp_path / "afile.txt").write_text("x", encoding="utf-8")
        assert self._run_discover(tmp_path) == []

    def test_missing_skill_file_skipped(self, tmp_path):
        (tmp_path / "demo").mkdir()
        assert self._run_discover(tmp_path) == []

    def test_unreadable_skill_file(self, tmp_path):
        d = tmp_path / "demo"
        d.mkdir()
        (d / "SKILL.md").write_text("x", encoding="utf-8")
        with patch.object(Path, "read_text", side_effect=OSError("denied")):
            assert self._run_discover(tmp_path) == []


class TestLoadSkillRefreshFailure:
    def test_body_refresh_failure(self, tmp_path):
        d = tmp_path / "demo"
        d.mkdir()
        (d / "SKILL.md").write_text("---\nname: demo\ndescription: d\n---\n\nbody",
                                    encoding="utf-8")
        sp._registry.clear()
        # Register directly so load_skill() gets past discovery.
        from backend.skill_playbooks import SkillManifest, SkillInfo
        sp._registry["demo"] = SkillInfo(
            name="demo",
            manifest=SkillManifest(name="demo", description="d",
                                   category="custom", allowed_tools=[]),
            dir_path=str(d),
            body="",
        )
        try:
            with patch.object(Path, "read_text", side_effect=OSError("denied")):
                res = sp.load_skill("demo")
            assert res["ok"] is True
            assert res["skill"]["enabled"] is True
        finally:
            sp._registry.clear()


class TestCreateSkillErrors:
    def test_name_too_long(self, tmp_path):
        res = sp.create_skill_template("z" * 100, description="d")
        assert res["ok"] is False
        assert "too long" in res["error"]

    def test_mkdir_failure(self, tmp_path):
        with patch.object(sp, "_PERSONAL_SKILLS_DIR", tmp_path), \
             patch.object(Path, "mkdir", side_effect=OSError("denied")):
            res = sp.create_skill_template("goodname", description="d")
        assert res["ok"] is False
        assert "Cannot create dir" in res["error"]
