"""
Coverage-gap tests for backend/skill_playbooks.py.

Covers:
  - create_skill_template: write failure branch
"""

from pathlib import Path
from unittest.mock import patch

import backend.skill_playbooks as sp


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
