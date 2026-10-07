"""
Tests for ``backend/agency_agents.py`` — AI persona registry (Pack 17).

Hermetic: the writable directory is redirected to ``tmp_path`` through
``MIRV_AGENTS_WRITE_DIR`` so bundled personas are never mutated.
"""
import os
import threading

import pytest

from backend import agency_agents as aa


@pytest.fixture(autouse=True)
def _isolated_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("MIRV_AGENTS_WRITE_DIR", str(tmp_path / "agents"))
    aa.discover(force=True)
    yield
    aa.discover(force=True)


# ════════════════════════════════════════════════════════════════
#  Discovery
# ════════════════════════════════════════════════════════════════

def test_discover_finds_vendored_personas():
    agents = aa.discover(force=True)
    assert len(agents) >= 39
    assert "security-penetration-tester" in agents
    assert "engineering-backend-architect" in agents


def test_discover_is_cached_between_calls():
    aa.discover(force=True)
    first = aa.discover()
    second = aa.discover()
    assert first == second


def test_vendored_personas_are_read_only():
    persona = aa.discover()["security-penetration-tester"]
    assert persona.editable is False
    assert persona.division == "security"
    assert persona.name
    assert persona.description
    assert persona.emoji
    assert persona.color.startswith("#")
    assert persona.body.strip()


def test_discovery_cache_invalidates_on_new_file(tmp_path):
    target = tmp_path / "extra"
    monkey_dir = target / "custom"
    monkey_dir.mkdir(parents=True)
    aa.discover(force=True)
    before = len(aa.discover())
    (monkey_dir / "zz-temp-persona.md").write_text(
        '---\nname: Temp\ndescription: d\n---\n\nbody', encoding="utf-8"
    )
    os.environ["MIRV_AGENTS_DIRS"] = str(target)
    try:
        after = aa.discover(force=True)
        assert len(after) == before + 1
        assert "zz-temp-persona" in after
    finally:
        os.environ.pop("MIRV_AGENTS_DIRS", None)


# ════════════════════════════════════════════════════════════════
#  Read API
# ════════════════════════════════════════════════════════════════

def test_list_agents_metadata_has_no_body():
    agents = aa.list_agents()
    assert agents
    for item in agents:
        assert "body" not in item
        assert {"slug", "division", "name", "chars"} <= set(item)


def test_list_agents_filter_by_division():
    agents = aa.list_agents(division="security")
    assert agents
    assert {a["division"] for a in agents} == {"security"}


def test_list_agents_filter_by_query():
    hits = aa.list_agents(q="mcp")
    assert hits
    assert any("mcp" in a["slug"] for a in hits)


def test_list_agents_unknown_division_is_empty():
    assert aa.list_agents(division="nope") == []


def test_get_agent_includes_body():
    agent = aa.get_agent("security-penetration-tester")
    assert agent is not None
    assert len(agent["body"]) > 500
    assert aa.get_agent("does-not-exist") is None


def test_get_agent_is_case_insensitive():
    assert aa.get_agent("SECURITY-PENETRATION-TESTER") is not None


def test_list_divisions_counts():
    divisions = aa.list_divisions()
    ids = {d["id"] for d in divisions}
    assert {"security", "testing", "engineering", "specialized", "custom"} <= ids
    by_id = {d["id"]: d for d in divisions}
    assert by_id["security"]["count"] >= 12
    assert by_id["security"]["label"]["es"] == "Seguridad"
    assert by_id["custom"]["count"] == 0


def test_summary():
    data = aa.summary()
    assert data["total"] >= 39
    assert data["divisions"] >= 4
    assert isinstance(data["dirs"], list) and data["dirs"]


# ════════════════════════════════════════════════════════════════
#  Prompt building
# ════════════════════════════════════════════════════════════════

def test_build_prompt_includes_identity_and_body():
    prompt = aa.build_persona_prompt("security-penetration-tester")
    assert prompt is not None
    assert "Penetration Tester" in prompt
    assert "security-penetration-tester" in prompt


def test_build_prompt_appends_task_and_context():
    prompt = aa.build_persona_prompt(
        "security-appsec-engineer",
        task="audita el login",
        context="app Express + JWT",
    )
    assert "## Assignment" in prompt and "audita el login" in prompt
    assert "## Context" in prompt and "Express" in prompt


def test_build_prompt_respects_body_limit():
    full = aa.build_persona_prompt("security-penetration-tester", body_limit=aa.MAX_PROMPT_CHARS)
    small = aa.build_persona_prompt("security-penetration-tester", body_limit=600)
    assert small is not None and full is not None
    assert len(small) < len(full)
    assert "persona truncated" in small


def test_build_prompt_body_limit_zero_keeps_identity_only():
    prompt = aa.build_persona_prompt("security-penetration-tester", body_limit=0)
    assert prompt is not None
    assert "Penetration Tester" in prompt


def test_build_prompt_unknown_slug_returns_none():
    assert aa.build_persona_prompt("nope") is None


def test_truncate_body_keeps_head_and_marker():
    body = "# Title\n\n## A\n" + ("x" * 5000) + "\n\n## B\n" + ("y" * 5000)
    out = aa._truncate_body(body, 600)
    assert out.startswith("# Title")
    assert "truncated" in out
    assert len(out) < len(body)


def test_truncate_body_noop_when_short():
    assert aa._truncate_body("short", 100) == "short"


# ════════════════════════════════════════════════════════════════
#  Frontmatter parsing
# ════════════════════════════════════════════════════════════════

def test_parse_frontmatter_basic():
    fm, body = aa._parse_frontmatter('---\nname: A\ndescription: "d"\n---\n\n# body\n')
    assert fm["name"] == "A"
    assert fm["description"] == "d"
    assert body.strip() == "# body"


def test_parse_frontmatter_missing_is_body_only():
    fm, body = aa._parse_frontmatter("# no frontmatter\n")
    assert fm == {}
    assert body.startswith("# no frontmatter")


def test_parse_frontmatter_multiline_value():
    fm, _ = aa._parse_frontmatter("---\nname: A\n  continued\n---\n\nx")
    assert fm["name"] == "A continued"


def test_normalize_color():
    assert aa._normalize_color("blue") == "#3b82f6"
    assert aa._normalize_color("#DC2626") == "#dc2626"
    assert aa._normalize_color("dc2626") == "#dc2626"
    assert aa._normalize_color("chartreuse") == "#64748b"


def test_persona_without_name_falls_back_to_title():
    agent, err = aa.create_agent({
        "slug": "no-name-persona", "division": "custom", "body": "b",
    })
    assert err is None
    assert agent["name"] == "No Name Persona"


# ════════════════════════════════════════════════════════════════
#  Write API
# ════════════════════════════════════════════════════════════════

def test_create_and_delete_custom_agent():
    agent, err = aa.create_agent({
        "slug": "acme-pentest-lead",
        "division": "custom",
        "name": "Acme Pentest Lead",
        "description": "lead de pentest",
        "emoji": "X",
        "color": "red",
        "vibe": "pragmatic",
        "body": "# Acme\n\nRules here.",
    })
    assert err is None
    assert agent["slug"] == "acme-pentest-lead"
    assert agent["editable"] is True
    assert agent["color"] == "#dc2626"
    assert "acme-pentest-lead" in aa.discover()

    ok, err = aa.delete_agent("acme-pentest-lead")
    assert ok is True and err is None
    assert "acme-pentest-lead" not in aa.discover()


def test_create_rejects_duplicate():
    aa.create_agent({"slug": "dup-agent", "division": "custom", "body": "b"})
    agent, err = aa.create_agent({"slug": "dup-agent", "division": "custom", "body": "b"})
    assert agent is None
    assert "already exists" in err


def test_create_validates_inputs():
    assert aa.create_agent({"slug": "Bad Slug!", "division": "custom", "body": "b"})[1]
    assert aa.create_agent({"slug": "ok-slug", "division": "Bad!", "body": "b"})[1]
    assert aa.create_agent({"slug": "ok-slug2", "division": "custom", "body": "  "})[1]
    assert aa.create_agent({"slug": "", "division": "custom", "body": "b"})[1]


def test_create_rejects_oversized_body():
    big = {"slug": "big-agent", "division": "custom", "body": "x" * (aa._BODY_MAX_CHARS + 10)}
    agent, err = aa.create_agent(big)
    assert agent is None
    assert "exceeds" in err


def test_create_survives_non_dict_payload():
    agent, err = aa.create_agent("not a dict")
    assert agent is None and err


def test_delete_protects_bundled_personas():
    ok, err = aa.delete_agent("security-penetration-tester")
    assert ok is False
    assert "bundled" in err
    assert "security-penetration-tester" in aa.discover()


def test_delete_unknown_agent():
    ok, err = aa.delete_agent("ghost")
    assert ok is False and err == "unknown agent"


# ════════════════════════════════════════════════════════════════
#  Export / import
# ════════════════════════════════════════════════════════════════

def test_export_registry_single_division():
    data = aa.export_registry(division="security")
    assert data["exported"] >= 12
    slugs = {a["slug"] for a in data["agents"]}
    assert "security-penetration-tester" in slugs


def test_export_without_body():
    data = aa.export_registry(division="custom", include_body=False)
    assert all("body" not in a for a in data["agents"])


def test_import_skips_bundled_and_creates_custom():
    aa.create_agent({"slug": "portable-agent", "division": "custom", "body": "# Portable\n"})
    data = aa.export_registry()
    assert any(a["slug"] == "portable-agent" for a in data["agents"])
    assert any(a["slug"] == "security-penetration-tester" for a in data["agents"])

    bundled_before = len(aa.list_agents(division="security"))
    aa.delete_agent("portable-agent")

    result = aa.import_registry(data)
    assert result["imported"] == 1
    assert result["skipped"] == len(data["agents"]) - 1
    assert "portable-agent" in aa.discover()
    assert len(aa.list_agents(division="security")) == bundled_before


def test_import_rejects_bad_payload():
    result = aa.import_registry({"agents": "nope"})
    assert result["imported"] == 0 and result["errors"]


def test_import_reports_entry_errors():
    result = aa.import_registry({"agents": [{"slug": "Bad Slug!", "division": "custom", "body": "x"}]})
    assert result["imported"] == 0
    assert result["errors"]


def test_import_overwrite_replaces_custom():
    aa.create_agent({"slug": "ow-agent", "division": "custom", "body": "v1"})
    result = aa.import_registry({"agents": [
        {"slug": "ow-agent", "division": "custom", "name": "OW", "body": "v2"},
    ]}, overwrite=True)
    assert result["imported"] == 1
    assert "v2" in aa.get_agent("ow-agent")["body"]


# ════════════════════════════════════════════════════════════════
#  Concurrency
# ════════════════════════════════════════════════════════════════

def test_discover_is_thread_safe():
    errors = []

    def worker():
        try:
            for _ in range(20):
                aa.discover()
                aa.list_agents()
        except Exception as exc:  # pragma: no cover - failure path
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
