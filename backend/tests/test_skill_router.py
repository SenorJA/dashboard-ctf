"""Tests for the MIRV Skill Router (backend/skill_router.py + /api/router/*)."""

import json
import os
import sys

import pytest
from fastapi.testclient import TestClient

from backend.main import app  # noqa: E402


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


# ════════════════════════════════════════════════════════════════
#  route_task — routing core
# ════════════════════════════════════════════════════════════════

def test_route_mobile_apk_es():
    from backend.skill_router import route_task
    r = route_task("reverse este apk y analiza el certificate pinning con frida", "es")
    assert r["ok"] and r["primary"]["id"] == "R10"
    assert r["primary"]["skill"] == "apk-reverse"
    assert r["primary"]["rationale"].startswith("Coinciden")
    assert "frida" in r["primary"]["tools"]
    assert r["fallback_used"] is False


def test_route_webvuln_idor_en():
    from backend.skill_router import route_task
    r = route_task("IDOR en el endpoint de usuario, prueba gobuster y ffuf", "en")
    assert r["primary"]["id"] == "R3"
    assert r["primary"]["skill"] == "webvuln"
    assert "gobuster" in r["primary"]["tools"]


def test_route_jwt_alg_confusion():
    from backend.skill_router import route_task
    r = route_task("JWT alg confusion en el id_token bearer")
    assert r["primary"]["id"] == "R5"
    assert r["primary"]["skill"] == "jwt"


def test_route_malware_webshell_es():
    from backend.skill_router import route_task
    r = route_task("he encontrado una webshell en memoria, parece trojano", "es")
    assert r["primary"]["id"] == "R12"
    assert r["primary"]["skill"] == "malware-analysis"


def test_route_pwn_ret2libc():
    from backend.skill_router import route_task
    r = route_task("exploit ret2libc con pwntools para el service")
    assert r["primary"]["id"] == "R13"
    assert r["primary"]["skill"] == "pwn-chain"
    assert "pwntools" in r["primary"]["tools"]


def test_route_ssrf_imds():
    from backend.skill_router import route_task
    r = route_task("probar ssrf a 169.254.169.254 con la url del fetch")
    assert r["primary"]["id"] == "R4"
    assert r["primary"]["skill"] == "ssrf"


def test_route_recon_not_mobile_after_ios_boundary_fix():
    # "subdominios" ends in 'ios' — must NOT trigger R10 (mobile).
    from backend.skill_router import route_task
    r = route_task("nmap de la subred y descubrir subdominios", "es")
    assert r["primary"]["id"] == "R1"
    assert r["primary"]["skill"] == "recon"


def test_route_priority_tiebreak_takeover_wins():
    from backend.skill_router import route_task
    r = route_task("subdominios con fallo de takeover", "en")
    assert r["primary"]["id"] == "R9"


def test_route_alternatives_included():
    from backend.skill_router import route_task
    r = route_task("necesito hackear el ctf de pwntools con ret2libc")
    assert r["primary"]["id"] == "R13"
    ids = [a["id"] for a in r["alternatives"]]
    assert "R19" in ids or ids  # at least one alternative scored
    assert len(r["alternatives"]) <= 5


def test_route_fallback_when_no_match():
    from backend.skill_router import route_task
    r = route_task("hola mundo que tal el dia", "es")
    assert r["primary"]["id"] == "R0"
    assert r["fallback_used"] is True
    assert "respaldo" in r["primary"]["rationale"]


def test_route_empty_hint_falls_back():
    from backend.skill_router import route_task
    r = route_task("")
    assert r["fallback_used"] is True


def test_route_ssrf_wins_over_webvuln():
    # Both R3 and R4 can match; R4 (specific) must win by priority.
    from backend.skill_router import route_task
    r = route_task("ssrf en la url del servidor web")
    assert r["primary"]["id"] == "R4"


# ════════════════════════════════════════════════════════════════
#  config loading / hot-reload / validation
# ════════════════════════════════════════════════════════════════

def test_load_config_is_valid_and_shipped():
    from backend.skill_router import load_config, list_routes
    load_config(force=True)
    out = list_routes("en")
    assert out["ok"] and out["fallbackId"] == "R0"
    rids = [r["id"] for r in out["routes"]]
    assert "R1" in rids and "R10" in rids and "R0" in rids
    assert out["routes"][0]["priority"] == 0


def test_hot_reload_picks_up_env_config(monkeypatch, tmp_path):
    from backend.skill_router import load_config, list_routes
    cfg = {
        "schemaVersion": "1.0",
        "meta": {"description": "temp", "fallbackId": "R0"},
        "routes": {
            "R1": {"label": {"en": "x", "es": "x"}, "skill": "recon",
                   "module": "m", "tools": [], "keywords": [{"must": "foo", "note": ""}]},
            "R0": {"label": {"en": "f", "es": "f"}, "skill": None,
                   "module": "m", "tools": [], "keywords": [{"must": "anything", "note": ""}]},
        },
        "priority": ["R1", "R0"],
    }
    p = tmp_path / "routing.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    monkeypatch.setenv("MIRV_ROUTER_CONFIG", str(p))
    load_config(force=True)
    assert "R1" in {r["id"] for r in list_routes("en")["routes"]}
    # toggle content + bump mtime -> reload on next load
    cfg["routes"]["R1"]["label"]["en"] = "changed"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    btime = p.stat().st_mtime + 2.0
    os.utime(p, (btime, btime))
    out = list_routes("en")
    assert out["routes"][0]["label"] == "changed"
    monkeypatch.delenv("MIRV_ROUTER_CONFIG", raising=False)
    load_config(force=True)


def test_invalid_config_fails_closed_to_embedded(monkeypatch, tmp_path):
    from backend.skill_router import load_config, route_task
    p = tmp_path / "bad.json"
    p.write_text('{"schemaVersion": 2, "bogus": true}', encoding="utf-8")
    monkeypatch.setenv("MIRV_ROUTER_CONFIG", str(p))
    cfg = load_config(force=True)
    assert cfg["schemaVersion"] == "1.0"  # embedded default survived
    r = route_task("nmap en la subred", "en")
    assert r["primary"]["id"] in {"R1", "R0"}
    monkeypatch.delenv("MIRV_ROUTER_CONFIG", raising=False)
    load_config(force=True)


def test_route_by_id():
    from backend.skill_router import route_by_id
    d = route_by_id("R14", "es")
    assert d["ok"] and d["skill"] == "firmware-pentest"
    assert d["keywords"]
    missing = route_by_id("R999")
    assert missing["ok"] is False


# ════════════════════════════════════════════════════════════════
#  detect_tools
# ════════════════════════════════════════════════════════════════

def test_detect_tools_fake_which():
    from backend.skill_router import detect_tools
    def fake_which(name):
        return "/bin/x" if name in {"nmap", "yara", "curl"} else None
    out = detect_tools(which_fn=fake_which, tools=["nmap", "yara", "curl", "jadx"])
    assert out["detected"] == ["curl", "nmap", "yara"]
    assert out["missing"] == ["jadx"]
    assert out["detected_count"] == 3


def test_detect_tools_which_raises_is_tolerated():
    from backend.skill_router import detect_tools
    def boom(_name):  # noqa: ANN001
        raise RuntimeError("path lookup failed")
    out = detect_tools(which_fn=boom, tools=["nmap", "jadx"])
    assert out["ok"] and out["detected"] == [] and out["detected_count"] == 0


# ════════════════════════════════════════════════════════════════
#  Ported RE skills are discovered + categorized (Pack 9)
# ════════════════════════════════════════════════════════════════

def test_ported_re_skills_discovered():
    from backend.skill_playbooks import discover_skills, get_skill_info
    discover_skills()
    expectations = {
        "apk-reverse": "mobile",
        "js-reverse": "reverse",
        "malware-analysis": "malware",
        "pwn-chain": "pwn",
        "firmware-pentest": "firmware",
    }
    for name, cat in expectations.items():
        info = get_skill_info(name)
        assert info is not None, f"{name} not discovered"
        assert info["category"] == cat
        assert info["allowed_tools"]


# ════════════════════════════════════════════════════════════════
#  API endpoints
# ════════════════════════════════════════════════════════════════

def test_api_router_routes_list(client):
    r = client.get("/api/router/routes")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and body["fallbackId"] == "R0"
    assert any(x["id"] == "R10" for x in body["routes"])


def test_api_router_routes_list_es(client):
    r = client.get("/api/router/routes?lang=es")
    assert r.status_code == 200
    first = r.json()["routes"][0]
    assert first["label"]


def test_api_router_route_post(client):
    r = client.post("/api/router/route", json={"hint": "render este apk con jadx y pinning frida", "lang": "es"})
    assert r.status_code == 200
    body = r.json()
    assert body["primary"]["id"] == "R10"
    assert body["primary"]["skill"] == "apk-reverse"


def test_api_router_route_get(client):
    r = client.get("/api/router/route", params={"hint": "JWT alg none bearer token", "lang": "en"})
    assert r.status_code == 200
    assert r.json()["primary"]["id"] == "R5"


def test_api_router_route_detail(client):
    r = client.get("/api/router/routes/R12")
    assert r.status_code == 200
    assert r.json()["skill"] == "malware-analysis"


def test_api_router_route_detail_unknown(client):
    r = client.get("/api/router/routes/R404")
    assert r.status_code == 200
    assert r.json()["ok"] is False


def test_api_router_tool_index(client):
    r = client.get("/api/router/tool-index")
    assert r.status_code == 200
    body = r.json()
    assert body["ok"] and "detected" in body and "tools" in body


def test_api_router_reload(client):
    r = client.post("/api/router/reload")
    assert r.status_code == 200
    assert r.json()["ok"] is True