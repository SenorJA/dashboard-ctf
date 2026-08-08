"""
Gap tests for main.py coverage: redact API, findings DB-fallback paths,
canary/DLP/SIEM/audit/plugin endpoints (success + error branches).
"""
import asyncio
import io
import json
import os
import runpy
import sys
from dataclasses import dataclass, asdict, field
from unittest.mock import patch, AsyncMock, MagicMock
from types import SimpleNamespace

from fastapi.testclient import TestClient
import main
from backend.finding_poc import FindingPoC
from backend.intelligence import DiffResult


def _body(resp):
    """Read the JSON body of a raw starlette JSONResponse."""
    return json.loads(resp.body)


@dataclass
class FakePermission:
    id: str = "p1"
    tool: str = "shell"
    command: str = "ls"
    status: str = "pending"


@dataclass
class FakeIntelWatch:
    id: str = "w1"
    name: str = "watch"
    target: str = "http://target.test/"
    watch_type: str = "http_headers"
    interval_seconds: int = 3600
    enabled: bool = True
    created_at: str = ""
    last_check: object = None
    tags: list = field(default_factory=list)


@dataclass
class FakeIntelSnapshot:
    id: str = "s1"
    watch_id: str = "w1"
    target: str = "http://target.test/"
    watch_type: str = "http_headers"
    captured_at: str = "2026-01-01T00:00:00Z"
    data: dict = field(default_factory=dict)
    previous_snapshot_id: object = None


@dataclass
class FakeIntelAlert:
    id: str = "a1"
    watch_id: str = "w1"
    target: str = "http://target.test/"
    alert_type: str = "change_detected"
    severity: str = "high"
    message: str = "changed"
    details: dict = field(default_factory=dict)
    created_at: str = "2026-01-01T00:00:00Z"
    acknowledged: bool = False


class _FakeStream(io.StringIO):
    def reconfigure(self, **kwargs):
        raise RuntimeError("no reconfigure")


class _HugeBytes:
    __len__ = lambda self: 500 * 1024 * 1024 + 1  # noqa: E731


def _fake_poc():
    return FindingPoC(
        finding_id="f1",
        method="GET",
        url="http://target.test/api/x",
        headers={},
        body=None,
        parameter=None,
        payload=None,
        response_status=200,
        response_excerpt="leak",
        curl_command="curl -s http://target.test/api/x",
        raw_request="GET /api/x HTTP/1.1\r\nHost: target.test\r\n\r\n",
        remediation=None,
        impact="info disclosure",
        evidence_hash="abc123",
    )


def _report(**overrides):
    base = {
        "source": "text",
        "source_name": "test",
        "content_length": 10,
        "lines_scanned": 1,
        "risk_score": 20,
        "duration_seconds": 0.1,
    }
    base.update(overrides)
    return SimpleNamespace(**base)


def _event(**overrides):
    base = {
        "id": "evt-1",
        "timestamp": "2026-01-01T00:00:00",
        "source": "test",
        "severity": "low",
        "title": "probe",
    }
    base.update(overrides)
    return SimpleNamespace(**base)


class TestRedactApi:
    def test_api_redact_success(self, client: TestClient):
        r = client.post("/api/redact", json={"text": "key = SK-1234"})
        assert r.status_code == 200
        assert r.json()["ok"] is True
        assert "redacted" in r.json()

    def test_api_redact_error(self, client: TestClient):
        with patch("main.redact_string", side_effect=RuntimeError("boom")):
            r = client.post("/api/redact", json={"text": "x"})
        assert r.status_code == 500
        assert r.json()["error"] == "boom"

    def test_api_redact_dict_success(self, client: TestClient):
        r = client.post("/api/redact/dict", json={"api_key": "AWSAKIA1234567890ABCDEF", "n": 1})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_api_redact_dict_empty(self, client: TestClient):
        r = client.post("/api/redact/dict", json={})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_api_redact_dict_error(self, client: TestClient):
        with patch("main.redact_dict", side_effect=RuntimeError("boom")):
            r = client.post("/api/redact/dict", json={"a": "b"})
        assert r.status_code == 500

    def test_api_redact_patterns(self, client: TestClient):
        r = client.get("/api/redact/patterns")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["count"] > 0
        assert "patterns" in body

    def test_api_redact_check(self, client: TestClient):
        r = client.post("/api/redact/check", json={"text": "nothing secret"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["sensitive"] is False
        assert body["matches"] == []

    def test_api_redact_check_error(self, client: TestClient):
        with patch("main.list_redaction_matches", side_effect=RuntimeError("boom")):
            r = client.post("/api/redact/check", json={"text": "x"})
        assert r.status_code == 500


class TestFindingsFallback:
    def test_get_findings_db_missing(self, client: TestClient):
        with patch("main.db.list_findings", return_value=None):
            r = client.get("/api/findings?target=example.com")
        assert r.status_code == 200
        assert r.json()["fallback"] is True
        assert r.json()["data"] == []

    def test_get_findings_success(self, client: TestClient):
        with patch("main.db.list_findings", return_value=[{"id": "1"}]):
            r = client.get("/api/findings")
        assert r.status_code == 200
        assert r.json()["data"] == [{"id": "1"}]
        assert "fallback" not in r.json()

    def test_create_finding_db_missing(self, client: TestClient):
        with patch("main.db.save_finding", return_value=None):
            r = client.post("/api/findings", json={"tool": "nmap"})
        assert r.status_code == 503

    def test_create_finding_empty(self, client: TestClient):
        r = client.post("/api/findings", json={})
        assert r.status_code == 400

    def test_create_finding_success(self, client: TestClient):
        with patch("main.db.save_finding", return_value={"id": "1"}):
            r = client.post("/api/findings", json={"tool": "nmap"})
        assert r.status_code == 201
        assert r.json()["data"]["id"] == "1"

    def test_create_findings_bulk_db_missing(self, client: TestClient):
        with patch("main.db.save_findings_bulk", return_value=None):
            r = client.post("/api/findings/bulk", json=[{"tool": "nmap"}])
        assert r.status_code == 503

    def test_create_findings_bulk_empty(self, client: TestClient):
        r = client.post("/api/findings/bulk", json=[])
        assert r.status_code == 400

    def test_create_findings_bulk_success(self, client: TestClient):
        with patch("main.db.save_findings_bulk", return_value=2):
            r = client.post("/api/findings/bulk", json=[{"tool": "a"}, {"tool": "b"}])
        assert r.status_code == 201
        assert r.json()["count"] == 2

    def test_remove_finding_db_missing(self, client: TestClient):
        with patch("main.db.delete_finding", return_value=None):
            r = client.delete("/api/findings/f1")
        assert r.status_code == 503

    def test_remove_finding_success(self, client: TestClient):
        with patch("main.db.delete_finding", return_value=True):
            r = client.delete("/api/findings/f1")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_clear_all_findings_db_missing(self, client: TestClient):
        with patch("main.db.delete_all_findings", return_value=None):
            r = client.delete("/api/findings")
        assert r.status_code == 503

    def test_clear_all_findings_success(self, client: TestClient):
        with patch("main.db.delete_all_findings", return_value=True):
            r = client.delete("/api/findings")
        assert r.status_code == 200
        assert r.json()["ok"] is True


class TestCanaryApi:
    def test_create_invalid_type(self, client: TestClient):
        r = client.post("/api/canary/token", data={"token_type": "bad", "name": "x"})
        assert r.status_code == 422

    def test_create_success(self, client: TestClient):
        with (
            patch("main.canary_generate", return_value=SimpleNamespace(id="t1")) as cg,
            patch("main.canary_to_mirv", return_value=[]) as cm,
            patch("main.asdict", side_effect=lambda o: {"id": o.id}),
        ):
            r = client.post("/api/canary/token", data={"token_type": "api-key", "name": "x"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["token"]["id"] == "t1"
        cg.assert_called_once_with("api-key", "x", "")
        cm.assert_called_once()

    def test_create_error(self, client: TestClient):
        with patch("main.canary_generate", side_effect=RuntimeError("boom")):
            r = client.post("/api/canary/token", data={"token_type": "jwt", "name": "x"})
        assert r.status_code == 500

    def test_list(self, client: TestClient):
        with patch("main.canary_list", return_value=[{"id": "t1"}]):
            r = client.get("/api/canary/tokens")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_activate_not_found(self, client: TestClient):
        with patch("main.canary_activate", return_value=None):
            r = client.get("/api/canary/activate/t1")
        assert r.status_code == 404

    def test_activate_success(self, client: TestClient):
        evt = SimpleNamespace(id="e1")
        tok = SimpleNamespace(id="t1")
        with (
            patch("main.canary_activate", return_value=evt),
            patch("main.canary_get", return_value=tok),
            patch("main.canary_to_mirv", return_value=[{"id": "f1"}]),
            patch("main.asdict", side_effect=lambda o: {"id": o.id}),
        ):
            r = client.get("/api/canary/activate/t1", headers={"User-Agent": "ua", "Referer": "ref"})
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["event"]["id"] == "e1"
        assert body["findings"] == [{"id": "f1"}]

    def test_events(self, client: TestClient):
        with patch("main.canary_events", return_value=[{"id": "e1"}]):
            r = client.get("/api/canary/events?token_id=t1")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_delete_not_found(self, client: TestClient):
        with patch("main.canary_delete", return_value=False):
            r = client.delete("/api/canary/token/t1")
        assert r.status_code == 404

    def test_delete_success(self, client: TestClient):
        with patch("main.canary_delete", return_value=True):
            r = client.delete("/api/canary/token/t1")
        assert r.status_code == 200
        assert r.json()["ok"] is True


class TestDlpApi:
    def test_scan_empty_text(self, client: TestClient):
        r = client.post("/api/dlp/scan", json={"text": "   "})
        assert r.status_code == 422

    def test_scan_success(self, client: TestClient):
        with (
            patch("main.dlp_scan_text", return_value=_report()),
            patch("main.dlp_to_mirv", return_value=[{"id": "f1"}]),
        ):
            r = client.post("/api/dlp/scan", json={"text": "hi"})
        assert r.status_code == 200
        assert r.json()["findings_count"] == 1

    def test_scan_error(self, client: TestClient):
        with patch("main.dlp_scan_text", side_effect=RuntimeError("boom")):
            r = client.post("/api/dlp/scan", json={"text": "hi"})
        assert r.status_code == 500

    def test_scan_file_success(self, client: TestClient):
        with (
            patch("main.dlp_scan_file", return_value=_report(source="file")),
            patch("main.dlp_to_mirv", return_value=[]),
        ):
            r = client.post("/api/dlp/scan-file", files={"file": ("test.txt", b"hello", "text/plain")})
        assert r.status_code == 200
        assert r.json()["source"] == "file"

    def test_scan_file_too_large(self, client: TestClient):
        big = b"x" * (20 * 1024 * 1024 + 1)
        r = client.post("/api/dlp/scan-file", files={"file": ("big.txt", big, "text/plain")})
        assert r.status_code == 413

    def test_scan_file_error(self, client: TestClient):
        with patch("main.dlp_scan_file", side_effect=RuntimeError("boom")):
            r = client.post("/api/dlp/scan-file", files={"file": ("t.txt", b"x", "text/plain")})
        assert r.status_code == 500

    def test_scan_url_missing(self, client: TestClient):
        r = client.get("/api/dlp/scan-url")
        assert r.status_code == 422

    def test_scan_url_bad_scheme(self, client: TestClient):
        r = client.get("/api/dlp/scan-url?url=ftp://x")
        assert r.status_code == 422

    def test_scan_url_success(self, client: TestClient):
        async def fake(url):
            return _report(source="url")
        with (
            patch("main.dlp_scan_url", side_effect=fake),
            patch("main.dlp_to_mirv", return_value=[]),
        ):
            r = client.get("/api/dlp/scan-url?url=https://example.com")
        assert r.status_code == 200
        assert r.json()["source"] == "url"

    def test_scan_url_error(self, client: TestClient):
        with (
            patch("main.dlp_scan_url", side_effect=RuntimeError("boom")),
            patch("main.dlp_to_mirv", return_value=[]),
        ):
            r = client.get("/api/dlp/scan-url?url=https://example.com")
        assert r.status_code == 502


class TestSiemApi:
    def test_ingest_success(self, client: TestClient):
        with patch("main.siem_ingest", return_value=_event()) as ing:
            r = client.post("/api/siem/event", json={
                "source": "test", "severity": "low", "title": "t", "detail": "d",
            })
        assert r.status_code == 200
        assert r.json()["event"]["id"] == "evt-1"
        ing.assert_called_once()

    def test_ingest_value_error(self, client: TestClient):
        with patch("main.siem_ingest", side_effect=ValueError("bad severity")):
            r = client.post("/api/siem/event", json={
                "source": "test", "severity": "low", "title": "t", "detail": "d",
            })
        assert r.status_code == 422

    def test_ingest_error(self, client: TestClient):
        with patch("main.siem_ingest", side_effect=RuntimeError("boom")):
            r = client.post("/api/siem/event", json={
                "source": "test", "severity": "low", "title": "t", "detail": "d",
            })
        assert r.status_code == 500

    def test_list_events_success(self, client: TestClient):
        with patch("main.siem_events", return_value=[{"id": "e1"}]):
            r = client.get("/api/siem/events?severity=low&source=x&since=2026-01-01")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_list_events_error(self, client: TestClient):
        with patch("main.siem_events", side_effect=RuntimeError("boom")):
            r = client.get("/api/siem/events")
        assert r.status_code == 500

    def test_stats_success(self, client: TestClient):
        with patch("main.siem_stats", return_value={"total_events": 5}):
            r = client.get("/api/siem/stats")
        assert r.status_code == 200
        assert r.json()["total_events"] == 5

    def test_stats_error(self, client: TestClient):
        with patch("main.siem_stats", side_effect=RuntimeError("boom")):
            r = client.get("/api/siem/stats")
        assert r.status_code == 500

    def test_create_rule_success(self, client: TestClient):
        with patch("main.siem_create_rule", return_value=SimpleNamespace(
            id="r1", name="n", condition="c", severity="high", enabled=True, config={}
        )):
            r = client.post("/api/siem/rules", json={
                "name": "n", "description": "d", "condition": "c", "severity": "high",
            })
        assert r.status_code == 200
        assert r.json()["rule"]["id"] == "r1"

    def test_create_rule_value_error(self, client: TestClient):
        with patch("main.siem_create_rule", side_effect=ValueError("bad")):
            r = client.post("/api/siem/rules", json={"name": "n", "condition": "c"})
        assert r.status_code == 422

    def test_create_rule_error(self, client: TestClient):
        with patch("main.siem_create_rule", side_effect=RuntimeError("boom")):
            r = client.post("/api/siem/rules", json={"name": "n", "description": "d", "condition": "c"})
        assert r.status_code == 500

    def test_list_rules_success(self, client: TestClient):
        with patch("main.siem_get_rules", return_value=[{"id": "r1"}]):
            r = client.get("/api/siem/rules")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_list_rules_error(self, client: TestClient):
        with patch("main.siem_get_rules", side_effect=RuntimeError("boom")):
            r = client.get("/api/siem/rules")
        assert r.status_code == 500

    def test_delete_rule_not_found(self, client: TestClient):
        with patch("main.siem_delete_rule", return_value=False):
            r = client.delete("/api/siem/rules/r1")
        assert r.status_code == 404

    def test_delete_rule_success(self, client: TestClient):
        with patch("main.siem_delete_rule", return_value=True):
            r = client.delete("/api/siem/rules/r1")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_delete_rule_error(self, client: TestClient):
        with patch("main.siem_delete_rule", side_effect=RuntimeError("boom")):
            r = client.delete("/api/siem/rules/r1")
        assert r.status_code == 500

    def test_list_alerts_success(self, client: TestClient):
        with patch("main.siem_get_alerts", return_value=[{"id": "a1"}]):
            r = client.get("/api/siem/alerts?limit=10&offset=0")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_list_alerts_error(self, client: TestClient):
        with patch("main.siem_get_alerts", side_effect=RuntimeError("boom")):
            r = client.get("/api/siem/alerts")
        assert r.status_code == 500

    def test_findings_success(self, client: TestClient):
        with patch("main.siem_get_alerts", return_value=[]):
            r = client.get("/api/siem/findings")
        assert r.status_code == 200
        assert r.json()["findings"] == []

    def test_findings_error(self, client: TestClient):
        with patch("main.siem_get_alerts", side_effect=RuntimeError("boom")):
            r = client.get("/api/siem/findings")
        assert r.status_code == 500


class TestAuditApi:
    def test_logs_success(self, client: TestClient):
        with patch("main.al_recent", return_value=[{"level": "INFO"}]):
            r = client.get("/api/audit/logs?limit=10&level=INFO&category=x&event=y&since=2026-01-01")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_logs_error(self, client: TestClient):
        with patch("main.al_recent", side_effect=RuntimeError("boom")):
            r = client.get("/api/audit/logs")
        assert r.status_code == 500

    def test_stats_success(self, client: TestClient):
        with patch("main.al_stats", return_value={"total": 3}):
            r = client.get("/api/audit/stats")
        assert r.status_code == 200
        assert r.json()["total"] == 3

    def test_stats_error(self, client: TestClient):
        with patch("main.al_stats", side_effect=RuntimeError("boom")):
            r = client.get("/api/audit/stats")
        assert r.status_code == 500

    def test_create_invalid_level(self, client: TestClient):
        r = client.post("/api/audit", json={"level": "nope", "message": "m"})
        assert r.status_code == 422

    def test_create_success(self, client: TestClient):
        with patch("main.al_audit", return_value={"ok": True, "skipped": False}) as aud:
            r = client.post("/api/audit", json={
                "level": "INFO", "category": "system", "event": "manual_entry",
                "message": "hi", "user": "u", "ip": "1.2.3.4", "target": "t",
                "session_id": "s", "details": {"a": 1},
            })
        assert r.status_code == 200
        assert r.json()["ok"] is True
        aud.assert_called_once()

    def test_create_not_ok(self, client: TestClient):
        with patch("main.al_audit", return_value={"ok": False, "error": "no"}):
            r = client.post("/api/audit", json={"message": "m"})
        assert r.status_code == 422

    def test_create_error(self, client: TestClient):
        with patch("main.al_audit", side_effect=RuntimeError("boom")):
            r = client.post("/api/audit", json={"message": "m"})
        assert r.status_code == 500


class TestPluginApi:
    def test_list_success(self, client: TestClient):
        with patch("main.pm_list", return_value=[{"name": "p1"}]):
            r = client.get("/api/plugins")
        assert r.status_code == 200
        assert len(r.json()["plugins"]) == 1

    def test_list_error(self, client: TestClient):
        with patch("main.pm_list", side_effect=RuntimeError("boom")):
            r = client.get("/api/plugins")
        assert r.status_code == 500

    def test_info_not_found(self, client: TestClient):
        with patch("main.pm_info", return_value=None):
            r = client.get("/api/plugins/p1")
        assert r.status_code == 404

    def test_info_success(self, client: TestClient):
        with patch("main.pm_info", return_value={"name": "p1"}):
            r = client.get("/api/plugins/p1")
        assert r.status_code == 200
        assert r.json()["plugin"]["name"] == "p1"

    def test_info_error(self, client: TestClient):
        with patch("main.pm_info", side_effect=RuntimeError("boom")):
            r = client.get("/api/plugins/p1")
        assert r.status_code == 500

    def _action(self, client, action):
        return client.post(f"/api/plugins/p1/{action}")

    def test_load_ok(self, client: TestClient):
        with patch("main.pm_load", return_value={"ok": True}):
            assert self._action(client, "load").status_code == 200

    def test_load_fail(self, client: TestClient):
        with patch("main.pm_load", return_value={"ok": False, "error": "no"}):
            assert self._action(client, "load").status_code == 400

    def test_load_error(self, client: TestClient):
        with patch("main.pm_load", side_effect=RuntimeError("boom")):
            assert self._action(client, "load").status_code == 500

    def test_unload_ok(self, client: TestClient):
        with patch("main.pm_unload", return_value={"ok": True}):
            assert self._action(client, "unload").status_code == 200

    def test_unload_error(self, client: TestClient):
        with patch("main.pm_unload", side_effect=RuntimeError("boom")):
            assert self._action(client, "unload").status_code == 500

    def test_reload_ok(self, client: TestClient):
        with patch("main.pm_reload", return_value={"ok": True}):
            assert self._action(client, "reload").status_code == 200

    def test_reload_error(self, client: TestClient):
        with patch("main.pm_reload", side_effect=RuntimeError("boom")):
            assert self._action(client, "reload").status_code == 500

    def test_enable_ok(self, client: TestClient):
        with patch("main.pm_enable", return_value={"ok": True}):
            assert self._action(client, "enable").status_code == 200

    def test_enable_error(self, client: TestClient):
        with patch("main.pm_enable", side_effect=RuntimeError("boom")):
            assert self._action(client, "enable").status_code == 500

    def test_disable_ok(self, client: TestClient):
        with patch("main.pm_disable", return_value={"ok": True}):
            assert self._action(client, "disable").status_code == 200

    def test_disable_error(self, client: TestClient):
        with patch("main.pm_disable", side_effect=RuntimeError("boom")):
            assert self._action(client, "disable").status_code == 500

    def test_hook_success(self, client: TestClient):
        with patch("main.pm_call_hook", return_value=[{"p1": None}]) as hook:
            r = client.post("/api/plugins/hooks/on_startup", json={"args": [], "kwargs": {}})
        assert r.status_code == 200
        assert r.json()["hook"] == "on_startup"
        hook.assert_called_once_with("on_startup")

    def test_hook_error(self, client: TestClient):
        with patch("main.pm_call_hook", side_effect=RuntimeError("boom")):
            r = client.post("/api/plugins/hooks/on_startup", json={"args": [], "kwargs": {}})
        assert r.status_code == 500


class TestStaticFiles:
    def test_css_forbidden(self):
        resp = asyncio.run(main.css_file("../../secret"))
        assert resp.status_code == 403

    def test_css_file(self, client: TestClient):
        r = client.get("/css/style.css")
        assert r.status_code == 200

    def test_css_not_found(self, client: TestClient):
        r = client.get("/css/nope.css")
        assert r.status_code == 404

    def test_js_forbidden(self):
        resp = asyncio.run(main.js_file("../../secret"))
        assert resp.status_code == 403

    def test_js_file(self, client: TestClient):
        r = client.get("/js/main.js")
        assert r.status_code == 200

    def test_js_not_found(self, client: TestClient):
        r = client.get("/js/nope.js")
        assert r.status_code == 404

    def test_img_forbidden(self):
        resp = asyncio.run(main.img_file("../../secret"))
        assert resp.status_code == 403

    def test_img_svg(self, client: TestClient):
        r = client.get("/img/favicon.svg")
        assert r.status_code == 200
        assert "image/svg+xml" in r.headers.get("content-type", "")

    def test_img_not_found(self, client: TestClient):
        r = client.get("/img/nope.png")
        assert r.status_code == 404


class TestPluginWatcherApi:
    def test_start_success(self, client: TestClient):
        with (
            patch("main.pm_start_watch", return_value=None),
            patch("main.pm_watch_status", return_value={"watching": True}),
        ):
            r = client.post("/api/plugins/watcher/start", json={"auto_load_new": True})
        assert r.status_code == 200
        assert r.json()["status"] == {"watching": True}

    def test_start_error(self, client: TestClient):
        with patch("main.pm_start_watch", side_effect=RuntimeError("boom")):
            r = client.post("/api/plugins/watcher/start")
        assert r.status_code == 500

    def test_stop_success(self, client: TestClient):
        with (
            patch("main.pm_stop_watch", return_value=None),
            patch("main.pm_watch_status", return_value={"watching": False}),
        ):
            r = client.post("/api/plugins/watcher/stop")
        assert r.status_code == 200
        assert r.json()["status"] == {"watching": False}

    def test_stop_error(self, client: TestClient):
        with patch("main.pm_stop_watch", side_effect=RuntimeError("boom")):
            r = client.post("/api/plugins/watcher/stop")
        assert r.status_code == 500

    def test_events_success(self, client: TestClient):
        with patch("main.pm_watch_events", return_value=[{"ev": 1}]):
            r = client.get("/api/plugins/watcher/events")
        assert r.status_code == 200
        assert len(r.json()["events"]) == 1

    def test_events_error(self, client: TestClient):
        with patch("main.pm_watch_events", side_effect=RuntimeError("boom")):
            r = client.get("/api/plugins/watcher/events")
        assert r.status_code == 500

    def test_status_success(self, client: TestClient):
        with patch("main.pm_watch_status", return_value={"watching": True}):
            r = client.get("/api/plugins/watcher/status")
        assert r.status_code == 200
        assert r.json()["status"] == {"watching": True}

    def test_status_error(self, client: TestClient):
        with patch("main.pm_watch_status", side_effect=RuntimeError("boom")):
            r = client.get("/api/plugins/watcher/status")
        assert r.status_code == 500


class TestSkillsApi:
    def test_list_success(self, client: TestClient):
        with (
            patch("main.sp_discover", return_value=None),
            patch("main.sp_list", return_value=[{"name": "recon"}]),
        ):
            r = client.get("/api/skills")
        assert r.status_code == 200
        assert len(r.json()["skills"]) == 1

    def test_list_error(self, client: TestClient):
        with patch("main.sp_discover", side_effect=RuntimeError("boom")):
            r = client.get("/api/skills")
        assert r.status_code == 500

    def test_info_not_found(self, client: TestClient):
        with patch("main.sp_info", return_value=None):
            r = client.get("/api/skills/recon")
        assert r.status_code == 404

    def test_info_success(self, client: TestClient):
        with patch("main.sp_info", return_value={"name": "recon"}):
            r = client.get("/api/skills/recon")
        assert r.status_code == 200
        assert r.json()["skill"]["name"] == "recon"

    def test_info_error(self, client: TestClient):
        with patch("main.sp_info", side_effect=RuntimeError("boom")):
            r = client.get("/api/skills/recon")
        assert r.status_code == 500

    def _action(self, client, action):
        return client.post(f"/api/skills/recon/{action}")

    def test_load_ok(self, client: TestClient):
        with patch("main.sp_load", return_value={"ok": True}):
            assert self._action(client, "load").status_code == 200

    def test_load_error(self, client: TestClient):
        with patch("main.sp_load", side_effect=RuntimeError("boom")):
            assert self._action(client, "load").status_code == 500

    def test_unload_ok(self, client: TestClient):
        with patch("main.sp_unload", return_value={"ok": True}):
            assert self._action(client, "unload").status_code == 200

    def test_unload_error(self, client: TestClient):
        with patch("main.sp_unload", side_effect=RuntimeError("boom")):
            assert self._action(client, "unload").status_code == 500

    def test_enable_ok(self, client: TestClient):
        with patch("main.sp_enable", return_value={"ok": True}):
            assert self._action(client, "enable").status_code == 200

    def test_enable_error(self, client: TestClient):
        with patch("main.sp_enable", side_effect=RuntimeError("boom")):
            assert self._action(client, "enable").status_code == 500

    def test_disable_ok(self, client: TestClient):
        with patch("main.sp_disable", return_value={"ok": True}):
            assert self._action(client, "disable").status_code == 200

    def test_disable_error(self, client: TestClient):
        with patch("main.sp_disable", side_effect=RuntimeError("boom")):
            assert self._action(client, "disable").status_code == 500

    def test_reload_ok(self, client: TestClient):
        with patch("main.sp_reload", return_value={"ok": True}):
            assert self._action(client, "reload").status_code == 200

    def test_reload_error(self, client: TestClient):
        with patch("main.sp_reload", side_effect=RuntimeError("boom")):
            assert self._action(client, "reload").status_code == 500

    def test_render_success(self, client: TestClient):
        with patch("main.sp_render", return_value="# body"):
            r = client.get("/api/skills/recon/render")
        assert r.status_code == 200
        assert r.json()["enabled"] is True

    def test_render_disabled(self, client: TestClient):
        with (
            patch("main.sp_render", return_value=""),
            patch("main.sp_info", return_value={"name": "recon"}),
        ):
            r = client.get("/api/skills/recon/render")
        assert r.status_code == 200
        assert r.json()["enabled"] is False
        assert r.json()["body"] == ""

    def test_render_not_found(self, client: TestClient):
        with (
            patch("main.sp_render", return_value=""),
            patch("main.sp_info", return_value=None),
        ):
            r = client.get("/api/skills/recon/render")
        assert r.status_code == 404

    def test_render_error(self, client: TestClient):
        with patch("main.sp_render", side_effect=RuntimeError("boom")):
            r = client.get("/api/skills/recon/render")
        assert r.status_code == 500

    def test_create_missing_name(self, client: TestClient):
        r = client.post("/api/skills/create", json={"name": "  "})
        assert r.status_code == 400

    def test_create_success(self, client: TestClient):
        with patch("main.sp_create_template", return_value={"ok": True}) as ct:
            r = client.post("/api/skills/create", json={
                "name": "newskill", "category": "recon", "description": "d",
                "allowed_tools": ["nmap"],
            })
        assert r.status_code == 200
        ct.assert_called_once_with(name="newskill", category="recon", description="d", allowed_tools=["nmap"])

    def test_create_error(self, client: TestClient):
        with patch("main.sp_create_template", side_effect=RuntimeError("boom")):
            r = client.post("/api/skills/create", json={"name": "newskill"})
        assert r.status_code == 500


class TestNewsApi:
    def _report(self):
        art = SimpleNamespace(
            title="t", link="http://x", published="2026", source_name="src",
            source_id="s", summary="sum", category="cat", author="a",
        )
        return SimpleNamespace(
            total_articles=1, sources_ok=1, sources_failed=0, duration_seconds=0.1,
            source_details=[], articles=[art],
        )

    def test_success(self, client: TestClient):
        async def fake(sources=None, max_per_source=5):
            return self._report()
        with (
            patch("main.fetch_news", side_effect=fake),
            patch("main.news_to_mirv", return_value=[{"id": "f1"}]),
        ):
            r = client.get("/api/news?sources=feed1&max_per_source=2")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["total_articles"] == 1
        assert body["articles"][0]["title"] == "t"
        assert len(body["findings"]) == 1

    def test_error(self, client: TestClient):
        async def fake(sources=None, max_per_source=5):
            raise RuntimeError("boom")
        with patch("main.fetch_news", side_effect=fake):
            r = client.get("/api/news")
        assert r.status_code == 502


class TestApiScanApi:
    def _report(self):
        ep = SimpleNamespace(path="/x", method="GET", status_code=200, content_length=10, response_time=0.1)
        issue = SimpleNamespace(severity="low", title="t", detail="d", endpoint="/x", category="c")
        return SimpleNamespace(
            base_url="https://x", endpoints_scanned=1, issues=[issue], open_endpoints=[ep],
            cors_enabled=False, auth_required=False, missing_headers=["h"], info_disclosures=["i"],
            duration_seconds=0.2,
        )

    def test_missing_url(self, client: TestClient):
        r = client.get("/api/apiscan")
        assert r.status_code == 422

    def test_success(self, client: TestClient):
        async def fake(url, timeout=10, concurrency=10):
            return self._report()
        with (
            patch("main.api_scan", side_effect=fake),
            patch("main.api_to_mirv", return_value=[]),
        ):
            r = client.get("/api/apiscan?url=https://x&timeout=5&concurrency=50")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["issues_count"] == 1
        assert body["open_endpoints"][0]["path"] == "/x"

    def test_error(self, client: TestClient):
        async def fake(url, timeout=10, concurrency=10):
            raise RuntimeError("boom")
        with patch("main.api_scan", side_effect=fake):
            r = client.get("/api/apiscan?url=https://x")
        assert r.status_code == 502


class TestHeadersScanApi:
    def test_bad_scheme(self, client: TestClient):
        r = client.get("/api/headers/scan?url=ftp://x")
        assert r.status_code == 422

    def test_success(self, client: TestClient):
        report = SimpleNamespace(final_url="https://x", status_code=200, score=90, grade="A")
        async def fake(url, timeout=10):
            return report
        with (
            patch("main.headers_scan", side_effect=fake),
            patch("main.report_to_mirv_findings", return_value=[{"id": "f1"}]),
        ):
            r = client.get("/api/headers/scan?url=https://x&timeout=3")
        assert r.status_code == 200
        assert r.json()["grade"] == "A"
        assert len(r.json()["findings"]) == 1

    def test_error(self, client: TestClient):
        async def fake(url, timeout=10):
            raise RuntimeError("boom")
        with patch("main.headers_scan", side_effect=fake):
            r = client.get("/api/headers/scan?url=https://x")
        assert r.status_code == 502


class TestAiLocalNoChoices:
    def test_local_llm_no_choices(self):
        data = b'{"choices": []}'
        resp = MagicMock()
        resp.__enter__.return_value.read.return_value = data
        with patch("main.urllib.request.urlopen", return_value=resp):
            out = main._call_llm_sync(
                "local", "", "llama3", [{"role": "user", "content": "hi"}], 5
            )
        assert "choices" in out
        assert "'choices': []" in out


class TestRedactPatternsError:
    def test_patterns_error(self, client: TestClient):
        with patch("main.REDACT_PATTERNS", SimpleNamespace(not_iterable=True)):
            r = client.get("/api/redact/patterns")
        assert r.status_code == 500


class TestStartupHandler:
    def _call(self):
        return asyncio.run(main._record_startup())

    def test_al_init_failure(self):
        with (
            patch("main.al_init", side_effect=RuntimeError("boom")),
            patch("main.pm_start_watch", return_value=None),
            patch("main.al_audit", return_value={"ok": True}),
        ):
            self._call()

    def test_dev_mode(self):
        with (
            patch("main.PRODUCTION", False),
            patch("main.al_init", return_value=None),
            patch("main.pm_start_watch", return_value=None),
            patch("main.al_audit", return_value={"ok": True}),
        ):
            self._call()

    def test_watcher_failure(self):
        with (
            patch("main.al_init", return_value=None),
            patch("main.pm_start_watch", side_effect=RuntimeError("boom")),
            patch("main.al_audit", return_value={"ok": True}),
        ):
            self._call()


class TestShutdownHandler:
    def test_shutdown_stop_error(self):
        with patch("main.pm_stop_watch", side_effect=RuntimeError("boom")):
            asyncio.run(main._stop_plugin_watcher())


class TestDockerHelpers:
    def test_docker_compose_not_installed(self):
        with patch("main.asyncio.create_subprocess_exec", side_effect=FileNotFoundError):
            res = asyncio.run(main._docker_compose("ps"))
        assert res["exit"] == -1
        assert res["stderr"] == "Docker not installed"

    def test_docker_compose_timeout(self):
        async def fake_create(*args, **kwargs):
            return MagicMock()
        with (
            patch("main.asyncio.create_subprocess_exec", side_effect=fake_create),
            patch("main.asyncio.wait_for", side_effect=asyncio.TimeoutError),
        ):
            res = asyncio.run(main._docker_compose("ps", timeout=1))
        assert res["exit"] == -2
        assert "Timeout" in res["stderr"]

    def test_docker_status_empty_lines(self, client: TestClient):
        with patch("main._run_docker_cmd", return_value={"ok": True, "stdout": "\n\n", "stderr": ""}):
            r = client.get("/api/docker/status")
        assert r.status_code == 200
        assert r.json()["containers"] == []


class TestReportGenerate:
    def test_generate_with_detail_and_save(self, client: TestClient):
        findings = [
            {
                "severity": "high", "tool": "nmap", "target": "example.com",
                "title": "Open port", "detail": "Port 22 open", "port": "22", "path": "/x",
            }
        ]
        with patch("main.db.save_report", return_value={"id": "r1"}):
            r = client.post("/api/report/generate", json={
                "target": "example.com", "title": "T", "findings": findings,
            })
        assert r.status_code == 201
        assert r.json()["data"]["id"] == "r1"


class TestPdfProfessionalObjects:
    def test_sections_and_findings_as_objects(self):
        req = main.PdfProfessionalRequest(title="Report", target="example.com")
        req.sections = [SimpleNamespace(heading="Intro", content="Hello")]
        req.findings = [SimpleNamespace(
            title="SQLi", severity="critical", detail="d", target="example.com",
            tool="sqlmap", recommendation="r", references=[],
        )]
        resp = asyncio.run(main.generate_pdf_professional(req))
        assert resp.status_code == 200


class TestSwarmList:
    def test_list(self):
        with patch("main.list_sessions", return_value=[{"id": "s1"}]):
            resp = asyncio.run(main.swarm_list())
        assert resp.status_code == 200
        assert _body(resp)["data"] == [{"id": "s1"}]


class TestMobileApi:
    def test_upload_not_apk(self, client: TestClient):
        r = client.post("/api/mobile/upload", files={"file": ("x.txt", b"hello", "text/plain")})
        assert r.status_code == 400

    def test_upload_too_large(self):
        from unittest.mock import AsyncMock as _AsyncMock
        async def fake_read():
            return b"x" * (200 * 1024 * 1024 + 1)
        fake_file = SimpleNamespace(filename="a.apk", read=fake_read)
        resp = asyncio.run(main.mobile_upload(fake_file))
        assert resp.status_code == 400

    def test_upload_write_error(self):
        async def fake_read():
            return b"x"
        fake_file = SimpleNamespace(filename="a.apk", read=fake_read)
        with patch("builtins.open", side_effect=OSError("disk full")):
            resp = asyncio.run(main.mobile_upload(fake_file))
        assert resp.status_code == 500
        assert "Upload failed" in _body(resp)["error"]

    def test_upload_analysis_error(self):
        async def fake_read():
            return b"x"
        fake_file = SimpleNamespace(filename="a.apk", read=fake_read)
        with (
            patch("main._ensure_ssh_connection", AsyncMock()),
            patch("main.mobile_analyze_apk", side_effect=RuntimeError("boom")),
        ):
            resp = asyncio.run(main.mobile_upload(fake_file))
        assert resp.status_code == 500
        assert "Analysis failed" in _body(resp)["error"]

    def test_upload_db_save_error(self):
        async def fake_read():
            return b"x"
        fake_file = SimpleNamespace(filename="a.apk", read=fake_read)
        with (
            patch("main._ensure_ssh_connection", AsyncMock()),
            patch("main.mobile_analyze_apk", return_value={"package": "p", "findings": []}),
            patch("main.db.save_mobile_apk", side_effect=RuntimeError("boom")),
        ):
            resp = asyncio.run(main.mobile_upload(fake_file))
        assert resp.status_code == 200
        assert _body(resp)["data"]["package"] == "p"

    def test_delete_cleans_upload(self, client: TestClient):
        with (
            patch("main.mobile_delete_apk", return_value=True),
            patch("main.os.listdir", return_value=["apk1.apk", "other.apk"]),
            patch("main.os.remove") as rm,
        ):
            r = client.delete("/api/mobile/apks/apk1")
        assert r.status_code == 200
        rm.assert_called_once()
        assert "apk1.apk" in str(rm.call_args[0][0])

    def test_delete_cleans_upload_oserror(self, client: TestClient):
        with (
            patch("main.mobile_delete_apk", return_value=True),
            patch("main.os.listdir", return_value=["apk1.apk"]),
            patch("main.os.remove", side_effect=OSError("busy")),
        ):
            r = client.delete("/api/mobile/apks/apk1")
        assert r.status_code == 200

    def test_delete_not_found(self, client: TestClient):
        with (
            patch("main.mobile_delete_apk", return_value=False),
            patch("main.os.listdir", return_value=[]),
        ):
            r = client.delete("/api/mobile/apks/nope")
        assert r.status_code == 404


class TestPermissionsApi:
    def test_pending_success(self, client: TestClient):
        with patch("main.sg_pending", return_value=[{"id": "p1"}]):
            r = client.get("/api/permissions/pending")
        assert r.status_code == 200
        assert r.json()["count"] == 1

    def test_pending_error(self, client: TestClient):
        with patch("main.sg_pending", side_effect=RuntimeError("boom")):
            r = client.get("/api/permissions/pending")
        assert r.status_code == 500

    def test_get_one_success(self, client: TestClient):
        with patch("main.sg_get_req", return_value={"id": "p1"}):
            r = client.get("/api/permissions/p1")
        assert r.status_code == 200
        assert r.json()["request"]["id"] == "p1"

    def test_get_one_not_found(self, client: TestClient):
        with patch("main.sg_get_req", return_value=None):
            r = client.get("/api/permissions/nope")
        assert r.status_code == 404

    def test_get_one_error(self, client: TestClient):
        with patch("main.sg_get_req", side_effect=RuntimeError("boom")):
            r = client.get("/api/permissions/p1")
        assert r.status_code == 500

    def test_decide_success(self, client: TestClient):
        with patch("main.sg_decide", return_value={"ok": True, "status": "approved"}):
            r = client.post("/api/permissions/p1/decide", json={"decision": "approve"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_decide_error_result(self, client: TestClient):
        with patch("main.sg_decide", return_value={"ok": False, "error": "nope"}):
            r = client.post("/api/permissions/p1/decide", json={"decision": "deny"})
        assert r.status_code == 400

    def test_decide_exception(self, client: TestClient):
        with patch("main.sg_decide", side_effect=RuntimeError("boom")):
            r = client.post("/api/permissions/p1/decide", json={"decision": "approve"})
        assert r.status_code == 500

    def test_classify_with_cache(self, client: TestClient):
        with (
            patch("main.sg_classify", return_value={"cache_key": "k1", "summary": "s"}),
            patch("main.sg_check_cache", return_value={"decision": "allow"}),
        ):
            r = client.post("/api/permissions/classify", json={"command": "ls"})
        assert r.status_code == 200
        assert r.json()["cached"] == {"decision": "allow"}

    def test_classify_no_cache(self, client: TestClient):
        with patch("main.sg_classify", return_value={"summary": "s"}):
            r = client.post("/api/permissions/classify", json={"command": "ls"})
        assert r.status_code == 200
        assert r.json()["cached"] is None

    def test_classify_error(self, client: TestClient):
        with patch("main.sg_classify", side_effect=RuntimeError("boom")):
            r = client.post("/api/permissions/classify", json={"command": "ls"})
        assert r.status_code == 500

    def test_request_autoclassify(self, client: TestClient):
        with (
            patch("main.sg_classify", return_value={"summary": "s", "detail": "d", "cache_key": "k"}),
            patch("main.sg_req_perm", return_value=FakePermission()) as rp,
        ):
            r = client.post("/api/permissions/request", json={"command": "nmap -sV x"})
        assert r.status_code == 200
        assert r.json()["request"]["id"] == "p1"
        rp.assert_called_once()

    def test_request_autoclassify_fallback_serialize(self, client: TestClient):
        with (
            patch("main.sg_classify", return_value={"summary": "s", "detail": "d"}),
            patch("main.sg_req_perm", return_value=SimpleNamespace(
                id="p2", tool="shell", command="ls", status="pending"
            )),
        ):
            r = client.post("/api/permissions/request", json={"command": "ls"})
        assert r.status_code == 200
        assert r.json()["request"]["id"] == "p2"

    def test_request_with_summary(self, client: TestClient):
        with (
            patch("main.sg_req_perm", return_value=FakePermission()) as rp,
        ):
            r = client.post("/api/permissions/request", json={
                "command": "ls", "summary": "mine", "detail": "mine", "cache_key": "ck",
            })
        assert r.status_code == 200
        rp.assert_called_once()

    def test_request_empty_command(self, client: TestClient):
        r = client.post("/api/permissions/request", json={"command": "   "})
        assert r.status_code == 400

    def test_request_error(self, client: TestClient):
        with patch("main.sg_req_perm", side_effect=RuntimeError("boom")):
            r = client.post("/api/permissions/request", json={"command": "ls"})
        assert r.status_code == 500

    def test_clear_all_success(self, client: TestClient):
        with patch("main.sg_clear_dec", return_value=None):
            r = client.delete("/api/permissions")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_clear_all_error(self, client: TestClient):
        with patch("main.sg_clear_dec", side_effect=RuntimeError("boom")):
            r = client.delete("/api/permissions")
        assert r.status_code == 500

    def test_cleanup_success(self, client: TestClient):
        with patch("main.sg_cleanup", return_value=3):
            r = client.post("/api/permissions/cleanup")
        assert r.status_code == 200
        assert r.json()["expired"] == 3

    def test_cleanup_error(self, client: TestClient):
        with patch("main.sg_cleanup", side_effect=RuntimeError("boom")):
            r = client.post("/api/permissions/cleanup")
        assert r.status_code == 500


class TestCredentialsApi:
    def test_list_fallback(self, client: TestClient):
        with patch("main.db.list_credentials", return_value=None):
            r = client.get("/api/credentials?target=x&service=y")
        assert r.status_code == 200
        assert r.json()["fallback"] is True
        assert r.json()["data"] == []

    def test_list_success(self, client: TestClient):
        with patch("main.db.list_credentials", return_value=[{"id": "c1"}]):
            r = client.get("/api/credentials")
        assert r.status_code == 200
        assert r.json()["data"] == [{"id": "c1"}]

    def test_create_db_missing(self, client: TestClient):
        with patch("main.db.save_credential", return_value=None):
            r = client.post("/api/credentials", json={"target": "x", "username": "u"})
        assert r.status_code == 503

    def test_create_success(self, client: TestClient):
        with patch("main.db.save_credential", return_value={"id": "c1"}):
            r = client.post("/api/credentials", json={"target": "x", "username": "u"})
        assert r.status_code == 201

    def test_delete_db_missing(self, client: TestClient):
        with patch("main.db.delete_credential", return_value=None):
            r = client.delete("/api/credentials/c1")
        assert r.status_code == 503

    def test_delete_success(self, client: TestClient):
        with patch("main.db.delete_credential", return_value=True):
            r = client.delete("/api/credentials/c1")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_clear_db_missing(self, client: TestClient):
        with patch("main.db.delete_all_credentials", return_value=None):
            r = client.delete("/api/credentials")
        assert r.status_code == 503

    def test_clear_success(self, client: TestClient):
        with patch("main.db.delete_all_credentials", return_value=True):
            r = client.delete("/api/credentials")
        assert r.status_code == 200
        assert r.json()["ok"] is True


class TestForensicsUploadApi:
    def test_no_filename(self):
        resp = asyncio.run(main.forensics_upload(SimpleNamespace(filename=None), "file"))
        assert resp.status_code == 400

    def test_too_large(self):
        fake = SimpleNamespace(filename="big.bin", read=AsyncMock(return_value=_HugeBytes()))
        resp = asyncio.run(main.forensics_upload(fake, "file"))
        assert resp.status_code == 400

    def test_write_error(self):
        fake = SimpleNamespace(filename="a.bin", read=AsyncMock(return_value=b"x" * 8))
        with patch("builtins.open", side_effect=OSError("disk full")):
            resp = asyncio.run(main.forensics_upload(fake, "file"))
        assert resp.status_code == 500

    def test_db_save_error_degrades(self):
        fake = SimpleNamespace(filename="a.bin", read=AsyncMock(return_value=b"x" * 8))
        result = {
            "file_type": "bin", "size": 8, "md5": "m", "sha256": "s",
            "findings": [], "summary": {},
        }
        with (
            patch("builtins.open", return_value=io.BytesIO()),
            patch("main.forensics_analyze", return_value=result),
            patch("main.db.save_forensics_evidence", side_effect=RuntimeError("db down")),
        ):
            resp = asyncio.run(main.forensics_upload(fake, "file"))
        assert resp.status_code == 200
        assert _body(resp)["ok"] is True


class TestForensicsRunApi:
    def test_run_tool_fallback_path(self):
        with (
            patch("main.forensics_get", return_value={"filename": "disk.img"}),
            patch("main.os.path.exists", return_value=False),
            patch("main.os.listdir", return_value=["ev1_capture.raw"]),
            patch("main.forensics_run_tool", return_value={"ok": True, "tool": "strings"}),
        ):
            resp = asyncio.run(main.forensics_run_tool_endpoint("ev1", {"tool": "strings"}))
        assert resp.status_code == 200
        assert _body(resp)["ok"] is True

    def test_delete_db_error_degrades(self, client: TestClient):
        with (
            patch("main.db.delete_forensics_evidence", side_effect=RuntimeError("db down")),
            patch("main.forensics_delete", return_value=True),
            patch("main.os.listdir", return_value=[]),
        ):
            r = client.delete("/api/forensics/ev1")
        assert r.status_code == 200
        assert r.json()["ok"] is True


class TestMissionsApiGaps:
    def test_list_fallback(self, client: TestClient):
        with patch("main.list_missions", return_value=None):
            r = client.get("/api/missions")
        assert r.status_code == 200
        assert r.json()["fallback"] is True

    def test_list_error(self, client: TestClient):
        with patch("main.list_missions", side_effect=RuntimeError("boom")):
            r = client.get("/api/missions")
        assert r.status_code == 500

    def test_compact_error(self, client: TestClient):
        with patch("main.ms_compact", side_effect=RuntimeError("boom")):
            r = client.post("/api/missions/m1/compact")
        assert r.status_code == 500

    def test_memory_error(self, client: TestClient):
        with patch("main.ms_memory", side_effect=RuntimeError("boom")):
            r = client.get("/api/missions/m1/memory")
        assert r.status_code == 500

    def test_memory_render_error(self, client: TestClient):
        with patch("main.ms_render_memory", side_effect=RuntimeError("boom")):
            r = client.get("/api/missions/m1/memory/render")
        assert r.status_code == 500

    def test_compact_all_empty(self, client: TestClient):
        with patch("main.list_missions", return_value=[]):
            r = client.post("/api/missions/compact-all")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_compact_all_skips_missing_id(self, client: TestClient):
        with patch("main.list_missions", return_value=[{"foo": "bar"}]):
            r = client.post("/api/missions/compact-all")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_compact_all_skips_autocompact_error(self, client: TestClient):
        with (
            patch("main.list_missions", return_value=[{"id": "m1"}]),
            patch("main.ms_autocompact", side_effect=RuntimeError("boom")),
        ):
            r = client.post("/api/missions/compact-all")
        assert r.status_code == 200
        assert r.json()["count"] == 0

    def test_compact_all_error(self, client: TestClient):
        with patch("main.list_missions", side_effect=RuntimeError("boom")):
            r = client.post("/api/missions/compact-all")
        assert r.status_code == 500

    def test_compact_count_error(self, client: TestClient):
        with patch("main.ms_count_compact", side_effect=RuntimeError("boom")):
            r = client.get("/api/missions/compact/count")
        assert r.status_code == 500


class TestCoverageErrorApi:
    def test_mark_error(self, client: TestClient):
        with patch("main.cov_mark", side_effect=RuntimeError("boom")):
            r = client.post("/api/coverage/mark", json={
                "endpoint": "/x", "param": "p", "vuln_class": "sqli", "status": "tested",
            })
        assert r.status_code == 500

    def test_list_error(self, client: TestClient):
        with patch("main.cov_list", side_effect=RuntimeError("boom")):
            r = client.get("/api/coverage/list")
        assert r.status_code == 500

    def test_summary_error(self, client: TestClient):
        with patch("main.cov_summary", side_effect=RuntimeError("boom")):
            r = client.get("/api/coverage/summary")
        assert r.status_code == 500

    def test_untested_error(self, client: TestClient):
        with patch("main.cov_untested", side_effect=RuntimeError("boom")):
            r = client.get("/api/coverage/untested")
        assert r.status_code == 500

    def test_next_error(self, client: TestClient):
        with patch("main.cov_next", side_effect=RuntimeError("boom")):
            r = client.get("/api/coverage/next")
        assert r.status_code == 500

    def test_clear_error(self, client: TestClient):
        with patch("main.cov_clear", side_effect=RuntimeError("boom")):
            r = client.delete("/api/coverage")
        assert r.status_code == 500

    def test_save_session_error(self, client: TestClient):
        with patch("main.cov_save_session", side_effect=RuntimeError("boom")):
            r = client.post("/api/coverage/sessions", json={"session_id": "s1"})
        assert r.status_code == 500

    def test_sessions_error(self, client: TestClient):
        with patch("main.cov_sessions", side_effect=RuntimeError("boom")):
            r = client.get("/api/coverage/sessions")
        assert r.status_code == 500

    def test_export_error(self, client: TestClient):
        with patch("main.cov_export", side_effect=RuntimeError("boom")):
            r = client.get("/api/coverage/export")
        assert r.status_code == 500


class TestBurpBridgeApi:
    INGEST = {
        "method": "GET", "url": "http://target.test/x",
        "headers": {"Host": "target.test"}, "body": None,
        "response_status": 200, "response_headers": {}, "response_body": "ok",
        "source": "burp",
    }
    CAPTURED = {
        "id": "r1", "method": "GET", "url": "http://target.test/x", "path": "/x",
        "headers": {"Host": "target.test"}, "body": None,
        "response_status": 200, "response_headers": {}, "response_body": "ok",
        "source": "burp", "received_at": "2026-01-01T00:00:00Z",
    }

    def test_ingest_bad_token(self, client: TestClient):
        with patch("main.bb_verify_token", return_value=False):
            r = client.post("/api/burp/ingest", json=self.INGEST)
        assert r.status_code == 401

    def test_ingest_success(self, client: TestClient):
        with (
            patch("main.bb_verify_token", return_value=True),
            patch("main.bb_ingest", return_value={"ok": True, "id": "r1"}),
        ):
            r = client.post("/api/burp/ingest", json=self.INGEST)
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_ingest_error(self, client: TestClient):
        with (
            patch("main.bb_verify_token", return_value=True),
            patch("main.bb_ingest", side_effect=RuntimeError("boom")),
        ):
            r = client.post("/api/burp/ingest", json=self.INGEST)
        assert r.status_code == 500

    def test_requests_success(self, client: TestClient):
        with patch("main.bb_list", return_value=[self.CAPTURED]):
            r = client.get("/api/burp/requests")
        assert r.status_code == 200
        assert len(r.json()["requests"]) == 1

    def test_requests_error(self, client: TestClient):
        with patch("main.bb_list", side_effect=RuntimeError("boom")):
            r = client.get("/api/burp/requests")
        assert r.status_code == 500

    def test_request_get_success(self, client: TestClient):
        with patch("main.bb_get", return_value=self.CAPTURED):
            r = client.get("/api/burp/requests/r1")
        assert r.status_code == 200

    def test_request_get_not_found(self, client: TestClient):
        with patch("main.bb_get", return_value=None):
            r = client.get("/api/burp/requests/r1")
        assert r.status_code == 404

    def test_request_get_error(self, client: TestClient):
        with patch("main.bb_get", side_effect=RuntimeError("boom")):
            r = client.get("/api/burp/requests/r1")
        assert r.status_code == 500

    def test_endpoints_success(self, client: TestClient):
        with patch("main.bb_endpoints", return_value=[{"path": "/x"}]):
            r = client.get("/api/burp/endpoints")
        assert r.status_code == 200

    def test_endpoints_error(self, client: TestClient):
        with patch("main.bb_endpoints", side_effect=RuntimeError("boom")):
            r = client.get("/api/burp/endpoints")
        assert r.status_code == 500

    def test_create_task_success(self, client: TestClient):
        with patch("main.bb_task", return_value={"ok": True, "task_id": "t1"}):
            r = client.post("/api/burp/tasks", json={"request_id": "r1"})
        assert r.status_code == 200

    def test_create_task_not_ok(self, client: TestClient):
        with patch("main.bb_task", return_value={"ok": False}):
            r = client.post("/api/burp/tasks", json={"request_id": "r1"})
        assert r.status_code == 404

    def test_create_task_error(self, client: TestClient):
        with patch("main.bb_task", side_effect=RuntimeError("boom")):
            r = client.post("/api/burp/tasks", json={"request_id": "r1"})
        assert r.status_code == 500

    def test_tasks_success(self, client: TestClient):
        with patch("main.bb_tasks", return_value=[{"id": "t1"}]):
            r = client.get("/api/burp/tasks")
        assert r.status_code == 200

    def test_tasks_error(self, client: TestClient):
        with patch("main.bb_tasks", side_effect=RuntimeError("boom")):
            r = client.get("/api/burp/tasks")
        assert r.status_code == 500

    def test_patch_task_success(self, client: TestClient):
        with patch("main.bb_update_task", return_value={"ok": True}):
            r = client.patch("/api/burp/tasks/t1", json={"status": "done"})
        assert r.status_code == 200

    def test_patch_task_not_ok(self, client: TestClient):
        with patch("main.bb_update_task", return_value={"ok": False}):
            r = client.patch("/api/burp/tasks/t1", json={"status": "done"})
        assert r.status_code == 404

    def test_patch_task_error(self, client: TestClient):
        with patch("main.bb_update_task", side_effect=RuntimeError("boom")):
            r = client.patch("/api/burp/tasks/t1", json={"status": "done"})
        assert r.status_code == 500

    def test_create_issue_success(self, client: TestClient):
        with patch("main.bb_issue", return_value={"ok": True, "issue_id": "i1"}):
            r = client.post("/api/burp/issues", json={"title": "t", "url": "http://x/"})
        assert r.status_code == 200

    def test_create_issue_not_ok(self, client: TestClient):
        with patch("main.bb_issue", return_value={"ok": False}):
            r = client.post("/api/burp/issues", json={"title": "t", "url": "http://x/"})
        assert r.status_code == 400

    def test_create_issue_error(self, client: TestClient):
        with patch("main.bb_issue", side_effect=RuntimeError("boom")):
            r = client.post("/api/burp/issues", json={"title": "t", "url": "http://x/"})
        assert r.status_code == 500

    def test_list_issues_success(self, client: TestClient):
        with patch("main.bb_issues", return_value=[{"id": "i1"}]):
            r = client.get("/api/burp/issues")
        assert r.status_code == 200

    def test_list_issues_error(self, client: TestClient):
        with patch("main.bb_issues", side_effect=RuntimeError("boom")):
            r = client.get("/api/burp/issues")
        assert r.status_code == 500

    def test_finding_to_issue_bad_json(self, client: TestClient):
        r = client.post("/api/burp/finding-to-issue", content="{bad", headers={"content-type": "application/json"})
        assert r.status_code == 400

    def test_finding_to_issue_success(self, client: TestClient):
        with patch("main.bb_to_issue", return_value={"ok": True, "issue": {}}):
            r = client.post("/api/burp/finding-to-issue", json={"title": "t"})
        assert r.status_code == 200

    def test_finding_to_issue_error(self, client: TestClient):
        with patch("main.bb_to_issue", side_effect=RuntimeError("boom")):
            r = client.post("/api/burp/finding-to-issue", json={"title": "t"})
        assert r.status_code == 500

    def test_raw_success(self, client: TestClient):
        with (
            patch("main.bb_get", return_value=self.CAPTURED),
            patch("main.bb_raw", return_value="GET /x HTTP/1.1\r\n\r\n"),
        ):
            r = client.post("/api/burp/raw", json={"request_id": "r1"})
        assert r.status_code == 200
        assert r.json()["raw"].startswith("GET")

    def test_raw_not_found(self, client: TestClient):
        with patch("main.bb_get", return_value=None):
            r = client.post("/api/burp/raw", json={"request_id": "r1"})
        assert r.status_code == 404

    def test_raw_error(self, client: TestClient):
        with patch("main.bb_get", side_effect=RuntimeError("boom")):
            r = client.post("/api/burp/raw", json={"request_id": "r1"})
        assert r.status_code == 500

    def test_export_bad_json(self, client: TestClient):
        r = client.post("/api/burp/export-findings", content="{bad", headers={"content-type": "application/json"})
        assert r.status_code == 400

    def test_export_list_success(self, client: TestClient):
        with patch("main.bb_export", return_value={"ok": True, "created": 1}):
            r = client.post("/api/burp/export-findings", json=[{"title": "t"}])
        assert r.status_code == 200

    def test_export_dict_success(self, client: TestClient):
        with patch("main.bb_export", return_value={"ok": True, "created": 1}):
            r = client.post("/api/burp/export-findings", json={"findings": [{"title": "t"}]})
        assert r.status_code == 200

    def test_export_error(self, client: TestClient):
        with patch("main.bb_export", side_effect=RuntimeError("boom")):
            r = client.post("/api/burp/export-findings", json=[{"title": "t"}])
        assert r.status_code == 500

    def test_snapshot_success(self, client: TestClient):
        with patch("main.bb_snapshot", return_value={"ok": True}):
            r = client.post("/api/burp/snapshot", json={"page_url": "http://x/"})
        assert r.status_code == 200

    def test_snapshot_error(self, client: TestClient):
        with patch("main.bb_snapshot", side_effect=RuntimeError("boom")):
            r = client.post("/api/burp/snapshot", json={"page_url": "http://x/"})
        assert r.status_code == 500

    def test_clear_success(self, client: TestClient):
        with patch("main.bb_clear", return_value={"ok": True}):
            r = client.delete("/api/burp/clear")
        assert r.status_code == 200

    def test_clear_error(self, client: TestClient):
        with patch("main.bb_clear", side_effect=RuntimeError("boom")):
            r = client.delete("/api/burp/clear")
        assert r.status_code == 500

    def test_status_success(self, client: TestClient):
        with patch("main.bb_status", return_value={"requests": 1}):
            r = client.get("/api/burp/status")
        assert r.status_code == 200

    def test_status_error(self, client: TestClient):
        with patch("main.bb_status", side_effect=RuntimeError("boom")):
            r = client.get("/api/burp/status")
        assert r.status_code == 500


class TestPocApi:
    def test_build_invalid_url(self, client: TestClient):
        with patch("main.poc_validate_url", return_value=False):
            r = client.post("/api/poc/build", json={"url": "http://x/"})
        assert r.status_code == 400

    def test_build_success(self, client: TestClient):
        with (
            patch("main.poc_validate_url", return_value=True),
            patch("main.poc_build", return_value=_fake_poc()),
        ):
            r = client.post("/api/poc/build", json={"url": "http://x/", "method": "GET"})
        assert r.status_code == 200
        assert r.json()["poc"]["finding_id"] == "f1"

    def test_build_error(self, client: TestClient):
        with (
            patch("main.poc_validate_url", return_value=True),
            patch("main.poc_build", side_effect=RuntimeError("boom")),
        ):
            r = client.post("/api/poc/build", json={"url": "http://x/"})
        assert r.status_code == 500

    def test_replay_missing(self, client: TestClient):
        r = client.post("/api/poc/replay", json={"timeout": 5})
        assert r.status_code == 400

    def test_replay_poc_dict(self, client: TestClient):
        with (
            patch("main.poc_from_f", return_value=_fake_poc()),
            patch("main.poc_replay", return_value={"ok": True, "evidence": "e"}),
        ):
            r = client.post("/api/poc/replay", json={"poc": {"method": "GET", "url": "http://x/"}})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_replay_finding(self, client: TestClient):
        with (
            patch("main.poc_from_f", return_value=_fake_poc()),
            patch("main.poc_replay", return_value={"ok": True}),
        ):
            r = client.post("/api/poc/replay", json={"finding": {"title": "t"}})
        assert r.status_code == 200

    def test_replay_error(self, client: TestClient):
        with (
            patch("main.poc_from_f", return_value=_fake_poc()),
            patch("main.poc_replay", side_effect=RuntimeError("boom")),
        ):
            r = client.post("/api/poc/replay", json={"poc": {"method": "GET", "url": "http://x/"}})
        assert r.status_code == 500

    def test_parse_curl_missing(self, client: TestClient):
        r = client.post("/api/poc/parse-curl", json={"curl": ""})
        assert r.status_code == 400

    def test_parse_curl_success(self, client: TestClient):
        with patch("main.poc_parse_curl", return_value=_fake_poc()):
            r = client.post("/api/poc/parse-curl", json={"curl": "curl http://x/"})
        assert r.status_code == 200

    def test_parse_curl_error(self, client: TestClient):
        with patch("main.poc_parse_curl", side_effect=RuntimeError("boom")):
            r = client.post("/api/poc/parse-curl", json={"curl": "curl http://x/"})
        assert r.status_code == 500

    def test_finding_to_md_bad_json(self, client: TestClient):
        r = client.post("/api/poc/finding-to-md", content="{bad", headers={"content-type": "application/json"})
        assert r.status_code == 400

    def test_finding_to_md_success(self, client: TestClient):
        with patch("main.poc_md", return_value="# Report"):
            r = client.post("/api/poc/finding-to-md", json={"title": "t"})
        assert r.status_code == 200
        assert r.json()["markdown"] == "# Report"

    def test_finding_to_md_error(self, client: TestClient):
        with patch("main.poc_md", side_effect=RuntimeError("boom")):
            r = client.post("/api/poc/finding-to-md", json={"title": "t"})
        assert r.status_code == 500

    def test_from_burp_bad_json(self, client: TestClient):
        r = client.post("/api/poc/from-burp", content="{bad", headers={"content-type": "application/json"})
        assert r.status_code == 400

    def test_from_burp_missing_url(self, client: TestClient):
        with patch("main.poc_from_burp", return_value=None):
            r = client.post("/api/poc/from-burp", json={"method": "GET"})
        assert r.status_code == 400

    def test_from_burp_success(self, client: TestClient):
        with patch("main.poc_from_burp", return_value=_fake_poc()):
            r = client.post("/api/poc/from-burp", json={"url": "http://x/"})
        assert r.status_code == 200

    def test_from_burp_error(self, client: TestClient):
        with patch("main.poc_from_burp", side_effect=RuntimeError("boom")):
            r = client.post("/api/poc/from-burp", json={"url": "http://x/"})
        assert r.status_code == 500

    def test_validate_bad_json(self, client: TestClient):
        r = client.post("/api/poc/validate", content="{bad", headers={"content-type": "application/json"})
        assert r.status_code == 400

    def test_validate_ok(self, client: TestClient):
        with (
            patch("main.poc_from_f", return_value=_fake_poc()),
            patch("main.poc_validate", return_value=[]),
        ):
            r = client.post("/api/poc/validate", json={"method": "GET", "url": "http://x/"})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_validate_with_errors(self, client: TestClient):
        with (
            patch("main.poc_from_f", return_value=_fake_poc()),
            patch("main.poc_validate", return_value=["url missing"]),
        ):
            r = client.post("/api/poc/validate", json={"method": "GET", "url": "http://x/"})
        assert r.status_code == 200
        assert r.json()["ok"] is False

    def test_validate_minimal_construction(self, client: TestClient):
        with patch("main.poc_validate", return_value=[]):
            r = client.post("/api/poc/validate", json={})
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_validate_error(self, client: TestClient):
        with patch("main.poc_validate", side_effect=RuntimeError("boom")):
            r = client.post("/api/poc/validate", json={"method": "GET", "url": "http://x/"})
        assert r.status_code == 500


class TestIntelApiGaps:
    def test_create_watch_success(self, client: TestClient):
        with patch("main.intel.create_watch", return_value=FakeIntelWatch()):
            r = client.post("/api/intelligence/watches", json={
                "name": "w", "target": "http://x/", "watch_type": "http_headers",
            })
        assert r.status_code == 200
        assert r.json()["watch"]["id"] == "w1"

    def test_create_watch_valueerror(self, client: TestClient):
        with patch("main.intel.create_watch", side_effect=ValueError("bad type")):
            r = client.post("/api/intelligence/watches", json={
                "name": "w", "target": "http://x/", "watch_type": "nope",
            })
        assert r.status_code == 400

    def test_create_watch_error(self, client: TestClient):
        with patch("main.intel.create_watch", side_effect=RuntimeError("boom")):
            r = client.post("/api/intelligence/watches", json={
                "name": "w", "target": "http://x/", "watch_type": "http_headers",
            })
        assert r.status_code == 500

    def test_list_watches_success(self, client: TestClient):
        with patch("main.intel.list_watches", return_value=[FakeIntelWatch()]):
            r = client.get("/api/intelligence/watches")
        assert r.status_code == 200
        assert len(r.json()["watches"]) == 1

    def test_list_watches_error(self, client: TestClient):
        with patch("main.intel.list_watches", side_effect=RuntimeError("boom")):
            r = client.get("/api/intelligence/watches")
        assert r.status_code == 500

    def test_get_watch_not_found(self, client: TestClient):
        with patch("main.intel.get_watch", return_value=None):
            r = client.get("/api/intelligence/watches/w1")
        assert r.status_code == 404

    def test_get_watch_success(self, client: TestClient):
        with patch("main.intel.get_watch", return_value=FakeIntelWatch()):
            r = client.get("/api/intelligence/watches/w1")
        assert r.status_code == 200

    def test_get_watch_error(self, client: TestClient):
        with patch("main.intel.get_watch", side_effect=RuntimeError("boom")):
            r = client.get("/api/intelligence/watches/w1")
        assert r.status_code == 500

    def test_update_watch_success(self, client: TestClient):
        with patch("main.intel.update_watch", return_value=FakeIntelWatch()):
            r = client.put("/api/intelligence/watches/w1", json={"name": "new"})
        assert r.status_code == 200

    def test_update_watch_not_found(self, client: TestClient):
        with patch("main.intel.update_watch", return_value=None):
            r = client.put("/api/intelligence/watches/w1", json={"name": "new"})
        assert r.status_code == 404

    def test_update_watch_valueerror(self, client: TestClient):
        with patch("main.intel.update_watch", side_effect=ValueError("bad")):
            r = client.put("/api/intelligence/watches/w1", json={"name": "new"})
        assert r.status_code == 400

    def test_update_watch_error(self, client: TestClient):
        with patch("main.intel.update_watch", side_effect=RuntimeError("boom")):
            r = client.put("/api/intelligence/watches/w1", json={"name": "new"})
        assert r.status_code == 500

    def test_delete_watch_not_found(self, client: TestClient):
        with patch("main.intel.delete_watch", return_value=False):
            r = client.delete("/api/intelligence/watches/w1")
        assert r.status_code == 404

    def test_delete_watch_success(self, client: TestClient):
        with patch("main.intel.delete_watch", return_value=True):
            r = client.delete("/api/intelligence/watches/w1")
        assert r.status_code == 200

    def test_delete_watch_error(self, client: TestClient):
        with patch("main.intel.delete_watch", side_effect=RuntimeError("boom")):
            r = client.delete("/api/intelligence/watches/w1")
        assert r.status_code == 500

    def test_capture_snapshot_not_found(self, client: TestClient):
        with patch("main.intel.get_watch", return_value=None):
            r = client.post("/api/intelligence/watches/w1/snapshot", json={"data": {}})
        assert r.status_code == 404

    def test_capture_snapshot_success(self, client: TestClient):
        with (
            patch("main.intel.get_watch", return_value=FakeIntelWatch()),
            patch("main.intel.capture_snapshot", return_value=FakeIntelSnapshot()),
        ):
            r = client.post("/api/intelligence/watches/w1/snapshot", json={"data": {}})
        assert r.status_code == 200
        assert r.json()["snapshot"]["id"] == "s1"

    def test_capture_snapshot_error(self, client: TestClient):
        with (
            patch("main.intel.get_watch", return_value=FakeIntelWatch()),
            patch("main.intel.capture_snapshot", side_effect=RuntimeError("boom")),
        ):
            r = client.post("/api/intelligence/watches/w1/snapshot", json={"data": {}})
        assert r.status_code == 500

    def test_get_snapshots_not_found(self, client: TestClient):
        with patch("main.intel.get_watch", return_value=None):
            r = client.get("/api/intelligence/watches/w1/snapshots")
        assert r.status_code == 404

    def test_get_snapshots_success(self, client: TestClient):
        with (
            patch("main.intel.get_watch", return_value=FakeIntelWatch()),
            patch("main.intel.get_snapshot_history", return_value=[FakeIntelSnapshot()]),
        ):
            r = client.get("/api/intelligence/watches/w1/snapshots")
        assert r.status_code == 200

    def test_get_snapshots_error(self, client: TestClient):
        with (
            patch("main.intel.get_watch", return_value=FakeIntelWatch()),
            patch("main.intel.get_snapshot_history", side_effect=RuntimeError("boom")),
        ):
            r = client.get("/api/intelligence/watches/w1/snapshots")
        assert r.status_code == 500

    def test_list_alerts_success(self, client: TestClient):
        with patch("main.intel.list_alerts", return_value=[FakeIntelAlert()]):
            r = client.get("/api/intelligence/alerts")
        assert r.status_code == 200

    def test_list_alerts_error(self, client: TestClient):
        with patch("main.intel.list_alerts", side_effect=RuntimeError("boom")):
            r = client.get("/api/intelligence/alerts")
        assert r.status_code == 500

    def test_acknowledge_not_found(self, client: TestClient):
        with patch("main.intel.acknowledge_alert", return_value=False):
            r = client.post("/api/intelligence/alerts/a1/acknowledge")
        assert r.status_code == 404

    def test_acknowledge_success(self, client: TestClient):
        with patch("main.intel.acknowledge_alert", return_value=True):
            r = client.post("/api/intelligence/alerts/a1/acknowledge")
        assert r.status_code == 200

    def test_acknowledge_error(self, client: TestClient):
        with patch("main.intel.acknowledge_alert", side_effect=RuntimeError("boom")):
            r = client.post("/api/intelligence/alerts/a1/acknowledge")
        assert r.status_code == 500

    def test_clear_alerts_success(self, client: TestClient):
        with patch("main.intel.clear_alerts", return_value=3):
            r = client.delete("/api/intelligence/alerts")
        assert r.status_code == 200
        assert r.json()["cleared"] == 3

    def test_clear_alerts_error(self, client: TestClient):
        with patch("main.intel.clear_alerts", side_effect=RuntimeError("boom")):
            r = client.delete("/api/intelligence/alerts")
        assert r.status_code == 500


class TestIntelDiffSeverity:
    def test_diff_upgrades_severity(self, client: TestClient):
        diff = DiffResult(
            watch_id="w1", target="http://x/", watch_type="http_headers",
            old_snapshot_id="s0", new_snapshot_id="s1", changed=True,
            changes=[
                {"field": "a", "old_value": "1", "new_value": "2", "severity": "info"},
                {"field": "b", "old_value": "1", "new_value": "2", "severity": "high"},
            ],
            summary="2 changes", detected_at="2026-01-01T00:00:00Z",
        )
        with (
            patch("main.intel.get_watch", return_value=FakeIntelWatch()),
            patch("main.intel.capture_snapshot", return_value=FakeIntelSnapshot()),
            patch("main.intel.get_latest_snapshot", return_value=None),
            patch("main.intel.get_snapshot_history", return_value=[FakeIntelSnapshot()]),
            patch("main.intel.compute_diff", return_value=diff),
            patch("main.intel.create_alert") as ca,
        ):
            r = client.post("/api/intelligence/diff/w1", json={"data": {"headers": {}}})
        assert r.status_code == 200
        assert r.json()["diff"]["new_snapshot_id"] == "s1"
        ca.assert_called_once()
        assert ca.call_args.kwargs["severity"] == "high"


class TestMainGuard:
    def test_guard_runs_dev_and_prod(self):
        import runpy as _runpy

        root = os.path.dirname(os.path.dirname(os.path.abspath(main.__file__)))
        backend_dir = os.path.join(root, "backend")
        main_mod = sys.modules.get("__main__")
        saved_main = dict(main_mod.__dict__) if main_mod else {}

        def _run(argv, cwd_override):
            fake_uv = SimpleNamespace(run=MagicMock())
            patchers = [
                patch.object(sys, "argv", argv),
                patch.dict(sys.modules, {"uvicorn": fake_uv, "dotenv": None}),
                patch.object(sys, "stdout", _FakeStream()),
                patch.object(sys, "stderr", _FakeStream()),
                patch.object(
                    sys, "path",
                    [p for p in sys.path if os.path.normpath(p) != root],
                ),
            ]
            if cwd_override:
                patchers.append(patch("os.getcwd", return_value=cwd_override))
            for p in patchers:
                p.start()
            try:
                _runpy.run_path(os.path.abspath(main.__file__), run_name="__main__")
            finally:
                for p in patchers:
                    p.stop()
            return fake_uv

        try:
            fake_dev = _run(["pytest", "--reload"], backend_dir)
            assert fake_dev.run.call_count >= 1
            fake_prod = _run(["pytest"], None)
            assert fake_prod.run.call_count >= 1
        finally:
            if main_mod:
                main_mod.__dict__.clear()
                main_mod.__dict__.update(saved_main)
