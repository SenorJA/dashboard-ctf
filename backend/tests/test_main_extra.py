"""
tests/test_main_extra.py — Additional main.py endpoint branches.

Covers the success/error paths of the EXIF OSINT upload+URL endpoints, the
SIEM findings conversion endpoint, the audit log CRUD endpoints, the swarm
report endpoint, the Finding PoC validation endpoint, the Continuous
Intelligence diff endpoint, the Docker control endpoints/helpers, and the
professional PDF generator.

Run:
    python -m pytest backend/tests/test_main_extra.py -q
"""

from __future__ import annotations

import asyncio
import io
import json
import os
import sys
import tempfile
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch, mock_open

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from main import (
    app,
    _run_docker_cmd as main_run_docker_cmd,
    _docker_compose as main_docker_compose,
    _docker_task_runner as main_docker_task_runner,
    _http_post_json as main_http_post_json,
    _http_get as main_http_get,
    get_active_ssh_client as main_get_active_ssh_client,
    _ensure_ssh_connection as main_ensure_ssh_connection,
    _check_kali_mcp as main_check_kali_mcp,
    _call_llm_sync as main_call_llm_sync,
)
import urllib.error as main_urlerror
from backend.exif_osint import (
    EXIFResult,
    ImageInfo,
    GPSInfo,
    CameraInfo,
    MetadataInfo,
)
from backend.intelligence import DiffResult
from backend.swarm import SwarmCoordinator
from backend.finding_poc import FindingPoC


@pytest.fixture()
def client():
    with TestClient(app) as c:
        yield c


@pytest.fixture(autouse=True)
def _patch_db_unavailable():
    with patch("backend.database.is_available", return_value=False), \
         patch("backend.database.get_client", return_value=None):
        yield


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _make_exif_result(**overrides) -> EXIFResult:
    """Build a realistic EXIFResult with sane defaults."""
    defaults = dict(
        gps=None,
        camera=CameraInfo(
            make="TestCam", model="X1", lens="50mm", focal_length="50mm",
            fnumber="f/1.8", iso="100", exposure_time="1/250",
            flash="off", software="TestSoft",
        ),
        image=ImageInfo(
            width=800, height=600, format="JPEG", color_space="RGB",
            orientation=1, file_size=4096, has_thumbnail=True,
        ),
        metadata=MetadataInfo(
            datetime_original="2024:01:01 12:00:00",
            datetime_digitized="2024:01:01 12:00:00",
            artist="Tester", copyright="", description="",
            x_resolution="72", y_resolution="72",
        ),
        thumbnail="base64thumb",
        has_exif=True,
        raw_tags={"Make": "TestCam"},
        severity="low",
        geocoding=None,
        duration_seconds=0.1,
        filename="test.jpg",
    )
    defaults.update(overrides)
    return EXIFResult(**defaults)


# ──────────────────────────────────────────────
# /api/exif/analyze  (file upload)
# ──────────────────────────────────────────────

def test_exif_upload_unsupported_content_type(client):
    resp = client.post(
        "/api/exif/analyze",
        files={"file": ("a.gif", io.BytesIO(b"x" * 100), "image/gif")},
    )
    assert resp.status_code == 422
    assert "Unsupported file type" in resp.json()["error"]


def test_exif_upload_file_too_small(client):
    resp = client.post(
        "/api/exif/analyze",
        files={"file": ("small.jpg", io.BytesIO(b"x" * 10), "image/jpeg")},
    )
    assert resp.status_code == 422
    assert "too small" in resp.json()["error"].lower()


def test_exif_upload_file_too_large(client):
    huge = b"x" * (20 * 1024 * 1024 + 1)
    with patch("starlette.datastructures.UploadFile.read",
               new=AsyncMock(return_value=huge)):
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("big.jpg", io.BytesIO(b"y" * 100), "image/jpeg")},
        )
    assert resp.status_code == 422
    assert "20MB" in resp.json()["error"]


def test_exif_upload_success_no_gps(client):
    result = _make_exif_result()
    with patch("main.exif_analyze", AsyncMock(return_value=result)):
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("photo.jpg", io.BytesIO(b"x" * 100), "image/jpeg")},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["filename"] == "photo.jpg"
    assert data["format"] == "JPEG"
    assert data["dimensions"] == "800x600"
    assert data["has_exif"] is True
    assert data["gps"] is None
    assert data["camera"]["make"] == "TestCam"
    assert data["metadata"]["artist"] == "Tester"
    assert data["thumbnail"] == "base64thumb"


def test_exif_upload_success_with_gps(client):
    gps = GPSInfo(
        lat=40.4168, lon=-3.7038, altitude=650, altitude_ref="m",
        gps_timestamp="12:00:00", map_url="https://map.example/1",
        google_maps_url="https://maps.example/1",
    )
    result = _make_exif_result(gps=gps)
    with patch("main.exif_analyze", AsyncMock(return_value=result)), \
         patch("main.exif_reverse_geocode", AsyncMock(return_value={"city": "Madrid"})):
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("gps.jpg", io.BytesIO(b"x" * 100), "image/jpeg")},
        )
    assert resp.status_code == 200
    data = resp.json()
    assert data["gps"]["lat"] == 40.4168
    assert data["gps"]["lon"] == -3.7038
    assert data["geocoding"] == {"city": "Madrid"}


def test_exif_upload_value_error(client):
    with patch("main.exif_analyze", AsyncMock(side_effect=ValueError("corrupt image"))):
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("bad.jpg", io.BytesIO(b"x" * 100), "image/jpeg")},
        )
    assert resp.status_code == 422
    assert resp.json()["ok"] is False


def test_exif_upload_generic_error(client):
    with patch("main.exif_analyze", AsyncMock(side_effect=RuntimeError("boom"))):
        resp = client.post(
            "/api/exif/analyze",
            files={"file": ("bad.jpg", io.BytesIO(b"x" * 100), "image/jpeg")},
        )
    assert resp.status_code == 502
    assert "EXIF analysis failed" in resp.json()["error"]


# ──────────────────────────────────────────────
# /api/exif/analyze  (URL)
# ──────────────────────────────────────────────

def test_exif_url_missing_url(client):
    resp = client.get("/api/exif/analyze")
    assert resp.status_code == 422


def test_exif_url_bad_scheme(client):
    resp = client.get("/api/exif/analyze", params={"url": "ftp://x/img.jpg"})
    assert resp.status_code == 422
    assert "http" in resp.json()["error"].lower()


def test_exif_url_success(client):
    result = _make_exif_result()
    with patch("main.exif_analyze_url", AsyncMock(return_value=result)):
        resp = client.get("/api/exif/analyze", params={"url": "https://example.com/img.jpg"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_exif_url_success_with_gps(client):
    gps = GPSInfo(
        lat=10.0, lon=20.0, altitude=1, altitude_ref="m",
        gps_timestamp="00:00:00", map_url="", google_maps_url="",
    )
    result = _make_exif_result(gps=gps)
    with patch("main.exif_analyze_url", AsyncMock(return_value=result)), \
         patch("main.exif_reverse_geocode", AsyncMock(return_value={"city": "X"})):
        resp = client.get("/api/exif/analyze", params={"url": "https://example.com/g.jpg"})
    assert resp.status_code == 200
    assert resp.json()["gps"]["lat"] == 10.0


def test_exif_url_generic_error(client):
    with patch("main.exif_analyze_url", AsyncMock(side_effect=RuntimeError("boom"))):
        resp = client.get("/api/exif/analyze", params={"url": "https://example.com/g.jpg"})
    assert resp.status_code == 502


# ──────────────────────────────────────────────
# /api/siem/findings
# ──────────────────────────────────────────────

def test_siem_findings_success(client):
    alert = {
        "id": "a1", "rule_name": "port-scan", "rule_id": "r1",
        "severity": "high", "title": "Scan detected", "detail": "d",
        "timestamp": "2024-01-01T00:00:00Z", "event_ids": ["e1"],
        "resolved": False,
    }
    with patch("main.siem_get_alerts", return_value=[alert]), \
         patch("main.siem_to_mirv", return_value=[{"title": "Scan detected", "severity": "high"}]):
        resp = client.get("/api/siem/findings")
    assert resp.status_code == 200
    data = resp.json()
    assert data["ok"] is True
    assert data["count"] == 1
    assert data["findings"][0]["title"] == "Scan detected"


def test_siem_findings_empty(client):
    with patch("main.siem_get_alerts", return_value=[]):
        resp = client.get("/api/siem/findings")
    assert resp.status_code == 200
    assert resp.json()["count"] == 0


def test_siem_findings_error(client):
    with patch("main.siem_get_alerts", side_effect=RuntimeError("boom")):
        resp = client.get("/api/siem/findings")
    assert resp.status_code == 500
    assert resp.json()["ok"] is False


# ──────────────────────────────────────────────
# Audit log endpoints
# ──────────────────────────────────────────────

def test_audit_logs_success(client):
    with patch("main.al_recent", return_value=[{"level": "INFO", "event": "x"}]):
        resp = client.get("/api/audit/logs", params={"limit": 10, "level": "INFO"})
    assert resp.status_code == 200
    assert resp.json()["count"] == 1


def test_audit_logs_error(client):
    with patch("main.al_recent", side_effect=RuntimeError("boom")):
        resp = client.get("/api/audit/logs")
    assert resp.status_code == 500


def test_audit_stats_success(client):
    with patch("main.al_stats", return_value={"total": 5}):
        resp = client.get("/api/audit/stats")
    assert resp.status_code == 200
    assert resp.json()["total"] == 5


def test_audit_stats_error(client):
    with patch("main.al_stats", side_effect=RuntimeError("boom")):
        resp = client.get("/api/audit/stats")
    assert resp.status_code == 500


def test_audit_create_invalid_level(client):
    resp = client.post("/api/audit", json={"level": "NOPE", "event": "x"})
    assert resp.status_code == 422
    assert "Invalid level" in resp.json()["error"]


def test_audit_create_success(client):
    with patch("main.al_audit", return_value={"ok": True, "id": "1"}):
        resp = client.post("/api/audit", json={"level": "WARNING", "event": "scope_change"})
    assert resp.status_code == 200
    assert resp.json()["id"] == "1"


def test_audit_create_audit_failed(client):
    with patch("main.al_audit", return_value={"ok": False, "error": "x"}):
        resp = client.post("/api/audit", json={"level": "INFO"})
    assert resp.status_code == 422


def test_audit_create_error(client):
    with patch("main.al_audit", side_effect=RuntimeError("boom")):
        resp = client.post("/api/audit", json={"level": "INFO"})
    assert resp.status_code == 500


# ──────────────────────────────────────────────
# /api/swarm/{id}/report
# ──────────────────────────────────────────────

def test_swarm_report_not_found(client):
    with patch("main.get_session", return_value=None):
        resp = client.get("/api/swarm/abc/report")
    assert resp.status_code == 404


def test_swarm_report_not_completed(client):
    swarm = SwarmCoordinator(target="example.com", ssh_ip="10.0.0.1",
                             ssh_user="u", ssh_pass="p")
    swarm.status = "running"
    with patch("main.get_session", return_value=swarm):
        resp = client.get(f"/api/swarm/{swarm.session_id}/report")
    assert resp.status_code == 400
    assert "not yet completed" in resp.json()["error"].lower()


def test_swarm_report_db_match(client):
    swarm = SwarmCoordinator(target="example.com", ssh_ip="10.0.0.1",
                             ssh_user="u", ssh_pass="p")
    swarm.status = "completed"
    swarm.add_finding({
        "source": "operator:report", "tool": "report",
        "title": "Report saved ID: abc123", "detail": "full text",
    })
    with patch("main.get_session", return_value=swarm), \
         patch("backend.database.list_reports",
               return_value=[{"type": "swarm", "target": "example.com", "data": "x"}]):
        resp = client.get(f"/api/swarm/{swarm.session_id}/report")
    assert resp.status_code == 200
    assert resp.json()["data"]["data"] == "x"


def test_swarm_report_fallback(client):
    swarm = SwarmCoordinator(target="example.com", ssh_ip="10.0.0.1",
                             ssh_user="u", ssh_pass="p")
    swarm.status = "completed"
    swarm.add_finding({"source": "operator:report", "tool": "nmap",
                       "title": "open ports", "detail": "80/tcp"})
    with patch("main.get_session", return_value=swarm), \
         patch("backend.database.list_reports", return_value=[]):
        resp = client.get(f"/api/swarm/{swarm.session_id}/report")
    assert resp.status_code == 200
    assert resp.json()["data"]["type"] == "swarm"
    assert "completed" in resp.json()["data"]["raw_output"]


def test_swarm_report_fallback_on_db_error(client):
    swarm = SwarmCoordinator(target="example.com", ssh_ip="10.0.0.1",
                             ssh_user="u", ssh_pass="p")
    swarm.status = "completed"
    with patch("main.get_session", return_value=swarm), \
         patch("backend.database.list_reports", side_effect=RuntimeError("db down")):
        resp = client.get(f"/api/swarm/{swarm.session_id}/report")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


# ──────────────────────────────────────────────
# /api/poc/validate
# ──────────────────────────────────────────────

def test_poc_validate_invalid_json(client):
    resp = client.post(
        "/api/poc/validate",
        content="not-json",
        headers={"Content-Type": "application/json"},
    )
    assert resp.status_code == 400
    assert "invalid json" in resp.json()["error"].lower()


def test_poc_validate_empty_dict(client):
    resp = client.post("/api/poc/validate", json={})
    assert resp.status_code == 200
    assert resp.json()["ok"] is False  # minimal PoC has structural errors
    assert isinstance(resp.json()["errors"], list)


def test_poc_validate_valid_poc(client):
    body = {
        "finding_id": "f1", "method": "GET", "url": "https://example.com/",
        "headers": {}, "body": None, "parameter": None, "payload": None,
        "response_status": 200, "response_excerpt": "ok",
        "curl_command": "", "raw_request": "", "remediation": None,
        "impact": "medium", "evidence_hash": "abc",
    }
    resp = client.post("/api/poc/validate", json=body)
    assert resp.status_code == 200
    assert isinstance(resp.json()["errors"], list)


def test_poc_validate_internal_error(client):
    with patch("main.poc_validate", side_effect=RuntimeError("boom")):
        resp = client.post("/api/poc/validate", json={"finding_id": "f1"})
    assert resp.status_code == 500


# ──────────────────────────────────────────────
# /api/intelligence/diff/{id}
# ──────────────────────────────────────────────

def _diff_result(changed: bool):
    return DiffResult(
        watch_id="w1", target="example.com", watch_type="http_headers",
        old_snapshot_id="s1", new_snapshot_id="s2", changed=changed,
        changes=[{"severity": "high", "header": "Server"}] if changed else [],
        summary="Header changed", detected_at="2024-01-01T00:00:00Z",
    )


def test_intel_diff_watch_not_found(client):
    with patch("main.intel.get_watch", return_value=None):
        resp = client.post("/api/intelligence/diff/w1", json={"data": {}})
    assert resp.status_code == 404


def test_intel_diff_success_no_changes(client):
    watch = SimpleNamespace(target="example.com", watch_type="http_headers")
    snap = SimpleNamespace(watch_id="w1", snapshot_id="s2", data={})
    diff = _diff_result(changed=False)
    with patch("main.intel.get_watch", return_value=watch), \
         patch("main.intel.capture_snapshot", return_value=snap), \
         patch("main.intel.get_latest_snapshot", return_value=snap), \
         patch("main.intel.get_snapshot_history", return_value=[snap]), \
         patch("main.intel.compute_diff", return_value=diff), \
         patch("main.intel.create_alert") as create_alert:
        resp = client.post("/api/intelligence/diff/w1", json={"data": {}})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["diff"]["changed"] is False
    create_alert.assert_not_called()


def test_intel_diff_success_with_changes(client):
    watch = SimpleNamespace(target="example.com", watch_type="http_headers")
    snap = SimpleNamespace(watch_id="w1", snapshot_id="s2", data={})
    diff = _diff_result(changed=True)
    with patch("main.intel.get_watch", return_value=watch), \
         patch("main.intel.capture_snapshot", return_value=snap), \
         patch("main.intel.get_latest_snapshot", return_value=snap), \
         patch("main.intel.get_snapshot_history", return_value=[snap]), \
         patch("main.intel.compute_diff", return_value=diff), \
         patch("main.intel.create_alert") as create_alert:
        resp = client.post("/api/intelligence/diff/w1", json={"data": {}})
    assert resp.status_code == 200
    assert resp.json()["diff"]["changed"] is True
    create_alert.assert_called_once()


def test_intel_diff_error(client):
    with patch("main.intel.get_watch", side_effect=RuntimeError("boom")):
        resp = client.post("/api/intelligence/diff/w1", json={"data": {}})
    assert resp.status_code == 500
    assert resp.json()["error"] == "diff failed"


# ──────────────────────────────────────────────
# Docker helpers (_run_docker_cmd / _docker_compose)
# ──────────────────────────────────────────────

class _FakeProc:
    def __init__(self, rc: int, out: bytes = b"", err: bytes = b""):
        self.returncode = rc
        self.communicate = AsyncMock(return_value=(out, err))


def _call_async(coro_factory):
    return asyncio.run(coro_factory())


def test_run_docker_cmd_success():
    proc = _FakeProc(0, b"container1", b"")
    with patch("main.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = _call_async(lambda: main_run_docker_cmd(["docker", "ps"]))
    assert result["ok"] is True
    assert result["stdout"] == "container1"


def test_run_docker_cmd_not_installed():
    with patch("main.asyncio.create_subprocess_exec",
               AsyncMock(side_effect=FileNotFoundError)):
        result = _call_async(lambda: main_run_docker_cmd(["docker", "ps"]))
    assert result["ok"] is False
    assert result["stderr"] == "Docker not installed"


def test_run_docker_cmd_timeout():
    proc = _FakeProc(0)
    proc.communicate = AsyncMock(side_effect=asyncio.TimeoutError)
    with patch("main.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = _call_async(lambda: main_run_docker_cmd(["docker", "ps"], timeout=1))
    assert result["ok"] is False
    assert "Timeout" in result["stderr"]


def test_run_docker_cmd_exception():
    with patch("main.asyncio.create_subprocess_exec",
               AsyncMock(side_effect=PermissionError("denied"))):
        result = _call_async(lambda: main_run_docker_cmd(["docker", "ps"]))
    assert result["ok"] is False
    assert result["exit"] == -3


def test_docker_compose_success():
    proc = _FakeProc(0, b"done", b"")
    with patch("main.asyncio.create_subprocess_exec", AsyncMock(return_value=proc)):
        result = _call_async(lambda: main_docker_compose("up", "-d"))
    assert result["ok"] is True
    assert result["stdout"] == "done"


def test_docker_compose_exception():
    with patch("main.asyncio.create_subprocess_exec",
               AsyncMock(side_effect=OSError("no docker"))):
        result = _call_async(lambda: main_docker_compose("ps"))
    assert result["ok"] is False


# ──────────────────────────────────────────────
# Docker REST endpoints
# ──────────────────────────────────────────────

def test_docker_status_not_installed(client):
    with patch("main._run_docker_cmd", AsyncMock(
            return_value={"ok": False, "exit": -1, "stdout": "", "stderr": "Docker not installed"})):
        resp = client.get("/api/docker/status")
    assert resp.status_code == 200
    assert resp.json()["installed"] is False


def test_docker_status_daemon_down(client):
    with patch("main._run_docker_cmd", AsyncMock(
            return_value={"ok": False, "exit": 1, "stdout": "", "stderr": "cannot connect"})):
        resp = client.get("/api/docker/status")
    assert resp.status_code == 200
    assert resp.json()["installed"] is True
    assert resp.json()["running"] is False


def test_docker_status_containers_running(client):
    payload = json.dumps({"Names": "mirv-kali-tools", "State": "running",
                          "Ports": "22/tcp"}) + "\n"
    payload += json.dumps({"Names": "mirv-backend", "State": "running", "Ports": ""})
    with patch("main._run_docker_cmd", AsyncMock(
            return_value={"ok": True, "exit": 0, "stdout": payload, "stderr": ""})):
        resp = client.get("/api/docker/status")
    assert resp.status_code == 200
    data = resp.json()
    assert data["installed"] is True
    assert data["kali_running"] is True
    assert data["backend_running"] is True
    assert len(data["containers"]) == 2


def test_docker_status_ignores_garbage_lines(client):
    payload = "not-json\n" + json.dumps({"Names": "c1", "State": "exited"})
    with patch("main._run_docker_cmd", AsyncMock(
            return_value={"ok": True, "exit": 0, "stdout": payload, "stderr": ""})):
        resp = client.get("/api/docker/status")
    assert resp.status_code == 200
    assert len(resp.json()["containers"]) == 1


def test_docker_start_success(client):
    with patch("main.os.path.exists", return_value=True), \
         patch("main._docker_compose", AsyncMock(
             return_value={"ok": True, "exit": 0, "stdout": "started", "stderr": ""})):
        resp = client.post("/api/docker/start")
    assert resp.status_code == 200
    assert resp.json()["msg"] == "Kali tools started"


def test_docker_start_compose_file_missing(client):
    with patch("main.os.path.exists", return_value=False):
        resp = client.post("/api/docker/start")
    assert resp.status_code == 404


def test_docker_start_failed(client):
    with patch("main.os.path.exists", return_value=True), \
         patch("main._docker_compose", AsyncMock(
             return_value={"ok": False, "exit": 1, "stdout": "", "stderr": "error"})):
        resp = client.post("/api/docker/start")
    assert resp.status_code == 500
    assert "Start failed" in resp.json()["msg"]


def test_docker_stop_success(client):
    with patch("main._docker_compose", AsyncMock(
            return_value={"ok": True, "exit": 0, "stdout": "", "stderr": ""})):
        resp = client.post("/api/docker/stop")
    assert resp.status_code == 200
    assert resp.json()["msg"] == "Kali tools stopped"


def test_docker_stop_failed(client):
    with patch("main._docker_compose", AsyncMock(
            return_value={"ok": False, "exit": 1, "stdout": "", "stderr": "err"})):
        resp = client.post("/api/docker/stop")
    assert resp.status_code == 500


def test_docker_clean_success(client):
    with patch("main._docker_compose", AsyncMock(
            return_value={"ok": True, "exit": 0, "stdout": "", "stderr": ""})):
        resp = client.post("/api/docker/clean")
    assert resp.status_code == 200
    assert "cleaned" in resp.json()["msg"].lower()


def test_docker_clean_stop_failed(client):
    with patch("main._docker_compose", AsyncMock(
            return_value={"ok": False, "exit": 1, "stdout": "", "stderr": "err"})):
        resp = client.post("/api/docker/clean")
    assert resp.status_code == 500


def test_docker_build_starts_task(client):
    with patch("main.asyncio.create_task") as create_task:
        resp = client.post("/api/docker/build")
    assert resp.status_code == 200
    assert "task_id" in resp.json()
    create_task.assert_called_once()


def test_docker_task_status_found(client):
    main_mod = sys.modules["main"]
    main_mod._docker_tasks["t1"] = {"status": "done", "action": "build"}
    try:
        resp = client.get("/api/docker/task/t1")
    finally:
        main_mod._docker_tasks.pop("t1", None)
    assert resp.status_code == 200
    assert resp.json()["task"]["status"] == "done"


def test_docker_task_status_not_found(client):
    resp = client.get("/api/docker/task/ghost")
    assert resp.status_code == 200
    assert resp.json()["ok"] is False


def test_docker_task_runner_done():
    with patch("main._docker_compose", AsyncMock(
            return_value={"ok": True, "exit": 0, "stdout": "", "stderr": ""})):
        _call_async(lambda: main_docker_task_runner("t", "build", "build"))
    assert sys.modules["main"]._docker_tasks["t"]["status"] == "done"
    sys.modules["main"]._docker_tasks.pop("t", None)


def test_docker_task_runner_failed():
    with patch("main._docker_compose", AsyncMock(
            return_value={"ok": False, "exit": 1, "stdout": "", "stderr": "err"})):
        _call_async(lambda: main_docker_task_runner("t", "build", "build"))
    assert sys.modules["main"]._docker_tasks["t"]["status"] == "failed"
    sys.modules["main"]._docker_tasks.pop("t", None)


def test_docker_task_runner_exception():
    with patch("main._docker_compose", AsyncMock(side_effect=RuntimeError("boom"))):
        _call_async(lambda: main_docker_task_runner("t", "build", "build"))
    assert sys.modules["main"]._docker_tasks["t"]["status"] == "failed"
    assert "boom" in sys.modules["main"]._docker_tasks["t"]["error"]
    sys.modules["main"]._docker_tasks.pop("t", None)


# ──────────────────────────────────────────────
# /api/generate-pdf-professional
# ──────────────────────────────────────────────

def test_pdf_professional_success(client):
    with patch("backend.pdf_engine.PdfEngine") as mock_engine:
        mock_engine.return_value.generate.return_value = b"%PDF-1.4 fake"
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Assessment", "target": "example.com",
            "sections": [{"heading": "Intro", "content": "text"}],
            "findings": [{"title": "XSS", "severity": "high", "detail": "d"}],
        })
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/pdf"
    assert resp.content == b"%PDF-1.4 fake"


def test_pdf_professional_markdown_fallback(client):
    with patch("backend.pdf_engine.PdfEngine") as mock_engine:
        mock_engine.return_value.generate.return_value = b"%PDF-1.4 fake"
        resp = client.post("/api/generate-pdf-professional", json={
            "title": "Assessment",
            "content": "## Section One\nhello\n## Section Two\nworld",
        })
    assert resp.status_code == 200


def test_pdf_professional_import_error(client):
    with patch.dict(sys.modules, {"backend.pdf_engine": SimpleNamespace()}):
        resp = client.post("/api/generate-pdf-professional", json={"title": "T"})
    assert resp.status_code == 500
    assert "reportlab" in resp.json()["error"].lower()


def test_pdf_professional_generic_error(client):
    with patch("backend.pdf_engine.PdfEngine",
               side_effect=RuntimeError("boom")):
        resp = client.post("/api/generate-pdf-professional", json={"title": "T"})
    assert resp.status_code == 500


# ──────────────────────────────────────────────
# POC endpoints (parse-curl / finding-to-md / from-burp)
# ──────────────────────────────────────────────

def _make_poc(**overrides):
    defaults = dict(
        finding_id="f1", method="GET", url="https://example.com/",
        headers={}, body=None, parameter=None, payload=None,
        response_status=200, response_excerpt="ok", curl_command="",
        raw_request="", remediation=None, impact="medium", evidence_hash=None,
    )
    defaults.update(overrides)
    return FindingPoC(**defaults)


def test_poc_parse_curl_missing(client):
    resp = client.post("/api/poc/parse-curl", json={"curl": ""})
    assert resp.status_code == 400
    assert "curl" in resp.json()["error"].lower()


def test_poc_parse_curl_success(client):
    poc = _make_poc(curl_command="curl https://example.com/")
    with patch("main.poc_parse_curl", return_value=poc):
        resp = client.post("/api/poc/parse-curl",
                           json={"curl": "curl https://example.com/"})
    assert resp.status_code == 200
    assert resp.json()["ok"] is True
    assert resp.json()["poc"]["method"] == "GET"


def test_poc_parse_curl_error(client):
    with patch("main.poc_parse_curl", side_effect=RuntimeError("boom")):
        resp = client.post("/api/poc/parse-curl",
                           json={"curl": "curl https://example.com/"})
    assert resp.status_code == 500


def test_poc_md_invalid_json(client):
    resp = client.post("/api/poc/finding-to-md", content="x",
                       headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


def test_poc_md_success(client):
    with patch("main.poc_md", return_value="# Finding\n"):
        resp = client.post("/api/poc/finding-to-md",
                           json={"title": "XSS", "severity": "high"})
    assert resp.status_code == 200
    assert resp.json()["markdown"].startswith("# Finding")


def test_poc_md_error(client):
    with patch("main.poc_md", side_effect=RuntimeError("boom")):
        resp = client.post("/api/poc/finding-to-md", json={})
    assert resp.status_code == 500


def test_poc_from_burp_invalid_json(client):
    resp = client.post("/api/poc/from-burp", content="x",
                       headers={"Content-Type": "application/json"})
    assert resp.status_code == 400


def test_poc_from_burp_success(client):
    poc = _make_poc()
    with patch("main.poc_from_burp", return_value=poc):
        resp = client.post("/api/poc/from-burp", json={"url": "https://example.com/"})
    assert resp.status_code == 200
    assert resp.json()["poc"]["url"] == "https://example.com/"


def test_poc_from_burp_missing_fields(client):
    with patch("main.poc_from_burp", return_value=None):
        resp = client.post("/api/poc/from-burp", json={})
    assert resp.status_code == 400
    assert "missing required fields" in resp.json()["error"].lower()


def test_poc_from_burp_error(client):
    with patch("main.poc_from_burp", side_effect=RuntimeError("boom")):
        resp = client.post("/api/poc/from-burp", json={"url": "x"})
    assert resp.status_code == 500


# ──────────────────────────────────────────────
# Browser Capture endpoints
# ──────────────────────────────────────────────

def test_bc_import_success(client):
    with patch("main.bc_import", return_value={"ok": True, "session": {"id": "s1"}}):
        resp = client.post(
            "/api/browser-capture/import",
            files={"file": ("capture.har", io.BytesIO(b"{}"), "application/json")},
        )
    assert resp.status_code == 200
    assert resp.json()["session"]["id"] == "s1"


def test_bc_import_not_ok(client):
    with patch("main.bc_import", return_value={"ok": False, "error": "bad har"}):
        resp = client.post(
            "/api/browser-capture/import",
            files={"file": ("capture.har", io.BytesIO(b"{}"), "application/json")},
        )
    assert resp.status_code == 400


def test_bc_import_error(client):
    with patch("main.bc_import", side_effect=RuntimeError("boom")):
        resp = client.post(
            "/api/browser-capture/import",
            files={"file": ("capture.har", io.BytesIO(b"{}"), "application/json")},
        )
    assert resp.status_code == 500


def test_bc_sessions(client):
    with patch("main.bc_sessions", return_value=[{"id": "s1"}]):
        resp = client.get("/api/browser-capture/sessions")
    assert resp.status_code == 200
    assert resp.json()["sessions"] == [{"id": "s1"}]


def test_bc_get_session_found(client):
    with patch("main.bc_get_session", return_value={"id": "s1", "name": "x"}):
        resp = client.get("/api/browser-capture/sessions/s1")
    assert resp.status_code == 200
    assert resp.json()["name"] == "x"


def test_bc_get_session_not_found(client):
    with patch("main.bc_get_session", return_value=None):
        resp = client.get("/api/browser-capture/sessions/ghost")
    assert resp.status_code == 404


def test_bc_delete_found(client):
    with patch("main.bc_delete", return_value=True):
        resp = client.delete("/api/browser-capture/sessions/s1")
    assert resp.status_code == 200
    assert resp.json()["ok"] is True


def test_bc_delete_not_found(client):
    with patch("main.bc_delete", return_value=False):
        resp = client.delete("/api/browser-capture/sessions/ghost")
    assert resp.status_code == 404


def test_bc_requests(client):
    with patch("main.bc_requests", return_value=[{"id": 1}]):
        resp = client.get("/api/browser-capture/sessions/s1/requests",
                          params={"method": "GET", "domain": "example.com"})
    assert resp.status_code == 200
    assert resp.json()["requests"] == [{"id": 1}]


def test_bc_analyze_not_found(client):
    with patch("main.bc_analyze", return_value=None):
        resp = client.post("/api/browser-capture/sessions/ghost/analyze")
    assert resp.status_code == 404


def test_bc_analyze_dict(client):
    with patch("main.bc_analyze", return_value={"score": 50}):
        resp = client.post("/api/browser-capture/sessions/s1/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"] == {"score": 50}


def test_bc_analyze_dataclass(client):
    from dataclasses import dataclass, field

    @dataclass
    class _Analysis:
        score: int = 50
        checks: list = field(default_factory=list)

    with patch("main.bc_analyze", return_value=_Analysis()):
        resp = client.post("/api/browser-capture/sessions/s1/analyze")
    assert resp.status_code == 200
    assert resp.json()["analysis"]["score"] == 50


def test_bc_get_analysis_cached_dict(client):
    with patch.dict("backend.browser_capture._analyses", {"s1": {"score": 10}}):
        resp = client.get("/api/browser-capture/sessions/s1/analysis")
    assert resp.status_code == 200
    assert resp.json()["score"] == 10


def test_bc_get_analysis_dataclass(client):
    from dataclasses import dataclass, field

    @dataclass
    class _Analysis:
        score: int = 10
        checks: list = field(default_factory=list)

    with patch.dict("backend.browser_capture._analyses", {"s1": _Analysis()}):
        resp = client.get("/api/browser-capture/sessions/s1/analysis")
    assert resp.status_code == 200
    assert resp.json()["score"] == 10


def test_bc_get_analysis_not_found(client):
    with patch.dict("backend.browser_capture._analyses", {}):
        resp = client.get("/api/browser-capture/sessions/ghost/analysis")
    assert resp.status_code == 404


def test_bc_findings_success(client):
    with patch.dict("backend.browser_capture._sessions", {"s1": {"id": "s1"}}), \
         patch.dict("backend.browser_capture._analyses", {"s1": {"score": 1}}), \
         patch("main.bc_findings", return_value=[{"title": "XSS"}]):
        resp = client.post("/api/browser-capture/sessions/s1/findings")
    assert resp.status_code == 200
    assert resp.json()["count"] == 1


def test_bc_findings_session_missing(client):
    with patch.dict("backend.browser_capture._sessions", {}):
        resp = client.post("/api/browser-capture/sessions/ghost/findings")
    assert resp.status_code == 404


def test_bc_findings_no_analysis(client):
    with patch.dict("backend.browser_capture._sessions", {"s1": {"id": "s1"}}), \
         patch.dict("backend.browser_capture._analyses", {}):
        resp = client.post("/api/browser-capture/sessions/s1/findings")
    assert resp.status_code == 400
    assert "analysis" in resp.json()["error"].lower()


def test_bc_stats_dict_sessions(client):
    with patch.dict("backend.browser_capture._sessions",
                    {"s1": {"request_count": 3, "analysis": {"ok": True}}}), \
         patch.dict("backend.browser_capture._analyses", {}):
        resp = client.get("/api/browser-capture/stats")
    assert resp.status_code == 200
    assert resp.json()["total_sessions"] == 1
    assert resp.json()["total_requests"] == 3
    assert resp.json()["analyzed_sessions"] == 1


def test_bc_stats_object_sessions(client):
    obj = SimpleNamespace(request_count=7, analysis={"ok": True})
    with patch.dict("backend.browser_capture._sessions", {"s1": obj}), \
         patch.dict("backend.browser_capture._analyses", {}):
        resp = client.get("/api/browser-capture/stats")
    assert resp.status_code == 200
    assert resp.json()["total_requests"] == 7
    assert resp.json()["analyzed_sessions"] == 1


# ──────────────────────────────────────────────
# Internal helpers: _http_post_json / _http_get
# ──────────────────────────────────────────────

class _FakeResponse:
    def __init__(self, body: bytes = b"{}", status: int = 200):
        self._body = body
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def read(self):
        return self._body


class _FakeHTTPError(main_urlerror.HTTPError):
    def __init__(self, code: int = 400, body: bytes = b"err"):
        self._body = body
        super().__init__("http://fake", code, "err", {}, None)

    def read(self):
        return self._body


def _urlerror_factory(reason: str):
    return main_urlerror.URLError(reason)


def test_http_post_json_success():
    with patch("main.urllib.request.urlopen", return_value=_FakeResponse(b'{"ok": true}', 200)):
        status, text = main_http_post_json("http://n8n/webhook", {"a": 1})
    assert status == 200
    assert text == '{"ok": true}'


def test_http_post_json_http_error():
    with patch("main.urllib.request.urlopen", side_effect=_FakeHTTPError(422, b"bad")):
        status, text = main_http_post_json("http://n8n/webhook", {})
    assert status == 422
    assert text == "bad"


def test_http_post_json_url_error():
    err = _urlerror_factory("connection refused")
    with patch("main.urllib.request.urlopen", side_effect=err):
        try:
            main_http_post_json("http://n8n/webhook", {})
            raise AssertionError("expected ConnectionError")
        except ConnectionError as e:
            assert "unreachable" in str(e)


def test_http_get_success():
    with patch("main.urllib.request.urlopen", return_value=_FakeResponse(b"", 200)):
        assert main_http_get("http://example.com") == 200


def test_http_get_url_error():
    err = _urlerror_factory("timed out")
    with patch("main.urllib.request.urlopen", side_effect=err):
        assert main_http_get("http://example.com") == 0


# ──────────────────────────────────────────────
# SSH helpers: get_active_ssh_client / _ensure_ssh_connection
# ──────────────────────────────────────────────

def _fake_transport(active: bool):
    return SimpleNamespace(is_active=lambda: active)


def _fake_ssh_client(transport=None, connect_exc=None):
    client = SimpleNamespace()
    client.transport = transport
    client.get_transport = lambda: transport
    client.set_missing_host_key_policy = lambda *a, **kw: None
    if connect_exc:
        def _connect(*a, **kw):
            raise connect_exc
        client.connect = _connect
    else:
        client.connect = lambda *a, **kw: None
    return client


def test_get_active_ssh_client_none():
    saved = sys.modules["main"]._active_ssh_client
    sys.modules["main"]._active_ssh_client = None
    try:
        assert main_get_active_ssh_client() is None
    finally:
        sys.modules["main"]._active_ssh_client = saved


def test_get_active_ssh_client_active():
    client = _fake_ssh_client(transport=_fake_transport(True))
    saved = sys.modules["main"]._active_ssh_client
    sys.modules["main"]._active_ssh_client = client
    try:
        assert main_get_active_ssh_client() is client
    finally:
        sys.modules["main"]._active_ssh_client = saved


def test_get_active_ssh_client_inactive_resets():
    client = _fake_ssh_client(transport=_fake_transport(False))
    saved = sys.modules["main"]._active_ssh_client
    sys.modules["main"]._active_ssh_client = client
    try:
        assert main_get_active_ssh_client() is None
        assert sys.modules["main"]._active_ssh_client is None
    finally:
        sys.modules["main"]._active_ssh_client = saved


def test_ensure_ssh_connection_returns_existing():
    client = _fake_ssh_client(transport=_fake_transport(True))
    with patch("main.get_active_ssh_client", return_value=client):
        assert _call_async(lambda: main_ensure_ssh_connection()) is client


def test_ensure_ssh_connection_connect_success():
    client = _fake_ssh_client()
    with patch("main.get_active_ssh_client", return_value=None), \
         patch("main.paramiko.SSHClient", return_value=client), \
         patch("main.mobile_set_ssh_client") as set_client, \
         patch.dict("main._ssh_credentials", {"ip": None, "user": None, "pass": None}, clear=True):
        result = _call_async(lambda: main_ensure_ssh_connection())
    assert result is client
    set_client.assert_called_once_with(client)
    assert sys.modules["main"]._active_ssh_client is client


def test_ensure_ssh_connection_connect_failure():
    client = _fake_ssh_client(connect_exc=Exception("auth failed"))
    with patch("main.get_active_ssh_client", return_value=None), \
         patch("main.paramiko.SSHClient", return_value=client), \
         patch.dict("main._ssh_credentials", {"ip": None, "user": None, "pass": None}, clear=True):
        result = _call_async(lambda: main_ensure_ssh_connection())
    assert result is None


# ──────────────────────────────────────────────
# _check_kali_mcp (startup handler)
# ──────────────────────────────────────────────

def _async_value(v):
    async def _inner():
        return v
    return _inner()


def _fake_httpx_client(status_code: int = 200, exc: Exception = None):
    if exc:
        async def _get(url):
            raise exc
    else:
        async def _get(url):
            return SimpleNamespace(status_code=status_code)

    class _AClient:
        async def __aenter__(self):
            return SimpleNamespace(get=_get)

        async def __aexit__(self, *a):
            return False

    return SimpleNamespace(AsyncClient=lambda **kw: _AClient())


def test_check_kali_mcp_detected():
    saved_url = sys.modules["main"].KALI_MCP_URL
    saved_flag = sys.modules["main"]._kali_mcp_available
    try:
        sys.modules["main"].KALI_MCP_URL = "http://kali:3001/mcp"
        sys.modules["main"]._kali_mcp_available = False
        with patch.dict(sys.modules, {"httpx": _fake_httpx_client(status_code=200)}):
            _call_async(lambda: main_check_kali_mcp())
        assert sys.modules["main"]._kali_mcp_available is True
    finally:
        sys.modules["main"].KALI_MCP_URL = saved_url
        sys.modules["main"]._kali_mcp_available = saved_flag


def test_check_kali_mcp_bad_status():
    saved_url = sys.modules["main"].KALI_MCP_URL
    try:
        sys.modules["main"].KALI_MCP_URL = "http://kali:3001/mcp"
        sys.modules["main"]._kali_mcp_available = True
        with patch.dict(sys.modules, {"httpx": _fake_httpx_client(status_code=500)}):
            _call_async(lambda: main_check_kali_mcp())
        assert sys.modules["main"]._kali_mcp_available is True  # unchanged
    finally:
        sys.modules["main"].KALI_MCP_URL = saved_url


def test_check_kali_mcp_exception():
    saved_url = sys.modules["main"].KALI_MCP_URL
    try:
        sys.modules["main"].KALI_MCP_URL = "http://kali:3001/mcp"
        with patch.dict(sys.modules, {"httpx": _fake_httpx_client(exc=RuntimeError("boom"))}):
            _call_async(lambda: main_check_kali_mcp())
    finally:
        sys.modules["main"].KALI_MCP_URL = saved_url


# ──────────────────────────────────────────────
# _call_llm_sync
# ──────────────────────────────────────────────

def test_llm_openai_success():
    resp = _FakeResponse(b'{"choices": [{"message": {"content": "hello"}}]}', 200)
    with patch("main.urllib.request.urlopen", return_value=resp):
        text = main_call_llm_sync("openai", "k", "gpt-4o-mini", [{"role": "user", "content": "hi"}])
    assert text == "hello"


def test_llm_openai_no_choices():
    resp = _FakeResponse(b'{"choices": []}', 200)
    with patch("main.urllib.request.urlopen", return_value=resp):
        text = main_call_llm_sync("openai", "k", "", [{"role": "user", "content": "hi"}])
    assert "choices" in text


def test_llm_openai_unicode_error():
    resp = _FakeResponse(b"\xff\xfe not utf8", 200)
    with patch("main.urllib.request.urlopen", return_value=resp):
        try:
            main_call_llm_sync("openai", "k", "m", [{"role": "user", "content": "hi"}])
            raise AssertionError("expected RuntimeError")
        except RuntimeError as e:
            assert "Encoding" in str(e)


def test_llm_openai_http_error():
    with patch("main.urllib.request.urlopen", side_effect=_FakeHTTPError(404, b"model not found")):
        try:
            main_call_llm_sync("openai", "k", "bad-model", [{"role": "user", "content": "hi"}])
            raise AssertionError("expected RuntimeError")
        except RuntimeError as e:
            assert "404" in str(e)


def test_llm_other_openai_providers():
    for provider in ("openrouter", "deepseek", "groq"):
        resp = _FakeResponse(b'{"choices": [{"message": {"content": "x"}}]}', 200)
        with patch("main.urllib.request.urlopen", return_value=resp):
            text = main_call_llm_sync(provider, "k", "model-x", [{"role": "user", "content": "hi"}])
        assert text == "x"


def test_llm_gemini_success():
    body = b'{"candidates": [{"content": {"parts": [{"text": "gem"}]}}]}'
    with patch("main.urllib.request.urlopen", return_value=_FakeResponse(body, 200)):
        text = main_call_llm_sync("gemini", "k", "", [{"role": "assistant", "content": "hi"}])
    assert text == "gem"


def test_llm_gemini_no_candidates():
    with patch("main.urllib.request.urlopen", return_value=_FakeResponse(b'{"candidates": []}', 200)):
        text = main_call_llm_sync("gemini", "k", "m", [{"role": "user", "content": "hi"}])
    assert "candidates" in text


def test_llm_anthropic_success():
    body = b'{"content": [{"text": "claude"}]}'
    with patch("main.urllib.request.urlopen", return_value=_FakeResponse(body, 200)):
        text = main_call_llm_sync("anthropic", "k", "", [{"role": "system", "content": "sys"}, {"role": "user", "content": "hi"}])
    assert text == "claude"


def test_llm_anthropic_no_content():
    with patch("main.urllib.request.urlopen", return_value=_FakeResponse(b'{"content": []}', 200)):
        text = main_call_llm_sync("anthropic", "k", "m", [{"role": "user", "content": "hi"}])
    assert "content" in text


def test_llm_local_success():
    resp = _FakeResponse(b'{"choices": [{"message": {"content": "local"}}]}', 200)
    with patch("main.urllib.request.urlopen", return_value=resp):
        text = main_call_llm_sync("local", "", "", [{"role": "user", "content": "hi"}])
    assert text == "local"


def test_llm_local_http_error():
    with patch("main.urllib.request.urlopen", side_effect=_FakeHTTPError(500, b"down")):
        try:
            main_call_llm_sync("local", "", "", [{"role": "user", "content": "hi"}])
            raise AssertionError("expected RuntimeError")
        except RuntimeError as e:
            assert "Local AI" in str(e)


def test_llm_local_url_error():
    err = _urlerror_factory("conn refused")
    with patch("main.urllib.request.urlopen", side_effect=err):
        try:
            main_call_llm_sync("local", "", "", [{"role": "user", "content": "hi"}])
            raise AssertionError("expected RuntimeError")
        except RuntimeError as e:
            assert "Ollama" in str(e)


def test_llm_unknown_provider():
    try:
        main_call_llm_sync("bogus", "", "", [{"role": "user", "content": "hi"}])
        raise AssertionError("expected ValueError")
    except ValueError as e:
        assert "Unknown provider" in str(e)
