"""Notifications hub tests — providers CRUD, masking, payload builders, send hooks.

Imports use the package prefix ``backend.notifications`` (see AGENTS.md style
convention — never mix bare ``import notifications`` forms).
"""
import json
import os
from unittest.mock import Mock, patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend import notifications as notif


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    notif.reset_providers()
    for var in (
        "MIRV_NOTIFY_TELEGRAM_BOT_TOKEN", "MIRV_NOTIFY_TELEGRAM_CHAT_ID",
        "MIRV_NOTIFY_DISCORD_URL", "MIRV_NOTIFY_SLACK_URL",
        "MIRV_NOTIFY_PUSHOVER_USER", "MIRV_NOTIFY_PUSHOVER_TOKEN",
        "MIRV_NOTIFY_WEBHOOK_URL",
    ):
        monkeypatch.delenv(var, raising=False)
    yield
    notif.reset_providers()


# ── configure / validate / mask ──────────────────────────────────────────

def test_configure_telegram():
    r = notif.configure_provider("telegram", {"bot_token": "123456:ABC", "chat_id": "42"})
    assert r["name"] == "telegram"
    assert set(r["config"]) == {"bot_token", "chat_id", "source"}
    assert "•••" in r["config"]["bot_token"]          # masked
    assert r["config"]["chat_id"] == "42"
    assert r["config"]["source"] == "api"


def test_configure_unknown_provider():
    with pytest.raises(ValueError, match="unknown provider"):
        notif.configure_provider("slack2", {"url": "x"})


def test_configure_missing_required_fields():
    with pytest.raises(ValueError, match="requires"):
        notif.configure_provider("telegram", {"bot_token": "x"})
    with pytest.raises(ValueError, match="requires"):
        notif.configure_provider("webhook", {})


def test_none_values_stripped():
    with pytest.raises(ValueError, match="requires"):
        notif.configure_provider("slack", {"url": None})


def test_configure_discord_and_list():
    notif.configure_provider("discord", {"url": "https://example.com/hook"})
    lst = notif.list_providers()
    assert len(lst) == 1 and lst[0]["name"] == "discord"
    assert lst[0]["source"] == "api"


# ── env fallback layer ────────────────────────────────────────────────────

def test_env_provider(monkeypatch):
    monkeypatch.setenv("MIRV_NOTIFY_TELEGRAM_BOT_TOKEN", "ENVTOK")
    monkeypatch.setenv("MIRV_NOTIFY_TELEGRAM_CHAT_ID", "-100")
    assert notif.is_configured("telegram")
    cfg = notif._get_config("telegram")
    assert cfg["bot_token"] == "ENVTOK" and cfg["source"] == "env"
    lst = notif.list_providers()
    assert lst[0]["source"] == "env"


def test_api_wins_over_env(monkeypatch):
    monkeypatch.setenv("MIRV_NOTIFY_TELEGRAM_BOT_TOKEN", "ENVTOK")
    monkeypatch.setenv("MIRV_NOTIFY_TELEGRAM_CHAT_ID", "-100")
    notif.configure_provider("telegram", {"bot_token": "APITOK", "chat_id": "-100"})
    assert notif._get_config("telegram")["bot_token"] == "APITOK"


def test_env_partial_ignored(monkeypatch):
    monkeypatch.setenv("MIRV_NOTIFY_TELEGRAM_BOT_TOKEN", "lonely")
    assert not notif.is_configured("telegram")          # needs chat_id too
    assert notif.list_providers() == []


def test_remove_provider():
    notif.configure_provider("webhook", {"url": "https://example.com/hook"})
    assert notif.remove_provider("webhook") is True
    assert notif.remove_provider("webhook") is False   # already gone


# ── payload builders ─────────────────────────────────────────────────────

def test_payload_discord_and_slack():
    _, b = notif._payload("discord", {"url": "https://example.com/hook"}, "T", "msg line", "info")
    assert b["content"] == "**T**\nmsg line"
    _, b = notif._payload("slack", {"url": "https://example.com/hook"}, "T", "msg", "info")
    assert b["text"] == "*T*\nmsg"


def test_payload_telegram_escapes_html():
    url, b = notif._payload("telegram", {"bot_token": "tok", "chat_id": "c"}, "<T>", "a & b <x>", "info")
    assert url == "https://api.telegram.org/bottok/sendMessage"
    assert b["chat_id"] == "c"
    assert "<b>&lt;T&gt;</b>" in b["text"]
    assert b["parse_mode"] == "HTML"


def test_payload_pushover_form_and_priority():
    _, b = notif._payload("pushover", {"user": "u", "token": "t"}, "T", "m", "critical")
    assert b["priority"] == 1
    _, b = notif._payload("pushover", {"user": "u", "token": "t"}, "T", "m", "info")
    assert b["priority"] == 0


def test_payload_webhook_schema():
    _, b = notif._payload("webhook", {"url": "https://example.com/hook"}, "T", "m", "high")
    assert set(b) == {"title", "message", "level", "source", "timestamp"}
    assert b["source"] == "mirv" and b["level"] == "high"


def test_truncate():
    assert len(notif._truncate("x" * 5000)) <= 4000
    assert notif._truncate("short") == "short"
    assert notif._truncate("") == ""


# ── deliveries (mocked urllib) ───────────────────────────────────────────

def test_deliver_telegram_url_and_json():
    notif.configure_provider("telegram", {"bot_token": "tok", "chat_id": "c"})
    with patch("backend.notifications.urllib.request.urlopen") as urlopen:
        urlopen.return_value.__enter__.return_value.read.return_value = b"{}"
        notif._deliver("telegram", "T", "m", "info")
        req = urlopen.call_args[0][0]
        assert req.full_url == "https://api.telegram.org/bottok/sendMessage"
        body = json.loads(req.data)
        assert body["chat_id"] == "c"


def test_deliver_pushover_form_encoded():
    notif.configure_provider("pushover", {"user": "u", "token": "t"})
    with patch("backend.notifications.urllib.request.urlopen") as urlopen:
        notif._deliver("pushover", "T", "m", "info")
        req = urlopen.call_args[0][0]
        assert b"priority=0" in req.data
        assert req.get_header("Content-type") == "application/x-www-form-urlencoded"


def test_deliver_quiet_no_provider_is_noop():
    with patch("backend.notifications.urllib.request.urlopen") as urlopen:
        notif._deliver_quiet("telegram", "T", "m", "info")
        urlopen.assert_not_called()


def test_deliver_quiet_errors_swallowed():
    notif.configure_provider("webhook", {"url": "https://example.com/hook"})
    with patch("backend.notifications.urllib.request.urlopen", side_effect=RuntimeError("boom")):
        notif._deliver_quiet("webhook", "T", "m", "info")   # must not raise


# ── send / send_sync ─────────────────────────────────────────────────────

def test_send_noop_when_nothing_configured():
    assert notif.send("T", "m") == 0


def test_send_queues_thread():
    notif.configure_provider("webhook", {"url": "https://example.com/hook"})
    assert notif.send("T", "m") == 1


def test_send_specific_provider():
    notif.configure_provider("webhook", {"url": "https://example.com/hook"})
    notif.configure_provider("slack", {"url": "https://example.com/hook2"})
    assert notif.send("T", "m", provider="slack") == 1


def test_send_unknown_provider_queues_zero():
    assert notif.send("T", "m", provider="nope") == 0


def test_send_sync_ok():
    notif.configure_provider("webhook", {"url": "https://example.com/hook"})
    with patch("backend.notifications.urllib.request.urlopen") as urlopen:
        r = notif.send_sync("T", "m")
    assert r["sent"] == 1 and r["all_ok"] is True
    urlopen.assert_called_once()


def test_send_sync_failure_reported():
    notif.configure_provider("webhook", {"url": "https://example.com/hook"})
    with patch("backend.notifications.urllib.request.urlopen", side_effect=RuntimeError("boom")):
        r = notif.send_sync("T", "m")
    assert r["sent"] == 0 and r["all_ok"] is False
    assert r["results"]["webhook"]["ok"] is False


def test_send_sync_raises_when_single_unconfigured():
    with pytest.raises(ValueError, match="not configured"):
        notif.send_sync("T", "m", provider="telegram")


# ── REST endpoints ───────────────────────────────────────────────────────

@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c


# ── REST endpoints ───────────────────────────────────────────────────────

def test_rest_list_providers_empty(client):
    r = client.get("/api/notifications/providers")
    assert r.status_code == 200 and r.json()["providers"] == []


def test_rest_configure_and_list_masked(client):
    r = client.post("/api/notifications/config", json={"provider": "telegram", "fields": {"bot_token": "123456:ABC", "chat_id": "42"}})
    assert r.status_code == 200 and r.json()["ok"] is True
    lst = client.get("/api/notifications/providers").json()["providers"]
    assert lst[0]["name"] == "telegram"
    assert "•••" in lst[0]["config"]["bot_token"] and lst[0]["config"]["chat_id"] == "42"


def test_rest_configure_bad_inputs(client):
    assert client.post("/api/notifications/config", json={}).status_code == 400
    assert client.post("/api/notifications/config", json={"provider": "wat", "fields": {}}).status_code == 400
    assert client.post("/api/notifications/config", json={"provider": "telegram", "fields": {}}).status_code == 400


def test_rest_config_delete(client):
    client.post("/api/notifications/config", json={"provider": "discord", "fields": {"url": "https://example.com/hook"}})
    r = client.delete("/api/notifications/config/discord")
    assert r.status_code == 200 and r.json()["removed"] is True
    assert client.delete("/api/notifications/config/discord").json()["removed"] is False


def test_rest_test_not_configured(client):
    r = client.post("/api/notifications/test", json={"provider": "telegram"})
    assert r.status_code == 400


def test_rest_test_ok_and_fail(client):
    client.post("/api/notifications/config", json={"provider": "webhook", "fields": {"url": "https://example.com/hook"}})
    with patch("backend.notifications.urllib.request.urlopen"):
        r = client.post("/api/notifications/test", json={"provider": "webhook"})
        assert r.status_code == 200 and r.json()["all_ok"] is True
    with patch("backend.notifications.urllib.request.urlopen", side_effect=RuntimeError("boom")):
        r = client.post("/api/notifications/test", json={"provider": "webhook", "message": "check"})
        assert r.status_code == 502 and r.json()["all_ok"] is False


def test_rest_send_queued(client):
    r = client.post("/api/notifications/send", json={"title": "T", "message": "m"})
    assert r.status_code == 200 and r.json()["queued"] == 0     # nothing configured
    client.post("/api/notifications/config", json={"provider": "slack", "fields": {"url": "https://example.com/hook"}})
    r = client.post("/api/notifications/send", json={"title": "T", "message": "m", "provider": "slack"})
    assert r.json()["queued"] == 1


# ── hooks: scheduled run + findings ──────────────────────────────────────

def test_finding_hook_notifies_on_high(client):
    client.post("/api/notifications/config", json={"provider": "webhook", "fields": {"url": "https://example.com/hook"}})
    with patch("backend.database.save_finding", return_value={"id": "f1"}), patch("backend.notifications.send") as send:
        r = client.post("/api/findings", json={"tool": "nmap", "severity": "high", "title": "Open RDP", "target": "10.0.0.5"})
        assert r.status_code == 201
        send.assert_called_once()
        assert "Open RDP" in send.call_args[0][1]
        assert send.call_args[1]["level"] == "high"


def test_finding_hook_silent_on_low(client):
    client.post("/api/notifications/config", json={"provider": "webhook", "fields": {"url": "https://example.com/hook"}})
    with patch("backend.database.save_finding", return_value={"id": "f1"}), patch("backend.notifications.send") as send:
        client.post("/api/findings", json={"tool": "nmap", "severity": "low", "title": "banner"})
        send.assert_not_called()


def test_finding_bulk_hook_counts_critical(client):
    client.post("/api/notifications/config", json={"provider": "webhook", "fields": {"url": "https://example.com/hook"}})
    with patch("backend.database.save_findings_bulk", return_value=3), patch("backend.notifications.send") as send:
        r = client.post("/api/findings/bulk", json=[
            {"tool": "x", "severity": "low", "title": "a"},
            {"tool": "x", "severity": "critical", "title": "b"},
            {"tool": "x", "severity": "high", "title": "c"},
        ])
        assert r.status_code == 201
        send.assert_called_once()
        assert "2 high/critical" in send.call_args[0][1]


def test_scheduler_record_hook(client):
    client.post("/api/notifications/config", json={"provider": "webhook", "fields": {"url": "https://example.com/hook"}})
    client.post("/api/scheduler/jobs", json={
        "name": "night-scan", "tool_id": "nmap", "target": "10.0.0.5", "interval_seconds": 60,
    })
    jid = client.get("/api/scheduler/jobs").json()["jobs"][0]["id"]
    with patch("backend.notifications.send") as send:
        r = client.post(f"/api/scheduler/jobs/{jid}/record", json={"result": "success", "findings": 3, "duration": 2.5})
        assert r.status_code == 200
        send.assert_called_once()
        message = send.call_args[0][1]
        assert "night-scan" in message and "3 finding(s)" in message

    with patch("backend.notifications.send") as send:
        r = client.post(f"/api/scheduler/jobs/{jid}/record", json={"result": "error", "error": "timeout", "duration": 9.0})
        assert r.status_code == 200
        assert send.call_args[1]["level"] == "high"


def test_hooks_noop_without_providers(client):
    with patch("backend.database.save_finding", return_value={"id": "f1"}), patch("backend.database.save_findings_bulk", return_value=1), patch("backend.notifications._deliver") as deliver:
        client.post("/api/findings", json={"tool": "x", "severity": "critical", "title": "c"})
        client.post("/api/scheduler/jobs", json={
            "name": "j", "tool_id": "nmap", "target": "t", "interval_seconds": 60,
        })
        jid = client.get("/api/scheduler/jobs").json()["jobs"][0]["id"]
        client.post(f"/api/scheduler/jobs/{jid}/record", json={"result": "success", "findings": 1, "duration": 1.0})
        deliver.assert_not_called()