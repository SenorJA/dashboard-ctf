"""Pack 20 — Privacy / egress-IP management (backend/privacy.py + /api/privacy/*).

Hermetic: the Kali host is never contacted. `run_on_host`/`public_ip` are patched,
the shared SSH client is injected with mocks and the registry is reset per test.
Endpoints are exercised through `TestClient(app)`.
"""
from __future__ import annotations

import base64

from unittest.mock import MagicMock, patch

import pytest

from backend import privacy as pv
from backend.main import app
from fastapi.testclient import TestClient


@pytest.fixture(autouse=True)
def _clean_state():
    pv.registry.clear()
    pv.set_ssh_client(None)
    yield
    pv.registry.clear()
    pv.set_ssh_client(None)


def _client():
    return TestClient(app)


def _profile(**kw):
    base = dict(name="p", kind="socks5", host="1.2.3.4", port=1080,
                username="", password="")
    base.update(kw)
    return pv.registry.add(**base)


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

class TestHelpers:
    def test_mask_secret_empty(self):
        assert pv.mask_secret("") == ""

    def test_mask_secret_short(self):
        assert pv.mask_secret("abcd") == "****"

    def test_mask_secret_long_keeps_last4(self):
        m = pv.mask_secret("supersecret")
        assert m.endswith("cret")
        assert "superse" not in m

    def test_extract_ip_from_text(self):
        assert pv._extract_ip("  203.0.113.9\n") == "203.0.113.9"

    def test_extract_ip_fallback_first_line(self):
        assert pv._extract_ip("not-an-ip-here\nother") == "not-an-ip-here"

    def test_extract_ip_empty(self):
        assert pv._extract_ip("") == ""


class TestValidate:
    @pytest.mark.parametrize("kind", ["socks5", "socks4", "http", "https"])
    def test_valid_kinds(self, kind):
        assert pv.validate(kind, "127.0.0.1", 1080) is None

    def test_bad_kind(self):
        assert "invalid kind" in pv.validate("bogus", "127.0.0.1", 1080)

    @pytest.mark.parametrize("host", ["", "bad host", "a;b"])
    def test_bad_host(self, host):
        assert pv.validate("socks5", host, 1080) == "invalid host"

    def test_bad_port(self):
        assert pv.validate("socks5", "1.2.3.4", "nope") == "invalid port"

    def test_port_out_of_range(self):
        assert pv.validate("socks5", "1.2.3.4", 0) == "port out of range (1-65535)"
        assert pv.validate("socks5", "1.2.3.4", 70000) == "port out of range (1-65535)"


class TestProxyProfile:
    def test_to_public_masks_password(self):
        prof = pv.ProxyProfile("x", "n", "socks5", "1.2.3.4", 1080,
                               username="u", password="hunter2")
        pub = prof.to_public()
        assert pub["password"] == "***ter2"
        assert pub["has_password"] is True
        assert pub["host"] == "1.2.3.4"

    def test_to_public_no_password(self):
        prof = pv.ProxyProfile("x", "n", "http", "h", 8080)
        assert prof.to_public()["has_password"] is False


class TestConfigBuilders:
    def test_proxychains_conf_plain(self):
        prof = pv.ProxyProfile("x", "n", "socks5", "9.9.9.9", 9050)
        conf = pv.build_proxychains_conf(prof)
        assert "[ProxyList]" in conf
        assert "socks5 9.9.9.9 9050" in conf

    def test_proxychains_conf_with_auth(self):
        prof = pv.ProxyProfile("x", "n", "socks5", "h", 1080, "user", "pw")
        assert "socks5 h 1080 user pw" in pv.build_proxychains_conf(prof)

    def test_http_maps_to_http(self):
        prof = pv.ProxyProfile("x", "n", "https", "h", 3128)
        assert "http h 3128" in pv.build_proxychains_conf(prof)

    def test_env_block_has_export(self):
        prof = pv.ProxyProfile("x", "n", "socks5", "h", 1080, "u", "p")
        block = pv._env_block(prof)
        assert "export http_proxy=socks5://u:p@h:1080" in block
        assert pv._ENV_BEGIN in block and pv._ENV_END in block

    def test_environment_block_no_export(self):
        prof = pv.ProxyProfile("x", "n", "http", "h", 8080)
        block = pv._environment_block(prof)
        assert "export" not in block
        assert "http_proxy=http://h:8080" in block

    def test_apply_commands_embed_base64_conf(self):
        prof = pv.ProxyProfile("x", "n", "socks5", "h", 1080)
        cmds = pv.build_apply_commands(prof)
        assert any("mkdir -p" in c for c in cmds)
        conf_cmd = next(c for c in cmds if pv._PROXYCHAINS_CONF in c)
        b64 = conf_cmd.split("'")[3]
        assert base64.b64decode(b64).decode() == pv.build_proxychains_conf(prof)
        assert any("/etc/environment" in c for c in cmds)

    def test_clear_commands_remove_and_strip(self):
        cmds = pv.build_clear_commands()
        assert any("rm -f" in c for c in cmds)
        assert any("/etc/environment" in c for c in cmds)


# ════════════════════════════════════════════════════════════════
#  Registry
# ════════════════════════════════════════════════════════════════

class TestRegistry:
    def test_add_get_list(self):
        prof = _profile(name="a")
        assert pv.registry.get(prof.pid) is prof
        assert [p.pid for p in pv.registry.list()] == [prof.pid]

    def test_delete(self):
        prof = _profile()
        assert pv.registry.delete(prof.pid) is True
        assert pv.registry.delete(prof.pid) is False
        assert pv.registry.list() == []

    def test_set_active_toggles_single(self):
        a = _profile(name="a")
        b = _profile(name="b")
        assert pv.registry.set_active(a.pid) is a
        assert pv.registry.active() is a
        pv.registry.set_active(b.pid)
        assert pv.registry.active() is b
        assert pv.registry.get(a.pid).active is False

    def test_set_active_none_clears(self):
        a = _profile()
        pv.registry.set_active(a.pid)
        pv.registry.set_active(None)
        assert pv.registry.active() is None

    def test_clear(self):
        _profile()
        _profile()
        assert pv.registry.clear() == 2

    def test_export_import_roundtrip(self):
        _profile(name="a")
        _profile(name="b")
        state = pv.registry.export_state()
        pv.registry.clear()
        assert pv.registry.import_state(state) == 2

    def test_import_skips_bad_rows(self):
        assert pv.registry.import_state([{"port": "not-an-int", "name": "x"}]) == 0


# ════════════════════════════════════════════════════════════════
#  run_on_host / SSH injection
# ════════════════════════════════════════════════════════════════

class TestRunOnHost:
    def test_not_configured_is_graceful(self, monkeypatch):
        monkeypatch.delenv("MIRV_PRIVACY_HOST", raising=False)
        monkeypatch.delenv("KALI_IP", raising=False)
        pv.set_ssh_client(None)
        out, err, rc = pv.run_on_host("echo hi")
        assert rc == 1
        assert "not configured" in err

    def test_injected_client_success(self):
        fake_stdout = MagicMock()
        fake_stdout.read.return_value = b"result\n"
        fake_stdout.channel.recv_exit_status.return_value = 0
        fake_stderr = MagicMock()
        fake_stderr.read.return_value = b""
        fake = MagicMock()
        fake.exec_command.return_value = (MagicMock(), fake_stdout, fake_stderr)
        pv.set_ssh_client(fake)
        out, err, rc = pv.run_on_host("echo hi")
        assert (out, err, rc) == ("result\n", "", 0)
        # Injected clients are not closed by run_on_host (shared resource).
        fake.close.assert_not_called()

    def test_injected_client_exception(self):
        fake = MagicMock()
        fake.exec_command.side_effect = RuntimeError("boom")
        pv.set_ssh_client(fake)
        out, err, rc = pv.run_on_host("x")
        assert out == "" and "boom" in err and rc == 1

    def test_env_ssh_client_none_without_host(self, monkeypatch):
        monkeypatch.delenv("MIRV_PRIVACY_HOST", raising=False)
        monkeypatch.delenv("KALI_IP", raising=False)
        assert pv._env_ssh_client() is None

    def test_env_ssh_client_none_when_paramiko_missing(self, monkeypatch):
        monkeypatch.setattr(pv, "paramiko", None)
        assert pv._env_ssh_client() is None


# ════════════════════════════════════════════════════════════════
#  public_ip / apply / clear / status
# ════════════════════════════════════════════════════════════════

class TestOperations:
    def test_public_ip_direct(self):
        with patch.object(pv, "run_on_host", return_value=("203.0.113.5\n", "", 0)):
            res = pv.public_ip(via_proxy=False)
        assert res["ip"] == "203.0.113.5"
        assert res["ok"] is True
        assert res["via_proxy"] is False

    def test_public_ip_via_proxy_uses_proxychains(self):
        seen = {}

        def fake_cmd(cmd, timeout=15):
            seen["cmd"] = cmd
            return "198.51.100.7", "", 0

        with patch.object(pv, "run_on_host", side_effect=fake_cmd):
            res = pv.public_ip(via_proxy=True)
        assert "proxychains4" in seen["cmd"]
        assert res["ip"] == "198.51.100.7"

    def test_public_ip_failure(self):
        with patch.object(pv, "run_on_host", return_value=("", "no route", 1)):
            res = pv.public_ip()
        assert res["ok"] is False
        assert res["error"] == "no route"

    def test_apply_proxy_success_marks_active(self):
        prof = _profile()
        with patch.object(pv, "run_on_host", return_value=("", "", 0)):
            res = pv.apply_proxy(prof.pid)
        assert res["ok"] is True
        assert res["active"] == prof.pid
        assert pv.registry.active() is prof

    def test_apply_proxy_missing(self):
        res = pv.apply_proxy("nope")
        assert res["ok"] is False
        assert res["error"] == "proxy profile not found"

    def test_apply_proxy_host_unreachable(self):
        prof = _profile()
        with patch.object(pv, "run_on_host",
                          return_value=("", "privacy host not configured (x)", 1)):
            res = pv.apply_proxy(prof.pid)
        assert res["ok"] is False
        assert "not configured" in res["error"]

    def test_clear_proxy(self):
        prof = _profile()
        pv.registry.set_active(prof.pid)
        with patch.object(pv, "run_on_host", return_value=("", "", 0)):
            res = pv.clear_proxy()
        assert res["ok"] is True and res["cleared"] is True
        assert pv.registry.active() is None

    def test_status_without_active(self):
        with patch.object(pv, "public_ip", return_value={"ok": True, "ip": "1.1.1.1"}):
            res = pv.status()
        assert res["active"] is None
        assert res["direct"]["ip"] == "1.1.1.1"
        assert res["proxied"] is None

    def test_status_with_active(self):
        prof = _profile()
        pv.registry.set_active(prof.pid)
        with patch.object(pv, "public_ip", return_value={"ok": True, "ip": "2.2.2.2"}):
            res = pv.status()
        assert res["active"]["pid"] == prof.pid
        assert res["proxied"]["ip"] == "2.2.2.2"

    def test_summary(self):
        _profile()
        res = pv.summary()
        assert res["profiles"] == 1
        assert "socks5" in res["kinds"]


# ════════════════════════════════════════════════════════════════
#  Persistence (opt-in workspace_store)
# ════════════════════════════════════════════════════════════════

class TestPersistence:
    def test_persist_calls_upsert(self, monkeypatch):
        store = MagicMock()
        monkeypatch.setattr(pv, "workspace_store", store)
        _profile(name="persisted")
        store.upsert.assert_called()
        assert store.upsert.call_args[0][0] == "privacy"

    def test_persist_noop_without_store(self, monkeypatch):
        monkeypatch.setattr(pv, "workspace_store", None)
        pv._persist()  # must not raise

    def test_hydrate_loads_rows(self, monkeypatch):
        store = MagicMock()
        store.load.return_value = [
            {"pid": "abc12345", "name": "loaded", "kind": "http",
             "host": "10.0.0.1", "port": 8080, "active": True},
        ]
        monkeypatch.setattr(pv, "workspace_store", store)
        assert pv.hydrate() == 1
        assert pv.registry.active().name == "loaded"

    def test_hydrate_noop_without_rows(self, monkeypatch):
        store = MagicMock()
        store.load.return_value = None
        monkeypatch.setattr(pv, "workspace_store", store)
        assert pv.hydrate() == 0

    def test_hydrate_noop_without_store(self, monkeypatch):
        monkeypatch.setattr(pv, "workspace_store", None)
        assert pv.hydrate() == 0


# ════════════════════════════════════════════════════════════════
#  Endpoints (/api/privacy/*)
# ════════════════════════════════════════════════════════════════

class TestPrivacyEndpoints:
    def test_summary(self):
        with _client() as c:
            r = c.get("/api/privacy/summary")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_list_empty(self):
        with _client() as c:
            r = c.get("/api/privacy/proxies")
        assert r.json()["proxies"] == []

    def test_create_masks_password(self):
        with _client() as c:
            r = c.post("/api/privacy/proxies", json={
                "name": "p1", "kind": "socks5", "host": "1.2.3.4",
                "port": 1080, "username": "u", "password": "hunter2"})
        assert r.status_code == 201
        pub = r.json()["proxy"]
        assert pub["password"] == "***ter2"
        assert pub["has_password"] is True

    def test_create_invalid_400(self):
        with _client() as c:
            r = c.post("/api/privacy/proxies", json={
                "name": "p", "kind": "bogus", "host": "1.2.3.4", "port": 1080})
        assert r.status_code == 400

    def test_get_and_delete(self):
        with _client() as c:
            pid = c.post("/api/privacy/proxies", json={
                "name": "p", "kind": "http", "host": "h", "port": 3128}).json()["proxy"]["pid"]
            g = c.get(f"/api/privacy/proxies/{pid}")
            d = c.delete(f"/api/privacy/proxies/{pid}")
            gone = c.get(f"/api/privacy/proxies/{pid}")
        assert g.status_code == 200
        assert d.json()["deleted"] == pid
        assert gone.status_code == 404

    def test_delete_missing_404(self):
        with _client() as c:
            r = c.delete("/api/privacy/proxies/nope")
        assert r.status_code == 404

    def test_activate_not_found_404(self):
        with _client() as c:
            r = c.post("/api/privacy/proxies/nope/activate")
        assert r.status_code == 404

    def test_activate_ok(self):
        with _client() as c:
            pid = c.post("/api/privacy/proxies", json={
                "name": "p", "kind": "socks5", "host": "h", "port": 1080}).json()["proxy"]["pid"]
            with patch.object(pv, "run_on_host", return_value=("", "", 0)):
                r = c.post(f"/api/privacy/proxies/{pid}/activate")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_deactivate(self):
        with patch.object(pv, "run_on_host", return_value=("", "", 0)):
            with _client() as c:
                r = c.post("/api/privacy/deactivate")
        assert r.status_code == 200
        assert r.json()["cleared"] is True

    def test_ip_endpoint(self):
        with patch.object(pv, "run_on_host", return_value=("8.8.8.8\n", "", 0)):
            with _client() as c:
                r = c.get("/api/privacy/ip")
        assert r.json()["ip"] == "8.8.8.8"

    def test_status_endpoint(self):
        with patch.object(pv, "public_ip", return_value={"ok": True, "ip": "1.1.1.1"}):
            with _client() as c:
                r = c.get("/api/privacy/status")
        assert r.status_code == 200
        assert r.json()["direct"]["ip"] == "1.1.1.1"

    def test_endpoints_degrade_when_module_unavailable(self):
        with patch("backend.main.priv", None):
            with _client() as c:
                assert c.get("/api/privacy/summary").status_code == 500
                assert c.get("/api/privacy/proxies").status_code == 500
                assert c.post("/api/privacy/proxies", json={}).status_code == 500
                assert c.get("/api/privacy/proxies/x").status_code == 500
                assert c.delete("/api/privacy/proxies/x").status_code == 500
                assert c.post("/api/privacy/proxies/x/activate").status_code == 500
                assert c.post("/api/privacy/deactivate").status_code == 500
                assert c.get("/api/privacy/ip").status_code == 500
                assert c.get("/api/privacy/status").status_code == 500
