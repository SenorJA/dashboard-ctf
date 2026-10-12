"""Pack 21 — VPN (WireGuard / OpenVPN) management (backend/vpn.py + /api/vpn/*).

Hermetic: the Kali host is never contacted. ``run_on_host``/``public_ip`` are
patched, the registry is reset per test. Endpoints go through ``TestClient(app)``.
"""
from __future__ import annotations

import base64

from unittest.mock import MagicMock, patch

import pytest

from backend import vpn as vp
from backend.main import app
from fastapi.testclient import TestClient

WG_CONF = """[Interface]
PrivateKey = aGVsbG8gc2VjcmV0IGtleSB0aGF0IGlzIGxvbmcgZW5vdWdoISE=
Address = 10.2.0.2/32
DNS = 10.2.0.1

[Peer]
PublicKey = cGVlciBwdWJsaWMga2V5IGJhc2U2NCB2YWx1ZSBoZXJlISE=
AllowedIPs = 0.0.0.0/0
"""

OVPN_CONF = """client
dev tun
proto udp
remote vpn.example.com 1194
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
deadbeef
-----END OpenVPN Static key V1-----
</tls-auth>
"""


@pytest.fixture(autouse=True)
def _clean_state():
    vp.registry.clear()
    yield
    vp.registry.clear()


def _client():
    return TestClient(app)


def _profile(**kw):
    base = dict(name="wg0", protocol="wireguard", config=WG_CONF)
    base.update(kw)
    return vp.registry.add(**base)


# ════════════════════════════════════════════════════════════════
#  Helpers
# ════════════════════════════════════════════════════════════════

class TestHelpers:
    def test_safe_iface_keeps_valid(self):
        assert vp.safe_iface("wg0") == "wg0"

    def test_safe_iface_sanitizes(self):
        assert vp.safe_iface("my vpn/../x") == "my_vpn____x"

    def test_safe_iface_truncates_15(self):
        assert len(vp.safe_iface("a" * 40)) == 15

    def test_safe_iface_empty_default(self):
        assert vp.safe_iface("") == "mirv0"

    def test_b64_roundtrip(self):
        raw = "line1\nline2\n"
        assert base64.b64decode(vp._b64(raw)).decode() == raw


class TestRedact:
    def test_wireguard_masks_private_key(self):
        out = vp.redact_config("wireguard", WG_CONF)
        assert "aGVsbG8" not in out
        assert "PrivateKey = ***" in out
        assert "10.2.0.2/32" in out  # non-secret preserved

    def test_wireguard_masks_preshared(self):
        conf = "[Interface]\nPrivateKey = x\nPresharedKey = SECRETPSK\n"
        out = vp.redact_config("wireguard", conf)
        assert "SECRETPSK" not in out

    def test_openvpn_masks_tls_block(self):
        out = vp.redact_config("openvpn", OVPN_CONF)
        assert "deadbeef" not in out
        assert "<tls-auth>" in out and "</tls-auth>" in out
        assert "vpn.example.com" in out

    def test_openvpn_masks_pem(self):
        conf = "client\n<key>\n-----BEGIN PRIVATE KEY-----\nAAAABBBB\n-----END PRIVATE KEY-----\n</key>\n"
        out = vp.redact_config("openvpn", conf)
        assert "AAAABBBB" not in out


# ════════════════════════════════════════════════════════════════
#  Validate
# ════════════════════════════════════════════════════════════════

class TestValidate:
    def test_wireguard_ok(self):
        assert vp.validate("wireguard", "wg0", WG_CONF) is None

    def test_openvpn_ok(self):
        assert vp.validate("openvpn", "ovpn1", OVPN_CONF) is None

    def test_bad_protocol(self):
        assert "invalid protocol" in vp.validate("pptp", "wg0", WG_CONF)

    @pytest.mark.parametrize("name", ["", "bad name", "a" * 16, "with/slash", "semi;colon"])
    def test_bad_name(self, name):
        assert "invalid name" in vp.validate("wireguard", name, WG_CONF)

    def test_empty_config(self):
        assert vp.validate("wireguard", "wg0", "   ") == "empty config"

    def test_wireguard_missing_interface(self):
        assert "missing [Interface]" in vp.validate("wireguard", "wg0", "PrivateKey = x")

    def test_wireguard_missing_private_key(self):
        assert "missing PrivateKey" in vp.validate("wireguard", "wg0", "[Interface]\nAddress = 1.2.3.4/32")

    def test_openvpn_missing_remote(self):
        assert "missing 'client'/'remote'" in vp.validate("openvpn", "v1", "foo bar")

    def test_config_too_large(self):
        assert "too large" in vp.validate("wireguard", "wg0", "[Interface]\nPrivateKey = x\n" + "a" * 200_001)


# ════════════════════════════════════════════════════════════════
#  Profile + registry
# ════════════════════════════════════════════════════════════════

class TestProfile:
    def test_to_public_redacts_key(self):
        prof = vp.VPNProfile("x", "wg0", "wireguard", WG_CONF)
        pub = prof.to_public()
        assert "aGVsbG8" not in pub["config"]
        assert pub["has_config"] is True
        assert pub["iface"] == "wg0"

    def test_to_public_without_config(self):
        prof = vp.VPNProfile("x", "wg0", "wireguard", WG_CONF)
        pub = prof.to_public(include_config=False)
        assert "config" not in pub
        assert pub["config_lines"] > 0

    def test_iface_derived(self):
        prof = vp.VPNProfile("x", "Weird Name!", "wireguard", WG_CONF)
        assert prof.iface == "Weird_Name_"


class TestRegistry:
    def test_add_get_list_delete(self):
        prof = _profile()
        assert vp.registry.get(prof.vid) is prof
        assert vp.registry.list() == [prof]
        assert vp.registry.delete(prof.vid) is True
        assert vp.registry.get(prof.vid) is None
        assert vp.registry.delete(prof.vid) is False

    def test_set_active_toggles(self):
        a = _profile(name="a")
        b = _profile(name="b")
        vp.registry.set_active(a.vid)
        assert vp.registry.active() is a
        vp.registry.set_active(b.vid)
        assert vp.registry.active() is b
        vp.registry.set_active(None)
        assert vp.registry.active() is None

    def test_clear(self):
        _profile()
        _profile(name="b")
        assert vp.registry.clear() == 2
        assert vp.registry.list() == []

    def test_export_import_roundtrip(self):
        _profile(name="exp")
        rows = vp.registry.export_state()
        vp.registry.clear()
        assert vp.registry.import_state(rows) == 1
        assert vp.registry.list()[0].name == "exp"

    def test_import_skips_bad_rows(self):
        assert vp.registry.import_state([{"name": "ok"}, None]) == 1


# ════════════════════════════════════════════════════════════════
#  Command builders
# ════════════════════════════════════════════════════════════════

class TestBuilders:
    def test_wireguard_apply_commands(self):
        prof = vp.VPNProfile("x", "wg0", "wireguard", WG_CONF)
        cmds = vp.build_apply_commands(prof)
        joined = "\n".join(cmds)
        assert "base64 -d" in joined
        assert "/etc/wireguard/wg0.conf" in joined
        assert "wg-quick up wg0" in joined
        assert "/etc/wireguard/wg0.conf" in cmds[1]

    def test_wireguard_apply_encodes_config(self):
        prof = vp.VPNProfile("x", "wg0", "wireguard", WG_CONF)
        cmd = vp.build_apply_commands(prof)[1]
        encoded = cmd.split("'")[3]
        assert base64.b64decode(encoded).decode() == WG_CONF

    def test_openvpn_apply_commands(self):
        prof = vp.VPNProfile("x", "v1", "openvpn", OVPN_CONF)
        joined = "\n".join(vp.build_apply_commands(prof))
        assert "/etc/openvpn/client/v1.conf" in joined
        assert "openvpn --daemon" in joined
        assert "/run/mirv-vpn-v1.pid" in joined

    def test_openvpn_clear_commands(self):
        prof = vp.VPNProfile("x", "v1", "openvpn", OVPN_CONF)
        joined = "\n".join(vp.build_clear_commands(prof))
        assert "/run/mirv-vpn-v1.pid" in joined
        assert "rm -f /etc/openvpn/client/v1.conf" in joined

    def test_wireguard_clear_commands(self):
        prof = vp.VPNProfile("x", "wg0", "wireguard", WG_CONF)
        joined = "\n".join(vp.build_clear_commands(prof))
        assert "wg-quick down wg0" in joined
        assert "rm -f /etc/wireguard/wg0.conf" in joined


# ════════════════════════════════════════════════════════════════
#  Operations
# ════════════════════════════════════════════════════════════════

class TestOperations:
    def test_apply_success_marks_active(self):
        prof = _profile()
        with patch.object(vp, "run_on_host", return_value=("", "", 0)):
            res = vp.apply_vpn(prof.vid)
        assert res["ok"] is True
        assert res["active"] == prof.vid
        assert vp.registry.active() is prof

    def test_apply_missing(self):
        res = vp.apply_vpn("nope")
        assert res["ok"] is False
        assert res["error"] == "vpn profile not found"

    def test_apply_host_unreachable(self):
        prof = _profile()
        with patch.object(vp, "run_on_host", return_value=("", "privacy host not configured (x)", 1)):
            res = vp.apply_vpn(prof.vid)
        assert res["ok"] is False
        assert "not configured" in res["error"]

    def test_apply_runner_unavailable(self):
        prof = _profile()
        with patch.object(vp, "run_on_host",
                          return_value=("", "vpn host runner unavailable (privacy module missing)", 1)):
            res = vp.apply_vpn(prof.vid)
        assert res["ok"] is False
        assert "unavailable" in res["error"]

    def test_apply_partial_failure_not_active(self):
        prof = _profile()
        with patch.object(vp, "run_on_host", return_value=("", "boom", 1)):
            res = vp.apply_vpn(prof.vid)
        assert res["ok"] is False
        assert vp.registry.active() is None

    def test_clear_vpn_with_active(self):
        prof = _profile()
        vp.registry.set_active(prof.vid)
        with patch.object(vp, "run_on_host", return_value=("", "", 0)):
            res = vp.clear_vpn()
        assert res["ok"] is True and res["cleared"] is True
        assert vp.registry.active() is None

    def test_clear_vpn_without_active_runs_nothing(self):
        with patch.object(vp, "run_on_host", return_value=("", "", 0)) as m:
            res = vp.clear_vpn()
        assert res["cleared"] is True
        assert m.call_count == 0

    def test_run_on_host_delegates_to_privacy(self, monkeypatch):
        sentinel = ("out", "", 0)
        fake = MagicMock(return_value=sentinel)
        monkeypatch.setattr(vp, "_host", MagicMock(run_on_host=fake))
        assert vp.run_on_host("echo hi") == sentinel
        fake.assert_called_once()

    def test_run_on_host_without_host(self, monkeypatch):
        monkeypatch.setattr(vp, "_host", None)
        out, err, rc = vp.run_on_host("echo hi")
        assert rc == 1
        assert "unavailable" in err


class TestStatusAndIp:
    def test_public_ip_without_host(self, monkeypatch):
        monkeypatch.setattr(vp, "_host", None)
        res = vp.public_ip()
        assert res["ok"] is False and "unavailable" in res["error"]

    def test_public_ip_delegates(self, monkeypatch):
        fake = MagicMock(return_value={"ok": True, "ip": "9.9.9.9", "duration_ms": 5, "error": None})
        monkeypatch.setattr(vp, "_host", MagicMock(public_ip=fake))
        res = vp.public_ip(via_vpn=True)
        assert res["ip"] == "9.9.9.9"
        assert res["via_vpn"] is True

    def test_status_without_active(self):
        with patch.object(vp, "public_ip", return_value={"ok": True, "ip": "1.1.1.1"}):
            res = vp.status()
        assert res["active"] is None
        assert res["current_ip"]["ip"] == "1.1.1.1"

    def test_status_with_active(self):
        prof = _profile()
        vp.registry.set_active(prof.vid)
        with patch.object(vp, "public_ip", return_value={"ok": True, "ip": "2.2.2.2"}) as m:
            res = vp.status()
        assert res["active"]["vid"] == prof.vid
        assert m.call_args.kwargs["via_vpn"] is True

    def test_status_no_probe(self):
        res = vp.status(probe_ip=False)
        assert res["current_ip"] is None

    def test_summary(self):
        _profile()
        res = vp.summary()
        assert res["profiles"] == 1
        assert "wireguard" in res["protocols"]


# ════════════════════════════════════════════════════════════════
#  Persistence (opt-in workspace_store)
# ════════════════════════════════════════════════════════════════

class TestPersistence:
    def test_persist_calls_upsert(self, monkeypatch):
        store = MagicMock()
        monkeypatch.setattr(vp, "workspace_store", store)
        _profile(name="persisted")
        store.upsert.assert_called()
        assert store.upsert.call_args[0][0] == "vpn"

    def test_persist_noop_without_store(self, monkeypatch):
        monkeypatch.setattr(vp, "workspace_store", None)
        vp._persist()  # must not raise

    def test_hydrate_loads_rows(self, monkeypatch):
        store = MagicMock()
        store.load.return_value = [
            {"vid": "abc12345", "name": "loaded", "protocol": "openvpn",
             "config": OVPN_CONF, "active": True},
        ]
        monkeypatch.setattr(vp, "workspace_store", store)
        assert vp.hydrate() == 1
        assert vp.registry.active().name == "loaded"

    def test_hydrate_noop_without_rows(self, monkeypatch):
        store = MagicMock()
        store.load.return_value = None
        monkeypatch.setattr(vp, "workspace_store", store)
        assert vp.hydrate() == 0

    def test_hydrate_noop_without_store(self, monkeypatch):
        monkeypatch.setattr(vp, "workspace_store", None)
        assert vp.hydrate() == 0


# ════════════════════════════════════════════════════════════════
#  Endpoints (/api/vpn/*)
# ════════════════════════════════════════════════════════════════

class TestVPNEndpoints:
    def test_summary(self):
        with _client() as c:
            r = c.get("/api/vpn/summary")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_list_empty(self):
        with _client() as c:
            r = c.get("/api/vpn/profiles")
        assert r.json()["profiles"] == []

    def test_create_redacts_config(self):
        with _client() as c:
            r = c.post("/api/vpn/profiles", json={
                "name": "wg0", "protocol": "wireguard", "config": WG_CONF})
        assert r.status_code == 201
        pub = r.json()["profile"]
        assert "aGVsbG8" not in pub["config"]
        assert pub["protocol"] == "wireguard"

    def test_create_invalid_400(self):
        with _client() as c:
            r = c.post("/api/vpn/profiles", json={
                "name": "wg0", "protocol": "pptp", "config": WG_CONF})
        assert r.status_code == 400

    def test_create_empty_config_400(self):
        with _client() as c:
            r = c.post("/api/vpn/profiles", json={
                "name": "wg0", "protocol": "wireguard", "config": ""})
        assert r.status_code == 400

    def test_get_and_delete(self):
        with _client() as c:
            vid = c.post("/api/vpn/profiles", json={
                "name": "wg0", "protocol": "wireguard", "config": WG_CONF}).json()["profile"]["vid"]
            g = c.get(f"/api/vpn/profiles/{vid}")
            d = c.delete(f"/api/vpn/profiles/{vid}")
            gone = c.get(f"/api/vpn/profiles/{vid}")
        assert g.status_code == 200
        assert d.json()["deleted"] == vid
        assert gone.status_code == 404

    def test_delete_missing_404(self):
        with _client() as c:
            assert c.delete("/api/vpn/profiles/nope").status_code == 404

    def test_activate_not_found_404(self):
        with _client() as c:
            assert c.post("/api/vpn/profiles/nope/activate").status_code == 404

    def test_activate_ok(self):
        with _client() as c:
            vid = c.post("/api/vpn/profiles", json={
                "name": "wg0", "protocol": "wireguard", "config": WG_CONF}).json()["profile"]["vid"]
            with patch.object(vp, "run_on_host", return_value=("", "", 0)):
                r = c.post(f"/api/vpn/profiles/{vid}/activate")
        assert r.status_code == 200
        assert r.json()["ok"] is True

    def test_deactivate(self):
        with patch.object(vp, "run_on_host", return_value=("", "", 0)):
            with _client() as c:
                r = c.post("/api/vpn/deactivate")
        assert r.status_code == 200
        assert r.json()["cleared"] is True

    def test_ip_endpoint(self):
        with patch.object(vp, "public_ip", return_value={"ok": True, "ip": "8.8.8.8"}):
            with _client() as c:
                r = c.get("/api/vpn/ip")
        assert r.json()["ip"] == "8.8.8.8"

    def test_status_endpoint(self):
        with patch.object(vp, "public_ip", return_value={"ok": True, "ip": "1.1.1.1"}):
            with _client() as c:
                r = c.get("/api/vpn/status")
        assert r.status_code == 200
        assert r.json()["current_ip"]["ip"] == "1.1.1.1"

    def test_endpoints_degrade_when_module_unavailable(self):
        with patch("backend.main.vpn", None):
            with _client() as c:
                assert c.get("/api/vpn/summary").status_code == 500
                assert c.get("/api/vpn/profiles").status_code == 500
                assert c.post("/api/vpn/profiles", json={}).status_code == 500
                assert c.get("/api/vpn/profiles/x").status_code == 500
                assert c.delete("/api/vpn/profiles/x").status_code == 500
                assert c.post("/api/vpn/profiles/x/activate").status_code == 500
                assert c.post("/api/vpn/deactivate").status_code == 500
                assert c.get("/api/vpn/ip").status_code == 500
