"""Tests for backend/mobile_analyzer.py — static APK analysis.

All tests are offline: parsers are exercised with literal strings and
temporary directories; SSH/apktool/aapt paths are mocked with MagicMock.
"""

import os
import subprocess

import pytest
from unittest.mock import MagicMock, patch

import mobile_analyzer as mobile


@pytest.fixture(autouse=True)
def _clean_globals():
    """Reset module-level state between tests."""
    mobile._apk_store.clear()
    mobile._work_dir = "/tmp/vulnforge_mobile"
    mobile._ssh_client = None
    yield
    mobile._apk_store.clear()
    mobile._ssh_client = None


# ──────────────────────────────────────────────
# SSH client management
# ──────────────────────────────────────────────

def test_set_get_ssh_client():
    fake = object()
    mobile.set_ssh_client(fake)
    assert mobile.get_ssh_client() is fake
    mobile.set_ssh_client(None)
    assert mobile.get_ssh_client() is None


def test_init_work_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "makedirs", lambda *a, **k: None)
    target = str(tmp_path / "mobile")
    assert mobile.init_work_dir(target) == target


def test_init_work_dir_oserror_fallback():
    with patch("os.makedirs", side_effect=[OSError("denied"), None]):
        result = mobile.init_work_dir("/proc/denied/vulnforge")
    assert "tmp" in result and "mobile" in result


# ──────────────────────────────────────────────
# Command execution helpers
# ──────────────────────────────────────────────

def test_run_cmd_local_success():
    with patch("subprocess.run") as run:
        run.return_value.stdout = "out"
        run.return_value.stderr = ""
        assert mobile._run_cmd_local(["ls"]) == ("out", "")


def test_run_cmd_local_timeout():
    with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 60)):
        assert mobile._run_cmd_local(["sleep", "999"]) == ("", "TIMEOUT")


def test_run_cmd_local_not_found():
    with patch("subprocess.run", side_effect=FileNotFoundError(2, "no", "aapt")):
        out, err = mobile._run_cmd_local(["aapt"])
        assert "Tool not found: aapt" in err


def test_run_cmd_local_generic_error():
    with patch("subprocess.run", side_effect=RuntimeError("boom")):
        out, err = mobile._run_cmd_local(["x"])
        assert "boom" in err


def _fake_client():
    client = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    chan = MagicMock()
    chan.recv.return_value = b"remote stdout"
    chan.recv_stderr.return_value = b"remote stderr"
    client.get_transport.return_value = transport
    transport.open_session.return_value = chan
    return client


def test_run_cmd_remote_no_client():
    out, err = mobile._run_cmd_remote("ls")
    assert out == "" and "No SSH connection" in err


def test_run_cmd_remote_transport_closed():
    client = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = False
    client.get_transport.return_value = transport
    mobile.set_ssh_client(client)
    out, err = mobile._run_cmd_remote("ls")
    assert out == "" and "transport closed" in err


def test_run_cmd_remote_success():
    client = _fake_client()
    mobile.set_ssh_client(client)
    out, err = mobile._run_cmd_remote("ls /tmp")
    assert out == "remote stdout"
    assert err == "remote stderr"


def test_run_cmd_remote_exception():
    client = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    chan = MagicMock()
    chan.exec_command.side_effect = RuntimeError("conn lost")
    client.get_transport.return_value = transport
    transport.open_session.return_value = chan
    mobile.set_ssh_client(client)
    out, err = mobile._run_cmd_remote("ls")
    assert out == "" and "conn lost" in err


def test_run_cmd_string_local_when_no_ssh():
    with patch.object(mobile, "_run_cmd_local", return_value=("", "")) as local:
        mobile._run_cmd("ls -la /tmp", use_ssh=True)
    local.assert_called_once_with(["ls", "-la", "/tmp"], 60)


def test_run_cmd_string_remote_when_ssh():
    client = _fake_client()
    mobile.set_ssh_client(client)
    with patch.object(mobile, "_run_cmd_remote", return_value=("", "")) as remote:
        mobile._run_cmd("ls -la /tmp", use_ssh=True)
    remote.assert_called_once_with("ls -la /tmp", 60)


def test_run_cmd_list_local_first():
    with patch.object(mobile, "_run_cmd_local", return_value=("out", "")) as local:
        assert mobile._run_cmd(["ls", "/tmp"]) == ("out", "")
    local.assert_called_once()


def test_run_cmd_list_fallback_ssh():
    client = _fake_client()
    mobile.set_ssh_client(client)
    with patch.object(mobile, "_run_cmd_local", return_value=("", "Tool not found: apktool")), \
         patch.object(mobile, "_run_cmd_remote", return_value=("remote", "")) as remote:
        out, err = mobile._run_cmd(["apktool", "d"])
    assert out == "remote"
    remote.assert_called_once_with("apktool d", 60)


def test_ssh_upload_no_client():
    assert mobile._ssh_upload_file("a", "b") is False


def test_ssh_upload_success():
    client = MagicMock()
    sftp = MagicMock()
    client.open_sftp.return_value = sftp
    mobile.set_ssh_client(client)
    assert mobile._ssh_upload_file("a", "b") is True
    sftp.put.assert_called_once_with("a", "b")
    sftp.close.assert_called_once()


def test_ssh_upload_error():
    client = MagicMock()
    sftp = MagicMock()
    sftp.put.side_effect = OSError("disk full")
    client.open_sftp.return_value = sftp
    mobile.set_ssh_client(client)
    assert mobile._ssh_upload_file("a", "b") is False


def test_ssh_download_no_client():
    assert mobile._ssh_download_file("a", "b") is False


def test_ssh_download_success():
    client = MagicMock()
    sftp = MagicMock()
    client.open_sftp.return_value = sftp
    mobile.set_ssh_client(client)
    assert mobile._ssh_download_file("a", "b") is True
    sftp.get.assert_called_once_with("a", "b")


def test_ssh_download_error():
    client = MagicMock()
    sftp = MagicMock()
    sftp.get.side_effect = OSError("gone")
    client.open_sftp.return_value = sftp
    mobile.set_ssh_client(client)
    assert mobile._ssh_download_file("a", "b") is False


# ──────────────────────────────────────────────
# Hashing & parsing
# ──────────────────────────────────────────────

def test_compute_hashes(tmp_path):
    f = tmp_path / "app.apk"
    f.write_bytes(b"hello-apk-content")
    h = mobile._compute_hashes(str(f))
    assert len(h["md5"]) == 32
    assert len(h["sha256"]) == 64
    assert h["sha256"] == mobile._compute_hashes(str(f))["sha256"]


def test_parse_aapt_output():
    out = (
        "package: name='com.test.app' versionCode='2' versionName='1.1'\n"
        "sdkVersion:'23'\n"
        "targetSdkVersion:'33'\n"
        "application-label:'Test'\n"
    )
    info = mobile._parse_aapt_output(out)
    assert info["package"] == "com.test.app"
    assert info["version_code"] == "2"
    assert info["version_name"] == "1.1"
    assert info["min_sdk"] == "23"
    assert info["target_sdk"] == "33"


def test_parse_aapt_output_empty():
    assert mobile._parse_aapt_output("") == {}


def test_parse_manifest_permissions(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<manifest><uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission android:name="android.permission.INTERNET"/>'
        '<uses-permission android:name="android.permission.CAMERA"/></manifest>'
    )
    perms = mobile._parse_manifest_for_permissions(str(manifest))
    assert perms == ["CAMERA", "INTERNET"]


def test_parse_manifest_permissions_missing(tmp_path):
    assert mobile._parse_manifest_for_permissions(str(tmp_path / "nope.xml")) == []


def test_parse_manifest_components(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<activity android:name=".Main" android:exported="true"/>'
        '<service android:name=".Svc" android:exported="false"/>'
        '<provider android:name=".Prov" android:exported="true"/>'
        '<receiver android:name=".Recv"/>'
    )
    comps = mobile._parse_manifest_components(str(manifest))
    assert comps["activities"] == [{"name": ".Main", "exported": True}]
    assert comps["services"] == [{"name": ".Svc", "exported": False}]
    assert comps["providers"] == [{"name": ".Prov", "exported": True}]
    assert comps["receivers"] == [{"name": ".Recv", "exported": False}]


def test_parse_manifest_components_missing(tmp_path):
    comps = mobile._parse_manifest_components(str(tmp_path / "nope.xml"))
    assert comps == {"activities": [], "services": [], "providers": [], "receivers": []}


def test_walk_smali_files(tmp_path):
    smali = tmp_path / "smali"
    (smali / "a").mkdir(parents=True)
    (smali / "a" / "one.smali").write_text("class A")
    (smali / "two.txt").write_text("not smali")
    found = list(mobile._walk_smali_files(str(smali)))
    assert len(found) == 1
    path, rel, content = found[0]
    assert path.endswith("one.smali")
    assert rel == os.path.join("a", "one.smali")
    assert content == "class A"


def test_walk_smali_files_missing(tmp_path):
    assert list(mobile._walk_smali_files(str(tmp_path / "no"))) == []


# ──────────────────────────────────────────────
# Vulnerability checks
# ──────────────────────────────────────────────

def _smali_dir(tmp_path, lines):
    d = tmp_path / "smali"
    d.mkdir(parents=True)
    (d / "App.smali").write_text("\n".join(lines))
    return str(d)


def test_check_webview_insecurities(tmp_path):
    smali = _smali_dir(tmp_path, [
        "setJavaScriptEnabled(true)",
        "setAllowFileAccess(true)",
    ])
    findings = mobile._check_webview_insecurities(smali)
    titles = {f["title"] for f in findings}
    assert "WebView with JavaScript Enabled" in titles
    assert "WebView with File Access" in titles


def test_check_secrets_in_smali(tmp_path):
    smali = _smali_dir(tmp_path, [
        'const-string v0, "api_key = \'sk-123456789012345678901234567890\'"',
        "invoke-static {}, Lfoo;->bar()V",
    ])
    findings = mobile._check_secrets_in_smali(smali)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "critical"
    assert "API Key" in findings[0]["title"] or "OpenAI" in findings[0]["title"]


def test_check_weak_crypto(tmp_path):
    smali = _smali_dir(tmp_path, ['Cipher.getInstance("DESede(ECB)")'])
    findings = mobile._check_weak_crypto(smali)
    assert len(findings) == 1
    assert findings[0]["category"] == "crypto"


def test_check_root_detection(tmp_path):
    smali = _smali_dir(tmp_path, ["magisk", "const-string v0, \"normal\""])
    findings = mobile._check_root_detection(smali)
    assert len(findings) == 1
    assert findings[0]["severity"] == "info"
    assert "Root Detection" in findings[0]["title"]


def test_check_ssl_pinning_present(tmp_path):
    smali = _smali_dir(tmp_path, ["CertificatePinner.builder()"])
    assert mobile._check_ssl_pinning(smali) == []


def test_check_ssl_pinning_absent(tmp_path):
    smali = _smali_dir(tmp_path, ["const-string v0, \"hello\""])
    findings = mobile._check_ssl_pinning(smali)
    assert len(findings) == 1
    assert findings[0]["title"] == "No SSL Pinning Detected"


def test_check_manifest_flags(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text(
        '<application android:allowBackup="true" android:debuggable="true" '
        'android:usesCleartextTraffic="true"/>'
    )
    findings = mobile._check_manifest_flags(str(manifest))
    titles = {f["title"] for f in findings}
    assert "Backup Enabled (allowBackup)" in titles
    assert "App is Debuggable" in titles
    assert "Cleartext HTTP Traffic Allowed" in titles


def test_check_manifest_flags_missing(tmp_path):
    assert mobile._check_manifest_flags(str(tmp_path / "nope.xml")) == []


def test_check_strings_for_secrets_res_pattern(tmp_path):
    res = tmp_path / "res" / "values"
    res.mkdir(parents=True)
    (res / "strings.xml").write_text('<string name="k">api_key = "secret123"</string>')
    findings = mobile._check_strings_for_secrets(str(res))
    assert len(findings) == 1
    assert findings[0]["severity"] == "high"
    assert "Secret in Resources" in findings[0]["title"]


def test_check_strings_for_secrets_base64(tmp_path):
    res = tmp_path / "res" / "values"
    res.mkdir(parents=True)
    b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpBQkNERUZHSElK"  # 50 chars, decodable
    (res / "strings.xml").write_text(f'<string name="k">{b64}</string>')
    findings = mobile._check_strings_for_secrets(str(res))
    assert any("Base64" in f["title"] for f in findings)


def test_check_strings_for_secrets_bad_base64(tmp_path):
    res = tmp_path / "res" / "values"
    res.mkdir(parents=True)
    # 45 chars — invalid base64 length → binascii.Error → except → pass
    (res / "bad.xml").write_text(
        '<string name="k">AAAAABBBBBCCCCCDDDDDEEEEEFGGGGGHHHHHIIIII</string>'
    )
    assert mobile._check_strings_for_secrets(str(res)) == []


def test_check_strings_for_secrets_missing(tmp_path):
    assert mobile._check_strings_for_secrets(str(tmp_path / "no")) == []


# ──────────────────────────────────────────────
# analyze_apk — full local pipeline
# ──────────────────────────────────────────────

def _build_extracted_apk(tmp_path, apk_id):
    extract_dir = tmp_path / f"extract_{apk_id}"
    (extract_dir / "smali").mkdir(parents=True)
    (extract_dir / "res" / "values").mkdir(parents=True)
    (extract_dir / "AndroidManifest.xml").write_text(
        '<manifest>'
        '<uses-permission android:name="android.permission.CAMERA"/>'
        '<uses-permission android:name="android.permission.INTERNET"/>'
        '<application android:allowBackup="true" android:debuggable="true" '
        'android:usesCleartextTraffic="true">'
        '<activity android:name=".Main" android:exported="true"/></application>'
        '</manifest>'
    )
    (extract_dir / "smali" / "App.smali").write_text(
        "setJavaScriptEnabled(true)\n"
        'const-string v0, "api_key = \'sk-123456789012345678901234567890\'"\n'
        'Cipher.getInstance("DESede(ECB)")\n'
        "const-string v0, \"hello\"\n"
    )
    (extract_dir / "res" / "values" / "strings.xml").write_text(
        '<string name="k">QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpBQkNERUZHSElK</string>'
    )
    return extract_dir


def test_analyze_apk_local_full(tmp_path, monkeypatch):
    mobile._work_dir = str(tmp_path)
    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PK\x03\x04fake-apk-bytes" * 20)
    _build_extracted_apk(tmp_path, "apk1")

    aapt_out = (
        "package: name='com.test.app' versionCode='2' versionName='1.1'\n"
        "sdkVersion:'23'\n"
        "targetSdkVersion:'33'\n"
    )

    def fake_local(cmd, timeout=60):
        if cmd[0] == "aapt":
            return aapt_out, ""
        return "", ""  # apktool

    monkeypatch.setattr(mobile, "_run_cmd_local", fake_local)

    result = mobile.analyze_apk(str(apk_path), "apk1")

    assert result["apk_id"] == "apk1"
    assert result["package"] == "com.test.app"
    assert result["version_name"] == "1.1"
    assert result["min_sdk"] == "23"
    assert result["target_sdk"] == "33"
    assert result["md5"] and result["sha256"]
    assert result["filename"] == "app.apk"
    assert result["permissions"] == ["CAMERA", "INTERNET"]
    assert result["components"]["activities"] == [{"name": ".Main", "exported": True}]

    titles = {f["title"] for f in result["findings"]}
    assert "Exported Activity: .Main" in titles
    assert "Backup Enabled (allowBackup)" in titles
    assert "App is Debuggable" in titles
    assert "Cleartext HTTP Traffic Allowed" in titles
    assert "WebView with JavaScript Enabled" in titles
    assert any("API Key" in t or "OpenAI" in t for t in titles)
    assert "Weak Cryptography Algorithm" in titles
    assert "No SSL Pinning Detected" in titles
    assert "Dangerous Permission: CAMERA" in titles

    assert result["summary"]["high"] >= 2
    assert result["summary"]["medium"] >= 2

    # Stored + retrievable
    assert mobile.get_apk("apk1") is result
    assert any(a["apk_id"] == "apk1" for a in mobile.list_apks())


def test_analyze_apk_auto_generated_id(tmp_path, monkeypatch):
    mobile._work_dir = str(tmp_path)
    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PKfake" * 20)
    monkeypatch.setattr(mobile, "_run_cmd_local",
                        lambda cmd, timeout=60: ("", "boom"))
    result = mobile.analyze_apk(str(apk_path))
    assert result["apk_id"] and len(result["apk_id"]) == 8
    assert "apktool extraction failed" in result["error"]


def test_analyze_apk_cannot_read_file(tmp_path):
    result = mobile.analyze_apk(str(tmp_path / "missing.apk"), "nope1")
    assert result["error"].startswith("Cannot read file")
    assert mobile.get_apk("nope1") is result


def test_analyze_apk_apktool_failure(tmp_path, monkeypatch):
    mobile._work_dir = str(tmp_path)
    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PKfake" * 20)

    def fake_local(cmd, timeout=60):
        if cmd[0] == "aapt":
            return "package: name='com.x' versionName='1.0'\n", ""
        return "", "apktool: not found"

    monkeypatch.setattr(mobile, "_run_cmd_local", fake_local)
    result = mobile.analyze_apk(str(apk_path), "fail1")
    assert "apktool extraction failed" in result["error"]


def test_analyze_apk_ssh_remote(tmp_path, monkeypatch):
    mobile._work_dir = str(tmp_path)
    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PKfake" * 20)

    client = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    chan = MagicMock()
    chan.recv.return_value = b"\nremote\n\nstdout"
    chan.recv_stderr.return_value = b""
    client.get_transport.return_value = transport
    transport.open_session.return_value = chan
    mobile.set_ssh_client(client)

    monkeypatch.setattr(mobile, "_ssh_upload_file", lambda a, b: True)
    monkeypatch.setattr(mobile, "_ssh_download_file", lambda a, b: False)

    result = mobile.analyze_apk(str(apk_path), "ssh1")
    assert result["apk_id"] == "ssh1"
    assert result["md5"]
    # SSH path doesn't crash; findings may be empty (no manifest downloaded)
    assert "error" not in result or result["error"] is None


def test_analyze_apk_ssh_upload_fails_falls_back(tmp_path, monkeypatch):
    mobile._work_dir = str(tmp_path)
    apk_path = tmp_path / "app.apk"
    apk_path.write_bytes(b"PKfake" * 20)
    _build_extracted_apk(tmp_path, "fb1")

    client = MagicMock()
    mobile.set_ssh_client(client)

    def fake_upload(a, b):
        raise OSError("sftp down")

    monkeypatch.setattr(mobile, "_ssh_upload_file", fake_upload)
    monkeypatch.setattr(mobile, "_run_cmd_local",
                        lambda cmd, timeout=60: ("", ""))
    monkeypatch.setattr(mobile, "_run_cmd_remote", lambda cmd, timeout=60: ("", ""))

    result = mobile.analyze_apk(str(apk_path), "fb1")
    assert result["apk_id"] == "fb1"


# ──────────────────────────────────────────────
# CRUD helpers
# ──────────────────────────────────────────────

def test_list_apks_empty():
    assert mobile.list_apks() == []


def test_list_apks_summary_view():
    mobile._apk_store["a1"] = {
        "filename": "x.apk", "package": "com.x", "version_name": "1.0",
        "version_code": "1", "size": 42, "findings": [{"severity": "high"}],
        "summary": {"high": 1},
    }
    rows = mobile.list_apks()
    assert rows[0]["apk_id"] == "a1"
    assert rows[0]["findings_count"] == 1
    assert rows[0]["summary"] == {"high": 1}


def test_get_apk_missing():
    assert mobile.get_apk("zzz") is None


def test_delete_apk_missing():
    assert mobile.delete_apk("zzz") is False


def test_delete_apk_local(tmp_path):
    mobile._work_dir = str(tmp_path)
    mobile._apk_store["d1"] = {"filename": "x.apk"}
    (tmp_path / "extract_d1").mkdir()
    (tmp_path / "extract_d1" / "file.txt").write_text("x")
    assert mobile.delete_apk("d1") is True
    assert "d1" not in mobile._apk_store
    assert not (tmp_path / "extract_d1").exists()


def test_delete_apk_remote_cleanup(tmp_path, monkeypatch):
    mobile._work_dir = str(tmp_path)
    mobile._apk_store["r1"] = {"filename": "x.apk"}
    client = _fake_client()
    mobile.set_ssh_client(client)
    with patch.object(mobile, "_run_cmd_remote", return_value=("", "")) as remote:
        assert mobile.delete_apk("r1") is True
    assert remote.call_count == 2
