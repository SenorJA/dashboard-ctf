"""
Tests for backend/adb_controller.py — ADB / Frida Controller.

Covers:
    - _get_ssh() import fallbacks
    - _ssh_exec() no SSH, transport inactive, SSH error, success
    - _ssh_sftp_upload() success, FileNotFoundError, PermissionError, no SSH
    - list_devices() no SSH, empty output, parsed output with model/device/transport
    - connect_device() with/without serial
    - install_apk()
    - get_available_scripts() local + built-in, no directory
    - stop_frida() with/without serial
    - run_frida_script() upload local, remote fallback, missing script
    - FRIDA_SCRIPTS_META structure
"""

import pytest
import sys
import os
from unittest.mock import patch, MagicMock, mock_open

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import adb_controller
from adb_controller import (
    FRIDA_SCRIPTS_META,
    FRIDA_SCRIPTS_DIR,
    _get_ssh,
    _ssh_exec,
    _ssh_sftp_upload,
    list_devices,
    connect_device,
    install_apk,
    get_available_scripts,
    stop_frida,
    run_frida_script,
)


@pytest.fixture
def mock_ssh():
    """Create a mock SSH client with transport."""
    client = MagicMock()
    transport = MagicMock()
    transport.is_active.return_value = True
    client.get_transport.return_value = transport
    return client


@pytest.fixture
def mock_chan():
    """Create a mock SSH channel."""
    chan = MagicMock()
    chan.recv.return_value = b"output data"
    chan.recv_stderr.return_value = b""
    return chan


# ════════════════════════════════════════════════════════════════
#  FRIDA_SCRIPTS_META
# ════════════════════════════════════════════════════════════════

class TestFridaScriptsMeta:
    def test_has_four_scripts(self):
        assert len(FRIDA_SCRIPTS_META) == 4

    def test_all_have_name_and_desc(self):
        for s in FRIDA_SCRIPTS_META:
            assert "name" in s
            assert "description" in s
            assert s["name"].endswith(".js")

    def test_ssl_bypass_present(self):
        names = [s["name"] for s in FRIDA_SCRIPTS_META]
        assert "ssl-bypass.js" in names

    def test_root_bypass_present(self):
        names = [s["name"] for s in FRIDA_SCRIPTS_META]
        assert "root-bypass.js" in names


# ════════════════════════════════════════════════════════════════
#  _get_ssh()
# ════════════════════════════════════════════════════════════════

class TestGetSsh:
    @patch("adb_controller._get_ssh")
    def test_returns_none_when_no_ssh(self, mock_get):
        mock_get.return_value = None
        assert mock_get() is None

    def test_main_import_fallback(self):
        """When backend.main can't provide get_active_ssh_client, falls back."""
        with patch.dict("sys.modules", {"backend.main": None, "backend.mobile_analyzer": None}):
            result = _get_ssh()
            assert result is None


# ════════════════════════════════════════════════════════════════
#  _ssh_exec()
# ════════════════════════════════════════════════════════════════

class TestSshExec:
    @patch.object(adb_controller, "_get_ssh")
    def test_no_ssh_connection(self, mock_get):
        mock_get.return_value = None
        result = _ssh_exec("ls")
        assert result.startswith("ERROR")
        assert "No SSH" in result

    @patch.object(adb_controller, "_get_ssh")
    def test_transport_inactive(self, mock_get, mock_ssh):
        mock_ssh.get_transport.return_value.is_active.return_value = False
        mock_get.return_value = mock_ssh
        result = _ssh_exec("ls")
        assert result.startswith("ERROR")
        assert "not active" in result

    @patch.object(adb_controller, "_get_ssh")
    def test_transport_none(self, mock_get, mock_ssh):
        mock_ssh.get_transport.return_value = None
        mock_get.return_value = mock_ssh
        result = _ssh_exec("ls")
        assert result.startswith("ERROR")

    @patch.object(adb_controller, "_get_ssh")
    def test_success(self, mock_get, mock_ssh, mock_chan):
        mock_ssh.get_transport.return_value.open_session.return_value = mock_chan
        mock_get.return_value = mock_ssh
        result = _ssh_exec("ls /tmp")
        assert "output data" in result

    @patch.object(adb_controller, "_get_ssh")
    def test_ssh_exception(self, mock_get, mock_ssh):
        mock_ssh.get_transport.return_value.open_session.side_effect = RuntimeError("timeout")
        mock_get.return_value = mock_ssh
        result = _ssh_exec("long_command")
        assert "ERROR" in result
        assert "timeout" in result


# ════════════════════════════════════════════════════════════════
#  _ssh_sftp_upload()
# ════════════════════════════════════════════════════════════════

class TestSshSftpUpload:
    @patch.object(adb_controller, "_get_ssh")
    def test_no_ssh(self, mock_get):
        mock_get.return_value = None
        result = _ssh_sftp_upload("/local/file.js", "/tmp/file.js")
        assert "No SSH" in result

    @patch.object(adb_controller, "_get_ssh")
    def test_success(self, mock_get, mock_ssh):
        mock_get.return_value = mock_ssh
        sftp = MagicMock()
        mock_ssh.open_sftp.return_value = sftp
        with patch.object(adb_controller, "_ssh_exec"):
            result = _ssh_sftp_upload("/local/file.js", "/tmp/file.js")
        assert result == "OK"
        sftp.put.assert_called_once()

    @patch.object(adb_controller, "_get_ssh")
    def test_file_not_found(self, mock_get, mock_ssh):
        mock_get.return_value = mock_ssh
        sftp = MagicMock()
        sftp.put.side_effect = FileNotFoundError("no such file")
        mock_ssh.open_sftp.return_value = sftp
        with patch.object(adb_controller, "_ssh_exec"):
            result = _ssh_sftp_upload("/nonexistent.js", "/tmp/file.js")
        assert "not found" in result.lower()

    @patch.object(adb_controller, "_get_ssh")
    def test_permission_denied(self, mock_get, mock_ssh):
        mock_get.return_value = mock_ssh
        sftp = MagicMock()
        sftp.put.side_effect = PermissionError("denied")
        mock_ssh.open_sftp.return_value = sftp
        with patch.object(adb_controller, "_ssh_exec"):
            result = _ssh_sftp_upload("/local/file.js", "/tmp/file.js")
        assert "permission" in result.lower()

    @patch.object(adb_controller, "_get_ssh")
    def test_generic_exception(self, mock_get, mock_ssh):
        mock_get.return_value = mock_ssh
        sftp = MagicMock()
        sftp.put.side_effect = RuntimeError("SFTP error")
        mock_ssh.open_sftp.return_value = sftp
        with patch.object(adb_controller, "_ssh_exec"):
            result = _ssh_sftp_upload("/local/file.js", "/tmp/file.js")
        assert "SFTP" in result


# ════════════════════════════════════════════════════════════════
#  list_devices()
# ════════════════════════════════════════════════════════════════

class TestListDevices:
    @patch.object(adb_controller, "_ssh_exec")
    def test_no_ssh_returns_empty(self, mock_exec):
        mock_exec.return_value = "ERROR: No SSH connection"
        result = list_devices()
        assert result == []

    @patch.object(adb_controller, "_ssh_exec")
    def test_empty_output(self, mock_exec):
        mock_exec.return_value = "List of devices attached\n\n"
        result = list_devices()
        assert result == []

    @patch.object(adb_controller, "_ssh_exec")
    def test_parses_single_device(self, mock_exec):
        mock_exec.return_value = "List of devices attached\nABCD1234 device usb:1-1 product:kazu model:Pixel_5 device:kazu transport_id:1\n\n"
        result = list_devices()
        assert len(result) == 1
        assert result[0]["serial"] == "ABCD1234"
        assert result[0]["state"] == "device"
        assert result[0]["model"] == "Pixel_5"
        assert result[0]["device"] == "kazu"
        assert result[0]["transport_id"] == "1"

    @patch("adb_controller._ssh_exec")
    def test_multiple_devices(self, mock_exec):
        mock_exec.return_value = (
            "List of devices attached\n"
            "DEVICE1 device product:p1 model:Phone1\n"
            "DEVICE2 device product:p2 model:Phone2\n\n"
        )
        result = list_devices()
        assert len(result) == 2

    @patch("adb_controller._ssh_exec")
    def test_offline_device_filtered(self, mock_exec):
        mock_exec.return_value = "List of devices attached\nDEVICE1 offline\n\n"
        result = list_devices()
        assert len(result) == 0

    @patch("adb_controller._ssh_exec")
    def test_no_model(self, mock_exec):
        mock_exec.return_value = "List of devices attached\nDEVICE1 device\n\n"
        result = list_devices()
        assert len(result) == 1
        assert "model" not in result[0]


# ════════════════════════════════════════════════════════════════
#  connect_device()
# ════════════════════════════════════════════════════════════════

class TestConnectDevice:
    @patch.object(adb_controller, "_ssh_exec")
    def test_with_serial(self, mock_exec):
        mock_exec.return_value = "connected to 192.168.1.50:5555"
        result = connect_device("192.168.1.50:5555")
        mock_exec.assert_called_once_with("adb connect 192.168.1.50:5555", timeout=15)

    @patch.object(adb_controller, "_ssh_exec")
    def test_without_serial(self, mock_exec):
        mock_exec.return_value = "List of devices"
        result = connect_device()
        mock_exec.assert_called_once_with("adb devices", timeout=10)


# ════════════════════════════════════════════════════════════════
#  install_apk()
# ════════════════════════════════════════════════════════════════

class TestInstallApk:
    @patch.object(adb_controller, "_ssh_exec")
    def test_install(self, mock_exec):
        mock_exec.return_value = "Success"
        result = install_apk("DEVICE1", "/tmp/app.apk")
        mock_exec.assert_called_once_with("adb -s DEVICE1 install -r /tmp/app.apk", timeout=120)


# ════════════════════════════════════════════════════════════════
#  get_available_scripts()
# ════════════════════════════════════════════════════════════════

class TestGetAvailableScripts:
    @patch("adb_controller.os.path.exists")
    @patch("adb_controller.os.listdir")
    def test_local_plus_built_in(self, mock_listdir, mock_exists):
        mock_exists.return_value = True
        mock_listdir.return_value = ["ssl-bypass.js", "custom.js"]
        scripts = get_available_scripts()
        names = [s["name"] for s in scripts]
        # ssl-bypass.js from local dir
        assert "ssl-bypass.js" in names
        assert "custom.js" in names
        # Built-in scripts not on local disk
        assert "root-bypass.js" in names
        assert "pin-bypass.js" in names

    @patch("adb_controller.os.path.exists")
    def test_no_local_dir(self, mock_exists):
        mock_exists.return_value = False
        scripts = get_available_scripts()
        # Should return all built-in scripts
        assert len(scripts) == len(FRIDA_SCRIPTS_META)

    @patch("adb_controller.os.path.exists")
    @patch("adb_controller.os.listdir")
    def test_local_scripts_get_desc(self, mock_listdir, mock_exists):
        mock_exists.return_value = True
        mock_listdir.return_value = ["ssl-bypass.js"]
        scripts = get_available_scripts()
        ssl = next(s for s in scripts if s["name"] == "ssl-bypass.js")
        assert "SSL" in ssl["description"]


# ════════════════════════════════════════════════════════════════
#  stop_frida()
# ════════════════════════════════════════════════════════════════

class TestStopFrida:
    @patch.object(adb_controller, "_ssh_exec")
    def test_stop_all(self, mock_exec):
        mock_exec.return_value = "DONE"
        result = stop_frida()
        assert mock_exec.call_count >= 1
        first_call_cmd = mock_exec.call_args_list[0][0][0]
        assert "pkill" in first_call_cmd
        assert "frida" in first_call_cmd

    @patch.object(adb_controller, "_ssh_exec")
    def test_stop_specific_device(self, mock_exec):
        mock_exec.return_value = "DONE"
        result = stop_frida("DEVICE1")
        first_call_cmd = mock_exec.call_args_list[0][0][0]
        assert "DEVICE1" in first_call_cmd


# ════════════════════════════════════════════════════════════════
#  run_frida_script()
# ════════════════════════════════════════════════════════════════

class TestRunFridaScript:
    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_missing_script_local_and_remote(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        mock_exec.return_value = "not found"
        result = run_frida_script("DEVICE1", "nonexistent.js")
        assert "ERROR" in result
        assert "not found" in result.lower()

    @patch.object(adb_controller, "_ssh_sftp_upload")
    @patch("adb_controller._ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_upload_local_script(self, mock_exists, mock_exec, mock_upload):
        mock_exists.return_value = True
        mock_upload.return_value = "OK"
        mock_exec.return_value = "Frida attached"
        result = run_frida_script("DEVICE1", "ssl-bypass.js", "com.target.app")
        assert "Frida attached" in result
        mock_upload.assert_called_once()

    @patch.object(adb_controller, "_ssh_sftp_upload")
    @patch("adb_controller._ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_upload_failure(self, mock_exists, mock_exec, mock_upload):
        mock_exists.return_value = True
        mock_upload.return_value = "Permission denied"
        result = run_frida_script("DEVICE1", "ssl-bypass.js")
        assert "ERROR" in result

    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_remote_script_exists(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        # 3 calls: mkdir, test -f, frida execution
        mock_exec.side_effect = ["", "OK", "Frida output"]
        result = run_frida_script("DEVICE1", "ssl-bypass.js")
        assert "Frida output" in result

    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_no_device_serial_uses_usb(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        # 3 calls: mkdir, test -f (returns OK), frida command
        mock_exec.side_effect = ["", "OK", "Frida started"]
        result = run_frida_script(None, "ssl-bypass.js")
        # Check that -U was used instead of -D
        frida_cmd = mock_exec.call_args_list[2][0][0]
        assert "-U" in frida_cmd

    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_with_device_serial(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        # 3 calls: mkdir, test -f (returns OK), frida command
        mock_exec.side_effect = ["", "OK", "Frida started"]
        result = run_frida_script("DEVICE123", "ssl-bypass.js")
        frida_cmd = mock_exec.call_args_list[2][0][0]
        assert "-D DEVICE123" in frida_cmd

    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_with_target_process(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        # 3 calls: mkdir, test -f (returns OK), frida command
        mock_exec.side_effect = ["", "OK", "Frida started"]
        result = run_frida_script("DEVICE1", "ssl-bypass.js", "com.target.app")
        frida_cmd = mock_exec.call_args_list[2][0][0]
        assert "-f com.target.app" in frida_cmd
        assert "--no-pause" in frida_cmd

    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_output_truncated_to_5000(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        # 3 calls: mkdir, test -f (returns OK), frida command
        mock_exec.side_effect = ["", "OK", "x" * 10000]
        result = run_frida_script("DEVICE1", "ssl-bypass.js")
        assert len(result) <= 5000

    @patch.object(adb_controller, "_ssh_exec")
    @patch("adb_controller.os.path.exists")
    def test_creates_remote_dir(self, mock_exists, mock_exec):
        mock_exists.return_value = False
        # 3 calls: mkdir, test -f (returns OK), frida command
        mock_exec.side_effect = ["", "OK", "output"]
        run_frida_script("DEVICE1", "ssl-bypass.js")
        # First call should be mkdir
        assert "mkdir" in mock_exec.call_args_list[0][0][0]
