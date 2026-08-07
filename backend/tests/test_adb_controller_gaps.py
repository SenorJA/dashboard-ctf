"""
Coverage-gap tests for backend/adb_controller.py.

Covers:
  - _get_ssh: successful fallback import via mobile_analyzer
"""

import types
from unittest.mock import patch

from backend.adb_controller import _get_ssh


class TestGetSshSuccessFallback:
    def test_returns_client_from_mobile_analyzer(self):
        fake_client = object()
        # backend.main exists but lacks get_active_ssh_client -> AttributeError
        fake_main = types.ModuleType("backend.main")
        with patch.dict("sys.modules", {"backend.main": fake_main}):
            with patch("backend.mobile_analyzer.get_ssh_client", return_value=fake_client):
                assert _get_ssh() is fake_client

    def test_returns_client_from_main(self):
        fake_client = object()
        fake_main = types.ModuleType("backend.main")
        fake_main.get_active_ssh_client = lambda: fake_client
        with patch.dict("sys.modules", {"backend.main": fake_main}):
            assert _get_ssh() is fake_client
