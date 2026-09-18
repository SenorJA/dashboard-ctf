"""
api_auth.py -- MIRV Module

Opt-in API token authentication for the ``/api/*`` namespace.

When a token is configured the guard is active and every request under
``/api/*`` (minus a tiny exempt whitelist) must present it through one of:

* ``Authorization: Bearer <token>``
* ``X-MIRV-Token: <token>``
* the ``mirv_token`` cookie (set automatically when serving the SPA at
  ``/``, so the browser frontend keeps working unchanged)

Configuration (first that applies wins):

* env var ``MIRV_API_TOKEN``, or
* the file at env var ``MIRV_API_TOKEN_FILE`` (default
  ``backend/data/api_token.txt``) — first non-empty line.

When nothing is configured the guard is disabled and the app behaves as
before (local single-operator tool). This keeps the hermetic test-suite
green and follows the project's opt-in convention (``MIRV_PERSIST_WORKSPACE``).

The guard only covers HTTP requests; the ``/ws`` WebSocket keeps its own
JSON auth handshake.
"""

from __future__ import annotations

import hmac
import logging
import os
from typing import Optional

_logger = logging.getLogger("vulnforge.api_auth")

_TOKEN_ENV = "MIRV_API_TOKEN"
_FILE_ENV = "MIRV_API_TOKEN_FILE"
_DEFAULT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "api_token.txt")
COOKIE_NAME = "mirv_token"

# Public endpoints that never require a token (health probe + auth status).
EXEMPT_PATHS = ("/api/health", "/api/auth/status")


def configured_token() -> str:
    """Return the active token or '' when the guard is disabled."""
    token = os.getenv(_TOKEN_ENV, "").strip()
    if token:
        return token
    path = os.getenv(_FILE_ENV, _DEFAULT_FILE)
    try:
        with open(path, "r", encoding="utf-8") as fh:
            token = fh.read().strip()
    except FileNotFoundError:
        return ""
    except OSError as exc:  # pragma: no cover - defensive
        _logger.warning("api_auth: cannot read token file '%s': %s", path, exc)
        return ""
    return token.splitlines()[0].strip() if token else ""


def token_source() -> str:
    """Where the active token comes from ('' when disabled)."""
    if os.getenv(_TOKEN_ENV, "").strip():
        return "env"
    if os.getenv(_FILE_ENV, "").strip():
        path = os.getenv(_FILE_ENV, _DEFAULT_FILE)
    else:
        path = _DEFAULT_FILE
    if os.path.isfile(path):
        return "file"
    return ""


def is_enabled() -> bool:
    return bool(configured_token())


def is_exempt(path: str) -> bool:
    return any(path == p or path.startswith(p + "/") for p in EXEMPT_PATHS)


def check(token: Optional[str]) -> bool:
    """Constant-time comparison. Always True when the guard is disabled."""
    expected = configured_token()
    if not expected:
        return True
    if not token:
        return False
    return hmac.compare_digest(token, expected)


def request_token(request_headers, cookies: Optional[dict] = None) -> Optional[str]:
    """Extract the presented token from headers/cookies (lowercase-safe)."""
    auth = (request_headers.get("authorization") or "").strip()
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    xt = (request_headers.get("x-mirv-token") or "").strip()
    if xt:
        return xt
    if cookies:
        token = cookies.get(COOKIE_NAME)
        if token:
            return str(token).strip()
    return None


def mask(token: str) -> str:
    """Human-friendly masked form (keeps first/last chars)."""
    if not token:
        return ""
    if len(token) <= 8:
        return "••••••••"
    return f"{token[:4]}•••{token[-4:]}"