"""
instagram_osint.py -- MIRV Module

Public Instagram profile OSINT, ported from ``fawadqureshi007/ghostig``
(GhostIG — Silent Instagram OSINT) and adapted to the MIRV security-audit
style: stdlib ``urllib.request`` run through ``asyncio.to_thread``, hard
timeouts, 1 MiB response cap, never raises (returns ``{"ok": False, ...}``).

Ethics & scope:
  - **Public profile data only.** No scraping, no enumeration loops, no
    credential harvesting — one profile fetch + (optionally) one lookup
    per call.
  - The Instagram ``sessionid`` cookie comes from the **operator's own
    account** via the ``IG_SESSIONID`` environment variable. It is never
    hardcoded, never read from the frontend and never logged. When it is
    absent every function degrades to
    ``{"ok": False, "error": "IG_SESSIONID env var not configured",
    "code": "session_missing"}``.

Endpoints used (Instagram private API — internal, subject to change):
  - ``web_profile_info``  -> user id + basic user object (mobile UA)
  - ``users/{id}/info/``  -> full public profile object
  - ``users/lookup/``     -> optional obfuscated email/phone hint
    (``skip_lookup=False`` only)

All public functions are ``async``, never raise and return JSON-serializable
dicts. Blocking I/O runs via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any

# -- Logger (no secrets: never log the sessionid cookie) --
_logger = logging.getLogger("vulnforge.instagram_osint")

# ════════════════════════════════════════════════════════════════
#  Constants (mirror the ghostig upstream values)
# ════════════════════════════════════════════════════════════════

WEB_PROFILE_URL = "https://i.instagram.com/api/v1/users/web_profile_info/"
USER_INFO_URL = "https://i.instagram.com/api/v1/users/{user_id}/info/"
LOOKUP_URL = "https://i.instagram.com/api/v1/users/lookup/"

WEB_PROFILE_HEADERS = {
    "User-Agent": "iphone_ua",
    "x-ig-app-id": "936619743392459",
}
USER_INFO_HEADERS = {
    "User-Agent": "Instagram 64.0.0.14.96",
}
LOOKUP_HEADERS = {
    "Accept-Language": "en-US",
    "User-Agent": "Instagram 101.0.0.15.120",
    "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
    "X-IG-App-ID": "124024574287414",
    "Accept-Encoding": "gzip, deflate",
    "Host": "i.instagram.com",
    "Connection": "keep-alive",
}

DEFAULT_TIMEOUT = 15.0
_MAX_BYTES = 1_048_576  # cap responses at 1 MiB

# Fallback User-Agent when the upstream-specific headers do not set one.
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 MIRV-OSINT/1.0"
)

_SESSION_ENV = "IG_SESSIONID"

__all__ = [
    "DEFAULT_TIMEOUT",
    "USER_AGENT",
    "WEB_PROFILE_URL",
    "USER_INFO_URL",
    "LOOKUP_URL",
    "UserProfile",
    "LookupInsight",
    "get_instagram_profile",
    "instagram_lookup",
]


# ════════════════════════════════════════════════════════════════
#  Internal helpers
# ════════════════════════════════════════════════════════════════

def _get_session_id(session_id: str | None) -> str:
    """Resolve the session id: explicit arg first, env var fallback."""
    if session_id:
        return session_id.strip()
    return os.environ.get(_SESSION_ENV, "").strip()


def _with_cookie(headers: dict[str, str], session_id: str) -> dict[str, str]:
    """Attach the operator ``sessionid`` cookie to a headers dict.

    urllib has no cookie jar here; sending the header manually is the
    equivalent of ghostig's ``session.cookies.set("sessionid", ...)``.
    """
    return {**headers, "Cookie": f"sessionid={session_id}"}


def _urlopen_sync(url: str, timeout: float, headers: dict, method: str,
                  data: bytes | None) -> dict:
    """
    Blocking urllib request.  Run via ``asyncio.to_thread``.

    Returns an internal result dict — never raises:
      - success: ``{"ok": True, "status": int, "body": bytes}``
      - failure: ``{"ok": False, "status": int|None, "error": str, "body": bytes}``
    """
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — public OSINT only
            body = resp.read(_MAX_BYTES)
            return {"ok": True, "status": resp.status, "body": body}
    except urllib.error.HTTPError as e:  # noqa: PERF203
        try:
            err_body = e.read(_MAX_BYTES)
        except Exception:  # noqa: BLE001
            err_body = b""
        return {"ok": False, "status": e.code, "error": f"HTTP {e.code}", "body": err_body}
    except urllib.error.URLError as e:  # noqa: PERF203
        return {"ok": False, "status": None, "error": f"Network error: {e.reason}", "body": b""}
    except (socket.timeout, TimeoutError):  # noqa: PERF203
        return {"ok": False, "status": None, "error": f"Timeout after {timeout}s", "body": b""}
    except Exception as e:  # noqa: BLE001
        _logger.debug("instagram _urlopen_sync failed for %s: %s", url, e)
        return {"ok": False, "status": None, "error": str(e), "body": b""}


async def _fetch(url: str, timeout: float = DEFAULT_TIMEOUT,
                 headers: dict | None = None, method: str = "GET",
                 data: bytes | None = None) -> dict:
    """
    Fetch a URL (with a hard timeout) and JSON-parse the body.

    Returns ``{"ok": True, "status": int, "data": dict}`` on success or
    ``{"ok": False, "status": int|None, "error": str, "code": str|None,
    "body": str}`` on failure (HTTP error, network error, timeout or
    non-JSON/empty payload).  Never raises.
    """
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    raw = await asyncio.to_thread(_urlopen_sync, url, timeout, hdrs, method, data)
    status = raw.get("status")
    body = raw.get("body", b"")
    text = body.decode("utf-8", errors="replace") if body else ""
    if not raw.get("ok"):
        return {
            "ok": False,
            "status": status,
            "error": raw.get("error", "Request failed"),
            "code": None,
            "body": text,
        }
    if not text:
        return {
            "ok": False,
            "status": status,
            "error": "Instagram API returned an empty response",
            "code": "parse_error",
            "body": "",
        }
    try:
        parsed = json.loads(text)
    except (ValueError, TypeError):
        return {
            "ok": False,
            "status": status,
            "error": "Instagram API returned invalid JSON",
            "code": "parse_error",
            "body": text,
        }
    return {"ok": True, "status": status, "data": parsed}


def _http_error_result(resp: dict) -> dict:
    """
    Map a failed ``_fetch`` response to a structured MIRV error dict.

    HTTP 404  -> ``not_found``, 429 -> ``rate_limited``, other >=400 ->
    ``HTTP {code}``.  Parse/network errors keep their own message/code.
    """
    status = resp.get("status")
    if status == 404:
        return {"ok": False, "status": 404, "error": "User not found.", "code": "not_found"}
    if status == 429:
        return {"ok": False, "status": 429, "error": "Rate limit reached.", "code": "rate_limited"}
    if status is not None and status >= 400:
        return {"ok": False, "status": status, "error": f"HTTP {status}", "code": f"http_{status}"}
    return {
        "ok": False,
        "status": status,
        "error": resp.get("error", "Request failed"),
        "code": resp.get("code"),
    }


# ════════════════════════════════════════════════════════════════
#  Dataclasses (ported from ghostig)
# ════════════════════════════════════════════════════════════════

@dataclass
class UserProfile:
    """Public Instagram profile fields (mirrors ghostig.UserProfile)."""

    username: str = ""
    user_id: str = ""
    full_name: str = ""
    is_verified: bool = False
    is_business: bool = False
    is_private: bool = False
    follower_count: int = 0
    following_count: int = 0
    media_count: int = 0
    total_igtv_videos: int = 0
    biography: str = ""
    external_url: str | None = None
    is_whatsapp_linked: bool = False
    is_memorialized: bool = False
    is_new_to_instagram: bool = False
    public_email: str | None = None
    public_phone_country_code: str | None = None
    public_phone_number: str | None = None
    hd_profile_pic_url: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any], user_id: str) -> "UserProfile":
        """Build a profile from the ``users/{id}/info/`` user object."""
        return cls(
            username=payload.get("username", ""),
            user_id=user_id,
            full_name=payload.get("full_name") or "",
            is_verified=bool(payload.get("is_verified", False)),
            is_business=bool(payload.get("is_business", False)),
            is_private=bool(payload.get("is_private", False)),
            follower_count=int(payload.get("follower_count", 0) or 0),
            following_count=int(payload.get("following_count", 0) or 0),
            media_count=int(payload.get("media_count", 0) or 0),
            total_igtv_videos=int(payload.get("total_igtv_videos", 0) or 0),
            biography=payload.get("biography") or "",
            external_url=payload.get("external_url"),
            is_whatsapp_linked=bool(payload.get("is_whatsapp_linked", False)),
            is_memorialized=bool(payload.get("is_memorialized", False)),
            is_new_to_instagram=bool(payload.get("is_new_to_instagram", False)),
            public_email=payload.get("public_email"),
            public_phone_country_code=payload.get("public_phone_country_code"),
            public_phone_number=payload.get("public_phone_number"),
            hd_profile_pic_url=(payload.get("hd_profile_pic_url_info") or {}).get("url"),
        )


@dataclass
class LookupInsight:
    """Obfuscated recovery data hint from the Instagram lookup endpoint."""

    message: str | None = None
    obfuscated_email: str | None = None
    obfuscated_phone: str | None = None

    @classmethod
    def from_payload(cls, payload: dict[str, Any]) -> "LookupInsight":
        return cls(
            message=payload.get("message"),
            obfuscated_email=payload.get("obfuscated_email"),
            obfuscated_phone=payload.get("obfuscated_phone"),
        )

    def has_data(self) -> bool:
        return any((self.message, self.obfuscated_email, self.obfuscated_phone))


# ════════════════════════════════════════════════════════════════
#  Public API
# ════════════════════════════════════════════════════════════════

async def get_instagram_profile(username: str = "", user_id: str = "",
                                *, session_id: str | None = None,
                                skip_lookup: bool = True,
                                timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Gather public profile intel for an Instagram username or numeric user id.

    Exactly one of ``username`` / ``user_id`` must be provided.  Uses the
    operator's own ``sessionid`` (``IG_SESSIONID`` env var) on every
    request.  When ``skip_lookup=False`` an additional obfuscated
    email/phone lookup is attached.  Never raises.
    """
    username = (username or "").strip()
    user_id = (user_id or "").strip()
    if username and user_id:
        return {"ok": False, "error": "Provide either 'username' or 'user_id', not both.",
                "code": "invalid_input"}
    if not username and not user_id:
        return {"ok": False, "error": "Provide 'username' or 'user_id'", "code": "invalid_input"}

    session_id = _get_session_id(session_id)
    if not session_id:
        return {"ok": False, "error": "IG_SESSIONID env var not configured",
                "code": "session_missing", "session_configured": False}

    try:
        # Resolve the numeric user id (username → web_profile_info).
        if username:
            web = await _fetch(
                f"{WEB_PROFILE_URL}?username={urllib.parse.quote(username)}",
                timeout=timeout,
                headers=_with_cookie(WEB_PROFILE_HEADERS, session_id),
            )
            if not web.get("ok"):
                return _http_error_result(web)
            user_obj = ((web.get("data") or {}).get("data") or {}).get("user") or {}
            raw_id = user_obj.get("id")
            if not raw_id:
                return {"ok": False, "error": "Instagram API did not return a user id",
                        "code": "parse_error"}
            try:
                user_id = str(int(raw_id))
            except (TypeError, ValueError):
                return {"ok": False, "error": "Instagram API returned a malformed user id",
                        "code": "parse_error"}
        else:
            try:
                user_id = str(int(user_id))
            except (TypeError, ValueError):
                return {"ok": False, "error": "Invalid user_id: must be numeric",
                        "code": "invalid_input"}

        # Full public profile.
        info = await _fetch(
            USER_INFO_URL.format(user_id=user_id),
            timeout=timeout,
            headers=_with_cookie(USER_INFO_HEADERS, session_id),
        )
        if not info.get("ok"):
            return _http_error_result(info)
        profile_payload = (info.get("data") or {}).get("user") or {}
        profile = UserProfile.from_payload(profile_payload, user_id)

        # Optional obfuscated email/phone hint.
        lookup = None
        if not skip_lookup:
            lookup_result = await instagram_lookup(
                profile.username or username, session_id=session_id, timeout=timeout
            )
            if lookup_result.get("ok"):
                lookup = lookup_result.get("lookup")

        return {
            "ok": True,
            "profile": asdict(profile),
            "lookup": lookup,
            "session_configured": True,
        }
    except Exception as e:  # noqa: BLE001 — never raise
        _logger.debug("get_instagram_profile failed: %s", e)
        return {"ok": False, "error": str(e)}


async def instagram_lookup(username: str, *, session_id: str | None = None,
                           timeout: float = DEFAULT_TIMEOUT) -> dict:
    """
    Run the Instagram users/lookup endpoint for a username.

    Returns the obfuscated email/phone hint (``{"ok": True, "lookup":
    {...}}``) or ``lookup=None`` when the API returns no data at all.
    Never raises.
    """
    username = (username or "").strip()
    if not username:
        return {"ok": False, "error": "No username provided", "code": "invalid_input"}

    session_id = _get_session_id(session_id)
    if not session_id:
        return {"ok": False, "error": "IG_SESSIONID env var not configured",
                "code": "session_missing", "session_configured": False}

    try:
        signed_body = "signed_body=SIGNATURE." + urllib.parse.quote_plus(
            json.dumps({"q": username, "skip_recovery": "1"}, separators=(",", ":"))
        )
        resp = await _fetch(
            LOOKUP_URL,
            timeout=timeout,
            headers=_with_cookie(LOOKUP_HEADERS, session_id),
            method="POST",
            data=signed_body.encode("utf-8"),
        )
        if not resp.get("ok"):
            return _http_error_result(resp)

        insight = LookupInsight.from_payload(resp.get("data") or {})
        if not insight.has_data():
            return {"ok": True, "lookup": None, "session_configured": True}
        return {"ok": True, "lookup": asdict(insight), "session_configured": True}
    except Exception as e:  # noqa: BLE001 — never raise
        _logger.debug("instagram_lookup failed: %s", e)
        return {"ok": False, "error": str(e)}
