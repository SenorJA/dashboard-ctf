"""
notifications.py -- MIRV Module

Notification hub: push operational alerts to messaging providers
(Telegram, Discord, Slack, Pushover) or a generic JSON webhook.

Providers are configured through the REST API (in-memory, like the SIEM
webhook) or via environment variables, which act as a fallback layer:

* ``MIRV_NOTIFY_TELEGRAM_BOT_TOKEN`` + ``MIRV_NOTIFY_TELEGRAM_CHAT_ID``
* ``MIRV_NOTIFY_DISCORD_URL`` / ``MIRV_NOTIFY_SLACK_URL``
* ``MIRV_NOTIFY_PUSHOVER_USER`` + ``MIRV_NOTIFY_PUSHOVER_TOKEN``
* ``MIRV_NOTIFY_WEBHOOK_URL``

``send()`` is a strict no-op when nothing is configured, so integrations
can call it unconditionally (the existing hermetic test-suite stays
green). Delivery is fire-and-forget on a daemon thread, with truncation
and provider-specific payload/escaping.
"""

from __future__ import annotations

import html
import json
import logging
import os
import threading
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_logger = logging.getLogger("vulnforge.notifications")

MAX_MESSAGE_LEN = 4000

_lock = threading.Lock()
_providers: Dict[str, Dict[str, Any]] = {}  # name -> config (API-configured)

VALID_PROVIDERS = ("telegram", "discord", "slack", "pushover", "webhook")

_SENSITIVE_KEYS = ("bot_token", "token")

_REQUIRED_FIELDS = {
    "telegram": ("bot_token", "chat_id"),
    "discord": ("url",),
    "slack": ("url",),
    "pushover": ("user", "token"),
    "webhook": ("url",),
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _truncate(text: str, limit: int = MAX_MESSAGE_LEN) -> str:
    if not text:
        return ""
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _env_config() -> Dict[str, Dict[str, Any]]:
    """Providers declared via environment (fallback layer, source='env')."""
    cfg: Dict[str, Dict[str, Any]] = {}
    token = os.getenv("MIRV_NOTIFY_TELEGRAM_BOT_TOKEN", "").strip()
    chat = os.getenv("MIRV_NOTIFY_TELEGRAM_CHAT_ID", "").strip()
    if token and chat:
        cfg["telegram"] = {"bot_token": token, "chat_id": chat, "source": "env"}
    for name, env_var in (
        ("discord", "MIRV_NOTIFY_DISCORD_URL"),
        ("slack", "MIRV_NOTIFY_SLACK_URL"),
        ("webhook", "MIRV_NOTIFY_WEBHOOK_URL"),
    ):
        url = os.getenv(env_var, "").strip()
        if url:
            cfg[name] = {"url": url, "source": "env"}
    user = os.getenv("MIRV_NOTIFY_PUSHOVER_USER", "").strip()
    token = os.getenv("MIRV_NOTIFY_PUSHOVER_TOKEN", "").strip()
    if user and token:
        cfg["pushover"] = {"user": user, "token": token, "source": "env"}
    return cfg


def _get_config(name: str) -> Optional[Dict[str, Any]]:
    """API-configured wins over env for the same provider name."""
    with _lock:
        if name in _providers:
            return dict(_providers[name])
    return _env_config().get(name)


def _mask(value: str) -> str:
    if not value:
        return ""
    if len(value) <= 8:
        return "••••••••"
    return f"{value[:4]}•••{value[-4:]}"


def list_providers() -> List[Dict[str, Any]]:
    """Every provider currently available, with sensitive values masked."""
    out: List[Dict[str, Any]] = []
    with _lock:
        api_names = set(_providers)
        api = {k: dict(v) for k, v in _providers.items()}
    env = _env_config()
    names = set(api_names) | set(env)
    for name in sorted(names):
        cfg = api.get(name) or env.get(name) or {}
        masked = {k: (_mask(str(v)) if k in _SENSITIVE_KEYS else v) for k, v in cfg.items()}
        out.append({"name": name, "type": name, "source": cfg.get("source", "api"), "config": masked})
    return out


def is_configured(name: str) -> bool:
    return _get_config(name) is not None


def configure_provider(name: str, fields: Dict[str, Any]) -> Dict[str, Any]:
    """Register/update a provider via the API. Raises ValueError on bad input."""
    name = (name or "").strip().lower()
    if name not in VALID_PROVIDERS:
        raise ValueError(f"unknown provider '{name}'. Allowed: {', '.join(VALID_PROVIDERS)}")
    if not isinstance(fields, dict):
        raise ValueError("fields must be an object")
    cleaned: Dict[str, Any] = {}
    for key, val in fields.items():
        if val is not None:
            cleaned[str(key).strip()] = str(val).strip()
    missing = [k for k in _REQUIRED_FIELDS[name] if not cleaned.get(k)]
    if missing:
        raise ValueError(f"provider '{name}' requires: {', '.join(missing)}")
    cleaned["source"] = "api"
    with _lock:
        _providers[name] = cleaned
    masked = {k: (_mask(str(v)) if k in _SENSITIVE_KEYS else v) for k, v in cleaned.items()}
    return {"name": name, "type": name, "source": "api", "config": masked}


def remove_provider(name: str) -> bool:
    with _lock:
        return _providers.pop(name.strip().lower(), None) is not None


def reset_providers() -> None:
    """Clear API-configured providers (used by tests)."""
    with _lock:
        _providers.clear()


# ── Payload builders (providers) ─────────────────────────────────────────

def _payload(name: str, cfg: Dict[str, Any], title: str, message: str, level: str) -> tuple:
    """Return (url, body). body is str for form-encoded or dict for JSON."""
    title = _truncate(title or "MIRV", 256)
    message = _truncate(message or "", MAX_MESSAGE_LEN)
    if name == "telegram":
        url = f"https://api.telegram.org/bot{cfg['bot_token']}/sendMessage"
        text = f"<b>{html.escape(title)}</b>\n{html.escape(message)}"
        return url, {
            "chat_id": cfg["chat_id"],
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }
    if name == "discord":
        content = f"**{title}**\n{message}"[:2000]
        return cfg["url"], {"content": content}
    if name == "slack":
        return cfg["url"], {"text": f"*{title}*\n{message}"}
    if name == "pushover":
        priority = 1 if level in ("high", "critical") else 0
        return "https://api.pushover.net/1/messages.json", {
            "user": cfg["user"],
            "token": cfg["token"],
            "message": message,
            "title": title[:100],
            "priority": priority,
        }
    # generic webhook
    return cfg["url"], {
        "title": title,
        "message": message,
        "level": level or "info",
        "source": "mirv",
        "timestamp": _now_iso(),
    }


# ── Sending ───────────────────────────────────────────────────────────────

def _deliver(name: str, title: str, message: str, level: str) -> None:
    cfg = _get_config(name)
    if not cfg:
        return
    url, body = _payload(name, cfg, title, message, level)
    headers = {"Content-Type": "application/json"}
    data = json.dumps(body).encode("utf-8")
    if name == "pushover":
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        data = urllib.parse.urlencode(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=6):
        pass


def _deliver_quiet(name: str, title: str, message: str, level: str) -> None:
    try:
        _deliver(name, title, message, level)
    except Exception as exc:
        _logger.warning("notification to '%s' failed: %s", name, exc)


def send(title: str = "MIRV", message: str = "", level: str = "info", provider: Optional[str] = None) -> int:
    """Fire-and-forget push to every configured provider (or just one).

    Returns how many providers were queued. No-op when nothing is set.
    """
    if provider:
        names = [provider]
    else:
        names = [p["name"] for p in list_providers()]
    if not names:
        return 0
    queued = 0
    for name in names:
        if is_configured(name):
            threading.Thread(
                target=_deliver_quiet,
                args=(name, title, message, level),
                name=f"notif-{name}",
                daemon=True,
            ).start()
            queued += 1
    return queued


def send_sync(title: str, message: str, level: str = "info", provider: Optional[str] = None) -> Dict[str, Any]:
    """Blocking send (used by the test endpoint so the UI gets a verdict)."""
    names = [provider] if provider else [p["name"] for p in list_providers()]
    if provider and not is_configured(provider):
        raise ValueError(f"provider '{provider}' is not configured")
    results: Dict[str, Dict[str, Any]] = {}
    sent = 0
    for name in names:
        if not is_configured(name):
            continue
        try:
            _deliver(name, title, message, level)
            results[name] = {"ok": True, "detail": "sent"}
            sent += 1
        except Exception as exc:
            results[name] = {"ok": False, "detail": str(exc).split(":")[0][:120]}
    return {
        "sent": sent,
        "results": results,
        "all_ok": sent > 0 and all(r["ok"] for r in results.values()),
    }