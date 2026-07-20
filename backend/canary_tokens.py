"""
canary_tokens.py -- MIRV Module

Canary Tokens / Honeytoken Detection System.

Generates realistic fake credentials (API keys, DB URLs, AWS keys, Slack
tokens, JWTs, env files, config files, generic URLs) designed to be planted
in codebases, config dirs, CI/CD pipelines, or shared drives.  When an
attacker picks up and uses a token, the activation endpoint fires and
MIRV records the event for alerting.

Token types:
  - api-key      : ``sk-<hex32>`` / ``pk-<hex32>``
  - db-url       : PostgreSQL connection string with random password
  - jwt          : Realistic-looking ``eyJ...`` three-part string
  - aws-key      : ``AKIA<upper16>``
  - slack-token  : ``xoxb-<digits>-<digits>-<hex>``
  - generic-url  : URL pointing back to ``/api/canary/activate/{id}``
  - env-file     : Multi-line .env text with fake secrets
  - config-file  : JSON config block with fake DB / Redis / API settings

Severity on activation:
  - high   : Token used from an external IP
  - info   : Token generated / deployed
"""

import json
import uuid
import secrets
import string
import logging
import threading
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Any

# -- Logger --
logger = logging.getLogger("vulnforge.canary")


# ================================================================
#  Data classes
# ================================================================

@dataclass
class CanaryToken:
    """Represents a single canary / honeytoken."""
    id: str
    type: str
    name: str
    value: str
    created_at: str
    expires_at: str
    active: bool
    payload: dict = field(default_factory=dict)


@dataclass
class CanaryEvent:
    """Records one activation / hit of a canary token."""
    token_id: str
    token_name: str
    timestamp: str
    ip: str
    user_agent: str
    referer: str | None = None
    country: str | None = None


# ================================================================
#  Module-level singleton store (thread-safe)
# ================================================================

_tokens: dict[str, CanaryToken] = {}
_events: list[CanaryEvent] = []
_lock = threading.Lock()

# ================================================================
#  Token value generators (private helpers)
# ================================================================

_VALID_TYPES = frozenset({
    "api-key", "db-url", "jwt", "aws-key",
    "slack-token", "generic-url", "env-file", "config-file",
})


def _gen_api_key() -> str:
    """``sk-`` or ``pk-`` + 32 hex chars."""
    prefix = secrets.choice(["sk", "pk"])
    return f"{prefix}-{secrets.token_hex(16)}"


def _gen_db_url() -> str:
    """Realistic PostgreSQL connection string."""
    short_id = uuid.uuid4().hex[:8]
    password = secrets.token_urlsafe(18)
    return (
        f"postgresql://admin:{password}@db-{short_id}.internal:5432/production"
    )


def _gen_jwt() -> str:
    """A realistic-looking (but fake) JWT."""
    import base64

    # Header
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "RS256", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()

    # Payload
    now = int(datetime.now(timezone.utc).timestamp())
    payload_obj = {
        "sub": uuid.uuid4().hex[:12],
        "name": secrets.token_hex(8),
        "iat": now,
        "exp": now + 86400,
        "iss": "auth.internal",
    }
    payload_b64 = base64.urlsafe_b64encode(
        json.dumps(payload_obj).encode()
    ).rstrip(b"=").decode()

    # Signature (random bytes, not real crypto)
    sig = base64.urlsafe_b64encode(
        secrets.token_bytes(64)
    ).rstrip(b"=").decode()

    return f"{header}.{payload_b64}.{sig}"


def _gen_aws_key() -> str:
    """AWS access key ID: ``AKIA`` + 16 uppercase letters/digits."""
    alphabet = string.ascii_uppercase + string.digits
    return "AKIA" + "".join(secrets.choice(alphabet) for _ in range(16))


def _gen_slack_token() -> str:
    """Slack bot token: ``xoxb-<digits>-<digits>-<hex>``."""
    part1 = str(secrets.randbelow(9_999_999_999)).zfill(10)
    part2 = str(secrets.randbelow(9_999_999_999_999_999)).zfill(17)
    part3 = secrets.token_hex(24)
    return f"xoxb-{part1}-{part2}-{part3}"


def _gen_generic_url(token_id: str) -> str:
    """URL that points back at MIRV's activation endpoint."""
    return f"https://mirv.internal/api/canary/activate/{token_id}"


def _gen_env_file() -> str:
    """Multi-line .env text with fake secrets."""
    fake_pass = secrets.token_urlsafe(24)
    fake_api_key = secrets.token_hex(32)
    fake_secret = secrets.token_hex(48)
    return (
        "# Auto-generated environment config\n"
        "DB_HOST=db-prod-01.internal\n"
        "DB_PORT=5432\n"
        "DB_USER=deploy_svc\n"
        f"DB_PASSWORD={fake_pass}\n"
        "DB_NAME=production\n"
        f"API_KEY=ak_live_{fake_api_key}\n"
        f"SECRET_KEY={fake_secret}\n"
        "REDIS_URL=redis://cache.internal:6379/0\n"
        "DEBUG=false\n"
        "LOG_LEVEL=info\n"
    )


def _gen_config_file() -> str:
    """JSON config block with fake DB / Redis / API settings."""
    config = {
        "app": {"name": "internal-api", "env": "production", "debug": False},
        "database": {
            "host": f"db-{uuid.uuid4().hex[:6]}.internal",
            "port": 5432,
            "user": "app_svc",
            "password": secrets.token_urlsafe(20),
            "name": "production",
            "pool_size": 10,
        },
        "redis": {
            "host": "cache.internal",
            "port": 6379,
            "db": 0,
            "password": secrets.token_urlsafe(16),
        },
        "api_keys": {
            "stripe": f"sk_live_{secrets.token_hex(24)}",
            "sendgrid": f"SG.{secrets.token_urlsafe(22)}.{secrets.token_hex(32)}",
        },
    }
    return json.dumps(config, indent=2)


_GENERATORS: dict[str, Any] = {
    "api-key": lambda _id, _name, _notes: _gen_api_key(),
    "db-url": lambda _id, _name, _notes: _gen_db_url(),
    "jwt": lambda _id, _name, _notes: _gen_jwt(),
    "aws-key": lambda _id, _name, _notes: _gen_aws_key(),
    "slack-token": lambda _id, _name, _notes: _gen_slack_token(),
    "generic-url": lambda token_id, _name, _notes: _gen_generic_url(token_id),
    "env-file": lambda _id, _name, _notes: _gen_env_file(),
    "config-file": lambda _id, _name, _notes: _gen_config_file(),
}


# ================================================================
#  Public API
# ================================================================

def generate_token(
    token_type: str,
    name: str = "",
    notes: str = "",
) -> CanaryToken:
    """
    Generate a new canary / honeytoken.

    Args:
        token_type: One of ``_VALID_TYPES``.
        name:       Human-friendly label (default: auto-generated).
        notes:      Free-text notes / tags.

    Returns:
        The newly created ``CanaryToken``.
    """
    if token_type not in _VALID_TYPES:
        raise ValueError(
            f"Invalid token type '{token_type}'. "
            f"Must be one of: {', '.join(sorted(_VALID_TYPES))}"
        )

    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires = now + timedelta(days=30)

    generator = _GENERATORS[token_type]
    value = generator(token_id, name, notes)

    if not name:
        name = f"canary-{token_type}-{token_id[:8]}"

    token = CanaryToken(
        id=token_id,
        type=token_type,
        name=name,
        value=value,
        created_at=now.isoformat(),
        expires_at=expires.isoformat(),
        active=True,
        payload={"notes": notes} if notes else {},
    )

    with _lock:
        _tokens[token_id] = token

    logger.info(
        "Canary token created: type=%s name=%s id=%s",
        token_type, name, token_id[:8],
    )
    return token


def list_tokens() -> list[dict]:
    """Return all active tokens as plain dicts (safe for JSON serialisation)."""
    with _lock:
        return [asdict(t) for t in _tokens.values() if t.active]


def get_token(token_id: str) -> CanaryToken | None:
    """Lookup a token by its UUID. Returns ``None`` if not found."""
    with _lock:
        return _tokens.get(token_id)


def activate_token(
    token_id: str,
    ip: str,
    user_agent: str,
    referer: str | None = None,
) -> CanaryEvent | None:
    """
    Record an activation event for a canary token.

    Args:
        token_id:   UUID of the token that was used.
        ip:         Client IP address.
        user_agent: Client ``User-Agent`` header value.
        referer:    Client ``Referer`` header (may be ``None``).

    Returns:
        The ``CanaryEvent`` if the token was found and active,
        or ``None`` if the token doesn't exist / is inactive.
    """
    with _lock:
        token = _tokens.get(token_id)
        if token is None or not token.active:
            return None

    event = CanaryEvent(
        token_id=token_id,
        token_name=token.name,
        timestamp=datetime.now(timezone.utc).isoformat(),
        ip=ip,
        user_agent=user_agent,
        referer=referer,
        country=None,  # GeoIP lookup can be added later
    )

    with _lock:
        _events.append(event)

    logger.warning(
        "CANARY ACTIVATED: token=%s name=%s ip=%s ua=%s",
        token_id[:8], token.name, ip, user_agent[:80],
    )
    return event


def get_events(token_id: str | None = None) -> list[dict]:
    """
    Return activation events as plain dicts.

    Args:
        token_id: If provided, filter to events for this token only.
    """
    with _lock:
        if token_id:
            return [
                asdict(e) for e in _events if e.token_id == token_id
            ]
        return [asdict(e) for e in _events]


def delete_token(token_id: str) -> bool:
    """
    Deactivate a canary token (soft-delete).

    Returns ``True`` if the token existed and was marked inactive,
    ``False`` if not found.
    """
    with _lock:
        token = _tokens.get(token_id)
        if token is None:
            return False
        token.active = False

    logger.info("Canary token deactivated: id=%s", token_id[:8])
    return True


# ================================================================
#  MIRV Findings conversion
# ================================================================

def report_to_mirv_findings(
    token: CanaryToken,
    event: CanaryEvent | None = None,
) -> list[dict]:
    """
    Generate MIRV-compatible findings for canary token operations.

    Args:
        token: The canary token involved.
        event: If provided, a HIGH-severity activation finding is emitted.
               If ``None``, an INFO-level deployment finding is emitted.

    Returns:
        List of finding dicts (always exactly one).
    """
    findings: list[dict] = []

    if event is not None:
        # -- Activation event (HIGH) --
        detail_lines = [
            f"Token type : {token.type}",
            f"Token name : {token.name}",
            f"Token ID   : {token.id}",
            f"Created    : {token.created_at}",
            f"Expires    : {token.expires_at}",
            "",
            f"--- Activation ---",
            f"IP address : {event.ip}",
            f"User-Agent : {event.user_agent}",
            f"Referer    : {event.referer or 'N/A'}",
            f"Country    : {event.country or 'Unknown'}",
            f"Timestamp  : {event.timestamp}",
        ]
        findings.append({
            "tool": "canary-token",
            "severity": "high",
            "title": (
                f"Canary token '{token.name}' activated from {event.ip}"
            ),
            "detail": "\n".join(detail_lines),
            "target": event.ip,
            "type": "vuln",
            "extra": {
                "token_id": token.id,
                "token_type": token.type,
                "token_name": token.name,
                "event_ip": event.ip,
                "event_ua": event.user_agent,
                "event_referer": event.referer,
                "event_country": event.country,
                "event_timestamp": event.timestamp,
            },
        })
    else:
        # -- Deployment / creation (INFO) --
        detail_lines = [
            f"Token type : {token.type}",
            f"Token name : {token.name}",
            f"Token ID   : {token.id}",
            f"Value      : {token.value[:60]}{'...' if len(token.value) > 60 else ''}",
            f"Created    : {token.created_at}",
            f"Expires    : {token.expires_at}",
            f"Active     : Yes",
        ]
        if token.payload.get("notes"):
            detail_lines.append(f"Notes      : {token.payload['notes']}")

        findings.append({
            "tool": "canary-token",
            "severity": "info",
            "title": f"Canary token '{token.name}' deployed",
            "detail": "\n".join(detail_lines),
            "target": token.type,
            "type": "tech",
            "extra": {
                "token_id": token.id,
                "token_type": token.type,
                "token_name": token.name,
                "created_at": token.created_at,
                "expires_at": token.expires_at,
            },
        })

    return findings
