"""
M.I.R.V. — Secret Store (at-rest encryption for app_credentials)

Encrypts credential values (AI API keys, Payload Studio creds, etc.)
before they are persisted in Supabase, so the DB never holds plaintext.

Design:
  - **Fernet** (AES-128-CBC + HMAC-SHA256) from the ``cryptography`` lib,
    imported lazily so the rest of the app keeps working if it is gone.
  - **Transparent API**: ``encrypt_value()`` / ``decrypt_value()`` mirror
    plain mirror functions so ``database.py`` stays dependency-light.
  - **Legacy passthrough**: rows written before this module existed hold
    plaintext.  ``decrypt_value()`` returns them unchanged (Fernet tokens
    always start with ``gAAAAA``), and the next ``save`` re-encrypts.
  - **Key resolution** (first hit wins):
      1. env ``MIRV_ENC_KEY``   — a raw Fernet key (32-byte urlsafe-base64)
         OR an arbitrary passphrase, derived via stdlib ``hashlib.scrypt``.
      2. key file              — ``backend/data/enc_secret.key`` (auto-created
         0600 on POSIX; override path with env ``MIRV_ENC_KEY_FILE``).  The
         file is the recommended default: a random key generated once and
         reused, so previously encrypted values stay decryptable.
  - **Opt-in**: importing this module changes nothing until a caller wraps
    its data (mirrors ``redact.py``).

OPSEC: keep ``MIRV_ENC_KEY`` (or the key file) secret.  Losing the key makes
stored secrets unrecoverable by design.  Rotating the key breaks old rows
(Fernet MAC fails → treated as missing); a future ``reencrypt_all()`` can
cycle keys without exposing plaintext.
"""

import hashlib
import logging
import os
import threading
from pathlib import Path

logger = logging.getLogger("vulnforge.secret_store")


class SecretStoreError(Exception):
    """Raised when a value cannot be encrypted/decrypted."""


# Fernet tokens always carry this base64 prefix; anything else is a legacy
# plaintext row written before this module existed.
FERNET_PREFIX = "gAAAAA"

_DERIVATION_SALT = b"mirv-enc-key-v1"
_DATA_DIR = Path(__file__).resolve().parent / "data"
_KEY_FILE = _DATA_DIR / "enc_secret.key"

_fernet = None
_fernet_error = None
_lock = threading.Lock()


# ───────────────────────────────────────────────────────────────────
#  Crypto availability (lazy)
# ───────────────────────────────────────────────────────────────────


def _crypto_available() -> bool:
    """True when the ``cryptography`` package can be imported."""
    try:
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


# ───────────────────────────────────────────────────────────────────
#  Key management
# ───────────────────────────────────────────────────────────────────


def _key_file_path() -> Path:
    """Key file location: env ``MIRV_ENC_KEY_FILE`` or the data directory."""
    override = os.getenv("MIRV_ENC_KEY_FILE", "").strip()
    return Path(override).expanduser() if override else _KEY_FILE


def _derive_key(passphrase: str) -> str:
    """Derive a Fernet key (32 bytes urlsafe-base64) from a passphrase.

    Uses stdlib ``hashlib.scrypt`` so we never have to reach into the
    ``cryptography`` KDF API for key setup (scrypt is memory-hard and
    resists GPU brute-force).
    """
    import base64
    try:
        raw = hashlib.scrypt(
            passphrase.encode("utf-8"),
            salt=_DERIVATION_SALT,
            n=2 ** 14,
            r=8,
            p=1,
            dklen=32,
        )
    except ValueError:
        raise SecretStoreError("MIRV_ENC_KEY passphrase could not be derived")
    return base64.urlsafe_b64encode(raw).decode("ascii")


def _valid_fernet_key(key: str) -> bool:
    """True if ``key`` is a well-formed Fernet key (32-byte urlsafe base64)."""
    try:
        from cryptography.fernet import Fernet
        Fernet(key.encode("ascii"))
        return True
    except Exception:
        return False


def _env_key() -> str | None:
    """Resolve a key from ``MIRV_ENC_KEY`` (raw Fernet key or passphrase)."""
    raw = os.getenv("MIRV_ENC_KEY", "").strip()
    if not raw:
        return None
    if _valid_fernet_key(raw):
        return raw
    # Not a raw key → treat as passphrase and derive a deterministic key.
    logger.info("MIRV_ENC_KEY is not a Fernet key — deriving via scrypt")
    return _derive_key(raw)


def _load_or_create_key(key_file: Path) -> str:
    """Read the key file or generate + persist a fresh random key."""
    if key_file.exists():
        key = key_file.read_text(encoding="utf-8").strip()
        if key and _valid_fernet_key(key):
            return key
        logger.error("secret key file %s is invalid — recreating", key_file)
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode("ascii")
    try:
        key_file.parent.mkdir(parents=True, exist_ok=True)
        key_file.write_text(key + "\n", encoding="utf-8")
        try:
            os.chmod(str(key_file), 0o600)  # POSIX-only; Windows ignores
        except OSError:
            pass
        logger.info("generated new secret-store key: %s", key_file)
    except OSError as e:
        raise SecretStoreError(f"cannot persist encryption key: {e}")
    return key


def _resolve_key() -> str:
    """Return the active Fernet key (env → key file → generated)."""
    env_key = _env_key()
    if env_key is not None:
        return env_key
    return _load_or_create_key(_key_file_path())


def get_key_source() -> str:
    """Human-readable description of the active key source (for logs/UI)."""
    env_raw = os.getenv("MIRV_ENC_KEY", "").strip()
    if env_raw:
        if _valid_fernet_key(env_raw):
            return "env:key"
        return "env:derived"
    if _key_file_path().exists():
        return "file"
    return "generated:file"


def _get_fernet():
    """Return the lazily-created (thread-safe) Fernet instance."""
    global _fernet, _fernet_error
    if _fernet is not None:
        return _fernet
    with _lock:
        if _fernet is not None:
            return _fernet
        if not _crypto_available():
            _fernet_error = "cryptography package not installed"
            raise SecretStoreError(_fernet_error)
        try:
            from cryptography.fernet import Fernet
            _fernet = Fernet(_resolve_key().encode("ascii"))
        except SecretStoreError:
            raise
        except Exception as e:  # pragma: no cover - defensive
            _fernet_error = str(e)
            raise SecretStoreError(f"cannot initialise Fernet: {e}")
        return _fernet


def reset() -> None:
    """Drop cached Fernet instance (test helper / key rotation hook)."""
    global _fernet, _fernet_error
    _fernet = None
    _fernet_error = None


# ───────────────────────────────────────────────────────────────────
#  Public API
# ───────────────────────────────────────────────────────────────────


def is_enabled() -> bool:
    """True when encryption is operational (crypto lib + resolvable key)."""
    try:
        _get_fernet()
        return True
    except Exception:
        return False


def encrypt_value(value: str) -> str:
    """Encrypt ``value`` and return the Fernet token (atomic w/ HMAC).

    Raises :class:`SecretStoreError` when the store is unavailable — callers
    MUST then refuse to persist plaintext (fail closed).
    """
    if value is None:
        return None
    try:
        token = _get_fernet().encrypt(str(value).encode("utf-8"))
    except SecretStoreError:
        raise
    except Exception as e:  # pragma: no cover - defensive
        raise SecretStoreError(f"encryption failed: {e}")
    return token.decode("ascii")


def decrypt_value(token) -> str | None:
    """Decrypt ``token``; legacy plaintext rows pass through unchanged.

    Returns ``None`` for ``None``/empty input.  Raises
    :class:`SecretStoreError` only for ciphertext that fails the HMAC
    (wrong key/tampered) — the caller should treat it as unavailable.
    """
    if not token:
        return token
    text = token if isinstance(token, str) else str(token, "utf-8")
    if not text.startswith(FERNET_PREFIX):
        return text  # legacy row written as plaintext
    try:
        raw = _get_fernet().decrypt(text.encode("utf-8"))
    except SecretStoreError:
        raise
    except Exception as e:
        raise SecretStoreError(f"decryption failed (bad key or tampered data): {e}")
    return raw.decode("utf-8")


# ───────────────────────────────────────────────────────────────────
#  Key-rotation helpers (re-encrypt rows when the key changes)
# ───────────────────────────────────────────────────────────────────


def encrypt_with(key: str, value: str) -> str:
    """Encrypt ``value`` using an explicit Fernet ``key`` (rotation helper).

    Mirrors :func:`encrypt_value` but does not touch the store's active
    key — lets a migration re-encrypt with a NEW key while the store still
    uses the OLD one.
    """
    try:
        from cryptography.fernet import Fernet
        token = Fernet(key.encode("ascii")).encrypt(str(value).encode("utf-8"))
    except Exception as e:
        raise SecretStoreError(f"encrypt_with failed: {e}")
    return token.decode("ascii")


def decrypt_with(key: str, token) -> str:
    """Decrypt ``token`` with an explicit Fernet ``key`` (rotation helper).

    Same semantics as :func:`decrypt_value` but pinned to ``key``: legacy
    plaintext passes through unchanged, and bad-key/tampered ciphertext
    raises :class:`SecretStoreError`.
    """
    if not token:
        return token
    text = token if isinstance(token, str) else str(token, "utf-8")
    if not text.startswith(FERNET_PREFIX):
        return text  # legacy plaintext row
    try:
        from cryptography.fernet import Fernet
        raw = Fernet(key.encode("ascii")).decrypt(text.encode("utf-8"))
    except Exception as e:
        raise SecretStoreError(f"decrypt_with failed (bad key or tampered data): {e}")
    return raw.decode("utf-8")