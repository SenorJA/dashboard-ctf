"""
Tests for backend/secret_store.py — at-rest Fernet encryption for
app_credentials values.

Covers: encrypt/decrypt round-trip, ciphertext integrity, legacy plaintext
passthrough, env key (raw + derived passphrase), key-file generation/reuse,
missing-crypto fail-closed behaviour, and key-source reporting.
"""

import pytest
from unittest.mock import patch

import backend.secret_store as ss
from backend.secret_store import SecretStoreError, FERNET_PREFIX


@pytest.fixture(autouse=True)
def _reset_store():
    """Drop cached Fernet before/after every test so key resolution and the
    global single instance can't leak across cases."""
    ss.reset()
    yield
    ss.reset()


@pytest.fixture
def tmp_key_file(tmp_path, monkeypatch):
    """Point the key file at an isolated temp path."""
    path = tmp_path / "enc_secret.key"
    monkeypatch.setattr(ss, "_key_file_path", lambda: path)
    return path


def _valid_env_key():
    from cryptography.fernet import Fernet
    return Fernet.generate_key().decode("ascii")


# ── Round-trip + ciphertext integrity ────────────────────────────


class TestRoundTrip:
    def test_encrypt_decrypt_roundtrip(self, tmp_key_file):
        token = ss.encrypt_value("sk-abc-123-secret")
        assert token != "sk-abc-123-secret"
        assert token.startswith(FERNET_PREFIX)
        assert ss.decrypt_value(token) == "sk-abc-123-secret"

    def test_encrypt_produces_distinct_ciphertexts(self, tmp_key_file):
        t1 = ss.encrypt_value("same-plaintext")
        t2 = ss.encrypt_value("same-plaintext")
        assert t1 != t2
        assert ss.decrypt_value(t1) == ss.decrypt_value(t2) == "same-plaintext"

    def test_decrypt_accepts_bytes_token(self, tmp_key_file):
        token = ss.encrypt_value("binary-roundtrip")
        assert ss.decrypt_value(token.encode("ascii")) == "binary-roundtrip"

    def test_empty_and_none_passthrough(self, tmp_key_file):
        assert ss.decrypt_value(None) is None
        assert ss.decrypt_value("") == ""
        assert ss.encrypt_value(None) is None

    def test_tampered_ciphertext_raises(self, tmp_key_file):
        token = ss.encrypt_value("integrity-check")
        # Flip a character in the MIDDLE so the gAAAAA prefix stays intact
        # (a first-char flip would make the row look like legacy plaintext).
        mid = len(token) // 2
        flipped = token[:mid] + ("A" if token[mid] != "A" else "B") + token[mid + 1:]
        assert flipped != token
        with pytest.raises(SecretStoreError):
            ss.decrypt_value(flipped)

    def test_decrypt_wrong_key_raises(self, tmp_path, monkeypatch):
        key_a = tmp_path / "keyA.key"
        key_b = tmp_path / "keyB.key"
        key_a.write_text(_valid_env_key() + "\n", encoding="utf-8")
        key_b.write_text(_valid_env_key() + "\n", encoding="utf-8")
        monkeypatch.setattr(ss, "_key_file_path", lambda: key_a)
        ss.reset()
        token = ss.encrypt_value("secret-value")
        assert ss.decrypt_value(token) == "secret-value"  # key A round-trips
        # Switching to key B invalidates the old ciphertext (HMAC fails)
        monkeypatch.setattr(ss, "_key_file_path", lambda: key_b)
        ss.reset()
        with pytest.raises(SecretStoreError):
            ss.decrypt_value(token)
        # But key B is fully functional for its own values
        token_b = ss.encrypt_value("other")
        assert ss.decrypt_value(token_b) == "other"


# ── Legacy plaintext rows ─────────────────────────────────────────


class TestLegacyPassthrough:
    def test_legacy_plaintext_returns_unchanged(self, tmp_key_file):
        assert ss.decrypt_value("sk-plain-old-row") == "sk-plain-old-row"

    def test_mixed_rows_work(self, tmp_key_file):
        encrypted = ss.encrypt_value("new")
        assert ss.decrypt_value(encrypted) == "new"
        assert ss.decrypt_value("old") == "old"


# ── Key sources ───────────────────────────────────────────────────


class TestKeySources:
    def test_env_raw_key_used(self, tmp_key_file, monkeypatch):
        key = _valid_env_key()
        monkeypatch.setenv("MIRV_ENC_KEY", key)
        token = ss.encrypt_value("env-key-value")
        assert ss.decrypt_value(token) == "env-key-value"
        assert ss.get_key_source() == "env:key"

    def test_env_passphrase_derived(self, tmp_key_file, monkeypatch):
        monkeypatch.setenv("MIRV_ENC_KEY", "super-secret passphrase 123!")
        token = ss.encrypt_value("derived-key-value")
        assert ss.decrypt_value(token) == "derived-key-value"
        assert ss.get_key_source() == "env:derived"

    def test_env_wins_over_file(self, tmp_key_file, monkeypatch):
        monkeypatch.setenv("MIRV_ENC_KEY", _valid_env_key())
        token = ss.encrypt_value("value")
        assert ss.get_key_source() == "env:key"
        # File is never created when an env key exists
        assert not tmp_key_file.exists()

    def test_key_file_generated_then_reused(self, tmp_key_file):
        assert not tmp_key_file.exists()
        token1 = ss.encrypt_value("file-key")
        assert tmp_key_file.exists()
        assert ss.decrypt_value(token1) == "file-key"
        assert ss.get_key_source() in ("file", "generated:file")
        # Second session reuses the persisted key (old tokens still decrypt)
        ss.reset()
        token2 = ss.encrypt_value("file-key-2")
        key1 = tmp_key_file.read_text(encoding="utf-8").strip()
        assert tmp_key_file.read_text(encoding="utf-8").strip() == key1
        assert ss.decrypt_value(token1) == "file-key"
        assert ss.decrypt_value(token2) == "file-key-2"

    def test_key_file_source_reporting(self, tmp_key_file):
        tmp_key_file.write_text(_valid_env_key() + "\n", encoding="utf-8")
        assert ss.get_key_source() == "file"

    def test_invalid_key_file_recreated(self, tmp_key_file):
        tmp_key_file.write_text("not-a-valid-key\n", encoding="utf-8")
        token = ss.encrypt_value("fix-me")
        assert ss.decrypt_value(token) == "fix-me"
        assert ss._valid_fernet_key(tmp_key_file.read_text(encoding="utf-8").strip())
        assert tmp_key_file.read_text(encoding="utf-8").strip() != "not-a-valid-key"

    def test_key_file_persist_failure_raises(self, tmp_path, monkeypatch):
        blocker = tmp_path / "blocker"
        blocker.write_text("x", encoding="utf-8")
        target = blocker / "nested" / "k.key"  # mkdir under a FILE → OSError
        with pytest.raises(SecretStoreError):
            ss._load_or_create_key(target)


# ── Missing crypto (fail closed) ──────────────────────────────────


class TestMissingCrypto:
    def test_is_enabled_true_with_crypto(self, tmp_key_file):
        assert ss.is_enabled() is True

    def test_is_enabled_false_without_crypto(self, tmp_key_file):
        with patch.object(ss, "_crypto_available", return_value=False):
            assert ss.is_enabled() is False

    def test_encrypt_refuses_when_crypto_missing(self, tmp_key_file):
        with patch.object(ss, "_crypto_available", return_value=False):
            with pytest.raises(SecretStoreError):
                ss.encrypt_value("should-not-encrypt")

    def test_decrypt_refuses_when_crypto_missing(self, tmp_key_file):
        with patch.object(ss, "_crypto_available", return_value=False):
            with pytest.raises(SecretStoreError):
                ss.decrypt_value(FERNET_PREFIX + "corrupted")

    def test_legacy_passthrough_still_works_without_crypto(self, tmp_key_file):
        """Plaintext rows never need the crypto lib."""
        with patch.object(ss, "_crypto_available", return_value=False):
            assert ss.decrypt_value("sk-plain") == "sk-plain"

    def test_missing_env_key_without_crypto_raises(self, tmp_key_file, monkeypatch):
        monkeypatch.delenv("MIRV_ENC_KEY", raising=False)
        with patch.object(ss, "_crypto_available", return_value=False):
            with pytest.raises(SecretStoreError):
                ss.encrypt_value("x")


# ── Reset helper ──────────────────────────────────────────────────


class TestReset:
    def test_reset_drops_cached_instance(self, tmp_key_file):
        ss.encrypt_value("seed")
        assert ss._fernet is not None
        ss.reset()
        assert ss._fernet is None
        assert ss.is_enabled() is True


# ── Key-rotation helpers (explicit key) ───────────────────────────


class TestRotationHelpers:
    def test_encrypt_with_decrypt_with_roundtrip(self, tmp_key_file):
        keyA = _valid_env_key()
        token = ss.encrypt_with(keyA, "rotation-value")
        assert token.startswith(FERNET_PREFIX)
        assert ss.decrypt_with(keyA, token) == "rotation-value"

    def test_cross_key_isolated(self, tmp_key_file):
        keyA = _valid_env_key()
        keyB = _valid_env_key()
        token = ss.encrypt_with(keyA, "value")
        assert ss.decrypt_with(keyA, token) == "value"
        with pytest.raises(SecretStoreError):
            ss.decrypt_with(keyB, token)

    def test_decrypt_with_legacy_plaintext_passthrough(self, tmp_key_file):
        assert ss.decrypt_with(_valid_env_key(), "plain-old") == "plain-old"

    def test_encrypt_with_invalid_key_raises(self, tmp_key_file):
        with pytest.raises(SecretStoreError):
            ss.encrypt_with("not-a-valid-key", "x")

    def test_rotation_flow_between_two_files(self, tmp_path, monkeypatch):
        """Simulate real key rotation across two persisted key files."""
        keyA_path = tmp_path / "keyA.key"
        keyB_path = tmp_path / "keyB.key"
        # Session 1 writes with key A.
        monkeypatch.setattr(ss, "_key_file_path", lambda: keyA_path)
        ss.reset()
        token_a = ss.encrypt_value("secret-under-A")
        # Operator rotates to key B.
        monkeypatch.setattr(ss, "_key_file_path", lambda: keyB_path)
        ss.reset()
        # Old token is no longer readable under B...
        with pytest.raises(SecretStoreError):
            ss.decrypt_value(token_a)
        # ...but decrypt_with(A) still recovers it and encrypt_with(B) migrates it.
        keyA = keyA_path.read_text(encoding="utf-8").strip()
        keyB = keyB_path.read_text(encoding="utf-8").strip()
        plain = ss.decrypt_with(keyA, token_a)
        assert plain == "secret-under-A"
        token_b = ss.encrypt_with(keyB, plain)
        assert ss.decrypt_value(token_b) == "secret-under-A"