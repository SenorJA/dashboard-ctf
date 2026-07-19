"""
Tests for backend/hash_cracker.py — MIRV Hash Identifier + Rainbow Cracker.

Covers:
  - identify_hash_type(): pattern/length-based hash classification
  - crack(): async rainbow-table cracking for MD5, SHA1, SHA256, SHA512, NTLM
  - report_to_mirv_findings(): CrackReport → MIRV findings conversion
"""

import hashlib
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from hash_cracker import (
    identify_hash_type,
    crack,
    _crack_single,
    _build_rainbow,
    report_to_mirv_findings,
    HashResult,
    CrackReport,
)


# ──────────────────────────────────────────────
#  identify_hash_type — hash type classification
# ──────────────────────────────────────────────


class TestIdentifyHashType:
    """Tests for identify_hash_type()."""

    def test_md5_32_hex_identifies_md5(self):
        """A 32-char lowercase hex string matches MD5 (and other 32-hex types)."""
        md5_hash = hashlib.md5(b"test").hexdigest()  # 098f6bcd4621d373cade4e832627b4f6
        assert len(md5_hash) == 32
        types = identify_hash_type(md5_hash)
        assert "MD5" in types

    def test_md5_also_matches_ntlm_and_md4_md2(self):
        """32-hex-char strings match all 32-char types: MD5, NTLM, MD4, MD2, LM."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # md5("password")
        types = identify_hash_type(md5_hash)
        # All 32-hex-char pattern types should match
        for expected in ("MD5", "NTLM", "MD4", "MD2", "LM"):
            assert expected in types, f"Expected '{expected}' in matches for 32-hex string"

    def test_md5_uppercase_also_identifies(self):
        """Uppercase hex should still match (re.IGNORECASE in the module)."""
        upper_md5 = "5F4DCC3B5AA765D61D8327DEB882CF99"
        types = identify_hash_type(upper_md5)
        assert "MD5" in types

    def test_sha1_40_hex_identifies_sha1(self):
        """A 40-char hex string matches SHA1 and RIPEMD160."""
        sha1_hash = hashlib.sha1(b"password").hexdigest()  # well-known SHA1
        assert len(sha1_hash) == 40
        types = identify_hash_type(sha1_hash)
        assert "SHA1" in types
        assert "RIPEMD160" in types

    def test_sha256_64_hex_identifies_sha256(self):
        """A 64-char hex string matches SHA256 and GOST."""
        sha256_hash = hashlib.sha256(b"test").hexdigest()
        assert len(sha256_hash) == 64
        types = identify_hash_type(sha256_hash)
        assert "SHA256" in types
        assert "GOST" in types

    def test_sha512_128_hex_identifies_sha512(self):
        """A 128-char hex string matches SHA512 and Whirlpool."""
        sha512_hash = hashlib.sha512(b"test").hexdigest()
        assert len(sha512_hash) == 128
        types = identify_hash_type(sha512_hash)
        assert "SHA512" in types
        assert "Whirlpool" in types

    def test_bcrypt_identifies_bcrypt(self):
        """$2b$10$... pattern identifies bcrypt."""
        bcrypt_hash = "$2b$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
        types = identify_hash_type(bcrypt_hash)
        assert "bcrypt" in types

    def test_bcrypt_variant_a_identifies(self):
        """$2a$ prefix also identifies bcrypt."""
        bcrypt_a = "$2a$10$SomeSaltAndHashValueThatIsLongEnoughForThePatternToMatchOk"
        types = identify_hash_type(bcrypt_a)
        assert "bcrypt" in types

    def test_sha256crypt_identifies(self):
        """$5$salt$hash identifies sha256crypt."""
        hash_str = "$5$salt$SomeHashValueHereThatIsReasonablyLongForIdentification"
        types = identify_hash_type(hash_str)
        assert "sha256crypt" in types

    def test_sha512crypt_identifies(self):
        """$6$salt$hash identifies sha512crypt."""
        hash_str = "$6$salt$SomeHashValueHereThatIsReasonablyLongForIdentification"
        types = identify_hash_type(hash_str)
        assert "sha512crypt" in types

    def test_mysql5_identifies(self):
        """*<40hex> pattern identifies MySQL5."""
        mysql5 = "*" + "a" * 40
        types = identify_hash_type(mysql5)
        assert "MySQL5" in types

    def test_mysql3_identifies(self):
        """16-char hex identifies MySQL3."""
        mysql3 = "a" * 16
        types = identify_hash_type(mysql3)
        assert "MySQL3" in types

    def test_crc32_identifies(self):
        """8-char hex identifies CRC32 and Adler32."""
        crc = "a" * 8
        types = identify_hash_type(crc)
        assert "CRC32" in types
        assert "Adler32" in types

    def test_invalid_too_short_returns_empty(self):
        """A string shorter than 8 chars should match no pattern."""
        types = identify_hash_type("abc123")
        assert types == []

    def test_invalid_empty_string_returns_empty(self):
        """Empty string matches nothing."""
        types = identify_hash_type("")
        assert types == []

    def test_invalid_non_hex_returns_empty(self):
        """A string with non-hex characters (e.g. 'xyz') should not match pure-hex patterns."""
        # Note: 32 chars of 'g' (non-hex) should not match MD5
        bad = "g" * 32
        types = identify_hash_type(bad)
        # Should NOT contain MD5, NTLM, etc. since 'g' is not [a-f0-9]
        assert "MD5" not in types
        assert "NTLM" not in types

    def test_special_chars_returns_empty(self):
        """Hash with special characters is not a valid hex hash."""
        types = identify_hash_type("!@#$%^&*()_+{}|:<>?")
        assert types == []

    def test_whitespace_is_stripped(self):
        """Leading/trailing whitespace should be stripped before identification."""
        md5_hash = "  5f4dcc3b5aa765d61d8327deb882cf99  "
        types = identify_hash_type(md5_hash)
        assert "MD5" in types

    def test_sha384_96_hex_identifies(self):
        """96-char hex matches SHA384."""
        sha384 = "a" * 96
        types = identify_hash_type(sha384)
        assert "SHA384" in types

    def test_sha224_56_hex_identifies(self):
        """56-char hex matches SHA224."""
        sha224 = "a" * 56
        types = identify_hash_type(sha224)
        assert "SHA224" in types


# ──────────────────────────────────────────────
#  crack() — async rainbow-table cracker
# ──────────────────────────────────────────────


class TestCrackRainbow:
    """Tests for the async crack() function."""

    @pytest.mark.asyncio
    async def test_crack_md5_password(self):
        """MD5 of 'password' should be cracked via rainbow table."""
        md5_of_password = "5f4dcc3b5aa765d61d8327deb882cf99"
        report = await crack(md5_of_password)

        assert isinstance(report, CrackReport)
        assert report.total == 1
        assert report.cracked == 1

        result = report.hashes[0]
        assert result.cracked is True
        assert result.plaintext == "password"
        assert result.crack_method == "rainbow"
        assert "MD5" in result.identified_types

    @pytest.mark.asyncio
    async def test_crack_md5_123456(self):
        """MD5 of '123456' should be cracked."""
        md5_of_123456 = hashlib.md5(b"123456").hexdigest()
        report = await crack(md5_of_123456)
        assert report.cracked == 1
        assert report.hashes[0].plaintext == "123456"

    @pytest.mark.asyncio
    async def test_crack_sha1_password(self):
        """SHA1 of 'password' should be cracked."""
        sha1_of_password = hashlib.sha1(b"password").hexdigest()
        report = await crack(sha1_of_password)
        assert report.cracked == 1
        assert report.hashes[0].plaintext == "password"
        assert report.hashes[0].crack_method == "rainbow"

    @pytest.mark.asyncio
    async def test_crack_sha256_password(self):
        """SHA256 of 'password' should be cracked."""
        sha256_of_password = hashlib.sha256(b"password").hexdigest()
        report = await crack(sha256_of_password)
        assert report.cracked == 1
        assert report.hashes[0].plaintext == "password"

    @pytest.mark.asyncio
    async def test_crack_sha512_password(self):
        """SHA512 of 'password' should be cracked."""
        sha512_of_password = hashlib.sha512(b"password").hexdigest()
        report = await crack(sha512_of_password)
        assert report.cracked == 1
        assert report.hashes[0].plaintext == "password"

    @pytest.mark.asyncio
    async def test_crack_unknown_hash_returns_not_cracked(self):
        """A random hash not in the rainbow table should return cracked=False."""
        # Use a realistic but obscure MD5 that won't be in common wordlists
        unknown = hashlib.md5(b"xK9!mP2@qR5#zL8^").hexdigest()
        report = await crack(unknown)
        assert report.total == 1
        assert report.cracked == 0
        assert report.hashes[0].cracked is False
        assert report.hashes[0].plaintext is None

    @pytest.mark.asyncio
    async def test_crack_garbage_hex_not_cracked(self):
        """All-zeros hex is valid MD5 format but won't be in the rainbow table."""
        report = await crack("0" * 32)
        assert report.cracked == 0

    @pytest.mark.asyncio
    async def test_crack_identify_only_does_not_crack(self):
        """identify_only=True should identify types but skip cracking."""
        md5_of_password = "5f4dcc3b5aa765d61d8327deb882cf99"
        report = await crack(md5_of_password, identify_only=True)
        assert report.total == 1
        assert report.cracked == 0
        assert len(report.hashes[0].identified_types) > 0  # types identified
        assert report.hashes[0].cracked is False

    @pytest.mark.asyncio
    async def test_crack_with_list_of_hashes(self):
        """Passing a list should crack each independently."""
        md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"   # md5("password")
        md5_admin = hashlib.md5(b"admin").hexdigest()          # md5("admin")
        sha1_hello = hashlib.sha1(b"hello").hexdigest()

        report = await crack([md5_password, md5_admin, sha1_hello])
        assert report.total == 3
        assert report.cracked >= 2  # password and admin should both crack

    @pytest.mark.asyncio
    async def test_crack_comma_separated_string(self):
        """String input with commas should be split and cracked individually."""
        md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"
        md5_123456 = hashlib.md5(b"123456").hexdigest()
        input_str = f"{md5_password},{md5_123456}"

        report = await crack(input_str)
        assert report.total == 2
        assert report.cracked == 2

    @pytest.mark.asyncio
    async def test_crack_newline_separated_string(self):
        """String input with newlines should also be split correctly."""
        md5_password = "5f4dcc3b5aa765d61d8327deb882cf99"
        md5_root = hashlib.md5(b"root").hexdigest()
        input_str = f"{md5_password}\n{md5_root}"

        report = await crack(input_str)
        assert report.total == 2
        assert report.cracked == 2

    @pytest.mark.asyncio
    async def test_crack_returns_duration(self):
        """CrackReport should include a non-negative duration."""
        report = await crack("5f4dcc3b5aa765d61d8327deb882cf99")
        assert report.duration_seconds >= 0

    @pytest.mark.asyncio
    async def test_crack_empty_input_returns_zero_total(self):
        """Empty / whitespace-only input should return total=0."""
        report = await crack("")
        assert report.total == 0
        assert report.cracked == 0
        assert report.hashes == []

    @pytest.mark.asyncio
    async def test_crack_whitespace_only_returns_zero_total(self):
        """Whitespace-only input should return total=0."""
        report = await crack("   \n  \t  ")
        assert report.total == 0

    @pytest.mark.asyncio
    async def test_crack_case_insensitive(self):
        """Uppercase MD5 should still be cracked."""
        upper_md5 = "5F4DCC3B5AA765D61D8327DEB882CF99"
        report = await crack(upper_md5)
        assert report.cracked == 1
        assert report.hashes[0].plaintext == "password"


# ──────────────────────────────────────────────
#  crack with explicit types via _crack_single
# ──────────────────────────────────────────────


class TestCrackWithExplicitTypes:
    """Tests for _crack_single() with explicit hash_types parameter."""

    def test_explicit_md5_type_cracks_password(self):
        """Forcing MD5 type should crack the MD5 of 'password'."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = _crack_single(md5_hash, ["MD5"])
        assert result.cracked is True
        assert result.plaintext == "password"
        assert result.crack_method == "rainbow"

    def test_explicit_sha1_type_does_not_crack_md5(self):
        """Forcing SHA1 type on an MD5 hash should not crack it."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = _crack_single(md5_hash, ["SHA1"])
        assert result.cracked is False

    def test_explicit_ntlm_type_cracks_via_md5_fallback(self):
        """NTLM cracking uses MD5 rainbow table as fallback (per module implementation)."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = _crack_single(md5_hash, ["NTLM"])
        assert result.cracked is True
        assert result.plaintext == "password"

    def test_multiple_types_tried_in_order(self):
        """When multiple types given, first matching type wins."""
        # "admin" is in _COMMON_PASSWORDS — MD5 won't match a 40-char hash,
        # but SHA1 will be tried next and should succeed.
        sha1_hash = hashlib.sha1(b"admin").hexdigest()
        assert len(sha1_hash) == 40
        result = _crack_single(sha1_hash, ["MD5", "SHA1", "SHA256"])
        assert result.cracked is True
        assert result.plaintext == "admin"

    def test_sha256_type_cracks_correctly(self):
        """Explicit SHA256 type should crack SHA256 hashes."""
        sha256_hash = hashlib.sha256(b"admin").hexdigest()
        result = _crack_single(sha256_hash, ["SHA256"])
        assert result.cracked is True
        assert result.plaintext == "admin"

    def test_sha512_type_cracks_correctly(self):
        """Explicit SHA512 type should crack SHA512 hashes."""
        sha512_hash = hashlib.sha512(b"root").hexdigest()
        result = _crack_single(sha512_hash, ["SHA512"])
        assert result.cracked is True
        assert result.plaintext == "root"

    def test_empty_types_list_returns_not_cracked(self):
        """Empty types list should return cracked=False."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = _crack_single(md5_hash, [])
        assert result.cracked is False

    def test_result_stores_identified_types(self):
        """The HashResult should carry back the types list passed in."""
        md5_hash = "5f4dcc3b5aa765d61d8327deb882cf99"
        result = _crack_single(md5_hash, ["MD5", "NTLM"])
        assert result.identified_types == ["MD5", "NTLM"]


# ──────────────────────────────────────────────
#  report_to_mirv_findings — findings conversion
# ──────────────────────────────────────────────


class TestReportToMIRVFindings:
    """Tests for report_to_mirv_findings()."""

    @pytest.mark.asyncio
    async def test_cracked_hash_produces_high_severity_finding(self):
        """A cracked hash should produce a 'high' severity finding."""
        report = await crack("5f4dcc3b5aa765d61d8327deb882cf99")
        findings = report_to_mirv_findings(report)
        assert len(findings) >= 1  # at least the cracked finding + summary

        cracked_finding = findings[0]
        assert cracked_finding["severity"] == "high"
        assert cracked_finding["tool"] == "hash-cracker"
        assert cracked_finding["type"] == "vuln"
        assert "password" in cracked_finding["detail"]

    @pytest.mark.asyncio
    async def test_unidentified_hash_produces_low_severity_finding(self):
        """A hash not matching any pattern should produce 'low' severity."""
        report = await crack("zzzz")  # not valid hex, not matching any pattern
        findings = report_to_mirv_findings(report)
        low_findings = [f for f in findings if f["severity"] == "low"]
        assert len(low_findings) >= 1

    @pytest.mark.asyncio
    async def test_summary_finding_appended(self):
        """The last finding should always be the summary (severity=info)."""
        report = await crack("5f4dcc3b5aa765d61d8327deb882cf99")
        findings = report_to_mirv_findings(report)
        summary = findings[-1]
        assert summary["severity"] == "info"
        assert "Crack complete" in summary["title"]
        assert summary["tool"] == "hash-cracker"

    @pytest.mark.asyncio
    async def test_empty_report_returns_no_hashes_finding(self):
        """An empty CrackReport should return a single info finding."""
        empty_report = CrackReport(hashes=[], total=0, cracked=0, duration_seconds=0.0)
        findings = report_to_mirv_findings(empty_report)
        assert len(findings) == 1
        assert findings[0]["title"] == "No hashes provided"
        assert findings[0]["severity"] == "info"

    @pytest.mark.asyncio
    async def test_findings_include_extra_metadata(self):
        """Each cracked/identified finding should include 'extra' with hash details."""
        report = await crack("5f4dcc3b5aa765d61d8327deb882cf99")
        findings = report_to_mirv_findings(report)
        cracked_finding = findings[0]
        assert "extra" in cracked_finding
        assert cracked_finding["extra"]["hash"] == "5f4dcc3b5aa765d61d8327deb882cf99"
        assert cracked_finding["extra"]["cracked"] is True
        assert cracked_finding["extra"]["plaintext"] == "password"

    @pytest.mark.asyncio
    async def test_uncracked_identified_finding_has_medium_severity(self):
        """A hash that's identified but not cracked should have 'medium' severity."""
        # "123456" is in the rainbow table, so use something identified but not in table
        # A random MD5 that IS valid hex (so identified as MD5) but not in rainbow
        unknown_md5 = hashlib.md5(b"ObscurePassword!98765").hexdigest()
        report = await crack(unknown_md5)
        findings = report_to_mirv_findings(report)
        medium_findings = [f for f in findings if f["severity"] == "medium"]
        assert len(medium_findings) >= 1
        assert medium_findings[0]["type"] == "tech"


# ──────────────────────────────────────────────
#  Rainbow table correctness
# ──────────────────────────────────────────────


class TestRainbowTable:
    """Verify rainbow table is built correctly."""

    def test_build_rainbow_populates_tables(self):
        """_build_rainbow() should populate all four tables."""
        _build_rainbow()
        from hash_cracker import _RAINBOW_MD5, _RAINBOW_SHA1, _RAINBOW_SHA256, _RAINBOW_SHA512
        assert len(_RAINBOW_MD5) > 0
        assert len(_RAINBOW_SHA1) > 0
        assert len(_RAINBOW_SHA256) > 0
        assert len(_RAINBOW_SHA512) > 0

    def test_rainbow_md5_contains_password(self):
        """The MD5 rainbow table should contain 'password'."""
        _build_rainbow()
        from hash_cracker import _RAINBOW_MD5
        md5_password = hashlib.md5(b"password").hexdigest()
        assert md5_password in _RAINBOW_MD5
        assert _RAINBOW_MD5[md5_password] == "password"

    def test_rainbow_sha1_contains_password(self):
        """The SHA1 rainbow table should contain 'password'."""
        _build_rainbow()
        from hash_cracker import _RAINBOW_SHA1
        sha1_password = hashlib.sha1(b"password").hexdigest()
        assert _RAINBOW_SHA1[sha1_password] == "password"

    def test_rainbow_sha256_contains_password(self):
        """The SHA256 rainbow table should contain 'password'."""
        _build_rainbow()
        from hash_cracker import _RAINBOW_SHA256
        sha256_password = hashlib.sha256(b"password").hexdigest()
        assert _RAINBOW_SHA256[sha256_password] == "password"

    def test_rainbow_sha512_contains_password(self):
        """The SHA512 rainbow table should contain 'password'."""
        _build_rainbow()
        from hash_cracker import _RAINBOW_SHA512
        sha512_password = hashlib.sha512(b"password").hexdigest()
        assert _RAINBOW_SHA512[sha512_password] == "password"

    def test_build_rainbow_idempotent(self):
        """Calling _build_rainbow() twice should not double the table size."""
        _build_rainbow()
        from hash_cracker import _RAINBOW_MD5
        size_before = len(_RAINBOW_MD5)
        _build_rainbow()
        size_after = len(_RAINBOW_MD5)
        assert size_before == size_after


# ──────────────────────────────────────────────
#  Dataclass contracts
# ──────────────────────────────────────────────


class TestDataclasses:
    """Verify dataclass structure and immutability."""

    def test_hash_result_frozen(self):
        """HashResult is frozen — attribute assignment should raise."""
        hr = HashResult(hash_value="abc", identified_types=["MD5"], cracked=False)
        with pytest.raises(AttributeError):
            hr.cracked = True  # type: ignore[misc]

    def test_crack_report_fields(self):
        """CrackReport should have the expected fields."""
        report = CrackReport(hashes=[], total=0, cracked=0, duration_seconds=0.0)
        assert report.total == 0
        assert report.cracked == 0
        assert report.hashes == []
        assert report.duration_seconds == 0.0

    def test_hash_result_defaults(self):
        """HashResult defaults: plaintext=None, crack_method=None."""
        hr = HashResult(hash_value="abc", identified_types=[], cracked=False)
        assert hr.plaintext is None
        assert hr.crack_method is None
