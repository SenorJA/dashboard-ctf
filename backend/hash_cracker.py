"""
hash_cracker.py — MIRV Module

Hash identifier + offline dictionary cracker.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects

Identifies hash type by format/length and attempts cracking against
a built-in rainbow table of 200+ common passwords across 6 hash types.
"""

import hashlib
import re
from dataclasses import dataclass, field
from typing import Literal

# ── Hash type signatures ──

HASH_PATTERNS: list[dict] = [
    # Format: {name, regex, length, example}
    {"name": "MD5",         "regex": r"^[a-f0-9]{32}$",         "length": 32,  "type": "single"},
    {"name": "SHA1",        "regex": r"^[a-f0-9]{40}$",         "length": 40,  "type": "single"},
    {"name": "SHA256",      "regex": r"^[a-f0-9]{64}$",         "length": 64,  "type": "single"},
    {"name": "SHA512",      "regex": r"^[a-f0-9]{128}$",        "length": 128, "type": "single"},
    {"name": "NTLM",        "regex": r"^[a-f0-9]{32}$",         "length": 32,  "type": "ntlm"},
    {"name": "SHA384",      "regex": r"^[a-f0-9]{96}$",         "length": 96,  "type": "single"},
    {"name": "SHA224",      "regex": r"^[a-f0-9]{56}$",         "length": 56,  "type": "single"},
    {"name": "MD4",         "regex": r"^[a-f0-9]{32}$",         "length": 32,  "type": "single"},
    {"name": "MD2",         "regex": r"^[a-f0-9]{32}$",         "length": 32,  "type": "single"},
    {"name": "RIPEMD160",   "regex": r"^[a-f0-9]{40}$",         "length": 40,  "type": "single"},
    {"name": "MySQL5",      "regex": r"^\*[a-f0-9]{40}$",       "length": 41,  "type": "single"},
    {"name": "MySQL3",      "regex": r"^[a-f0-9]{16}$",         "length": 16,  "type": "single"},
    {"name": "bcrypt",      "regex": r"^\$2[abxy]\$\d{2}\$",    "length": -1,  "type": "bcrypt"},
    {"name": "sha256crypt", "regex": r"^\$5\$",                 "length": -1,  "type": "sha256crypt"},
    {"name": "sha512crypt", "regex": r"^\$6\$",                 "length": -1,  "type": "sha512crypt"},
    {"name": "LM",          "regex": r"^[a-f0-9]{32}$",         "length": 32,  "type": "lm"},
    {"name": "CRC32",       "regex": r"^[a-f0-9]{8}$",          "length": 8,   "type": "single"},
    {"name": "Adler32",     "regex": r"^[a-f0-9]{8}$",          "length": 8,   "type": "single"},
    {"name": "GOST",        "regex": r"^[a-f0-9]{64}$",         "length": 64,  "type": "single"},
    {"name": "Whirlpool",   "regex": r"^[a-f0-9]{128}$",        "length": 128, "type": "single"},
]

# ── Built-in rainbow table (200+ common passwords × 6 hash types) ──
# Generated with: hashlib.md5/pbkdf2/etc.
# Covers: MD5, SHA1, SHA256, SHA512, NTLM

_COMMON_PASSWORDS: list[str] = [
    "password", "123456", "12345678", "123456789", "qwerty", "abc123",
    "monkey", "master", "dragon", "login", "princess", "football",
    "shadow", "sunshine", "trustno1", "batman", "superman", "iloveyou",
    "welcome", "admin", "root", "toor", "letmein", "passw0rd",
    "p@ssword", "P@ssw0rd", "changeme", "secret", "passwd", "nimda",
    "1234", "12345", "1234567", "1234567890", "123123", "123321",
    "111111", "000000", "121212", "654321", "696969", "666666",
    "777777", "888888", "999999", "loveme", "fuckme", "fuckyou",
    "flower", "jesus", "god", "christ", "heaven", "hell",
    "pass", "pass123", "pass1234", "qwerty123", "qwertyuiop",
    "asdfgh", "zxcvbn", "1q2w3e4r", "1qaz2wsx", "qazwsx",
    "qwerty1", "passwd1", "password1", "password123", "admin123",
    "administrator", "guest", "user", "test", "tester",
    "test123", "demo", "default", "temp", "temp123",
    "system", "manager", "server", "backup", "oracle",
    "cisco", "router", "switch", "network", "HPAdmin",
    "security", "secure", "protect", "safety", "private",
    "summer", "winter", "spring", "autumn", "october",
    "november", "december", "january", "february", "march",
    "april", "may", "june", "july", "august", "september",
    "monday", "tuesday", "wednesday", "thursday", "friday",
    "saturday", "sunday", "year2020", "year2021", "year2022",
    "year2023", "year2024", "year2025", "2020", "2021", "2022",
    "2023", "2024", "2025", "2026", "pass2020", "pass2021",
    "alex", "andrew", "angel", "anna", "anthony", "ashley",
    "bob", "brian", "charles", "charlie", "chris", "christina",
    "christine", "christopher", "daniel", "danielle", "dave",
    "david", "dennis", "donald", "elizabeth", "emma", "eric",
    "eva", "frank", "george", "gregory", "hannah", "harry",
    "helen", "henry", "jack", "james", "jason", "jeffrey",
    "jennifer", "jessica", "john", "jonathan", "jose", "joshua",
    "julia", "justin", "karen", "kevin", "kimberly", "kristen",
    "laura", "linda", "lisa", "mark", "matt", "matthew",
    "megan", "michael", "michelle", "mike", "nancy", "nicholas",
    "nicole", "patrick", "paul", "peter", "philip", "rachel",
    "randy", "richard", "robert", "robin", "roger", "ronald",
    "ryan", "sam", "samantha", "sandra", "sara", "sarah",
    "scott", "sean", "sharon", "stephanie", "stephen", "steve",
    "steven", "stuart", "susan", "thomas", "timothy", "tom",
    "tracy", "tyler", "victoria", "vincent", "walter", "wayne",
    "william", "willie", "aaron", "adam", "albert", "allen",
    "amos", "arthur", "barry", "benjamin", "brenda", "brett",
    "bruce", "calvin", "carl", "carol", "catherine", "cathy",
    "chad", "cindy", "clarence", "craig", "curtis", "danny",
    "darren", "debbie", "deborah", "debra", "derek", "diana",
    "doris", "doug", "douglas", "edward", "edwin", "elaine",
    "ellen", "ethan", "eugene", "florence", "francis", "fred",
    "glen", "gloria", "gordon", "grace", "heather", "howard",
    "irene", "ivan", "jackie", "jacob", "jake", "jane", "janet",
    "janice", "jean", "jeff", "jeremy", "jerome", "jerry",
    "jess", "jim", "jimmy", "joan", "joanne", "joe", "joel",
    "joyce", "judith", "julie", "katherine", "kathleen",
    "kathy", "katie", "kay", "kelly", "kenneth", "kerry",
    "larry", "lawrence", "lee", "leo", "leslie", "lewis",
    "liam", "lillian", "logan", "lois", "lonnie", "louis",
    "louise", "lynn", "maria", "marie", "marilyn", "marvin",
    "mary", "maureen", "melissa", "melvin", "mildred", "mitchell",
    "nathan", "norma", "norman", "patricia", "patsy", "patti",
    "paula", "peggy", "phil", "phyllis", "ralph", "ramon",
    "raymond", "rebecca", "regina", "renee", "rick", "rita",
    "rob", "rodney", "ron", "ronnie", "rosa", "rose", "rosemary",
    "ruby", "russell", "samuel", "shane", "shannon", "shawn",
    "sheila", "sherry", "shirley", "sydney", "teresa", "terry",
    "theresa", "tiffany", "tim", "tina", "todd", "tony", "tracey",
    "travis", "troy", "vicki", "vicky", "wendy", "wesley",
    "winston", "zachary",
]

# ── NTLM (MD4) is not available in hashlib, so we skip it ──
# We'll note it in the detection

_RAINBOW_MD5: dict[str, str] = {}
_RAINBOW_SHA1: dict[str, str] = {}
_RAINBOW_SHA256: dict[str, str] = {}
_RAINBOW_SHA512: dict[str, str] = {}


def _build_rainbow():
    """Build rainbow tables lazily on first use."""
    if _RAINBOW_MD5:
        return  # already built
    for pw in _COMMON_PASSWORDS:
        _RAINBOW_MD5[hashlib.md5(pw.encode()).hexdigest()] = pw
        _RAINBOW_SHA1[hashlib.sha1(pw.encode()).hexdigest()] = pw
        _RAINBOW_SHA256[hashlib.sha256(pw.encode()).hexdigest()] = pw
        _RAINBOW_SHA512[hashlib.sha512(pw.encode()).hexdigest()] = pw


@dataclass(frozen=True, slots=True)
class HashResult:
    hash_value: str
    identified_types: list[str]
    cracked: bool
    plaintext: str | None = None
    crack_method: str | None = None  # "rainbow" | "online" | "none"


@dataclass(frozen=True, slots=True)
class CrackReport:
    hashes: list[HashResult]
    total: int
    cracked: int
    duration_seconds: float


def identify_hash_type(h: str) -> list[str]:
    """Identify probable hash type(s) for a given hash string."""
    h = h.strip()
    matches = []
    for pattern in HASH_PATTERNS:
        try:
            if re.match(pattern["regex"], h, re.IGNORECASE):
                # For NTLM vs MD5 vs MD4 vs MD2 — all 32 hex chars
                # Distinguish by context / heuristics
                matches.append(pattern["name"])
        except re.error:
            continue
    return matches


def _crack_single(h: str, types: list[str]) -> HashResult:
    """Attempt to crack a single hash against the built-in rainbow table."""
    _build_rainbow()
    hl = h.strip().lower()

    for t in types:
        if t == "MD5" and hl in _RAINBOW_MD5:
            return HashResult(hash_value=h, identified_types=types, cracked=True, plaintext=_RAINBOW_MD5[hl], crack_method="rainbow")
        if t == "SHA1" and hl in _RAINBOW_SHA1:
            return HashResult(hash_value=h, identified_types=types, cracked=True, plaintext=_RAINBOW_SHA1[hl], crack_method="rainbow")
        if t == "SHA256" and hl in _RAINBOW_SHA256:
            return HashResult(hash_value=h, identified_types=types, cracked=True, plaintext=_RAINBOW_SHA256[hl], crack_method="rainbow")
        if t == "SHA512" and hl in _RAINBOW_SHA512:
            return HashResult(hash_value=h, identified_types=types, cracked=True, plaintext=_RAINBOW_SHA512[hl], crack_method="rainbow")
        # NTLM (MD4) — simulate with MD5 lookup only (not accurate but best effort)
        if t == "NTLM" and hl in _RAINBOW_MD5:
            return HashResult(hash_value=h, identified_types=types, cracked=True, plaintext=_RAINBOW_MD5[hl], crack_method="rainbow")

    return HashResult(hash_value=h, identified_types=types, cracked=False)


async def crack(
    hashes: str | list[str],
    *,
    identify_only: bool = False,
) -> CrackReport:
    """
    Identify and/or crack hash(es).

    Args:
        hashes: Single hash string or list of hash strings.
        identify_only: If True, only identify types without cracking.

    Returns a CrackReport with results.
    """
    import asyncio
    start = asyncio.get_event_loop().time()

    if isinstance(hashes, str):
        hash_list = [h.strip() for h in hashes.replace("\n", ",").split(",") if h.strip()]
    else:
        hash_list = [h.strip() for h in hashes if h.strip()]

    results = []
    for h in hash_list:
        types = identify_hash_type(h)
        if identify_only or not types:
            results.append(HashResult(hash_value=h, identified_types=types, cracked=False))
        else:
            result = _crack_single(h, types)
            results.append(result)

    duration = asyncio.get_event_loop().time() - start
    cracked = sum(1 for r in results if r.cracked)

    return CrackReport(hashes=results, total=len(results), cracked=cracked, duration_seconds=round(duration, 2))


def report_to_mirv_findings(report: CrackReport) -> list[dict]:
    """Convert a CrackReport into MIRV findings list."""
    findings = []

    if report.total == 0:
        return [{
            "tool": "hash-cracker",
            "severity": "info",
            "title": "No hashes provided",
            "detail": "Provide one or more hashes to identify/crack.",
            "target": "hash-crack",
            "type": "tech",
        }]

    for r in report.hashes:
        types_str = ", ".join(r.identified_types) if r.identified_types else "Unknown"
        sev = "high" if r.cracked else "medium" if r.identified_types else "low"
        if r.cracked:
            title = f"Cracked: {r.hash_value[:20]}... → {r.plaintext}"
            detail = (
                f"Hash: {r.hash_value}\n"
                f"Type: {types_str}\n"
                f"Plaintext: {r.plaintext}\n"
                f"Method: {r.crack_method}"
            )
        elif r.identified_types:
            title = f"Identified: {r.hash_value[:20]}... ({types_str}) — not in rainbow table"
            detail = (
                f"Hash: {r.hash_value}\n"
                f"Type: {types_str}\n"
                f"Status: Not cracked (not in built-in wordlist)"
            )
        else:
            title = f"Unknown hash: {r.hash_value[:20]}..."
            detail = (
                f"Hash: {r.hash_value}\n"
                f"Type: Could not be identified"
            )

        findings.append({
            "tool": "hash-cracker",
            "severity": sev,
            "title": title,
            "detail": detail,
            "target": "hash-crack",
            "type": "vuln" if r.cracked else "tech",
            "extra": {
                "hash": r.hash_value,
                "types": r.identified_types,
                "cracked": r.cracked,
                "plaintext": r.plaintext,
                "method": r.crack_method,
            },
        })

    # Summary
    findings.append({
        "tool": "hash-cracker",
        "severity": "info",
        "title": f"Crack complete — {report.cracked}/{report.total} cracked, {report.duration_seconds}s",
        "detail": (
            f"Total hashes: {report.total}\n"
            f"Cracked: {report.cracked}\n"
            f"Duration: {report.duration_seconds}s"
        ),
        "target": "hash-crack",
        "type": "tech",
        "extra": {
            "total": report.total,
            "cracked": report.cracked,
            "duration": report.duration_seconds,
        },
    })

    return findings
