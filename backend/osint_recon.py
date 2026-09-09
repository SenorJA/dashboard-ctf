"""
osint_recon.py -- MIRV Module

Passive OSINT reconnaissance, ported from ``fawadqureshi007/Black``
(BlackTrace / DARKNET OSINT RECON PROBE) and adapted to the MIRV
security-audit style.

Scope:
  - **Public data only.** No scanning, no exploitation, no credentials
    harvesting. Every lookup is against public APIs / public web pages
    and is rate-limited with hard timeouts.
  - **stdlib only** (``urllib.request`` + ``socket`` + ``asyncio``).
    Optional API keys are read from environment variables and the whole
    module degrades gracefully when they are absent:
      ``HIBP_API_KEY``, ``GITHUB_TOKEN``, ``NUMVERIFY_API_KEY``,
      ``IPINFO_TOKEN``, ``ABUSEIPDB_API_KEY`` (alias ``ABUSEIPDB_KEY``),
      ``TINEYE_API_KEY``.

Modules implemented (BlackTrace mapping):
  - ``check_email_breach``   -> email_analysis (HackerTarget pastebin + optional HIBP)
  - ``verify_email``         -> email_lookup_and_verification (format + MX via DNS-over-HTTPS)
  - ``google_dorking``       -> google_dorking (DuckDuckGo HTML + Bing HTML parse)
  - ``phone_number_lookup``  -> phone_number_lookup (numverify optional + public fallback)
  - ``reverse_image_search`` -> reverse_image_search (TinEye optional + DDG fallback)
  - ``wayback_machine_lookup`` -> wayback_machine_lookup (CDX API)
  - ``ip_geolocation``       -> ip_geolocation_blacklist (ipinfo.io + optional AbuseIPDB)
  - ``username_recon``       -> social_media_investigation (HEAD probe of ~18 platforms)
  - ``github_recon``         -> github_recon (api.github.com user + repos)

Ronda API-based #2 (from the ``cporter202/agentic-ai-apis`` catalogue, all
keyless public APIs, one per network-data / security / lookup category):
  - ``dns_recon``            -> DNS-over-HTTPS (dns.google) A/AAAA/MX/NS/CNAME/TXT
  - ``rdap_whois``           -> RDAP (rdap.org) registrar + events + nameservers
  - ``pwned_passwords``      -> HIBP Pwned Passwords k-anonymity range (no key)
  - ``urlhaus_lookup``       -> abuse.ch URLhaus URL/host reputation (POST)
  - ``page_snapshot``        -> Jina Reader (r.jina.ai) page-content extraction

All public functions are ``async``, never raise, and return JSON-serializable
dicts (``{"ok": True, ...}`` or ``{"ok": False, "error": ...}``). Use them from
async route handlers directly — blocking I/O runs via ``asyncio.to_thread``.
"""

from __future__ import annotations

import asyncio
import hashlib
import html
import ipaddress
import json
import logging
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# -- Logger (no secrets) --
_logger = logging.getLogger("vulnforge.osint_recon")

# ════════════════════════════════════════════════════════════════
#  Constants
# ════════════════════════════════════════════════════════════════

TIMEOUT_DEFAULT = 10.0
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 MIRV-OSINT/1.0"
)
_MAX_BODY = 1024 * 1024  # cap downloads at 1 MiB
_MAX_DORK_PAGES = 5
_MAX_WAYBACK_LIMIT = 200
_MAX_DDG_RESULTS = 50

EMAIL_RE = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
USERNAME_RE = re.compile(r"^[\w.\-]{1,30}$")

# Small inline disposable-email domain list (no external dependency).
DISPOSABLE_DOMAINS = frozenset({
    "mailinator.com", "10minutemail.com", "guerrillamail.com",
    "sharklasers.com", "maildrop.cc", "tempmail.com", "temp-mail.org",
    "throwawaymail.com", "yopmail.com", "getnada.com", "trashmail.com",
    "mailnesia.com", "dispostable.com", "mailcatch.com", "mytemp.email",
    "33mail.com", "spamgourmet.com", "burnermail.io", "inboxbear.com",
    "spambox.us",
})

# Platforms probed by ``username_recon`` (BlackTrace social_media_investigation).
USERNAME_PLATFORMS: dict[str, str] = {
    "GitHub": "https://github.com/{u}",
    "Twitter/X": "https://twitter.com/{u}",
    "Instagram": "https://instagram.com/{u}",
    "Telegram": "https://t.me/{u}",
    "LinkedIn": "https://linkedin.com/in/{u}",
    "Reddit": "https://reddit.com/user/{u}",
    "YouTube": "https://www.youtube.com/@{u}",
    "TikTok": "https://www.tiktok.com/@{u}",
    "Medium": "https://medium.com/@{u}",
    "Pinterest": "https://www.pinterest.com/{u}",
    "Snapchat": "https://www.snapchat.com/add/{u}",
    "Vimeo": "https://vimeo.com/{u}",
    "SoundCloud": "https://soundcloud.com/{u}",
    "Tumblr": "https://{u}.tumblr.com",
    "Quora": "https://www.quora.com/profile/{u}",
    "Steam": "https://steamcommunity.com/id/{u}",
    "Twitch": "https://twitch.tv/{u}",
    "Patreon": "https://www.patreon.com/{u}",
}

_TAG_RE = re.compile(r"<[^>]+>")
_DDG_ANCHOR_RE = re.compile(
    r'<a[^>]+class="result__a"[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S
)
_DDG_SNIPPET_RE = re.compile(
    r'<a[^>]+class="result__snippet"[^>]*>(.*?)</a>', re.S
)
_BING_BLOCK_RE = re.compile(r'<li class="b_algo".*?</li>', re.S)
_BING_LINK_RE = re.compile(
    r'<h2[^>]*>\s*<a[^>]*href="([^"]+)"[^>]*>(.*?)</a>', re.S
)
_BING_SNIPPET_RE = re.compile(r'<div class="b_caption"[^>]*>.*?<p[^>]*>(.*?)</p>', re.S)

__all__ = [
    "TIMEOUT_DEFAULT",
    "USER_AGENT",
    "check_email_breach",
    "verify_email",
    "google_dorking",
    "phone_number_lookup",
    "reverse_image_search",
    "wayback_machine_lookup",
    "ip_geolocation",
    "username_recon",
    "github_recon",
    "dns_recon",
    "rdap_whois",
    "pwned_passwords",
    "urlhaus_lookup",
    "page_snapshot",
]


# ════════════════════════════════════════════════════════════════
#  Internal helpers
# ════════════════════════════════════════════════════════════════

def _get_env(key: str) -> str:
    """Read an optional API key from the environment (never logged)."""
    return os.environ.get(key, "").strip()


def _urlopen_sync(url: str, timeout: float, headers: dict, method: str, data: bytes | None):
    """Blocking urllib GET/HEAD/POST.  Run via ``asyncio.to_thread``."""
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — public OSINT only
        body = resp.read(_MAX_BODY)
        return resp.status, body


async def _fetch(url: str, timeout: float = TIMEOUT_DEFAULT, headers: dict | None = None,
                 method: str = "GET", data: bytes | None = None) -> dict:
    """
    Fetch a URL with a User-Agent and hard timeout.

    Returns ``{"ok": True, "status": int, "text": str}`` on success or
    ``{"ok": False, "status": int|None, "error": str, "body": str}`` on
    failure.  Never raises.
    """
    hdrs = {"User-Agent": USER_AGENT}
    if headers:
        hdrs.update(headers)
    try:
        status, body = await asyncio.to_thread(_urlopen_sync, url, timeout, hdrs, method, data)
        return {"ok": True, "status": status, "text": body.decode("utf-8", errors="replace")}
    except urllib.error.HTTPError as e:  # noqa: PERF203
        try:
            err_body = e.read(_MAX_BODY).decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            err_body = ""
        return {"ok": False, "status": e.code, "error": f"HTTP {e.code}", "body": err_body}
    except urllib.error.URLError as e:  # noqa: PERF203
        return {"ok": False, "status": None, "error": f"Network error: {e.reason}", "body": ""}
    except (socket.timeout, TimeoutError):  # noqa: PERF203
        return {"ok": False, "status": None, "error": f"Timeout after {timeout}s", "body": ""}
    except Exception as e:  # noqa: BLE001
        _logger.debug("_fetch failed for %s: %s", url, e)
        return {"ok": False, "status": None, "error": str(e), "body": ""}


def _parse_json(resp: dict) -> Any | None:
    """Best-effort JSON parse of a ``_fetch`` response (body on HTTP error)."""
    text = resp.get("text") if resp.get("ok") else resp.get("body", "")
    if not text:
        return None
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return None


def _clean_text(raw: str) -> str:
    """Strip HTML tags and unescape entities."""
    return html.unescape(_TAG_RE.sub("", raw)).strip()


def _ddg_redirect_url(href: str) -> str:
    """Resolve DuckDuckGo ``/l/?uddg=`` redirect links to the real URL."""
    if "uddg=" in href:
        parsed = urllib.parse.urlparse(href)
        qs = urllib.parse.parse_qs(parsed.query)
        if qs.get("uddg"):
            return qs["uddg"][0]
    return href


def _parse_ddg_results(text: str) -> list[dict]:
    """Parse DuckDuckGo HTML search results into title/url/snippet dicts."""
    results: list[dict] = []
    for m in _DDG_ANCHOR_RE.finditer(text):
        href = html.unescape(m.group(1).strip())
        url = _ddg_redirect_url(href)
        if not url.startswith(("http://", "https://")):
            continue
        results.append({
            "title": _clean_text(m.group(2)),
            "url": url,
            "snippet": "",
            "engine": "duckduckgo",
        })
    snippets = _DDG_SNIPPET_RE.findall(text)
    for i, snip in enumerate(snippets[: len(results)]):
        results[i]["snippet"] = _clean_text(snip)
    return results


def _parse_bing_results(text: str) -> list[dict]:
    """Parse Bing HTML search results into title/url/snippet dicts."""
    results: list[dict] = []
    for block in _BING_BLOCK_RE.findall(text):
        lm = _BING_LINK_RE.search(block)
        if not lm:
            continue
        sm = _BING_SNIPPET_RE.search(block)
        results.append({
            "title": _clean_text(lm.group(2)),
            "url": html.unescape(lm.group(1)),
            "snippet": _clean_text(sm.group(1)) if sm else "",
            "engine": "bing",
        })
    return results


def _dedupe_results(results: list[dict], limit: int = _MAX_DDG_RESULTS) -> list[dict]:
    """Deduplicate search results by URL."""
    seen: set[str] = set()
    out: list[dict] = []
    for r in results:
        u = r.get("url", "")
        if u and u not in seen:
            seen.add(u)
            out.append(r)
    return out[:limit]


# ════════════════════════════════════════════════════════════════
#  1. Email breach & paste sweep  (BlackTrace: email_analysis)
# ════════════════════════════════════════════════════════════════

async def check_email_breach(email: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Check an email address against public breach/paste sources.

    Uses the no-key HackerTarget pastebin lookup plus the optional
    HaveIBeenPwned v3 API when ``HIBP_API_KEY`` is set.  Passive: only
    public breach/paste metadata is returned, never credentials.
    """
    email = (email or "").strip()
    if not email or not EMAIL_RE.match(email):
        return {"ok": False, "error": "Invalid email format"}

    paste_urls: list[str] = []
    note = ""
    resp = await _fetch(
        f"https://api.hackertarget.com/pastebin_lookup/?q={urllib.parse.quote(email)}",
        timeout=timeout,
    )
    if resp.get("ok"):
        lines = [ln.strip() for ln in resp["text"].splitlines() if ln.strip()]
        error_lines = [ln for ln in lines if re.match(r"^(error|invalid|api count)", ln, re.I)]
        if error_lines:
            note = f" HackerTarget: {error_lines[0]}"
        else:
            paste_urls = [ln for ln in lines if ln.startswith("http")]
    else:
        note = f" HackerTarget unavailable: {resp.get('error')}"

    breaches: list[dict] = []
    hibp_key = _get_env("HIBP_API_KEY")
    if hibp_key:
        hresp = await _fetch(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}",
            timeout=timeout,
            headers={"hibp-api-key": hibp_key},
        )
        data = _parse_json(hresp)
        if hresp.get("ok") and isinstance(data, list):
            breaches = [
                {
                    "name": b.get("Name"),
                    "date": b.get("BreachDate"),
                    "data_classes": b.get("DataClasses") or [],
                    "description": (b.get("Description") or "")[:200],
                }
                for b in data
                if isinstance(b, dict)
            ]
        elif hresp.get("status") != 404:
            note += f" HIBP unavailable: {hresp.get('error')}"

    found = bool(paste_urls) or bool(breaches)
    return {
        "ok": True,
        "email": email,
        "found": found,
        "paste_urls": paste_urls[:20],
        "breaches": breaches,
        "source": "hackertarget" + ("+hibp" if hibp_key else ""),
        "note": note.strip() or None,
    }


# ════════════════════════════════════════════════════════════════
#  2. Email verification  (BlackTrace: email_lookup_and_verification)
# ════════════════════════════════════════════════════════════════

async def verify_email(email: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Verify an email address: format regex, disposable-domain check and
    MX records via DNS-over-HTTPS (dns.google) with a plain-DNS fallback.

    Passive: no SMTP probing, no emails sent.
    """
    email = (email or "").strip()
    if not email or not EMAIL_RE.match(email):
        return {
            "ok": True,
            "email": email,
            "valid_format": False,
            "domain": None,
            "mx_records": [],
            "disposable": False,
            "domain_resolves": False,
            "note": "Invalid email format",
        }

    domain = email.rsplit("@", 1)[1].lower()
    disposable = domain in DISPOSABLE_DOMAINS
    mx_records: list[str] = []
    domain_resolves = False

    try:
        resp = await _fetch(
            f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type=MX",
            timeout=timeout,
        )
        data = _parse_json(resp)
        if data is not None and isinstance(data, dict):
            answers = data.get("Answer") or []
            mx_records = sorted({
                a.get("data", "").rstrip(".")
                for a in answers
                if isinstance(a, dict) and a.get("type") == 15 and a.get("data")
            })
            domain_resolves = data.get("Status") == 0
    except Exception as e:  # noqa: BLE001
        _logger.debug("DNS-over-HTTPS MX lookup failed for %s: %s", domain, e)

    if not domain_resolves:
        # Fallback: plain system-DNS resolution (A/AAAA) in a thread.
        def _resolve() -> bool:
            try:
                return bool(socket.getaddrinfo(domain, None, proto=socket.IPPROTO_TCP))
            except Exception:  # noqa: BLE001
                return False

        try:
            domain_resolves = await asyncio.to_thread(_resolve)
        except Exception:  # noqa: BLE001
            domain_resolves = False

    return {
        "ok": True,
        "email": email,
        "valid_format": True,
        "domain": domain,
        "mx_records": mx_records,
        "disposable": disposable,
        "domain_resolves": domain_resolves,
    }


# ════════════════════════════════════════════════════════════════
#  3. Search dorking  (BlackTrace: google_dorking)
# ════════════════════════════════════════════════════════════════

async def google_dorking(query: str, pages: int = 1, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Run a search dork against DuckDuckGo (HTML) and Bing.

    Google itself blocks bots, so the search URLs are provided for manual
    use while results are parsed from DDG + Bing.  Uses a browser
    User-Agent and hard timeouts.  Max 5 pages.
    """
    query = (query or "").strip()
    if not query:
        return {"ok": False, "error": "No query provided"}
    try:
        pages = max(1, min(int(pages), _MAX_DORK_PAGES))
    except (TypeError, ValueError):
        pages = 1

    results: list[dict] = []
    for page in range(pages):
        ddg = await _fetch(
            f"https://html.duckduckgo.com/html/?q={urllib.parse.quote(query)}&s={page * 30}",
            timeout=timeout,
        )
        if ddg.get("ok"):
            results.extend(_parse_ddg_results(ddg["text"]))

        bing = await _fetch(
            f"https://www.bing.com/search?q={urllib.parse.quote(query)}&first={page * 10 + 1}",
            timeout=timeout,
        )
        if bing.get("ok"):
            results.extend(_parse_bing_results(bing["text"]))

    deduped = _dedupe_results(results)
    q_enc = urllib.parse.quote(query)
    return {
        "ok": True,
        "query": query,
        "engine": "duckduckgo+bing",
        "pages": pages,
        "result_count": len(deduped),
        "results": deduped,
        "search_urls": {
            "google": f"https://www.google.com/search?q={q_enc}",
            "duckduckgo": f"https://duckduckgo.com/?q={q_enc}",
            "bing": f"https://www.bing.com/search?q={q_enc}",
        },
    }


# ════════════════════════════════════════════════════════════════
#  4. Phone number lookup  (BlackTrace: phone_number_lookup)
# ════════════════════════════════════════════════════════════════

async def phone_number_lookup(phone: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Normalize a phone number and look up carrier/line-type intel.

    Uses the numverify API when ``NUMVERIFY_API_KEY`` is set; otherwise
    degrades to a passive public DuckDuckGo search of the number.
    Never calls or messages the number.
    """
    raw = (phone or "").strip()
    digits = re.sub(r"[^\d]", "", raw)
    if not digits or len(digits) < 7 or len(digits) > 15:
        return {
            "ok": False,
            "error": "Invalid phone number: provide an international number with country code (e.g. +14155551234)",
        }
    e164 = "+" + digits

    country: str | None = None
    carrier: str | None = None
    line_type: str | None = None
    valid = False
    web_results: list[dict] = []

    key = _get_env("NUMVERIFY_API_KEY")
    if key:
        resp = await _fetch(
            f"https://api.numverify.com/validate?access_key={urllib.parse.quote(key)}"
            f"&number={digits}&format=1",
            timeout=timeout,
        )
        data = _parse_json(resp)
        if data is not None and isinstance(data, dict):
            valid = bool(data.get("valid"))
            country = data.get("country_name")
            carrier = data.get("carrier")
            line_type = data.get("line_type")

    if not country:
        # Passive fallback — public search snippets only.
        q = urllib.parse.quote(f'"{e164}" OR "{digits}"')
        resp = await _fetch(f"https://html.duckduckgo.com/html/?q={q}", timeout=timeout)
        if resp.get("ok"):
            web_results = _parse_ddg_results(resp["text"])

    return {
        "ok": True,
        "phone": e164,
        "country": country,
        "carrier": carrier,
        "line_type": line_type,
        "valid": valid,
        "web_results": web_results,
        "note": "Carrier/line type require NUMVERIFY_API_KEY (free tier)." if not key else None,
    }


# ════════════════════════════════════════════════════════════════
#  5. Reverse image search  (BlackTrace: reverse_image_search)
# ════════════════════════════════════════════════════════════════

async def reverse_image_search(image_url: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Reverse-image lookup for a publicly hosted image.

    Uses the TinEye REST API when ``TINEYE_API_KEY`` is set; otherwise
    falls back to a passive DuckDuckGo search for the image URL and
    returns openable engine URLs (Google Lens, Yandex, Bing, SauceNAO).
    """
    image_url = (image_url or "").strip()
    if not image_url.startswith(("http://", "https://")):
        return {"ok": False, "error": "image_url must start with http:// or https://"}

    img_q = urllib.parse.quote(image_url, safe="")
    engines = {
        "Google Lens": f"https://lens.google.com/uploadbyurl?url={img_q}",
        "Yandex": f"https://yandex.com/images/search?rpt=imageview&url={img_q}",
        "Bing Visual": f"https://www.bing.com/images/search?q=imgurl:{img_q}",
        "TinEye": f"https://tineye.com/search?url={img_q}",
        "SauceNAO": f"https://saucenao.com/search.php?url={img_q}",
        "ImgOps": f"https://imgops.com/{img_q}",
    }

    tineye_key = _get_env("TINEYE_API_KEY")
    if tineye_key:
        resp = await _fetch(
            f"https://api.tineye.com/rest/v2/search/?url={img_q}",
            timeout=timeout,
            headers={"x-api-key": tineye_key},
        )
        data = _parse_json(resp)
        if data is not None and isinstance(data.get("results"), list):
            results = [
                {
                    "title": r.get("backlink_title") or r.get("image_name", ""),
                    "url": r.get("backlink_url") or r.get("image_url", ""),
                    "source": "tineye",
                }
                for r in data["results"][:10]
                if isinstance(r, dict)
            ]
            return {
                "ok": True,
                "image_url": image_url,
                "engine": "tineye",
                "results": results,
                "engines": engines,
            }

    q = urllib.parse.quote(f'"{image_url}"')
    resp = await _fetch(f"https://html.duckduckgo.com/html/?q={q}", timeout=timeout)
    results = _parse_ddg_results(resp.get("text", "")) if resp.get("ok") else []
    return {
        "ok": True,
        "image_url": image_url,
        "engine": "duckduckgo",
        "results": results,
        "engines": engines,
        "note": (
            "No TINEYE_API_KEY configured; performed a passive DuckDuckGo search. "
            "Open one of the engine URLs for deeper visual matches."
            if not tineye_key else None
        ),
    }


# ════════════════════════════════════════════════════════════════
#  6. Wayback Machine snapshots  (BlackTrace: wayback_machine_lookup)
# ════════════════════════════════════════════════════════════════

# Strict domain regex: RFC-1035-ish labels, at least one dot, no scheme/port.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(\.[A-Za-z0-9-]{1,63})+$"
)
# Private/reserved TLDs that are not part of the public DNS root and have no
# meaningful Wayback history (e.g. metadata.google.internal, myapp.local).
_PRIVATE_TLDS = {
    "internal", "local", "localhost", "lan", "intranet", "corp",
    "home", "box", "test", "example", "invalid",
}


async def wayback_machine_lookup(domain: str, limit: int = 20, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    List archived snapshots of a domain via the Wayback CDX API.

    Returns at most ``limit`` snapshots (default 20, max 200) with
    timestamp, original URL, HTTP status and the archive URL.

    Strict validation rejects IP addresses (even dressed up as hostnames)
    and private/reserved TLDs that have no public archive history.
    """
    domain = (domain or "").strip().lower()
    if "://" in domain:
        domain = urllib.parse.urlparse(domain).netloc or domain
    domain = domain.split("/")[0].split(":")[0]
    if not domain or "." not in domain or any(c in domain for c in " \t\r\n"):
        return {"ok": False, "error": "Invalid domain. Use a valid domain like 'example.com'"}

    # H-006: strict domain validation — reject IPs and private TLDs.
    if not _DOMAIN_RE.match(domain):
        return {"ok": False, "error": "Invalid domain. Use a valid domain like 'example.com'"}
    try:
        ipaddress.ip_address(domain)
        return {"ok": False, "error": "Invalid domain. IP addresses are not supported"}
    except ValueError:
        pass
    tld = domain.rsplit(".", 1)[-1]
    if tld in _PRIVATE_TLDS:
        return {"ok": False, "error": "Invalid domain. Private/reserved TLD has no public archive"}

    try:
        limit = max(1, min(int(limit), _MAX_WAYBACK_LIMIT))
    except (TypeError, ValueError):
        limit = 20

    cdx = (
        f"https://web.archive.org/cdx/search/cdx?url={urllib.parse.quote(domain)}/*"
        f"&output=json&fl=timestamp,original,statuscode&collapse=urlkey&limit={limit}"
    )
    resp = await _fetch(cdx, timeout=timeout)
    data = _parse_json(resp)
    if data is None:
        return {"ok": False, "error": resp.get("error", "Wayback CDX API unavailable")}
    if not isinstance(data, list):
        return {"ok": False, "error": "Wayback CDX API returned an unexpected payload"}

    rows = data
    # First row is the header when the API returns column names.
    if rows and isinstance(rows[0], list) and rows[0] and "timestamp" in rows[0][0]:
        rows = rows[1:]

    snapshots: list[dict] = []
    for row in rows:
        if not isinstance(row, list) or len(row) < 3:
            continue
        ts, original, status = row[0], row[1], row[2]
        snapshots.append({
            "timestamp": str(ts),
            "url": str(original),
            "status": str(status),
            "archive_url": f"https://web.archive.org/web/{ts}/{original}",
        })

    return {"ok": True, "domain": domain, "limit": limit, "total": len(snapshots), "snapshots": snapshots[:limit]}


# ════════════════════════════════════════════════════════════════
#  7. IP geolocation + optional abuse report  (BlackTrace: ip_geolocation_blacklist)
# ════════════════════════════════════════════════════════════════

async def ip_geolocation(ip: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Geolocate an IP via ipinfo.io (no token needed, rate-limited).

    When ``IPINFO_TOKEN`` is set it is used to lift the rate limit; when
    ``ABUSEIPDB_API_KEY`` (or legacy ``ABUSEIPDB_KEY``) is set, an abuse
    confidence report is attached.  All passive.
    """
    ip = (ip or "").strip()
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": "Invalid IP address syntax"}

    # H-005: reject private/reserved IPs — geolocation is not meaningful.
    if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
        return {"ok": False, "error": "Private/reserved IP — geolocation not meaningful"}

    token = _get_env("IPINFO_TOKEN")
    headers = {"Authorization": f"Bearer {token}"} if token else None
    resp = await _fetch(f"https://ipinfo.io/{urllib.parse.quote(ip)}/json", timeout=timeout, headers=headers)
    data = _parse_json(resp)
    if data is None or not isinstance(data, dict):
        return {"ok": False, "error": resp.get("error", "ipinfo.io geo lookup failed")}

    abuse: dict | None = None
    abuse_key = _get_env("ABUSEIPDB_API_KEY") or _get_env("ABUSEIPDB_KEY")
    if abuse_key:
        aresp = await _fetch(
            f"https://api.abuseipdb.com/api/v2/check?ipAddress={urllib.parse.quote(ip)}&maxAgeInDays=90",
            timeout=timeout,
            headers={"Key": abuse_key, "Accept": "application/json"},
        )
        adata = _parse_json(aresp)
        if adata is not None and isinstance(adata.get("data"), dict):
            d = adata["data"]
            reports = d.get("reports") or []
            abuse = {
                "abuse_confidence_score": d.get("abuseConfidenceScore", 0),
                "total_reports": d.get("totalReports", 0),
                "reports_90d": [
                    {"reported_at": r.get("reportedAt"), "comment": (r.get("comment") or "")[:200]}
                    for r in reports[:3]
                    if isinstance(r, dict)
                ],
            }
        else:
            abuse = {"error": aresp.get("error", "AbuseIPDB API call failed")}

    return {
        "ok": True,
        "ip": ip,
        "city": data.get("city"),
        "region": data.get("region"),
        "country": data.get("country"),
        "org": data.get("org"),
        "loc": data.get("loc"),
        "postal": data.get("postal"),
        "timezone": data.get("timezone"),
        "hostname": data.get("hostname"),
        "abuse": abuse,
    }


# ════════════════════════════════════════════════════════════════
#  8. Username recon across platforms  (BlackTrace: social_media_investigation)
# ════════════════════════════════════════════════════════════════

async def username_recon(username: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Probe ~18 public platforms for a username using HEAD requests.

    Rate-limited: max one HEAD request per platform, per-request timeout
    capped at 5s, concurrency capped at 4.  A profile "exists" when the
    platform does not answer 404/410 (soft-404s are a known limitation).
    """
    username = (username or "").strip()
    if not username or not USERNAME_RE.match(username):
        return {"ok": False, "error": "Invalid username: 1-30 chars, letters/digits/._-"}

    per_req_timeout = min(float(timeout), 5.0)
    sem = asyncio.Semaphore(4)

    async def _check(platform: str, url: str) -> dict:
        async with sem:
            try:
                resp = await _fetch(url, timeout=per_req_timeout, method="HEAD")
                status = resp.get("status")
                exists = resp.get("ok") and status not in (404, 410)
                return {
                    "platform": platform,
                    "url": url,
                    "exists": bool(exists),
                    "status_code": status,
                    "error": None if resp.get("ok") else resp.get("error"),
                }
            except Exception as e:  # noqa: BLE001
                return {"platform": platform, "url": url, "exists": False, "status_code": None, "error": str(e)}

    tasks = [_check(p, url_template.format(u=username)) for p, url_template in USERNAME_PLATFORMS.items()]
    profiles = await asyncio.gather(*tasks)

    return {
        "ok": True,
        "username": username,
        "checked": len(profiles),
        "found": sum(1 for p in profiles if p["exists"]),
        "profiles": profiles,
    }


# ════════════════════════════════════════════════════════════════
#  9. GitHub recon  (BlackTrace: github_recon)
# ════════════════════════════════════════════════════════════════

async def github_recon(username: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Gather public GitHub profile + top-10 repos for a username.

    Uses the unauthenticated api.github.com endpoint (≈60 req/h shared
    pool; 403 is surfaced as a rate-limit error).  Set ``GITHUB_TOKEN``
    to raise the limit to 5000/h.
    """
    username = (username or "").strip()
    if not username or not USERNAME_RE.match(username):
        return {"ok": False, "error": "Invalid GitHub username"}

    headers: dict[str, str] = {}
    token = _get_env("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"token {token}"

    user_resp = await _fetch(
        f"https://api.github.com/users/{urllib.parse.quote(username)}", timeout=timeout, headers=headers
    )
    if not user_resp.get("ok"):
        status = user_resp.get("status")
        if status == 404:
            return {"ok": False, "error": "User not found"}
        if status == 403:
            return {"ok": False, "error": "rate limited (set GITHUB_TOKEN or wait for the hourly quota reset)"}
        return {"ok": False, "error": user_resp.get("error", "GitHub API unavailable")}

    data = _parse_json(user_resp)
    if data is None or not isinstance(data, dict):
        return {"ok": False, "error": "GitHub API returned invalid JSON"}

    profile = {
        "login": data.get("login"),
        "name": data.get("name"),
        "bio": data.get("bio"),
        "public_repos": data.get("public_repos"),
        "public_gists": data.get("public_gists"),
        "followers": data.get("followers"),
        "following": data.get("following"),
        "created_at": data.get("created_at"),
        "updated_at": data.get("updated_at"),
        "html_url": data.get("html_url"),
        "blog": data.get("blog"),
        "location": data.get("location"),
        "company": data.get("company"),
        "twitter_username": data.get("twitter_username"),
    }

    repos: list[dict] = []
    repo_resp = await _fetch(
        f"https://api.github.com/users/{urllib.parse.quote(username)}/repos?per_page=10&sort=updated",
        timeout=timeout,
        headers=headers,
    )
    repo_data = _parse_json(repo_resp)
    if isinstance(repo_data, list):
        repos = [
            {
                "name": r.get("name"),
                "html_url": r.get("html_url"),
                "description": r.get("description"),
                "language": r.get("language"),
                "stargazers_count": r.get("stargazers_count"),
                "forks_count": r.get("forks_count"),
                "updated_at": r.get("updated_at"),
            }
            for r in repo_data
            if isinstance(r, dict)
        ]

    return {
        "ok": True,
        "found": True,
        "username": username,
        "profile": profile,
        "repos": repos,
        "repo_count": len(repos),
    }


# ════════════════════════════════════════════════════════════════
#  Ronda API-based #2 (agentic-ai-apis catalogue, keyless public APIs)
#   10. dns_recon        — DNS-over-HTTPS (dns.google)
#   11. rdap_whois       — RDAP (rdap.org)
#   12. pwned_passwords  — HIBP range (k-anonymity)
#   13. urlhaus_lookup   — abuse.ch URLhaus reputation
#   14. page_snapshot    — Jina Reader text extraction
# ════════════════════════════════════════════════════════════════

def _normalize_host(raw: str) -> tuple[str | None, str | None]:
    """Validate a plain domain/host; returns (host, None) or (None, error)."""
    host = (raw or "").strip().lower().rstrip(".")
    if "://" in host:
        host = urllib.parse.urlparse(host).netloc or host
    host = host.split("/")[0].split(":")[0]
    if not host or not _DOMAIN_RE.match(host):
        return None, "Invalid host. Use a domain like 'example.com'"
    try:
        ipaddress.ip_address(host)
        return None, "Invalid domain. IP addresses are not supported"
    except ValueError:
        pass
    if host.rsplit(".", 1)[-1] in _PRIVATE_TLDS:
        return None, "Invalid domain. Private/reserved TLD is not publicly resolvable"
    return host, None


async def dns_recon(host: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Resolve common DNS record types via DNS-over-HTTPS (dns.google).

    Keyless public API.  Queries A, AAAA, MX, NS, CNAME and TXT in
    parallel and returns the raw record values per type.  Validates the
    host strictly (H-005) and rejects IPs / private TLDs.
    """
    host, err = _normalize_host(host)
    if err:
        return {"ok": False, "error": err}

    async def _resolve(record_type: str) -> dict:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(host)}&type={record_type}"
        resp = await _fetch(url, timeout=timeout)
        data = _parse_json(resp)
        if not resp.get("ok"):
            return {"type": record_type, "ok": False, "error": resp.get("error", "DoH unavailable")}
        if data is None or not isinstance(data, dict):
            return {"type": record_type, "ok": False, "error": "DoH returned an invalid payload"}
        values = [
            str(a.get("data", "")).rstrip(".").strip('"')
            for a in data.get("Answer", [])
            if isinstance(a, dict) and a.get("data")
        ]
        return {
            "type": record_type,
            "ok": True,
            "status": data.get("Status"),
            "values": list(dict.fromkeys(values)),
        }

    records = await asyncio.gather(*(_resolve(t) for t in ("A", "AAAA", "MX", "NS", "CNAME", "TXT")))
    types = [r["type"] for r in records if r.get("ok") and r.get("values")]
    return {"ok": True, "host": host, "resolved_types": types, "records": records}


def _vcard_value(entity: dict) -> str:
    """Best-effort extract the FN/org name from an RDAP vcardArray."""
    vcard = entity.get("vcardArray") if isinstance(entity, dict) else None
    if not isinstance(vcard, list) or len(vcard) < 2 or not isinstance(vcard[1], list):
        return ""
    for field in vcard[1]:
        if isinstance(field, list) and field and field[0] in ("fn", "org") and len(field) > 3:
            return str(field[3])
    return ""


async def rdap_whois(domain: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    WHOIS-lite via RDAP (rdap.org) — registrar, lifecycle events and
    nameservers for a publicly registered domain.  Keyless.
    """
    domain, err = _normalize_host(domain)
    if err:
        return {"ok": False, "error": err}

    resp = await _fetch(
        f"https://rdap.org/domain/{urllib.parse.quote(domain)}",
        timeout=timeout,
        headers={"Accept": "application/json"},
    )
    if not resp.get("ok"):
        if resp.get("status") == 404:
            return {"ok": False, "error": "Domain not found in RDAP (not publicly registered)"}
        return {"ok": False, "error": resp.get("error", "RDAP unavailable")}
    data = _parse_json(resp)
    if data is None or not isinstance(data, dict):
        return {"ok": False, "error": "RDAP returned an invalid payload"}

    events = {}
    for e in data.get("events", []):
        if not isinstance(e, dict):
            continue
        action = e.get("eventAction") or e.get("action")
        date = e.get("eventDate") or e.get("date")
        if action:
            events[str(action)] = str(date or "")
    nameservers = [
        str(ns.get("ldhName", "")) for ns in data.get("nameservers", [])
        if isinstance(ns, dict) and ns.get("ldhName")
    ]
    entities = data.get("entities", [])
    registrars, abuse_contacts, registrants = [], [], []
    for e in entities:
        if not isinstance(e, dict):
            continue
        roles = e.get("roles") or []
        name = _vcard_value(e)
        if not name:
            continue
        if "registrar" in roles:
            registrars.append(name)
        if "abuse" in roles:
            abuse_contacts.append(name)
        if "registrant" in roles:
            registrants.append(name)

    return {
        "ok": True,
        "domain": domain,
        "handle": data.get("handle"),
        "status": data.get("status") or [],
        "events": events,
        "nameservers": nameservers,
        "registrar": registrars[0] if registrars else None,
        "registrants": list(dict.fromkeys(registrants)),
        "abuse_contact": abuse_contacts[0] if abuse_contacts else None,
    }


async def pwned_passwords(password: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Check a candidate password against the HIBP Pwned Passwords corpus
    via the k-anonymity range endpoint (no API key, full hash never sent).

    Only the SHA-1 prefix is transmitted; the caller is told how many
    times the full hash has been seen in breaches.  The raw password is
    never echoed back or logged.
    """
    password = (password or "").strip() if password else ""
    if not password:
        return {"ok": False, "error": "password must not be empty"}
    if len(password) > 200:
        return {"ok": False, "error": "password too long (max 200 chars)"}

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    resp = await _fetch(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        timeout=timeout,
        headers={"Add-Padding": "true", "Accept": "text/plain"},
    )
    if not resp.get("ok"):
        status = resp.get("status")
        if status == 403:
            return {"ok": False, "error": "Pwned Passwords rate limited; retry later"}
        return {"ok": False, "error": resp.get("error", "Pwned Passwords unavailable")}

    seen = 0
    for line in (resp.get("text", "") or "").splitlines():
        parts = line.split(":")
        if len(parts) >= 2 and parts[0].strip().upper() == suffix:
            try:
                seen = int(parts[1].strip())
            except ValueError:
                seen = 0
            break

    if seen >= 1000000:
        rank = "critical"
    elif seen >= 10000:
        rank = "high"
    elif seen >= 1:
        rank = "medium"
    else:
        rank = "clean"
    return {
        "ok": True,
        "length": len(password),
        "found": seen > 0,
        "times_seen": seen,
        "rank": rank,
        "note": "Checked against HIBP Pwned Passwords via k-anonymity range; the full hash was never sent.",
    }


async def urlhaus_lookup(url: str, host: str = "", timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Check a URL or host against abuse.ch URLhaus (malware distribution).

    Keyless POST to the URLhaus v1 API.  ``url`` wins when both are given
    (the URL is more specific).  Response includes the threat tag and the
    provider blacklist verdicts when the entry is known.
    """
    url = (url or "").strip()
    host = (host or "").strip()
    if not url and not host:
        return {"ok": False, "error": "Provide a url or host"}
    if url:
        parsed = urllib.parse.urlparse(url)
        if not url.startswith(("http://", "https://")) or not parsed.netloc:
            return {"ok": False, "error": "url must be a full http(s) URL"}
        endpoint, form = "url/", {"url": url}
    else:
        norm_host, err = _normalize_host(host)
        if err:
            return {"ok": False, "error": "Invalid host. Use a domain like 'example.com'"}
        endpoint, form = "host/", {"host": norm_host}

    resp = await _fetch(
        f"https://urlhaus-api.abuse.ch/v1/{endpoint}",
        timeout=timeout,
        method="POST",
        data=urllib.parse.urlencode(form).encode("utf-8"),
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
            **({"Auth-Key": urlhaus_token} if (urlhaus_token := os.environ.get("MIRV_URLHAUS_TOKEN")) else {}),
        },
    )
    data = _parse_json(resp)
    if data is None or not isinstance(data, dict):
        return {"ok": False, "error": resp.get("error", "URLhaus API unavailable")}

    status = str(data.get("query_status", "")).lower()
    if status in ("", "error") and str(data.get("error", "")).lower() == "unauthorized":
        return {"ok": False,
                "error": "URLhaus now requires a free account API key (set MIRV_URLHAUS_TOKEN)"}
    if status == "no_results":
        return {"ok": True, "found": False, "target": url or host,
                "type": "url" if url else "host", "note": "Not listed in URLhaus."}
    if status == "invalid_url":
        return {"ok": False, "error": "URLhaus rejected the value (invalid url/host)"}
    if status == "rate_limit":
        return {"ok": False, "error": "URLhaus rate limit reached; retry later"}
    if status == "unauthorized":
        return {"ok": False,
                "error": "URLhaus now requires a free account API key (set MIRV_URLHAUS_TOKEN)"}
    if status != "ok":
        return {"ok": False, "error": "URLhaus unknown query status: {}".format(status)}

    return {
        "ok": True,
        "found": True,
        "target": url or host,
        "type": "url" if url else "host",
        "threat": data.get("threat"),
        "tags": data.get("tags") or [],
        "blacklists": data.get("blacklists") or {},
        "urlhaus_reference": data.get("urlhaus_reference"),
        "id": data.get("id"),
    }


async def page_snapshot(url: str, timeout: float = TIMEOUT_DEFAULT) -> dict:
    """
    Extract readable text from a public page via the Jina Reader
    (https://r.jina.ai/) — free keyless tier for webvuln/recon passive
    recon and intelligence page-content checks.

    Output is capped to keep the response small for the dashboard/AI.
    """
    url = (url or "").strip()
    if not url.startswith(("http://", "https://")):
        return {"ok": False, "error": "url must start with http:// or https://"}
    headers = (
        {"Authorization": f"Bearer {jina_key}"}
        if (jina_key := os.environ.get("MIRV_JINA_KEY")) else None
    )
    resp = await _fetch(f"https://r.jina.ai/{url}", timeout=timeout, headers=headers)
    if not resp.get("ok"):
        if resp.get("status") in (401, 403):
            return {"ok": False,
                    "error": "Jina Reader rate-limited or requires a free API key (set MIRV_JINA_KEY)"}
        return {"ok": False, "error": resp.get("error", "Reader unavailable")}
    text = resp.get("text", "") or ""
    if len(text) > 60000:
        text = text[:60000] + "\n...[truncated]"
    title = ""
    for line in text.splitlines():
        if line.strip():
            title = line.strip()[:120]
            break
    return {"ok": True, "url": url, "title": title, "chars": len(text), "text": text}
