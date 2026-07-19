"""
news_scraper.py — MIRV Module

Security news aggregator — fetches and parses RSS/Atom feeds from
major cybersecurity news sources.
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects
"""

import asyncio
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parsedate_to_datetime
import time
from typing import Literal

import httpx

# ── Feed sources ──

SECURITY_FEEDS: list[dict] = [
    {
        "id": "hackernews",
        "name": "The Hacker News",
        "url": "https://feeds.feedburner.com/TheHackerNews",
        "lang": "en",
        "category": "news",
    },
    {
        "id": "bleepingcomputer",
        "name": "Bleeping Computer",
        "url": "https://www.bleepingcomputer.com/feed/",
        "lang": "en",
        "category": "news",
    },
    {
        "id": "krebs",
        "name": "Krebs on Security",
        "url": "https://krebsonsecurity.com/feed/",
        "lang": "en",
        "category": "blog",
    },
    {
        "id": "portswigger",
        "name": "PortSwigger Research",
        "url": "https://portswigger.net/research/rss",
        "lang": "en",
        "category": "research",
    },
    {
        "id": "schneier",
        "name": "Schneier on Security",
        "url": "https://www.schneier.com/blog/atom.xml",
        "lang": "en",
        "category": "blog",
    },
    {
        "id": "darkreading",
        "name": "Dark Reading",
        "url": "https://www.darkreading.com/rss.xml",
        "lang": "en",
        "category": "news",
    },
    {
        "id": "threatpost",
        "name": "Threatpost",
        "url": "https://threatpost.com/feed/",
        "lang": "en",
        "category": "news",
    },
    {
        "id": "securityweek",
        "name": "SecurityWeek",
        "url": "https://www.securityweek.com/feed/",
        "lang": "en",
        "category": "news",
    },
    {
        "id": "helpnetsecurity",
        "name": "Help Net Security",
        "url": "https://www.helpnetsecurity.com/feed/",
        "lang": "en",
        "category": "news",
    },
]


# ── Data classes ──

@dataclass(frozen=True, slots=True)
class NewsArticle:
    title: str
    link: str
    published: str  # ISO format datetime string
    source_id: str
    source_name: str
    summary: str = ""
    category: str = "news"
    author: str = ""


@dataclass(frozen=True, slots=True)
class NewsReport:
    articles: list[NewsArticle]
    sources_ok: int
    sources_failed: int
    total_articles: int
    duration_seconds: float
    source_details: list[dict] = field(default_factory=list)


# ── RSS/Atom parser ──

def _parse_date(date_str: str) -> str:
    """Try to parse a date string to ISO format. Return original on failure."""
    if not date_str:
        return datetime.now(timezone.utc).isoformat()
    try:
        try:
            dt = parsedate_to_datetime(date_str)
            return dt.isoformat()
        except (ValueError, TypeError):
            pass
        # Try common RSS formats
        for fmt in [
            "%a, %d %b %Y %H:%M:%S %z",
            "%a, %d %b %Y %H:%M:%S %Z",
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%d %H:%M:%S",
            "%d %b %Y %H:%M:%S %z",
        ]:
            try:
                dt = datetime.strptime(date_str, fmt)
                return dt.isoformat()
            except ValueError:
                continue
    except Exception:
        pass
    return date_str


def _parse_rss(root: ET.Element, source: dict) -> list[NewsArticle]:
    """Parse RSS 2.0 feed."""
    articles = []
    for item in root.iter("item"):
        title = item.findtext("title", "").strip()
        link = item.findtext("link", "").strip()
        pub_date = item.findtext("pubDate", "")
        description = item.findtext("description", "").strip()
        author = item.findtext("author", "") or ""
        # Clean HTML from description
        summary = _strip_html(description)[:500]

        if not title and not link:
            continue

        articles.append(NewsArticle(
            title=title or "(no title)",
            link=link,
            published=_parse_date(pub_date),
            source_id=source["id"],
            source_name=source["name"],
            summary=summary,
            category=source.get("category", "news"),
            author=author.strip(),
        ))
    return articles


def _parse_atom(root: ET.Element, source: dict) -> list[NewsArticle]:
    """Parse Atom feed."""
    ns = {"atom": "http://www.w3.org/2005/Atom"}
    articles = []
    for entry in root.iter("{http://www.w3.org/2005/Atom}entry"):
        title_el = entry.find("atom:title", ns)
        title = title_el.text.strip() if title_el is not None and title_el.text else ""

        link_el = entry.find("atom:link", ns)
        link = link_el.get("href", "") if link_el is not None else ""

        published_el = entry.find("atom:published", ns) or entry.find("atom:updated", ns)
        published = published_el.text or "" if published_el is not None else ""

        summary_el = entry.find("atom:summary", ns) or entry.find("atom:content", ns)
        summary = _strip_html(summary_el.text or "")[:500] if summary_el is not None and summary_el.text else ""

        author_el = entry.find("atom:author", ns)
        author = ""
        if author_el is not None:
            name_el = author_el.find("atom:name", ns)
            if name_el is not None and name_el.text:
                author = name_el.text.strip()

        if not title and not link:
            continue

        articles.append(NewsArticle(
            title=title or "(no title)",
            link=link,
            published=_parse_date(published),
            source_id=source["id"],
            source_name=source["name"],
            summary=summary,
            category=source.get("category", "news"),
            author=author,
        ))
    return articles


def _strip_html(text: str) -> str:
    """Remove HTML tags and decode common entities."""
    import re
    text = re.sub(r'<[^>]+>', ' ', text)
    text = re.sub(r'\s+', ' ', text)
    text = text.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>').replace('&quot;', '"').replace('&#39;', "'")
    return text.strip()


def _detect_format(xml_data: str) -> Literal["rss", "atom", "unknown"]:
    """Detect if XML is RSS 2.0 or Atom."""
    if "<rss" in xml_data[:500]:
        return "rss"
    if 'xmlns="http://www.w3.org/2005/Atom"' in xml_data[:1000]:
        return "atom"
    return "unknown"


async def _fetch_feed(client: httpx.AsyncClient, source: dict, timeout: float = 15.0) -> list[NewsArticle]:
    """Fetch and parse a single feed."""
    try:
        resp = await client.get(source["url"], timeout=timeout, follow_redirects=True)
        resp.raise_for_status()
        xml_text = resp.text

        fmt = _detect_format(xml_text)
        root = ET.fromstring(xml_text)

        if fmt == "rss":
            articles = _parse_rss(root, source)
        elif fmt == "atom":
            articles = _parse_atom(root, source)
        else:
            # Try both
            articles = _parse_rss(root, source)
            if not articles:
                articles = _parse_atom(root, source)

        for a in articles:
            a = a  # noqa
        return articles

    except Exception as e:
        return []  # Feed failed, will be counted in failed_sources


async def fetch_news(
    sources: list[str] | None = None,
    *,
    max_per_source: int = 5,
    timeout: float = 15.0,
) -> NewsReport:
    """
    Fetch latest security news from RSS/Atom feeds.

    Args:
        sources: List of source IDs to fetch (None = all).
        max_per_source: Max articles per source.
        timeout: HTTP timeout per feed.

    Returns a NewsReport.
    """
    start = time.monotonic()
    active_sources = [s for s in SECURITY_FEEDS if sources is None or s["id"] in sources]

    if not active_sources:
        return NewsReport(
            articles=[],
            sources_ok=0,
            sources_failed=0,
            total_articles=0,
            duration_seconds=0.0,
            source_details=[],
        )

    async with httpx.AsyncClient(limits=httpx.Limits(max_keepalive_connections=10)) as client:
        tasks = [_fetch_feed(client, s, timeout) for s in active_sources]
        results = await asyncio.gather(*tasks)

    articles: list[NewsArticle] = []
    sources_ok = 0
    sources_failed = 0
    source_details = []

    for source, result in zip(active_sources, results):
        if result:
            sources_ok += 1
            articles.extend(result[:max_per_source])
        else:
            sources_failed += 1
        source_details.append({
            "id": source["id"],
            "name": source["name"],
            "articles_found": len(result),
            "ok": bool(result),
        })

    # Sort by published date (newest first), with fallback to source order
    def _sort_key(a: NewsArticle) -> str:
        try:
            return a.published or ""
        except Exception:
            return ""
    articles.sort(key=_sort_key, reverse=True)

    duration = time.monotonic() - start

    return NewsReport(
        articles=articles,
        sources_ok=sources_ok,
        sources_failed=sources_failed,
        total_articles=len(articles),
        duration_seconds=round(duration, 2),
        source_details=source_details,
    )


def report_to_mirv_findings(report: NewsReport) -> list[dict]:
    """Convert NewsReport into MIRV findings list."""
    findings = []

    findings.append({
        "tool": "news-scraper",
        "severity": "info",
        "title": f"Security News: {report.total_articles} articles from {report.sources_ok} sources",
        "detail": (
            f"Sources OK: {report.sources_ok}\n"
            f"Sources failed: {report.sources_failed}\n"
            f"Total articles: {report.total_articles}\n"
            f"Duration: {report.duration_seconds}s"
        ),
        "target": "news-scraper",
        "type": "tech",
        "extra": {
            "sources_ok": report.sources_ok,
            "sources_failed": report.sources_failed,
            "total": report.total_articles,
        },
    })

    if report.sources_failed > 0:
        failed_names = [
            s["name"] for s in report.source_details if not s["ok"]
        ]
        findings.append({
            "tool": "news-scraper",
            "severity": "low",
            "title": f"Failed feeds: {', '.join(failed_names)}",
            "detail": f"The following {len(failed_names)} feed(s) could not be fetched: {', '.join(failed_names)}",
            "target": "news-scraper",
            "type": "tech",
        })

    for article in report.articles[:10]:
        findings.append({
            "tool": "news-scraper",
            "severity": "info",
            "title": article.title,
            "detail": (
                f"Source: {article.source_name}\n"
                f"Published: {article.published}\n"
                f"Link: {article.link}\n"
                f"Summary: {article.summary}"
            ),
            "target": "news-scraper",
            "type": "tech",
            "extra": {
                "source": article.source_name,
                "published": article.published,
                "link": article.link,
                "summary": article.summary[:200],
            },
        })

    return findings
