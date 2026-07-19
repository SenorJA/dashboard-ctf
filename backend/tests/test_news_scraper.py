"""
tests/test_news_scraper.py — Tests for news_scraper module.

Covers:
    1. fetch_news() completes with ok=True equivalent (sources_ok >= 5)
    2. Response shape: NewsReport dataclass fields
    3. Article shape: required keys present
    4. Articles sorted by recency (newest first)
    5. report_to_mirv_findings() conversion
    6. fetch_news() with empty source list
    7. report_to_mirv_findings() with empty report

All tests hit real RSS/Atom feeds — marked slow, 30s timeout.
"""

from __future__ import annotations

import asyncio
import sys
import os

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from news_scraper import (
    NewsArticle,
    NewsReport,
    fetch_news,
    report_to_mirv_findings,
)

# ──────────────────────────────────────────────
# Constants
# ──────────────────────────────────────────────
NETWORK_TIMEOUT = 30  # seconds — generous for 9 parallel feed fetches

REQUIRED_REPORT_FIELDS = {
    "articles",
    "sources_ok",
    "sources_failed",
    "total_articles",
    "duration_seconds",
    "source_details",
}

REQUIRED_ARTICLE_FIELDS = {"title", "link", "summary", "published", "source_id", "source_name"}

# ──────────────────────────────────────────────
# 1. fetch_news — success + sane response
# ──────────────────────────────────────────────
@pytest.mark.slow
@pytest.mark.asyncio
async def test_fetch_news_succeeds():
    """fetch_news() should reach >= 5 of 9 feeds and return articles."""
    report: NewsReport = await asyncio.wait_for(
        fetch_news(),
        timeout=NETWORK_TIMEOUT,
    )

    assert isinstance(report, NewsReport)
    # Core success assertions (equivalent of ok=True + minimum viable feed count)
    assert report.sources_ok >= 5, (
        f"Expected >= 5 successful sources, got {report.sources_ok}"
    )
    assert report.total_articles > 0, "Expected at least 1 article"
    assert report.duration_seconds > 0, "Duration should be positive"
    assert len(report.articles) == report.total_articles, (
        "total_articles must match len(articles)"
    )
    # At least some feeds must have failed (threatpost is defunct, etc.)
    # But the ok threshold is the important gate


# ──────────────────────────────────────────────
# 2. fetch_news — response shape
# ──────────────────────────────────────────────
@pytest.mark.slow
@pytest.mark.asyncio
async def test_fetch_news_response_shape():
    """NewsReport must have all expected fields with correct types."""
    report: NewsReport = await asyncio.wait_for(
        fetch_news(),
        timeout=NETWORK_TIMEOUT,
    )

    # All required top-level fields present
    for field in REQUIRED_REPORT_FIELDS:
        assert hasattr(report, field), f"NewsReport missing field: {field}"

    # Type checks
    assert isinstance(report.articles, list)
    assert isinstance(report.sources_ok, int)
    assert isinstance(report.sources_failed, int)
    assert isinstance(report.total_articles, int)
    assert isinstance(report.duration_seconds, (int, float))
    assert isinstance(report.source_details, list)

    # source_details entries have expected shape
    for detail in report.source_details:
        assert "id" in detail
        assert "name" in detail
        assert "articles_found" in detail
        assert "ok" in detail
        assert isinstance(detail["ok"], bool)
        assert isinstance(detail["articles_found"], int)


# ──────────────────────────────────────────────
# 3. fetch_news — article shape
# ──────────────────────────────────────────────
@pytest.mark.slow
@pytest.mark.asyncio
async def test_fetch_news_article_fields():
    """Every article must have the required fields (title, link, summary, etc.)."""
    report: NewsReport = await asyncio.wait_for(
        fetch_news(),
        timeout=NETWORK_TIMEOUT,
    )

    assert len(report.articles) > 0

    for article in report.articles:
        assert isinstance(article, NewsArticle), f"Expected NewsArticle, got {type(article)}"

        # All required fields must exist (they're dataclass fields so they always will,
        # but we verify they're populated strings)
        for field in REQUIRED_ARTICLE_FIELDS:
            value = getattr(article, field, None)
            assert value is not None, f"Article field '{field}' is None"

        # title and link should be non-empty (core identifiers)
        assert len(article.title.strip()) > 0, "Article title must not be empty"
        assert article.link.startswith("http"), (
            f"Article link must be a URL, got: {article.link!r}"
        )

        # summary may be empty for some sources — that's acceptable
        # published should be an ISO string or at least non-empty
        assert isinstance(article.published, str)


# ──────────────────────────────────────────────
# 4. fetch_news — articles sorted by recency
# ──────────────────────────────────────────────
@pytest.mark.slow
@pytest.mark.asyncio
async def test_fetch_news_articles_sorted_by_recency():
    """Articles should be sorted newest-first based on published date."""
    report: NewsReport = await asyncio.wait_for(
        fetch_news(),
        timeout=NETWORK_TIMEOUT,
    )

    if len(report.articles) < 2:
        pytest.skip("Need >= 2 articles to verify sort order")

    # Compare published timestamps — each should be >= the next (newest first)
    for i in range(len(report.articles) - 1):
        current = report.articles[i].published or ""
        nxt = report.articles[i + 1].published or ""
        assert current >= nxt, (
            f"Articles not sorted newest-first at index {i}: "
            f"'{current}' < '{nxt}'"
        )


# ──────────────────────────────────────────────
# 5. fetch_news — sources_ok + sources_failed consistency
# ──────────────────────────────────────────────
@pytest.mark.slow
@pytest.mark.asyncio
async def test_fetch_news_source_counts_consistent():
    """sources_ok + sources_failed should equal len(source_details)."""
    report: NewsReport = await asyncio.wait_for(
        fetch_news(),
        timeout=NETWORK_TIMEOUT,
    )

    expected_total = report.sources_ok + report.sources_failed
    assert len(report.source_details) == expected_total, (
        f"sources_ok({report.sources_ok}) + sources_failed({report.sources_failed}) "
        f"!= len(source_details)({len(report.source_details)})"
    )

    # Each source_detail.ok should match the count buckets
    ok_count = sum(1 for d in report.source_details if d["ok"])
    failed_count = sum(1 for d in report.source_details if not d["ok"])
    assert ok_count == report.sources_ok
    assert failed_count == report.sources_failed


# ──────────────────────────────────────────────
# 6. fetch_news — empty source list
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_fetch_news_empty_sources():
    """Passing an empty source list should return an empty report instantly."""
    report: NewsReport = await fetch_news(sources=[])

    assert isinstance(report, NewsReport)
    assert report.total_articles == 0
    assert report.sources_ok == 0
    assert report.sources_failed == 0
    assert report.articles == []
    assert report.source_details == []
    assert report.duration_seconds == 0.0


# ──────────────────────────────────────────────
# 7. report_to_mirv_findings — populated report
# ──────────────────────────────────────────────
@pytest.mark.slow
@pytest.mark.asyncio
async def test_report_to_mirv_findings_populated():
    """report_to_mirv_findings should convert a real report into findings."""
    report: NewsReport = await asyncio.wait_for(
        fetch_news(),
        timeout=NETWORK_TIMEOUT,
    )

    findings = report_to_mirv_findings(report)

    assert isinstance(findings, list)
    assert len(findings) >= 1, "Should have at least the summary finding"

    # Every finding must have the required MIRV keys
    for f in findings:
        assert "tool" in f
        assert "severity" in f
        assert "title" in f
        assert "detail" in f
        assert "target" in f
        assert "type" in f
        assert f["tool"] == "news-scraper"

    # First finding is the summary
    summary = findings[0]
    assert str(report.total_articles) in summary["title"] or "articles" in summary["title"]
    assert summary["severity"] == "info"


# ──────────────────────────────────────────────
# 8. report_to_mirv_findings — empty report
# ──────────────────────────────────────────────
@pytest.mark.asyncio
async def test_report_to_mirv_findings_empty():
    """report_to_mirv_findings with no articles should return a single finding."""
    empty_report = NewsReport(
        articles=[],
        sources_ok=0,
        sources_failed=0,
        total_articles=0,
        duration_seconds=0.0,
        source_details=[],
    )
    findings = report_to_mirv_findings(empty_report)

    assert isinstance(findings, list)
    assert len(findings) >= 1
    assert findings[0]["severity"] == "info"
    assert findings[0]["tool"] == "news-scraper"
