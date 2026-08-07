"""
Coverage-gap tests for backend/news_scraper.py.

Covers _parse_date edge cases, RSS/Atom entries without title+link,
unknown-format dual parsing in _fetch_feed, and the sort fallback.
"""

import asyncio
import xml.etree.ElementTree as ET
from unittest.mock import AsyncMock, patch

import pytest

import backend.news_scraper as ns


class TestParseDate:
    def test_empty_date_returns_now(self):
        out = ns._parse_date("")
        assert out.endswith("+00:00") or out.endswith("Z")

    def test_unknown_type_raises_then_returns_original(self):
        # parsedate_to_datetime(123) -> TypeError; strptime formats also
        # TypeError -> swallowed by the outer except Exception.
        assert ns._parse_date(123) == 123


class TestParseRss:
    def test_item_without_title_and_link_skipped(self):
        root = ET.fromstring(
            "<rss><channel><item><description>no id</description></item>"
            "<item><title>ok</title><link>http://x</link></item></channel></rss>"
        )
        articles = ns._parse_rss(root, {"id": "t", "name": "T", "category": "news"})
        assert len(articles) == 1
        assert articles[0].title == "ok"


class TestParseAtom:
    def test_entry_without_title_and_link_skipped(self):
        root = ET.fromstring(
            '<feed xmlns="http://www.w3.org/2005/Atom">'
            "<entry><summary>no id</summary></entry>"
            "<entry><title>ok</title><link href='http://x'/></entry>"
            "</feed>"
        )
        articles = ns._parse_atom(root, {"id": "t", "name": "T", "category": "news"})
        assert len(articles) == 1
        assert articles[0].title == "ok"


class TestFetchFeedUnknownFormat:
    @pytest.mark.asyncio
    async def test_unknown_falls_back_to_atom(self):
        # Unknown format with no RSS items -> Atom parse succeeds.
        atom_xml = (
            '<feed xmlns="http://www.w3.org/2005/Atom">'
            "<entry><title>hello</title><link href='http://x'/></entry>"
            "</feed>"
        )

        class FakeResp:
            text = atom_xml

            def raise_for_status(self):
                pass

        client = AsyncMock()
        client.get.return_value = FakeResp()

        articles = await ns._fetch_feed(
            client,
            {"id": "t", "name": "T", "url": "http://fake.local/feed", "category": "news"},
        )
        assert len(articles) == 1
        assert articles[0].title == "hello"

    @pytest.mark.asyncio
    async def test_unknown_dual_parse_empty(self):
        # Unknown format: RSS parse yields no items (no title+link),
        # Atom parse also yields nothing -> both fallbacks run, result [].
        xml = (
            "<channel><item><description>no id</description></item></channel>"
        )
        assert ns._detect_format(xml) == "unknown"

        class FakeResp:
            text = xml

            def raise_for_status(self):
                pass

        client = AsyncMock()
        client.get.return_value = FakeResp()

        articles = await ns._fetch_feed(
            client,
            {"id": "t", "name": "T", "url": "http://fake.local/feed", "category": "news"},
        )
        assert articles == []


class TestSortKey:
    def test_published_access_exception_falls_back(self):
        class BrokenArticle:
            @property
            def published(self):
                raise RuntimeError("boom")

        import backend.news_scraper as ns2

        # Patch the sort helper's module-level symbol via the reported line.
        from backend.news_scraper import fetch_news  # noqa: F401

        # Directly exercise the same logic by building a report through fetch_news
        # with a source whose article is broken, ensuring _sort_key fallback runs.
        asyncio.run(_sort_fallback_scenario())


async def _sort_fallback_scenario():
    """Ensure a broken `published` property falls back to '' in _sort_key."""

    class Broken:
        @property
        def published(self):
            raise RuntimeError("boom")

    # Monkeypatch SECURITY_FEEDS so only one fake source runs without network.
    fake_source = {
        "id": "fake",
        "name": "Fake",
        "url": "http://fake.local/feed",
        "lang": "en",
        "category": "news",
    }
    original_feeds = ns.SECURITY_FEEDS
    ns.SECURITY_FEEDS = [fake_source]
    try:
        with patch(
            "backend.news_scraper._fetch_feed",
            new=AsyncMock(return_value=[Broken()]),
        ):
            report = await ns.fetch_news(sources=["fake"], max_per_source=5)
        # The sort key fell back to "" — article present but unsorted.
        assert report.total_articles == 1
    finally:
        ns.SECURITY_FEEDS = original_feeds
