"""
Tests for the curated prompt library (Fase A) — ``backend/prompts_library.py``
and the ``/api/prompts`` endpoints.
"""
import json

import pytest

from backend import prompts_library as pl


@pytest.fixture(autouse=True)
def _clear_cache():
    """Reset the module cache so each test reads the shipped data file."""
    pl._CACHE = []
    yield
    pl._CACHE = []


def _write_library(path, items):
    path.write_text(json.dumps(items, ensure_ascii=False), encoding="utf-8")


@pytest.fixture
def small_library(tmp_path, monkeypatch):
    data = [
        {"id": "recon-host", "title": "Host recon", "prompt": "scan",
         "tags": ["recon"], "source": "test"},
        {"id": "web-xss", "title": "XSS hunter", "prompt": "xss",
         "tags": ["web", "vuln"], "source": "test"},
        {"id": "audit-gap", "title": "Audit gap", "prompt": "audit",
         "tags": ["audit"], "source": "test"},
    ]
    f = tmp_path / "prompts.json"
    _write_library(f, data)
    monkeypatch.setattr(pl, "DATA_FILE", f)
    return data


def test_count_returns_number(small_library):
    assert pl.count() == 3


def test_list_prompts_returns_lightweight_items(small_library):
    items = pl.list_prompts()
    assert len(items) == 3
    assert set(items[0]) == {"id", "title", "tags", "source"}


def test_list_prompts_filters_by_query(small_library):
    items = pl.list_prompts(q="xss")
    assert [i["id"] for i in items] == ["web-xss"]


def test_list_prompts_filters_by_tag(small_library):
    items = pl.list_prompts(tag="vuln")
    assert [i["id"] for i in items] == ["web-xss"]


def test_list_prompts_combines_query_and_tag(small_library):
    assert pl.list_prompts(q="audit", tag="web") == []
    assert [i["id"] for i in pl.list_prompts(q="audit", tag="audit")] == ["audit-gap"]


def test_get_prompt_found(small_library):
    item = pl.get_prompt("web-xss")
    assert item["title"] == "XSS hunter"
    assert "prompt" in item


def test_get_prompt_missing(small_library):
    assert pl.get_prompt("nope") is None


def test_missing_file_returns_empty(tmp_path, monkeypatch):
    monkeypatch.setattr(pl, "DATA_FILE", tmp_path / "does-not-exist.json")
    assert pl.count() == 0
    assert pl.list_prompts() == []


def test_malformed_file_returns_empty(tmp_path, monkeypatch):
    f = tmp_path / "bad.json"
    f.write_text("not json", encoding="utf-8")
    monkeypatch.setattr(pl, "DATA_FILE", f)
    assert pl.count() == 0


def test_non_list_payload_returns_empty(tmp_path, monkeypatch):
    f = tmp_path / "obj.json"
    f.write_text('{"id": "x"}', encoding="utf-8")
    monkeypatch.setattr(pl, "DATA_FILE", f)
    assert pl.count() == 0


def test_shipped_library_has_at_least_500_prompts():
    pl._CACHE = []
    assert pl.count() >= 500


def test_shipped_library_entries_are_well_formed():
    pl._CACHE = []
    for item in pl._load():
        assert item.get("id")
        assert item.get("title")
        assert item.get("prompt")
        assert isinstance(item.get("tags"), list)


class TestPromptsEndpoints:
    def test_list_endpoint(self, client, small_library):
        r = client.get("/api/prompts")
        assert r.status_code == 200
        body = r.json()
        assert body["ok"] is True
        assert body["count"] == 3
        assert body["total"] == 3

    def test_list_endpoint_query(self, client, small_library):
        r = client.get("/api/prompts", params={"q": "xss"})
        assert r.json()["count"] == 1

    def test_list_endpoint_tag(self, client, small_library):
        r = client.get("/api/prompts", params={"tag": "audit"})
        assert [i["id"] for i in r.json()["items"]] == ["audit-gap"]

    def test_get_endpoint_found(self, client, small_library):
        r = client.get("/api/prompts/web-xss")
        assert r.status_code == 200
        assert r.json()["prompt"]["title"] == "XSS hunter"

    def test_get_endpoint_not_found(self, client, small_library):
        r = client.get("/api/prompts/does-not-exist")
        assert r.status_code == 404
        assert r.json()["ok"] is False
