"""
Coverage-gap tests for backend/dns_lookup.py — edge branches.

Covers:
  - _query_doh(): non-200 status, request exception
  - lookup(): URL-style domain normalization, default record types,
    reverse DNS from A records
  - _rtype_to_str(): unknown type number
"""

import asyncio
import os
import sys

from unittest.mock import AsyncMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.dns_lookup import (
    RECORD_TYPES,
    _query_doh,
    _rtype_to_str,
    lookup,
)


class _Resp500:
    status_code = 500

    def json(self):
        return {}


class _RaisingClient:
    async def get(self, *args, **kwargs):
        raise RuntimeError("network down")


class TestQueryDohGaps:
    def test_non_200_returns_empty(self):
        class _Client:
            async def get(self, *args, **kwargs):
                return _Resp500()

        assert asyncio.run(_query_doh(_Client(), "example.com", "A")) == []

    def test_exception_returns_empty(self):
        assert asyncio.run(_query_doh(_RaisingClient(), "example.com", "A")) == []


class TestRtypeToStrGaps:
    def test_unknown_type(self):
        assert _rtype_to_str(999) == "TYPE999"


class _FakeResp:
    status_code = 200

    def __init__(self, answer):
        self._answer = answer

    def json(self):
        return {"Answer": self._answer}


class _FakeClient:
    def __init__(self, answer=None):
        self._answer = answer

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def get(self, url, **kwargs):
        return _FakeResp(self._answer)


class TestLookupGaps:
    def test_url_domain_normalized_with_reverse(self):
        answer = [{"name": "example.com", "type": 1, "TTL": 300, "data": "1.2.3.4"}]
        with patch("dns_lookup.httpx.AsyncClient", return_value=_FakeClient(answer)):
            with patch("dns_lookup._reverse_dns", new=AsyncMock(return_value="ptr.example")):
                report = asyncio.run(
                    lookup("https://example.com:443/path", record_types=["A"], reverse=True)
                )
        assert report.domain == "example.com"
        assert report.records["A"][0].value == "1.2.3.4"
        assert report.reverse_dns == "ptr.example"

    def test_default_record_types(self):
        with patch("dns_lookup.httpx.AsyncClient", return_value=_FakeClient([])):
            report = asyncio.run(lookup("example.com"))
        assert report.domain == "example.com"
        assert report.records == {}

    def test_reverse_from_aaaa_records(self):
        answer = [{"name": "example.com", "type": 28, "TTL": 300, "data": "2001:db8::1"}]
        with patch("dns_lookup.httpx.AsyncClient", return_value=_FakeClient(answer)):
            with patch("dns_lookup._reverse_dns", new=AsyncMock(return_value="ptr6.example")):
                report = asyncio.run(
                    lookup("example.com", record_types=["AAAA"], reverse=True)
                )
        assert report.records["AAAA"][0].value == "2001:db8::1"
        assert report.reverse_dns == "ptr6.example"

    def test_path_and_port_stripped(self):
        with patch("dns_lookup.httpx.AsyncClient", return_value=_FakeClient([])):
            report = asyncio.run(lookup("example.com:8443/path"))
        assert report.domain == "example.com"
