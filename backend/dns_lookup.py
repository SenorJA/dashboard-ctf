"""
dns_lookup.py — MIRV Module

Async DNS lookup tool supporting multiple record types via DNS-over-HTTPS (DoH).
Adapted from: https://github.com/CarterPerez-dev/Cybersecurity-Projects

Uses Cloudflare's 1.1.1.1 DNS-over-HTTPS API for reliable, async resolution.
Falls back to system resolver for reverse DNS (PTR).
"""

import asyncio
import socket
from dataclasses import dataclass, field
from typing import Literal

import httpx

# ── DNS-over-HTTPS endpoint ──
DOH_URL = "https://cloudflare-dns.com/dns-query"
RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA"]


@dataclass(frozen=True, slots=True)
class DNSRecord:
    name: str
    type: str
    ttl: int
    value: str


@dataclass(frozen=True, slots=True)
class DNSReport:
    domain: str
    records: dict[str, list[DNSRecord]]  # type -> records
    reverse_dns: str | None = None
    duration_seconds: float = 0.0


async def _query_doh(
    client: httpx.AsyncClient,
    name: str,
    rtype: str,
    timeout: float = 5.0,
) -> list[DNSRecord]:
    """Query Cloudflare DNS-over-HTTPS for a specific record type."""
    try:
        resp = await client.get(
            DOH_URL,
            params={"name": name, "type": rtype},
            headers={"Accept": "application/dns-json"},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return []
        data = resp.json()
        records = []
        for answer in data.get("Answer", []):
            rtype_name = _rtype_to_str(answer.get("type", 0))
            records.append(DNSRecord(
                name=answer.get("name", name),
                type=rtype_name,
                ttl=answer.get("TTL", 0),
                value=answer.get("data", ""),
            ))
        return records
    except Exception:
        return []


def _rtype_to_str(rtype: int) -> str:
    """Convert DNS record type number to string."""
    mapping = {
        1: "A", 28: "AAAA", 5: "CNAME", 15: "MX",
        16: "TXT", 2: "NS", 6: "SOA", 12: "PTR",
        33: "SRV", 65: "HTTPS", 257: "CAA",
    }
    return mapping.get(rtype, f"TYPE{rtype}")


async def _reverse_dns(ip: str, timeout: float = 3.0) -> str | None:
    """Perform reverse DNS lookup (PTR)."""
    try:
        hostname = await asyncio.wait_for(
            asyncio.to_thread(socket.gethostbyaddr, ip),
            timeout=timeout,
        )
        return hostname[0] if hostname else None
    except Exception:
        return None


async def lookup(
    domain: str,
    record_types: list[str] | None = None,
    *,
    timeout: float = 5.0,
    reverse: bool = False,
) -> DNSReport:
    """
    Perform DNS lookups for a domain.

    Args:
        domain: Domain to query (e.g. "example.com").
        record_types: List of record types. Defaults to all common types.
        timeout: Seconds per HTTP request.
        reverse: Whether to attempt reverse DNS lookup.

    Returns a DNSReport with all records grouped by type.
    """
    # Clean domain
    domain = domain.strip().lower()
    if domain.startswith(("http://", "https://")):
        from urllib.parse import urlparse
        domain = urlparse(domain).hostname or domain
    domain = domain.split("/")[0]
    domain = domain.split(":")[0]

    if record_types is None:
        record_types = RECORD_TYPES

    start = asyncio.get_event_loop().time()

    async with httpx.AsyncClient() as client:
        tasks = {}
        for rtype in record_types:
            tasks[rtype] = _query_doh(client, domain, rtype, timeout=timeout)
        results = await asyncio.gather(*list(tasks.values()))

    records: dict[str, list[DNSRecord]] = {}
    for rtype, recs in zip(tasks.keys(), results):
        if recs:
            records[rtype] = recs

    # Reverse DNS
    rev = None
    if reverse:
        # Try to get an IP from A or AAAA records
        ips = []
        for r in records.get("A", []):
            ips.append(r.value)
        for r in records.get("AAAA", []):
            ips.append(r.value)
        if ips:
            rev = await _reverse_dns(ips[0], timeout=timeout)

    duration = asyncio.get_event_loop().time() - start
    return DNSReport(
        domain=domain,
        records=records,
        reverse_dns=rev,
        duration_seconds=round(duration, 2),
    )


async def reverse_lookup(
    ip: str,
    timeout: float = 5.0,
) -> DNSReport:
    """
    Perform a reverse DNS lookup on an IP address.

    Args:
        ip: IP address to look up.
        timeout: Seconds for the query.

    Returns a DNSReport with PTR record if found.
    """
    start = asyncio.get_event_loop().time()
    hostname = await _reverse_dns(ip, timeout=timeout)
    duration = asyncio.get_event_loop().time() - start

    records: dict[str, list[DNSRecord]] = {}
    if hostname:
        records["PTR"] = [DNSRecord(
            name=ip,
            type="PTR",
            ttl=0,
            value=hostname,
        )]

    return DNSReport(
        domain=ip,
        records=records,
        reverse_dns=hostname,
        duration_seconds=round(duration, 2),
    )


def report_to_mirv_findings(report: DNSReport, domain: str) -> list[dict]:
    """Convert a DNSReport into MIRV findings list."""
    findings = []
    total_records = sum(len(recs) for recs in report.records.values())

    if total_records == 0:
        return [{
            "tool": "dns-lookup",
            "severity": "info",
            "title": f"No DNS records found for {domain}",
            "detail": f"Domain: {domain}\nNo records found.",
            "target": domain,
            "type": "tech",
        }]

    for rtype, recs in report.records.items():
        for r in recs:
            sev = "info"
            title = f"{rtype} record: {r.name} → {r.value}"
            detail = (
                f"Type: {rtype}\n"
                f"Name: {r.name}\n"
                f"Value: {r.value}\n"
                f"TTL: {r.ttl}"
            )
            findings.append({
                "tool": "dns-lookup",
                "severity": sev,
                "title": title,
                "detail": detail,
                "target": domain,
                "type": "tech",
                "extra": {
                    "record_type": rtype,
                    "name": r.name,
                    "value": r.value,
                    "ttl": r.ttl,
                },
            })

    # Summary
    rev_info = f"\nReverse DNS: {report.reverse_dns}" if report.reverse_dns else ""
    summary_detail = (
        f"Domain: {report.domain}\n"
        f"Record types found: {', '.join(report.records.keys())}\n"
        f"Total records: {total_records}"
        f"{rev_info}\n"
        f"Duration: {report.duration_seconds}s"
    )
    findings.append({
        "tool": "dns-lookup",
        "severity": "info",
        "title": f"DNS lookup complete — {total_records} records across {len(report.records)} types",
        "detail": summary_detail,
        "target": domain,
        "type": "tech",
        "extra": {
            "record_types": list(report.records.keys()),
            "total_records": total_records,
            "reverse_dns": report.reverse_dns,
            "duration": report.duration_seconds,
        },
    })

    return findings
