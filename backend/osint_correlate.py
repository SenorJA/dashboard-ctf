"""
osint_correlate.py -- MIRV Module

Parallel OSINT correlation engine.

Given a ``target_type`` and a ``target`` value, this module fans out the
relevant passive OSINT functions from :mod:`backend.osint_recon` and
:mod:`backend.subdomain_scanner` **in parallel** (``asyncio.gather``) and
returns a single correlated envelope:

    {
        "ok": True,
        "target_type": "email",
        "target": "user@example.com",
        "results": {"breach": {...}, "verification": {...}},
        "duration_seconds": 1.23,
    }

Design goals
------------
* **Never raises.** A global ``try/except`` wraps every dispatch path
  and any underlying coroutine failure is surfaced as
  ``{"ok": False, "error": str(e)}`` so the calling route handler can
  stay exception-free (consistent with the H-008 "Internal error"
  contract on the ``/api/osint/*`` family).
* **Target-type dispatch.** Each known target type runs its own set of
  correlating lookups concurrently so a single HTTP request produces a
  multi-source picture in roughly the time of the slowest source.
* **Composable.** ``phone`` currently runs a single lookup but the
  dispatch structure is shaped so adding a second phone source later
  is a one-line ``asyncio.gather`` change.
* **No secrets logged.** The module logger (``vulnforge.osint_correlate``)
  only logs dispatch/error metadata, never the raw target value when it
  could carry PII (email/phone/username).
* **Pure orchestration.** Every network call is delegated to the
  existing OSINT primitives (which are themselves mocked in tests),
  keeping this module thin and 100% unit-testable offline.
"""

from __future__ import annotations

import asyncio
import dataclasses
import logging
import time
from typing import Any

from backend.osint_recon import (
    check_email_breach,
    github_recon,
    phone_number_lookup,
    username_recon,
    verify_email,
    wayback_machine_lookup,
)
from backend.subdomain_scanner import SubdomainReport, scan_passive

__all__ = ["correlate_target", "SUPPORTED_TARGET_TYPES"]

_logger = logging.getLogger("vulnforge.osint_correlate")

# The set of target types understood by :func:`correlate_target`.
# Exposed for introspection / endpoint docs / test parametrization.
SUPPORTED_TARGET_TYPES: tuple[str, ...] = ("email", "username", "domain", "phone")

_UNKNOWN_TYPE_ERROR = (
    "Unknown target_type. Use: email, username, domain, phone"
)


def _subdomain_report_to_dict(report: SubdomainReport) -> dict[str, Any]:
    """Serialize a :class:`SubdomainReport` dataclass to a plain dict.

    ``scan_passive`` returns a frozen dataclass (``slots=True``); the
    REST envelope must be JSON-serializable so we use
    :func:`dataclasses.asdict` which recursively converts nested
    dataclasses (``SubdomainResult``) and their ``list``/``str`` fields.
    """
    return dataclasses.asdict(report)


async def _correlate_email(target: str, timeout: float) -> dict[str, Any]:
    """Run breach + verification lookups concurrently for an email."""
    breach, verification = await asyncio.gather(
        check_email_breach(target, timeout=timeout),
        verify_email(target, timeout=timeout),
    )
    return {"breach": breach, "verification": verification}


async def _correlate_username(target: str, timeout: float) -> dict[str, Any]:
    """Run platform probe + GitHub recon concurrently for a username."""
    platforms, github = await asyncio.gather(
        username_recon(target, timeout=timeout),
        github_recon(target, timeout=timeout),
    )
    return {"platforms": platforms, "github": github}


async def _correlate_domain(target: str, timeout: float) -> dict[str, Any]:
    """Run wayback + passive subdomain enumeration concurrently for a domain."""
    wayback, subdomain_report = await asyncio.gather(
        wayback_machine_lookup(target, timeout=timeout),
        scan_passive(target, timeout=timeout),
    )
    return {
        "wayback": wayback,
        "subdomains": _subdomain_report_to_dict(subdomain_report),
    }


async def _correlate_phone(target: str, timeout: float) -> dict[str, Any]:
    """Run the phone lookup.

    Single source for now, but the structure is intentionally a plain
    dict-of-results so a future second source can be folded in with a
    single ``asyncio.gather`` change without touching the call sites.
    """
    lookup = await phone_number_lookup(target, timeout=timeout)
    return {"lookup": lookup}


# Dispatch table — kept module-level so it is trivially extensible and
# easy to introspect from tests (``SUPPORTED_TARGET_TYPES`` mirrors it).
_DISPATCH: dict[str, Any] = {
    "email": _correlate_email,
    "username": _correlate_username,
    "domain": _correlate_domain,
    "phone": _correlate_phone,
}


async def correlate_target(target_type: str, target: str, timeout: float = 10.0) -> dict:
    """
    Correlate multiple passive OSINT sources for a single target.

    Args:
        target_type: One of ``email``, ``username``, ``domain``, ``phone``.
        target: The target value (an email address, a username, a bare
            domain like ``example.com``, or an international phone
            number with country code).
        timeout: Per-source timeout in seconds (default 10).

    Returns:
        On success::

            {
                "ok": True,
                "target_type": "<type>",
                "target": "<target>",
                "results": { ... per-source dicts ... },
                "duration_seconds": <float>,
            }

        On an unknown target type::

            {"ok": False, "error": "Unknown target_type. Use: email, username, domain, phone"}

        On any unexpected exception (e.g. a source raising)::

            {"ok": False, "error": "<str(exc)>"}

    The function **never raises** — route handlers can await it
    directly without a wrapping try/except for the orchestration
    itself.
    """
    # Normalize inputs defensively (callers may pass None / non-str).
    target_type = (target_type or "").strip().lower()
    target = (target or "").strip()

    handler = _DISPATCH.get(target_type)
    if handler is None:
        _logger.debug("correlate_target: unknown target_type=%r", target_type)
        return {"ok": False, "error": _UNKNOWN_TYPE_ERROR}

    start = time.monotonic()
    try:
        results = await handler(target, timeout)
    except Exception as exc:  # noqa: BLE001 — orchestrator must never raise
        # Log dispatch metadata only (target may be PII — never echo it).
        _logger.debug(
            "correlate_target: source failure for type=%r (see source logs)",
            target_type,
        )
        return {"ok": False, "error": str(exc)}

    duration = round(time.monotonic() - start, 3)
    return {
        "ok": True,
        "target_type": target_type,
        "target": target,
        "results": results,
        "duration_seconds": duration,
    }
