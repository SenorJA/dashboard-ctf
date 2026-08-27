"""Simple per-IP rate limiter for /api/osint/* endpoints.

A zero-dependency sliding-window limiter (no slowapi, no redis). Each
(path, client-IP) pair gets its own ``deque`` of hit timestamps; hits
older than ``_WINDOW`` seconds are evicted on every check.

Design goals
------------
* **No external deps** — keeps the MIRV install footprint minimal and
  avoids pinning a third-party middleware that might break under
  FastAPI/Starlette upgrades.
* **Per-path limits** — username/instagram probes hit third-party
  platforms that rate-limit hard, so they get a stricter bucket.
* **Thread-safe** — a single ``threading.Lock`` guards the dict; the
  limiter is hot-path but cheap (deque popleft is O(1)).
* **Reset hook** — tests can wipe state between cases.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

# 30 req/min for the majority of OSINT endpoints, 10 req/min for the
# expensive username/instagram probes (they fan out to many platforms).
_LIMITS = {
    "/api/osint/username": 10,
    "/api/osint/instagram": 10,
}
_DEFAULT_LIMIT = 30  # requests per minute
_WINDOW = 60.0  # seconds


class RateLimiter:
    """Sliding-window per (ip, path) limiter."""

    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, ip: str, path: str) -> tuple[bool, int]:
        """Returns ``(allowed, retry_after_seconds)``.

        When ``allowed`` is False, ``retry_after`` is the (clamped, >=1)
        number of seconds until the oldest hit falls out of the window.
        """
        limit = _LIMITS.get(path, _DEFAULT_LIMIT)
        now = time.monotonic()
        key = f"{ip}:{path}"
        with self._lock:
            dq = self._hits[key]
            while dq and now - dq[0] > _WINDOW:
                dq.popleft()
            if len(dq) >= limit:
                retry_after = int(_WINDOW - (now - dq[0])) + 1
                return False, max(retry_after, 1)
            dq.append(now)
            return True, 0

    def reset(self) -> None:
        """Wipe all hit state (used by tests)."""
        with self._lock:
            self._hits.clear()


# Module-level singleton — one limiter per process.
_rate_limiter = RateLimiter()


def check_rate_limit(ip: str, path: str) -> tuple[bool, int]:
    """Convenience wrapper around the process-wide limiter."""
    return _rate_limiter.check(ip, path)


def reset_rate_limiter() -> None:
    """Wipe limiter state (test hook)."""
    _rate_limiter.reset()
