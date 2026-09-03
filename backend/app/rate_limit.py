"""In-process rate limiting.

Deliberately simple: one sliding window per client, plus a global concurrency
cap. Correct for a single worker, which is what the Compose setup runs. Behind
several workers this needs a shared store (Redis `INCR` + `EXPIRE`); the
interface below is what would be swapped out.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

from .config import settings
from .errors import ScanError


class SlidingWindowRateLimiter:
    def __init__(self, *, limit: int, window_seconds: int) -> None:
        self._limit = limit
        self._window = window_seconds
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(self, key: str, *, now: float | None = None) -> None:
        """Record one hit for `key`, or raise ScanError if over the limit."""
        current = time.monotonic() if now is None else now
        async with self._lock:
            hits = self._hits[key]
            cutoff = current - self._window
            while hits and hits[0] <= cutoff:
                hits.popleft()

            if len(hits) >= self._limit:
                retry_after = max(1, int(hits[0] + self._window - current) + 1)
                raise ScanError(
                    "rate_limited",
                    f"Limite de {self._limit} scans por {self._window}s atingido. "
                    f"Tente de novo em {retry_after}s.",
                    status_code=429,
                )

            hits.append(current)

    async def prune(self, *, now: float | None = None) -> None:
        """Drop windows that fully expired, so idle clients stop costing memory."""
        current = time.monotonic() if now is None else now
        async with self._lock:
            cutoff = current - self._window
            stale = [key for key, hits in self._hits.items() if not hits or hits[-1] <= cutoff]
            for key in stale:
                del self._hits[key]

    @property
    def tracked_keys(self) -> int:
        return len(self._hits)

    def retry_after_seconds(self) -> int:
        return self._window


limiter = SlidingWindowRateLimiter(
    limit=settings.rate_limit_requests,
    window_seconds=settings.rate_limit_window_seconds,
)

#: Bounds how much outbound work the process does at once, independent of who
#: asked for it. Without this, N slow targets tie up N event-loop tasks.
scan_slots = asyncio.Semaphore(settings.max_concurrent_scans)
