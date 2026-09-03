from __future__ import annotations

import pytest

from app.errors import ScanError
from app.rate_limit import SlidingWindowRateLimiter


async def test_allows_up_to_the_limit() -> None:
    limiter = SlidingWindowRateLimiter(limit=3, window_seconds=60)
    for _ in range(3):
        await limiter.check("1.2.3.4", now=100.0)


async def test_blocks_past_the_limit() -> None:
    limiter = SlidingWindowRateLimiter(limit=2, window_seconds=60)
    await limiter.check("1.2.3.4", now=100.0)
    await limiter.check("1.2.3.4", now=100.0)
    with pytest.raises(ScanError) as exc:
        await limiter.check("1.2.3.4", now=100.0)
    assert exc.value.code == "rate_limited"
    assert exc.value.status_code == 429


async def test_window_slides_forward() -> None:
    limiter = SlidingWindowRateLimiter(limit=1, window_seconds=60)
    await limiter.check("1.2.3.4", now=100.0)
    with pytest.raises(ScanError):
        await limiter.check("1.2.3.4", now=159.0)
    await limiter.check("1.2.3.4", now=161.0)


async def test_clients_are_isolated() -> None:
    limiter = SlidingWindowRateLimiter(limit=1, window_seconds=60)
    await limiter.check("1.1.1.1", now=100.0)
    await limiter.check("2.2.2.2", now=100.0)


async def test_prune_drops_expired_windows() -> None:
    limiter = SlidingWindowRateLimiter(limit=5, window_seconds=60)
    await limiter.check("1.1.1.1", now=100.0)
    assert limiter.tracked_keys == 1
    await limiter.prune(now=100.0)
    assert limiter.tracked_keys == 1
    await limiter.prune(now=200.0)
    assert limiter.tracked_keys == 0
