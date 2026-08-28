from __future__ import annotations

from ntshield.rate_limit import FixedWindowRateLimiter


def test_fixed_window_rate_limiter_resets_without_leaking_keys() -> None:
    limiter = FixedWindowRateLimiter(window_seconds=60, max_keys=100)
    assert limiter.check("alice", 2, now=1).allowed
    assert limiter.check("alice", 2, now=2).allowed
    denied = limiter.check("alice", 2, now=3)
    assert not denied.allowed
    assert denied.retry_after_seconds > 0
    reset = limiter.check("alice", 2, now=61)
    assert reset.allowed
    assert reset.remaining == 1
