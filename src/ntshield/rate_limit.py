from __future__ import annotations

import threading
import time
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int


@dataclass(slots=True)
class _Bucket:
    window: int
    count: int


class FixedWindowRateLimiter:
    """Small in-process limiter used before a distributed Redis limiter is configured.

    It is deliberately fail-closed at the process boundary and keyed by authenticated
    principal and tenant. Multi-replica deployments should replace it with a shared
    implementation, but this still prevents one request stream from exhausting a
    single worker.
    """

    def __init__(self, *, window_seconds: int = 60, max_keys: int = 100_000):
        if window_seconds < 1:
            raise ValueError("window_seconds must be positive")
        if max_keys < 100:
            raise ValueError("max_keys must be at least 100")
        self.window_seconds = window_seconds
        self.max_keys = max_keys
        self._lock = threading.RLock()
        self._buckets: dict[str, _Bucket] = {}

    def check(self, key: str, limit: int, *, now: float | None = None) -> RateLimitDecision:
        if limit < 1:
            raise ValueError("rate limit must be positive")
        timestamp = time.time() if now is None else now
        window = int(timestamp // self.window_seconds)
        retry_after = max(1, int((window + 1) * self.window_seconds - timestamp))
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None or bucket.window != window:
                bucket = _Bucket(window=window, count=0)
                self._buckets[key] = bucket
            if bucket.count >= limit:
                return RateLimitDecision(False, limit, 0, retry_after)
            bucket.count += 1
            remaining = max(0, limit - bucket.count)
            if len(self._buckets) > self.max_keys:
                self._prune(window)
        return RateLimitDecision(True, limit, remaining, retry_after)

    def _prune(self, current_window: int) -> None:
        stale = [key for key, bucket in self._buckets.items() if bucket.window < current_window]
        for key in stale:
            self._buckets.pop(key, None)
        if len(self._buckets) <= self.max_keys:
            return
        overflow = len(self._buckets) - self.max_keys
        for key in list(self._buckets)[:overflow]:
            self._buckets.pop(key, None)
