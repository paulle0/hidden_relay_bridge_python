"""A small token bucket, used to cap how fast one pubkey can drive the bridge."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class TokenBucket:
    capacity: float
    refill_per_second: float
    tokens: float = field(default=0.0)
    updated_at: float = field(default_factory=time.monotonic)

    def __post_init__(self) -> None:
        if self.tokens == 0.0:
            self.tokens = self.capacity

    def take(self, amount: float = 1.0, now: float | None = None) -> bool:
        now = time.monotonic() if now is None else now
        elapsed = max(0.0, now - self.updated_at)
        self.updated_at = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        if self.tokens < amount:
            return False
        self.tokens -= amount
        return True


class PerKeyRateLimiter:
    """One bucket per key, with lazy cleanup of buckets that refilled fully."""

    def __init__(self, per_minute: int, burst: int | None = None) -> None:
        self.per_minute = per_minute
        self.capacity = float(burst if burst is not None else max(1, per_minute))
        self.refill_per_second = per_minute / 60.0
        self._buckets: Dict[str, TokenBucket] = {}

    def allow(self, key: str, now: float | None = None) -> bool:
        if self.per_minute <= 0:  # 0 disables the limit
            return True
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = TokenBucket(self.capacity, self.refill_per_second)
            self._buckets[key] = bucket
        return bucket.take(1.0, now)

    def forget_full(self, now: float | None = None) -> None:
        """Drop buckets that have refilled, so idle pubkeys stop using memory."""
        now = time.monotonic() if now is None else now
        for key, bucket in list(self._buckets.items()):
            elapsed = max(0.0, now - bucket.updated_at)
            projected = bucket.tokens + elapsed * bucket.refill_per_second
            if projected >= bucket.capacity:
                del self._buckets[key]
