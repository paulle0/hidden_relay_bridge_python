from hidden_relay_bridge.ratelimit import PerKeyRateLimiter, TokenBucket


def test_bucket_starts_full_and_drains():
    bucket = TokenBucket(capacity=3, refill_per_second=0)
    assert [bucket.take(now=0) for _ in range(4)] == [True, True, True, False]


def test_bucket_refills_over_time():
    bucket = TokenBucket(capacity=2, refill_per_second=1.0)
    assert bucket.take(now=0) and bucket.take(now=0)
    assert bucket.take(now=0) is False
    assert bucket.take(now=1.0) is True


def test_limiter_is_per_key():
    limiter = PerKeyRateLimiter(per_minute=60, burst=1)
    assert limiter.allow("alice", now=0) is True
    assert limiter.allow("alice", now=0) is False
    assert limiter.allow("bob", now=0) is True


def test_zero_disables_the_limit():
    limiter = PerKeyRateLimiter(per_minute=0)
    assert all(limiter.allow("alice", now=0) for _ in range(100))


def test_forget_full_only_drops_buckets_that_refilled():
    limiter = PerKeyRateLimiter(per_minute=60, burst=1)
    limiter.allow("alice", now=0)
    limiter.forget_full(now=0)
    assert limiter.allow("alice", now=0) is False, "still rate limited, keep the bucket"
    limiter.forget_full(now=120)
    assert limiter.allow("alice", now=0) is True, "refilled, so the bucket can go"
