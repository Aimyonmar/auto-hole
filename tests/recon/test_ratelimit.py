# -*- coding: utf-8 -*-
"""限速：令牌桶节流 / 越界拒绝 / 自适应降速 / 熔断 / 持久化配额。"""
import time

import pytest

from modules.recon.ratelimit import (ABSOLUTE_MAX_CONCURRENCY, AdaptiveLimiter,
                                     BudgetLedger, CircuitBreaker, RateConfigError,
                                     TokenBucket, validate_limits)


def test_validate_limits_rejects_unbounded():
    assert validate_limits(8, 20.0) == (8, 20.0)
    for conc, rps in [(0, 10.0), (-1, 10.0), (ABSOLUTE_MAX_CONCURRENCY + 1, 10.0),
                      (8, 0), (8, -1.0), (8, 999.0)]:
        with pytest.raises(RateConfigError):
            validate_limits(conc, rps)


def test_token_bucket_paces():
    bucket = TokenBucket(rate=50, burst=1)
    bucket.acquire()                     # 消耗初始令牌
    t0 = time.monotonic()
    for _ in range(5):
        bucket.acquire()
    elapsed = time.monotonic() - t0
    # 5 个令牌 @50 rps ≈ 0.1s（允许 20% 误差）
    assert 0.07 <= elapsed <= 0.15


def test_token_bucket_rate_change_takes_effect():
    bucket = TokenBucket(rate=10, burst=1)
    bucket.acquire()
    bucket.set_rate(100)
    t0 = time.monotonic()
    bucket.acquire()
    assert time.monotonic() - t0 < 0.05


def test_circuit_breaker_opens_and_recovers():
    cb = CircuitBreaker(failure_threshold=2, cooldown_s=1)
    assert cb.state == "closed" and cb.allow()
    cb.record_success()
    cb.record_failure()
    assert cb.state == "closed"
    cb.record_failure()
    assert cb.state == "open" and not cb.allow()
    cb.record_success()
    assert cb.state == "closed" and cb.allow()


def test_adaptive_limiter_cuts_rate_on_failure():
    lim = AdaptiveLimiter(rps=40, concurrency=8, min_rps=2)
    base = lim.current_rps
    lim.record_failure()
    assert lim.current_rps < base
    assert lim.stats.rate_cuts == 1
    for _ in range(10):
        lim.record_failure()
    assert lim.current_rps >= 2          # 不低于下限，绝不降到 0


def test_adaptive_throttle_and_stats():
    lim = AdaptiveLimiter(rps=20, concurrency=4, min_rps=2)
    lim.acquire()
    lim.record_throttle()
    assert lim.current_rps == 10
    snap = lim.snapshot()
    assert snap["concurrency"] == 4
    assert snap["requests"] == 1
    assert snap["circuit"] == "closed"


def test_adaptive_breaker_blocks_acquire():
    lim = AdaptiveLimiter(rps=10, concurrency=2, failure_threshold=2, cooldown_s=1)
    lim.record_failure()
    lim.record_failure()
    with pytest.raises(RuntimeError):
        lim.acquire()


def test_backoff_is_bounded():
    lim = AdaptiveLimiter(rps=10, concurrency=2, backoff_base=0.01, backoff_max=0.05)
    slept = lim.backoff_sleep(attempt=10)
    assert 0 < slept <= 0.06


def test_budget_ledger_persists_and_stops(tmp_path):
    db = tmp_path / "t.db"
    ledger = BudgetLedger(db, "t1", daily_limit=3)
    ledger.charge(1)
    ledger.charge(2, source="scan")
    assert ledger.used() == 3 and ledger.remaining() == 0
    assert ledger.breakdown()["scan"] == 2
    with pytest.raises(RuntimeError):
        ledger.charge(1)
    ledger.close()

    # 重新打开仍是累计值（跨进程/跨运行持久化）
    ledger2 = BudgetLedger(db, "t1", daily_limit=3)
    assert ledger2.used() == 3
    ledger2.close()

    # 不同目标互不影响
    ledger3 = BudgetLedger(db, "t2", daily_limit=1)
    assert ledger3.used() == 0
    ledger3.close()


def test_budget_ledger_rejects_bad_limit(tmp_path):
    with pytest.raises(RateConfigError):
        BudgetLedger(tmp_path / "x.db", "t", daily_limit=0)
