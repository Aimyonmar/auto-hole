# -*- coding: utf-8 -*-
"""有界并发 + 令牌桶 + 自适应降速 + 熔断 + 持久化配额。

借鉴点：
- naabu/masscan 的速率模型：一个全局令牌桶 + 固定 worker 数，二者都是“有界”的
- nmap 的 RTT 自适应思路 → 这里简化为“按失败信号降速”，成功后再缓慢回升
- nuclei -rl/-c 的双重限速：速率（每秒）和并发（同时在飞）分别控制

不可突破的底线（代码级）：
- concurrency 必须是正整数且 ≤ ABSOLUTE_MAX_CONCURRENCY
- 每秒请求数必须有上限
- 连续失败达阈值 → 熔断冷却，期间拒绝发请求
"""
from __future__ import annotations

import os
import sqlite3
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path

# 代码级绝对上限：任何配置/参数都不能超过（“有界并发”，不存在无上限模式）
ABSOLUTE_MAX_CONCURRENCY = 64
ABSOLUTE_MAX_RPS = 200.0
ABSOLUTE_MIN_RPS = 0.5


class RateConfigError(ValueError):
    """限速参数越界。"""


def validate_limits(concurrency: int, rps: float) -> tuple[int, float]:
    """校验并返回 (concurrency, rps)；越界直接抛异常，不静默修正。"""
    if not isinstance(concurrency, int) or concurrency <= 0:
        raise RateConfigError(f"并发必须为正整数，当前 {concurrency!r}")
    if concurrency > ABSOLUTE_MAX_CONCURRENCY:
        raise RateConfigError(
            f"并发 {concurrency} 超过代码级上限 {ABSOLUTE_MAX_CONCURRENCY}（禁止无界并发）")
    if rps <= 0:
        raise RateConfigError(f"每秒请求数必须 > 0，当前 {rps!r}")
    if rps > ABSOLUTE_MAX_RPS:
        raise RateConfigError(f"每秒请求数 {rps} 超过代码级上限 {ABSOLUTE_MAX_RPS}")
    return concurrency, float(rps)


class TokenBucket:
    """线程安全令牌桶：rate 可运行时调整（自适应降速用）。"""

    def __init__(self, rate: float, burst: int = 1):
        self._rate = max(ABSOLUTE_MIN_RPS, float(rate))
        self._burst = max(1, int(burst))
        self._tokens = float(self._burst)
        self._last = time.monotonic()
        self._lock = threading.Lock()

    @property
    def rate(self) -> float:
        with self._lock:
            return self._rate

    def set_rate(self, rate: float) -> None:
        with self._lock:
            self._rate = min(ABSOLUTE_MAX_RPS, max(ABSOLUTE_MIN_RPS, float(rate)))

    def acquire(self, tokens: int = 1, max_wait: float = 30.0) -> float:
        """取令牌，必要时阻塞；返回等待秒数。max_wait 兜底防止无限等待。"""
        waited = 0.0
        need = max(1, int(tokens))
        while True:
            with self._lock:
                now = time.monotonic()
                self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
                self._last = now
                if self._tokens >= need:
                    self._tokens -= need
                    return waited
                missing = need - self._tokens
                sleep_s = min(missing / self._rate, max_wait - waited, 2.0)
            if sleep_s <= 0 or waited >= max_wait:
                return waited
            time.sleep(sleep_s)
            waited += sleep_s


class CircuitBreaker:
    """连续失败熔断：open → 冷却 → half-open（只放一个探针）→ closed。"""

    def __init__(self, failure_threshold: int = 8, cooldown_s: float = 60.0):
        self.threshold = max(1, failure_threshold)
        self.cooldown_s = max(1.0, cooldown_s)
        self._failures = 0
        self._opened_at = 0.0
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._failures < self.threshold:
                return "closed"
            if time.monotonic() - self._opened_at < self.cooldown_s:
                return "open"
            return "half-open"

    def allow(self) -> bool:
        return self.state != "open"

    def opened_seconds(self) -> float:
        with self._lock:
            return time.monotonic() - self._opened_at if self._failures >= self.threshold else 0.0

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.threshold:
                self._opened_at = time.monotonic()

    def reset(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = 0.0


@dataclass
class LimiterStats:
    requests: int = 0
    waits: float = 0.0            # 累计等待时长（秒），用于反推实际速率
    rate_cuts: int = 0
    failures: int = 0
    circuit_opens: int = 0
    min_rate: float = 0.0
    max_rate: float = 0.0

    def to_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()}


class AdaptiveLimiter:
    """组合令牌桶 + 指数退避 + 熔断，记录实际速率供审计。"""

    def __init__(self, rps: float, concurrency: int, burst: int = 1,
                 min_rps: float = 2.0, backoff_base: float = 0.5,
                 backoff_max: float = 8.0, failure_threshold: int = 8,
                 cooldown_s: float = 60.0):
        rps, conc = float(rps), int(concurrency)
        validate_limits(conc, rps)
        self.concurrency = conc
        self.bucket = TokenBucket(rps, burst=max(1, burst))
        self.breaker = CircuitBreaker(failure_threshold, cooldown_s)
        self.base_rps = rps
        self.min_rps = max(ABSOLUTE_MIN_RPS, float(min_rps))
        self.backoff_base = backoff_base
        self.backoff_max = backoff_max
        self.stats = LimiterStats(min_rate=rps, max_rate=rps)
        self._success_streak = 0
        self._lock = threading.Lock()

    # ---- 请求前 ----
    def acquire(self) -> None:
        """熔断打开时抛 RuntimeError；否则阻塞取令牌。"""
        if not self.breaker.allow():
            raise RuntimeError(
                f"熔断已打开（连续失败 {self.breaker.threshold} 次），冷却 "
                f"{self.breaker.opened_seconds():.0f}s 后重试")
        waited = self.bucket.acquire()
        with self._lock:
            self.stats.requests += 1
            self.stats.waits = round(self.stats.waits + waited, 3)

    # ---- 请求后 ----
    def record_success(self) -> None:
        self.breaker.record_success()
        with self._lock:
            self._success_streak += 1
            # 每 20 次成功回升 10%，上限回到基线
            if self._success_streak >= 20:
                self._success_streak = 0
                new_rate = min(self.base_rps, self.bucket.rate * 1.10)
                if new_rate > self.bucket.rate:
                    self.bucket.set_rate(new_rate)

    def record_failure(self, retryable: bool = True) -> None:
        self.breaker.record_failure()
        with self._lock:
            self.stats.failures += 1
            if not retryable:
                return
            # 降速 50%，不低于 min_rps
            old = self.bucket.rate
            new_rate = max(self.min_rps, old * 0.5)
            if new_rate < old:
                self.bucket.set_rate(new_rate)
                self.stats.rate_cuts += 1
                self.stats.min_rate = min(self.stats.min_rate, new_rate)
            if self.breaker.state == "open":
                self.stats.circuit_opens += 1

    def record_throttle(self) -> None:
        """对端返回 429/503：立即降速并不计入普通失败。"""
        with self._lock:
            old = self.bucket.rate
            new_rate = max(self.min_rps, old * 0.5)
            self.bucket.set_rate(new_rate)
            if new_rate < old:
                self.stats.rate_cuts += 1
                self.stats.min_rate = min(self.stats.min_rate, new_rate)
            self.stats.max_rate = max(self.stats.max_rate, old)

    def backoff_sleep(self, attempt: int) -> float:
        """指数退避（带抖动），有上限；返回实际睡眠秒数。"""
        delay = min(self.backoff_max, self.backoff_base * (2 ** attempt))
        delay *= 0.7 + 0.3 * (os.getpid() % 7) / 7.0  # 轻抖动，避免同步打击
        time.sleep(delay)
        return delay

    @property
    def current_rps(self) -> float:
        return round(self.bucket.rate, 2)

    def snapshot(self) -> dict:
        d = self.stats.to_dict()
        d.update({
            "concurrency": self.concurrency,
            "current_rps": self.current_rps,
            "base_rps": self.base_rps,
            "circuit": self.breaker.state,
        })
        return d


class BudgetLedger:
    """持久化请求配额（按 target+day），跨进程/跨次运行累计。

    SQLite 表独立于 core 的 request_counter，互不干扰；两者都强制持久化。
    """

    def __init__(self, db_path: Path, target: str, daily_limit: int):
        if daily_limit <= 0:
            raise RateConfigError(f"日请求上限必须 > 0，当前 {daily_limit}")
        self.db_path = Path(db_path)
        self.target = target
        self.limit = int(daily_limit)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS recon_budget ("
            " target TEXT, day TEXT, source TEXT, count INTEGER,"
            " PRIMARY KEY(target, day, source))")

    @property
    def today(self) -> str:
        return time.strftime("%Y-%m-%d")

    def _used_unlocked(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(count),0) FROM recon_budget WHERE target=? AND day=?",
            (self.target, self.today)).fetchone()
        return int(row[0] or 0)

    def used(self) -> int:
        with self._lock:
            return self._used_unlocked()

    def remaining(self) -> int:
        return max(0, self.limit - self.used())

    def charge(self, n: int = 1, source: str = "probe") -> None:
        """登记 n 次请求；超限抛 RuntimeError（由调用方熔断）。"""
        if n <= 0:
            return
        with self._lock:
            used = self._used_unlocked()
            if used + n > self.limit:
                raise RuntimeError(
                    f"日请求配额熔断：目标「{self.target}」已用 {used}/{self.limit}，"
                    f"本次需 {n}")
            self._conn.execute(
                "INSERT INTO recon_budget(target, day, source, count) VALUES(?,?,?,?) "
                "ON CONFLICT(target, day, source) DO UPDATE SET count = count + ?",
                (self.target, self.today, source, n, n))
            self._conn.commit()

    def breakdown(self) -> dict:
        with self._lock:
            rows = self._conn.execute(
                "SELECT source, count FROM recon_budget WHERE target=? AND day=?",
                (self.target, self.today)).fetchall()
        return {str(r[0]): int(r[1]) for r in rows}

    def close(self) -> None:
        self._conn.close()
