# -*- coding: utf-8 -*-
"""HTTP 存活探测 + 指纹识别（单次请求完成多维提取）。

借鉴点（httpx / EHole / ObserverWard）：
- 一次请求同时拿状态码、Server、标题、正文指纹 —— 不做“先探活再抓正文”的两趟请求
- URL 归一化后再请求（host:port 统一构造，https→http 回退仅限 TLS 端口）
- 请求前先过范围校验 → 再登记配额 → 再取令牌，顺序固定，任何一步失败都不发请求
- 每个请求写一条审计记录（含耗时与当时速率），命中额外写 fingerprint_hit
"""
from __future__ import annotations

import hashlib
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

import requests
import urllib3

from core.constitution import TargetDef, check_host_in_scope

from .audit import AuditLog
from .config import Profile, ReconConfig
from .fingerprint import FingerprintEngine, MatchContext
from .ratelimit import AdaptiveLimiter, BudgetLedger
from .schema import (Asset, build_url, extract_title, normalize_url,
                    scheme_for_port)
from .state import RunState

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

HTTPS_FALLBACK_PORTS = frozenset({443, 8443, 9443})


class ProbeAborted(RuntimeError):
    """配额/熔断导致的整体中止。"""


class WafDetected(ProbeAborted):
    """识别到 WAF/拦截特征，当前目标必须停止后续阶段。"""


@dataclass
class ProbeStats:
    hosts: int = 0
    requests: int = 0
    alive: int = 0
    dead: int = 0
    errors: int = 0
    throttled: int = 0
    duration_s: float = 0.0
    effective_rps: float = 0.0
    limiter: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return dict(self.__dict__)


class Prober:
    def __init__(self, *, recon: ReconConfig, target: TargetDef, profile: Profile,
                 limiter: AdaptiveLimiter, ledger: BudgetLedger,
                 audit: AuditLog, engine: Optional[FingerprintEngine] = None,
                 console: Callable[[str], None] = print,
                 in_scope: Optional[Callable[[str], bool]] = None,
                 waf_guard=None):
        self.recon = recon
        self.target = target
        self.profile = profile
        self.limiter = limiter
        self.ledger = ledger
        self.audit = audit
        self.engine = engine
        self.log = console
        self.in_scope = in_scope or (lambda h: check_host_in_scope(h, target))
        self.waf_guard = waf_guard
        self._tls = threading.local()

    # ------------------------------------------------------------------
    # 会话
    # ------------------------------------------------------------------
    def new_session(self) -> requests.Session:
        """创建一个独立会话（越权检测按身份隔离 cookie，避免串号）。"""
        s = requests.Session()
        s.verify = self.recon.probe.verify_tls
        s.trust_env = bool(self.recon.probe.trust_env)
        s.max_redirects = int(self.recon.probe.max_redirects)
        s.headers.update({
            "User-Agent": self.recon.probe.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
        })
        return s

    def _session(self) -> requests.Session:
        s = getattr(self._tls, "session", None)
        if s is None:
            s = self.new_session()
            self._tls.session = s
        return s

    # ------------------------------------------------------------------
    # 对外：批量探测
    # ------------------------------------------------------------------
    def probe_assets(self, assets: Iterable[Asset],
                     state: Optional[RunState] = None) -> tuple[list[Asset], ProbeStats]:
        pending = [a for a in assets if not (state and state.is_processed("probe", a.key))]
        stats = ProbeStats(hosts=len({a.host for a in pending}))
        t0 = time.monotonic()
        results: list[Asset] = []

        if not pending:
            stats.duration_s = 0.0
            return results, stats

        futures = {}
        with ThreadPoolExecutor(max_workers=max(1, self.profile.concurrency),
                                thread_name_prefix="recon-probe") as ex:
            for a in pending:
                futures[ex.submit(self._probe_one, a.host, self._ports_for(a))] = a

            for fut in as_completed(futures):
                base = futures[fut]
                try:
                    probe_results = fut.result()
                except ProbeAborted as e:
                    self.log(f"[!] 探测中止: {e}")
                    for f in futures:
                        f.cancel()
                    break
                except Exception as e:  # 单主机异常不影响整体
                    stats.errors += 1
                    self.audit.write("error", stage="probe", host=base.host, error=str(e)[:200])
                    if state:
                        state.mark_processed("probe", [base.key], persist=False)
                    continue
                if probe_results:
                    stats.alive += 1
                    for r in probe_results:
                        _inherit(r, base)
                        results.append(r)
                else:
                    stats.dead += 1
                if state:
                    # 同时记录原始 key 与实际探测到的 host|port，保证二次续跑不重复请求
                    keys = [base.key] + [r.key for r in probe_results]
                    state.mark_processed("probe", keys, persist=False)

                done = stats.alive + stats.dead
                if done % 50 == 0:
                    self.log(f"    探测进度 {done}/{len(pending)} 存活 {stats.alive}")

        if state:
            state.set_counter("probe", "alive", stats.alive)
            state.set_counter("probe", "dead", stats.dead)
            state.save()

        stats.duration_s = round(time.monotonic() - t0, 2)
        stats.limiter = self.limiter.snapshot()
        stats.requests = int(stats.limiter.get("requests", 0))
        stats.effective_rps = round(stats.requests / stats.duration_s, 2) if stats.duration_s else 0.0
        return results, stats

    # ------------------------------------------------------------------
    # 单主机
    # ------------------------------------------------------------------
    def _ports_for(self, asset: Asset) -> list[int]:
        if asset.port:
            return [asset.port]
        if asset.url:
            _, p, _, _ = normalize_url(asset.url)
            if p and p not in (80, 443):
                return [p]
        return list(self.profile.probe_ports)

    def _urls_for(self, host: str, port: int) -> list[str]:
        scheme = scheme_for_port(port)
        urls = [build_url(host, port, scheme)]
        if port in HTTPS_FALLBACK_PORTS:
            urls.append(build_url(host, port, "http"))
        return urls

    def _probe_one(self, host: str, ports: list[int]) -> list[Asset]:
        out: list[Asset] = []
        for port in ports:
            for url in self._urls_for(host, port):
                asset = self._fetch(url, host, port)
                if asset is not None:
                    out.append(asset)
                    break   # 该端口已探活成功，换下一个端口
        return out

    # ------------------------------------------------------------------
    # 统一请求通道（探测 / 爬取 / 路径探测共用）
    # ------------------------------------------------------------------
    def request(self, url: str, host: str, *, stage: str = "probe",
                extra_headers: Optional[dict] = None,
                session: Optional[requests.Session] = None,
                identity: str = "", audit_url: str = "",
                tag: str = "") -> Optional[dict]:
        """发一次 GET，返回 {status, headers, body, text, elapsed_ms, url}。

        顺序固定：范围校验 → 配额登记 → 令牌桶 → 请求；任一步失败都不发请求。
        越权检测通过 extra_headers / 独立 session 注入身份，不改变本函数的 GET 语义。
        """
        aurl = audit_url or url
        if not self.in_scope(host):
            self.audit.write("scope_reject", stage=stage, host=host, url=aurl,
                             reason="不在授权范围", identity=identity or None,
                             tag=tag or None)
            return None

        attempts = int(self.profile.probe_retries) + 1
        for attempt in range(attempts):
            try:
                self.ledger.charge(1, source=stage)
                self.limiter.acquire()
            except RuntimeError as e:
                self.audit.write("budget_stop", stage=stage, host=host, url=aurl,
                                 note=str(e)[:200], identity=identity or None,
                                 tag=tag or None)
                raise ProbeAborted(str(e)) from e

            if self.recon.probe.min_delay_ms > 0:
                time.sleep(self.recon.probe.min_delay_ms / 1000.0)

            t0 = time.perf_counter()
            try:
                sess = session or self._session()
                resp = sess.get(
                    url,
                    timeout=(float(self.recon.probe.connect_timeout),
                             float(self.profile.probe_timeout)),
                    allow_redirects=bool(self.profile.follow_redirects),
                    stream=True,
                    headers=extra_headers or None,
                )
                status = int(resp.status_code)
                headers = {str(k).lower(): str(v) for k, v in resp.headers.items()}
                encoding = resp.encoding or "utf-8"
                body = _read_limited(resp, int(self.profile.max_body_bytes))
                resp.close()
            except requests.RequestException as e:
                elapsed = round((time.perf_counter() - t0) * 1000, 1)
                self.limiter.record_failure()
                self.audit.write("request", stage=stage, host=host, url=aurl,
                                 status=None, elapsed_ms=elapsed, attempt=attempt,
                                 rps=self.limiter.current_rps, outcome="error",
                                 error=type(e).__name__, identity=identity or None,
                                 tag=tag or None)
                if attempt + 1 < attempts:
                    self.limiter.backoff_sleep(attempt)
                    continue
                return None

            elapsed = round((time.perf_counter() - t0) * 1000, 1)
            outcome = "ok"
            if status == 429:
                self.limiter.record_throttle()
                outcome = "throttled"
            elif status >= 500:
                self.limiter.record_failure()
                outcome = "server_error"
            else:
                self.limiter.record_success()

            text = _decode(body, encoding)
            result = {"url": url, "status": status, "headers": headers,
                      "body": body, "text": text, "elapsed_ms": elapsed}
            self.audit.write("request", stage=stage, host=host, url=aurl,
                             status=status, elapsed_ms=elapsed, attempt=attempt,
                             rps=self.limiter.current_rps, outcome=outcome,
                             body_len=len(body), identity=identity or None,
                             tag=tag or None)
            if self.waf_guard is not None and self.waf_guard.observe(
                    stage=stage, url=aurl, status=status,
                    headers=headers, text=text):
                exc = WafDetected(f"WAF 拦截：{aurl} HTTP {status}")
                exc.info = self.waf_guard.to_dict()
                exc.response = result
                raise exc
            return result
        return None

    # ------------------------------------------------------------------
    # 单次请求 + 提取 + 指纹
    # ------------------------------------------------------------------
    def _fetch(self, url: str, host: str, port: int) -> Optional[Asset]:
        res = self.request(url, host)
        if res is None:
            return None

        status = res["status"]
        headers = res["headers"]
        body = res["body"]
        text = res["text"]
        elapsed = res["elapsed_ms"]
        title = extract_title(text)
        favicon = ""
        if self.profile.favicon:
            favicon = self._favicon_hash(host, port, url)

        products = []
        if self.engine is not None:
            matches = self.engine.match(MatchContext(
                url=url, status=status, title=title,
                headers=headers, body=text, favicon_sha256=favicon))
            products = [m.to_dict() for m in matches]
            for m in matches:
                self.audit.write("fingerprint_hit", stage="probe", host=host, url=url,
                                 product=m.product, rule_id=m.rule_id,
                                 confidence=round(m.confidence, 3),
                                 matched=m.matched)

        return Asset(
            host=host, port=port, url=url, scheme=scheme_for_port(port),
            status=status, title=title,
            server=headers.get("server", ""),
            content_type=headers.get("content-type", ""),
            tech=[], products=products, sources=[],
            evidence={
                "url": url, "status": status, "elapsed_ms": elapsed,
                "body_sha256": hashlib.sha256(body).hexdigest()[:16],
                "body_len": len(body),
                **({"favicon_sha256": favicon} if favicon else {}),
            },
            meta={"probe": "http"},
        )

    def _favicon_hash(self, host: str, port: int, base_url: str) -> str:
        """可选：抓 favicon 并算 sha256（对应 EHole/ObserverWard 的 favicon hash 规则）。"""
        url = base_url.rstrip("/") + "/favicon.ico"
        if not self.in_scope(host):
            return ""
        try:
            self.ledger.charge(1, source="probe:favicon")
            self.limiter.acquire()
            resp = self._session().get(
                url, timeout=(float(self.recon.probe.connect_timeout),
                              float(self.profile.probe_timeout)), stream=True)
            data = _read_limited(resp, 16384)
            resp.close()
            if data:
                return hashlib.sha256(data).hexdigest()
        except Exception:
            return ""
        return ""


def _read_limited(resp: requests.Response, limit: int) -> bytes:
    """按上限读取响应体，避免把大响应整个拉下来（省流量也省内存）。"""
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=16384):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= limit:
            break
    return b"".join(chunks)[:limit]


def _decode(body: bytes, encoding: str) -> str:
    try:
        return body.decode(encoding, errors="replace")
    except LookupError:
        return body.decode("utf-8", errors="replace")


def _inherit(result: Asset, origin: Asset) -> None:
    """把发现来源（sources/tech/tags/first_seen）继承到探测结果上。"""
    if not origin.sources and not origin.tech and not origin.tags:
        return
    clone = Asset(
        host=origin.host, port=result.port,
        title=origin.title, tech=list(origin.tech), sources=list(origin.sources),
        tags=list(origin.tags), meta=dict(origin.meta),
        first_seen=origin.first_seen,
    )
    clone.url = ""       # 不覆盖探测到的真实 URL
    clone.scheme = ""
    result.merge(clone)
