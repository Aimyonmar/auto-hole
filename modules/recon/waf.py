# -*- coding: utf-8 -*-
"""WAF 拦截识别与自动中止守卫。

只做“识别 → 审计 → 停止”，不做绕过、不重试 payload。
默认首次识别即停；可通过 waf.stop_after 配置为累计 N 次才停。
"""
from __future__ import annotations

import re
import threading
from typing import Optional

WAF_MARKERS = (
    ("cloudflare", re.compile(r"cloudflare|cf-ray|cf-cache-status|cf-mitigated", re.I)),
    ("akamai", re.compile(r"akamai|akamai-ghost", re.I)),
    ("imperva", re.compile(r"imperva|incapsula|visid_incap|X-Iinfo", re.I)),
    ("sucuri", re.compile(r"sucuri|x-sucuri", re.I)),
    ("aws-waf", re.compile(r"awswaf|aws.?waf|x-amzn-waf", re.I)),
    ("aliyun-waf", re.compile(r"aliyun|yundun|阿里云盾|errors\.aliyun", re.I)),
    ("tencent-waf", re.compile(r"tencent|腾讯云waf|waf\.tencent", re.I)),
    ("safedog", re.compile(r"safedog|安全狗", re.I)),
    ("yunsuo", re.compile(r"yunsuo|云锁", re.I)),
    ("chaitin", re.compile(r"chaitin|长亭|雷池|safeline", re.I)),
    ("360waf", re.compile(r"360waf|360网站卫士|360安全", re.I)),
    ("modsecurity", re.compile(r"modsecurity|mod_security", re.I)),
)
BLOCK_STATUSES = frozenset({403, 405, 406, 429, 503})
BLOCK_PAGE_PATTERNS = (
    ("cloudflare-block", re.compile(
        r"attention required[!！]?\s*[-|]?\s*cloudflare|cf-error-details|ray id", re.I)),
    ("generic-block", re.compile(
        r"access denied|request blocked|web application firewall|"
        r"人机验证|captcha|请稍后再试|请求疑似攻击|访问被拦截", re.I)),
)
CHALLENGE_HEADERS = ("cf-mitigated", "x-amzn-waf-action", "x-sucuri-block")


def detect_waf(status: int, headers: Optional[dict], text: str = "") -> list[str]:
    """返回命中的 WAF/拦截特征；空列表表示未识别为拦截。"""
    headers = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    corpus = " ".join([
        headers.get("server", ""),
        " ".join(f"{k}: {v}" for k, v in headers.items()),
        (text or "")[:4096],
    ])
    vendor = [name for name, rx in WAF_MARKERS if rx.search(corpus)]
    block_page = [name for name, rx in BLOCK_PAGE_PATTERNS if rx.search(corpus)]
    if int(status) == 429:
        return ["http_429"] + vendor[:2]
    if any(h in headers for h in CHALLENGE_HEADERS):
        return vendor[:2] or ["challenge"]
    if int(status) in BLOCK_STATUSES and (vendor or block_page):
        return (vendor[:2] or block_page[:2])
    if int(status) in (200, 201) and "cloudflare-block" in block_page:
        return vendor[:2] or block_page[:2]
    return []


class WafGuard:
    """跨阶段共享的 WAF 计数器；达到阈值后 stopped=True。"""

    def __init__(self, *, enabled: bool = True, stop_after: int = 1,
                 audit=None, console=None):
        self.enabled = bool(enabled)
        self.threshold = max(1, int(stop_after))
        self.audit = audit
        self.console = console or (lambda _m: None)
        self.hits = 0
        self.stopped = False
        self.info: dict = {}
        self._lock = threading.Lock()

    def observe(self, *, stage: str, url: str, status: int,
                headers: Optional[dict], text: str = "") -> bool:
        if not self.enabled:
            return False
        markers = detect_waf(status, headers, text)
        if not markers:
            return False
        with self._lock:
            self.hits += 1
            rec = {"stage": stage, "url": url, "status": int(status),
                   "markers": markers, "hit": self.hits,
                   "threshold": self.threshold}
            if self.audit is not None:
                self.audit.write("waf_hit", **rec)
            if self.stopped:
                return True
            if self.hits < self.threshold:
                return False
            self.stopped = True
            self.info = {**rec, "stopped": True}
            if self.audit is not None:
                self.audit.write("waf_stop", **self.info)
        self.console(
            f"[!] WAF 拦截（{stage}，HTTP {status}，特征 {','.join(markers)}）；"
            f"当前目标中止后续阶段")
        return True

    def to_dict(self) -> dict:
        out = {
            "enabled": self.enabled,
            "threshold": self.threshold,
            "hits": self.hits,
            "stopped": self.stopped,
        }
        if self.info:
            out.update(self.info)
        return out
