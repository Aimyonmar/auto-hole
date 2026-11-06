# -*- coding: utf-8 -*-
"""URL / 路径 / 参数发现（仅主动、可分级、全部走统一请求通道）。

借鉴点：
- katana：深度控制、同源限制、静态资源过滤、去重、并发
- ffuf：字典探测 + 基线校准（先探一个随机不存在路径，据此判断“异常响应”）
- gau/waybackurls：历史 URL 源（本项目提供离线导入，避免开发期访问外部）

分级由 profile 控制：
- light：深度 1、最多 30 个 URL、20 条路径字典、抓 inline JS
- standard：深度 2、200 个 URL、60 条路径
- deep：深度 3、800 个 URL、120 条路径

所有请求都经过 Prober.request()（范围校验 → 配额 → 令牌桶 → 审计），不存在旁路。
"""
from __future__ import annotations

import re
import statistics
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from .config import Profile, ReconConfig
from .probe import ProbeAborted, Prober
from .schema import Asset, normalize_url
from .state import RunState
from .targeting import primary_product

STATIC_EXT = {
    ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".ico", ".webp", ".css",
    ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".avi", ".mov", ".pdf",
    ".zip", ".rar", ".7z", ".gz", ".tar", ".exe", ".dmg", ".iso",
}

_LINK_RE = re.compile(r"""<(?:a|form|iframe)\b[^>]*(?:href|action)\s*=\s*["']([^"'#]+)["']""",
                      re.IGNORECASE)
_SCRIPT_RE = re.compile(r"""<script\b[^>]*src\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_INPUT_RE = re.compile(r"""<input\b[^>]*name\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_QUOTED_PATH_RE = re.compile(r"""["']([^"'\s<>]{3,200})["']""")
_JS_CALL_RE = re.compile(r"""\.(?:get|post|put|delete|ajax)\(\s*["']([^"']+)["']""",
                         re.IGNORECASE)
_FETCH_RE = re.compile(r"""fetch\(\s*["']([^"']+)["']""", re.IGNORECASE)


@dataclass
class DiscoveredUrl:
    url: str
    host: str
    source: str                 # crawl | js | path_scan | history
    depth: int = 0
    status: int = 0
    length: int = 0
    params: list = field(default_factory=list)
    interesting: bool = False
    product: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["schema"] = "recon.url/v1"
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DiscoveredUrl":
        keys = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**keys)


def url_key(url: str) -> str:
    """URL 去重 key：去 fragment、统一 scheme/host、去默认端口。"""
    u = urllib.parse.urlsplit(url)
    if u.scheme not in ("http", "https"):
        return ""
    netloc = u.netloc.lower()
    if netloc.endswith(":80"):
        netloc = netloc[:-3]
    if netloc.endswith(":443"):
        netloc = netloc[:-4]
    path = u.path or "/"
    return urllib.parse.urlunsplit((u.scheme.lower(), netloc, path, u.query, ""))


def same_origin(a: str, b: str) -> bool:
    ua, ub = urllib.parse.urlsplit(a), urllib.parse.urlsplit(b)
    na = ua.netloc.lower().replace(":80", "").replace(":443", "")
    nb = ub.netloc.lower().replace(":80", "").replace(":443", "")
    return ua.scheme.lower() == ub.scheme.lower() and na == nb


def is_static(url: str) -> bool:
    path = urllib.parse.urlsplit(url).path.lower()
    return any(path.endswith(ext) for ext in STATIC_EXT)


def join_url(base: str, href: str) -> str:
    href = (href or "").strip()
    if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
        return ""
    full = urllib.parse.urljoin(base, href)
    full = urllib.parse.urlsplit(full)._replace(fragment="").geturl()
    return full if full.startswith(("http://", "https://")) else ""


def extract_links(html: str, base: str) -> list[str]:
    """从 HTML 提取可爬链接（a/form/iframe/script）。"""
    if not html:
        return []
    out = []
    for rx in (_LINK_RE, _SCRIPT_RE):
        for m in rx.finditer(html):
            u = join_url(base, m.group(1))
            if u and u not in out:
                out.append(u)
    return out


def extract_inputs(html: str) -> list[str]:
    return list({m.group(1) for m in _INPUT_RE.finditer(html or "")})


def extract_js_endpoints(text: str) -> list[str]:
    """从 JS / inline script 提取端点与接口路径。"""
    out: list[str] = []
    for m in _JS_CALL_RE.finditer(text or ""):
        out.append(m.group(1))
    for m in _FETCH_RE.finditer(text or ""):
        out.append(m.group(1))
    for m in _QUOTED_PATH_RE.finditer(text or ""):
        s = m.group(1)
        if "/" in s and not s.startswith("//") and len(s) >= 4:
            out.append(s)
    seen, result = set(), []
    for s in out:
        s = s.strip()
        if s and s not in seen:
            seen.add(s)
            result.append(s)
    return result[:100]


def params_of(url: str) -> list[str]:
    q = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query, keep_blank_values=True)
    return list(q.keys())


def load_history_urls(recon: ReconConfig, target_name: str,
                      console: Callable[[str], None] = print) -> list[str]:
    """历史 URL 离线导入（gau/waybackurls 导出放这里即可）。

    文件：<import_dir>/<target>.urls.txt，每行一个 URL。
    在线 CDX 查询未内置：开发期不允许访问外部资产，导出后离线导入更可控。
    """
    safe = "".join(c for c in target_name if c.isalnum() or c in "-_.")[:64] or "target"
    p = recon.abs_path(recon.sources.import_dir) / f"{safe}.urls.txt"
    if not p.exists():
        return []
    urls = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or not line.startswith(("http://", "https://")):
            continue
        urls.append(line)
    console(f"    history 导入 {len(urls)} 条历史 URL（{p.name}）")
    return urls


def load_path_dict(recon: ReconConfig, limit: int) -> list[str]:
    p = recon.abs_path(recon.sources.path_dict)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        out.append(line if line.startswith("/") else "/" + line)
    return out[:max(0, limit)]


class Discovery:
    """爬取 + JS 提取 + 路径字典探测。"""

    def __init__(self, *, prober: Prober, profile: Profile, recon: ReconConfig,
                 target_name: str, state: Optional[RunState] = None,
                 console: Callable[[str], None] = print):
        self.prober = prober
        self.profile = profile
        self.recon = recon
        self.target_name = target_name
        self.state = state
        self.log = console
        self._lock = threading.Lock()
        self.stats = {"pages": 0, "urls": 0, "js_endpoints": 0,
                      "paths_tested": 0, "history_urls": 0, "aborted": False}

    # ------------------------------------------------------------------
    def run(self, assets: Iterable[Asset]) -> list[DiscoveredUrl]:
        seeds: list[tuple[str, str]] = []
        for a in assets:
            if not a.url or not a.status or a.status >= 400:
                continue
            if is_static(a.url):
                continue
            seeds.append((a.url, primary_product(a)))

        history = load_history_urls(self.recon, self.target_name, self.log)
        self.stats["history_urls"] = len(history)
        for u in history:
            host = normalize_url(u)[0]
            seeds.append((u, ""))

        found: list[DiscoveredUrl] = []
        if self.profile.discover_enabled:
            found = self._crawl(seeds)
            found += self._scan_paths(assets)
        # 高价值优先：路径探测中“异常响应”的排前面，其次历史/爬取
        found.sort(key=lambda r: (not r.interesting, r.source != "path_scan", r.depth))
        return found

    # ------------------------------------------------------------------
    def _crawl(self, seeds: list[tuple[str, str]]) -> list[DiscoveredUrl]:
        max_depth = int(self.profile.crawl_depth)
        max_urls = int(self.profile.crawl_max_urls)
        out: list[DiscoveredUrl] = []
        visited: set[str] = set()
        frontier = [(u, 0, p) for u, p in seeds]
        for u, _, _ in frontier:
            visited.add(url_key(u))

        for depth in range(max_depth + 1):
            if not frontier or len(out) >= max_urls:
                break
            level = frontier[: max(0, max_urls - len(out))]
            frontier = []
            results = self._fetch_many([u for u, _, _ in level])

            for (url, d, product), res in zip(level, results):
                if res is None:
                    continue
                self.stats["pages"] += 1
                status = res["status"]
                if status >= 500:
                    continue
                rec = DiscoveredUrl(
                    url=url, host=normalize_url(url)[0], source="crawl", depth=d,
                    status=status, length=len(res["body"]),
                    params=params_of(url) + extract_inputs(res["text"]),
                    product=product,
                )
                out.append(rec)
                if d >= max_depth:
                    continue
                for link, source in self._expand(res["text"], url, d):
                    k = url_key(link)
                    if not k or k in visited or is_static(link):
                        continue
                    if len(visited) >= max_urls:
                        break
                    if self.profile.crawl_same_origin and not same_origin(url, link):
                        continue
                    if self.state and self.state.is_processed("discover", k):
                        continue
                    visited.add(k)
                    frontier.append((link, d + 1, product))
                    if source == "js":
                        self.stats["js_endpoints"] += 1
        self.stats["urls"] = len(out)
        return out

    def _expand(self, html: str, base: str, depth: int) -> list[tuple[str, str]]:
        pairs: list[tuple[str, str]] = []
        for link in extract_links(html, base):
            pairs.append((link, "crawl"))
        if self.profile.js_extract:
            for ep in extract_js_endpoints(html):
                u = join_url(base, ep)
                if u:
                    pairs.append((u, "js"))
            # 同源 JS 文件里的端点（每个页面最多取 2 个 JS，控制请求量）
            js_files = [u for u in extract_links(html, base)
                        if urllib.parse.urlsplit(u).path.lower().endswith(".js")][:2]
            for js in js_files:
                if not same_origin(base, js):
                    continue
                res = self.prober.request(js, normalize_url(js)[0], stage="discover")
                if not res:
                    continue
                for ep in extract_js_endpoints(res["text"]):
                    u = join_url(base, ep)
                    if u:
                        pairs.append((u, "js"))
        return pairs

    def _fetch_many(self, urls: list[str]) -> list[Optional[dict]]:
        def one(u: str) -> Optional[dict]:
            try:
                return self.prober.request(u, normalize_url(u)[0], stage="discover")
            except ProbeAborted:
                with self._lock:
                    self.stats["aborted"] = True
                return None

        workers = max(1, min(int(self.profile.crawl_concurrency),
                             int(self.profile.concurrency)))
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="recon-crawl") as ex:
            results = list(ex.map(one, urls))
        if self.state:
            self.state.mark_processed("discover", [url_key(u) for u in urls], persist=False)
        return results

    # ------------------------------------------------------------------
    def _scan_paths(self, assets: Iterable[Asset]) -> list[DiscoveredUrl]:
        if not self.profile.path_scan_enabled:
            return []
        paths = load_path_dict(self.recon, int(self.profile.path_scan_max_paths))
        if not paths:
            return []
        bases: list[tuple[str, str]] = []
        for a in assets:
            if a.url and a.status and a.status < 400:
                base = a.url.rstrip("/")
                item = (base, primary_product(a))
                if item not in bases:
                    bases.append(item)

        out: list[DiscoveredUrl] = []
        for base, product in bases:
            # 软 404 基线：3 条随机路径取样；状态取众数，长度取中位数
            samples: list[tuple[int, int]] = []
            stamp = int(time.time() * 1000)
            for i in range(3):
                baseline_url = f"{base}/__auto_hole_probe_{stamp}_{i}"
                base_res = self.prober.request(baseline_url, normalize_url(base)[0],
                                               stage="discover")
                if base_res is None:
                    continue
                samples.append((int(base_res["status"]), len(base_res["body"])))
            if not samples:
                continue
            counts = Counter(s for s, _ in samples)
            b_status = counts.most_common(1)[0][0]
            lens = [n for s, n in samples if s == b_status] or [n for _, n in samples]
            b_len = int(statistics.median(lens))

            for path in paths:
                url = base + path
                try:
                    res = self.prober.request(url, normalize_url(url)[0], stage="discover")
                except ProbeAborted:
                    self.stats["aborted"] = True
                    return out
                if res is None:
                    continue
                self.stats["paths_tested"] += 1
                status, length = res["status"], len(res["body"])
                interesting = False
                if status in (200, 201) and (status != b_status or length > b_len * 1.15):
                    interesting = True
                elif status in (401, 403, 500) and status != b_status:
                    interesting = True
                out.append(DiscoveredUrl(
                    url=url, host=normalize_url(url)[0], source="path_scan",
                    depth=1, status=status, length=length,
                    params=params_of(url), interesting=interesting, product=product,
                ))
        return out


def write_discovered(path: Path, items: Iterable[DiscoveredUrl]) -> int:
    import json
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    n = 0
    with tmp.open("w", encoding="utf-8") as f:
        for it in items:
            f.write(json.dumps(it.to_dict(), ensure_ascii=False) + "\n")
            n += 1
    tmp.replace(path)
    return n


def read_discovered(path: Path) -> list[DiscoveredUrl]:
    import json
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            out.append(DiscoveredUrl.from_dict(json.loads(line)))
        except (json.JSONDecodeError, TypeError):
            continue
    return out
