# -*- coding: utf-8 -*-
"""统一结果 schema：资产（Asset）与命中（Finding）的唯一真源。

借鉴点（subfinder / amass / httpx / nuclei 的共同做法）：
- 归一化：所有来源原始字段先归一化到同一套字段，再做任何业务判断
- 来源标注：同一条资产可被多个数据源命中，保留 sources 列表（可审计“从哪里来”）
- 去重 key：host + port（httpx 的 input/host 归一化 + naabu 的 host:port 思路）
- 合并而非覆盖：重复命中时取并集（tech/sources），取更优值（status/title）
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Iterable, Optional

# 常见 Web 端口 → 默认 scheme（httpx 的端口推断逻辑）
HTTPS_PORTS = frozenset({443, 8443, 9443, 4443, 6443})
HTTP_PORTS = frozenset({80, 8000, 8080, 8081, 8888, 9090, 7001, 7002, 9000, 9091})

DEFAULT_PORTS = (80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 7002)

SEVERITIES = ("critical", "high", "medium", "low", "info", "unknown")

_SEVERITY_ALIAS = {
    "严重": "critical", "高危": "high", "中危": "medium", "低危": "low", "信息": "info",
    "CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "INFO": "info",
}


def normalize_severity(raw: str) -> str:
    """把 nuclei 各种写法统一到固定枚举（结果标准化）。"""
    s = (raw or "").strip()
    if not s:
        return "unknown"
    s = _SEVERITY_ALIAS.get(s, _SEVERITY_ALIAS.get(s.upper(), s.lower()))
    return s if s in SEVERITIES else "unknown"


def normalize_host(raw: str) -> str:
    """host 归一化：去 scheme/路径/端口，小写，IPv6 保留原样。

    >>> normalize_host("HTTPS://A.Example.com:8443/x")
    'a.example.com'
    """
    h = (raw or "").strip().lower()
    if not h:
        return ""
    for scheme in ("http://", "https://", "//"):
        if h.startswith(scheme):
            h = h[len(scheme):]
    h = h.split("/")[0].split("?")[0].split("#")[0]
    # IPv6：[::1]:8080 或 ::1
    if h.startswith("["):
        return h[1:h.find("]")] if "]" in h else h[1:]
    if h.count(":") == 1:  # host:port
        h = h.split(":")[0]
    return h


def normalize_port(raw) -> int:
    try:
        p = int(raw)
    except (TypeError, ValueError):
        return 0
    return p if 0 < p < 65536 else 0


def scheme_for_port(port: int) -> str:
    if port in HTTPS_PORTS:
        return "https"
    return "http"


def has_explicit_port(raw: str) -> bool:
    """URL 中是否显式写了端口（host:port）。

    用于区分“端口未知（0，按策略探测常用端口）”与“缺省端口（80/443）”。
    """
    u = (raw or "").strip()
    if "://" not in u:
        return False
    hostport = u.split("://", 1)[1].split("/")[0].split("?")[0].split("#")[0]
    if hostport.startswith("["):
        return "]" in hostport and hostport[hostport.find("]"):].startswith("]:")
    return hostport.count(":") == 1


def normalize_url(raw: str) -> tuple[str, int, str, str]:
    """解析 URL → (host, port, scheme, url)。

    端口缺失时按 scheme 补默认端口（80/443），与 httpx / nuclei 的行为一致。
    """
    u = (raw or "").strip()
    if not u:
        return "", 0, "", ""
    if "://" not in u:
        u = "http://" + u.lstrip("/")
    scheme, rest = u.split("://", 1)
    scheme = scheme.lower()
    if scheme not in ("http", "https"):
        return "", 0, "", ""
    hostport = rest.split("/")[0].split("?")[0].split("#")[0]
    if hostport.startswith("["):  # IPv6
        idx = hostport.find("]")
        host = hostport[1:idx] if idx >= 0 else hostport[1:]
        port = normalize_port(hostport[idx + 2:]) if hostport[idx + 1:idx + 2] == ":" else 0
    elif hostport.count(":") == 1:
        host, _, p = hostport.partition(":")
        port = normalize_port(p)
    else:
        host, port = hostport, 0
    port = port or (443 if scheme == "https" else 80)
    url = build_url(host, port, scheme)
    return normalize_host(host), port, scheme, url


def build_url(host: str, port: int, scheme: str = "") -> str:
    """按 host:port 构造可访问 URL（80/443 省略端口）。"""
    if not host:
        return ""
    scheme = scheme or scheme_for_port(port)
    if port in (0, 80, 443):
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def now_iso() -> str:
    return datetime.now().isoformat(timespec="seconds")


def stable_hash(text: str, length: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:length]


def _union(a: list, b: list) -> list:
    """有序并集（保持首次出现顺序），用于 tech / sources / tags。"""
    out = list(a or [])
    seen = {str(x).lower() for x in out}
    for x in (b or []):
        if str(x).lower() not in seen:
            out.append(x)
            seen.add(str(x).lower())
    return out


# ------------------------------------------------------------------
# 资产记录
# ------------------------------------------------------------------
@dataclass
class Asset:
    """一条归一化资产。

    host/port 是身份，其余字段是可合并的属性。
    """
    host: str
    port: int = 0
    url: str = ""
    scheme: str = ""
    status: int = 0
    title: str = ""
    server: str = ""
    content_type: str = ""
    tech: list = field(default_factory=list)
    products: list = field(default_factory=list)      # [{"product","rule_id","confidence"}]
    sources: list = field(default_factory=list)       # ["subfinder", "hunter", ...]
    tags: list = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    evidence: dict = field(default_factory=dict)      # {"url","status","elapsed_ms","body_sha256","body_len"}
    meta: dict = field(default_factory=dict)          # 来源附加信息（hunter 查询语法等）

    def __post_init__(self) -> None:
        self.host = normalize_host(self.host)
        self.port = normalize_port(self.port)
        if self.url:
            h, p, s, u = normalize_url(self.url)
            if h:
                self.host = self.host or h
                # 只有 URL 显式带端口时才回填 port；否则保留 0（= 端口未知，按策略探测）
                if not self.port and has_explicit_port(self.url):
                    self.port = p
                self.scheme = self.scheme or s
                self.url = u
        if not self.url and self.host:
            self.url = build_url(self.host, self.port, self.scheme)
        if not self.scheme and self.port:
            self.scheme = scheme_for_port(self.port)
        if not self.first_seen:
            self.first_seen = now_iso()
        if not self.last_seen:
            self.last_seen = self.first_seen

    @property
    def key(self) -> str:
        """去重 key：host|port（port=0 表示未知端口）。"""
        return f"{self.host}|{self.port}"

    def product_names(self) -> list[str]:
        return [p.get("product", "") for p in self.products if p.get("product")]

    def merge(self, other: "Asset") -> "Asset":
        """合并同一 key 的另一条记录：并集优先，不做破坏性覆盖。"""
        self.tech = _union(self.tech, other.tech)
        self.sources = _union(self.sources, other.sources)
        self.tags = _union(self.tags, other.tags)
        # 产品指纹：同名取最高置信度
        by_name = {p.get("product"): p for p in self.products}
        for p in other.products:
            name = p.get("product")
            if not name:
                continue
            cur = by_name.get(name)
            if cur is None or float(p.get("confidence", 0)) > float(cur.get("confidence", 0)):
                by_name[name] = p
        self.products = sorted(by_name.values(), key=lambda x: -float(x.get("confidence", 0)))
        # 优质字段优先
        if other.status and (not self.status or other.status < 400 <= self.status):
            self.status = other.status
        if other.title and not self.title:
            self.title = other.title
        if other.server and not self.server:
            self.server = other.server
        if other.content_type and not self.content_type:
            self.content_type = other.content_type
        if other.url and (not self.url or len(other.url) > len(self.url)):
            self.url = other.url
        if other.evidence:
            self.evidence = {**other.evidence, **self.evidence}
        if other.meta:
            self.meta = {**other.meta, **self.meta}
        if other.first_seen and (not self.first_seen or other.first_seen < self.first_seen):
            self.first_seen = other.first_seen
        if other.last_seen and other.last_seen > self.last_seen:
            self.last_seen = other.last_seen
        return self

    def to_dict(self) -> dict:
        d = asdict(self)
        d["schema"] = "recon.asset/v1"
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Asset":
        allowed = {k: d[k] for k in cls.__dataclass_fields__ if k in d}
        return cls(**allowed)

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)


def dedupe(assets: Iterable[Asset]) -> list[Asset]:
    """按 key 合并去重，保持首次出现顺序（稳定输出便于 diff）。"""
    out: dict[str, Asset] = {}
    for a in assets:
        k = a.key
        if k in out:
            out[k].merge(a)
        else:
            out[k] = a
    return list(out.values())


# ------------------------------------------------------------------
# 命中记录
# ------------------------------------------------------------------
_NON_FINDING_TYPES = {"stats", "error", "trace", "progress"}


def is_nuclei_finding(j: dict) -> bool:
    """nuclei JSONL 行是否为有效命中。

    注意：nuclei 的命中行 type 常见为 http/dns/ssl/tcp/websocket 等，
    不能按 type 白名单过滤，只能排除 stats/error 这类非命中行。
    """
    if not isinstance(j, dict):
        return False
    if str(j.get("type") or "").lower() in _NON_FINDING_TYPES:
        return False
    return bool(j.get("template-id") or j.get("templateID"))


@dataclass
class Finding:
    """一条漏洞命中（nuclei 输出归一化后的稳定结构）。"""
    template_id: str
    name: str = ""
    severity: str = "unknown"
    host: str = ""
    matched_at: str = ""
    curl_command: str = ""
    product: str = ""
    source: str = "nuclei"
    tags: list = field(default_factory=list)        # nuclei info.tags，用于价值分类
    product_instances: int = 0                      # 同产品公网实例数（通用1.0 影响力）
    value: dict = field(default_factory=dict)       # 价值评分结果（value.py 产出）
    evidence: dict = field(default_factory=dict)
    created_at: str = ""

    def __post_init__(self) -> None:
        self.severity = normalize_severity(self.severity)
        self.host = normalize_host(self.host or self.matched_at)
        if not self.created_at:
            self.created_at = now_iso()

    @property
    def key(self) -> str:
        """跨目标去重 key：模板 + host + 命中点。"""
        return f"{self.template_id}|{self.host}|{stable_hash(self.matched_at, 8)}"

    def to_dict(self) -> dict:
        d = asdict(self)
        d["schema"] = "recon.finding/v1"
        return d

    @classmethod
    def from_nuclei(cls, j: dict) -> Optional["Finding"]:
        """从 nuclei -jsonl 的一行构造 Finding；非命中行返回 None。"""
        if not is_nuclei_finding(j):
            return None
        info = j.get("info") or {}
        template_id = j.get("template-id") or j.get("templateID") or ""
        matched = j.get("matched-at") or j.get("matched") or j.get("host") or ""
        return cls(
            template_id=str(template_id),
            name=str(info.get("name") or template_id),
            severity=str(info.get("severity") or "unknown"),
            host=str(j.get("host") or matched),
            matched_at=str(matched),
            curl_command=str(j.get("curl-command") or ""),
            tags=[str(t) for t in (info.get("tags") or [])],
            evidence={"matcher": j.get("matcher-name") or "", "type": j.get("type") or "",
                      "extracted": j.get("extracted-results") or [],
                      "request": j.get("request") or "",
                      "response": j.get("response") or ""},
        )


_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def extract_title(html: str, limit: int = 200) -> str:
    """从 HTML 提取标题（单次正则，避免重复解析）。"""
    if not html:
        return ""
    m = _TITLE_RE.search(html)
    if not m:
        return ""
    return re.sub(r"\s+", " ", m.group(1)).strip()[:limit]
