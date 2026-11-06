# -*- coding: utf-8 -*-
"""数据源：外部资产清单导入（测绘平台导出 → 本地 txt）。

用途：
- 通用1.0 需要“同产品公网实例 ≥100”，而免费 Hunter 只有游客模式（10 条/首页）；
- 用户可以把自己在 FOFA / Quake / 鹰图 导出的资产清单放进 workspace/import/<目标名>.txt；
- 本工具只读取文件、不联网，随后统一做存活探测与指纹，计入产品盘点。

文件格式（每行一条，容忍常见导出格式）：
    a.example.com
    a.example.com:8080
    http://a.example.com:8443/path
    192.168.1.10,443,https://192.168.1.10,标题...     # CSV：自动识别 IP/端口/URL
    # 注释行忽略

安全说明：导入的 host 仍要过授权范围校验；仅在“产品型目标（hunter_query）”下，
导入清单被视为用户显式声明的范围（其余情况只接受 domains/ips 内资产）。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterator, Optional

from ..schema import Asset, normalize_host, normalize_url
from . import register
from .base import Source, SourceContext

_SPLIT = re.compile(r"[,;\t|]+")
_IPV4 = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")


def safe_name(name: str) -> str:
    keep = [c for c in str(name) if c.isalnum() or c in "-_."]
    return "".join(keep)[:64] or "target"


def import_path(ctx: SourceContext) -> Path:
    return ctx.recon.abs_path(ctx.recon.sources.import_dir) / f"{safe_name(ctx.target.name)}.txt"


def parse_line(line: str) -> Optional[Asset]:
    """解析一行导入记录 → Asset；无法解析返回 None。"""
    raw = (line or "").strip().lstrip("\ufeff")
    if not raw or raw.startswith("#"):
        return None

    # 直接是 URL
    if raw.lower().startswith(("http://", "https://")):
        host, port, scheme, url = normalize_url(raw)
        if not host:
            return None
        return Asset(host=host, port=port, url=url, scheme=scheme, sources=["import"],
                     meta={"import": raw[:120]})

    # CSV / 空白分隔：取第一个像 host 的字段，再找端口/URL
    fields = [f.strip() for f in _SPLIT.split(raw) if f.strip()]
    fields += [f.strip() for f in raw.split() if f.strip() and f.strip() not in fields]
    host_field, port = "", 0
    url = ""
    for f in fields:
        if not url and f.lower().startswith(("http://", "https://")):
            url = f
            continue
        if not host_field:
            h = f
            if "://" in h:
                h = h.split("://", 1)[1]
            h = h.split("/")[0]
            if _IPV4.match(h.split(":")[0]) or ("." in h):
                if h.count(":") == 1:
                    host_field, _, p = h.partition(":")
                    port = int(p) if p.isdigit() else 0
                else:
                    host_field = h
                continue
        if not port and f.isdigit() and 0 < int(f) < 65536:
            port = int(f)

    if not host_field and url:
        host_field, port, _, _ = normalize_url(url)
    host = normalize_host(host_field)
    if not host or len(host) > 255:
        return None
    return Asset(host=host, port=port, url=url, sources=["import"],
                 meta={"import": raw[:120]})


@register
class ImportListSource(Source):
    name = "import"
    kind = "declared"
    requires = ()

    def available(self, ctx: SourceContext) -> tuple[bool, str]:
        p = import_path(ctx)
        if not p.exists():
            return False, f"未找到导入文件 {p}"
        return True, ""

    def fetch(self, ctx: SourceContext) -> Iterator[Asset]:
        p = import_path(ctx)
        seen: set[str] = set()
        count = 0
        for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
            a = parse_line(line)
            if a is None:
                continue
            if a.key in seen:
                continue
            seen.add(a.key)
            count += 1
            yield a
        ctx.log(f"    import 导入 {count} 条（{p.name}）")
        ctx.audit.write("source_result", source=self.name, count=count, file=p.name)
