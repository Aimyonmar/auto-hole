# -*- coding: utf-8 -*-
"""数据源：鹰图 Hunter 测绘 API（免费账号自动降级游客模式）。

保持既有约定：无开放 API 权限时降级为网页内部接口（每页 ≤10 条、仅首页），
不试图绕过权限；配额告警沿用 core.hunter 的实现。
"""
from __future__ import annotations

from typing import Iterator

from core.hunter import HunterClient

from ..schema import Asset
from . import register
from .base import Source, SourceContext


@register
class HunterSource(Source):
    name = "hunter"
    kind = "passive"
    requires = ("api:hunter",)

    def available(self, ctx: SourceContext) -> tuple[bool, str]:
        key = (ctx.app.hunter.api_key or "").strip()
        if not key or key.startswith("YOUR_"):
            return False, "未配置 hunter.api_key"
        if not ctx.target.hunter_query and not ctx.target.domains:
            return False, "目标未声明 hunter_query/domains"
        return True, ""

    def fetch(self, ctx: SourceContext) -> Iterator[Asset]:
        client = HunterClient(ctx.app.hunter, logger=ctx.log)
        query = ctx.target.hunter_query or client.build_domain_query(list(ctx.target.domains))
        limit = min(int((ctx.recon.sources.hunter or {}).get("max_records", 1000)),
                    int(ctx.app.hunter.max_records or 1000))
        ctx.log(f"    Hunter 查询: {query[:100]}")
        count = 0
        for a in client.search(query, max_records=limit):
            host = (a.domain or a.ip or "").strip()
            if not host:
                continue
            count += 1
            yield Asset(
                host=host, port=a.port, url=a.url, title=a.title,
                tech=list(a.component or []), sources=[self.name],
                meta={"query": query},
            )
        ctx.audit.write("source_result", source=self.name, count=count, query=query[:200])
