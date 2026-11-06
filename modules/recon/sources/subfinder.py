# -*- coding: utf-8 -*-
"""数据源：subfinder 被动子域枚举 + dnsx 解析存活过滤。

复用 core.subdomain 的既有实现（隔离环境变量、项目内二进制），
只在其结果上补来源标注与存活校验（借鉴 amass 的“枚举 → 解析 → 去重”三段式）。
"""
from __future__ import annotations

from typing import Iterator

from core.subdomain import enumerate_subdomains, resolve_hosts

from ..schema import Asset
from . import register
from .base import Source, SourceContext


@register
class SubfinderSource(Source):
    name = "subfinder"
    kind = "passive"
    requires = ("binary:subfinder",)

    def available(self, ctx: SourceContext) -> tuple[bool, str]:
        if not ctx.target.domains:
            return False, "目标未声明域名，跳过被动枚举"
        exe = ctx.app.tool_path("subfinder")
        if not exe.exists():
            return False, f"缺少项目内二进制 {exe}"
        return True, ""

    def fetch(self, ctx: SourceContext) -> Iterator[Asset]:
        opts = ctx.recon.sources.subfinder or {}
        subs = enumerate_subdomains(list(ctx.target.domains), ctx.app)
        ctx.log(f"    subfinder 原始子域 {len(subs)} 个")
        ctx.audit.write("source_result", source=self.name, count=len(subs))

        if opts.get("resolve", True) and subs:
            exact = resolve_hosts(subs, ctx.app)
            dropped = len(subs) - len(exact)
            ctx.log(f"    dnsx 解析存活 {len(exact)} 个（丢弃不可解析 {dropped} 个）")
            subs = exact

        for host in sorted(subs):
            yield Asset(host=host, port=0, sources=[self.name],
                        meta={"discovered_by": self.name})
