# -*- coding: utf-8 -*-
"""数据源：目标自身声明的域名/IP（seed）。

作用：
- 保证即便所有外部数据源都不可用，也能对“用户显式声明”的资产做存活探测
- 不做任何网络请求，零成本、零风险
"""
from __future__ import annotations

from typing import Iterator

from ..schema import Asset
from . import register
from .base import Source, SourceContext


@register
class SeedSource(Source):
    name = "seed"
    kind = "declared"
    requires = ()

    def available(self, ctx: SourceContext) -> tuple[bool, str]:
        if not ctx.target.domains and not ctx.target.ips:
            return False, "目标未声明 domains/ips"
        return True, ""

    def fetch(self, ctx: SourceContext) -> Iterator[Asset]:
        for d in ctx.target.domains:
            yield Asset(host=d, port=0, sources=[self.name],
                        meta={"declared": "domain", "authorization": ctx.target.authorization})
        for ip in ctx.target.ips:
            if "/" in ip:
                ctx.log(f"[!] seed: CIDR 段 {ip} 不展开（避免大规模扫描），请显式列出单个 IP")
                continue
            yield Asset(host=ip, port=0, sources=[self.name],
                        meta={"declared": "ip", "authorization": ctx.target.authorization})
