# -*- coding: utf-8 -*-
"""按产品分组的定向扫描计划。

为什么按产品分组：
- nuclei 全模板扫描是“每条 URL × 全部模板”，命中率低、请求量大；
- 已经识别出产品后，只需要跑该产品相关模板（CVE/暴露面），请求量可降一个量级；
- 同一 URL 不同产品几乎不会同时命中，分组后每组只传该产品的模板目录，避免互相污染。

产物是“扫描组”列表，由 runner 逐组调用既有 nuclei 编排（不复制 POC 执行逻辑）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Iterable, Optional

from .fingerprint import FingerprintEngine
from .schema import Asset


@dataclass
class ScanGroup:
    product: str                      # "unidentified" 表示未识别
    urls: list = field(default_factory=list)
    template_dirs: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    hosts: list = field(default_factory=list)

    @property
    def is_identified(self) -> bool:
        return self.product != "unidentified"

    def to_dict(self) -> dict:
        return {"product": self.product, "urls": len(self.urls),
                "template_dirs": list(self.template_dirs),
                "tags": list(self.tags), "hosts": len(self.hosts)}


def primary_product(asset: Asset) -> str:
    """取置信度最高的产品名（products 已按置信度降序）。"""
    for p in asset.products:
        name = p.get("product", "")
        if name:
            return name
    return ""


def group_by_product(assets: Iterable[Asset], engine: Optional[FingerprintEngine],
                     *, include_unidentified: bool = False,
                     processed: Optional[Callable[[str], bool]] = None,
                     max_urls_per_group: int = 500,
                     max_groups: int = 50,
                     require_template_dirs: bool = False) -> list[ScanGroup]:
    """按主产品归组；已处理过的 URL 不重复入组。

    require_template_dirs=True 时（有指纹库的情况下），跳过“已识别但没有模板目录”的产品
    （如纯 Nginx/Apache 页面），避免用全量模板去打价值低的通用组件。
    """
    groups: dict[str, ScanGroup] = {}
    for a in assets:
        if not a.url or not a.status or a.status >= 500:
            continue
        if processed and processed(a.url):
            continue
        product = primary_product(a)
        if not product and not include_unidentified:
            continue
        key = product or "unidentified"
        g = groups.setdefault(key, ScanGroup(product=key))
        if a.url not in g.urls:
            g.urls.append(a.url)
        if a.host not in g.hosts:
            g.hosts.append(a.host)

    for g in groups.values():
        if engine is not None and g.is_identified:
            g.template_dirs = engine.template_dirs_for([g.product])
            g.tags = engine.tags_for([g.product])
        g.urls = g.urls[:max_urls_per_group]

    ordered = sorted(groups.values(), key=lambda x: (-len(x.urls), x.product))
    out = []
    for g in ordered:
        if not g.urls:
            continue
        if require_template_dirs and engine is not None and g.is_identified \
                and not g.template_dirs:
            continue
        out.append(g)
    return out[:max_groups]


def estimate_requests(group: ScanGroup, per_url: int = 15) -> int:
    """沿用 legacy 的保守估算口径（URL × 15），用于组级配额预检。"""
    return len(group.urls) * per_url
