# -*- coding: utf-8 -*-
"""数据源插件基类与上下文。

插件约定（借鉴 subfinder 的 Source 接口 + amass 的 data source 抽象）：
- 一个数据源 = 一个类，声明 name/kind/requires
- available() 先做可用性判断（缺二进制、缺 key 时明确降级而不是抛异常）
- fetch() 只产出 Asset，不做范围校验、不做限速（统一由 runner/prober 处理）
- 失败必须抛异常，由 runner 记录为“该源失败”，不影响其它源
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Iterator, Optional

from core.config import AppConfig
from core.constitution import TargetDef

from ..audit import AuditLog
from ..config import Profile, ReconConfig
from ..ratelimit import AdaptiveLimiter
from ..schema import Asset
from ..state import RunState


class _NullAudit:
    """无审计对象时的空实现（便于单测/离线调用）。"""
    degraded = False

    def write(self, *args, **kwargs) -> None:
        return

    def count(self) -> int:
        return 0


@dataclass
class SourceContext:
    app: AppConfig
    recon: ReconConfig
    target: TargetDef
    profile: Profile
    limiter: AdaptiveLimiter
    audit: AuditLog
    state: Optional[RunState] = None
    console: Callable[[str], None] = print

    def __post_init__(self) -> None:
        if self.audit is None:
            self.audit = _NullAudit()

    def log(self, msg: str) -> None:
        self.console(msg)


class Source:
    """数据源基类。子类必须声明 name 并实现 fetch()。"""

    name: str = ""
    kind: str = "passive"          # passive（查库/查公开数据）| active（主动解析/请求）
    requires: tuple = ()           # ("binary:subfinder", "api:hunter", ...)

    def available(self, ctx: SourceContext) -> tuple[bool, str]:
        """返回 (是否可用, 原因)。缺依赖时返回 False 而非抛异常（可降级）。"""
        return True, ""

    def fetch(self, ctx: SourceContext) -> Iterator[Asset]:
        raise NotImplementedError

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return f"<Source {self.name} kind={self.kind}>"
