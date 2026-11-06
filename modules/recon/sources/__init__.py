# -*- coding: utf-8 -*-
"""数据源注册表 + 插件自动发现。

自动发现规则：
1. 本包内的所有 *.py 模块（除 base/__init__）在 load_plugins() 时导入，
   模块内用 @register 装饰的类自动注册
2. 额外插件目录（config.recon.sources.plugins_dir）中的 *.py 同样导入，
   便于在不改本仓库代码的情况下追加数据源

新增一个数据源的完整步骤：
    # modules/recon/sources/xxx.py
    from .base import Source, SourceContext
    from . import register

    @register
    class XxxSource(Source):
        name = "xxx"
        kind = "passive"
        def fetch(self, ctx): yield Asset(host="a.com", sources=["xxx"])
"""
from __future__ import annotations

import importlib
import importlib.util
import pkgutil
import sys
from pathlib import Path
from typing import Iterable, Type

from .base import Source, SourceContext  # noqa: F401  (对外导出)

_REGISTRY: dict[str, Type[Source]] = {}
_LOADED = False


def register(cls: Type[Source]) -> Type[Source]:
    """类装饰器：注册数据源。"""
    if not getattr(cls, "name", ""):
        raise ValueError(f"{cls.__name__} 必须声明 name")
    _REGISTRY[cls.name] = cls
    return cls


# 静态导入内置源：PyInstaller 只跟踪静态 import，动态 import_module 冻结后会丢模块。
from . import seed, subfinder, hunter, import_list  # noqa: E402,F401


def registry() -> dict[str, Type[Source]]:
    load_plugins()
    return dict(_REGISTRY)


def get(name: str) -> Type[Source]:
    load_plugins()
    if name not in _REGISTRY:
        raise KeyError(f"未注册的数据源: {name}（已注册 {sorted(_REGISTRY)}）")
    return _REGISTRY[name]


def available_names() -> list[str]:
    load_plugins()
    return sorted(_REGISTRY)


def load_plugins(extra_dir: str | Path | None = None) -> None:
    """导入内置数据源模块 + 可选外部插件目录。幂等。"""
    global _LOADED
    if not _LOADED:
        pkg = __name__
        # 显式导入内置源：PyInstaller 冻结后 pkgutil 可能看不到模块
        for name in ("seed", "subfinder", "hunter", "import_list"):
            try:
                importlib.import_module(f"{pkg}.{name}")
            except Exception as e:  # pragma: no cover
                print(f"[!] 数据源模块 {name} 加载失败: {e}")
        for info in pkgutil.iter_modules(__path__):
            if info.name.startswith("_") or info.name in ("base",) or \
                    info.name in ("seed", "subfinder", "hunter", "import_list"):
                continue
            try:
                importlib.import_module(f"{pkg}.{info.name}")
            except Exception as e:  # pragma: no cover - 插件自身导入失败不应阻断全局
                print(f"[!] 数据源模块 {info.name} 加载失败: {e}")
        _LOADED = True

    if extra_dir:
        _load_external_dir(Path(extra_dir))


def _load_external_dir(directory: Path) -> None:
    if not directory.is_dir():
        return
    for py in sorted(directory.glob("*.py")):
        if py.name.startswith("_"):
            continue
        mod_name = f"autohole_recon_plugin_{py.stem}"
        if mod_name in sys.modules:
            continue
        try:
            spec = importlib.util.spec_from_file_location(mod_name, py)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)
        except Exception as e:  # pragma: no cover
            print(f"[!] 外部插件 {py.name} 加载失败: {e}")


def build_sources(enabled: Iterable[str], ctx: SourceContext,
                  extra_dir: str | Path | None = None) -> tuple[list[Source], list[dict]]:
    """按配置实例化数据源；返回 (可用源列表, 跳过说明列表)。"""
    load_plugins(extra_dir)
    usable: list[Source] = []
    skipped: list[dict] = []
    for name in enabled:
        cls = _REGISTRY.get(str(name))
        if cls is None:
            skipped.append({"name": str(name), "reason": "未注册"})
            continue
        src = cls()
        ok, reason = src.available(ctx)
        if not ok:
            skipped.append({"name": src.name, "reason": reason})
            continue
        usable.append(src)
    return usable, skipped
