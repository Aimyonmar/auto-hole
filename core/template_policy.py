# -*- coding: utf-8 -*-
"""nuclei 模板子集选择。

约束：
- 已识别产品：只允许跑指纹标签筛出的具体模板文件，禁止回退全量目录；
- 未识别产品：只允许跑显式白名单目录（config.paths.nuclei_templates_base）；
- intrusive / dos / fuzz 永远通过 -exclude-tags 排除，不依赖物理删除。

实现说明：直接读取本地 YAML 的 tags/severity 建立索引（只扫描 http/），
不启动 nuclei -tl 子进程，避免打包环境下遍历全量模板时超时。
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, Optional

from .config import AppConfig


class TemplatePolicyError(RuntimeError):
    """模板策略不满足时拒绝扫描（不允许静默回退全量）。"""


MANDATORY_EXCLUDES = ("intrusive", "dos", "fuzz")
TAG_RE = re.compile(r"^\s*tags:\s*(.+)$", re.M)
SEVERITY_RE = re.compile(r"^\s*severity:\s*(.+)$", re.M)
_INDEX_CACHE: dict[Path, list[tuple[Path, set[str], set[str]]]] = {}


def effective_excludes(cfg: AppConfig, extra: Optional[Iterable[str]] = None) -> list[str]:
    """命令行强制排除项：配置排除 + 代码级强制项。"""
    values = {str(x).strip().lower() for x in (cfg.scan.tags_exclude or []) if str(x).strip()}
    values.update(MANDATORY_EXCLUDES)
    values.update(str(x).strip().lower() for x in (extra or []) if str(x).strip())
    return sorted(values)


def base_templates(cfg: AppConfig) -> list[Path]:
    """未识别产品时的显式白名单目录；为空/缺失直接报错。"""
    root = cfg.nuclei_templates_base_dir
    if not root.exists():
        raise TemplatePolicyError(
            f"未识别产品且基准模板目录不存在：{root}；"
            f"请配置 paths.nuclei_templates_base 或补入白名单模板")
    files = sorted(p for p in root.rglob("*")
                   if p.is_file() and p.suffix.lower() in (".yaml", ".yml"))
    if not files:
        raise TemplatePolicyError(f"基准模板目录为空：{root}；拒绝回退全量模板")
    return files


def _split_values(raw: str) -> set[str]:
    s = raw.strip().strip("[]").strip()
    return {x.strip().strip("'\"").lower()
            for x in re.split(r"[,;]", s) if x.strip()}


def _load_index(root: Path) -> list[tuple[Path, set[str], set[str]]]:
    cache_key = root.resolve()
    if cache_key in _INDEX_CACHE:
        return _INDEX_CACHE[cache_key]
    out: list[tuple[Path, set[str], set[str]]] = []
    for p in root.rglob("*"):
        if p.suffix.lower() not in (".yaml", ".yml"):
            continue
        try:
            rel = p.relative_to(root).as_posix()
        except OSError:
            continue
        if not rel.startswith("http/"):
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        tm = TAG_RE.search(text)
        sm = SEVERITY_RE.search(text)
        tags = _split_values(tm.group(1)) if tm else set()
        sev = _split_values(sm.group(1)) if sm else set()
        out.append((p, tags, sev))
    _INDEX_CACHE[cache_key] = out
    return out


def select_templates(cfg: AppConfig, tags: Iterable[str], *,
                     severity: Optional[str] = None,
                     exclude_tags: Optional[Iterable[str]] = None) -> list[Path]:
    """按标签/严重度从本地模板库筛出具体模板文件（不启动 nuclei）。"""
    wanted = {str(t).strip().lower() for t in tags if str(t).strip()}
    if not wanted:
        return []
    root = cfg.nuclei_templates_dir
    if not root.exists():
        raise TemplatePolicyError(f"nuclei 模板目录不存在：{root}")
    excludes = set(effective_excludes(cfg, exclude_tags))
    severity_set = _split_values(severity) if severity else set()
    files = [
        p for p, tpl_tags, tpl_sev in _load_index(root)
        if (tpl_tags & wanted)
        and not (tpl_tags & excludes)
        and (not severity_set or tpl_sev & severity_set)
    ]
    if not files:
        raise TemplatePolicyError(
            f"指纹标签 {sorted(wanted)} 未匹配到模板；"
            f"拒绝回退全量模板，请检查标签映射或调整 scan_tags_include")
    return sorted(files)
