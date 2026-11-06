# -*- coding: utf-8 -*-
"""nuclei 扫描编排（宪法第2/3条硬校验落地）。

- 第2条：禁用 dos/fuzz 标签；strict_readonly 模式下过滤文件写入类模板
- 第3条：并发 ≤20、rate-limit、单目标日请求熔断
- 结果：nuclei -jsonl 输出 → findings 入库（含 curl 复现命令）
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Optional

from .config import AppConfig
from .constitution import RateLimiter, TargetDef
from .db import DB
from .subdomain import isolated_env
from .template_policy import (TemplatePolicyError, base_templates,
                              effective_excludes, select_templates)

# strict_readonly 模式下按模板名过滤的写入类关键词（宪法第2条）
WRITE_POC_KEYWORDS = ["upload", "webshell", "write-file", "file-write", "create-file"]


def build_nuclei_cmd(cfg: AppConfig, urls_file: Path, out_file: Path,
                     template_files: list[Path], *,
                     tags_include: Optional[list[str]] = None,
                     tags_exclude: Optional[list[str]] = None,
                     user_agent: str = "") -> list[str]:
    """构造 nuclei 命令：只接受具体模板文件，禁止回退全量目录。"""
    if not template_files:
        raise TemplatePolicyError("模板文件列表为空，拒绝启动 nuclei")
    exe = cfg.tool_path("nuclei")
    cmd = [
        str(exe),
        "-l", str(urls_file),
    ]
    for tpl in template_files:
        cmd += ["-t", str(tpl)]
    cmd += [
        "-severity", cfg.scan.severity,
        "-rate-limit", str(cfg.scan.concurrency),        # 宪法第3条
        "-bulk-size", "25", "-concurrency", str(cfg.scan.concurrency),
        "-timeout", "8", "-retries", "1",
        "-jsonl", "-o", str(out_file),
        "-disable-update-check",                          # 不联网检查更新（隔离）
        "-no-interactsh",                                 # 禁用 OAST 外连（降低噪音）
        "-stats", "-silent",
    ]
    if tags_include:
        cmd += ["-tags", ",".join(sorted(set(tags_include)))]
    if tags_exclude:
        cmd += ["-exclude-tags", ",".join(sorted(set(tags_exclude)))]
    if user_agent:
        cmd += ["-header", f"User-Agent: {user_agent}"]
    return cmd


def _is_write_poc(template_id: str, name: str) -> bool:
    """strict_readonly 取证模式下识别写入类 POC（宪法第2条）。"""
    blob = f"{template_id} {name}".lower()
    return any(k in blob for k in WRITE_POC_KEYWORDS)


def scan_urls(cfg: AppConfig, target: TargetDef, urls: list[str],
              db: DB, limiter: RateLimiter, console=print,
              target_tags: Optional[list[str]] = None,
              template_files: Optional[list[Path]] = None,
              user_agent: str = "",
              label: str = "") -> int:
    """对 URL 列表执行 nuclei 扫描，命中结果入库。返回新增 finding 数。

    target_tags：指纹标签；用于从全量模板库筛出具体模板文件。
    template_files：已筛选好的模板文件（测试/上层复用）；与 target_tags 二选一。
    user_agent：nuclei -header 注入的 UA；默认由上层传入探测 UA。
    label：批次标签，用于生成不冲突的中间文件名（多产品分组扫描时使用）。
    """
    if not urls:
        console("[*] 无待扫描 URL")
        return 0
    ws = cfg.workspace_dir
    ws.mkdir(parents=True, exist_ok=True)
    suffix = f"_{label}" if label else ""
    urls_file = ws / f"{target.name}_urls{suffix}.txt"
    out_file = ws / (f"{target.name}_nuclei{suffix}_"
                     f"{__import__('time').strftime('%Y%m%d_%H%M%S')}.jsonl")
    urls_file.write_text("\n".join(urls), encoding="utf-8")

    mode = "targeted" if (target_tags or template_files) else "base"
    excludes = effective_excludes(cfg)
    if not cfg.scan.weak_password:
        excludes.append("default-login")
    include = sorted(set(cfg.scan.tags_include or []) | set(target_tags or []))
    try:
        files = list(template_files or [])
        if not files:
            if target_tags:
                files = select_templates(cfg, target_tags,
                                         severity=cfg.scan.severity,
                                         exclude_tags=excludes)
            else:
                files = base_templates(cfg)
    except TemplatePolicyError as e:
        console(f"[!] 模板策略拒绝扫描：{e}")
        raise
    if not files:
        raise TemplatePolicyError("模板文件列表为空，拒绝回退全量模板")

    # 宪法第3条：登记预计请求量（保守按 URL×15 估算，触熔断则截断）
    try:
        limiter.acquire(min(len(urls) * 15, cfg.scan.daily_request_limit))
    except Exception as e:
        console(f"[!] {e}")
        return 0

    console(f"[*] 模板策略：{mode}，{len(files)} 个模板；"
            f"标签 {','.join(include) or '-'}；排除 {','.join(excludes)}")
    cmd = build_nuclei_cmd(cfg, urls_file, out_file, files,
                           tags_include=include, tags_exclude=excludes,
                           user_agent=user_agent)
    console(f"[*] nuclei 扫描 {len(urls)} 个 URL（并发 {cfg.scan.concurrency}，"
            f"模板 {len(files)}）...")
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=7200,
                           encoding="utf-8", errors="replace", env=isolated_env())
        if r.returncode != 0 and not out_file.exists():
            console(f"[!] nuclei 异常: {r.stderr[:1500]}")
            return 0
    except subprocess.TimeoutExpired:
        console("[!] nuclei 超时（2h），已保留部分结果")

    # 解析 jsonl 结果入库
    count = 0
    if out_file.exists():
        for line in out_file.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            # 注意：nuclei 命中行的 type 常见为 http/dns/ssl/tcp 等，
            # 不能按 type 白名单过滤（否则会丢掉真实命中），只排除 stats/error 类非命中行
            if str(j.get("type") or "").lower() in ("stats", "error", "trace", "progress"):
                continue
            if not (j.get("template-id") or j.get("templateID")):
                continue
            info = j.get("info") or {}
            template_id = j.get("template-id") or j.get("templateID") or ""
            name = info.get("name") or template_id
            severity = info.get("severity") or "unknown"
            host = (j.get("host") or "").lower()
            matched = j.get("matched-at") or j.get("matched") or host

            # 宪法第2条：strict_readonly 模式跳过写入类 POC 命中（不入库不算数）
            if cfg.scan.evidence_mode == "strict_readonly" and _is_write_poc(template_id, name):
                console(f"[宪法第2条] 跳过写入类 POC 命中: {template_id}")
                continue

            # 宪法第5条：去重
            if db.is_duplicate(template_id, host):
                continue

            curl = j.get("curl-command") or j.get("curl") or ""
            db.insert_finding(
                target=target.name, template_id=template_id, name=name,
                severity=severity, host=host, url=j.get("host") or "",
                matched_at=matched, curl_command=curl,
                raw=line, product="")
            count += 1
            console(f"  [+] 命中: [{severity}] {name} @ {matched}")
    return count
