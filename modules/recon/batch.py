# -*- coding: utf-8 -*-
"""批量编排：授权目标清单 → 优先级调度 → 全局/单目标双层配额 → 失败隔离 → 断点续跑。

清单（batch.yaml）：
    targets:
      - file: targets/a.yaml        # 必须是带 authorization 的目标文件
        priority: 1
        daily_limit: 3000           # 该目标的日请求上限（可选）
      - file: targets/b.yaml
        priority: 2

约束：
- 清单内目标才会执行；`load_target` 仍会强制校验 authorization；
- 全局日预算为所有目标账本之和，超限不再调度新目标；
- 单目标异常只记录、不影响后续目标；连续失败达到阈值的标记熔断；
- 默认串行（max_parallel=1），并行时按“全局 rps / 并行数”缩放单目标速率。
"""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from pathlib import Path
from typing import Callable, Optional

import yaml

from core.config import AppConfig
from core.constitution import TargetDef, load_target

from .config import ReconConfig
from .runner import run as run_target

DEFAULT_BATCH_STATE = "batch-state.json"
MAX_FAILURES_PER_TARGET = 2


def load_manifest(path: str | Path) -> list[dict]:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"批量清单不存在: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    items = raw.get("targets") if isinstance(raw, dict) else None
    if not items:
        raise ValueError("批量清单缺少 targets")
    out = []
    for i, item in enumerate(items):
        if not isinstance(item, dict) or not (item.get("file") or item.get("target")):
            raise ValueError(f"第 {i + 1} 项缺少 file 或 target")
        out.append({
            "file": str(item.get("file") or ""),
            "target": str(item.get("target") or ""),
            "priority": int(item.get("priority", i)),
            "daily_limit": int(item.get("daily_limit") or 0),
            "scan": bool(item.get("scan", True)),
            "fresh": bool(item.get("fresh", False)),
            "note": str(item.get("note") or ""),
        })
    return sorted(out, key=lambda x: (x["priority"], x["file"] or x["target"]))


class BatchState:
    def __init__(self, path: Path, fresh: bool = False):
        self.path = path
        self.data = {"started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
                     "completed": [], "failed": {}, "skipped": []}
        if path.exists() and not fresh:
            try:
                self.data.update(json.loads(path.read_text(encoding="utf-8")))
            except json.JSONDecodeError:
                pass
        if fresh:
            self.save()

    def completed(self, name: str) -> bool:
        return name in self.data.get("completed", [])

    def mark_done(self, name: str, info: dict) -> None:
        if name not in self.data["completed"]:
            self.data["completed"].append(name)
        self.data.setdefault("results", {})[name] = info
        self.save()

    def mark_failed(self, name: str, error: str) -> None:
        fails = self.data.setdefault("failed", {})
        fails[name] = int(fails.get(name, 0)) + 1
        self.data.setdefault("errors", {})[name] = str(error)[:300]
        self.save()

    def failures(self, name: str) -> int:
        return int(self.data.get("failed", {}).get(name, 0))

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(self.path)


def _db_usage(app: AppConfig) -> int:
    """全局已用请求 = recon_budget + legacy request_counter（当日）。"""
    import sqlite3
    day = time.strftime("%Y-%m-%d")
    if not app.db_path.exists():
        return 0
    total = 0
    try:
        conn = sqlite3.connect(str(app.db_path))
        for table, cond in (("recon_budget", "day=?"), ("request_counter", "day=?")):
            try:
                row = conn.execute(
                    f"SELECT COALESCE(SUM(count),0) FROM {table} WHERE {cond}", (day,)).fetchone()
                total += int(row[0] or 0)
            except sqlite3.OperationalError:
                continue
        conn.close()
    except sqlite3.Error:
        return total
    return total


def _effective_recon(recon: ReconConfig, *, profile: str | None, daily_limit: int,
                     parallel: int, scan: bool = True) -> ReconConfig:
    cfg = recon
    if profile:
        cfg = replace(cfg, profile=profile)
    if daily_limit > 0:
        cfg = replace(cfg, limits=replace(cfg.limits, daily_request_limit=daily_limit))
    if parallel > 1:
        profiles = {k: replace(v, requests_per_second=max(1.0, v.requests_per_second / parallel))
                    for k, v in cfg.profiles.items()}
        cfg = replace(cfg, profiles=profiles)
    if scan:
        # 批量任务默认要出结果：仅在本批次内打开扫描，不改动全局默认档位
        profiles = dict(cfg.profiles)
        active = cfg.profile
        if active in profiles:
            profiles[active] = replace(profiles[active], scan_enabled=True)
        cfg = replace(cfg, profiles=profiles)
    return cfg


def run_batch(app: AppConfig, manifest_path: str | Path, recon: ReconConfig, *,
              profile: str | None = None, max_parallel: int = 1,
              global_daily_limit: int = 0, fresh: bool = False,
              console: Callable[[str], None] = print) -> dict:
    entries = load_manifest(manifest_path)
    parallel = max(1, min(int(max_parallel), 3))
    state = BatchState(recon.state_dir() / DEFAULT_BATCH_STATE, fresh=fresh)
    started = time.monotonic()
    results = []

    def run_one(entry: dict) -> dict:
        from .ledger import preflight, resolve_identifier
        ident = entry.get("file") or entry.get("target")
        tpath, intake_obj, err = resolve_identifier(ident, recon, console)
        if err or not tpath:
            raise RuntimeError(err or "目标无法解析")
        if intake_obj is not None:
            if not preflight(intake_obj, recon, yes=True, console=console):
                raise RuntimeError("预检未通过")
        target: TargetDef = load_target(tpath)   # 宪法第1条：授权校验
        if state.completed(target.name):
            return {"name": target.name, "skipped": "已完成（断点续跑）"}
        if state.failures(target.name) >= MAX_FAILURES_PER_TARGET:
            return {"name": target.name, "skipped": "连续失败已熔断"}
        if global_daily_limit > 0 and _db_usage(app) >= global_daily_limit:
            return {"name": target.name, "skipped": "全局日配额已用尽"}

        cfg = _effective_recon(recon, profile=profile,
                               daily_limit=entry["daily_limit"], parallel=parallel,
                               scan=bool(entry.get("scan", True)))
        if profile is None and intake_obj is not None and intake_obj.tier:
            cfg = _effective_recon(recon, profile=intake_obj.tier,
                                   daily_limit=entry["daily_limit"], parallel=parallel,
                                   scan=bool(entry.get("scan", True)))
        app_eff = app
        if entry["daily_limit"] > 0:
            app_eff = replace(app, scan=replace(app.scan,
                                                daily_request_limit=entry["daily_limit"]))
        console(f"[*] 目标 {target.name}（优先级 {entry['priority']}）")
        res = run_target(app_eff, target, cfg, stage="all",
                         fresh=bool(entry.get("fresh", False)), console=console)
        return {
            "name": target.name,
            "status": getattr(res, "status", "done"),
            "hits": len(res.findings),
            "assets": len(res.assets),
            "requests": int((res.summary.get("probe") or {}).get("requests", 0)),
            "elapsed_s": res.elapsed_s,
            "metrics": res.paths.get("metrics", ""),
        }

    if parallel == 1:
        for entry in entries:
            name = Path(entry["file"]).stem if entry.get("file") else str(entry.get("target"))
            try:
                r = run_one(entry)
            except Exception as e:
                state.mark_failed(name, str(e))
                console(f"[!] 目标 {name} 失败（已隔离）：{e}")
                results.append({"name": name, "error": str(e)})
                continue
            if r.get("skipped"):
                state.data.setdefault("skipped", []).append({"name": r["name"], "reason": r["skipped"]})
                state.save()
                console(f"    [skip] {r['skipped']}")
            else:
                state.mark_done(r["name"], r)
            results.append(r)
    else:
        with ThreadPoolExecutor(max_workers=parallel, thread_name_prefix="batch") as ex:
            futs = {ex.submit(run_one, e): e for e in entries}
            for fut in as_completed(futs):
                entry = futs[fut]
                name = Path(entry["file"]).stem if entry.get("file") else str(entry.get("target"))
                try:
                    r = fut.result()
                except Exception as e:
                    state.mark_failed(name, str(e))
                    console(f"[!] 目标 {name} 失败（已隔离）：{e}")
                    results.append({"name": name, "error": str(e)})
                    continue
                if r.get("skipped"):
                    state.data.setdefault("skipped", []).append(
                        {"name": r["name"], "reason": r["skipped"]})
                    state.save()
                else:
                    state.mark_done(r["name"], r)
                results.append(r)

    summary = {
        "schema": "recon.batch/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "manifest": str(manifest_path),
        "max_parallel": parallel,
        "global_daily_limit": global_daily_limit,
        "global_used": _db_usage(app),
        "targets_total": len(entries),
        "results": results,
        "elapsed_s": round(time.monotonic() - started, 2),
    }
    out = recon.state_dir() / "batch-summary.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    (recon.state_dir() / "batch-report.md").write_text(_render(summary), encoding="utf-8")
    console(f"[✓] 批量完成：{sum(1 for r in results if 'hits' in r)} 成功 / "
            f"{sum(1 for r in results if 'error' in r)} 失败 / "
            f"{sum(1 for r in results if 'skipped' in r)} 跳过")
    console(f"    汇总：{out}")
    return summary


def _render(summary: dict) -> str:
    lines = ["# 批量运行汇总", "",
             f"- 生成时间：{summary['generated_at']}",
             f"- 目标数：{summary['targets_total']}；并行度：{summary['max_parallel']}",
             f"- 全局日配额：{summary['global_daily_limit'] or '未设置'}；"
             f"已用：{summary['global_used']}",
             f"- 总耗时：{summary['elapsed_s']}s", "",
             "| 目标 | 资产 | 命中 | 探测请求 | 耗时 | 状态 |",
             "|---|---|---|---|---|---|"]
    for r in summary["results"]:
        status = ("WAF 中止" if r.get("status") == "waf_stop" else
                  "成功" if "hits" in r else ("跳过：" + r.get("skipped", "") if "skipped" in r
                                             else "失败：" + r.get("error", "")))
        lines.append(f"| {r.get('name')} | {r.get('assets', '-')} | {r.get('hits', '-')} | "
                     f"{r.get('requests', '-')} | {r.get('elapsed_s', '-')} | {status} |")
    lines += ["", "> 仅执行清单内、带授权依据的目标；失败目标已隔离，未影响后续调度。"]
    return "\n".join(lines) + "\n"
