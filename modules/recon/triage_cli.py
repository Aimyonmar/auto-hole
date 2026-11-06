# -*- coding: utf-8 -*-
"""triage 子命令：只做侦察/研判，零 nuclei/模板扫描。"""
from __future__ import annotations

from typing import Callable

from core.config import AppConfig
from core.constitution import TargetDef

from .config import ReconConfigError, load_recon_config
from .triage import TriageError, run_triage


def main(app: AppConfig, target: TargetDef, *, profile: str = "light",
         max_requests: int = 0, fresh: bool = False,
         recon_config: str | None = None,
         console: Callable[[str], None] = print) -> int:
    try:
        recon = load_recon_config(recon_config, profile)
    except (ReconConfigError, ValueError) as e:
        console(f"[!] recon 配置错误：{e}")
        return 2
    console(f"[*] 目标体检：{target.name}（只做侦察与研判，零扫描请求）")
    try:
        result = run_triage(app, target, recon, profile_override=profile,
                            max_requests=max_requests, fresh=fresh, console=console)
    except TriageError as e:
        console(f"[!] 体检拒绝：{e}")
        return 2
    except Exception as e:
        console(f"[!] 体检失败：{e}")
        return 1
    report = result.report
    basics = report.get("basics") or {}
    conclusion = report.get("conclusion") or {}
    console("")
    console(f"[✓] 体检完成（{report.get('elapsed_s')}s）")
    console(f"    存活主机 {basics.get('alive_hosts', 0)}；端口 "
            f"{', '.join(str(x) for x in (basics.get('ports') or [])) or '-'}")
    console(f"    技术栈 {len(report.get('tech') or [])} 项；"
            f"暴露面 {len(report.get('exposures') or [])} 条；"
            f"风险方向 {len(report.get('risks') or [])} 条（推断）")
    console(f"    体检请求 {basics.get('request_budget', {}).get('used', 0)} / "
            f"{basics.get('request_budget', {}).get('limit', 0)}")
    console(f"    结论：{conclusion.get('verdict')}（评分 {conclusion.get('score')}）"
            f"：{conclusion.get('reason')}")
    console(f"    报告：{result.paths.get('md')}")
    console(f"    机读：{result.paths.get('json')}")
    for w in result.warnings:
        console(f"[!] {w}")
    return 0
