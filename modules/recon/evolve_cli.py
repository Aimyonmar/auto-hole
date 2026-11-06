# -*- coding: utf-8 -*-
"""evolve 子命令：误报标记 / 候选生成与靶场回归 / 人工入库 / 回滚 / 版本列表。"""
from __future__ import annotations

import json
from pathlib import Path

from core.config import AppConfig
from core.constitution import TargetDef

from .adapters import read_assets_jsonl, read_findings_jsonl
from .config import ReconConfig, load_recon_config
from .evolution import (add_feedback, approve, compute_key, list_versions,
                        load_feedback, propose, rollback)


def _target_dir(recon: ReconConfig, target: TargetDef) -> Path:
    return recon.target_state_dir(target.name)


def cmd_mark(recon: ReconConfig, target: TargetDef, args, console=print) -> int:
    tdir = _target_dir(recon, target)
    findings = read_findings_jsonl(tdir / "findings.jsonl")
    matched = [f for f in findings
               if f.template_id == args.template_id and f.host == args.host]
    if not matched:
        console(f"[!] 未找到 {args.template_id} @ {args.host} 的命中记录")
        return 1
    f = matched[0]
    add_feedback(
        tdir, finding_key=f.key, template_id=f.template_id, host=f.host,
        label=args.label, reason=args.reason, product=args.product or f.product,
        marker_type=args.marker_type, marker_name=args.marker_name,
        marker_value=args.marker_value,
    )
    console(f"[✓] 已记录反馈：{f.key}（{args.label}）")
    return 0


def cmd_propose(app: AppConfig, recon: ReconConfig, target: TargetDef,
                args, console=print) -> int:
    tdir = _target_dir(recon, target)
    findings = read_findings_jsonl(tdir / "findings.jsonl")
    assets = read_assets_jsonl(tdir / "assets.jsonl")
    if not findings:
        console("[!] 没有命中记录，无法生成候选（先跑 scan）")
        return 1
    result = propose(app, recon, tdir, findings, assets,
                     positive_url=args.lab_positive,
                     negative_url=args.lab_negative, console=console)
    console(f"[✓] 候选 {result['total']} 条：通过 {result['passed']} / 未通过或阻塞 "
            f"{result['blocked_or_failed']}")
    console(f"    待审清单：{result['dir']}/REVIEW.md")
    console("    说明：候选不会自动入库，需人工核对后用 evolve approve")
    return 0


def cmd_approve(recon: ReconConfig, target: TargetDef, args, console=print) -> int:
    if not args.candidate_dir or not args.candidate_id:
        console("[!] approve 需要 --candidate-dir 与 --candidate-id")
        return 1
    metrics = None
    tdir = _target_dir(recon, target)
    mp = tdir / "metrics.json"
    if mp.exists():
        try:
            metrics = json.loads(mp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            metrics = None
    index = approve(recon, Path(args.candidate_dir), args.candidate_id,
                    note=args.note, metrics=metrics, console=console)
    console(f"    版本记录：{len(index.get('versions', []))} 条")
    return 0


def cmd_rollback(recon: ReconConfig, args, console=print) -> int:
    if args.version <= 0:
        console("[!] rollback 需要 --version N")
        return 1
    rollback(recon, args.version, note=args.note, console=console)
    return 0


def cmd_list(recon: ReconConfig, console=print) -> int:
    index = list_versions(recon)
    versions = index.get("versions", [])
    if not versions:
        console("[i] 还没有规则库版本记录（approve 后生成）")
        return 0
    for v in versions:
        console(f"    v{v.get('version')}: {v.get('action')} "
                f"{v.get('candidate') or ''} {v.get('note') or ''}")
    return 0


def main(app: AppConfig, args, console=print) -> int:
    try:
        recon = load_recon_config(getattr(args, "recon_config", None))
    except Exception as e:
        console(f"[!] recon 配置错误：{e}")
        return 2

    if args.action == "list":
        return cmd_list(recon, console)
    if args.action == "rollback":
        return cmd_rollback(recon, args, console)

    if not args.target:
        console("[!] 该动作需要 -t/--target 目标文件")
        return 1
    from core.constitution import load_target
    target = load_target(args.target)

    if args.action == "mark":
        return cmd_mark(recon, target, args, console)
    if args.action == "propose":
        return cmd_propose(app, recon, target, args, console)
    if args.action == "approve":
        return cmd_approve(recon, target, args, console)
    if args.action == "rollback":
        return cmd_rollback(recon, args, console)
    console(f"[!] 未知动作 {args.action}")
    return 1
