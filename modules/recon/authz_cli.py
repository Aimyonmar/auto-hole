# -*- coding: utf-8 -*-
"""authz 子命令：导入加密账号 → 只读越权检测（GET only）。"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Callable

from core.config import AppConfig
from core.constitution import TargetDef

from .authz_creds import AuthzConfigError, prepare_accounts_from_file
from .config import ReconConfigError, load_recon_config
from .runner import run


def main(app: AppConfig, target: TargetDef, *, accounts: str = "",
         prepare_only: bool = False, max_requests: int = 0,
         similarity_threshold: float = 0.0, fresh: bool = False,
         recon_config: str | None = None,
         console: Callable[[str], None] = print) -> int:
    try:
        recon = load_recon_config(recon_config)
    except (ReconConfigError, ValueError) as e:
        console(f"[!] recon 配置错误：{e}")
        return 2

    overrides: dict = {}
    if max_requests > 0:
        overrides["max_requests"] = int(max_requests)
    if similarity_threshold > 0:
        overrides["similarity_threshold"] = float(similarity_threshold)

    if accounts:
        try:
            meta_path, meta = prepare_accounts_from_file(
                target=target, plain_path=accounts,
                accounts_dir=recon.abs_path(recon.authz.accounts_dir),
                vault_path=recon.abs_path(recon.authz.vault_path),
                key_path=recon.abs_path(recon.authz.key_path),
                settings=overrides,
            )
        except AuthzConfigError as e:
            console(f"[!] 账号导入失败：{e}")
            return 2
        console(f"[✓] 账号已加密保存：{meta_path}")
        console(f"    身份 {len(meta.get('identities') or [])} 个；"
                f"垂直路径 {len((meta.get('vertical') or {}).get('paths') or [])} 条")
        console("[i] 明文账号文件请自行删除；元数据与加密库均不含 secret")
        if prepare_only:
            return 0

    console(f"[*] 只读越权检测：目标 {target.name}（GET only，不实现写方法）")
    try:
        result = run(app, target, recon, stage="authz", fresh=fresh,
                     console=console, authz_overrides=overrides or None)
    except Exception as e:
        console(f"[!] 越权检测失败：{e}")
        return 1

    az = result.summary.get("authz") or {}
    if not az:
        console("[!] 没有执行越权检测（未配置账号或 authz 被禁用）")
        return 1
    console("")
    console(f"[✓] 越权检测完成（{result.elapsed_s}s）")
    console(f"    疑似 {az.get('suspects', 0)} 条"
            f"（水平 {az.get('horizontal_suspects', 0)} / "
            f"垂直 {az.get('vertical_suspects', 0)}）；"
            f"公共页抑制 {az.get('suppressed_public', 0)}；"
            f"正常/负样本 {az.get('normal', 0)}")
    console(f"    候选 {az.get('candidates', 0)}；请求 {az.get('requests', 0)}"
            f"/{az.get('max_requests', 0)}"
            f"{'（预算已用尽即停）' if az.get('budget_exhausted') else ''}")
    asum = (result.paths or {}).get("authz_summary", "")
    areport = (result.paths or {}).get("authz_report", "")
    if asum:
        console(f"    汇总：{asum}")
    if areport:
        console(f"    报告：{areport}")
    for w in result.warnings:
        console(f"[!] {w}")
    return 0
