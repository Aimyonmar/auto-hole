# -*- coding: utf-8 -*-
"""recon CLI：挂到 main.py 的 recon 子命令。

用法：
  python main.py recon -t targets/xxx.yaml                    # 默认 standard（collect+probe）
  python main.py recon -t targets/xxx.yaml --profile light    # 首次低并发
  python main.py recon -t targets/xxx.yaml --stage scan       # 单独跑分级扫描
  python main.py recon -t targets/xxx.yaml --fresh            # 丢弃进度重来
  python main.py recon -t targets/xxx.yaml --stage status     # 只看进度/清单
"""
from __future__ import annotations

import json
from pathlib import Path

from core.config import AppConfig
from core.constitution import TargetDef

from .adapters import read_assets_jsonl, read_findings_jsonl
from .config import ReconConfigError, load_recon_config
from .report_export import export_findings
from .runner import run
from .state import RunState


def main(app: AppConfig, target: TargetDef, *, profile: str | None = None,
         stage: str = "all", fresh: bool = False,
         recon_config: str | None = None, config_root: Path | None = None) -> int:
    try:
        recon = load_recon_config(recon_config, profile)
    except (ReconConfigError, ValueError) as e:
        print(f"[!] recon 配置错误：{e}")
        return 2

    prof = recon.active_profile()
    print(f"[*] 目标：{target.name}（授权依据：{target.authorization[:60]}）")
    print(f"[*] 档位：{prof.name}  并发 {prof.concurrency}  速率 {prof.requests_per_second} rps  "
          f"端口 {len(prof.probe_ports)} 个")
    print("[*] 底线：仅对已声明授权目标请求；有界并发/超时/退避/熔断；只读不写入；全程留痕")

    if stage == "status":
        return _status(recon, target)

    try:
        result = run(app, target, recon, stage=stage, fresh=fresh, console=print)
    except Exception as e:
        print(f"[!] 运行失败：{e}")
        return 1

    s = result.summary
    a = s.get("assets", {})
    print("")
    print(f"[✓] 完成（{result.elapsed_s}s）  资产 {a.get('total', 0)} 存活 {a.get('alive', 0)} "
          f"有指纹 {a.get('with_fingerprint', 0)}  命中 {len(result.findings)}")
    if result.probe_stats:
        print(f"    请求 {result.probe_stats.get('requests', 0)} 次，"
              f"实际 {result.probe_stats.get('effective_rps', 0)} rps，"
              f"存活 {result.probe_stats.get('alive', 0)} / 无响应 {result.probe_stats.get('dead', 0)}")
    for p in s.get("products", [])[:10]:
        print(f"    - {p['product']}: {p['hosts']} 台（置信度 {p['max_confidence']:.2f}）")

    fd = s.get("findings") or {}
    if fd:
        print(f"[*] 命中价值：可提交 {fd.get('submit_ready', 0)} 条，"
              f"等级 {fd.get('by_grade', {})}")
        for t in (fd.get("top_value") or [])[:5]:
            print(f"    [{t.get('grade')}{t.get('score')}] {t.get('name')} @ "
                  f"{t.get('matched_at') or '-'}（{t.get('advice')}）")
    if result.evidence_paths:
        print(f"    证据包 {len(result.evidence_paths)} 份 → {result.paths['evidence']}")
    az = s.get("authz") or {}
    if az:
        print(f"[*] 越权疑似：{az.get('suspects', 0)} 条"
              f"（水平 {az.get('horizontal_suspects', 0)} / "
              f"垂直 {az.get('vertical_suspects', 0)}）；"
              f"公共页抑制 {az.get('suppressed_public', 0)}；"
              f"正常/负样本 {az.get('normal', 0)}")
        if az.get("budget_exhausted"):
            print("    [!] 越权请求预算已用尽，检测提前停止")
        if result.paths.get("authz_report"):
            print(f"    越权报告：{result.paths['authz_report']}")

    for w in result.warnings:
        print(f"[!] {w}")
    print(f"    资产清单：{result.paths['assets']}")
    print(f"    汇总报告：{result.paths['report']}")
    print(f"    审计日志：{result.paths['audit']}")
    print("[i] 跨目标产品盘点（通用1.0 影响力）：main.py inventory")
    return 0


def export_reports(app: AppConfig, target: TargetDef, *, fmt: str = "md",
                   out: str = "", min_score: float = 0.0,
                   recon_config: str | None = None) -> int:
    """把已有命中导出为结构化报告（md/json，单条 + 批量清单）。"""
    try:
        recon = load_recon_config(recon_config)
    except (ReconConfigError, ValueError) as e:
        print(f"[!] recon 配置错误：{e}")
        return 2
    tdir = recon.target_state_dir(target.name)
    findings = read_findings_jsonl(tdir / "findings.jsonl")
    if not findings:
        print(f"[!] 没有命中记录：{tdir / 'findings.jsonl'}")
        return 1
    assets = read_assets_jsonl(tdir / "assets.jsonl")
    out_dir = Path(out) if out else (tdir / "reports")
    export_findings(findings, assets, target, out_dir, fmt=fmt,
                    min_score=min_score, console=print)
    return 0


def _status(recon, target: TargetDef) -> int:
    target_dir = recon.target_state_dir(target.name)
    state = RunState(target_dir / "state.json", target.name)
    assets = read_assets_jsonl(target_dir / "assets.jsonl")
    findings = read_findings_jsonl(target_dir / "findings.jsonl")
    print(f"[*] 状态目录：{target_dir}")
    snap = state.snapshot()
    for name, st in snap.get("stages", {}).items():
        print(f"    {name}: {st.get('status')}（已处理 {st.get('processed')}）")
    print(f"[*] 资产 {len(assets)} 条 / 命中 {len(findings)} 条")
    products: dict[str, int] = {}
    for a in assets:
        for p in a.products:
            products[p.get("product", "")] = products.get(p.get("product", ""), 0) + 1
    for name, n in sorted(products.items(), key=lambda x: -x[1]):
        print(f"    - {name}: {n} 台")
    summary = target_dir / "summary.json"
    if summary.exists():
        try:
            data = json.loads(summary.read_text(encoding="utf-8"))
            print(f"[*] 上次汇总：{data.get('generated_at', '')}，档位 {data.get('profile', {}).get('name', '')}")
        except json.JSONDecodeError:
            pass
    return 0
