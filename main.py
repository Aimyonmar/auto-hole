# -*- coding: utf-8 -*-
"""auto-hole CLI 入口。

命令：
  doctor            自检：工具链 / Hunter / GLM / 宪法配置
  collect -t FILE   资产收集（Hunter + subfinder + httpx）
  scan -t FILE      对已入库资产跑 nuclei POC 扫描
  judge -t FILE     AI 误报筛查 + 价值评估（GLM）
  report -t FILE    生成补天格式报告（本地文件，不提交）
  run -t FILE       一键全流程：collect → scan → judge → report
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from core.config import ROOT, load_config
from core.constitution import load_target

console = Console()


# ----------------------------------------------------------------------
# doctor：环境自检
# ----------------------------------------------------------------------
def cmd_doctor(args) -> int:
    cfg = load_config(args.config)
    ok = True

    # 1. 工具链（项目内，宪法第7条）
    tbl = Table(title="auto-hole doctor")
    tbl.add_column("检查项", style="cyan")
    tbl.add_column("状态")
    tbl.add_column("说明")

    for tool in ("nuclei", "subfinder", "httpx", "dnsx"):
        p = cfg.tool_path(tool)
        if p.exists():
            ver = _tool_version(p)
            tbl.add_row(tool, "[green]OK[/green]", ver)
        else:
            tbl.add_row(tool, "[red]缺失[/red]", f"运行 tools/setup_tools.ps1 安装（{p}）")
            ok = False

    tpl = cfg.nuclei_templates_dir
    n_tpl = len(list(tpl.glob("**/*.yaml"))) if tpl.exists() else 0
    if n_tpl > 1000:
        tbl.add_row("nuclei-templates", "[green]OK[/green]", f"{n_tpl} 个模板")
    else:
        tbl.add_row("nuclei-templates", "[red]缺失/不全[/red]", f"{n_tpl} 个模板（应 >1000）")
        ok = False

    # 2. Hunter API（轻量探活：无 key 时跳过）
    if cfg.hunter.api_key and not cfg.hunter.api_key.startswith("YOUR_"):
        tbl.add_row("hunter.api_key", "[green]已配置[/green]", "（配额在首次拉取时校验）")
    else:
        tbl.add_row("hunter.api_key", "[yellow]未配置[/yellow]", "config.yaml 填写鹰图 key")

    # 3. GLM
    if cfg.llm.api_key and not cfg.llm.api_key.startswith("YOUR_"):
        alive = _glm_probe(cfg)
        tbl.add_row("GLM API", "[green]连通[/green]" if alive else "[red]不通[/red]",
                    cfg.llm.model)
        ok = ok and alive
    else:
        tbl.add_row("GLM API", "[yellow]未配置[/yellow]", "config.yaml 填写 GLM key")

    # 4. 宪法配置校验（load_config 内部已 enforce，走到这里即通过）
    tbl.add_row("宪法配置校验", "[green]通过[/green]",
                f"并发={cfg.scan.concurrency} 日限={cfg.scan.daily_request_limit} "
                f"取证={cfg.scan.evidence_mode}")

    # 5. 环境隔离（宪法第7条）：确认数据目录都在项目内
    cfg.workspace_dir.mkdir(exist_ok=True)
    cfg.reports_dir.mkdir(exist_ok=True)
    tbl.add_row("环境隔离", "[green]项目内[/green]", str(ROOT))

    console.print(tbl)
    console.print("[bold green]全部就绪[/bold green]" if ok else
                  "[bold red]存在缺失项，按提示修复后重试[/bold red]")
    return 0 if ok else 1


def _tool_version(p: Path) -> str:
    import subprocess
    from core.subdomain import isolated_env
    try:
        r = subprocess.run([str(p), "-version"], capture_output=True, text=True,
                           timeout=30, encoding="utf-8", errors="replace",
                           env=isolated_env())
        for line in (r.stdout + r.stderr).splitlines():
            if "version" in line.lower():
                return line.strip()[:60]
        return "OK"
    except Exception:
        return "OK"


def _glm_probe(cfg) -> bool:
    import requests
    try:
        r = requests.post(cfg.llm.base_url,
                          headers={"Authorization": f"Bearer {cfg.llm.api_key}"},
                          json={"model": cfg.llm.model,
                                "messages": [{"role": "user", "content": "ping"}],
                                "max_tokens": 4},
                          timeout=cfg.llm.timeout)
        return r.status_code == 200
    except Exception:
        return False


# ----------------------------------------------------------------------
# 命令注册（collect/scan/judge/report/run 在后续模块就绪后接入）
# ----------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(prog="auto-hole",
                                 description="个人自动化漏洞挖掘工具（补天变现）")
    ap.add_argument("--config", default=str(ROOT / "config.yaml"), help="配置文件路径")
    ap.add_argument("--yes", action="store_true", help="跳过预检确认（非交互环境必须）")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("doctor", help="环境自检")

    for name, desc in [("collect", "资产收集"), ("scan", "POC 扫描"),
                       ("judge", "AI 筛查"), ("report", "生成报告"),
                       ("run", "一键全流程")]:
        p = sub.add_parser(name, help=desc)
        p.add_argument("-t", "--target", required=True, help="targets/ 目标文件")

    # 增强采集（modules/recon）：插件化数据源 + 指纹引擎 + 自适应限速 + 断点续跑
    rp = sub.add_parser("recon", help="增强采集（分级策略/断点续跑）")
    rp.add_argument("-t", "--target", required=True, help="targets/ 目标文件")
    rp.add_argument("--profile", default=None, choices=["light", "standard", "deep"],
                    help="策略档位（默认取 config/recon.yaml）")
    rp.add_argument("--stage", default="all",
                    choices=["all", "collect", "probe", "discover", "scan", "authz",
                             "evidence", "status"],
                    help="只跑指定阶段；discover=URL/路径发现；authz=只读越权检测；"
                         "evidence=用已有命中生成证据包")
    rp.add_argument("--fresh", action="store_true", help="丢弃断点进度重新开始")
    rp.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 跨目标产品盘点（通用1.0 影响力证明的本地底稿，不发请求）
    ip = sub.add_parser("inventory", help="跨目标产品资产盘点（通用1.0 达标统计）")
    ip.add_argument("--min-instances", type=int, default=100,
                    help="通用1.0 门槛：同产品公网实例数（默认 100）")
    ip.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 进化回路：误报标记 → 候选生成/靶场回归 → 人工入库 → 回滚
    ev = sub.add_parser("evolve", help="规则进化（候选生成/验证/版本化）")
    ev.add_argument("--action", required=True,
                    choices=["mark", "propose", "approve", "rollback", "list"])
    ev.add_argument("-t", "--target", default=None, help="targets/ 目标文件")
    ev.add_argument("--template-id", default="")
    ev.add_argument("--host", default="")
    ev.add_argument("--label", default="false_positive", choices=["false_positive"])
    ev.add_argument("--reason", default="")
    ev.add_argument("--product", default="")
    ev.add_argument("--marker-type", default="", choices=["", "header", "body", "title"])
    ev.add_argument("--marker-name", default="")
    ev.add_argument("--marker-value", default="")
    ev.add_argument("--lab-positive", default="http://127.0.0.1:18090")
    ev.add_argument("--lab-negative", default="http://127.0.0.1:18091")
    ev.add_argument("--candidate-dir", default="")
    ev.add_argument("--candidate-id", default="")
    ev.add_argument("--version", type=int, default=0)
    ev.add_argument("--note", default="")
    ev.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 目标接入：模板预检 / 授权档案导入 / 可挖清单
    itp = sub.add_parser("intake", help="目标接入预检（模板校验 + dry-run 计划）")
    itp.add_argument("file", help="targets/*.yaml 接入模板")
    itp.add_argument("--dry-run", action="store_true", help="只打印计划，不发请求不写文件")
    itp.add_argument("--emit", default="", help="预检通过后生成可执行目标文件路径")
    itp.add_argument("--profile", default="", choices=["", "light", "standard", "deep"])
    itp.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    imp = sub.add_parser("import", help="导入补天项目页（本地 HTML/文本）生成授权档案")
    imp.add_argument("file", nargs="?", default="", help="本地 HTML/TXT 文件")
    imp.add_argument("--text", default="", help="直接粘贴文本（优先于文件）")
    imp.add_argument("--tier", default="light", choices=["light", "standard", "deep"])
    imp.add_argument("--force", action="store_true", help="覆盖已存在的档案")
    imp.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    tg = sub.add_parser("targets", help="可挖目标清单（序号选择）")
    tg.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 目标体检：只做侦察/研判，零 nuclei/模板扫描
    tp = sub.add_parser("triage", help="目标体检（只侦察/研判，零扫描请求）")
    tp.add_argument("-t", "--target", required=True, help="targets/ 目标文件")
    tp.add_argument("--profile", default="light", choices=["light", "standard", "deep"])
    tp.add_argument("--max-requests", type=int, default=0, help="体检请求上限（默认 60）")
    tp.add_argument("--fresh", action="store_true", help="清空旧体检产物")
    tp.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 只读越权检测（IDOR / 水平 + 垂直；GET only）
    az = sub.add_parser("authz", help="只读越权检测（GET only，不实现写方法）")
    az.add_argument("-t", "--target", required=True, help="targets/ 目标文件")
    az.add_argument("--accounts", default="", help="明文账号 YAML（导入后立即加密存储）")
    az.add_argument("--prepare-only", action="store_true", help="只导入账号，不执行检测")
    az.add_argument("--max-requests", type=int, default=0, help="本次请求上限（默认 200）")
    az.add_argument("--similarity-threshold", type=float, default=0.0,
                    help="疑似越权相似度阈值（默认 0.90）")
    az.add_argument("--fresh", action="store_true", help="丢弃断点进度")
    az.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 批量编排：授权清单 → 优先级/双层配额/失败隔离/断点续跑
    bp = sub.add_parser("batch", help="批量编排（授权清单）")
    bp.add_argument("-m", "--manifest", required=True, help="批量清单 yaml")
    bp.add_argument("--profile", default=None, choices=["light", "standard", "deep"])
    bp.add_argument("--max-parallel", type=int, default=1)
    bp.add_argument("--global-daily-limit", type=int, default=0)
    bp.add_argument("--fresh", action="store_true")
    bp.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 结构化报告导出（单条 + 批量）
    xp = sub.add_parser("export", help="结构化报告导出（md/json）")
    xp.add_argument("-t", "--target", required=True, help="targets/ 目标文件")
    xp.add_argument("--format", default="md", choices=["md", "json"])
    xp.add_argument("--out", default="", help="输出目录（默认 <state>/<target>/reports）")
    xp.add_argument("--min-score", type=float, default=0.0)
    xp.add_argument("--recon-config", default=None, help="config/recon.yaml 路径")

    # 历史命中状态（去重生命周期）
    hp = sub.add_parser("history", help="历史命中库状态（已提交/忽略）")
    hp.add_argument("--key", required=True, help="历史命中 key（见 summary/findings）")
    hp.add_argument("--status", required=True, choices=["new", "reported", "ignored"])

    args = ap.parse_args()

    if args.cmd == "doctor":
        sys.exit(cmd_doctor(args))

    if args.cmd == "inventory":
        cfg = load_config(args.config)
        from modules.recon.inventory import main as inventory_main
        sys.exit(inventory_main(cfg, min_instances=args.min_instances,
                                recon_config=args.recon_config))

    if args.cmd == "evolve":
        cfg = load_config(args.config)
        from modules.recon.evolve_cli import main as evolve_main
        sys.exit(evolve_main(cfg, args))

    if args.cmd == "batch":
        cfg = load_config(args.config)
        from modules.recon.batch import run_batch
        from modules.recon.config import load_recon_config
        recon = load_recon_config(args.recon_config)
        result = run_batch(cfg, args.manifest, recon, profile=args.profile,
                           max_parallel=args.max_parallel,
                           global_daily_limit=args.global_daily_limit,
                           fresh=args.fresh, console=console.print)
        sys.exit(0 if result["targets_total"] else 1)

    if args.cmd == "history":
        from modules.recon.config import load_recon_config
        from modules.recon.history import HistoryStore
        cfg = load_config(args.config)
        recon = load_recon_config(None)
        hist = HistoryStore(cfg.db_path)
        ok = hist.mark(args.key, args.status)
        hist.close()
        console.print(f"[✓] {args.key} → {args.status}" if ok else f"[!] 未找到 {args.key}")
        sys.exit(0 if ok else 1)

    if args.cmd == "intake":
        from modules.recon.config import load_recon_config
        from modules.recon.intake import main as intake_main
        cfg = load_config(args.config)
        sys.exit(intake_main(cfg, args.file, dry_run=args.dry_run, emit=args.emit,
                             profile=args.profile, recon_config=args.recon_config))

    if args.cmd == "import":
        from modules.recon.config import load_recon_config
        from modules.recon.ledger import import_project
        recon = load_recon_config(args.recon_config)
        try:
            out, parsed = import_project(recon, file=args.file, text=args.text,
                                         tier=args.tier, force=args.force,
                                         console=console.print)
        except Exception as e:
            console.print(f"[!] 导入失败：{e}")
            sys.exit(1)
        console.print(f"    厂商={parsed['vendor']} 状态={parsed['registration_status']} "
                      f"域名={len(parsed['domains'])} IP={len(parsed['ips'])} "
                      f"自动化={parsed['automation_allowed']}")
        sys.exit(0)

    if args.cmd == "targets":
        from modules.recon.config import load_recon_config
        from modules.recon.ledger import load_ledgers, render_list
        recon = load_recon_config(args.recon_config)
        entries = load_ledgers(recon)
        if not entries:
            console.print(f"[!] 没有授权档案（先 main.py import）")
            sys.exit(1)
        console.print(render_list(entries))
        sys.exit(0)

    # 以下命令都需要目标文件 + 宪法校验
    cfg = load_config(args.config)
    from modules.recon.config import load_recon_config
    from modules.recon.ledger import preflight, resolve_identifier
    recon_pre = load_recon_config(getattr(args, "recon_config", None))
    target_path, intake_obj, err = resolve_identifier(args.target, recon_pre, console.print)
    if not target_path or err:
        console.print(f"[!] {err or '目标无法解析'}")
        sys.exit(1)
    if intake_obj is not None:
        prof = getattr(args, "profile", "") or ""
        # 档案里的档位优先（用户未显式指定 --profile 时）
        if not prof:
            prof = intake_obj.tier or "light"
        if not preflight(intake_obj, recon_pre, yes=bool(args.yes),
                         profile_override=prof, console=console.print):
            console.print("[!] 预检未通过或未确认，终止（未发送任何请求）")
            sys.exit(1)
        if hasattr(args, "profile"):
            args.profile = prof
    target = load_target(target_path)   # 宪法第1条：授权校验

    if args.cmd == "recon":
        from modules.recon.cli import main as recon_main
        sys.exit(recon_main(cfg, target, profile=args.profile, stage=args.stage,
                            fresh=args.fresh, recon_config=args.recon_config))

    if args.cmd == "triage":
        from modules.recon.triage_cli import main as triage_main
        sys.exit(triage_main(cfg, target, profile=args.profile,
                            max_requests=args.max_requests, fresh=args.fresh,
                            recon_config=args.recon_config, console=console.print))

    if args.cmd == "authz":
        from modules.recon.authz_cli import main as authz_main
        sys.exit(authz_main(cfg, target, accounts=args.accounts,
                            prepare_only=args.prepare_only,
                            max_requests=args.max_requests,
                            similarity_threshold=args.similarity_threshold,
                            fresh=args.fresh, recon_config=args.recon_config,
                            console=console.print))

    if args.cmd == "export":
        from modules.recon.cli import export_reports
        sys.exit(export_reports(cfg, target, fmt=args.format, out=args.out,
                                min_score=args.min_score,
                                recon_config=args.recon_config))

    if args.cmd in ("collect", "run"):
        from core.pipeline import cmd_collect
        cmd_collect(cfg, target)
    if args.cmd in ("scan", "run"):
        from core.pipeline import cmd_scan
        cmd_scan(cfg, target)
    if args.cmd in ("judge", "run"):
        from core.pipeline import cmd_judge
        cmd_judge(cfg, target)
    if args.cmd in ("report", "run"):
        from core.pipeline import cmd_report
        cmd_report(cfg, target)

    console.print("[bold green]完成[/bold green]")


if __name__ == "__main__":
    main()
