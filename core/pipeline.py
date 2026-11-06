# -*- coding: utf-8 -*-
"""流水线编排：collect → scan → judge → report。

每个环节都过宪法守门（第1条范围校验 / 第3条限流 / 第5条去重 / 第6条只出本地报告）。
"""
from __future__ import annotations

import json
from rich.console import Console

from .config import AppConfig
from .constitution import (RateLimiter, TargetDef, check_host_in_scope,
                           ScopeViolation)
from .db import DB
from .fingerprint import extract_products, guess_from_title
from .hunter import HunterClient
from .subdomain import enumerate_subdomains, probe_http, resolve_hosts

console = Console()


# ------------------------------------------------------------------
# collect：资产收集（Hunter + subfinder + httpx）
# ------------------------------------------------------------------
def cmd_collect(cfg: AppConfig, target: TargetDef) -> None:
    db = DB(cfg.db_path)
    limiter = RateLimiter(cfg.db_path, target.name, cfg.scan.daily_request_limit)

    # 1) Hunter 资产（如配置了 hunter_query 或有域名）
    hunter_assets = []
    try:
        hc = HunterClient(cfg.hunter, logger=console.print)
        query = target.hunter_query or (hc.build_domain_query(target.domains) if target.domains else "")
        if query:
            console.print(f"[cyan][*] Hunter 拉取资产：{query[:80]}[/cyan]")
            for a in hc.search(query):
                host = (a.domain or a.ip or "").lower()
                if not host:
                    continue
                # 宪法第1条：范围校验（hunter_query 模式下 IP 资产放行，域名资产校验）
                if target.domains and a.domain and not check_host_in_scope(a.domain, target):
                    continue
                hunter_assets.append({
                    "host": host, "port": a.port, "url": a.url,
                    "title": a.title, "tech": a.component, "status": 200,
                    "webserver": "", "source": "hunter",
                })
            console.print(f"[+] Hunter 资产 {len(hunter_assets)} 条")
    except SystemExit:
        raise
    except Exception as e:
        console.print(f"[yellow][!] Hunter 拉取跳过/失败: {e}[/yellow]")

    # 2) subfinder 被动子域 + httpx 存活探测
    sub_assets = []
    if target.domains:
        console.print(f"[cyan][*] subfinder 枚举子域: {target.domains}[/cyan]")
        try:
            subs = enumerate_subdomains(target.domains, cfg)
            console.print(f"[+] 子域 {len(subs)} 个")
            resolved = resolve_hosts(subs, cfg)
            console.print(f"[+] 可解析 {len(resolved)} 个")
            sub_assets = probe_http(resolved, cfg, target, limiter)
            console.print(f"[+] 存活 HTTP 资产 {len(sub_assets)} 个")
        except ScopeViolation as e:
            console.print(f"[red][!] {e}[/red]")
        except Exception as e:
            console.print(f"[yellow][!] subfinder/httpx 失败: {e}[/yellow]")

    # 3) 合并入库
    for a in hunter_assets + sub_assets:
        db.upsert_asset(target.name, a["host"], a.get("port") or 0,
                        url=a.get("url", ""), title=a.get("title", ""),
                        tech=a.get("tech"), status=a.get("status", 0),
                        webserver=a.get("webserver", ""), source=a.get("source", ""))
    total = len(db.assets(target.name))
    console.print(f"[bold green][✓] 资产收集完成，库内 {total} 条[/bold green]")
    limiter.close()


# ------------------------------------------------------------------
# scan：指纹标注 + nuclei 扫描
# ------------------------------------------------------------------
def cmd_scan(cfg: AppConfig, target: TargetDef) -> None:
    db = DB(cfg.db_path)
    limiter = RateLimiter(cfg.db_path, target.name, cfg.scan.daily_request_limit)
    rows = db.assets(target.name)
    if not rows:
        console.print("[yellow][!] 无资产，先运行 collect[/yellow]")
        return

    # 1) 指纹归一化标注（httpx tech + 标题兜底）
    products_map: dict[str, list[str]] = {}
    for r in rows:
        tech = json.loads(r["tech"]) if r["tech"] else []
        products = extract_products(tech, r["title"] or "")
        if not products:
            products = guess_from_title(r["title"] or "")
        products_map[r["url"] or r["host"]] = products

    # 2) 扫描 URL 列表
    urls = [r["url"] for r in rows if r["url"]]
    from .scanner import scan_urls
    n = scan_urls(cfg, target, urls, db, limiter, console=console.print)
    console.print(f"[bold green][✓] 扫描完成，新增命中 {n} 条[/bold green]")
    limiter.close()


# ------------------------------------------------------------------
# judge：AI 误报筛查 + 价值预估
# ------------------------------------------------------------------
def cmd_judge(cfg: AppConfig, target: TargetDef) -> None:
    db = DB(cfg.db_path)
    rows = db.findings(target.name)
    if not rows:
        console.print("[yellow][!] 无命中记录[/yellow]")
        return
    try:
        from .ai import AIClient, check_duplicate_risk, estimate_value, judge_finding
        ai = AIClient(cfg, console=console.print)
    except SystemExit as e:
        console.print(f"[yellow][!] {e}[/yellow]")
        return

    asset_count = len(db.assets(target.name))
    for r in rows:
        if r["ai_verdict"]:  # 已判定过
            continue
        console.print(f"[*] AI 判定: {r['name']} @ {r['host']}")
        verdict = judge_finding(ai, r)
        if not verdict:
            continue
        value = estimate_value(ai, r, verdict, asset_count, r["product"] or "")
        dup = check_duplicate_risk(db, r)
        if dup:
            console.print(f"    [yellow]{dup}[/yellow]")
        db.update_finding_ai(
            r["id"], verdict,
            json.dumps(value, ensure_ascii=False) if value else "")
        if verdict.get("real"):
            v = (value or {}).get("kb_estimate", "")
            console.print(f"    [green]真实漏洞 ✓ 置信度 {verdict.get('confidence')} 预估 {v}[/green]")
        else:
            console.print(f"    [red]疑似误报 ✗ {verdict.get('reason')}[/red]")
    console.print("[bold green][✓] AI 筛查完成[/bold green]")


# ------------------------------------------------------------------
# report：补天格式报告（只写本地文件，宪法第6条）
# ------------------------------------------------------------------
def cmd_report(cfg: AppConfig, target: TargetDef) -> None:
    from .report import gen_report
    db = DB(cfg.db_path)
    rows = db.findings(target.name)
    real_rows = [r for r in rows
                 if r["ai_verdict"] and '"real": true' in r["ai_verdict"].replace(" ", "")
                 or (r["ai_verdict"] and '"real":true' in r["ai_verdict"])]
    if not real_rows:
        console.print("[yellow][!] 无判定为真实的发现（先运行 judge，或无真实漏洞）[/yellow]")
        real_rows = rows  # 没有AI判定时也允许生成报告供人工审阅
    n = 0
    for r in real_rows:
        if gen_report(cfg, target, db, r, console=console.print):
            n += 1
    console.print(f"[bold green][✓] 报告生成完成 {n} 份 → {cfg.reports_dir}[/bold green]")
    console.print("[bold]宪法第6条：请人工审阅后手动提交补天，工具不会自动提交[/bold]")
