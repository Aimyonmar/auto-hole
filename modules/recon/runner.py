# -*- coding: utf-8 -*-
"""recon 编排：collect → probe(+fingerprint) → scan → summary，支持断点续跑。

阶段幂等性：
- 每个数据源完成后在 state 里记 done:<source>，重跑默认跳过
- 每台主机探测完成后记 processed，重跑默认跳过
- 扫描按 URL 记 processed，命中按 (template, host) 去重
- --fresh 清空进度重新开始
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from core.config import AppConfig
from core.constitution import (RateLimiter, TargetDef, check_host_in_scope)
from core.db import DB

from .adapters import (build_summary, read_assets_jsonl, read_findings_jsonl,
                       run_scan, upsert_assets, write_assets_jsonl,
                       write_findings_jsonl, write_summary_json, write_summary_md)
from .audit import AuditLog
from .authz import AuthzRunner, ProberFetch, write_outputs
from .authz_creds import AuthzConfigError, load_plan
from .config import Profile, ReconConfig
from .discovery import Discovery, DiscoveredUrl, read_discovered, write_discovered
from .evolution import build_metrics, load_feedback, write_metrics
from .evidence import generate_bundles
from .fingerprint import FingerprintEngine, FingerprintError
from .history import (HistoryStore, calibrate, is_public_known,
                      load_disclosures, write_calibration)
from .probe import ProbeAborted, Prober, ProbeStats
from .ratelimit import AdaptiveLimiter, BudgetLedger
from .schema import Asset, Finding, dedupe, normalize_url
from .sources import SourceContext, build_sources
from .state import RunState
from .targeting import ScanGroup, estimate_requests, group_by_product, primary_product
from .value import ValueModel
from .waf import WafGuard


@dataclass
class RunResult:
    target: str
    profile: str
    stage: str
    status: str = "done"
    assets: list[Asset] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    paths: dict = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    elapsed_s: float = 0.0
    probe_stats: dict = field(default_factory=dict)
    evidence_paths: list = field(default_factory=list)


def run(app: AppConfig, target: TargetDef, recon: ReconConfig, *,
        stage: str = "all", fresh: bool = False,
        console: Callable[[str], None] = print,
        authz_overrides: Optional[dict] = None) -> RunResult:
    profile = recon.active_profile()
    target_dir = recon.target_state_dir(target.name)
    target_dir.mkdir(parents=True, exist_ok=True)

    store = target_dir / "assets.jsonl"
    findings_store = target_dir / "findings.jsonl"
    discovered_store = target_dir / "discovered.jsonl"
    summary_path = target_dir / "summary.json"
    report_path = target_dir / "report.md"
    audit_path = recon.audit_dir() / "audit.jsonl"

    state = RunState(target_dir / "state.json", target.name, profile.name)
    if fresh:
        state.reset()
        # --fresh 语义：进度与旧结果一起清空，避免旧命中被重复计入
        for p in (store, findings_store, discovered_store):
            try:
                p.unlink()
            except FileNotFoundError:
                pass
    state.start_stage(stage)

    audit = AuditLog(audit_path, target.name, enabled=recon.audit.enabled)
    waf_guard = WafGuard(enabled=recon.waf.enabled,
                         stop_after=recon.waf.stop_after,
                         audit=audit, console=console)
    daily_limit = int(recon.limits.daily_request_limit or app.scan.daily_request_limit)
    limiter = AdaptiveLimiter(
        rps=profile.requests_per_second, concurrency=profile.concurrency,
        burst=recon.limits.burst, min_rps=recon.limits.min_rps,
        backoff_base=recon.limits.backoff_base, backoff_max=recon.limits.backoff_max,
        failure_threshold=recon.limits.failure_threshold, cooldown_s=recon.limits.cooldown_seconds,
    )
    ledger = BudgetLedger(app.db_path, target.name, daily_limit)
    legacy_limiter = RateLimiter(app.db_path, target.name, app.scan.daily_request_limit)
    db = DB(app.db_path)

    engine = _load_engine(recon, console)
    warnings: list[str] = []
    skipped_sources: list[dict] = []
    t0 = time.monotonic()

    try:
        timing: dict = {}
        # ---------------- 越权检测：账号校验 + 会话预检（先于任何采集请求） ----------------
        authz_plan = None
        authz_runner = None
        authz_summary: dict = {}
        if stage in ("all", "authz"):
            required = stage == "authz"
            if stage == "all" and not (recon.authz.enabled and recon.authz.auto_run):
                pass
            else:
                authz_plan = load_plan(target, recon, required=required,
                                       overrides=authz_overrides)
            if authz_plan is not None:
                pre_assets = read_assets_jsonl(store)
                guard = _make_guard(target, _declared_hosts(target, pre_assets))
                authz_prober = Prober(
                    recon=recon, target=target, profile=profile, limiter=limiter,
                    ledger=ledger, audit=audit, engine=None, console=console,
                    in_scope=guard, waf_guard=waf_guard,
                )
                fetch = ProberFetch(authz_prober, authz_plan, console)
                authz_runner = AuthzRunner(
                    plan=authz_plan, fetch=fetch, target=target, console=console,
                    in_scope=guard,
                )
                # 身份过期/单账号/凭据损坏都在这里直接失败，后续不会重放
                authz_runner.precheck()
                if waf_guard.stopped:
                    warnings.append("WAF 拦截，越权预检中止；后续阶段跳过")
                    if stage in ("all", "authz"):
                        state.finish_stage("authz", "waf_stop")

        # ---------------- collect ----------------
        assets: list[Asset] = read_assets_jsonl(store)
        if not waf_guard.stopped and stage in ("collect", "all", "probe"):
            if stage != "probe":
                t_stage = time.monotonic()
                assets, skipped_sources, collect_warn = _collect(
                    app, target, recon, profile, limiter, audit, state,
                    assets, fresh, store, console)
                warnings.extend(collect_warn)
                write_assets_jsonl(store, assets)
                timing["collect"] = round(time.monotonic() - t_stage, 2)

        # ---------------- probe（含指纹） ----------------
        probe_stats = ProbeStats()
        if not waf_guard.stopped and stage in ("probe", "all"):
            t_stage = time.monotonic()
            assets = read_assets_jsonl(store)
            if not assets:
                warnings.append("无可探测资产（请先跑 collect）")
            else:
                allowed = _declared_hosts(target, assets)
                guard = _make_guard(target, allowed)
                prober = Prober(
                    recon=recon, target=target, profile=profile, limiter=limiter,
                    ledger=ledger, audit=audit, engine=engine, console=console,
                    in_scope=guard, waf_guard=waf_guard,
                )
                alive, stats = prober.probe_assets(assets, state)
                if alive or stats.hosts > 0:
                    assets = dedupe(alive)          # 本轮探测结果即最新存活集
                # stats.hosts == 0 表示全部命中断点（无待处理主机）→ 保留既有资产清单
                upsert_assets(db, target.name, assets)
                write_assets_jsonl(store, assets)
                probe_stats = stats
                console(f"    资产 {len(assets)}（本次请求 {stats.requests}，"
                        f"实际 {stats.effective_rps} rps）")
            timing["probe"] = round(time.monotonic() - t_stage, 2)
            if waf_guard.stopped:
                state.finish_stage("probe", "waf_stop")
                warnings.append("WAF 拦截，探测阶段中止；后续阶段跳过")

        # ---------------- discover（URL/路径/参数发现，主动但受控） ----------------
        discovered: list[DiscoveredUrl] = read_discovered(discovered_store)
        discovery_stats: dict = {}
        scan_stats_all: dict = {}
        if not waf_guard.stopped and stage in ("discover", "all"):
            t_stage = time.monotonic()
            assets = read_assets_jsonl(store)
            if not assets:
                warnings.append("无可发现资产（请先跑 probe）")
            else:
                allowed = _declared_hosts(target, assets)
                guard = _make_guard(target, allowed)
                prober = Prober(
                    recon=recon, target=target, profile=profile, limiter=limiter,
                    ledger=ledger, audit=audit, engine=None, console=console,
                    in_scope=guard, waf_guard=waf_guard,
                )
                disc = Discovery(prober=prober, profile=profile, recon=recon,
                                 target_name=target.name, state=state, console=console)
                try:
                    discovered = disc.run(assets)
                except ProbeAborted as e:
                    warnings.append(f"发现阶段因配额/熔断中止：{e}")
                discovery_stats = dict(disc.stats)
                write_discovered(discovered_store, discovered)
                console(f"    发现 URL {len(discovered)} 条（页面 {discovery_stats.get('pages', 0)}，"
                        f"路径探测 {discovery_stats.get('paths_tested', 0)}，"
                        f"JS 端点 {discovery_stats.get('js_endpoints', 0)}）")
            timing["discover"] = round(time.monotonic() - t_stage, 2)
            if waf_guard.stopped:
                state.finish_stage("discover", "waf_stop")
                warnings.append("WAF 拦截，发现阶段中止；扫描与越权阶段跳过")

        # ---------------- scan（按产品分组定向扫描） ----------------
        findings = read_findings_jsonl(findings_store)
        if not waf_guard.stopped and (stage == "scan" or (stage == "all" and profile.scan_enabled)):
            t_stage = time.monotonic()
            if not profile.scan_enabled and stage == "scan":
                warnings.append(f"profile={profile.name} 默认不扫描，按显式 --stage scan 执行")
            assets = read_assets_jsonl(store)
            allowed = _declared_hosts(target, assets)
            guard = _make_guard(target, allowed)
            scan_prober = Prober(
                recon=recon, target=target, profile=profile, limiter=limiter,
                ledger=ledger, audit=audit, engine=None, console=console,
                in_scope=guard, waf_guard=waf_guard,
            )
            new_findings, scan_warn, scan_stats = _scan_stage(
                app=app, target=target, profile=profile, engine=engine, assets=assets,
                db=db, limiter=legacy_limiter, state=state, console=console,
                discovered=discovered, user_agent=recon.probe.user_agent,
                waf_prober=scan_prober)
            warnings.extend(scan_warn)
            scan_stats_all = scan_stats
            findings.extend(new_findings)
            for f in new_findings:
                audit.write("finding", stage="scan", template_id=f.template_id,
                            severity=f.severity, host=f.host,
                            matched_at=f.matched_at, evidence=f.evidence)
            timing["scan"] = round(time.monotonic() - t_stage, 2)
            if waf_guard.stopped:
                state.finish_stage("scan", "waf_stop")
                warnings.append("WAF 拦截，扫描阶段中止；越权阶段跳过")

        # ---------------- 只读越权检测（GET only） ----------------
        if not waf_guard.stopped and authz_runner is not None:
            t_stage = time.monotonic()
            # 阶段边界：重置 recon 的连续失败计数，避免端口探测失败把越权重放熔断；
            # 仍然使用同一令牌桶、日配额与审计，authz 自身连续失败会重新熔断。
            try:
                limiter.breaker.reset()
            except Exception:
                pass
            authz_result = authz_runner.run(
                discovered_urls=[d.url for d in discovered],
                assets=read_assets_jsonl(store),
                precheck=False,
            )
            authz_summary = write_outputs(
                authz_result, target_dir=target_dir, audit=audit, plan=authz_plan)
            warnings.extend(authz_result.warnings)
            console(
                f"    越权检测：疑似 {authz_summary.get('suspects', 0)}"
                f"（水平 {authz_summary.get('horizontal_suspects', 0)} / "
                f"垂直 {authz_summary.get('vertical_suspects', 0)}），"
                f"公共页抑制 {authz_summary.get('suppressed_public', 0)}，"
                f"请求 {authz_summary.get('requests', 0)}/"
                f"{authz_summary.get('max_requests', 0)}")
            timing["authz"] = round(time.monotonic() - t_stage, 2)
            if waf_guard.stopped:
                state.finish_stage("authz", "waf_stop")
                warnings.append("WAF 拦截，只读越权阶段中止")

        # ---------------- 价值评分（决定提交顺序） ----------------
        t_stage = time.monotonic()
        findings = _dedupe_findings(findings)
        assets = read_assets_jsonl(store)
        feedback = load_feedback(target_dir)
        fp_keys = {str(x.get("key")) for x in feedback
                   if x.get("label") == "false_positive"}
        model = ValueModel(
            generic_bonus=recon.value.generic_bonus,
            public_bonus=recon.value.public_bonus,
            min_score_for_evidence=recon.value.min_score_for_evidence,
            min_score_to_submit=recon.value.min_score_to_submit,
        )
        if findings:
            findings = _score_findings(findings, assets, target, db, model, fp_keys)
            findings, calibration = _apply_history(
                findings, app, target.name, recon, feedback)
            write_findings_jsonl(findings_store, findings)
            write_calibration(target_dir, calibration)

        # ---------------- 证据包（本地，人工复核后才提交） ----------------
        evidence_paths: list = []
        if (stage in ("all", "evidence")
                or (stage == "scan" and recon.value.evidence_enabled)):
            if recon.value.evidence_enabled and findings:
                evidence_paths = generate_bundles(
                    findings, target_name=target.name, vendor=target.vendor,
                    authorization=target.authorization,
                    out_dir=target_dir / "evidence", model=model,
                    assets=assets, product_instances=_product_host_counts(assets),
                    console=console)
                console(f"    证据包 {len(evidence_paths)} 份 → {target_dir / 'evidence'}")
        timing["score_evidence"] = round(time.monotonic() - t_stage, 2)

        assets = read_assets_jsonl(store)
        findings = read_findings_jsonl(findings_store)

        # ---------------- 汇总 ----------------
        if waf_guard.stopped:
            state.finish_stage(stage, "waf_stop")
            if stage != "all":
                warnings.append("WAF 拦截，当前目标中止")
        elif stage == "all":
            for s in ("collect", "probe", "discover"):
                state.finish_stage(s, "done")
            if profile.scan_enabled:
                state.finish_stage("scan", "done")
            if authz_runner is not None:
                state.finish_stage("authz", "done")
            state.finish_stage("all", "done")
        else:
            state.finish_stage(stage, "done")
        summary = build_summary(
            target.name, profile, assets,
            stage_info=state.snapshot().get("stages", {}),
            limiter_snapshot=limiter.snapshot(),
            budget={"daily_limit": daily_limit, "used": ledger.used(),
                    "remaining": ledger.remaining(), "breakdown": ledger.breakdown()},
            warnings=warnings, skipped_sources=skipped_sources,
            findings=findings,
        )
        summary["probe"] = probe_stats.to_dict()
        summary["discovery"] = {
            **(discovery_stats or {}),
            "urls": len(discovered),
            "path": str(discovered_store),
        }
        summary["scan"] = scan_stats_all or {}
        summary["status"] = "waf_stop" if waf_guard.stopped else "done"
        summary["waf"] = waf_guard.to_dict()
        if authz_summary:
            summary["authz"] = authz_summary
        summary["audit"] = {"path": str(audit_path), "records": audit.count(),
                            "degraded": audit.degraded}
        summary["evidence"] = {"dir": str(target_dir / "evidence"),
                               "bundles": len(evidence_paths)}
        summary["timing"] = dict(timing)
        write_summary_json(summary_path, summary)
        write_summary_md(report_path, summary, audit_path)

        elapsed = round(time.monotonic() - t0, 2)
        summary["elapsed_s"] = elapsed
        summary["timing"]["total"] = elapsed
        write_summary_json(summary_path, summary)

        metrics = build_metrics(summary, findings, feedback)
        metrics_path = write_metrics(target_dir, metrics)
        summary["metrics"] = {"path": str(metrics_path)}

        return RunResult(
            target=target.name, profile=profile.name, stage=stage,
            status="waf_stop" if waf_guard.stopped else "done",
            assets=assets, findings=findings, summary=summary,
            paths={"assets": str(store), "findings": str(findings_store),
                   "summary": str(summary_path), "report": str(report_path),
                   "audit": str(audit_path), "metrics": str(metrics_path),
                   "discovered": str(discovered_store),
                   "authz": str(target_dir / "authz.jsonl"),
                   "authz_summary": str(target_dir / "authz-summary.json"),
                   "authz_report": str(target_dir / "authz-report.md"),
                   "evidence": str(target_dir / "evidence")},
            warnings=warnings, elapsed_s=elapsed, probe_stats=probe_stats.to_dict(),
            evidence_paths=[str(p) for p in evidence_paths],
        )
    except Exception:
        state.fail_stage(stage, "运行异常")
        raise
    finally:
        ledger.close()
        legacy_limiter.close()
        db.close()


# ------------------------------------------------------------------
# collect
# ------------------------------------------------------------------
def _collect(app: AppConfig, target: TargetDef, recon: ReconConfig, profile: Profile,
             limiter: AdaptiveLimiter, audit: AuditLog,
             state: RunState, assets: list[Asset], fresh: bool,
             store: Path, console: Callable[[str], None]) -> tuple[list[Asset], list[dict], list[str]]:
    warnings: list[str] = []
    ctx = SourceContext(app=app, recon=recon, target=target, profile=profile,
                        limiter=limiter, audit=audit, state=state, console=console)
    plugins_dir = recon.abs_path(recon.sources.plugins_dir) if recon.sources.plugins_dir else None
    sources, skipped = build_sources(recon.sources.enabled, ctx, plugins_dir)
    for s in skipped:
        console(f"[!] 跳过数据源 {s['name']}：{s['reason']}")

    for src in sources:
        done_key = f"done:{src.name}"
        if not fresh and state.counter("collect", done_key, False):
            console(f"    [resume] 数据源 {src.name} 已完成，跳过")
            continue
        console(f"[*] 数据源 {src.name}（{src.kind}）")
        t = time.monotonic()
        try:
            got = list(src.fetch(ctx))
        except SystemExit as e:
            warnings.append(f"数据源 {src.name} 退出：{e}")
            state.set_counter("collect", f"error:{src.name}", str(e)[:200])
            continue
        except Exception as e:
            warnings.append(f"数据源 {src.name} 失败：{e}")
            state.set_counter("collect", f"error:{src.name}", str(e)[:200])
            audit.write("source_error", source=src.name, error=str(e)[:200])
            console(f"[!] {src.name} 失败：{e}")
            continue

        if got:
            assets = dedupe(list(assets) + got)
        state.set_counter("collect", f"count:{src.name}", len(got))
        state.set_counter("collect", done_key, True)
        state.save()
        write_assets_jsonl(store, assets)
        console(f"    {src.name} 返回 {len(got)} 条，累计去重 {len(assets)} 条"
                f"（{round(time.monotonic() - t, 1)}s）")
        audit.write("source_result", source=src.name, count=len(got))

    # 上限保护：唯一 host 数超过 profile.max_hosts 时截断（禁止无界规模）
    hosts = {a.host for a in assets}
    if len(hosts) > profile.max_hosts:
        warnings.append(
            f"唯一主机 {len(hosts)} 超过 profile.max_hosts={profile.max_hosts}，已按顺序截断")
        console(f"[!] 主机数 {len(hosts)} 超过上限 {profile.max_hosts}，截断")
        assets = _truncate_by_host(assets, profile.max_hosts)

    return assets, skipped, warnings


def _truncate_by_host(assets: list[Asset], max_hosts: int) -> list[Asset]:
    allowed: set[str] = set()
    out: list[Asset] = []
    for a in assets:
        if a.host in allowed or len(allowed) < max_hosts:
            allowed.add(a.host)
            out.append(a)
    return out


# ------------------------------------------------------------------
# 范围与扫描清单
# ------------------------------------------------------------------
def _declared_hosts(target: TargetDef, assets: list[Asset]) -> set[str]:
    """产品型目标（仅有 hunter_query）下，导入清单与查询结果本身即授权范围。"""
    if target.domains or target.ips or not target.hunter_query:
        return set()
    return {a.host for a in assets
            if {"hunter", "import"} & set(a.sources or [])}


def _make_guard(target: TargetDef, allowed: set[str]) -> Callable[[str], bool]:
    def guard(host: str) -> bool:
        if host in allowed:
            return True
        return check_host_in_scope(host, target)
    return guard


# ------------------------------------------------------------------
# 扫描：按产品分组（定向模板）
# ------------------------------------------------------------------
def _scan_stage(*, app: AppConfig, target: TargetDef, profile: Profile,
                engine, assets: list[Asset], db, limiter, state: RunState,
                console: Callable[[str], None],
                discovered: Optional[list[DiscoveredUrl]] = None,
                user_agent: str = "",
                waf_prober=None,
                ) -> tuple[list[Finding], list[str], dict]:
    warnings: list[str] = []
    groups = group_by_product(
        assets, engine,
        include_unidentified=bool(profile.scan_unidentified),
        processed=lambda u: state.is_processed("scan", _url_key(u)),
        max_urls_per_group=int(profile.scan_max_urls),
        max_groups=int(profile.scan_max_groups),
        require_template_dirs=bool(profile.scan_grouped),
    )
    if discovered:
        by_key = {g.product: g for g in groups}
        host_products = {a.host: primary_product(a) for a in assets if a.products}
        for rec in discovered:
            product = rec.product or host_products.get(rec.host, "")
            if not product and not profile.scan_unidentified:
                continue
            key = product or "unidentified"
            g = by_key.get(key)
            if g is None:
                g = ScanGroup(product=key)
                if engine is not None and g.is_identified:
                    g.template_dirs = engine.template_dirs_for([key])
                    g.tags = engine.tags_for([key])
                by_key[key] = g
            if rec.url not in g.urls:
                g.urls.append(rec.url)
            if rec.host not in g.hosts:
                g.hosts.append(rec.host)
        groups = list(by_key.values())
        if profile.scan_grouped and engine is not None:
            groups = [g for g in groups if not g.is_identified or g.template_dirs]
        groups = sorted((g for g in groups if g.urls),
                        key=lambda x: (-len(x.urls), x.product))[:int(profile.scan_max_groups)]
        for g in groups:
            g.urls = g.urls[:int(profile.scan_max_urls)]

    if not groups:
        msg = "无可扫描 URL（已处理完，或未识别产品且未开启 scan_unidentified）"
        console(f"[*] {msg}")
        warnings.append(msg + "；未回退全量模板")
        return [], warnings, {"groups": 0, "urls": 0, "requests_estimated": 0}

    results: list[Finding] = []
    urls_scanned = 0
    groups_run = 0
    console(f"[*] 扫描计划：{len(groups)} 组（profile={profile.name}，"
            f"已识别产品优先、未识别默认跳过）")

    def _waf_canary(g: ScanGroup) -> bool:
        """nuclei 内部响应不可见；每组前后用同 URL 做一次 GET 金丝雀检查。"""
        if waf_prober is None or not g.urls:
            return False
        url = g.urls[0]
        host = g.hosts[0] if g.hosts else normalize_url(url)[0]
        try:
            waf_prober.request(url, host, stage="scan-canary")
            return False
        except ProbeAborted:
            guard = getattr(waf_prober, "waf_guard", None)
            return bool(guard and guard.stopped)

    for i, g in enumerate(groups, 1):
        remaining = max(0, int(limiter.limit) - int(limiter.used))
        est = estimate_requests(g)
        if remaining <= 0:
            warnings.append("日请求配额已用尽，扫描提前停止")
            console("[!] 日请求配额已用尽，停止扫描")
            break
        if est > remaining:
            allowed = remaining // 15
            if allowed <= 0:
                warnings.append(f"配额不足，跳过扫描组 {g.product}")
                console(f"[!] 配额不足，跳过 {g.product}")
                continue
            g.urls = g.urls[:allowed]
            warnings.append(f"配额不足，{g.product} 组截断为 {allowed} 个 URL")

        tpl = ", ".join(g.template_dirs) or "默认标签"
        console(f"[*] 组 {i}/{len(groups)}：{g.product}（{len(g.urls)} URL；模板 {tpl}）")
        if _waf_canary(g):
            warnings.append("WAF 拦截：扫描前金丝雀命中，停止后续扫描")
            break
        res = run_scan(app=app, profile=profile, target=target, urls=g.urls,
                       db=db, limiter=limiter, console=console,
                       target_tags=g.tags, extra_templates=g.template_dirs,
                       user_agent=user_agent, label=_safe_label(g.product))
        results.extend(res["findings"])
        urls_scanned += len(g.urls)
        groups_run += 1
        state.mark_processed("scan", [_url_key(u) for u in g.urls])
        console(f"    新增命中 {res['new']} 条")
        if _waf_canary(g):
            warnings.append("WAF 拦截：扫描后金丝雀命中，停止后续扫描")
            break
    return results, warnings, {
        "groups": groups_run,
        "urls": urls_scanned,
        "requests_estimated": urls_scanned * 15,   # 与 legacy 预算口径一致（保守估算）
    }


def _safe_label(name: str) -> str:
    keep = [c if c.isalnum() or c in "-_" else "_" for c in (name or "group")[:32]]
    return "".join(keep) or "group"


def _url_key(url: str) -> str:
    from .schema import normalize_url
    host, port, scheme, u = normalize_url(url)
    return u or url


# ------------------------------------------------------------------
# 价值评分
# ------------------------------------------------------------------
def _product_host_counts(assets: list[Asset]) -> dict[str, int]:
    """本目标内每个产品的存活 host 数（去重）。"""
    hosts: dict[str, set[str]] = {}
    for a in assets:
        p = primary_product(a)
        if p and a.status and a.status > 0:
            hosts.setdefault(p, set()).add(a.host)
    return {k: len(v) for k, v in hosts.items()}


def _score_findings(findings: list[Finding], assets: list[Asset], target: TargetDef,
                    db, model: ValueModel, fp_keys: set[str] | None = None) -> list[Finding]:
    host_products: dict[str, str] = {}
    for a in assets:
        p = primary_product(a)
        if p:
            host_products.setdefault(a.host, p)
    counts = _product_host_counts(assets)
    program = "generic" if target.hunter_query else "public"
    fp_keys = fp_keys or set()

    for f in findings:
        if f.key in fp_keys:
            f.value = {
                "score": 0.0, "grade": "D", "advice": "人工标记误报，不提交",
                "reasons": ["人工反馈标记为误报"], "reward_hint": "不建议投入",
                "vuln_class": "其他", "program": program,
            }
            continue
        if not f.product:
            f.product = host_products.get(f.host, "")
        f.product_instances = counts.get(f.product, 0)
        dup_hits, reported = _duplicate_info(db, target.name, f)
        f.value = model.assess(
            f, program=program, product_instances=f.product_instances,
            duplicate_hits=dup_hits, reported=reported,
        ).to_dict()
    return findings


def _dedupe_findings(findings: list[Finding]) -> list[Finding]:
    """按 Finding.key 去重（同模板+host+命中点只保留一条，优先保留信息更全的）。"""
    out: dict[str, Finding] = {}
    for f in findings:
        cur = out.get(f.key)
        if cur is None:
            out[f.key] = f
            continue
        if (len(json.dumps(f.evidence or {}, ensure_ascii=False))
                > len(json.dumps(cur.evidence or {}, ensure_ascii=False))):
            out[f.key] = f
    return list(out.values())


def _apply_history(findings: list[Finding], app: AppConfig, target_name: str,
                   recon: ReconConfig, feedback: list[dict]) -> tuple[list[Finding], dict]:
    """历史去重 + 公开披露比对 + 误报率校准；命中后压制为 D（不出证据包）。"""
    calibration = calibrate(findings, feedback)
    suppressed = set(calibration.get("suppressed_templates") or [])
    disclosures = load_disclosures(recon)
    hist = HistoryStore(app.db_path)
    try:
        for f in findings:
            status = hist.check(f)["status"]
            reason = ""
            if status in ("reported", "ignored"):
                reason = f"历史命中已标记为 {status}，不重复出报告"
            elif is_public_known(f, disclosures):
                reason = "已公开披露/老 Nday，避免重复提交"
            elif f.template_id in suppressed:
                reason = "该模板人工反馈误报率偏高，暂停出报告"
            if reason:
                f.value = {
                    **f.value,
                    "score": min(float(f.value.get("score", 0)), 25.0),
                    "grade": "D", "advice": "历史/披露/校准压制，不提交",
                    "reasons": list(f.value.get("reasons", [])) + [reason],
                    "history_status": status,
                }
        hist.record(target_name, findings)
    finally:
        hist.close()
    return findings, calibration


def _duplicate_info(db, target_name: str, finding: Finding) -> tuple[int, bool]:
    """返回 (库内同模板其它命中数, 是否已有已提交记录)。"""
    try:
        row = db.conn.execute(
            "SELECT COUNT(*) AS c, SUM(CASE WHEN reported=1 THEN 1 ELSE 0 END) AS r "
            "FROM findings WHERE template_id=? AND target=? AND id!=?",
            (finding.template_id, target_name,
             int((finding.evidence or {}).get("db_id") or 0))).fetchone()
    except Exception:
        return 0, False
    hits = int(row["c"] or 0) if row else 0
    reported = bool(row and row["r"])
    return hits, reported


# ------------------------------------------------------------------
# 引擎
# ------------------------------------------------------------------
def _load_engine(recon: ReconConfig, console: Callable[[str], None]):
    lib = recon.fingerprint_library()
    if not lib.exists():
        console(f"[!] 指纹库不存在：{lib}（本次只做存活探测）")
        return None
    try:
        engine = FingerprintEngine.from_yaml(
            lib, min_confidence=recon.fingerprint.min_confidence,
            weak_match_penalty=recon.fingerprint.weak_match_penalty,
            body_limit=recon.fingerprint.body_limit,
            enable_prefilter=recon.fingerprint.enable_prefilter,
        )
    except FingerprintError as e:
        console(f"[!] 指纹库加载失败：{e}（本次只做存活探测）")
        return None
    st = engine.stats()
    console(f"[*] 指纹库 {st['rules']} 条规则 / {st['products']} 个产品"
            f"（前置过滤 {'启用' if st['prefilter'] else '关闭'}）")
    return engine
