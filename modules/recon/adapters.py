# -*- coding: utf-8 -*-
"""适配层：recon 结果 → 既有 DB / 既有 scanner / 本地报告。

设计原则：
- core/ 的既有函数签名、表结构、CLI 行为都不变
- recon 的 canonical 输出是 workspace/recon/<target>/assets.jsonl（标准 schema）
- SQLite 的 assets 表只是“兼容镜像”，字段语义与 legacy 一致（tech 存字符串列表）
"""
from __future__ import annotations

import json
import time
from dataclasses import replace
from pathlib import Path
from typing import Callable, Iterable, Optional

from core.config import AppConfig, MANDATORY_EXCLUDED_TAGS
from core.constitution import TargetDef

from .config import Profile
from .schema import Asset, Finding

SCHEMA_VERSION = "recon.asset/v1"


# ------------------------------------------------------------------
# 文件存取（标准 schema）
# ------------------------------------------------------------------
def write_assets_jsonl(path: Path, assets: Iterable[Asset]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for a in assets:
            f.write(a.to_json() + "\n")
            n += 1
    tmp.replace(path)     # 原子写入，避免中断后读到半截文件
    return n


def read_assets_jsonl(path: Path) -> list[Asset]:
    if not path.exists():
        return []
    out: list[Asset] = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        try:
            out.append(Asset.from_dict(d))
        except TypeError:
            continue
    return out


def write_findings_jsonl(path: Path, findings: Iterable[Finding]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f:
        for x in findings:
            f.write(json.dumps(x.to_dict(), ensure_ascii=False) + "\n")
            n += 1
    tmp.replace(path)
    return n


def read_findings_jsonl(path: Path) -> list[Finding]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip().startswith("{"):
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        out.append(Finding(
            template_id=d.get("template_id", ""), name=d.get("name", ""),
            severity=d.get("severity", "unknown"), host=d.get("host", ""),
            matched_at=d.get("matched_at", ""), curl_command=d.get("curl_command", ""),
            product=d.get("product", ""), source=d.get("source", "nuclei"),
            tags=list(d.get("tags") or []),
            product_instances=int(d.get("product_instances") or 0),
            value=dict(d.get("value") or {}),
            evidence=d.get("evidence") or {}, created_at=d.get("created_at", ""),
        ))
    return out


# ------------------------------------------------------------------
# 写入既有 SQLite（兼容镜像）
# ------------------------------------------------------------------
def upsert_assets(db, target_name: str, assets: Iterable[Asset]) -> int:
    """写 legacy assets 表；tech 字段保持 legacy 语义（字符串列表 JSON）。"""
    n = 0
    for a in assets:
        tech: list[str] = []
        for p in a.product_names():
            if p not in tech:
                tech.append(p)
        for t in a.tech:
            if str(t) not in tech:
                tech.append(str(t))
        db.upsert_asset(
            target=target_name, host=a.host, port=a.port,
            url=a.url or "", title=a.title or "",
            tech=tech or None, status=int(a.status or 0),
            webserver=a.server or "",
            source=",".join(a.sources) if a.sources else "",
        )
        n += 1
    return n


def findings_since(db, target_name: str, min_id: int) -> list[dict]:
    rows = db.conn.execute(
        "SELECT * FROM findings WHERE target=? AND id>? ORDER BY id",
        (target_name, min_id)).fetchall()
    return [dict(r) for r in rows]


def max_finding_id(db, target_name: str) -> int:
    row = db.conn.execute(
        "SELECT COALESCE(MAX(id),0) FROM findings WHERE target=?", (target_name,)).fetchone()
    return int(row[0] or 0)


# ------------------------------------------------------------------
# 分级扫描：复用 core.scanner，只替换策略参数
# ------------------------------------------------------------------
def effective_app_config(app: AppConfig, profile: Profile) -> AppConfig:
    """按 profile 覆盖扫描策略；tags_exclude 永远保留 dos/fuzz 等强制项。"""
    excludes = sorted(set(profile.scan_tags_exclude) | set(MANDATORY_EXCLUDED_TAGS))
    scan = replace(
        app.scan,
        concurrency=int(profile.concurrency),
        severity=str(profile.scan_severity),
        tags_include=list(profile.scan_tags_include),
        tags_exclude=excludes,
    )
    return replace(app, scan=scan)


def run_scan(*, app: AppConfig, profile: Profile, target: TargetDef, urls: list[str],
             db, limiter, console: Callable[[str], None] = print,
             target_tags: Optional[list[str]] = None,
             extra_templates: Optional[list[str]] = None,
             user_agent: str = "",
             label: str = "") -> dict:
    """调用既有 nuclei 编排；返回 {new, findings}。

    target_tags：指纹命中产品的标签，用于筛出具体模板文件（禁止全量回退）。
    extra_templates：兼容旧调用方保留；不再作为模板范围依据。
    user_agent：nuclei -header 注入的 UA（默认由 runner 传探测 UA）。
    label：批次标签，用于生成不冲突的中间文件名（多产品分组扫描时使用）。
    """
    from core.scanner import scan_urls

    if not urls:
        return {"new": 0, "findings": []}
    eff = effective_app_config(app, profile)
    before = max_finding_id(db, target.name)
    n = scan_urls(eff, target, urls, db, limiter, console=console,
                  target_tags=target_tags, user_agent=user_agent, label=label)
    new_rows = findings_since(db, target.name, before)
    findings = [_row_to_finding(r) for r in new_rows]
    return {"new": int(n), "findings": findings}


def _row_to_finding(row: dict) -> Finding:
    """legacy findings 行 → Finding（优先从 raw JSONL 还原完整证据）。"""
    raw = (row.get("raw") or "").strip()
    f = None
    if raw.startswith("{"):
        try:
            f = Finding.from_nuclei(json.loads(raw))
        except (json.JSONDecodeError, TypeError):
            f = None
    if f is None:
        f = Finding(
            template_id=row.get("template_id", ""), name=row.get("name", ""),
            severity=row.get("severity", ""), host=row.get("host", ""),
            matched_at=row.get("matched_at", "") or "",
            curl_command=row.get("curl_command", "") or "",
            product=row.get("product", "") or "",
            evidence={"raw": raw[:1000]},
        )
    f.product = row.get("product") or f.product
    f.evidence["db_id"] = row.get("id")
    return f


# ------------------------------------------------------------------
# 汇总输出
# ------------------------------------------------------------------
def build_summary(target_name: str, profile: Profile, assets: list[Asset],
                  stage_info: dict, limiter_snapshot: dict,
                  budget: dict, warnings: list[str], skipped_sources: list[dict],
                  findings: Optional[Iterable[Finding]] = None) -> dict:
    products: dict[str, dict] = {}
    for a in assets:
        for p in a.products:
            name = p.get("product", "")
            if not name:
                continue
            item = products.setdefault(name, {"product": name, "hosts": 0,
                                              "max_confidence": 0.0, "rules": []})
            item["hosts"] += 1
            item["max_confidence"] = max(item["max_confidence"], float(p.get("confidence", 0)))
            rid = p.get("rule_id", "")
            if rid and rid not in item["rules"]:
                item["rules"].append(rid)

    alive = [a for a in assets if a.status]
    summary = {
        "schema": "recon.summary/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": target_name,
        "profile": profile.to_dict(),
        "stages": stage_info,
        "assets": {
            "total": len(assets),
            "alive": len(alive),
            "with_fingerprint": len([a for a in assets if a.products]),
        },
        "products": sorted(products.values(), key=lambda x: (-x["hosts"], x["product"]))[:50],
        "sources": _source_breakdown(assets),
        "limits": {"runtime": limiter_snapshot, "budget": budget},
        "skipped_sources": skipped_sources,
        "warnings": warnings,
    }
    if findings is not None:
        summary["findings"] = _findings_summary(list(findings))
    return summary


def _findings_summary(findings: list[Finding]) -> dict:
    """命中汇总：按价值等级分桶 + TOP N（提交顺序）。"""
    from .value import rank_findings
    ranked = rank_findings(findings)
    grades = {"S": 0, "A": 0, "B": 0, "C": 0, "D": 0}
    for f in ranked:
        g = str(f.value.get("grade", "D"))
        grades[g] = grades.get(g, 0) + 1
    top = []
    for f in ranked[:10]:
        v = f.value or {}
        top.append({
            "template_id": f.template_id, "name": f.name, "severity": f.severity,
            "product": f.product, "matched_at": f.matched_at,
            "score": v.get("score", 0), "grade": v.get("grade", ""),
            "advice": v.get("advice", ""),
        })
    return {"total": len(ranked), "by_grade": grades, "top_value": top,
            "submit_ready": len([f for f in ranked
                                 if float(f.value.get("score", 0)) >= 45])}


def _source_breakdown(assets: list[Asset]) -> dict:
    out: dict[str, int] = {}
    for a in assets:
        for s in (a.sources or ["unknown"]):
            out[s] = out.get(s, 0) + 1
    return out


def write_summary_json(path: Path, summary: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


def render_summary_md(summary: dict, audit_path: Optional[Path] = None) -> str:
    """生成人可读报告（用于资产清单归档 / 补天通用产品影响力证明）。"""
    st = summary.get("assets", {})
    lines = [
        f"# 采集汇总 — {summary.get('target', '')}",
        "",
        f"- 生成时间：{summary.get('generated_at', '')}",
        f"- 策略档位：{summary.get('profile', {}).get('name', '')}"
        f"（并发 {summary.get('profile', {}).get('concurrency')}，"
        f"速率 {summary.get('profile', {}).get('requests_per_second')} rps）",
        f"- 资产：总计 {st.get('total', 0)} / 存活 {st.get('alive', 0)} / 有指纹 {st.get('with_fingerprint', 0)}",
        "",
    ]
    waf = summary.get("waf") or {}
    if waf.get("stopped"):
        lines += [
            "## WAF 中止",
            "",
            f"- 状态：{summary.get('status', 'waf_stop')}",
            f"- 阶段：{waf.get('stage', '-')}",
            f"- URL：{waf.get('url', '-')}",
            f"- HTTP：{waf.get('status', '-')}",
            f"- 特征：{', '.join(waf.get('markers') or []) or '-'}",
            f"- 命中次数：{waf.get('hits', 0)} / 阈值 {waf.get('threshold', 1)}",
            "",
        ]
    lines += [
        "## 产品指纹分布",
        "",
        "| 产品 | 主机数 | 最高置信度 | 规则 |",
        "|---|---|---|---|",
    ]
    for p in summary.get("products", []):
        lines.append(f"| {p.get('product')} | {p.get('hosts')} | "
                     f"{float(p.get('max_confidence', 0)):.2f} | {', '.join(p.get('rules', []))} |")
    if not summary.get("products"):
        lines.append("| （无） | 0 | - | - |")

    src = summary.get("sources", {})
    lines += ["", "## 数据源贡献", "", "| 来源 | 资产数 |", "|---|---|"]
    for k, v in sorted(src.items(), key=lambda x: -x[1]):
        lines.append(f"| {k} | {v} |")

    fd = summary.get("findings") or {}
    if fd:
        lines += ["", "## 高价值命中（按价值分排序，先提交上面的）", ""]
        lines.append(f"- 命中 {fd.get('total', 0)} 条；达到可提交线 {fd.get('submit_ready', 0)} 条；"
                     f"等级分布 {fd.get('by_grade', {})}")
        if fd.get("top_value"):
            lines += ["", "| 等级 | 分数 | 漏洞 | 产品 | 命中 URL | 建议 |",
                      "|---|---|---|---|---|---|"]
            for t in fd["top_value"]:
                url = (t.get("matched_at") or "")[:60]
                lines.append(f"| {t.get('grade')} | {t.get('score')} | {t.get('name')} | "
                             f"{t.get('product') or '-'} | {url} | {t.get('advice')} |")
        lines += ["", "> 证据包位置见 `workspace/recon/<target>/evidence/`（人工复核后才可提交）。"]

    lim = summary.get("limits", {}).get("runtime", {})
    lines += [
        "", "## 速率与审计", "",
        f"- 实际请求数：{lim.get('requests', 0)}",
        f"- 当前速率：{lim.get('current_rps', 0)} rps（基线 {lim.get('base_rps', 0)}）",
        f"- 降速次数：{lim.get('rate_cuts', 0)}；失败：{lim.get('failures', 0)}；熔断状态：{lim.get('circuit', '')}",
        f"- 审计日志：{audit_path or 'workspace/recon/audit.jsonl'}",
    ]
    if summary.get("skipped_sources"):
        lines += ["", "## 跳过的数据源", "", "| 数据源 | 原因 |", "|---|---|"]
        for s in summary["skipped_sources"]:
            lines.append(f"| {s.get('name')} | {s.get('reason')} |")
    if summary.get("warnings"):
        lines += ["", "## 警告", ""] + [f"- {w}" for w in summary["warnings"]]
    lines += ["", "> 仅对显式声明授权的目标采集；结果仅供人工复核，工具不会自动提交任何平台。"]
    return "\n".join(lines) + "\n"


def write_summary_md(path: Path, summary: dict, audit_path: Optional[Path] = None) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_summary_md(summary, audit_path), encoding="utf-8")
    return path
