# -*- coding: utf-8 -*-
"""结构化报告导出（对齐常见 SRC 提交字段，提交动作仍为人工）。

单条/批量都支持，输出 md 与 json；证据统一截断 400 字符并脱敏 Bearer。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Optional

from core.constitution import TargetDef

from .evidence import IMPACT_TEXT, _excerpt, _safe_filename
from .schema import Asset, Finding
from .value import normalize_severity, rank_findings

RISK_LABELS = {"critical": "严重", "high": "高危", "medium": "中危",
               "low": "低危", "info": "信息", "unknown": "未知"}


def build_report(finding: Finding, target: TargetDef,
                 asset: Optional[Asset] = None) -> dict:
    product = finding.product or (asset.product_names()[0] if asset and asset.products else "")
    product = product or "（未识别）"
    vuln = finding.name or finding.template_id
    ev = finding.evidence or {}
    req, resp = _excerpt(ev.get("request") or "", 400), _excerpt(ev.get("response") or "", 400)
    value = finding.value or {}
    return {
        "schema": "recon.report/v1",
        "title": f"{target.vendor}{product}存在{vuln}漏洞",
        "vuln_name": vuln,
        "template_id": finding.template_id,
        "severity": finding.severity,
        "risk_level": RISK_LABELS.get(normalize_severity(finding.severity), "未知"),
        "product": product,
        "vendor": target.vendor,
        "authorization": target.authorization,
        "impact_scope": {
            "host": finding.host,
            "matched_at": finding.matched_at,
            "product_instances": finding.product_instances,
            "impact": IMPACT_TEXT.get(value.get("vuln_class", ""), IMPACT_TEXT["其他"]),
        },
        "steps": [
            f"请求 {finding.matched_at or finding.host}",
            f"匹配器 {ev.get('matcher') or '-'}；提取 {ev.get('extracted') or '-'}",
            "观察响应包含上述特征（截图含时间戳与 URL）",
        ],
        "reproduction": {"curl": finding.curl_command or "",
                         "request_excerpt": req, "response_excerpt": resp},
        "evidence": {"matched_at": finding.matched_at, "matcher": ev.get("matcher") or "",
                     "extracted": ev.get("extracted") or [],
                     "request": req, "response": resp},
        "fix_advice": f"升级 {product} 至官方最新版本并参考对应安全公告；无法升级时下线或加访问控制。",
        "value": value,
        "history_status": value.get("history_status", "new"),
        "created_at": finding.created_at,
    }


def report_markdown(r: dict) -> str:
    lines = [
        f"# {r['title']}", "",
        "## 一、基本信息", "",
        f"- 风险等级：{r['risk_level']}（{r['severity']}）",
        f"- 受影响产品：{r['product']}",
        f"- 命中地址：{r['impact_scope']['matched_at'] or '-'}",
        f"- 同产品实例数：{r['impact_scope']['product_instances']}",
        f"- 授权依据：{r['authorization']}", "",
        "## 二、影响说明", "", r["impact_scope"]["impact"], "",
        "## 三、复现步骤", "",
    ]
    if r["reproduction"]["curl"]:
        lines += ["```bash", r["reproduction"]["curl"], "```", ""]
    for i, step in enumerate(r["steps"], 1):
        lines.append(f"{i}. {step}")
    lines += ["", "## 四、证据（截断脱敏）", "",
              "```http", r["evidence"]["request"] or "（无请求摘录）", "```", "",
              "```http", r["evidence"]["response"] or "（无响应摘录）", "```", "",
              "## 五、修复建议", "", r["fix_advice"], "",
              "## 六、价值评估（本地排序，非平台定价）", "",
              f"- 分数：{r['value'].get('score')}；等级：{r['value'].get('grade')}；"
              f"建议：{r['value'].get('advice')}",
              f"- 依据：{'；'.join(r['value'].get('reasons', [])) or '-'}", "",
              "## 七、去重状态", "", f"- {r['history_status']}", "",
              "---", "*仅提交补天；提交前请人工复现确认，勿公开传播。*"]
    return "\n".join(lines) + "\n"


def export_findings(findings: Iterable[Finding], assets: Iterable[Asset],
                    target: TargetDef, out_dir: Path, *,
                    fmt: str = "md", min_score: float = 0.0,
                    console=print) -> list[Path]:
    by_host: dict[str, Asset] = {}
    for a in (assets or []):
        by_host.setdefault(a.host, a)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    index = []

    for f in rank_findings(findings):
        score = float((f.value or {}).get("score", 0))
        if score < min_score:
            continue
        r = build_report(f, target, by_host.get(f.host))
        name = f"{_safe_filename(r['vuln_name'])}-{_safe_filename(f.template_id)}"
        if fmt == "json":
            p = out_dir / f"{name}.json"
            p.write_text(json.dumps(r, ensure_ascii=False, indent=2), encoding="utf-8")
        else:
            p = out_dir / f"{name}.md"
            p.write_text(report_markdown(r), encoding="utf-8")
        paths.append(p)
        index.append({"file": p.name, "title": r["title"], "risk": r["risk_level"],
                      "score": score, "grade": (f.value or {}).get("grade", ""),
                      "status": r["history_status"]})

    if index:
        (out_dir / "index.json").write_text(
            json.dumps({"schema": "recon.report-index/v1", "target": target.name,
                        "items": index}, ensure_ascii=False, indent=2), encoding="utf-8")
        lines = [f"# 报告清单 — {target.name}", "",
                 "| 等级 | 分数 | 风险 | 标题 | 文件 | 去重状态 |",
                 "|---|---|---|---|---|---|"]
        for it in index:
            lines.append(f"| {it['grade']} | {it['score']} | {it['risk']} | "
                         f"{it['title']} | {it['file']} | {it['status']} |")
        (out_dir / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    console(f"[✓] 导出 {len(paths)} 条报告 → {out_dir}")
    return paths
