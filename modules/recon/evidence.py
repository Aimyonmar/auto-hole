# -*- coding: utf-8 -*-
"""提交级证据包：把一条命中整理成“可直接人工核对、再提交补天”的本地 Markdown。

补天提交要素（公益SRC / 通用1.0 通用）：
- 标题：[厂商全称]+[产品名称]+存在[漏洞名称]漏洞
- 环境/版本证明、复现步骤、请求响应证据、影响说明
- 通用型需影响力证明（同产品公网实例数，≥100 台）
- 只读取证：证据只需证明漏洞存在，不拖数据、不写文件

本模块不联网、不提交，只生成本地文件。
"""
from __future__ import annotations

import re
import time
from pathlib import Path
from typing import Iterable, Optional

from .schema import Asset, Finding
from .value import ValueAssessment, ValueModel, rank_findings

IMPACT_TEXT = {
    "远程代码执行": "攻击者可在目标服务器上执行任意命令，通常可直接获取服务器权限，属于最高危类型。",
    "文件上传": "攻击者可上传恶意文件形成 WebShell（本工具仅验证上传接口存在与回显，未上传利用文件）。",
    "未授权访问/越权": "未授权用户可直接访问受保护的功能或数据，可能导致敏感信息泄露或后台接管。",
    "SQL注入": "可绕过身份校验或读取数据库内容（本工具仅以只读方式验证注入点存在，未导出数据）。",
    "反序列化": "可构造恶意序列化数据触发代码执行或远程命令，危害通常为高危及以上。",
    "任意文件读取/下载": "可读取服务器上的任意文件（如配置文件、密钥），可能进一步导致权限提升。",
    "默认口令/弱口令": "使用默认或弱口令即可登录管理后台，攻击者可获得管理员权限。",
    "SSRF": "可伪造服务器端请求，可能探测内网或访问云元数据接口。",
    "敏感信息泄露": "暴露了不应公开的配置、密钥或内部信息，可作为进一步攻击的跳板。",
    "XSS": "可在受害者浏览器中执行脚本，通常用于会话劫持或钓鱼。",
    "CSRF": "可诱导已登录用户执行非预期操作。",
    "其他": "具体危害需结合复现结果人工确认。",
}

CHECKLIST = """- [ ] 已人工复现一次，确认非误报（响应与截图一致）
- [ ] 已在授权范围内，且授权依据填写正确
- [ ] 复现过程只读，未修改/删除目标数据，未上传利用文件
- [ ] 证据包含请求、响应、时间戳、目标 URL
- [ ] 未在公开渠道传播该漏洞细节
- [ ] 与历史提交无重复（同模板不同资产按“补充资产”提交，不拆分刷洞）
- [ ] 通用1.0：已附同产品公网实例数证明（≥100 台）
"""


def _safe_filename(s: str, limit: int = 48) -> str:
    keep = [c if c.isalnum() or c in "-_" else "_" for c in (s or "")[:limit]]
    return "".join(keep) or "finding"


def _excerpt(text: str, limit: int = 400) -> str:
    """截断证据，避免把大段响应（可能含敏感数据）写进报告。"""
    t = re.sub(r"\s+", " ", (text or "").strip())
    t = re.sub(r"(Bearer\s+)[A-Za-z0-9\-_.]+", r"\1***", t)
    return (t[:limit] + "…") if len(t) > limit else t


def _evidence_excerpts(finding: Finding) -> tuple[str, str]:
    ev = finding.evidence or {}
    req = ev.get("request") or ""
    resp = ev.get("response") or ""
    raw = ev.get("raw") or ""
    if (not req or not resp) and raw.startswith("{"):
        # 兼容旧版只存 raw JSON 的记录
        import json
        try:
            j = json.loads(raw)
            req = req or j.get("request") or ""
            resp = resp or j.get("response") or ""
        except (json.JSONDecodeError, AttributeError):
            pass
    return _excerpt(req), _excerpt(resp)


def build_bundle(*, finding: Finding, assessment: ValueAssessment,
                 target_name: str, vendor: str, authorization: str,
                 out_dir: Path, asset: Optional[Asset] = None,
                 product_instances: int = 0) -> Path:
    product = finding.product or (asset.product_names()[0] if asset and asset.products else "")
    product = product or "（未识别，请人工确认）"
    vuln_name = finding.name or finding.template_id
    title = f"{vendor}{product}存在{vuln_name}漏洞"

    req, resp = _evidence_excerpts(finding)
    ev = finding.evidence or {}
    extracted = ev.get("extracted") or []
    matcher = ev.get("matcher") or ""
    impact = IMPACT_TEXT.get(assessment.vuln_class, IMPACT_TEXT["其他"])

    lines = [
        f"# {title}",
        "",
        "> 由 auto-hole 生成，**仅供人工复核后手动提交**（宪法第6条：工具不自动提交）。",
        f"> 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}；目标：{target_name}",
        "",
        "## 一、价值评级（用于排序，非平台定价）",
        "",
        f"- 评级：**{assessment.grade}**（{assessment.score} 分）→ {assessment.advice}",
        f"- 漏洞类型：{assessment.vuln_class}；程序类型："
        f"{'通用1.0（产品可复用）' if assessment.program == 'generic' else '公益SRC（单点）'}",
        f"- 粗估区间：{assessment.reward_hint}",
        "",
        "评分依据：",
    ]
    lines += [f"- {r}" for r in assessment.reasons] or ["- （无）"]

    lines += [
        "",
        "## 二、漏洞信息",
        "",
        "| 项 | 内容 |",
        "|---|---|",
        f"| 漏洞名称 | {vuln_name} |",
        f"| 模板 ID | {finding.template_id} |",
        f"| 危害等级 | {finding.severity} |",
        f"| 受影响产品 | {product} |",
        f"| 命中 URL | {finding.matched_at or '-'} |",
        f"| 厂商 | {vendor} |",
        f"| 授权依据 | {authorization} |",
        "",
        "## 三、复现步骤",
        "",
    ]
    if finding.curl_command:
        lines += ["```bash", finding.curl_command, "```", ""]
    else:
        lines += ["（模板未提供 curl 命令，请按下方请求摘录手工构造）", ""]
    lines += [f"1. 访问/请求：`{finding.matched_at or finding.host}`",
              f"2. nuclei 匹配器：`{matcher or '-'}`；提取结果：`{extracted or '-'}`",
              "3. 观察响应是否包含上述特征（截图需含时间戳与 URL）。", ""]

    lines += ["## 四、请求 / 响应证据（截断）", ""]
    lines += ["```http", req or "（无请求摘录）", "```", ""]
    lines += ["```http", resp or "（无响应摘录）", "```", ""]

    lines += [
        "## 五、影响说明",
        "",
        impact,
        "",
        "## 六、影响资产证明",
        "",
        f"- 本任务已采集的同产品实例数：**{product_instances}** 台（去重 host）",
        f"- 通用1.0 常见门槛：≥100 台 → {'已达标' if product_instances >= 100 else '未达标（可先补量）'}",
        "- 补量方式：`main.py inventory` 查看产品盘点；用测绘平台导出清单放入 "
        "`workspace/import/<目标名>.txt` 后再跑 recon。",
        "",
        "## 七、修复建议",
        "",
        f"升级 {product} 至官方最新版本并参考对应安全公告；无法升级时临时下线该接口或加访问控制。",
        "",
        "## 八、提交前检查清单",
        "",
        CHECKLIST,
        "",
        "---",
        "*只读取证：本证据仅包含证明漏洞存在所需的最小信息，未导出业务数据、未修改目标系统。*",
    ]

    out_dir.mkdir(parents=True, exist_ok=True)
    fname = (f"{time.strftime('%Y%m%d')}-{assessment.grade}{int(assessment.score)}-"
             f"{_safe_filename(vuln_name)}-{_safe_filename(finding.template_id)}.md")
    path = out_dir / fname
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def generate_bundles(findings: Iterable[Finding], *, target_name: str, vendor: str,
                     authorization: str, out_dir: Path,
                     model: ValueModel, assets: Optional[list[Asset]] = None,
                     product_instances: Optional[dict[str, int]] = None,
                     console=print) -> list[Path]:
    """为价值达标的命中生成证据包；返回生成的文件列表。"""
    by_host: dict[str, Asset] = {}
    for a in (assets or []):
        by_host.setdefault(a.host, a)
    instances = product_instances or {}

    paths: list[Path] = []
    for f in rank_findings(findings):
        score = float(f.value.get("score", 0))
        if score < model.min_score_for_evidence:
            console(f"    [skip] 价值 {score} < {model.min_score_for_evidence}：{f.template_id}")
            continue
        assessment = ValueAssessment(
            score=score,
            grade=str(f.value.get("grade", "D")),
            advice=str(f.value.get("advice", "")),
            reasons=list(f.value.get("reasons", [])),
            reward_hint=str(f.value.get("reward_hint", "")),
            vuln_class=str(f.value.get("vuln_class", "")),
            program=str(f.value.get("program", "public")),
        )
        n = instances.get(f.product or "", 0)
        if f.product_instances:
            n = max(n, f.product_instances)
        p = build_bundle(finding=f, assessment=assessment, target_name=target_name,
                         vendor=vendor, authorization=authorization, out_dir=out_dir,
                         asset=by_host.get(f.host), product_instances=n)
        paths.append(p)
        console(f"    [+] 证据包 {assessment.grade}{assessment.score:g}: {p.name}")
    return paths
