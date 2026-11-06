# -*- coding: utf-8 -*-
"""补天格式报告生成（宪法第6条：只生成本地文件，永不自动提交）。

补天提交规范（来源：补天官方公告）：
- 标题：[系统开发厂商全称]+[产品名称]+存在[漏洞名称]漏洞
- 正文：漏洞环境 / 版本证明 / 漏洞分析 / 复现步骤 / 影响资产证明
- 通用型需 EXP（Nday 类以 curl/复现步骤代替）
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from .config import AppConfig
from .constitution import TargetDef
from .db import DB

REPORT_TEMPLATE = """# {title}

> 本报告由 auto-hole 自动生成，提交前请人工审阅确认（宪法第6条）。
> 生成时间：{timestamp}

## 一、漏洞信息

| 项 | 内容 |
|---|---|
| 漏洞名称 | {vuln_name} |
| 漏洞类型 | {vuln_type} |
| 危害等级 | {severity} |
| 影响产品 | {product} |
| 厂商 | {vendor} |
| 授权依据 | {authorization} |

## 二、漏洞描述

{description}

## 三、复现步骤

{repro_steps}

## 四、证据截图占位

（人工补充：请求/响应截图，含时间戳与目标 URL）

## 五、影响资产证明

- 命中 URL：{matched_url}
- 本任务关联资产数：{asset_count}
- 测绘资产数证明（通用1.0需独立IP≥100）：{hunter_proof}

## 六、AI 审核意见（供参考，提交前请自行复核）

- 真实性判定：{ai_real}（置信度 {ai_confidence}）
- 判定理由：{ai_reason}
- 价值预估：{ai_value}
- 去重提示：{dup_note}

## 七、修复建议

{fix_advice}

---
*宪法第4条：本报告仅存本地，禁止公开传播；宪法第5条：同一漏洞不投第三方平台。*
"""


def gen_report(cfg: AppConfig, target: TargetDef, db: DB,
               finding_row, console=print) -> Optional[Path]:
    """为单个 finding 生成补天格式报告，返回文件路径。"""
    ai_verdict = {}
    try:
        ai_verdict = json.loads(finding_row["ai_verdict"] or "{}")
    except json.JSONDecodeError:
        pass

    # 产品名（指纹归一化结果）
    product = finding_row["product"] or "（未识别，请人工确认）"
    vuln_name = finding_row["name"] or finding_row["template_id"]

    # 补天标题规范：[厂商]+[产品]+存在[漏洞名]漏洞
    title = f"{target.vendor}{product}存在{vuln_name}漏洞"

    repro = []
    if finding_row["curl_command"]:
        repro.append("curl 复现命令：")
        repro.append(f"```bash\n{finding_row['curl_command']}\n```")
    if finding_row["matched_at"]:
        repro.append(f"验证 URL：{finding_row['matched_at']}")
    repro.append("原始证据（nuclei 输出）：")
    repro.append(f"```json\n{(finding_row['raw'] or '')[:800]}\n```")
    repro_steps = "\n\n".join(repro) if repro else "（人工补充复现步骤）"

    asset_count = len(db.assets(target.name))
    # 通用1.0 影响证明：从 Hunter 查询语法生成测绘资产数建议
    hunter_proof = "请用鹰图/Fofa 检索产品指纹统计独立 IP 数（≥100 为通用1.0门槛）"
    if target.hunter_query:
        hunter_proof = f"鹰图语法参考：{target.hunter_query}（提交前查询 restotal 截图）"

    value_est = finding_row["value_estimate"] or "（未评估）"

    content = REPORT_TEMPLATE.format(
        title=title,
        timestamp=time.strftime("%Y-%m-%d %H:%M:%S"),
        vuln_name=vuln_name,
        vuln_type=_guess_vuln_type(vuln_name, finding_row["template_id"]),
        severity=finding_row["severity"] or "medium",
        product=product,
        vendor=target.vendor,
        authorization=target.authorization,
        description=(f"自动化扫描器在授权资产范围内发现 {product}（或关联组件）存在"
                     f"{vuln_name}，nuclei 模板 ID：{finding_row['template_id']}。"
                     f"具体危害与影响范围见复现步骤与证据。"),
        repro_steps=repro_steps,
        matched_url=finding_row["matched_at"] or "",
        asset_count=asset_count,
        hunter_proof=hunter_proof,
        ai_real=str(ai_verdict.get("real", "未判定")),
        ai_confidence=str(ai_verdict.get("confidence", "-")),
        ai_reason=ai_verdict.get("reason", "-"),
        ai_value=value_est,
        dup_note="无",
        fix_advice=f"升级 {product} 至官方最新版本，并参考官方安全公告修复该漏洞。",
    )

    cfg.reports_dir.mkdir(parents=True, exist_ok=True)
    safe_name = _safe_filename(title)
    out = cfg.reports_dir / f"{time.strftime('%Y%m%d')}-{safe_name}.md"
    out.write_text(content, encoding="utf-8")
    console(f"[+] 报告已生成: {out}")
    return out


def _guess_vuln_type(name: str, template_id: str) -> str:
    blob = f"{name} {template_id}".lower()
    for kw, t in [("rce", "远程代码执行"), ("exec", "命令执行"), ("upload", "文件上传"),
                  ("sqli", "SQL注入"), ("sql", "SQL注入"), ("unauth", "未授权访问"),
                  ("login", "弱口令/默认凭据"), ("lfi", "任意文件读取"),
                  ("ssrf", "SSRF"), ("xss", "XSS"), ("info", "信息泄露"),
                  ("deserial", "反序列化"), ("cve-", "已知漏洞(CVE)")]:
        if kw in blob:
            return t
    return "其他"


def _safe_filename(s: str) -> str:
    keep = [c if c.isalnum() or c in "-_" else "_" for c in s[:60]]
    return "".join(keep)
