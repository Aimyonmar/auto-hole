# -*- coding: utf-8 -*-
"""AI 智能层（GLM）：误报筛查 + 漏洞价值预估 + 去重辅助（宪法第5条）。

设计：
- 输入：nuclei finding 的原始证据（template/matcher/curl/响应片段）
- 输出：结构化 JSON {real: bool, severity, reason, confidence}
- 价值预估：对照补天通用1.0/公益SRC 评分要素（危害等级、独立IP数量级、特殊行业、时间跨度）
"""
from __future__ import annotations

import json
import re
from typing import Optional

import requests

from .config import AppConfig
from .db import DB

# ------------------------------------------------------------------
# 误报筛查 Prompt
# ------------------------------------------------------------------
JUDGE_SYSTEM_PROMPT = """你是资深漏洞审核专家，负责对自动化扫描器（nuclei）的命中结果做误报筛查。
你会收到一条扫描命中记录（模板名、严重度、命中URL、curl 复现命令、响应摘要等证据）。

判定标准：
1. real=true 需满足：证据能明确证明漏洞存在（如敏感数据回显、版本指纹与漏洞影响版本匹配、未授权接口返回了受保护内容）
2. 以下情况判 real=false：仅状态码 200 无内容佐证、通用 404/默认页误报、版本不匹配、需要认证的接口返回登录页、模板本身为检测型（detection only）而非可利用证明
3. 常见误报类型：泛解析 CDN 页面、WAF 拦截页被当作漏洞页、页面标题匹配型模板的误匹配

严格输出 JSON（不要任何其他文字）：
{"real": true/false, "severity": "high/medium/low", "confidence": 0.0-1.0, "reason": "一句话判定理由", "evidence_ok": "证据是否足以提交漏洞平台"}"""

VALUE_SYSTEM_PROMPT = """你是补天漏洞响应平台的漏洞定价顾问。根据以下要素预估漏洞的提交价值（补天通用1.0/公益SRC口径）：

评分要素：
1. 危害等级：RCE > 任意文件上传/SQL注入(getshell) > 未授权访问敏感数据 > 弱口令 > 信息泄露
2. 资产数量：公网独立IP数量级（≥100 为通用1.0门槛）
3. 特殊行业：教育/医疗/金融/国企等特殊行业资产加权
4. 漏洞类型：通用产品漏洞（可重复提交不同厂商实例）vs 单点漏洞

输出格式（严格 JSON）：
{"value_level": "高/中/低", "kb_estimate": "预估KB或现金区间，如 '500-1500 KB' 或 '300-800 元'", "submit_advice": "是否建议提交（是/否/需补充证据）", "advice_reason": "一句话理由", "bonus_note": "加分建议（如补充测绘资产数证明）"}"""


class AIClient:
    def __init__(self, cfg: AppConfig, console=print):
        if not cfg.llm.api_key or cfg.llm.api_key.startswith("YOUR_"):
            raise SystemExit("[!] config.yaml 中 llm.api_key 未配置（GLM key）")
        self.cfg = cfg
        self.log = console

    def chat(self, system: str, user: str, max_tokens: int = 1024,
             temperature: float = 0.1) -> str:
        """调用 OpenAI 兼容端点（GLM）。"""
        r = requests.post(
            self.cfg.llm.base_url,
            headers={"Authorization": f"Bearer {self.cfg.llm.api_key}",
                     "Content-Type": "application/json"},
            json={"model": self.cfg.llm.model,
                  "messages": [{"role": "system", "content": system},
                               {"role": "user", "content": user}],
                  "temperature": temperature, "max_tokens": max_tokens},
            timeout=self.cfg.llm.timeout)
        r.raise_for_status()
        return r.json()["choices"][0]["message"]["content"]

    @staticmethod
    def _extract_json(text: str) -> Optional[dict]:
        """从模型输出中提取 JSON（容错：markdown 代码块/前后缀）。"""
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        try:
            return json.loads(m.group(0))
        except json.JSONDecodeError:
            return None


# ------------------------------------------------------------------
# finding 判定流程
# ------------------------------------------------------------------

def judge_finding(ai: AIClient, finding_row) -> Optional[dict]:
    """误报筛查单个 finding。返回判定 dict 或 None（解析失败）。"""
    raw = finding_row["raw"] or ""
    evidence = {
        "template_id": finding_row["template_id"],
        "name": finding_row["name"],
        "severity": finding_row["severity"],
        "matched_url": finding_row["matched_at"],
        "curl_command": finding_row["curl_command"],
        "raw_json_head": raw[:1200],
    }
    user_msg = json.dumps(evidence, ensure_ascii=False, indent=1)
    try:
        resp = ai.chat(JUDGE_SYSTEM_PROMPT, user_msg)
        verdict = AIClient._extract_json(resp)
        if verdict is None:
            ai.log(f"[!] AI 输出无法解析 JSON: {resp[:200]}")
        return verdict
    except Exception as e:
        ai.log(f"[!] AI 调用失败: {e}")
        return None


def estimate_value(ai: AIClient, finding_row, verdict: dict,
                   asset_count: int, product: str = "") -> Optional[dict]:
    """价值预估（补天口径）。"""
    user_payload = {
        "漏洞名": finding_row["name"],
        "严重度": finding_row["severity"],
        "AI判定": verdict,
        "产品": product or "未知",
        "本任务资产数": asset_count,
        "命中URL": finding_row["matched_at"],
    }
    try:
        resp = ai.chat(VALUE_SYSTEM_PROMPT,
                       json.dumps(user_payload, ensure_ascii=False, indent=1))
        return AIClient._extract_json(resp)
    except Exception as e:
        ai.log(f"[!] 价值预估失败: {e}")
        return None


def check_duplicate_risk(db: DB, finding_row) -> str:
    """宪法第5条：去重辅助提示（库内已有同模板不同资产的记录 → 提示补提交而非新洞）。"""
    rows = db.conn.execute(
        "SELECT COUNT(*) AS c FROM findings WHERE template_id=? AND reported=1",
        (finding_row["template_id"],)).fetchone()
    if rows and rows["c"] > 0:
        return (f"注意：模板 {finding_row['template_id']} 已有 {rows['c']} 条已提交记录，"
                f"如为同产品不同资产实例，建议以补充资产形式提交，避免拆分刷洞（宪法第5条）")
    return ""
