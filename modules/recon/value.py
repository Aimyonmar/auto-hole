# -*- coding: utf-8 -*-
"""价值评分：把“命中”换算成“值不值得提交”，用于排序与筛选。

变现口径（补天）：
- 公益SRC：单点漏洞，KB 为主，现金较少
- 通用1.0：同一产品的公网实例 ≥100，按危害/行业/时间跨度定价（可重复提交不同实例）
所以“能不能赚钱”取决于四个变量：**危害等级 × 漏洞类型 × 产品可复用规模 × 重复风险**，
而不是命中数量。本模型只做可解释的加权，不依赖大模型，也不声称等于平台定价。
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Iterable, Optional

from .schema import Finding, normalize_severity

# ---- 严重度基础分 ----
SEVERITY_BASE = {
    "critical": 55.0,
    "high": 40.0,
    "medium": 25.0,
    "low": 10.0,
    "info": 3.0,
    "unknown": 8.0,
}

# ---- 漏洞类型加分（取最高命中项，不叠加，避免双重计分） ----
# 顺序即优先级：同一条命中可能同时含多个关键词，只取最值钱的那个
CLASS_RULES: list[tuple[str, float, tuple[str, ...]]] = [
    ("远程代码执行", 20.0, ("rce", "remote code", "code execution", "命令执行", "代码执行",
                          "command injection", "command execution", "exec")),
    ("文件上传", 18.0, ("file upload", "arbitrary upload", "文件上传", "upload")),
    ("未授权访问/越权", 16.0, ("unauth", "missing authentication", "authorization bypass",
                            "未授权", "越权", "privilege escalation")),
    ("SQL注入", 15.0, ("sqli", "sql injection", "sql注入")),
    ("反序列化", 15.0, ("deserial", "反序列化")),
    ("任意文件读取/下载", 12.0, ("lfi", "file read", "file download", "path traversal",
                             "directory traversal", "任意文件读取", "任意文件下载", "目录遍历")),
    ("默认口令/弱口令", 12.0, ("default-login", "default login", "weak password",
                            "default credential", "弱口令", "默认口令")),
    ("SSRF", 10.0, ("ssrf",)),
    ("敏感信息泄露", 8.0, ("exposure", "disclosure", "info leak", "information leak",
                        "信息泄露", "敏感信息")),
    ("XSS", 3.0, ("xss", "cross site scripting", "跨站")),
    ("CSRF", 1.0, ("csrf",)),
]

# ---- 证据强度扣分 ----
NO_CURL_PENALTY = 8.0
NO_EXTRACT_PENALTY = 5.0

# ---- 重复风险 ----
DUPLICATE_PENALTY = 12.0      # 本库已提交过同模板
OLD_CVE_PENALTY = 6.0         # 老 CVE（公开 POC 多，撞车概率高）

SCALE_CAP = 20.0              # 资产规模加分上限
GENERIC_MIN_INSTANCES = 100   # 补天通用1.0 常见门槛


@dataclass
class ValueAssessment:
    score: float
    grade: str
    advice: str
    reasons: list = field(default_factory=list)
    reward_hint: str = ""
    vuln_class: str = ""
    program: str = "public"

    def to_dict(self) -> dict:
        return asdict(self)


def classify_vuln(finding: Finding) -> tuple[str, float]:
    """从模板名/ID/标签判定漏洞类型，返回 (类型名, 加分)。"""
    blob = " ".join([
        (finding.name or "").lower(),
        (finding.template_id or "").lower(),
        " ".join(str(t).lower() for t in (finding.tags or [])),
    ])
    for name, bonus, kws in CLASS_RULES:
        if any(k in blob for k in kws):
            return name, bonus
    return "其他", 0.0


def scale_bonus(instances: int) -> tuple[float, str]:
    """产品公网实例数加分：10 台起算，100 台（通用1.0 门槛）额外加成。"""
    n = max(0, int(instances or 0))
    if n < 10:
        return 0.0, ""
    # 按数量级给分：10~99 → 4 分；100~999 → 8 分；1000+ → 12 分
    bonus = min(SCALE_CAP, 4.0 * (len(str(n)) - 1))
    note = f"产品公网实例 {n} 台"
    if n >= GENERIC_MIN_INSTANCES:
        bonus = min(SCALE_CAP, bonus + 8.0)
        note += "（达到通用1.0 常见门槛 ≥100）"
    return bonus, note


def _old_cve(template_id: str, current_year: Optional[int] = None) -> bool:
    """粗略判断是否为“老 CVE”（公开 POC 多，重复提交风险高）。"""
    tid = (template_id or "").upper()
    if not tid.startswith("CVE-"):
        return False
    try:
        year = int(tid.split("-")[1])
    except (IndexError, ValueError):
        return False
    return year <= (current_year or datetime.now().year) - 3


class ValueModel:
    """可配置的价值评分器。"""

    def __init__(self, *, generic_bonus: float = 10.0, public_bonus: float = 0.0,
                 min_score_for_evidence: float = 40.0, min_score_to_submit: float = 45.0):
        self.generic_bonus = float(generic_bonus)
        self.public_bonus = float(public_bonus)
        self.min_score_for_evidence = float(min_score_for_evidence)
        self.min_score_to_submit = float(min_score_to_submit)

    def assess(self, finding: Finding, *, program: str = "public",
               product_instances: int = 0, duplicate_hits: int = 0,
               reported: bool = False) -> ValueAssessment:
        """program: generic（通用产品）| public（公益SRC）。"""
        reasons: list[str] = []
        score = SEVERITY_BASE.get(normalize_severity(finding.severity), 8.0)
        reasons.append(f"危害等级 {normalize_severity(finding.severity)}：{score:.0f} 分")

        vclass, class_bonus = classify_vuln(finding)
        if class_bonus:
            score += class_bonus
            reasons.append(f"漏洞类型「{vclass}」：+{class_bonus:.0f}")

        if program == "generic":
            score += self.generic_bonus
            reasons.append(f"通用产品可复用：+{self.generic_bonus:.0f}")
        elif self.public_bonus:
            score += self.public_bonus

        sb, snote = scale_bonus(product_instances)
        if sb:
            score += sb
            reasons.append(f"{snote}：+{sb:.1f}")

        ev = finding.evidence or {}
        if not finding.curl_command:
            score -= NO_CURL_PENALTY
            reasons.append(f"缺少 curl 复现命令：-{NO_CURL_PENALTY:.0f}")
        if not (ev.get("extracted") or ev.get("matcher") or ev.get("response")):
            score -= NO_EXTRACT_PENALTY
            reasons.append(f"缺少回显/匹配证据：-{NO_EXTRACT_PENALTY:.0f}")

        if reported:
            score -= DUPLICATE_PENALTY
            reasons.append(f"本库已有同模板提交记录：-{DUPLICATE_PENALTY:.0f}")
        elif duplicate_hits > 0:
            score -= DUPLICATE_PENALTY / 2
            reasons.append(f"本库已有 {duplicate_hits} 条同模板命中（多为补充资产）："
                           f"-{DUPLICATE_PENALTY / 2:.0f}")

        if _old_cve(finding.template_id):
            score -= OLD_CVE_PENALTY
            reasons.append(f"老 CVE（公开 POC 多，撞车概率高）：-{OLD_CVE_PENALTY:.0f}")

        score = max(0.0, min(100.0, round(score, 1)))
        grade = self._grade(score)
        advice = self._advice(score)
        return ValueAssessment(
            score=score, grade=grade, advice=advice, reasons=reasons,
            reward_hint=self._reward_hint(grade),
            vuln_class=vclass, program=program,
        )

    def _grade(self, score: float) -> str:
        if score >= 75:
            return "S"
        if score >= 60:
            return "A"
        if score >= self.min_score_to_submit:
            return "B"
        if score >= self.min_score_for_evidence:
            return "C"
        return "D"

    def _advice(self, score: float) -> str:
        if score >= 60:
            return "优先提交"
        if score >= self.min_score_to_submit:
            return "可提交（建议补强证据）"
        if score >= self.min_score_for_evidence:
            return "价值偏低，作为补充资产"
        return "不建议提交"

    @staticmethod
    def _reward_hint(grade: str) -> str:
        # 粗估区间，仅用于排序；不代表平台实际定价
        return {
            "S": "约 800–3000 元或 1000+ KB（粗估）",
            "A": "约 300–1000 元（粗估）",
            "B": "约 100–500 KB（粗估）",
            "C": "约 50–200 KB（粗估）",
            "D": "不建议投入",
        }.get(grade, "")


def rank_findings(findings: Iterable[Finding]) -> list[Finding]:
    """按价值分降序，同分按严重度。"""
    order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
    return sorted(
        findings,
        key=lambda f: (-float(f.value.get("score", 0)), -order.get(
            normalize_severity(f.severity), 0)),
    )


def requires_evidence(finding: Finding, model: ValueModel) -> bool:
    return float(finding.value.get("score", 0)) >= model.min_score_for_evidence
