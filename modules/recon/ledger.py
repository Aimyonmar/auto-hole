# -*- coding: utf-8 -*-
"""授权档案：解析补天项目页导出 → targets/authorized/<slug>.yaml → 清单/选择/预检。

硬约束：
- 只解析本地文件或粘贴文本，**不访问补天站点**；
- 解析保守：关键字段识别不出来就报错，不生成半成品档案；
- 只有“报名状态=已通过 且 范围非空”才可执行，其余一律 blocked 并给出原因。
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

import yaml

from core.config import ROOT
from core.constitution import load_target

from .config import ReconConfig
from .intake import Intake, plan as intake_plan, render as intake_render, \
    normalize_domain, normalize_ip

AUTHORIZED_DIR = ROOT / "targets" / "authorized"

STATUS_MAP = {
    "已通过": "approved", "通过": "approved", "报名成功": "approved",
    "审核中": "pending", "待审核": "pending", "报名中": "pending",
    "未通过": "rejected", "驳回": "rejected",
    "未报名": "not_registered",
}

SECTION_HEADERS = re.compile(r"(平台)?禁止(项|事项)|限制条件|报名状态|项目(链接|编号|地址)|资产范围")

_HTML_TAG = re.compile(r"<[^>]+>")
_BLANK = re.compile(r"\n\s*\n")


def strip_html(raw: str) -> str:
    """HTML → 纯文本：li/br 转换行、去标签、反转义。"""
    import html
    text = re.sub(r"<br\s*/?>", "\n", raw, flags=re.I)
    text = re.sub(r"</?li[^>]*>", "\n", text, flags=re.I)
    text = re.sub(r"</p>", "\n", text, flags=re.I)
    text = _HTML_TAG.sub(" ", text)
    text = html.unescape(text)
    text = re.sub(r"[ \t\u00a0]+", " ", text)
    return text.strip()


def _find(pattern: str, text: str, flags=re.S) -> str:
    m = re.search(pattern, text, flags)
    return (m.group(1).strip() if m else "")


def _line_value(text: str, labels: list[str]) -> str:
    for label in labels:
        m = re.search(label + r"\s*[：:]\s*([^\n]{1,120})", text)
        if m:
            return m.group(1).strip()
    return ""


def _section(text: str, header_regex: str, max_lines: int = 40) -> list[str]:
    """取某个标题之后的若干行，遇到下一个标题或空行截止。"""
    lines = [ln.strip() for ln in text.splitlines()]
    out, started = [], False
    for ln in lines:
        if not started:
            if re.search(header_regex, ln):
                tail = re.sub(header_regex, "", ln).lstrip("：: ").strip()
                if tail:
                    out.append(tail)
                started = True
            continue
        if not ln:
            continue
        if SECTION_HEADERS.search(ln) and not re.search(header_regex, ln):
            break
        out.append(ln)
        if len(out) >= max_lines:
            break
    return out


def parse_project_text(raw: str, *, source: str = "<paste>") -> dict:
    """解析项目页文本/HTML，返回字段与缺失列表（不猜、不补）。"""
    text = strip_html(raw)
    vendor = _line_value(text, [r"厂商(?:名称)?", r"企业名称", r"公司名称"]) \
        or _find(r"<title>\s*([^<|]{2,60})", raw)
    program_url = _find(r"(https?://(?:www\.)?butian\.net/(?:Company/\d+|Loo/submit\?cid=\d+)[^\s\"'<>)]*)", text)
    program_id = _line_value(text, [r"项目(?:编号|ID)"]) \
        or _find(r"(?:Company/|cid=)(\d{3,})", text)
    status_raw = _line_value(text, [r"报名状态"])
    status = STATUS_MAP.get(status_raw, "")
    if status_raw and not status:
        status = "unknown"

    scope_lines = _section(text, r"资产范围")
    domains, ips, rejected = [], [], []
    for line in scope_lines:
        for token in re.split(r"[、,，;；\s]+", line):
            token = token.strip()
            if not token:
                continue
            if re.match(r"^[0-9.]+(?:/\d+)?$", token):
                ip, why = normalize_ip(token)
                if ip:
                    ips.append(ip)
                else:
                    rejected.append({"value": token, "reason": why})
                continue
            d, why = normalize_domain(token)
            if d:
                domains.append(d)
            elif why and why != "空项":
                rejected.append({"value": token, "reason": why})

    restriction_lines = _section(text, r"(?:平台)?禁止(?:项|事项)|限制条件")
    restrictions_raw = "\n".join(restriction_lines).strip()
    automation = "unstated"
    if re.search(r"禁止.{0,12}(自动化|扫描|脚本)|(自动化|扫描|脚本).{0,12}禁止", restrictions_raw):
        automation = "no"
    elif re.search(r"(允许|可).{0,6}(自动化|扫描|脚本)", restrictions_raw):
        automation = "yes"

    missing = []
    if not vendor:
        missing.append("vendor")
    if not (program_url or program_id):
        missing.append("program_url/program_id")
    if not status_raw:
        missing.append("registration_status")
    if not domains and not ips:
        missing.append("scope.domains")
    if not restrictions_raw:
        missing.append("restrictions.raw")

    return {
        "vendor": vendor, "program_url": program_url, "program_id": program_id,
        "registration_status": status or "unknown", "domains": list(dict.fromkeys(domains)),
        "ips": list(dict.fromkeys(ips)), "rejected": rejected,
        "restrictions_raw": restrictions_raw, "automation_allowed": automation,
        "missing": missing, "source": source,
        "digest": hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16],
        "excerpt": text[:200].replace("\n", " "),
    }


def slugify(vendor: str) -> str:
    s = "".join(c if (c.isalnum() or c in "-_") else "-" for c in (vendor or "target"))
    s = re.sub(r"-{2,}", "-", s).strip("-_")[:48]
    return s or "target"


@dataclass
class LedgerEntry:
    path: Path
    intake: Intake
    registration_status: str = "unknown"
    executable: bool = False
    reasons: list = field(default_factory=list)
    last_run: str = ""
    last_hits: int = 0

    @property
    def name(self) -> str:
        return self.intake.name or self.intake.vendor


def import_project(recon: ReconConfig, *, file: str = "", text: str = "",
                   tier: str = "light", force: bool = False,
                   console: Callable[[str], None] = print) -> tuple[Optional[Path], dict]:
    """解析并生成授权档案；字段缺失直接失败，不写半成品。"""
    raw_text = text or ""
    source = "<paste>"
    if not raw_text:
        p = Path(file)
        if not p.exists():
            raise FileNotFoundError(f"导入文件不存在: {p}")
        raw_text = p.read_text(encoding="utf-8", errors="replace")
        source = str(p)
    parsed = parse_project_text(raw_text, source=source)
    if parsed["missing"]:
        raise ValueError("未识别字段：" + "、".join(parsed["missing"]) +
                         "；请手动补全后重新导入（未生成档案）")

    vendor = parsed["vendor"]
    slug = slugify(vendor)
    out = AUTHORIZED_DIR / f"{slug}.yaml"
    if out.exists() and not force:
        raise ValueError(f"档案已存在：{out}；如需覆盖请加 --force")

    ref = parsed["program_url"] or f"补天项目 {parsed['program_id']}"
    record = {
        "name": vendor, "slug": slug, "vendor": vendor,
        "program_url": parsed["program_url"], "program_id": parsed["program_id"],
        "registration_status": parsed["registration_status"],
        "authorization_ref": f"{ref}（补天项目页，本地导入）",
        "scope": {
            "domains": parsed["domains"], "ips": parsed["ips"],
            "include_subdomains": False, "include_third_party": False,
            "note": "由项目页导入，子域默认不纳入",
        },
        "restrictions": {
            "raw": parsed["restrictions_raw"],
            "automation_allowed": parsed["automation_allowed"],
        },
        "tier": tier if tier in ("light", "standard", "deep") else "light",
        "test_accounts": [],
        "source": {
            "file": source, "imported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "digest": parsed["digest"], "excerpt": parsed["excerpt"],
        },
    }
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(yaml.safe_dump(record, allow_unicode=True, sort_keys=False),
                   encoding="utf-8")
    it = Intake(
        source=str(out), name=vendor, vendor=vendor,
        program_url=parsed["program_url"] or f"program:{parsed['program_id']}",
        authorization_ref=record["authorization_ref"], tier=record["tier"],
        domains=parsed["domains"], ips=parsed["ips"],
        restrictions_raw=parsed["restrictions_raw"],
        automation_allowed=parsed["automation_allowed"],
    )
    console(f"[✓] 已生成授权档案：{out}")
    if parsed["rejected"]:
        console("    导入时忽略的条目：")
        for r in parsed["rejected"]:
            console(f"      - {r['value']!r}：{r['reason']}")
    return out, parsed


def _last_run(recon: ReconConfig, name: str) -> tuple[str, int]:
    tdir = recon.target_state_dir(name)
    sp = tdir / "summary.json"
    if sp.exists():
        try:
            d = json.loads(sp.read_text(encoding="utf-8"))
            return str(d.get("generated_at", "")), int((d.get("findings") or {}).get("total", 0))
        except (json.JSONDecodeError, TypeError):
            pass
    return "", 0


def load_ledgers(recon: ReconConfig) -> list[LedgerEntry]:
    entries: list[LedgerEntry] = []
    if not AUTHORIZED_DIR.exists():
        return entries
    for p in sorted(AUTHORIZED_DIR.glob("*.yaml")):
        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError:
            continue
        if not isinstance(raw, dict):
            continue
        from .intake import load_intake
        it = load_intake(p)
        status = str(raw.get("registration_status") or "unknown").lower()
        reasons = []
        if status != "approved":
            reasons.append(f"报名状态={status}（需 approved）")
        reasons.extend(it.fatal_reasons())
        if it.asset_count() == 0:
            reasons.append("资产范围为空")
        entry = LedgerEntry(path=p, intake=it, registration_status=status,
                            executable=not reasons, reasons=reasons)
        entry.last_run, entry.last_hits = _last_run(recon, entry.name)
        entries.append(entry)
    return entries


def render_list(entries: list[LedgerEntry]) -> str:
    ready = [e for e in entries if e.executable]
    blocked = [e for e in entries if not e.executable]
    lines = ["可执行目标：", "序号 | 厂商 | 报名状态 | 资产数 | 上次运行 | 上次命中"]
    if not ready:
        lines.append("（暂无：所有档案都被 blocked，见下方原因）")
    for i, e in enumerate(ready, 1):
        lines.append(f"{i} | {e.name} | {e.registration_status} | "
                     f"{e.intake.asset_count()} | {e.last_run or '-'} | {e.last_hits}")
    if blocked:
        lines += ["", "Blocked（不可执行）：", "厂商 | 报名状态 | 资产数 | 原因"]
        for e in blocked:
            lines.append(f"{e.name} | {e.registration_status} | {e.intake.asset_count()} | "
                         f"{'；'.join(e.reasons)}")
    return "\n".join(lines)


def resolve_identifier(identifier: str, recon: ReconConfig,
                       console: Callable[[str], None] = print
                       ) -> tuple[Optional[Path], Optional[Intake], str]:
    """把“序号 / 厂商名 / 文件路径”解析成可执行目标文件。

    返回 (target_path, intake, error)。blocked 目标一律拒绝并给出原因。
    """
    p = Path(identifier)
    if p.exists():
        with p.open(encoding="utf-8") as f:
            raw = yaml.safe_load(f) or {}
        if isinstance(raw, dict) and ("scope" in raw or "authorization_ref" in raw):
            from .intake import load_intake
            it = load_intake(p)
            status = str(raw.get("registration_status") or "").lower()
            if status and status != "approved":
                return None, it, f"目标被 blocked：报名状态={status}（需 approved）"
            if not it.ok:
                return None, it, "预检未通过：" + "；".join(it.fatal_reasons())
            return _emit(it, recon), it, ""
        return p, None, ""

    entries = load_ledgers(recon)
    ready = [e for e in entries if e.executable]
    hit: Optional[LedgerEntry] = None
    if identifier.isdigit():
        idx = int(identifier)
        if 1 <= idx <= len(ready):
            hit = ready[idx - 1]
    else:
        low = identifier.lower()
        for e in entries:
            if low in (e.name.lower(), slugify(e.name).lower()) or low in e.name.lower():
                hit = e
                break
    if hit is None:
        return None, None, f"未找到目标 `{identifier}`（可用 main.py targets 查看清单）"
    if not hit.executable:
        return None, hit.intake, "目标被 blocked：" + "；".join(hit.reasons)
    return _emit(hit.intake, recon), hit.intake, ""


def _emit(it: Intake, recon: ReconConfig) -> Path:
    from .intake import emit_target
    out = recon.target_state_dir(it.name or "target") / "target.from-ledger.yaml"
    return emit_target(it, out)


def confirmation_lines(it: Intake, plan_data: dict) -> list[str]:
    scope = ", ".join(it.domains + it.ips) or "（空）"
    return [
        f"厂商：{it.vendor}",
        f"项目/授权：{it.program_url} | {it.authorization_ref}",
        f"范围（{it.asset_count()} 个）：{scope}",
        f"含子域：{'是' if it.include_subdomains else '否'}；第三方："
        f"{'是（禁止）' if it.include_third_party else '否'}",
        f"档位：{plan_data['profile']}（并发 {plan_data['concurrency']} / "
        f"{plan_data['rps']} rps / 日配额 {plan_data['daily_limit']}）",
        f"预估请求上限：{plan_data['request_upper']}；熔断：连续失败 "
        f"{plan_data['failure_threshold']} 次 / 冷却 {plan_data['cooldown_s']}s",
        f"授权依据已读入：{'是' if it.authorization_ref else '否'}",
    ]


def preflight(it: Intake, recon: ReconConfig, *, yes: bool = False,
              profile_override: str = "", console: Callable[[str], None] = print) -> bool:
    """选择目标后的自动预检 + 确认；失败/未确认一律返回 False（不发请求）。"""
    plan_data = intake_plan(it, recon, profile_override=profile_override)
    console(intake_render(it, plan_data))
    if not it.ok:
        return False
    console("")
    console("待确认摘要：")
    for line in confirmation_lines(it, plan_data):
        console(f"  - {line}")
    if yes:
        return True
    if not sys.stdin.isatty():
        console("[!] 非交互环境，需加 --yes 确认后才执行")
        return False
    ans = input("确认执行？[y/N] ").strip().lower()
    return ans in ("y", "yes")
