# -*- coding: utf-8 -*-
"""目标接入模板 + 预检 + dry-run 计划（不发送任何请求）。

目标：把“用户只填必要信息”的接入格式校验成工具可执行的授权范围，
任何不合规项都在这里拒绝，避免带着模糊范围进入采集/扫描。
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional
from urllib.parse import urlsplit

import yaml

from core.config import AppConfig
from core.constitution import load_target

from .config import ReconConfig, load_recon_config

ALLOWED_TIERS = {"light", "standard", "deep"}
ALLOWED_AUTOMATION = {"yes", "unstated", "no"}
DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


@dataclass
class Issue:
    field: str
    reason: str
    fatal: bool = True

    def __str__(self) -> str:
        return f"{self.field}: {self.reason}"


@dataclass
class Intake:
    source: str = ""
    name: str = ""
    vendor: str = ""
    program_url: str = ""
    authorization_ref: str = ""
    tier: str = "light"
    domains: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    include_subdomains: bool = False
    include_third_party: bool = False
    restrictions_raw: str = ""
    automation_allowed: str = ""
    test_accounts: list = field(default_factory=list)
    scope_note: str = ""
    issues: list = field(default_factory=list)
    rejected_entries: list = field(default_factory=list)
    notes: list = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not any(i.fatal for i in self.issues)

    def fatal_reasons(self) -> list[str]:
        return [str(i) for i in self.issues if i.fatal]

    def warnings(self) -> list[str]:
        return [i.reason for i in self.issues if not i.fatal]

    def asset_count(self) -> int:
        return len(self.domains) + len(self.ips)


def _get(raw: dict, *keys, default=None):
    cur = raw
    for k in keys:
        if not isinstance(cur, dict) or k not in cur:
            return default
        cur = cur[k]
    return cur


def normalize_domain(raw) -> tuple[Optional[str], Optional[str]]:
    """返回 (规范化域名, 拒绝原因)。IP/CIDR 返回 None 并提示归入 ips。"""
    s = str(raw or "").strip().lower()
    if not s:
        return None, "空项"
    if "*" in s:
        return None, "通配符范围不允许（禁止 * 形式的模糊范围）"
    if "://" in s:
        s = urlsplit(s).netloc or ""
        s = s.lower()
    s = s.split("/")[0].split("?")[0].split("#")[0].strip()
    if not s:
        return None, "去掉协议/路径后为空"
    if "," in s or " " in s:
        return None, "包含分隔符或空格"
    # IP / CIDR
    try:
        ipaddress.ip_network(s, strict=False)
        return None, f"IP/CIDR `{s}` 不是域名（请填到 scope.ips）"
    except ValueError:
        pass
    if not DOMAIN_RE.match(s):
        return None, "不是合法域名（需为 a.b 形式，仅字母数字和 -）"
    return s, None


def normalize_ip(raw) -> tuple[Optional[str], Optional[str]]:
    s = str(raw or "").strip().lower()
    if not s:
        return None, "空项"
    if "*" in s:
        return None, "通配符范围不允许"
    try:
        net = ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None, "不是合法 IP/CIDR"
    # 单个 IP 保持原样；CIDR 保留网段表示（不展开）
    return (str(net) if "/" in s else str(net.network_address)), None


def load_intake(path: str | Path) -> Intake:
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"目标文件不存在: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return parse_payload(raw, source=str(p))


def parse_payload(raw: dict, source: str = "<form>") -> Intake:
    """从字典构造并校验 Intake（命令行文件与面板表单共用同一套规则）。"""
    if not isinstance(raw, dict):
        raise ValueError("目标文件顶层必须是字典")

    it = Intake(source=source, name=str(raw.get("name") or "").strip())
    it.vendor = str(raw.get("vendor") or "").strip()
    it.program_url = str(raw.get("program_url") or "").strip()
    it.authorization_ref = str(raw.get("authorization_ref") or "").strip()
    it.tier = str(raw.get("tier") or "light").strip().lower()
    it.restrictions_raw = str(_get(raw, "restrictions", "raw", default="") or "").strip()
    it.automation_allowed = str(
        _get(raw, "restrictions", "automation_allowed", default="") or "").strip().lower()
    it.include_subdomains = bool(_get(raw, "scope", "include_subdomains", default=False))
    it.include_third_party = bool(_get(raw, "scope", "include_third_party", default=False))
    it.scope_note = str(_get(raw, "scope", "note", default="") or "").strip()
    accounts = raw.get("test_accounts")
    if isinstance(accounts, list):
        it.test_accounts = accounts
    elif accounts:
        it.test_accounts = [str(accounts)]

    req = [
        ("vendor", it.vendor, "厂商名不能为空"),
        ("program_url", it.program_url, "补天项目链接/编号不能为空"),
        ("authorization_ref", it.authorization_ref, "授权依据不能为空"),
        ("restrictions.raw", it.restrictions_raw, "平台禁止项原文不能为空"),
        ("restrictions.automation_allowed", it.automation_allowed, "必须声明 yes/unstated/no"),
    ]
    for fname, value, reason in req:
        if not value:
            it.issues.append(Issue(fname, reason))

    if it.tier not in ALLOWED_TIERS:
        it.issues.append(Issue("tier", f"档位 `{it.tier}` 非法，只允许 light/standard/deep"))
    if it.automation_allowed and it.automation_allowed not in ALLOWED_AUTOMATION:
        it.issues.append(Issue("restrictions.automation_allowed",
                               f"取值 `{it.automation_allowed}` 非法，只允许 yes/unstated/no"))
    if it.automation_allowed == "no":
        it.issues.append(Issue("restrictions.automation_allowed",
                               "平台/厂商禁止自动化扫描，本工具拒绝执行（无可覆盖路径）"))
    if it.include_third_party:
        it.issues.append(Issue("scope.include_third_party",
                               "第三方资产不在厂商授权范围，拒绝纳入清单"))

    # 域名 / IP 规范化
    domains_raw = _get(raw, "scope", "domains", default=[]) or []
    ips_raw = _get(raw, "scope", "ips", default=[]) or []
    if isinstance(domains_raw, str):
        domains_raw = [x for x in domains_raw.splitlines()]
    if isinstance(ips_raw, str):
        ips_raw = [x for x in ips_raw.splitlines()]
    for item in domains_raw:
        d, why = normalize_domain(item)
        if d is None:
            it.rejected_entries.append({"field": "scope.domains", "value": str(item),
                                         "reason": why})
        elif d not in it.domains:
            it.domains.append(d)
    for item in ips_raw:
        ip, why = normalize_ip(item)
        if ip is None:
            it.rejected_entries.append({"field": "scope.ips", "value": str(item),
                                         "reason": why})
        elif ip not in it.ips:
            it.ips.append(ip)

    if not it.domains and not it.ips:
        it.issues.append(Issue("scope.domains", "没有任何有效域名或 IP（范围为空）"))
    if it.include_subdomains:
        it.notes.append("include_subdomains=true：子域会进入清单（运行时枚举后仍需过范围校验）")
    else:
        it.notes.append("include_subdomains=false：子域不会进入清单（仅主域本身）")
    if "unstated" == it.automation_allowed:
        it.notes.append("automation_allowed=unstated：平台未明确允许自动化，建议人工确认后再跑")
    if it.test_accounts:
        it.notes.append(f"已登记测试账号 {len(it.test_accounts)} 条（仅本地保存，不参与扫描）")
    return it


def plan(it: Intake, recon: ReconConfig, *, profile_override: str = "") -> dict:
    profile_name = profile_override or it.tier
    profile = recon.profiles.get(profile_name) or recon.profiles["light"]
    assets = it.asset_count()
    ports = len(profile.probe_ports)
    probe_upper = assets * ports * (1 + int(profile.probe_retries))
    discover_upper = (int(profile.crawl_max_urls) * 3
                      + int(profile.path_scan_max_paths) * assets + assets)
    scan_upper = int(profile.scan_max_urls) * 15 if profile.scan_enabled else 0
    daily = int(recon.limits.daily_request_limit or 5000)
    return {
        "profile": profile_name,
        "concurrency": profile.concurrency,
        "rps": profile.requests_per_second,
        "daily_limit": daily,
        "assets": assets,
        "domains": len(it.domains),
        "ips": len(it.ips),
        "ports": ports,
        "probe_upper": probe_upper,
        "discover_upper": discover_upper,
        "scan_upper": scan_upper,
        "request_upper": probe_upper + discover_upper + scan_upper,
        "failure_threshold": recon.limits.failure_threshold,
        "cooldown_s": recon.limits.cooldown_seconds,
        "scan_enabled": bool(profile.scan_enabled),
    }


def emit_target(it: Intake, path: Path) -> Path:
    """把接入模板规范化为工具可执行的目标文件（legacy 兼容）。"""
    import re
    raw_name = it.name or it.vendor or "target"
    name = re.sub(r'[\\/:*?"<>|]', "_", raw_name).strip() or "target"
    data = {
        "name": name,
        "vendor": it.vendor,
        "authorization": f"{it.program_url} | {it.authorization_ref}",
        "domains": list(it.domains),
        "ips": list(it.ips),
        "hunter_query": "",
        "scope_note": (f"tier={it.tier}; 含子域={it.include_subdomains}; "
                       f"自动化={it.automation_allowed}; {it.scope_note}").strip(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, allow_unicode=True, sort_keys=False), encoding="utf-8")
    load_target(path)          # 立刻回读校验，确保 legacy 校验也能通过
    return path


def render(it: Intake, plan_data: Optional[dict] = None) -> str:
    lines = []
    status = "通过" if it.ok else "未通过"
    lines.append(f"[{status}] 目标预检：{it.name or it.vendor or it.source}")
    lines.append(f"  文件：{it.source}")
    lines.append(f"  厂商：{it.vendor or '-'}；项目：{it.program_url or '-'}")
    lines.append(f"  授权依据：{it.authorization_ref or '（空）'}")
    lines.append(f"  档位：{it.tier or '-'}；自动化声明：{it.automation_allowed or '-'}")
    lines.append("  范围：")
    if it.domains:
        for d in it.domains:
            lines.append(f"    - {d}" + ("（含子域）" if it.include_subdomains else "（不含子域）"))
    if it.ips:
        for ip in it.ips:
            lines.append(f"    - {ip}（IP/CIDR）")
    if not it.domains and not it.ips:
        lines.append("    （无有效条目）")
    lines.append(f"  待测资产数：{it.asset_count()}（域名 {len(it.domains)} / IP {len(it.ips)}）")
    for n in it.notes:
        lines.append(f"  提示：{n}")
    if it.rejected_entries:
        lines.append("  被拒绝条目：")
        for r in it.rejected_entries:
            lines.append(f"    - [{r['field']}] {r['value']!r}：{r['reason']}")
    if plan_data:
        lines.append("  计划（dry-run，未发送任何请求）：")
        lines.append(f"    - 并发 {plan_data['concurrency']} / 速率 {plan_data['rps']} rps / "
                     f"日配额 {plan_data['daily_limit']}")
        lines.append(f"    - 端口 {plan_data['ports']} 个；扫描 {'开启' if plan_data['scan_enabled'] else '关闭'}")
        lines.append(f"    - 预估请求上限：探测 {plan_data['probe_upper']} + 发现 "
                     f"{plan_data['discover_upper']} + 扫描 {plan_data['scan_upper']} = "
                     f"{plan_data['request_upper']}（受日配额约束）")
        lines.append(f"    - 熔断：连续失败 {plan_data['failure_threshold']} 次 / "
                     f"冷却 {plan_data['cooldown_s']}s")
        lines.append(f"    - 授权依据已读入：{'是' if it.authorization_ref else '否'}")
    if not it.ok:
        lines.append("  拒绝原因：")
        for r in it.fatal_reasons():
            lines.append(f"    ✗ {r}")
    return "\n".join(lines)


def main(app: AppConfig, file: str, *, dry_run: bool = False, emit: str = "",
         profile: str = "", recon_config: str | None = None,
         console: Callable[[str], None] = print) -> int:
    """intake 入口：只做本地校验与计划，不发送任何网络请求。"""
    from .config import ReconConfigError
    try:
        recon = load_recon_config(recon_config)
    except (ReconConfigError, ValueError) as e:
        console(f"[!] recon 配置错误：{e}")
        return 2
    try:
        it = load_intake(file)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as e:
        console(f"[!] 无法读取目标文件：{e}")
        return 2

    plan_data = plan(it, recon, profile_override=profile)
    console(render(it, plan_data))
    if not it.ok:
        console("[✗] 预检未通过：拒绝执行，未写入任何目标文件")
        return 1

    if dry_run:
        console("[dry-run] 已输出计划，未发送任何请求、未写入文件")
        return 0
    if emit:
        try:
            out = emit_target(it, Path(emit))
        except Exception as e:
            console(f"[!] 生成目标文件失败：{e}")
            return 2
        console(f"[✓] 已生成可执行目标文件：{out}")
    else:
        console("[i] 未指定 --emit，本次只做预检；确认无误后可加 --emit 生成目标文件")
    return 0
