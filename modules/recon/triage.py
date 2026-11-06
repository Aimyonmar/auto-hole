# -*- coding: utf-8 -*-
"""目标体检：种子采集 → 存活探测 → 指纹识别 → 暴露面梳理 → 研判报告。

硬约束：
- 只做侦察与研判，不 import / 不调用 nuclei、模板扫描或任何 scan 阶段；
- 体检请求有独立预算（默认 60），与全局令牌桶/日配额/审计共用；
- 种子只允许 seed（目标声明）与 import（本地清单），不访问外部数据源；
- 风险方向、重复概率、成本、结论均为“推断”，不写成已发现漏洞。
"""
from __future__ import annotations

import json
import re
import statistics
import threading
import time
from collections import Counter
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import urljoin, urlsplit, urlunsplit

import yaml

from core.config import AppConfig
from core.constitution import TargetDef, check_host_in_scope

from .audit import AuditLog
from .config import Profile, ReconConfig
from .fingerprint import FingerprintEngine, MatchContext
from .history import load_disclosures
from .probe import ProbeAborted, Prober, WafDetected
from .ratelimit import AdaptiveLimiter, BudgetLedger
from .schema import build_url, extract_title, normalize_host, scheme_for_port
from .sources import SourceContext, build_sources
from .waf import WAF_MARKERS, WafGuard

RISK_LIBRARY = Path(__file__).resolve().parent / "data" / "triage_risks.yaml"
HTTPS_FALLBACK_PORTS = frozenset({443, 8443, 9443})
GENERIC_PATHS = (
    ("admin", "/admin/"), ("admin", "/manager/"), ("admin", "/console/"),
    ("login", "/login"), ("login", "/signin"),
    ("api", "/api"), ("api", "/api/v1"), ("api", "/graphql"),
    ("upload", "/upload"), ("upload", "/uploads"),
    ("debug", "/debug"), ("debug", "/actuator"), ("debug", "/phpinfo.php"),
    ("docs", "/swagger-ui/"), ("docs", "/docs"), ("docs", "/readme.html"),
    ("backup", "/backup.zip"), ("backup", "/www.zip"), ("backup", "/.git/"),
)
CMS_PATHS = {
    "wordpress": (("login", "/wp-login.php"), ("admin", "/wp-admin/"),
                  ("api", "/wp-json/"), ("upload", "/wp-content/uploads/"),
                  ("docs", "/readme.html"), ("backup", "/wp-config.php.bak")),
    "dedecms": (("admin", "/dede/"), ("api", "/api/"), ("upload", "/uploads/"),
                ("backup", "/data/backup/")),
    "discuz": (("admin", "/admin.php"), ("login", "/member.php?mod=logging"),
               ("api", "/api/"), ("upload", "/data/attachment/")),
}
BLOCKED_EXT = {".jpg", ".jpeg", ".png", ".gif", ".svg", ".css", ".woff", ".woff2",
               ".ttf", ".mp4", ".zip", ".rar", ".7z", ".gz", ".tar"}


class TriageError(RuntimeError):
    """体检前置条件不满足。"""


class TriageBudgetExceeded(ProbeAborted):
    """体检独立预算用尽。"""


class TriageBudget:
    def __init__(self, limit: int):
        self.limit = max(1, int(limit))
        self.used = 0
        self.exhausted = False
        self._lock = threading.Lock()

    def take(self) -> bool:
        with self._lock:
            if self.used >= self.limit:
                self.exhausted = True
                return False
            self.used += 1
            return True


class TriageProber(Prober):
    """在 Prober 上加独立预算；每个 request 入口只记 1 次。"""

    def __init__(self, *args, budget: TriageBudget, **kwargs):
        super().__init__(*args, **kwargs)
        self.triage_budget = budget

    def request(self, *args, **kwargs):
        if not self.triage_budget.take():
            raise TriageBudgetExceeded("体检请求预算已用尽")
        return super().request(*args, **kwargs)


@dataclass
class TriageAsset:
    host: str
    port: int
    url: str
    status: int
    title: str = ""
    server: str = ""
    headers: dict = field(default_factory=dict)
    text: str = ""
    elapsed_ms: float = 0.0
    products: list = field(default_factory=list)
    body_len: int = 0


@dataclass
class TriageResult:
    report: dict = field(default_factory=dict)
    summary: dict = field(default_factory=dict)
    paths: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


def _load_risk_library() -> list[dict]:
    if not RISK_LIBRARY.exists():
        return []
    try:
        raw = yaml.safe_load(RISK_LIBRARY.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError):
        return []
    return [x for x in (raw.get("products") or []) if isinstance(x, dict)]


def _version_tuple(v: str) -> tuple:
    parts = re.findall(r"\d+", str(v or ""))
    return tuple(int(x) for x in parts[:4]) if parts else ()


def _version_lt(actual: str, limit: str) -> bool:
    a, b = _version_tuple(actual), _version_tuple(limit)
    return bool(a and b and a < b)


def _extract_version(product: str, aliases: Iterable[str], asset: TriageAsset) -> tuple[str, str]:
    """从标题/Server/正文前段提取版本；返回 (version, source)。"""
    texts = (("title", asset.title), ("server", asset.server),
             ("body", asset.body_excerpt if hasattr(asset, "body_excerpt") else asset.text[:4096]))
    for source, text in texts:
        for alias in [product, *list(aliases)]:
            alias_re = re.escape(str(alias))
            m = re.search(alias_re + r"\s*(?:[/:]|version\s*)?\s*v?(\d+(?:\.\d+){1,3})",
                          text or "", re.I)
            if m:
                return m.group(1), source
    return "", ""


def _waf_markers(asset: TriageAsset) -> list[dict]:
    out = []
    corpus = " ".join([
        str(asset.server or ""),
        " ".join(f"{k}: {v}" for k, v in (asset.headers or {}).items()),
        (asset.text or "")[:2048],
    ])
    for name, rx in WAF_MARKERS:
        if rx.search(corpus):
            out.append({"name": name, "evidence": "响应头/正文特征", "inferred": True})
    return out


def _detect_products(engine, asset: TriageAsset) -> list[dict]:
    if engine is None:
        return []
    try:
        matches = engine.match(MatchContext(
            url=asset.url, status=asset.status, title=asset.title,
            headers=asset.headers, body=asset.text,
        ))
    except Exception:
        return []
    return [m.to_dict() for m in matches]


def _global_guard(target: TargetDef, assets: Iterable[TriageAsset]):
    allowed = {a.host for a in assets if a.host}
    return lambda h: h in allowed or check_host_in_scope(h, target)


def _urls_for(host: str, port: int) -> list[str]:
    scheme = scheme_for_port(port)
    urls = [build_url(host, port, scheme)]
    if port in HTTPS_FALLBACK_PORTS:
        urls.append(build_url(host, port, "http"))
    return urls


def _fetch_sites(prober: TriageProber, seeds, profile: Profile,
                 budget: TriageBudget, max_hosts: int, body_chars: int,
                 console: Callable[[str], None]) -> tuple[list[TriageAsset], list[str]]:
    warnings: list[str] = []
    hosts: list[str] = []
    explicit_ports: dict[str, set[int]] = {}
    for a in seeds:
        if a.host not in hosts:
            hosts.append(a.host)
        if a.port:
            explicit_ports.setdefault(a.host, set()).add(a.port)
    hosts = hosts[:max_hosts]
    assets: list[TriageAsset] = []
    dead = 0
    for host in hosts:
        ports = sorted(explicit_ports.get(host) or list(profile.probe_ports))
        alive = False
        for port in ports:
            if budget.exhausted:
                break
            for url in _urls_for(host, port):
                try:
                    res = prober.request(url, host, stage="triage-probe")
                except TriageBudgetExceeded:
                    warnings.append("体检请求预算用尽，探测提前停止")
                    return assets, warnings
                except ProbeAborted as e:
                    warnings.append(f"体检探测中止：{e}")
                    return assets, warnings
                if not res:
                    continue
                text = str(res.get("text") or "")
                headers = {str(k).lower(): str(v) for k, v in (res.get("headers") or {}).items()}
                asset = TriageAsset(
                    host=host, port=port, url=str(res.get("url") or url),
                    status=int(res.get("status") or 0), title=extract_title(text),
                    server=str(headers.get("server") or ""), headers=headers,
                    text=text[:body_chars], elapsed_ms=float(res.get("elapsed_ms") or 0),
                    body_len=len(res.get("body") or b""),
                )
                asset.products = _detect_products(prober.engine, asset)
                assets.append(asset)
                alive = True
                break
            if alive:
                break
        if not alive:
            dead += 1
    console(f"    存活主机 {len({a.host for a in assets})} / {len(hosts)}"
            f"（无响应 {dead}）")
    return assets, warnings


def _exposure_candidates(asset: TriageAsset, max_paths: int) -> list[tuple[str, str]]:
    paths: list[tuple[str, str]] = list(GENERIC_PATHS)
    for p in asset.products:
        product = str(p.get("product") or "").lower()
        for key, extra in CMS_PATHS.items():
            if key in product or (key == "wordpress" and "wordpress" in product):
                paths = list(extra) + paths
                break
    seen, out = set(), []
    for category, path in paths:
        if path in seen:
            continue
        seen.add(path)
        out.append((category, path))
        if len(out) >= max_paths:
            break
    return out


def _probe_exposures(prober: TriageProber, assets: list[TriageAsset],
                     max_paths: int, budget: TriageBudget,
                     console: Callable[[str], None]) -> list[dict]:
    out: list[dict] = []
    for asset in assets:
        base = asset.url or build_url(asset.host, asset.port, scheme_for_port(asset.port))
        for category, path in _exposure_candidates(asset, max_paths):
            if budget.exhausted:
                return out
            url = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            try:
                res = prober.request(url, asset.host, stage="triage-exposure")
            except TriageBudgetExceeded:
                return out
            except WafDetected as e:
                blocked = getattr(e, "response", {}) or {}
                text = str(blocked.get("text") or "")
                out.append({
                    "url": url,
                    "category": category,
                    "status": int(blocked.get("status") or 0),
                    "title": extract_title(text),
                    "length": len(blocked.get("body") or b""),
                    "reason": "WAF 拦截（已中止后续阶段）",
                    "inferred": False,
                })
                return out
            except ProbeAborted:
                return out
            if not res:
                continue
            status = int(res.get("status") or 0)
            if status in (404, 410) or status >= 500:
                continue
            text = str(res.get("text") or "")
            item = {
                "url": url,
                "category": category,
                "status": status,
                "title": extract_title(text),
                "length": len(res.get("body") or b""),
                "reason": ("可访问（仅探测状态，未做利用）" if status in (200, 201, 202, 204, 301, 302, 303, 307, 308)
                           else "受保护/未确认"),
                "inferred": True,
            }
            out.append(item)
    if out:
        console(f"    暴露面命中 {len(out)} 条")
    return out


def _tech_items(assets: list[TriageAsset], library: list[dict]) -> list[dict]:
    lib_by_product: dict[str, dict] = {}
    for entry in library:
        for name in [entry.get("product"), *(entry.get("aliases") or [])]:
            if name:
                lib_by_product[str(name).lower()] = entry
    items: list[dict] = []
    seen = set()
    for asset in assets:
        for p in asset.products:
            product = str(p.get("product") or "")
            if not product:
                continue
            entry = lib_by_product.get(product.lower()) or {}
            version, source = _extract_version(product, entry.get("aliases") or [], asset)
            key = (asset.host, product, version)
            if key in seen:
                continue
            seen.add(key)
            items.append({
                "host": asset.host,
                "product": product,
                "version": version,
                "version_source": source,
                "version_observed": bool(version),
                "confidence": float(p.get("confidence") or 0),
                "rule_id": str(p.get("rule_id") or ""),
                "inferred": False,
            })
    items.sort(key=lambda x: (-int(bool(x["version"])), -x["confidence"], x["product"]))
    return items


def _risk_directions(tech: list[dict], library: list[dict]) -> list[dict]:
    lib_by_product: dict[str, dict] = {}
    for entry in library:
        for name in [entry.get("product"), *(entry.get("aliases") or [])]:
            if name:
                lib_by_product[str(name).lower()] = entry
    out: list[dict] = []
    seen = set()
    for item in tech:
        entry = lib_by_product.get(item["product"].lower())
        if not entry:
            continue
        for risk in entry.get("risks") or []:
            direction = str(risk.get("direction") or "")
            if not direction:
                continue
            limit = str(risk.get("version_lt") or "")
            if limit and item["version"] and not _version_lt(item["version"], limit):
                continue
            key = (item["product"], direction)
            if key in seen:
                continue
            seen.add(key)
            basis = f"产品={item['product']}"
            if item["version"]:
                basis += f" 版本={item['version']}（来源：{item['version_source']}）"
            else:
                basis += " 版本未识别"
            if limit:
                basis += f"；参考线 {limit}"
            out.append({
                "product": item["product"],
                "version": item["version"],
                "cves": list(risk.get("cves") or []),
                "direction": direction,
                "severity": str(risk.get("severity") or "medium"),
                "basis": basis,
                "inferred": True,
            })
    out.sort(key=lambda x: ({"high": 0, "medium": 1, "low": 2}.get(x["severity"], 1),
                            x["product"]))
    return out


def _duplicate_risks(tech: list[dict], library: list[dict], disclosures: dict) -> list[dict]:
    hot: dict[str, dict] = {}
    for entry in library:
        if entry.get("hot"):
            for name in [entry.get("product"), *(entry.get("aliases") or [])]:
                if name:
                    hot[str(name).lower()] = entry
    disclosed = [str(x).lower() for x in (disclosures.get("products") or [])]
    out: list[dict] = []
    seen = set()
    for item in tech:
        product = item["product"]
        key = product.lower()
        if key in hot:
            reason = str(hot[key].get("repeat_reason") or "常见热门产品，公开披露多")
            if key not in seen:
                seen.add(key)
                out.append({"product": product, "repeat_probability": "high",
                            "reason": reason, "inferred": True})
        elif any(d and d in key for d in disclosed):
            if key not in seen:
                seen.add(key)
                out.append({"product": product, "repeat_probability": "high",
                            "reason": "命中本地 known_disclosures 已公开披露产品",
                            "inferred": True})
    return out


def _cost(profile: Profile, alive_hosts: int, has_waf: bool,
          has_403: bool) -> dict:
    assets = max(1, alive_hosts)
    probe = assets * len(profile.probe_ports) * (1 + int(profile.probe_retries))
    discover = int(profile.crawl_max_urls) * 2 + int(profile.path_scan_max_paths) * assets + assets
    scan = int(profile.scan_max_urls) * 15
    total = probe + discover + scan
    seconds = round(total / max(1.0, float(profile.requests_per_second)) + 10, 1)
    if has_waf or has_403 or alive_hosts == 0:
        tier = "light"
    elif alive_hosts > 30:
        tier = "deep"
    else:
        tier = "standard"
    return {
        "estimated_requests": total,
        "estimated_seconds": seconds,
        "recommended_tier": tier,
        "basis": "推断：基于 standard profile 的端口/发现/扫描上限与存活主机数；未实际扫描",
        "inferred": True,
    }


def _assess(*, basics: dict, tech: list[dict], exposures: list[dict],
            risks: list[dict], duplicates: list[dict], waf: list[dict],
            budget: TriageBudget) -> dict:
    signals: list[str] = []
    alive = int(basics.get("alive_hosts") or 0)
    if alive == 0:
        return {"verdict": "不建议", "score": -10,
                "reason": "没有存活响应或全部超时，无法形成可决策的体检结论",
                "signals": ["无存活主机"], "inferred": True}
    score = 1
    versioned = sum(1 for x in tech if x.get("version"))
    if versioned:
        score += min(6, 2 * versioned)
        signals.append(f"带版本号的技术栈 {versioned} 个")
    if risks:
        score += min(6, 2 * len(risks))
        signals.append(f"可深挖方向 {len(risks)} 条（推断）")
    confirmed = [e for e in exposures if int(e.get("status") or 0) in (200, 201, 202, 204, 401)]
    cats = {str(e.get("category")) for e in confirmed}
    if cats:
        score += min(6, 2 * len(cats))
        signals.append(f"可访问/受保护的暴露面类别 {len(cats)} 类")
    backup = any(e.get("category") == "backup" and int(e.get("status") or 0) in (200, 201, 202, 204)
                 for e in exposures)
    if backup:
        score += 2
        signals.append("备份文件迹象可访问")
    if waf:
        score -= 4
        signals.append(f"检测到 WAF/CDN {len(waf)} 个")
    if duplicates:
        score -= 3
        signals.append(f"高重复概率产品 {len(duplicates)} 个")
    if not tech:
        score -= 2
        signals.append("未识别到技术栈")
    all_403 = bool(exposures) and all(int(e.get("status") or 0) == 403 for e in exposures)
    if all_403:
        score -= 2
        signals.append("暴露面统一 403/拒绝")
    if not tech and not confirmed:
        score -= 3
        signals.append("无指纹且无可用暴露面（静态/封闭站特征）")
    if alive >= 3:
        score += 1
        signals.append(f"存活主机 {alive} 个")
    if budget.exhausted:
        score -= 1
        signals.append("体检预算用尽，结论基于部分数据")
    if score >= 8:
        verdict = "建议深挖"
        reason = "存在版本化技术栈/可深挖方向/暴露面，值得进入人工复核与正式扫描"
    elif score >= 4:
        verdict = "可试"
        reason = "有一定技术栈或暴露面线索，但证据不足以直接投入正式扫描"
    else:
        verdict = "不建议"
        reason = "技术栈/暴露面/重复风险不足以支撑优先投入，建议先换目标或人工确认"
    return {"verdict": verdict, "score": int(score), "reason": reason,
            "signals": signals, "inferred": True}


def _basics(assets: list[TriageAsset], budget: TriageBudget) -> dict:
    hosts = {a.host for a in assets}
    ports = sorted({a.port for a in assets if a.port})
    statuses = Counter(str(a.status) for a in assets)
    elapsed = [a.elapsed_ms for a in assets if a.elapsed_ms > 0]
    return {
        "alive_hosts": len(hosts),
        "responses": len(assets),
        "ports": ports,
        "status_distribution": dict(statuses),
        "median_response_ms": round(statistics.median(elapsed), 1) if elapsed else None,
        "request_budget": {"limit": budget.limit, "used": budget.used,
                           "exhausted": budget.exhausted},
    }


def _render_md(report: dict) -> str:
    b = report.get("basics") or {}
    lines = [
        "# 目标体检报告", "",
        f"- 目标：{report.get('target')}",
        f"- 生成时间：{report.get('generated_at')}",
        f"- 模式：triage（只做侦察与研判，**零 nuclei/模板扫描**）",
        f"- 请求：{b.get('request_budget', {}).get('used')} / "
        f"{b.get('request_budget', {}).get('limit')}"
        f"{'（已用尽）' if b.get('request_budget', {}).get('exhausted') else ''}",
        "",
        "> 本报告的风险方向、重复概率、成本与结论均为**推断**，不是已发现漏洞；"
        "进入正式扫描前需人工复核授权与范围。", "",
        "## 1. 基础面", "",
        f"- 存活主机：{b.get('alive_hosts', 0)}",
        f"- 端口：{', '.join(str(x) for x in b.get('ports') or []) or '未识别'}",
        f"- 状态码分布：{json.dumps(b.get('status_distribution') or {}, ensure_ascii=False)}",
        f"- 响应耗时中位数：{b.get('median_response_ms') if b.get('median_response_ms') is not None else '-'} ms",
    ]
    tech = report.get("tech") or []
    lines += ["", "## 2. 技术栈（带版本号优先，推断仅用于定向）", ""]
    if tech:
        lines += ["| 主机 | 产品 | 版本 | 来源 | 置信度 |", "|---|---|---|---|---|"]
        for t in tech:
            lines.append(f"| {t['host']} | {t['product']} | {t['version'] or '未识别'} | "
                         f"{t['version_source'] or '-'} | {t['confidence']:.2f} |")
    else:
        lines.append("未识别到技术栈（指纹库未命中或页面特征不足）。")

    lines += ["", "## 3. 暴露面（只探测状态，不做利用）", ""]
    exposures = report.get("exposures") or []
    if exposures:
        lines += ["| 类别 | URL | 状态 | 标题/说明 |", "|---|---|---|---|"]
        for e in exposures:
            lines.append(f"| {e['category']} | {e['url']} | {e['status']} | "
                         f"{e.get('title') or e.get('reason') or '-'} |")
    else:
        lines.append("未发现可记录的暴露面（404/5xx 已跳过）。")

    lines += ["", "## 4. 风险方向（推断，不是漏洞结论）", ""]
    risks = report.get("risks") or []
    if risks:
        for r in risks:
            cves = ("；参考 " + ", ".join(r["cves"])) if r.get("cves") else ""
            lines.append(f"- **{r['product']}**（{r['version'] or '版本未识别'}，"
                         f"{r['severity']}）：{r['direction']}；依据：{r['basis']}{cves}")
    else:
        lines.append("没有匹配到本地离线风险库的方向。")

    lines += ["", "## 5. 重复风险提示（推断）", ""]
    duplicates = report.get("duplicates") or []
    if duplicates:
        for d in duplicates:
            lines.append(f"- **{d['product']}**：高重复概率（{d['reason']}）")
    else:
        lines.append("未命中热门产品/本地已公开披露库。")

    cost = report.get("cost") or {}
    lines += ["", "## 6. 成本预估（推断，未实际扫描）", "",
              f"- 预估请求数：{cost.get('estimated_requests')}",
              f"- 预估耗时：{cost.get('estimated_seconds')} s",
              f"- 建议档位：{cost.get('recommended_tier')}",
              f"- 依据：{cost.get('basis')}"]

    conc = report.get("conclusion") or {}
    lines += ["", "## 7. 结论", "",
              f"**{conc.get('verdict')}**（评分 {conc.get('score')}）：{conc.get('reason')}",
              "", "信号：" + "；".join(conc.get("signals") or [])]
    waf = report.get("waf") or []
    if waf:
        lines += ["", "WAF/CDN：" + "、".join(w["name"] for w in waf)]
    warnings = report.get("warnings") or []
    if warnings:
        lines += ["", "## 警告", ""] + [f"- {w}" for w in warnings]
    return "\n".join(lines) + "\n"


def run_triage(app: AppConfig, target: TargetDef, recon: ReconConfig, *,
               profile_override: str = "light", max_requests: int = 0,
               fresh: bool = False,
               console: Callable[[str], None] = print) -> TriageResult:
    if target.automation_allowed == "no":
        raise TriageError("平台/厂商禁止自动化扫描，拒绝体检（无可覆盖路径）")
    if not target.authorization:
        raise TriageError("缺少授权依据，拒绝体检")
    limit = int(max_requests or recon.triage.max_requests)
    if not (1 <= limit <= 200):
        raise TriageError(f"体检请求上限必须在 1~200，当前 {limit}")
    profile_name = profile_override or "light"
    if profile_name not in recon.profiles:
        raise TriageError(f"未知档位：{profile_name}")
    profile = replace(recon.profiles[profile_name], concurrency=1,
                      probe_retries=0, favicon=False, follow_redirects=False)
    target_dir = recon.target_state_dir(target.name)
    target_dir.mkdir(parents=True, exist_ok=True)
    if fresh:
        for name in ("triage.json", "triage.md", "summary.json"):
            try:
                (target_dir / name).unlink()
            except FileNotFoundError:
                pass
    audit = AuditLog(recon.audit_dir() / "audit.jsonl", target.name,
                     enabled=recon.audit.enabled)
    daily = int(recon.limits.daily_request_limit or app.scan.daily_request_limit or 5000)
    limiter = AdaptiveLimiter(
        rps=profile.requests_per_second, concurrency=1,
        burst=recon.limits.burst, min_rps=recon.limits.min_rps,
        backoff_base=recon.limits.backoff_base, backoff_max=recon.limits.backoff_max,
        failure_threshold=recon.limits.failure_threshold,
        cooldown_s=recon.limits.cooldown_seconds,
    )
    ledger = BudgetLedger(app.db_path, target.name, daily)
    budget = TriageBudget(limit)
    waf_guard = WafGuard(enabled=recon.waf.enabled,
                         stop_after=recon.waf.stop_after,
                         audit=audit, console=console)
    warnings: list[str] = []
    t0 = time.monotonic()
    engine = None
    try:
        engine = FingerprintEngine.from_yaml(
            recon.fingerprint_library(),
            min_confidence=recon.fingerprint.min_confidence,
            weak_match_penalty=recon.fingerprint.weak_match_penalty,
            enable_prefilter=recon.fingerprint.enable_prefilter,
        )
    except Exception as e:
        warnings.append(f"指纹库不可用：{type(e).__name__}")
    ctx = SourceContext(app=app, recon=recon, target=target, profile=profile,
                        limiter=limiter, audit=audit, state=None, console=console)
    seeds = []
    try:
        sources, skipped = build_sources(list(recon.triage.sources), ctx)
        for s in skipped:
            warnings.append(f"跳过数据源 {s['name']}：{s['reason']}")
        for src in sources:
            try:
                got = list(src.fetch(ctx))
            except Exception as e:
                warnings.append(f"数据源 {src.name} 失败：{type(e).__name__}")
                continue
            console(f"    种子 {src.name} 返回 {len(got)} 条")
            seeds.extend(got)
    finally:
        pass
    # 去重（host|port）+ 主机上限；同主机多端口保留
    seen, unique, host_count = set(), [], 0
    seen_hosts = set()
    for a in seeds:
        key = f"{a.host}|{a.port}"
        if key in seen:
            continue
        if a.host not in seen_hosts:
            if host_count >= int(recon.triage.max_hosts):
                break
            seen_hosts.add(a.host)
            host_count += 1
        seen.add(key)
        unique.append(a)
    if not unique:
        warnings.append("没有可用种子资产（seed/import 均为空）")
    if target.domains or target.ips:
        guard = lambda h: check_host_in_scope(h, target)
    else:
        allowed_hosts = {a.host for a in unique if "import" in (a.sources or [])}
        guard = lambda h: h in allowed_hosts
    prober = TriageProber(
        recon=recon, target=target, profile=profile, limiter=limiter,
        ledger=ledger, audit=audit, engine=engine, console=console,
        in_scope=guard, budget=budget, waf_guard=waf_guard,
    )
    assets, fetch_warn = _fetch_sites(prober, unique, profile, budget,
                                      int(recon.triage.max_hosts),
                                      int(recon.triage.max_body_chars), console)
    warnings.extend(fetch_warn)
    exposures = _probe_exposures(prober, assets, int(recon.triage.max_exposure_paths),
                                 budget, console) if assets else []
    library = _load_risk_library()
    tech = _tech_items(assets, library)
    risks = _risk_directions(tech, library)
    duplicates = _duplicate_risks(tech, library, load_disclosures(recon))
    waf = []
    for a in assets:
        for marker in _waf_markers(a):
            if marker not in waf:
                waf.append(marker)
    if waf_guard.stopped:
        info = waf_guard.to_dict()
        waf.append({
            "name": "waf-stop",
            "evidence": "WAF 拦截，体检提前中止",
            "url": info.get("url", ""),
            "status": info.get("status", 0),
            "markers": info.get("markers", []),
            "inferred": False,
        })
        warnings.append(
            f"WAF 拦截（{info.get('stage', '')} 阶段），当前目标中止后续阶段")
    basics = _basics(assets, budget)
    formal = recon.profiles.get("standard") or profile
    has_403 = bool(exposures) and all(int(e.get("status") or 0) == 403 for e in exposures)
    cost = _cost(formal, int(basics["alive_hosts"]), bool(waf), has_403)
    conclusion = _assess(basics=basics, tech=tech, exposures=exposures,
                         risks=risks, duplicates=duplicates, waf=waf,
                         budget=budget)
    elapsed = round(time.monotonic() - t0, 2)
    report = {
        "schema": "recon.triage/v1",
        "mode": "triage",
        "target": target.name,
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "elapsed_s": elapsed,
        "basics": basics,
        "tech": tech,
        "exposures": exposures,
        "risks": risks,
        "duplicates": duplicates,
        "waf": waf,
        "cost": cost,
        "conclusion": conclusion,
        "warnings": warnings,
        "status": "waf_stop" if waf_guard.stopped else "done",
        "waf_stop": waf_guard.to_dict(),
        "audit": {"path": str(audit.path), "records": audit.count(),
                  "degraded": audit.degraded},
        "inferred_fields": ["risks", "duplicates", "cost", "conclusion", "waf"],
    }
    md_path = target_dir / "triage.md"
    json_path = target_dir / "triage.json"
    summary_path = target_dir / "summary.json"
    report["paths"] = {"md": str(md_path), "json": str(json_path)}
    md_path.write_text(_render_md(report), encoding="utf-8")
    json_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    summary = {
        "schema": "recon.summary/v1", "kind": "triage",
        "target": target.name, "vendor": target.vendor,
        "generated_at": report["generated_at"], "elapsed_s": elapsed,
        "profile": {"name": profile.name},
        "assets": {"total": len(unique), "alive": basics["alive_hosts"]},
        "findings": {"total": 0},
        "probe": {"requests": budget.used, "alive": basics["alive_hosts"],
                  "duration_s": elapsed,
                  "effective_rps": round(budget.used / elapsed, 2) if elapsed else 0,
                  "limiter": limiter.snapshot()},
        "triage": {"verdict": conclusion["verdict"], "score": conclusion["score"],
                   "suspects": 0, "paths": report["paths"]},
        "warnings": warnings,
    }
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    console(f"    体检结论：{conclusion['verdict']}（评分 {conclusion['score']}）")
    console(f"    报告：{md_path}")
    limiter.close() if hasattr(limiter, "close") else None
    ledger.close()
    return TriageResult(report=report, summary=summary,
                        paths={"md": str(md_path), "json": str(json_path),
                               "summary": str(summary_path)},
                        warnings=warnings)
