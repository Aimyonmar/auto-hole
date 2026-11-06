# -*- coding: utf-8 -*-
"""recon 独立配置（config/recon.yaml）加载与校验。

原则：
- 不覆盖主项目 config.yaml，recon 只读自己的配置
- 所有可调参数都有内置默认值，配置文件缺失也能跑（默认温和档）
- 任何速率/路径参数在加载时校验，越界直接报错（不静默修正）
"""
from __future__ import annotations

from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Optional

import yaml

from core.config import ROOT
from .ratelimit import RateConfigError, validate_limits

DEFAULT_CONFIG_PATH = ROOT / "config" / "recon.yaml"


class ReconConfigError(ValueError):
    """recon 配置非法。"""


@dataclass
class Profile:
    """分级扫描策略（light/standard/deep）。"""
    name: str = "standard"
    concurrency: int = 8
    requests_per_second: float = 20.0
    probe_ports: list = field(default_factory=lambda: [80, 443, 8080, 8443,
                                                       8000, 8888, 9090, 7001, 7002])
    probe_timeout: float = 10.0
    probe_retries: int = 1
    max_hosts: int = 2000
    max_body_bytes: int = 262144          # 256 KB，指纹只看正文前段
    follow_redirects: bool = True
    favicon: bool = False                 # 额外请求 /favicon.ico，默认关（省请求）
    max_urls_per_host: int = 1            # 每主机探测的 URL 上限（后续可扩路径）
    scan_enabled: bool = False
    scan_severity: str = "medium,high,critical"
    scan_tags_include: list = field(default_factory=lambda: [
        "cve", "rce", "unauth", "default-login", "exposure", "upload", "deserialization"])
    scan_tags_exclude: list = field(default_factory=lambda: ["dos", "fuzz","intrusive"])
    scan_max_urls: int = 500
    scan_grouped: bool = True             # 按产品分组定向扫描（提高命中率、省配额）
    scan_unidentified: bool = False       # 未识别产品的资产是否仍按默认模板扫（默认不扫省配额）
    scan_max_groups: int = 50
    # ---- URL/路径/参数发现（主动行为，默认 light 档最保守） ----
    discover_enabled: bool = True
    crawl_depth: int = 1                  # 爬取深度
    crawl_max_urls: int = 30              # 单目标最多发现 URL 数
    crawl_concurrency: int = 2            # 爬取并发（同时受 profile.concurrency 约束）
    crawl_same_origin: bool = True        # 仅同源
    js_extract: bool = True               # JS 端点/参数提取
    path_scan_enabled: bool = True
    path_scan_max_paths: int = 20         # 字典探测条数

    def to_dict(self) -> dict:
        return dict(self.__dict__)


BUILTIN_PROFILES: dict[str, Profile] = {
    "light": Profile(
        name="light", concurrency=3, requests_per_second=5.0,
        probe_ports=[80, 443], probe_timeout=8.0, probe_retries=1,
        max_hosts=300, scan_enabled=False,
        scan_max_urls=100, scan_severity="high,critical",
        scan_tags_include=["cve", "rce", "unauth", "default-login", "exposure"],
        scan_tags_exclude=["dos", "fuzz", "intrusive"],
    ),
    "standard": Profile(
        name="standard", concurrency=8, requests_per_second=20.0,
        probe_ports=[80, 443, 8080, 8443, 8000, 8888, 9090, 7001, 7002],
        probe_timeout=10.0, probe_retries=1, max_hosts=2000,
        scan_enabled=False,
        crawl_depth=2, crawl_max_urls=200, crawl_concurrency=4,
        path_scan_max_paths=60,
    ),
    "deep": Profile(
        name="deep", concurrency=16, requests_per_second=50.0,
        probe_ports=[80, 443, 8080, 8443, 8000, 8001, 8081, 8888, 9090, 7001, 7002],
        probe_timeout=12.0, probe_retries=2, max_hosts=8000,
        scan_enabled=True, scan_max_urls=1000,
        crawl_depth=3, crawl_max_urls=800, crawl_concurrency=8,
        path_scan_max_paths=120,
    ),
}


@dataclass
class SourcesConfig:
    enabled: list = field(default_factory=lambda: ["seed", "subfinder", "hunter", "import"])
    plugins_dir: str = ""                     # 额外插件目录（可选），相对项目根
    import_dir: str = "workspace/import"      # 外部资产清单目录（<target>.txt）
    path_dict: str = "modules/recon/dicts/sensitive_paths.txt"
    subfinder: dict = field(default_factory=lambda: {
        "all_sources": True, "timeout": 600, "resolve": True,
    })
    hunter: dict = field(default_factory=lambda: {
        "max_records": 1000, "allow_guest": True,
    })


@dataclass
class ProbeSettings:
    connect_timeout: float = 5.0
    max_redirects: int = 5
    user_agent: str = "auto-hole-recon/1.0 (authorized security testing)"
    verify_tls: bool = False                 # 授权测试目标常见自签证书
    min_delay_ms: int = 0                    # 每个请求额外固定延迟
    trust_env: bool = False                  # 不继承系统代理环境变量（保证可控与可复现）


@dataclass
class FingerprintConfig:
    library: str = "modules/recon/fingerprints/builtin.yaml"
    min_confidence: float = 0.6
    weak_match_penalty: float = 0.7
    body_limit: int = 262144
    enable_prefilter: bool = True


@dataclass
class LimitsConfig:
    daily_request_limit: Optional[int] = None   # None → 沿用主配置 scan.daily_request_limit
    burst: int = 1
    min_rps: float = 2.0
    backoff_base: float = 0.5
    backoff_max: float = 8.0
    failure_threshold: int = 8
    cooldown_seconds: float = 60.0


@dataclass
class AuditConfig:
    enabled: bool = True
    path: str = "workspace/recon"             # 目录，实际文件为 <dir>/audit.jsonl


@dataclass
class ValueConfig:
    """价值评分参数（决定“先提交哪个”）。"""
    generic_bonus: float = 10.0               # 通用1.0（产品可复用）加分
    public_bonus: float = 0.0                 # 公益SRC 加分
    min_score_for_evidence: float = 40.0      # 低于该分不生成证据包
    min_score_to_submit: float = 45.0         # 低于该分建议不提交
    evidence_enabled: bool = True             # 运行结束自动生成证据包


@dataclass
class StateConfig:
    dir: str = "workspace/recon"


@dataclass
class AuthzConfig:
    """只读越权检测（GET only）的全局默认值；账号元数据按目标存放。"""
    enabled: bool = True                 # false 时即使有账号也不自动跑
    auto_run: bool = True                # all 阶段发现账号元数据时自动执行
    max_requests: int = 200              # 每目标本次越权请求上限（含预检/采集/重放）
    similarity_threshold: float = 0.90   # 判定疑似越权的内容相似度
    public_similarity: float = 0.92      # 匿名访问与 A 的相似度达到此值 → 公共页抑制
    max_candidates: int = 100
    max_vertical_paths: int = 30
    max_collect_pages: int = 10
    response_truncate: int = 400         # 证据响应截断字符数
    accounts_dir: str = "targets/authz"
    vault_path: str = "workspace/authz/vault.enc"
    key_path: str = "workspace/authz/vault.key"
    vertical_paths: list = field(default_factory=list)


@dataclass
class TriageConfig:
    """目标体检：只做侦察/研判，零扫描请求。"""
    max_requests: int = 60             # 每目标体检请求上限（独立预算）
    max_hosts: int = 50
    max_exposure_paths: int = 12       # 每个存活主机最多探测的暴露面路径
    sources: list = field(default_factory=lambda: ["seed", "import"])
    max_body_chars: int = 4096         # 版本/暴露面研判只读前 4KB，不存原文


@dataclass
class WafConfig:
    """WAF 拦截自动中止：默认首次识别即停。"""
    enabled: bool = True
    stop_after: int = 1                # 1=首次；N=累计 N 次命中后停


@dataclass
class ReconConfig:
    version: int = 1
    profile: str = "standard"
    profiles: dict = field(default_factory=lambda: dict(BUILTIN_PROFILES))
    sources: SourcesConfig = field(default_factory=SourcesConfig)
    probe: ProbeSettings = field(default_factory=ProbeSettings)
    fingerprint: FingerprintConfig = field(default_factory=FingerprintConfig)
    limits: LimitsConfig = field(default_factory=LimitsConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    value: ValueConfig = field(default_factory=ValueConfig)
    state: StateConfig = field(default_factory=StateConfig)
    authz: AuthzConfig = field(default_factory=AuthzConfig)
    triage: TriageConfig = field(default_factory=TriageConfig)
    waf: WafConfig = field(default_factory=WafConfig)
    config_path: str = ""

    # ---- 路径 ----
    def abs_path(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else ROOT / p

    def active_profile(self) -> Profile:
        prof = self.profiles.get(self.profile)
        if prof is None:
            raise ReconConfigError(
                f"未知 profile: {self.profile}（可选 {sorted(self.profiles)}）")
        return prof

    def fingerprint_library(self) -> Path:
        return self.abs_path(self.fingerprint.library)

    def audit_dir(self) -> Path:
        return self.abs_path(self.audit.path)

    def state_dir(self) -> Path:
        return self.abs_path(self.state.dir)

    def target_state_dir(self, target_name: str) -> Path:
        return self.state_dir() / _safe_name(target_name)


def _safe_name(name: str) -> str:
    """目标名转安全目录名（避免路径穿越）。"""
    keep = [c for c in str(name) if c.isalnum() or c in "-_."]
    return "".join(keep)[:64] or "target"


def _merge_dict(base: dict, override: dict) -> dict:
    out = dict(base)
    out.update(override or {})
    return out


def _profile_from_dict(name: str, raw: dict, base: Optional[Profile]) -> Profile:
    b = base or Profile(name=name)
    allowed = {k: v for k, v in (raw or {}).items() if k in Profile.__dataclass_fields__}
    return replace(b, name=name, **allowed)


def load_recon_config(path: str | Path | None = None,
                      profile_override: str | None = None) -> ReconConfig:
    """加载 config/recon.yaml；不存在则使用内置默认（不写文件）。"""
    p = Path(path) if path else DEFAULT_CONFIG_PATH
    raw: dict = {}
    if p.exists():
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        if not isinstance(raw, dict):
            raise ReconConfigError(f"{p} 顶层必须是字典")

    profiles = dict(BUILTIN_PROFILES)
    for name, override in (raw.get("profiles") or {}).items():
        profiles[str(name)] = _profile_from_dict(str(name), override or {}, profiles.get(str(name)))

    cfg = ReconConfig(
        version=int(raw.get("version", 1)),
        profile=str(profile_override or raw.get("profile") or "standard"),
        profiles=profiles,
        sources=SourcesConfig(**_merge_dict(
            {k: getattr(SourcesConfig(), k) for k in SourcesConfig.__dataclass_fields__},
            raw.get("sources") or {})),
        probe=ProbeSettings(**_merge_dict(
            {k: getattr(ProbeSettings(), k) for k in ProbeSettings.__dataclass_fields__},
            raw.get("probe") or {})),
        fingerprint=FingerprintConfig(**_merge_dict(
            {k: getattr(FingerprintConfig(), k) for k in FingerprintConfig.__dataclass_fields__},
            raw.get("fingerprint") or {})),
        limits=LimitsConfig(**_merge_dict(
            {k: getattr(LimitsConfig(), k) for k in LimitsConfig.__dataclass_fields__},
            raw.get("limits") or {})),
        audit=AuditConfig(**_merge_dict(
            {k: getattr(AuditConfig(), k) for k in AuditConfig.__dataclass_fields__},
            raw.get("audit") or {})),
        value=ValueConfig(**_merge_dict(
            {k: getattr(ValueConfig(), k) for k in ValueConfig.__dataclass_fields__},
            raw.get("value") or {})),
        state=StateConfig(**_merge_dict(
            {k: getattr(StateConfig(), k) for k in StateConfig.__dataclass_fields__},
            raw.get("state") or {})),
        authz=AuthzConfig(**_merge_dict(
            {k: getattr(AuthzConfig(), k) for k in AuthzConfig.__dataclass_fields__},
            raw.get("authz") or {})),
        triage=TriageConfig(**_merge_dict(
            {k: getattr(TriageConfig(), k) for k in TriageConfig.__dataclass_fields__},
            raw.get("triage") or {})),
        waf=WafConfig(**_merge_dict(
            {k: getattr(WafConfig(), k) for k in WafConfig.__dataclass_fields__},
            raw.get("waf") or {})),
        config_path=str(p) if p.exists() else "",
    )
    validate_recon_config(cfg)
    return cfg


def validate_recon_config(cfg: ReconConfig) -> None:
    """配置合法性校验：越界即抛，不静默修正。"""
    prof = cfg.active_profile()
    try:
        validate_limits(int(prof.concurrency), float(prof.requests_per_second))
    except RateConfigError as e:
        raise ReconConfigError(f"profile {prof.name}: {e}") from e

    if prof.probe_retries < 0 or prof.probe_retries > 5:
        raise ReconConfigError(f"probe_retries 必须在 0~5，当前 {prof.probe_retries}")
    if prof.probe_timeout <= 0 or prof.probe_timeout > 60:
        raise ReconConfigError(f"probe_timeout 必须在 (0, 60]，当前 {prof.probe_timeout}")
    if not prof.probe_ports or any(not (0 < int(p) < 65536) for p in prof.probe_ports):
        raise ReconConfigError(f"probe_ports 非法: {prof.probe_ports}")
    if prof.max_hosts <= 0:
        raise ReconConfigError(f"max_hosts 必须 > 0，当前 {prof.max_hosts}")

    fp = cfg.fingerprint
    if not (0.0 <= fp.min_confidence <= 1.0):
        raise ReconConfigError(f"min_confidence 必须在 [0,1]，当前 {fp.min_confidence}")
    if not (0.0 < fp.weak_match_penalty <= 1.0):
        raise ReconConfigError(f"weak_match_penalty 必须在 (0,1]，当前 {fp.weak_match_penalty}")
    if fp.body_limit <= 0:
        raise ReconConfigError(f"body_limit 必须 > 0，当前 {fp.body_limit}")

    az = cfg.authz
    if not (1 <= int(az.max_requests) <= 1000):
        raise ReconConfigError(f"authz.max_requests 必须在 1~1000，当前 {az.max_requests}")
    if not (0.5 <= float(az.similarity_threshold) <= 1.0):
        raise ReconConfigError(
            f"authz.similarity_threshold 必须在 [0.5,1.0]，当前 {az.similarity_threshold}")
    if not (0.5 <= float(az.public_similarity) <= 1.0):
        raise ReconConfigError(
            f"authz.public_similarity 必须在 [0.5,1.0]，当前 {az.public_similarity}")
    if not (1 <= int(az.max_candidates) <= 500):
        raise ReconConfigError(f"authz.max_candidates 必须在 1~500，当前 {az.max_candidates}")
    if not (1 <= int(az.max_vertical_paths) <= 100):
        raise ReconConfigError(
            f"authz.max_vertical_paths 必须在 1~100，当前 {az.max_vertical_paths}")
    if not (1 <= int(az.max_collect_pages) <= 30):
        raise ReconConfigError(
            f"authz.max_collect_pages 必须在 1~30，当前 {az.max_collect_pages}")
    if not (80 <= int(az.response_truncate) <= 2000):
        raise ReconConfigError(
            f"authz.response_truncate 必须在 80~2000，当前 {az.response_truncate}")
    for rel in (az.accounts_dir, az.vault_path, az.key_path):
        ap = cfg.abs_path(rel)
        if ROOT not in ap.parents and ap != ROOT:
            raise ReconConfigError(f"authz 路径 {ap} 逃出项目目录")

    tr = cfg.triage
    if not (1 <= int(tr.max_requests) <= 200):
        raise ReconConfigError(f"triage.max_requests 必须在 1~200，当前 {tr.max_requests}")
    if not (1 <= int(tr.max_hosts) <= 200):
        raise ReconConfigError(f"triage.max_hosts 必须在 1~200，当前 {tr.max_hosts}")
    if not (1 <= int(tr.max_exposure_paths) <= 50):
        raise ReconConfigError(
            f"triage.max_exposure_paths 必须在 1~50，当前 {tr.max_exposure_paths}")
    bad_sources = set(tr.sources or []) - {"seed", "import"}
    if bad_sources:
        raise ReconConfigError(
            f"triage.sources 只允许 seed/import（被动/本地清单），当前多出 {sorted(bad_sources)}")
    if not (512 <= int(tr.max_body_chars) <= 131072):
        raise ReconConfigError(
            f"triage.max_body_chars 必须在 512~131072，当前 {tr.max_body_chars}")

    wa = cfg.waf
    if not (1 <= int(wa.stop_after) <= 10):
        raise ReconConfigError(f"waf.stop_after 必须在 1~10，当前 {wa.stop_after}")

    lim = cfg.limits
    if lim.daily_request_limit is not None and lim.daily_request_limit <= 0:
        raise ReconConfigError(f"daily_request_limit 必须 > 0，当前 {lim.daily_request_limit}")
    if lim.min_rps <= 0:
        raise ReconConfigError(f"min_rps 必须 > 0，当前 {lim.min_rps}")
    if lim.failure_threshold <= 0:
        raise ReconConfigError(f"failure_threshold 必须 > 0，当前 {lim.failure_threshold}")

    # 路径必须落在项目内（与宪法第7条一致）
    for rel in (cfg.fingerprint.library, cfg.audit.path, cfg.state.dir,
                cfg.sources.plugins_dir, cfg.sources.import_dir, cfg.sources.path_dict):
        if not rel:
            continue
        ap = cfg.abs_path(rel)
        if ROOT not in ap.resolve().parents and ap.resolve() != ROOT:
            raise ReconConfigError(f"路径 {ap} 逃出项目目录，禁止")
