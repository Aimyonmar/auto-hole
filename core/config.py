# -*- coding: utf-8 -*-
"""配置加载与校验。

宪法（CONSTITUTION.md）硬约束在此落地：
- 并发/日请求：不再写死 20/5000，改为“按授权范围可配置”
  * 默认温和档（8 并发 / 5000 日请求）
  * 超过温和档（>20 并发 或 >5000 日请求）必须填写 scan.authorization_ref（授权依据）
  * 代码级绝对上限（64 并发 / 100000 日请求）不可突破，杜绝无界并发
- scan.evidence_mode 只允许 strict_readonly / temp_file_cleanup（宪法第2条）
- tags_exclude 必须包含 dos、fuzz（宪法第2条）
"""
from __future__ import annotations

import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import List

import yaml

# 打包（PyInstaller）后以 exe 所在目录为项目根，保证配置/工作区可写；
# 开发态保持源码根目录不变。
ROOT = (Path(sys.executable).resolve().parent if getattr(sys, "frozen", False)
        else Path(__file__).resolve().parent.parent)

# ---- 温和档（默认口径，不填授权依据时的天花板） ----
GENTLE_CONCURRENCY = 20             # 宪法第3条：温和档并发
GENTLE_DAILY_REQUESTS = 5000        # 宪法第3条：温和档单目标日请求

# ---- 代码级绝对上限（任何配置/参数都不能突破，保证“有界”） ----
ABSOLUTE_MAX_CONCURRENCY = 64       # 禁止无界并发
ABSOLUTE_MAX_DAILY_REQUESTS = 100000

ALLOWED_EVIDENCE_MODES = {"strict_readonly", "temp_file_cleanup"}  # 宪法第2条
MANDATORY_EXCLUDED_TAGS = {"dos", "fuzz"}                          # 宪法第2条


class ConstitutionViolation(Exception):
    """配置违反宪法时抛出。"""


@dataclass
class HunterConfig:
    api_key: str = ""
    page_size: int = 100
    max_records: int = 1000
    quota_alert_ratio: float = 0.8


@dataclass
class LLMConfig:
    base_url: str = "https://open.bigmodel.cn/api/paas/v4/chat/completions"
    api_key: str = ""
    model: str = "glm-4-flash"
    timeout: int = 60


@dataclass
class ScanConfig:
    concurrency: int = 8                  # 默认温和档（首次对新目标不高于 8）
    daily_request_limit: int = 5000
    authorization_ref: str = ""           # 超出温和档时必须填写：授权依据（链接/编号）
    evidence_mode: str = "strict_readonly"
    severity: str = "medium,high,critical"
    tags_include: List[str] = field(default_factory=lambda: [
        "cve", "rce", "unauth", "default-login", "exposure", "upload", "deserialization",
    ])
    tags_exclude: List[str] = field(default_factory=lambda: ["dos", "fuzz"])
    weak_password: bool = True


@dataclass
class PathsConfig:
    tools_dir: str = "tools"
    nuclei_templates: str = "tools/nuclei-templates"
    nuclei_templates_base: str = "tools/nuclei-templates-engage/base"
    workspace: str = "workspace"
    reports: str = "reports"
    db: str = "workspace/autohole.db"


@dataclass
class AppConfig:
    hunter: HunterConfig = field(default_factory=HunterConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    scan: ScanConfig = field(default_factory=ScanConfig)
    paths: PathsConfig = field(default_factory=PathsConfig)
    _raw: dict = field(default_factory=dict)

    # ---- 路径解析（全部项目内，宪法第7条） ----
    def abs_path(self, rel: str) -> Path:
        p = Path(rel)
        return p if p.is_absolute() else ROOT / p

    @property
    def tools_dir(self) -> Path:
        return self.abs_path(self.paths.tools_dir)

    @property
    def nuclei_templates_dir(self) -> Path:
        return self.abs_path(self.paths.nuclei_templates)

    @property
    def nuclei_templates_base_dir(self) -> Path:
        return self.abs_path(self.paths.nuclei_templates_base)

    @property
    def workspace_dir(self) -> Path:
        return self.abs_path(self.paths.workspace)

    @property
    def reports_dir(self) -> Path:
        return self.abs_path(self.paths.reports)

    @property
    def db_path(self) -> Path:
        return self.abs_path(self.paths.db)

    def tool_path(self, name: str) -> Path:
        """返回项目内工具二进制路径（宪法第7条：不依赖系统 PATH）。"""
        return self.tools_dir / f"{name}.exe" if _is_windows() else self.tools_dir / name


def _is_windows() -> bool:
    import sys
    return sys.platform.startswith("win")


def enforce_constitution(cfg: AppConfig) -> None:
    """宪法硬校验：任何越线配置直接抛异常，任务不允许启动。"""
    scan = cfg.scan
    if scan.concurrency <= 0:
        raise ConstitutionViolation(f"宪法第3条：并发必须为正整数，当前 {scan.concurrency}")
    if scan.concurrency > ABSOLUTE_MAX_CONCURRENCY:
        raise ConstitutionViolation(
            f"宪法第3条：并发 {scan.concurrency} 超过代码级绝对上限 "
            f"{ABSOLUTE_MAX_CONCURRENCY}（禁止无界并发）")
    if scan.daily_request_limit <= 0:
        raise ConstitutionViolation(
            f"宪法第3条：单目标日请求上限必须 > 0，当前 {scan.daily_request_limit}")
    if scan.daily_request_limit > ABSOLUTE_MAX_DAILY_REQUESTS:
        raise ConstitutionViolation(
            f"宪法第3条：单目标日请求上限 {scan.daily_request_limit} 超过代码级绝对上限 "
            f"{ABSOLUTE_MAX_DAILY_REQUESTS}")
    # 超出温和档必须写明授权依据（“按授权范围可配置”，而不是随便放宽）
    if (scan.concurrency > GENTLE_CONCURRENCY
            or scan.daily_request_limit > GENTLE_DAILY_REQUESTS) \
            and not str(scan.authorization_ref or "").strip():
        raise ConstitutionViolation(
            f"宪法第3条：并发 {scan.concurrency} / 日请求 {scan.daily_request_limit} 超出温和档"
            f"（{GENTLE_CONCURRENCY}/{GENTLE_DAILY_REQUESTS}），必须在 scan.authorization_ref "
            f"填写对应授权依据")
    if scan.evidence_mode not in ALLOWED_EVIDENCE_MODES:
        raise ConstitutionViolation(
            f"宪法第2条：非法取证模式 {scan.evidence_mode}，允许值 {ALLOWED_EVIDENCE_MODES}")
    if not MANDATORY_EXCLUDED_TAGS.issubset(set(scan.tags_exclude)):
        raise ConstitutionViolation(
            f"宪法第2条：tags_exclude 必须包含 {sorted(MANDATORY_EXCLUDED_TAGS)}")
    # 宪法第7条：任何配置路径不得逃出项目目录
    for rel in (cfg.paths.tools_dir, cfg.paths.nuclei_templates,
                cfg.paths.nuclei_templates_base,
                cfg.paths.workspace, cfg.paths.reports, cfg.paths.db):
        ap = cfg.abs_path(rel)
        if ROOT not in ap.parents and ap != ROOT:
            raise ConstitutionViolation(
                f"宪法第7条：路径 {ap} 逃出项目目录，禁止")


def load_config(path: str | Path | None = None) -> AppConfig:
    """加载 config.yaml；不存在则从 example 生成提示。"""
    cfg_path = Path(path) if path else ROOT / "config.yaml"
    if not cfg_path.exists():
        example = ROOT / "config.example.yaml"
        if not cfg_path.exists() and example.exists():
            shutil.copy(example, cfg_path)
            raise SystemExit(
                f"[!] 已从模板生成 {cfg_path}，请填写 hunter.api_key / llm.api_key 后重试")
        raise SystemExit(f"[!] 配置文件不存在: {cfg_path}")

    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    cfg = AppConfig(
        hunter=HunterConfig(**(raw.get("hunter") or {})),
        llm=LLMConfig(**(raw.get("llm") or {})),
        scan=ScanConfig(**(raw.get("scan") or {})),
        paths=PathsConfig(**(raw.get("paths") or {})),
        _raw=raw,
    )
    enforce_constitution(cfg)  # 宪法守门：不合法配置在这里死掉
    return cfg
