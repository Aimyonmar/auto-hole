# -*- coding: utf-8 -*-
"""任务执行所需的 CLI 配置：开发态复用项目配置；打包态在 exe 同级生成无凭据配置。"""
from __future__ import annotations

from pathlib import Path

import yaml

SAFE_CONFIG = {
    "hunter": {"api_key": "", "page_size": 100, "max_records": 1000,
               "quota_alert_ratio": 0.8},
    "llm": {"base_url": "https://open.bigmodel.cn/api/paas/v4/chat/completions",
            "api_key": "", "model": "glm-4-flash", "timeout": 60},
    "scan": {"concurrency": 8, "daily_request_limit": 5000,
             "authorization_ref": "", "evidence_mode": "strict_readonly",
             "severity": "info,low,medium,high,critical",
             "tags_include": ["cve", "rce", "unauth", "exposure", "lfi"],
             "tags_exclude": ["dos", "fuzz"], "weak_password": True},
    "paths": {"tools_dir": "_internal/tools",
              "nuclei_templates": "_internal/tools/nuclei-templates",
              "nuclei_templates_base": "_internal/tools/nuclei-templates-engage/base",
              "workspace": "workspace", "reports": "reports",
              "db": "workspace/autohole.db"},
}

SAFE_RECON = {
    "version": 1, "profile": "light",
    # 面板可选档位只有 light / standard；deep 仅供 CLI 显式使用。
    "profiles": {
        "light": {"concurrency": 3, "requests_per_second": 5, "probe_ports": [80, 443],
                  "probe_timeout": 8, "probe_retries": 1, "max_hosts": 300,
                  "scan_enabled": False, "scan_severity": "high,critical",
                  "scan_max_urls": 100, "scan_max_groups": 20},
        "standard": {"concurrency": 8, "requests_per_second": 20,
                     "probe_ports": [80, 443, 8080, 8443], "probe_timeout": 10,
                     "probe_retries": 1, "max_hosts": 2000,
                     "scan_enabled": False, "scan_max_urls": 500},
        "deep": {"concurrency": 16, "requests_per_second": 50,
                 "probe_ports": [80, 443, 8080, 8443, 8000, 9090], "probe_timeout": 12,
                 "probe_retries": 2, "max_hosts": 8000, "scan_enabled": True,
                 "scan_max_urls": 1000},
    },
    "sources": {"enabled": ["seed"], "import_dir": "workspace/import",
                "path_dict": "_internal/modules/recon/dicts/sensitive_paths.txt"},
    "probe": {"connect_timeout": 3, "max_redirects": 5,
              "user_agent": "auto-hole-recon/1.0 (authorized security testing)",
              "verify_tls": False,
              "min_delay_ms": 0, "trust_env": False},
    "fingerprint": {"library": "_internal/modules/recon/fingerprints/builtin.yaml",
                    "min_confidence": 0.6, "weak_match_penalty": 0.7,
                    "body_limit": 262144, "enable_prefilter": True},
    "limits": {"daily_request_limit": 5000, "burst": 1, "min_rps": 1,
               "backoff_base": 0.5, "backoff_max": 4, "failure_threshold": 8,
               "cooldown_seconds": 60},
    "audit": {"enabled": True, "path": "workspace/recon"},
    "value": {"generic_bonus": 10, "public_bonus": 0,
              "min_score_for_evidence": 40, "min_score_to_submit": 45,
              "evidence_enabled": True},
    "state": {"dir": "workspace/recon"},
    "authz": {"enabled": True, "auto_run": True, "max_requests": 200,
              "similarity_threshold": 0.90, "public_similarity": 0.92,
              "max_candidates": 100, "max_vertical_paths": 30,
              "max_collect_pages": 10, "response_truncate": 400,
              "accounts_dir": "targets/authz",
              "vault_path": "workspace/authz/vault.enc",
              "key_path": "workspace/authz/vault.key", "vertical_paths": []},
    "triage": {"max_requests": 60, "max_hosts": 50,
               "max_exposure_paths": 12,
               "sources": ["seed", "import"], "max_body_chars": 4096},
    "waf": {"enabled": True, "stop_after": 1},
}


RECON_HEADER = (
    "# 面板可选档位：light / standard（与 dashboard/jobs.py 一致）；"
    "deep 仅供 CLI 显式使用。\n"
    "# standard.scan_enabled=false 为现状保留；batch/面板任务会按清单显式打开扫描。\n"
)


def ensure_runtime_configs(app_dir: Path, *, frozen: bool) -> tuple[Path, Path]:
    """返回 (主配置, recon 配置)；打包态仅在缺失时生成，绝不覆盖用户已有配置。"""
    app_dir = Path(app_dir)
    cfg = app_dir / "config.yaml"
    recon = app_dir / "config" / "recon.yaml"
    if frozen:
        if not cfg.exists():
            cfg.write_text(yaml.safe_dump(SAFE_CONFIG, allow_unicode=True,
                                          sort_keys=False), encoding="utf-8")
        if not recon.exists():
            recon.parent.mkdir(parents=True, exist_ok=True)
            recon.write_text(RECON_HEADER + yaml.safe_dump(SAFE_RECON, allow_unicode=True,
                                                           sort_keys=False), encoding="utf-8")
    return cfg, recon
