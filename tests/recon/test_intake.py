# -*- coding: utf-8 -*-
"""目标接入模板：字段校验、规范化、dry-run 零请求、emit 兼容性。"""
import subprocess
from pathlib import Path

import pytest
import yaml

from core.config import AppConfig, PathsConfig
from core.constitution import load_target

from modules.recon import intake as intake_mod
from modules.recon.config import load_recon_config


def _app(tmp_path) -> AppConfig:
    return AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                       reports=str(tmp_path / "rp"),
                                       db=str(tmp_path / "ws" / "d.db")))


def _write(tmp_path, **over) -> Path:
    data = {
        "name": "demo", "vendor": "某某科技有限公司",
        "program_url": "https://www.butian.net/Company/12345",
        "authorization_ref": "项目页已报名通过",
        "scope": {"domains": ["  https://a.example.com/ ", "A.example.com", "*.example.com"],
                  "ips": ["1.2.3.4"], "include_subdomains": False,
                  "include_third_party": False},
        "restrictions": {"raw": "禁止破坏性测试", "automation_allowed": "unstated"},
        "tier": "light", "test_accounts": [],
    }
    data.update(over)
    p = tmp_path / "target.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    return p


def test_template_file_itself_is_rejected():
    import yaml
    from core.config import ROOT
    p = ROOT / "targets" / "_template.yaml"
    it = intake_mod.load_intake(p)
    assert not it.ok
    assert any("authorization_ref" in r for r in it.fatal_reasons())


def test_missing_vendor_rejected(tmp_path):
    it = intake_mod.load_intake(_write(tmp_path, vendor=""))
    assert not it.ok and any("vendor" in r for r in it.fatal_reasons())


def test_empty_authorization_rejected(tmp_path):
    it = intake_mod.load_intake(_write(tmp_path, authorization_ref="   "))
    assert not it.ok
    assert any("授权依据" in r for r in it.fatal_reasons())


def test_automation_no_rejected(tmp_path):
    it = intake_mod.load_intake(_write(
        tmp_path, restrictions={"raw": "平台禁止自动化扫描", "automation_allowed": "no"}))
    assert not it.ok
    assert any("禁止自动化" in r for r in it.fatal_reasons())


def test_invalid_tier_rejected(tmp_path):
    it = intake_mod.load_intake(_write(tmp_path, tier="turbo"))
    assert not it.ok and any("tier" in r for r in it.fatal_reasons())


def test_third_party_rejected(tmp_path):
    scope = {"domains": ["a.example.com"], "include_subdomains": False,
             "include_third_party": True}
    it = intake_mod.load_intake(_write(tmp_path, scope=scope))
    assert not it.ok and any("第三方" in r for r in it.fatal_reasons())


def test_domain_normalization_and_rejections(tmp_path):
    it = intake_mod.load_intake(_write(tmp_path))
    assert it.ok
    assert it.domains == ["a.example.com"]           # 去协议/路径/大小写/去重
    assert it.ips == ["1.2.3.4"]
    assert it.asset_count() == 2
    assert any("通配符" in r["reason"] for r in it.rejected_entries)
    assert any("子域不会进入清单" in n for n in it.notes)


def test_include_subdomains_note(tmp_path):
    scope = {"domains": ["a.example.com"], "include_subdomains": True}
    it = intake_mod.load_intake(_write(tmp_path, scope=scope))
    assert any("子域会进入清单" in n for n in it.notes)


def test_plan_numbers():
    recon = load_recon_config()
    it = intake_mod.load_intake(
        Path(__file__).resolve().parents[2] / "targets" / "_template.yaml")
    # 模板不通过但 plan 仍可计算（用于预检展示）
    p = intake_mod.plan(it, recon)
    assert p["concurrency"] > 0 and p["request_upper"] >= 0
    assert p["failure_threshold"] > 0


def test_emit_target_is_legacy_loadable(tmp_path):
    it = intake_mod.load_intake(_write(tmp_path))
    out = intake_mod.emit_target(it, tmp_path / "exec.yaml")
    tgt = load_target(out)                     # legacy 校验必须能通过
    assert "a.example.com" in tgt.domains
    assert "12345" in tgt.authorization


def test_dry_run_makes_no_network_calls(tmp_path, monkeypatch):
    # 任何网络调用都会让测试失败
    import requests

    def boom(*a, **k):
        raise AssertionError("dry-run 不应产生网络请求")

    monkeypatch.setattr(requests.Session, "get", boom)
    monkeypatch.setattr(requests, "get", boom)

    p = _write(tmp_path)
    rc = intake_mod.main(_app(tmp_path), str(p), dry_run=True, recon_config=None,
                         console=lambda m: None)
    assert rc == 0
    assert not list(tmp_path.glob("exec.yaml"))


def test_intake_cli_dry_run(tmp_path):
    p = _write(tmp_path)
    out = subprocess.run(
        [str(Path(__file__).resolve().parents[2] / ".venv-recon" / "Scripts" / "python.exe"),
         str(Path(__file__).resolve().parents[2] / "main.py"),
         "intake", str(p), "--dry-run"],
        capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120,
        cwd=str(Path(__file__).resolve().parents[2]))
    assert out.returncode == 0
    assert "dry-run" in out.stdout and "预估请求上限" in out.stdout
