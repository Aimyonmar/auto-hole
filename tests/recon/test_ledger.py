# -*- coding: utf-8 -*-
"""授权档案：本地 HTML 解析、blocked 规则、按序号/厂商选择、预检零请求。"""
from pathlib import Path

import pytest

from core.config import ROOT
from modules.recon import ledger as ledger_mod
from modules.recon.config import load_recon_config
from modules.recon.intake import load_intake
from modules.recon.ledger import (import_project, load_ledgers, render_list,
                                  resolve_identifier, preflight, parse_project_text)


def _recon(tmp_path):
    recon = load_recon_config()
    recon.state.dir = str(tmp_path / "state")
    ledger_mod.AUTHORIZED_DIR = tmp_path / "authorized"
    return recon


NORMAL = """<html><head><title>补天项目</title></head><body>
<div>厂商名称：某某科技有限公司</div>
<div>项目链接：https://www.butian.net/Company/12345</div>
<div>项目编号：12345</div>
<div>报名状态：已通过</div>
<h3>资产范围</h3>
<ul><li>a.example.com</li><li>*.example.com</li><li>1.2.3.4</li></ul>
<h3>平台禁止项</h3>
<p>禁止破坏性测试；禁止影响业务稳定</p>
</body></html>"""

PENDING = NORMAL.replace("已通过", "审核中")
NO_AUTO = NORMAL.replace("禁止破坏性测试；禁止影响业务稳定",
                         "禁止高并发、自动化扫描与破坏性测试")
EMPTY_SCOPE = """<html><body>
<div>厂商名称：空范围厂商</div>
<div>项目链接：https://www.butian.net/Company/99999</div>
<div>报名状态：已通过</div>
<div>平台禁止项：禁止破坏性测试</div>
</body></html>"""
MISSING_VENDOR = """<html><body>
<div>项目链接：https://www.butian.net/Company/88888</div>
<div>报名状态：已通过</div>
<h3>资产范围</h3><ul><li>a.example.com</li></ul>
<h3>平台禁止项</h3><p>禁止破坏性测试</p>
</body></html>"""


def test_parse_normal_fixture():
    parsed = parse_project_text(NORMAL)
    assert parsed["vendor"] == "某某科技有限公司"
    assert parsed["program_url"].endswith("/Company/12345")
    assert parsed["registration_status"] == "approved"
    assert parsed["domains"] == ["a.example.com"]
    assert parsed["ips"] == ["1.2.3.4"]
    assert parsed["automation_allowed"] == "unstated"
    assert any("通配符" in r["reason"] for r in parsed["rejected"])
    assert not parsed["missing"]


def test_parse_missing_vendor_fails_import(tmp_path):
    recon = _recon(tmp_path)
    with pytest.raises(ValueError) as e:
        import_project(recon, text=MISSING_VENDOR, console=lambda m: None)
    assert "vendor" in str(e.value)
    assert not list((tmp_path / "authorized").glob("*.yaml"))


def test_parse_empty_scope_fails_import(tmp_path):
    recon = _recon(tmp_path)
    with pytest.raises(ValueError) as e:
        import_project(recon, text=EMPTY_SCOPE, console=lambda m: None)
    assert "scope.domains" in str(e.value)
    assert not list((tmp_path / "authorized").glob("*.yaml"))


def test_import_normal_and_list(tmp_path):
    recon = _recon(tmp_path)
    out, parsed = import_project(recon, text=NORMAL, console=lambda m: None)
    assert out.exists()
    y = out.read_text(encoding="utf-8")
    assert "registration_status: approved" in y
    assert "source:" in y and "digest:" in y
    entries = load_ledgers(recon)
    assert len(entries) == 1 and entries[0].executable
    text = render_list(entries)
    assert "可执行目标" in text and "某某科技有限公司" in text


def test_pending_is_blocked(tmp_path):
    recon = _recon(tmp_path)
    import_project(recon, text=PENDING, console=lambda m: None)
    entries = load_ledgers(recon)
    assert not entries[0].executable
    assert any("pending" in r for r in entries[0].reasons)
    assert "Blocked" in render_list(entries)


def test_resolve_blocked_by_name_and_path(tmp_path):
    recon = _recon(tmp_path)
    out, _ = import_project(recon, text=PENDING, console=lambda m: None)
    path, it, err = resolve_identifier("某某科技", recon, console=lambda m: None)
    assert path is None and "blocked" in err
    path2, it2, err2 = resolve_identifier(str(out), recon, console=lambda m: None)
    assert path2 is None and "blocked" in err2


def test_automation_no_is_blocked(tmp_path):
    recon = _recon(tmp_path)
    import_project(recon, text=NO_AUTO, console=lambda m: None)
    e = load_ledgers(recon)[0]
    assert not e.executable
    assert any("禁止自动化" in r for r in e.reasons)


def test_resolve_by_index_and_name(tmp_path):
    recon = _recon(tmp_path)
    import_project(recon, text=NORMAL, console=lambda m: None)
    path, it, err = resolve_identifier("1", recon, console=lambda m: None)
    assert not err and path.exists()
    from core.constitution import load_target
    tgt = load_target(path)
    assert "a.example.com" in tgt.domains

    path2, it2, err2 = resolve_identifier("某某科技", recon, console=lambda m: None)
    assert not err2 and path2.exists()


def test_preflight_fails_on_automation_no(tmp_path):
    recon = _recon(tmp_path)
    out, _ = import_project(recon, text=NO_AUTO, console=lambda m: None)
    it = load_intake(out)
    assert not it.ok
    assert preflight(it, recon, yes=True, console=lambda m: None) is False


def test_import_list_resolve_make_no_network(tmp_path, monkeypatch):
    import requests

    def boom(*a, **k):
        raise AssertionError("授权档案流程不应产生网络请求")

    monkeypatch.setattr(requests.Session, "get", boom)
    monkeypatch.setattr(requests, "get", boom)

    recon = _recon(tmp_path)
    import_project(recon, text=NORMAL, console=lambda m: None)
    entries = load_ledgers(recon)
    render_list(entries)
    resolve_identifier("1", recon, console=lambda m: None)

    it = load_intake(ROOT / "targets" / "_template.yaml")
    assert not preflight(it, recon, yes=True, console=lambda m: None)
