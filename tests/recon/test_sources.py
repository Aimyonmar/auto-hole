# -*- coding: utf-8 -*-
"""数据源插件化：注册表 / 内置源 / 外部插件目录 / 可用性降级。"""
from pathlib import Path

from core.config import AppConfig, PathsConfig, HunterConfig
from core.constitution import TargetDef

from modules.recon.config import load_recon_config
from modules.recon.sources import (Source, SourceContext, available_names,
                                   build_sources, get, load_plugins, register,
                                   registry)


def _ctx(tmp_path, target):
    app = AppConfig(
        hunter=HunterConfig(api_key="YOUR_KEY"),
        paths=PathsConfig(workspace=str(tmp_path / "ws"), reports=str(tmp_path / "rp"),
                          db=str(tmp_path / "ws" / "db.sqlite")),
    )
    recon = load_recon_config()
    return SourceContext(app=app, recon=recon, target=target,
                         profile=recon.active_profile(), limiter=None,
                         audit=None, console=lambda m: None)


def _target(**kw):
    base = dict(name="t", vendor="v", authorization="补天公益SRC")
    base.update(kw)
    return TargetDef(**base)


def test_builtin_sources_registered():
    load_plugins()
    names = available_names()
    assert {"seed", "subfinder", "hunter"} <= set(names)
    assert get("seed") is registry()["seed"]


def test_seed_source_yields_declared_assets(tmp_path):
    ctx = _ctx(tmp_path, _target(domains=["example.com"], ips=["10.0.0.1", "10.0.0.0/24"]))
    src = get("seed")()
    ok, reason = src.available(ctx)
    assert ok, reason
    assets = list(src.fetch(ctx))
    hosts = {a.host for a in assets}
    assert "example.com" in hosts and "10.0.0.1" in hosts
    assert "10.0.0.0" not in hosts          # CIDR 不展开（避免大规模扫描）


def test_seed_unavailable_without_declaration(tmp_path):
    ctx = _ctx(tmp_path, _target())
    ok, reason = get("seed")().available(ctx)
    assert not ok and "未声明" in reason


def test_subfinder_requires_binary_and_domains(tmp_path):
    ctx = _ctx(tmp_path, _target())          # 未声明域名
    ok, reason = get("subfinder")().available(ctx)
    assert not ok

    ctx2 = _ctx(tmp_path, _target(domains=["example.com"]))
    ok2, reason2 = get("subfinder")().available(ctx2)
    # 项目 tools/ 下是否安装 subfinder 决定结果，本机存在则为 True
    assert isinstance(ok2, bool)


def test_hunter_downgrades_without_key(tmp_path):
    ctx = _ctx(tmp_path, _target(domains=["example.com"]))
    ok, reason = get("hunter")().available(ctx)
    assert not ok and "hunter.api_key" in reason


def test_build_sources_skips_unavailable(tmp_path):
    ctx = _ctx(tmp_path, _target(domains=["example.com"]))
    usable, skipped = build_sources(["seed", "not-exist"], ctx)
    assert [s.name for s in usable] == ["seed"]
    assert skipped and skipped[0]["name"] == "not-exist"


def test_external_plugin_dir(tmp_path, monkeypatch):
    plugin = tmp_path / "myplug.py"
    plugin.write_text(
        "from modules.recon.sources import register\n"
        "from modules.recon.sources.base import Source\n"
        "from modules.recon.schema import Asset\n"
        "@register\n"
        "class MyPlugin(Source):\n"
        "    name = 'myplugin'\n"
        "    kind = 'passive'\n"
        "    def fetch(self, ctx):\n"
        "        yield Asset(host='plugin.example.com', sources=['myplugin'])\n",
        encoding="utf-8")
    load_plugins(tmp_path)
    assert "myplugin" in available_names()

    ctx = _ctx(tmp_path, _target(domains=["example.com"]))
    usable, _ = build_sources(["myplugin"], ctx, tmp_path)
    assert len(usable) == 1
    assets = list(usable[0].fetch(ctx))
    assert assets[0].host == "plugin.example.com"
