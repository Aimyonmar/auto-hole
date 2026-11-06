# -*- coding: utf-8 -*-
"""外部资产清单导入：解析容错、去重、可用性。"""
from modules.recon.schema import Asset
from modules.recon.sources import get
from modules.recon.sources.import_list import parse_line


def test_parse_plain_host():
    a = parse_line("a.example.com")
    assert a.host == "a.example.com" and a.port == 0
    assert a.url == "http://a.example.com"


def test_parse_host_port():
    a = parse_line("a.example.com:8080")
    assert a.host == "a.example.com" and a.port == 8080


def test_parse_url():
    a = parse_line("https://a.example.com:8443/login")
    assert a.host == "a.example.com" and a.port == 8443 and a.scheme == "https"


def test_parse_csv_export():
    # 常见测绘导出：IP,端口,URL,标题
    a = parse_line("1.2.3.4,443,https://1.2.3.4,admin panel")
    assert a.host == "1.2.3.4" and a.port == 443


def test_parse_skips_comment_and_garbage():
    assert parse_line("# 注释") is None
    assert parse_line("") is None
    assert parse_line("not a host line") is None


def test_parse_asset_is_dedupable():
    a = parse_line("a.example.com:80")
    b = parse_line("http://a.example.com")
    assert a.key == b.key == "a.example.com|80"


def test_import_source_available_and_fetch(tmp_path):
    from core.config import AppConfig, PathsConfig
    from core.constitution import TargetDef
    from modules.recon.config import load_recon_config
    from modules.recon.sources.base import SourceContext

    recon = load_recon_config()
    recon.sources.import_dir = str(tmp_path)
    target = TargetDef(name="demo", vendor="v", authorization="a", ips=["1.2.3.4"])
    app = AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                      reports=str(tmp_path / "rp"),
                                      db=str(tmp_path / "ws" / "d.db")))
    ctx = SourceContext(app=app, recon=recon, target=target,
                        profile=recon.active_profile(), limiter=None,
                        audit=None, console=lambda m: None)

    src = get("import")()
    ok, _ = src.available(ctx)
    assert not ok and "未找到导入文件" in _

    (tmp_path / "demo.txt").write_text(
        "1.2.3.4\n1.2.3.4:443\nhttps://5.6.7.8\n1.2.3.4\n", encoding="utf-8")
    ok2, _ = src.available(ctx)
    assert ok2
    assets = list(src.fetch(ctx))
    hosts = {a.host for a in assets}
    assert hosts == {"1.2.3.4", "5.6.7.8"}       # 重复行被去重
    assert isinstance(assets[0], Asset)
