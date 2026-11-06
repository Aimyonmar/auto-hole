# -*- coding: utf-8 -*-
"""URL/路径/参数发现：解析、爬取控制、JS 提取、字典探测（全部本地回环）。"""
import http.server
import socketserver
import threading

import pytest

from core.config import AppConfig, PathsConfig
from core.constitution import TargetDef

from modules.recon.audit import AuditLog
from modules.recon.config import load_recon_config
from modules.recon.discovery import (Discovery, extract_inputs,
                                     extract_js_endpoints, extract_links,
                                     is_static, join_url, load_history_urls,
                                     params_of, same_origin, url_key,
                                     write_discovered, read_discovered)
from modules.recon.probe import Prober
from modules.recon.ratelimit import AdaptiveLimiter, BudgetLedger
from modules.recon.schema import Asset
from modules.recon.state import RunState


# ---------------------------------------------------------------- 纯函数
def test_url_normalization_and_origin():
    assert url_key("http://A.com:80/x?y=1#frag") == "http://a.com/x?y=1"
    assert same_origin("http://a.com/x", "http://a.com/y")
    assert not same_origin("http://a.com/x", "https://a.com/y")
    assert is_static("/a.png") is True and is_static("/a") is False
    assert join_url("http://a.com/base", "x/y") == "http://a.com/x/y"
    assert join_url("http://a.com/", "javascript:void(0)") == ""


def test_extract_links_js_inputs_params():
    html = ('<a href="/p1">1</a><form action="/login"><input name="user">'
            '<script src="/app.js"></script>'
            '<script>fetch("/api/user?id=1")</script>')
    links = extract_links(html, "http://a.com/")
    assert "http://a.com/p1" in links and "http://a.com/login" in links
    assert "http://a.com/app.js" in links
    assert extract_inputs(html) == ["user"]
    js = 'axios.get("/api/list");fetch("/api/user?id=1");var a="/x/y";'
    eps = extract_js_endpoints(js)
    assert "/api/list" in eps and "/api/user?id=1" in eps
    assert params_of("http://a.com/x?a=1&b=2") == ["a", "b"]


# ---------------------------------------------------------------- mock 站点
class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        routes = self.server.routes
        path = self.path.split("?")[0]
        status, body = routes.get(path, (404, "not found"))
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *args):
        pass


def _site(routes: dict) -> socketserver.ThreadingTCPServer:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.routes = routes
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def lab():
    root = ('<html><title>Demo</title>'
            '<a href="/page">page</a><a href="/static.png">img</a>'
            '<script src="/app.js"></script>'
            '<script>fetch("/api/user?id=1")</script></html>')
    srv = _site({
        "/": (200, root),
        "/page": (200, '<html><title>Page</title><a href="/deep">deep</a></html>'),
        "/deep": (200, "deep page"),
        "/app.js": (200, 'axios.get("/api/list");'),
        "/api/user": (200, "user list"),
        "/api/list": (200, "items"),
        "/.git/config": (200, "repositoryformatversion = 0"),
        "/__auto_hole_probe_x": (404, "not found"),
    })
    yield srv.server_address[1]
    srv.shutdown()


def _make(tmp_path, port, *, depth=1, max_urls=30, paths=3, js=True):
    recon = load_recon_config()
    profile = recon.active_profile()          # light
    profile.crawl_depth = depth
    profile.crawl_max_urls = max_urls
    profile.crawl_concurrency = 2
    profile.js_extract = js
    profile.path_scan_enabled = True
    profile.path_scan_max_paths = paths

    app = AppConfig(paths=PathsConfig(
        workspace=str(tmp_path / "ws"), reports=str(tmp_path / "rp"),
        db=str(tmp_path / "ws" / "d.db")))
    target = TargetDef(name="lab", vendor="v", authorization="本地", ips=["127.0.0.1"])
    limiter = AdaptiveLimiter(rps=20, concurrency=2)
    ledger = BudgetLedger(app.db_path, "lab", 200)
    audit = AuditLog(tmp_path / "audit.jsonl", "lab")
    prober = Prober(recon=recon, target=target, profile=profile, limiter=limiter,
                    ledger=ledger, audit=audit, engine=None, console=lambda m: None)
    assets = [Asset(host="127.0.0.1", port=port, url=f"http://127.0.0.1:{port}",
                    status=200, sources=["seed"])]
    state = RunState(tmp_path / "state.json", "lab")
    disc = Discovery(prober=prober, profile=profile, recon=recon,
                     target_name="lab", state=state, console=lambda m: None)
    return disc, assets, ledger, state


def test_crawl_respects_depth_and_static_filter(tmp_path, lab):
    disc, assets, ledger, _ = _make(tmp_path, lab, depth=1)
    urls = disc.run(assets)
    found = {u.url for u in urls}
    assert f"http://127.0.0.1:{lab}/page" in found
    assert f"http://127.0.0.1:{lab}/api/user?id=1" in found
    assert f"http://127.0.0.1:{lab}/api/list" in found       # 从 JS 文件提取
    assert any(u.endswith("/static.png") for u in found) is False
    assert any(u.url.endswith("/deep") for u in urls) is False  # depth=1 不深入
    assert ledger.used() <= 20
    # 路径探测命中 /.git/config（异常响应）
    hit = [u for u in urls if u.url.endswith("/.git/config")]
    assert hit and hit[0].interesting and hit[0].source == "path_scan"


def test_crawl_max_urls_limit(tmp_path, lab):
    disc, assets, _, _ = _make(tmp_path, lab, depth=2, max_urls=3)
    urls = disc.run(assets)
    crawl = [u for u in urls if u.source == "crawl"]
    assert len(crawl) <= 3


def test_js_extract_disabled(tmp_path, lab):
    disc, assets, _, _ = _make(tmp_path, lab, js=False)
    urls = disc.run(assets)
    assert not any("api/list" in u.url for u in urls)


def test_path_scan_can_be_disabled(tmp_path, lab):
    disc, assets, _, _ = _make(tmp_path, lab)
    disc.profile.path_scan_enabled = False
    urls = disc.run(assets)
    assert not [u for u in urls if u.source == "path_scan"]


def test_history_import(tmp_path, lab):
    recon = load_recon_config()
    recon.sources.import_dir = str(tmp_path)
    (tmp_path / "lab.urls.txt").write_text(
        f"http://127.0.0.1:{lab}/page\n# comment\nnot-a-url\n", encoding="utf-8")
    urls = load_history_urls(recon, "lab", console=lambda m: None)
    assert urls == [f"http://127.0.0.1:{lab}/page"]


def test_discovered_roundtrip(tmp_path, lab):
    disc, assets, _, _ = _make(tmp_path, lab)
    urls = disc.run(assets)
    p = tmp_path / "d.jsonl"
    assert write_discovered(p, urls) == len(urls)
    back = read_discovered(p)
    assert {u.url for u in back} == {u.url for u in urls}


def test_soft_404_three_sample_baseline_drops_fake_200(tmp_path):
    class _Soft(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = "soft not found page".encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Soft)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        port = srv.server_address[1]
        disc, assets, ledger, _ = _make(tmp_path, port, paths=3)
        urls = disc.run(assets)
        paths = [u for u in urls if u.source == "path_scan"]
        assert paths and all(not u.interesting for u in paths), \
            "软 404 全 200 不应被当成暴露面"
        assert ledger.used() >= 3          # 至少 3 条基线取样
    finally:
        srv.shutdown()
