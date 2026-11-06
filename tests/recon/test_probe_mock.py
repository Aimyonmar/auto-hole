# -*- coding: utf-8 -*-
"""端到端（本地 mock 服务）：探测 + 指纹 + 审计 + 断点续跑 + 配额熔断 + 入库。

全程只访问 127.0.0.1，零外部请求。
"""
import http.server
import json
import socketserver
import threading
from pathlib import Path

import pytest

from core.config import AppConfig, PathsConfig
from core.constitution import TargetDef
from core.db import DB

from modules.recon.adapters import (read_assets_jsonl, upsert_assets,
                                   write_assets_jsonl)
from modules.recon.audit import AuditLog
from modules.recon.config import load_recon_config
from modules.recon.fingerprint import FingerprintEngine
from modules.recon.probe import Prober, ProbeAborted
from modules.recon.ratelimit import AdaptiveLimiter, BudgetLedger
from modules.recon.schema import Asset
from modules.recon.state import RunState

BUILTIN = Path(__file__).resolve().parents[2] / "modules/recon/fingerprints/builtin.yaml"


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        site = self.server.site
        if self.path == "/favicon.ico":
            data = site.get("favicon", b"")
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        body = site["body"].encode("utf-8")
        self.send_response(int(site.get("status", 200)))
        self.send_header("Server", site.get("server", "nginx"))
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def _start(site: dict) -> socketserver.ThreadingTCPServer:
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    srv.site = site
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def sites():
    a = _start({
        "status": 200, "server": "nginx/1.20",
        "body": "<html><title>致远OA V8.1 登录</title><body>seeyon portal</body></html>",
        "favicon": b"seeyon-icon",
    })
    b = _start({
        "status": 200, "server": "openresty/1.21.4.1",
        "body": "<html><title>Welcome</title><body>plain page</body></html>",
        "favicon": b"plain-icon",
    })
    yield [a.server_address[1], b.server_address[1]]
    for s in (a, b):
        s.shutdown()


def _make_prober(tmp_path, ports, *, target_ips=("127.0.0.1",), ledger_limit=100,
                 limiter=None, state=None):
    recon = load_recon_config()
    profile = recon.active_profile()
    app = AppConfig(paths=PathsConfig(
        workspace=str(tmp_path / "ws"), reports=str(tmp_path / "rp"),
        db=str(tmp_path / "ws" / "db.sqlite")))
    target = TargetDef(name="mock", vendor="local", authorization="本地 mock 授权",
                       ips=list(target_ips))
    limiter = limiter or AdaptiveLimiter(rps=20, concurrency=2)
    ledger = BudgetLedger(app.db_path, "mock", ledger_limit)
    audit = AuditLog(tmp_path / "audit.jsonl", "mock")
    engine = FingerprintEngine.from_yaml(BUILTIN)
    prober = Prober(recon=recon, target=target, profile=profile, limiter=limiter,
                    ledger=ledger, audit=audit, engine=engine,
                    console=lambda m: None)
    return prober, ledger, audit, target


def _assets(ports):
    return [Asset(host="127.0.0.1", port=p, sources=["seed"]) for p in ports]


def test_probe_and_fingerprint(tmp_path, sites):
    prober, ledger, audit, _ = _make_prober(tmp_path, sites)
    alive, stats = prober.probe_assets(_assets(sites))

    assert len(alive) == 2
    assert stats.alive == 2 and stats.dead == 0
    assert stats.requests == 2 and stats.effective_rps > 0
    assert ledger.used() == 2

    by_port = {a.port: a for a in alive}
    a = by_port[sites[0]]
    products = {p["product"] for p in a.products}
    assert {"致远OA", "Nginx"} <= products
    assert a.status == 200 and a.title.startswith("致远OA")
    assert a.sources == ["seed"]              # 继承发现来源
    assert a.evidence["body_len"] > 0

    b = by_port[sites[1]]
    assert {p["product"] for p in b.products} == {"OpenResty"}


def test_audit_records_every_request(tmp_path, sites):
    prober, _, audit, _ = _make_prober(tmp_path, sites)
    prober.probe_assets(_assets(sites))

    lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8").splitlines()]
    reqs = [e for e in lines if e["event"] == "request"]
    assert len(reqs) == 2
    assert all({"ts", "target", "host", "url", "status", "elapsed_ms", "rps"} <= set(r) for r in reqs)
    hits = [e for e in lines if e["event"] == "fingerprint_hit"]
    assert any(h["product"] == "致远OA" for h in hits)
    assert any(h["event"] == "fingerprint_hit" and "matched" in h for h in hits)


def test_scope_reject_without_request(tmp_path, sites):
    prober, ledger, audit, _ = _make_prober(tmp_path, sites, target_ips=("127.0.0.1",))
    out_of_scope = Asset(host="192.168.10.10", port=80)
    alive, stats = prober.probe_assets([out_of_scope])
    assert alive == [] and stats.requests == 0
    assert ledger.used() == 0
    lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert any(e["event"] == "scope_reject" and e["host"] == "192.168.10.10" for e in lines)


def test_resume_skips_processed(tmp_path, sites):
    prober, ledger, _, _ = _make_prober(tmp_path, sites)
    state = RunState(tmp_path / "state.json", "mock")
    assets = _assets(sites)

    first, st1 = prober.probe_assets(assets, state)
    assert len(first) == 2

    second, st2 = prober.probe_assets(assets, state)
    assert second == [] and st2.requests == 0
    assert ledger.used() == 2                # 没有重复计费


def test_budget_cutoff_stops(tmp_path, sites):
    prober, ledger, audit, _ = _make_prober(tmp_path, sites, ledger_limit=1)
    alive, stats = prober.probe_assets(_assets(sites))
    assert ledger.used() == 1
    assert len(alive) <= 1
    assert stats.requests <= 1
    lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert any(e["event"] == "budget_stop" for e in lines)


def test_favicon_hash_enables_hash_rule(tmp_path, sites):
    recon = load_recon_config()
    recon.profile = "deep"                   # deep 默认抓 favicon
    recon.profiles["deep"].favicon = True
    prober, ledger, audit, _ = _make_prober(tmp_path, sites)
    prober.recon = recon
    prober.profile = recon.active_profile()

    alive, _ = prober.probe_assets(_assets([sites[0]]))
    fav = alive[0].evidence.get("favicon_sha256", "")
    assert len(fav) == 64 and set(fav) <= set("0123456789abcdef")
    assert ledger.used() >= 2               # 页面 + favicon 两次请求
    lines = [json.loads(x) for x in (tmp_path / "audit.jsonl").read_text(
        encoding="utf-8").splitlines()]
    assert any(e["event"] == "request" for e in lines)


def test_jsonl_roundtrip_and_legacy_mirror(tmp_path, sites):
    prober, _, _, _ = _make_prober(tmp_path, sites)
    alive, _ = prober.probe_assets(_assets(sites))

    store = tmp_path / "assets.jsonl"
    assert write_assets_jsonl(store, alive) == 2
    back = read_assets_jsonl(store)
    assert len(back) == 2
    assert {a.key for a in back} == {a.key for a in alive}
    assert back[0].products

    db = DB(tmp_path / "mirror.db")
    assert upsert_assets(db, "mock", back) == 2
    rows = db.assets("mock")
    assert len(rows) == 2
    tech = json.loads(rows[0]["tech"])
    assert isinstance(tech, list) and tech        # legacy 语义：tech 存字符串列表
    db.close()
