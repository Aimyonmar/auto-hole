# -*- coding: utf-8 -*-
"""WAF 拦截自动中止：识别、审计、阶段停止（全部本地回环）。"""
import http.server
import json
import socketserver
import threading
from pathlib import Path

import pytest

from core.config import AppConfig, PathsConfig
from core.constitution import TargetDef
from modules.recon.audit import AuditLog
from modules.recon.config import load_recon_config
from modules.recon.fingerprint import FingerprintEngine
from modules.recon.probe import Prober, WafDetected
from modules.recon.ratelimit import AdaptiveLimiter, BudgetLedger
from modules.recon.runner import _scan_stage, run
from modules.recon.schema import Asset
from modules.recon.state import RunState
from modules.recon.waf import WafGuard, detect_waf


class _WafHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = ("<html><head><title>Attention Required! | Cloudflare</title></head>"
                "<body>Ray ID: test-cf-ray</body></html>").encode("utf-8")
        self.send_response(403)
        self.send_header("Server", "cloudflare")
        self.send_header("CF-RAY", "test-cf-ray")
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture
def waf_port():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _WafHandler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def _app(tmp_path) -> AppConfig:
    return AppConfig(paths=PathsConfig(
        workspace=str(tmp_path / "ws"), reports=str(tmp_path / "rp"),
        db=str(tmp_path / "ws" / "d.db")))


def _recon(tmp_path):
    recon = load_recon_config()
    recon.state.dir = str(tmp_path / "state")
    recon.audit.path = str(tmp_path / "audit")
    recon.sources.enabled = []
    recon.authz.enabled = False
    recon.authz.auto_run = False
    recon.profile = "light"
    recon.waf.enabled = True
    recon.waf.stop_after = 1
    return recon


def _target(port: int) -> TargetDef:
    return TargetDef(name="waf", vendor="v", authorization="本地授权",
                     ips=["127.0.0.1"])


def test_detect_cloudflare_block_vs_normal_page():
    assert detect_waf(403, {"server": "cloudflare", "cf-ray": "x"},
                      "Attention Required! | Cloudflare") == ["cloudflare"]
    assert detect_waf(200, {"server": "cloudflare"}, "normal page") == []
    assert detect_waf(429, {}, "") == ["http_429"]


def test_waf_threshold_is_configurable(tmp_path, waf_port):
    recon = _recon(tmp_path)
    recon.waf.stop_after = 2
    app = _app(tmp_path)
    target = _target(waf_port)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl", target.name)
    limiter = AdaptiveLimiter(rps=5, concurrency=1)
    ledger = BudgetLedger(app.db_path, target.name, 1000)
    guard = WafGuard(enabled=True, stop_after=2, audit=audit,
                     console=lambda m: None)
    prober = Prober(recon=recon, target=target, profile=recon.active_profile(),
                    limiter=limiter, ledger=ledger, audit=audit,
                    engine=None, console=lambda m: None, waf_guard=guard)
    url = f"http://127.0.0.1:{waf_port}/"
    first = prober.request(url, "127.0.0.1", stage="probe")
    assert first and first["status"] == 403
    assert guard.hits == 1 and not guard.stopped
    with pytest.raises(WafDetected):
        prober.request(url, "127.0.0.1", stage="probe")
    assert guard.stopped and guard.info["status"] == 403
    events = [json.loads(x) for x in
              (tmp_path / "audit" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    stops = [e for e in events if e.get("event") == "waf_stop"]
    assert stops and stops[-1]["markers"] and stops[-1]["status"] == 403
    ledger.close()


def test_runner_probe_waf_stops_later_stages(tmp_path, waf_port, monkeypatch):
    recon = _recon(tmp_path)
    app = _app(tmp_path)
    target = _target(waf_port)
    tdir = recon.target_state_dir(target.name)
    tdir.mkdir(parents=True, exist_ok=True)
    asset = Asset(host="127.0.0.1", port=waf_port,
                  url=f"http://127.0.0.1:{waf_port}/", status=0, sources=["seed"])
    (tdir / "assets.jsonl").write_text(asset.to_json() + "\n", encoding="utf-8")

    called = {"discover": False, "scan": False}

    def _discover_fail(*a, **k):
        called["discover"] = True
        return []

    def _scan_fail(**k):
        called["scan"] = True
        return {"new": 0, "findings": []}

    monkeypatch.setattr("modules.recon.runner.Discovery.run", _discover_fail)
    monkeypatch.setattr("modules.recon.runner.run_scan", _scan_fail)

    result = run(app, target, recon, stage="all", console=lambda m: None)
    assert result.status == "waf_stop"
    assert result.summary["status"] == "waf_stop"
    assert result.summary["waf"]["stage"] == "probe"
    assert result.summary["stages"]["probe"]["status"] == "waf_stop"
    assert result.probe_stats["requests"] == 1
    assert called == {"discover": False, "scan": False}
    events = [json.loads(x) for x in
              (tmp_path / "audit" / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    stops = [e for e in events if e.get("event") == "waf_stop"]
    assert stops and stops[-1]["stage"] == "probe"
    report = (tdir / "report.md").read_text(encoding="utf-8")
    assert "WAF 中止" in report


def test_scan_stage_canary_stops_before_nuclei(tmp_path, waf_port, monkeypatch):
    recon = _recon(tmp_path)
    app = _app(tmp_path)
    target = _target(waf_port)
    audit = AuditLog(tmp_path / "audit" / "audit.jsonl", target.name)
    limiter = AdaptiveLimiter(rps=5, concurrency=1)
    ledger = BudgetLedger(app.db_path, target.name, 1000)
    guard = WafGuard(enabled=True, stop_after=1, audit=audit,
                     console=lambda m: None)
    prober = Prober(recon=recon, target=target, profile=recon.active_profile(),
                    limiter=limiter, ledger=ledger, audit=audit,
                    engine=None, console=lambda m: None, waf_guard=guard)
    engine = FingerprintEngine.from_yaml(
        recon.fingerprint_library(),
        min_confidence=recon.fingerprint.min_confidence,
        weak_match_penalty=recon.fingerprint.weak_match_penalty,
    )
    assets = [Asset(host="127.0.0.1", port=waf_port,
                    url=f"http://127.0.0.1:{waf_port}/", status=200,
                    products=[{"product": "致远OA", "rule_id": "seeyon-oa",
                               "confidence": 0.95}])]
    calls = []
    monkeypatch.setattr("modules.recon.runner.run_scan",
                        lambda **k: calls.append(k) or {"new": 0, "findings": []})
    state = RunState(tmp_path / "state" / "state.json", target.name)
    findings, warnings, stats = _scan_stage(
        app=app, target=target, profile=recon.active_profile(), engine=engine,
        assets=assets, db=None, limiter=type("L", (), {"limit": 1000, "used": 0})(),
        state=state, console=lambda m: None, waf_prober=prober)
    assert findings == [] and calls == []
    assert any("WAF" in w for w in warnings)
    assert stats["groups"] == 0
    assert guard.stopped
    ledger.close()
