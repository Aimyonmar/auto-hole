# -*- coding: utf-8 -*-
"""目标体检：三档靶场、零扫描、预算、空目标/超时/指纹缺失、报告内容。"""
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

from core.config import AppConfig, PathsConfig, ScanConfig
from core.constitution import TargetDef
from modules.recon.config import (AuditConfig, FingerprintConfig, LimitsConfig,
                                  Profile, ReconConfig, SourcesConfig, StateConfig,
                                  TriageConfig)
from modules.recon.triage import run_triage

ROOT = Path(__file__).resolve().parents[2]


def _start_lab(mode: str):
    path = ROOT / "outputs" / "triage-demo" / "lab_server.py"
    spec = importlib.util.spec_from_file_location(f"triage_lab_{mode}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    srv.mode = mode
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _recon(tmp_path, port: int, max_requests: int = 60) -> ReconConfig:
    profile = Profile(name="light", concurrency=1, requests_per_second=5,
                      probe_ports=[port], probe_timeout=2, probe_retries=0,
                      max_hosts=10, scan_enabled=False, favicon=False,
                      crawl_max_urls=40, path_scan_max_paths=8,
                      scan_max_urls=200)
    return ReconConfig(
        profile="light", profiles={"light": profile},
        sources=SourcesConfig(enabled=["seed"], path_dict=""),
        fingerprint=FingerprintConfig(
            library=str(ROOT / "modules" / "recon" / "fingerprints" / "builtin.yaml")),
        limits=LimitsConfig(daily_request_limit=300, failure_threshold=5,
                            cooldown_seconds=10),
        audit=AuditConfig(enabled=True, path=str(tmp_path / "audit")),
        state=StateConfig(dir=str(tmp_path / "state")),
        triage=TriageConfig(max_requests=max_requests, max_hosts=10,
                            max_exposure_paths=12, sources=["seed", "import"]),
    )


def _app(tmp_path) -> AppConfig:
    return AppConfig(scan=ScanConfig(concurrency=1, daily_request_limit=300),
                     paths=PathsConfig(workspace=str(tmp_path / "workspace"),
                                       reports=str(tmp_path / "reports"),
                                       db=str(tmp_path / "autohole.db"),
                                       tools_dir=str(tmp_path / "tools"),
                                       nuclei_templates=str(tmp_path / "templates")))


def _run_mode(tmp_path, mode: str, max_requests: int = 60):
    srv, port = _start_lab(mode)
    try:
        target = TargetDef(name=f"Triage {mode}", vendor=f"Triage {mode}",
                           authorization="Company/9004", ips=["127.0.0.1"])
        recon = _recon(tmp_path, port, max_requests)
        result = run_triage(_app(tmp_path), target, recon,
                            profile_override="light", max_requests=max_requests)
        return result
    finally:
        srv.shutdown()
        srv.server_close()


def _audit_events(tmp_path) -> list[dict]:
    p = tmp_path / "audit" / "audit.jsonl"
    return [json.loads(x) for x in p.read_text(encoding="utf-8").splitlines() if x.strip()]


def test_three_lab_verdicts(tmp_path):
    cms = _run_mode(tmp_path / "cms", "cms")
    assert cms.report["conclusion"]["verdict"] == "建议深挖"
    assert cms.report["basics"]["alive_hosts"] == 1
    tech = {(x["product"], x["version"]) for x in cms.report["tech"]}
    assert ("WordPress", "5.8.2") in tech
    assert any(e["category"] == "backup" and e["status"] == 200
               for e in cms.report["exposures"])
    assert "WordPress 5.8.2" in Path(cms.paths["md"]).read_text(encoding="utf-8")

    waf = _run_mode(tmp_path / "waf", "waf")
    assert waf.report["conclusion"]["verdict"] in ("不建议", "可试")
    assert waf.report["waf"]
    assert any(e["status"] == 403 for e in waf.report["exposures"])

    static = _run_mode(tmp_path / "static", "static")
    assert static.report["conclusion"]["verdict"] == "不建议"
    assert not static.report["tech"]
    assert not static.report["exposures"]


def test_zero_scan_requests(tmp_path):
    result = _run_mode(tmp_path, "cms")
    events = _audit_events(tmp_path)
    assert events
    for e in events:
        stage = str(e.get("stage") or "").lower()
        assert not stage.startswith("scan")
        assert "nuclei" not in stage
        assert e.get("event") != "finding"
    assert result.report["basics"]["request_budget"]["used"] <= 60
    src = (ROOT / "modules" / "recon" / "triage.py").read_text(encoding="utf-8")
    assert "run_scan" not in src
    assert "core.scanner" not in src
    assert (Path(result.paths["md"])).exists()
    assert (Path(result.paths["json"])).exists()


def test_triage_budget_exhausted(tmp_path):
    result = _run_mode(tmp_path, "cms", max_requests=5)
    used = result.report["basics"]["request_budget"]["used"]
    assert used <= 5
    assert result.report["basics"]["request_budget"]["limit"] == 5
    assert result.report["basics"]["request_budget"]["exhausted"] is True or used < 5


def test_empty_target_report(tmp_path):
    target = TargetDef(name="Empty", vendor="Empty", authorization="Company/9005",
                       domains=[], ips=[])
    recon = _recon(tmp_path, 1, max_requests=5)
    result = run_triage(_app(tmp_path), target, recon, max_requests=5)
    assert result.report["basics"]["alive_hosts"] == 0
    assert result.report["conclusion"]["verdict"] == "不建议"
    assert result.report["basics"]["request_budget"]["used"] == 0


def test_timeout_and_no_fingerprint(tmp_path):
    target = TargetDef(name="Timeout", vendor="Timeout", authorization="Company/9006",
                       ips=["127.0.0.1"])
    recon = _recon(tmp_path, 1, max_requests=5)
    recon.profiles["light"].probe_timeout = 1
    result = run_triage(_app(tmp_path), target, recon, max_requests=5)
    assert result.report["basics"]["alive_hosts"] == 0
    assert result.report["conclusion"]["verdict"] == "不建议"
    assert result.warnings
