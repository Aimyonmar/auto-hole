# -*- coding: utf-8 -*-
"""面板后端：空库/脏数据/缺字段容错、分页、只读、零外网。"""
import json
import socket
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

from dashboard.data import DashboardData
from dashboard.server import create_server


def _write_json(p: Path, data: dict):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def _write_jsonl(p: Path, items: list):
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = []
    for it in items:
        if isinstance(it, str):
            lines.append(it)
        else:
            lines.append(json.dumps(it, ensure_ascii=False))
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.fixture
def dataset(tmp_path):
    data_dir = tmp_path / "data"
    run = data_dir / "run1"
    _write_json(run / "summary.json", {
        "target": "某某科技", "generated_at": "2026-11-02T04:20:00",
        "profile": {"name": "light"}, "elapsed_s": 12.5,
        "assets": {"total": 3, "alive": 2},
        "findings": {"total": 2},
        "probe": {"requests": 5, "effective_rps": 4.2},
        "scan": {"requests_estimated": 30, "urls": 2},
        "timing": {"discover": 2.0, "probe": 0.5, "scan": 9.0, "total": 12.5},
        "limits": {"runtime": {"circuit": "closed"},
                   "budget": {"daily_limit": 500, "used": 35, "remaining": 465}},
        "warnings": ["配额截断"],
    })
    _write_json(run / "metrics.json", {"hits": 2, "false_positives": 1})
    _write_jsonl(run / "assets.jsonl", [
        {"host": "a.example.com", "port": 443, "url": "https://a.example.com",
         "status": 200, "title": "<script>alert(1)</script>", "server": "nginx",
         "products": [{"product": "致远OA", "confidence": 0.95, "rule_id": "seeyon"}],
         "sources": ["seed"]},
        {"host": "b.example.com", "port": 80, "status": 403, "title": "b"},
        {"host": "c.example.com"},          # 缺字段
        "not-json",                          # 脏行
    ])
    _write_jsonl(run / "findings.jsonl", [
        {"template_id": "t1", "name": "RCE", "severity": "high", "host": "a.example.com",
         "matched_at": "https://a.example.com/x", "product": "致远OA",
         "tags": ["rce", "demo"], "curl_command": "curl https://a.example.com/x",
         "value": {"score": 70, "grade": "A", "advice": "优先提交", "vuln_class": "远程代码执行"},
         "evidence": {"request": "GET /x HTTP/1.1" + " A" * 400,
                      "response": "HTTP/1.1 200 OK", "matcher": "word"}},
        {"template_id": "t2", "severity": "low"},   # 缺 name/host
        "garbage-line",
    ])
    _write_jsonl(run / "audit.jsonl", [
        {"ts": "2026-11-02T04:20:01", "target": "某某科技", "event": "request",
         "host": "a.example.com", "url": "https://a.example.com", "status": 200,
         "elapsed_ms": 12.3, "rps": 4.2, "outcome": "ok"},
        {"ts": "2026-11-02T04:20:02", "target": "某某科技", "event": "request",
         "host": "b.example.com", "status": 429, "outcome": "throttled"},
        {"ts": "2026-11-02T04:20:03", "target": "other", "event": "request",
         "host": "x", "status": 200},
    ])
    _write_jsonl(run / "feedback.jsonl", [
        {"key": "t2|b", "template_id": "t2", "label": "false_positive"},
    ])
    (run / "evidence").mkdir()
    (run / "evidence" / "20261102-A70-RCE-t1.md").write_text("# report\n", encoding="utf-8")

    # 第二个运行（无 summary 的 assets-only）
    run2 = data_dir / "run2"
    _write_jsonl(run2 / "assets.jsonl", [{"host": "d.example.com", "status": 200}])

    # 授权档案
    targets = tmp_path / "authorized"
    targets.mkdir()
    (targets / "ok.yaml").write_text(yaml.safe_dump({
        "vendor": "某某科技", "registration_status": "approved",
        "authorization_ref": "项目页", "tier": "light",
        "scope": {"domains": ["a.example.com"], "ips": []},
        "restrictions": {"automation_allowed": "unstated"},
    }, allow_unicode=True), encoding="utf-8")
    (targets / "blocked.yaml").write_text(yaml.safe_dump({
        "vendor": "待审厂商", "registration_status": "pending",
        "authorization_ref": "", "scope": {"domains": ["b.example.com"]},
        "restrictions": {"automation_allowed": "no"},
    }, allow_unicode=True), encoding="utf-8")

    # 进化候选与版本
    cand = data_dir / "evolution" / "candidates" / "20261102_0420"
    cand.mkdir(parents=True)
    _write_json(cand / "ah-cand-1.validation.json", {
        "id": "ah-cand-1", "kind": "template", "status": "passed",
        "product": "", "validation": {"positive_hit": "http://x", "negative_hit": None},
        "reasons": ["来自 t1"],
    })
    _write_json(data_dir / "evolution" / "versions" / "index.json", {
        "versions": [{"version": 1, "action": "approve", "candidate": "ah-fp-1",
                      "note": "test", "created_at": "2026-11-02T04:30:00"}]
    })

    return DashboardData(root=tmp_path, db_path=tmp_path / "missing.db",
                         data_dirs=[data_dir], targets_dir=targets)


def test_runs_discovery_dedup(dataset):
    runs = dataset.runs()
    assert len(runs) == 2
    run = next(r for r in runs if r["target"] == "某某科技")
    assert run["assets_alive"] == 2
    assert run["requests_scan_estimated"] == 30


def test_overview(dataset):
    o = dataset.overview()
    assert o["runs"] == 2
    assert o["findings"] == 2
    assert o["severity"]["high"] == 1
    assert o["severity"]["low"] == 1
    assert o["false_positives"] == 1
    assert o["false_positive_rate"] == 50.0
    assert o["avg_elapsed_s"] == 12.5


def test_empty_dataset(tmp_path):
    data = DashboardData(root=tmp_path, db_path=tmp_path / "nope.db",
                         data_dirs=[tmp_path / "empty"], targets_dir=tmp_path / "none")
    o = data.overview()
    assert o["runs"] == 0 and o["assets"] == 0 and o["findings"] == 0
    assert o["false_positive_rate"] is None
    assert data.runs() == []
    assert data.targets() == []
    assert data.evolution() == {"candidates": [], "versions": []}
    assert data.assets("missing")["items"] == []
    assert data.audit("missing")["items"] == []


def test_assets_pagination_and_dirty(dataset):
    run = next(r for r in dataset.runs() if r["target"] == "某某科技")
    page = dataset.assets(run["id"], page=1, size=2)
    assert page["total"] == 3              # 脏行被跳过，缺字段仍保留
    assert len(page["items"]) == 2
    assert page["pages"] == 2
    assert page["items"][0]["title"] == "<script>alert(1)</script>"
    p2 = dataset.assets(run["id"], page=2, size=2)
    assert len(p2["items"]) == 1


def test_findings_filter_and_truncate(dataset):
    run = next(r for r in dataset.runs() if r["target"] == "某某科技")
    allf = dataset.findings(run["id"], page=1, size=10)
    assert allf["total"] == 2
    assert allf["items"][0]["has_report"] is True
    assert allf["items"][0]["truncated"] is True
    high = dataset.findings(run["id"], severity="high")
    assert high["total"] == 1
    none = dataset.findings(run["id"], severity="critical")
    assert none["total"] == 0
    detail = dataset.finding_detail(run["id"], "t1", "a.example.com",
                                    "https://a.example.com/x")
    assert detail["evidence"]["matcher"] == "word"


def test_targets_blocked(dataset):
    items = dataset.targets()
    assert len(items) == 2
    ok = [x for x in items if x["executable"]]
    bad = [x for x in items if not x["executable"]]
    assert len(ok) == 1 and ok[0]["last_hits"] == 2
    assert any("报名状态" in r for r in bad[0]["reasons"])
    assert any("禁止自动化" in r for r in bad[0]["reasons"])


def test_evolution_and_versions(dataset):
    ev = dataset.evolution()
    assert len(ev["candidates"]) == 1
    assert ev["candidates"][0]["status"] == "passed"
    assert any(v.get("version") == 1 and v.get("action") == "approve" for v in ev["versions"])


def test_audit_filter_and_pagination(dataset):
    run = next(r for r in dataset.runs() if r["target"] == "某某科技")
    page = dataset.audit(run["id"], page=1, size=10)
    assert page["total"] == 2               # 只保留本目标
    assert page["items"][0]["ts"].endswith("02")   # 倒序
    assert page["items"][0]["outcome"] == "throttled"


def test_run_detail(dataset):
    run = next(r for r in dataset.runs() if r["target"] == "某某科技")
    d = dataset.run_detail(run["id"])
    assert d["requests"]["probe_measured"] == 5
    assert d["requests"]["scan_estimated"] == 30
    assert any(s["stage"] == "scan" for s in d["stages"])
    assert d["limiter"]["throttled"] == 1
    assert d["quota"]["used"] == 35


# ---------------------------------------------------------------- HTTP
@pytest.fixture
def server(dataset):
    srv = create_server("127.0.0.1", 0, dataset)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()
    srv.server_close()


def _get(url: str):
    with urllib.request.urlopen(url, timeout=5) as r:
        return r.status, r.read().decode("utf-8")


def test_http_endpoints(server):
    status, body = _get(server + "/api/overview")
    assert status == 200 and '"runs": 2' in body
    status, body = _get(server + "/")
    assert status == 200 and "只读面板" in body
    status, body = _get(server + "/static/app.js")
    assert status == 200 and "function esc" in body
    with pytest.raises(urllib.error.HTTPError) as e:
        _get(server + "/api/run?id=missing")
    assert e.value.code == 404


def test_http_readonly_and_traversal(server):
    # 未带本地 token 的写请求一律 403（CSRF 防线）
    req = urllib.request.Request(server + "/api/overview", method="POST", data=b"x")
    with pytest.raises(urllib.error.HTTPError) as e:
        urllib.request.urlopen(req, timeout=5)
    assert e.value.code == 403
    try:
        _get(server + "/static/../../config.yaml")
    except urllib.error.HTTPError as err:
        assert err.code in (403, 404)
    else:
        pytest.fail("路径穿越未被拦截")


def test_server_rejects_non_loopback():
    with pytest.raises(ValueError):
        create_server("0.0.0.0", 0, DashboardData(root=Path.cwd()))


def test_no_external_urls_in_frontend():
    static = Path(__file__).resolve().parents[2] / "dashboard" / "static"
    for p in static.rglob("*"):
        if p.is_file():
            text = p.read_text(encoding="utf-8", errors="replace")
            assert "http://" not in text
            assert "https://" not in text
            assert "cdn." not in text


def test_no_outbound_network(server, monkeypatch):
    """只允许回环连接；任何非本地地址都会断言失败。"""
    orig = socket.create_connection

    def guard(address, *a, **k):
        host = address[0] if isinstance(address, tuple) else str(address)
        assert host in ("127.0.0.1", "::1", "localhost"), f"外部网络请求: {host}"
        return orig(address, *a, **k)

    monkeypatch.setattr(socket, "create_connection", guard)
    status, body = _get(server + "/api/runs")
    assert status == 200
