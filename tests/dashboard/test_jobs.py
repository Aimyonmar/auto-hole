# -*- coding: utf-8 -*-
"""面板任务：表单校验、串行队列、取消进程树、CSRF、脏数据容错。"""
import ctypes
import json
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from core.constitution import load_target
from dashboard.data import DashboardData
from dashboard.jobs import (JobManager, JobStore, SubmissionError,
                            read_log_tail, validate_submission)
from dashboard.server import create_server


def _payload(**over):
    data = {
        "vendor": "测试厂商", "program_url": "Company/12345",
        "scope": "a.example.com\n1.2.3.4",
        "include_subdomains": False, "include_third_party": False,
        "restrictions_raw": "禁止破坏性测试",
        "tier": "light", "authorized": True,
    }
    data.update(over)
    return data


def _errors(payload, tmp_path) -> list[str]:
    try:
        validate_submission(payload, tmp_path / "authorized")
    except SubmissionError as e:
        return e.errors
    return []


def test_validation_rejections(tmp_path):
    assert any("授权依据" in e or "项目" in e for e in
               _errors(_payload(program_url=""), tmp_path))
    assert any("范围" in e for e in _errors(_payload(scope=" \n "), tmp_path))
    assert any("通配符" in e for e in _errors(_payload(scope="*.example.com"), tmp_path))
    assert any("禁止自动化" in e for e in
               _errors(_payload(restrictions_raw="禁止自动化扫描"), tmp_path))
    assert any("第三方" in e for e in
               _errors(_payload(include_third_party=True), tmp_path))
    assert any("档位" in e for e in _errors(_payload(tier="deep"), tmp_path))
    assert any("勾选" in e for e in _errors(_payload(authorized=False), tmp_path))


def test_authz_submission_encrypts_credentials(tmp_path):
    payload = _payload(vendor="越权面板测试", authz={
        "enabled": True,
        "max_requests": 50,
        "similarity_threshold": 0.9,
        "identities": [
            {"name": "A", "role": "high", "cookie": "sid=SECRET-A",
             "start_urls": ["http://a.example.com/orders"],
             "session_check_url": "http://a.example.com/api/me"},
            {"name": "B", "role": "low", "cookie": "sid=SECRET-B",
             "headers": "X-Api-Key: KEY-SECRET-B",
             "session_check_url": "http://a.example.com/api/me"},
        ],
    })
    path, it = validate_submission(
        payload, tmp_path / "targets" / "authorized",
        authz_dir=tmp_path / "targets" / "authz",
        vault_path=tmp_path / "workspace" / "authz" / "vault.enc",
        key_path=tmp_path / "workspace" / "authz" / "vault.key")
    ledger = path.read_text(encoding="utf-8")
    assert "sid=SECRET-A" not in ledger and "sid=SECRET-B" not in ledger
    assert "authz_accounts" in ledger
    meta = tmp_path / "targets" / "authz" / f"{path.stem}.yaml"
    assert meta.exists()
    assert "SECRET-A" not in meta.read_text(encoding="utf-8")
    vault = (tmp_path / "workspace" / "authz" / "vault.enc").read_bytes()
    assert b"SECRET-A" not in vault and b"KEY-SECRET-B" not in vault
    assert (tmp_path / "workspace" / "authz" / "vault.key").exists()


def test_authz_single_account_rejected(tmp_path):
    payload = _payload(vendor="单账号测试", authz={
        "enabled": True,
        "identities": [
            {"name": "A", "role": "high", "cookie": "sid=A",
             "session_check_url": "http://a.example.com/api/me"},
        ],
    })
    with pytest.raises(SubmissionError) as e:
        validate_submission(payload, tmp_path / "targets" / "authorized",
                            authz_dir=tmp_path / "targets" / "authz",
                            vault_path=tmp_path / "workspace" / "authz" / "vault.enc",
                            key_path=tmp_path / "workspace" / "authz" / "vault.key")
    assert any("至少需要 2 个身份" in x for x in e.value.errors)


def test_triage_job_command_and_data(tmp_path):
    mgr, store = _manager(tmp_path)
    job = mgr.submit({**_payload(vendor="体检目标", tier="light"),
                      "kind": "triage", "max_requests": 5})
    assert job["kind"] == "triage"
    assert job["max_requests"] == 5
    cmd = mgr._build_command(job)
    assert "triage" in cmd
    assert "--max-requests" in cmd
    assert "batch" not in cmd
    run = tmp_path / "runs" / "Triage Target"
    run.mkdir(parents=True)
    (run / "summary.json").write_text(json.dumps({
        "kind": "triage", "target": "Triage Target",
        "generated_at": "2026-11-02T20:00:00", "profile": {"name": "light"},
        "elapsed_s": 2, "assets": {"total": 1, "alive": 1},
        "findings": {"total": 0}, "probe": {}, "scan": {},
        "timing": {"triage": 2}, "warnings": [],
        "triage": {"verdict": "建议深挖", "score": 9},
    }), encoding="utf-8")
    (run / "triage.json").write_text(json.dumps({
        "schema": "recon.triage/v1", "target": "Triage Target",
        "generated_at": "2026-11-02T20:00:00",
        "basics": {"alive_hosts": 1, "ports": [18080]},
        "tech": [{"product": "WordPress", "version": "5.8.2"}],
        "exposures": [], "risks": [], "duplicates": [], "waf": [],
        "cost": {"estimated_requests": 100, "recommended_tier": "standard"},
        "conclusion": {"verdict": "建议深挖", "score": 9, "reason": "test"},
    }, ensure_ascii=False), encoding="utf-8")
    (run / "triage.md").write_text("# triage\n", encoding="utf-8")
    data = DashboardData(tmp_path, data_dirs=[tmp_path / "runs"])
    rid = data.runs()[0]["id"]
    detail = data.triage(rid)
    assert detail["conclusion"]["verdict"] == "建议深挖"
    assert data.runs()[0]["kind"] == "triage"
    assert data.runs()[0]["has_triage"] is True
    assert data.triage_report(rid, "md").startswith("# triage")
    mgr.shutdown()
    store.close()


def test_authz_dashboard_data(tmp_path):
    run = tmp_path / "runs" / "Authz Lab"
    run.mkdir(parents=True)
    (run / "summary.json").write_text(json.dumps({
        "target": "Authz Lab", "generated_at": "2026-11-02T18:00:00",
        "profile": {"name": "light"}, "elapsed_s": 3,
        "assets": {"total": 1, "alive": 1}, "findings": {"total": 0},
        "probe": {}, "scan": {}, "timing": {"authz": 2}, "warnings": [],
    }), encoding="utf-8")
    (run / "authz-summary.json").write_text(json.dumps({
        "suspects": 2, "horizontal_suspects": 1, "vertical_suspects": 1,
        "suppressed_public": 1, "normal": 2, "horizontal_tested": 3,
        "vertical_tested": 2, "threshold": 0.9, "identities": [],
    }), encoding="utf-8")
    (run / "authz.jsonl").write_text(json.dumps({
        "kind": "horizontal", "url": "http://a/orders/1001", "method": "GET",
        "identity_a": "A", "identity_b": "B", "a_status": 200, "b_status": 200,
        "a_len": 100, "b_len": 100, "similarity": 0.98, "threshold": 0.9,
        "reason": "B 200 且高相似", "sensitive_fields": ["email"],
        "a_sample": "A sample", "b_sample": "B sample", "evidence_score": 2.98,
    }, ensure_ascii=False) + "\n", encoding="utf-8")
    data = DashboardData(tmp_path, data_dirs=[tmp_path / "runs"])
    rid = data.runs()[0]["id"]
    detail = data.authz(rid)
    assert detail["has_authz"] is True
    assert detail["summary"]["suspects"] == 2
    assert detail["items"][0]["url"] == "http://a/orders/1001"
    assert detail["items"][0]["a_sample"] == "A sample"


def test_derive_automation_clauses():
    from dashboard.jobs import derive_automation
    assert derive_automation("允许授权范围内的低速率自动化扫描；禁止拒绝服务测试") == "yes"
    assert derive_automation("平台禁止自动化扫描") == "no"
    assert derive_automation("平台未明确允许自动化") == "unstated"
    assert derive_automation("禁止破坏性测试") == "unstated"


def test_valid_submission_writes_ledger(tmp_path):
    path, it = validate_submission(_payload(), tmp_path / "authorized")
    assert path.exists()
    from modules.recon.intake import load_intake
    loaded = load_intake(path)
    assert loaded.ok
    assert loaded.domains == ["a.example.com"]
    assert loaded.ips == ["1.2.3.4"]
    assert "approved" in path.read_text(encoding="utf-8")
    # 档案可被命令行解析成可执行目标
    from modules.recon.ledger import resolve_identifier
    from modules.recon.config import load_recon_config
    recon = load_recon_config()
    recon.state.dir = str(tmp_path / "state")
    tpath, intake_obj, err = resolve_identifier(str(path), recon, console=lambda m: None)
    assert not err and tpath and load_target(tpath)


def test_store_queue_positions_and_dirty(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    a = store.add(job_id="a", vendor="v1", ledger="l1", tier="light", log_path="x")
    b = store.add(job_id="b", vendor="v2", ledger="l2", tier="light", log_path="y")
    assert store.queue_position("a") == 1
    assert store.queue_position("b") == 2
    store.cancel_queued("a")
    assert store.queue_position("b") == 1
    store.finish("b", "failed", 1, "x")
    assert store.get("b")["status"] == "failed"
    assert store.get("missing") is None
    store.close()


def _manager(tmp_path, **kw):
    store = JobStore(tmp_path / "jobs.db")
    mgr = JobManager(store, app_dir=tmp_path, frozen=False,
                     config_path=tmp_path / "config.yaml",
                     recon_config=tmp_path / "recon.yaml",
                     authorized_dir=tmp_path / "authorized",
                     audit=lambda *a, **k: None,
                     logger=lambda *a, **k: None, **kw)
    return mgr, store


def test_jobs_are_serial(tmp_path):
    mgr, store = _manager(tmp_path)
    active = {"now": 0, "max": 0}
    lock = threading.Lock()

    def fake_run(job):
        with lock:
            active["now"] += 1
            active["max"] = max(active["max"], active["now"])
        time.sleep(0.35)
        with lock:
            active["now"] -= 1
        store.finish(job["id"], "done", 0)

    mgr._run_job = fake_run
    j1 = mgr.submit(_payload(vendor="串行A"))
    j2 = mgr.submit(_payload(vendor="串行B", scope="b.example.com"))
    mgr.start()
    deadline = time.time() + 8
    while time.time() < deadline:
        if store.get(j1["id"])["status"] == "done" and \
                store.get(j2["id"])["status"] == "done":
            break
        time.sleep(0.1)
    assert store.get(j1["id"])["status"] == "done"
    assert store.get(j2["id"])["status"] == "done"
    assert active["max"] == 1
    mgr.shutdown()
    store.close()


def _alive(pid: int) -> bool:
    try:
        h = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
        if not h:
            return False
        ctypes.windll.kernel32.CloseHandle(h)
        return True
    except Exception:
        return False


@pytest.mark.skipif(sys.platform != "win32", reason="Windows 进程树")
def test_cancel_kills_process_tree(tmp_path):
    mgr, store = _manager(tmp_path)
    mgr._build_command = lambda job: [
        sys.executable, "-c", "import time; time.sleep(30)"]
    job = mgr.submit(_payload(vendor="取消测试"))
    mgr.start()
    deadline = time.time() + 5
    while time.time() < deadline:
        j = store.get(job["id"])
        if j["status"] == "running" and j["pid"]:
            break
        time.sleep(0.1)
    assert store.get(job["id"])["status"] == "running"
    pid = store.get(job["id"])["pid"]
    assert _alive(pid)
    assert mgr.cancel(job["id"])
    deadline = time.time() + 8
    while time.time() < deadline:
        if store.get(job["id"])["status"] == "canceled":
            break
        time.sleep(0.1)
    assert store.get(job["id"])["status"] == "canceled"
    deadline = time.time() + 5
    while time.time() < deadline and _alive(pid):
        time.sleep(0.1)
    assert not _alive(pid)
    mgr.shutdown()
    store.close()


def test_failure_does_not_block_queue(tmp_path):
    mgr, store = _manager(tmp_path)

    def cmd(job):
        if job["vendor"] == "失败A":
            return [sys.executable, "-c", "import sys; sys.exit(2)"]
        return [sys.executable, "-c", "pass"]

    mgr._build_command = cmd
    j1 = mgr.submit(_payload(vendor="失败A"))
    j2 = mgr.submit(_payload(vendor="成功B", scope="b.example.com"))
    mgr.start()
    deadline = time.time() + 10
    while time.time() < deadline:
        if store.get(j2["id"])["status"] == "done":
            break
        time.sleep(0.1)
    assert store.get(j1["id"])["status"] == "failed"
    assert store.get(j2["id"])["status"] == "done"
    mgr.shutdown()
    store.close()


def test_timeout_marks_failed_and_kills(tmp_path):
    mgr, store = _manager(tmp_path, timeout_s=2)
    mgr._build_command = lambda job: [
        sys.executable, "-c", "import time; time.sleep(30)"]
    job = mgr.submit(_payload(vendor="超时测试"))
    mgr.start()
    deadline = time.time() + 12
    while time.time() < deadline:
        j = store.get(job["id"])
        if j["status"] == "failed":
            break
        time.sleep(0.1)
    j = store.get(job["id"])
    assert j["status"] == "failed"
    assert "超时" in j["error"]
    pid = j["pid"]
    deadline = time.time() + 5
    while time.time() < deadline and _alive(pid):
        time.sleep(0.1)
    assert not _alive(pid)
    mgr.shutdown()
    store.close()


def test_nonzero_exit_marks_failed(tmp_path):
    mgr, store = _manager(tmp_path)
    mgr._build_command = lambda job: [sys.executable, "-c", "import sys; sys.exit(3)"]
    job = mgr.submit(_payload(vendor="失败测试"))
    mgr.start()
    deadline = time.time() + 8
    while time.time() < deadline:
        if store.get(job["id"])["status"] == "failed":
            break
        time.sleep(0.1)
    j = store.get(job["id"])
    assert j["status"] == "failed" and j["exit_code"] == 3
    mgr.shutdown()
    store.close()


# ------------------------------------------------------------------ HTTP
@pytest.fixture
def server(tmp_path):
    store = JobStore(tmp_path / "jobs.db")
    mgr = JobManager(store, app_dir=tmp_path, frozen=False,
                     config_path=tmp_path / "config.yaml",
                     recon_config=tmp_path / "recon.yaml",
                     authorized_dir=tmp_path / "authorized",
                     audit=lambda *a, **k: None, logger=lambda *a, **k: None)
    data = DashboardData(root=tmp_path, db_path=tmp_path / "none.db",
                         data_dirs=[tmp_path / "data"], targets_dir=tmp_path / "authorized")
    srv = create_server("127.0.0.1", 0, data, jobs=mgr, token="test-token")
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield base, mgr, store
    srv.shutdown()
    srv.server_close()
    store.close()


def _post(url, payload, token="", origin=""):
    req = urllib.request.Request(url, method="POST",
                                 data=json.dumps(payload).encode("utf-8"))
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("X-AutoHole-Token", token)
    if origin:
        req.add_header("Origin", origin)
    return urllib.request.urlopen(req, timeout=5)


def test_csrf_token_and_origin(server):
    base, _, _ = server
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(base + "/api/jobs", _payload())
    assert e.value.code == 403
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(base + "/api/jobs", _payload(), token="test-token",
              origin="http://evil.example")
    assert e.value.code == 403
    localhost = base.replace("127.0.0.1", "localhost")
    resp = _post(base + "/api/jobs", _payload(), token="test-token",
                 origin=localhost)
    assert resp.status == 201


def test_submit_http_validates_and_enqueues(server):
    base, mgr, store = server
    with pytest.raises(urllib.error.HTTPError) as e:
        _post(base + "/api/jobs", _payload(program_url=""), token="test-token")
    assert e.value.code == 400
    body = json.loads(e.value.read().decode("utf-8"))
    assert any("授权依据" in x or "项目" in x for x in body["errors"])
    resp = _post(base + "/api/jobs", _payload(), token="test-token", origin=base)
    assert resp.status == 201
    data = json.loads(resp.read().decode("utf-8"))
    assert data["job"]["status"] == "queued"
    assert data["queue_position"] == 1
    with urllib.request.urlopen(base + "/api/jobs", timeout=5) as r:
        items = json.loads(r.read().decode("utf-8"))["items"]
    assert len(items) == 1


def test_jobs_empty_and_missing(tmp_path):
    data = DashboardData(root=tmp_path, db_path=tmp_path / "none.db",
                         data_dirs=[tmp_path / "data"], targets_dir=tmp_path / "authorized")
    srv = create_server("127.0.0.1", 0, data)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{srv.server_address[1]}"
        with urllib.request.urlopen(base + "/api/jobs", timeout=5) as r:
            assert json.loads(r.read().decode("utf-8"))["items"] == []
        with pytest.raises(urllib.error.HTTPError) as e:
            urllib.request.urlopen(base + "/api/jobs/xxx", timeout=5)
        assert e.value.code == 503
    finally:
        srv.shutdown()
        srv.server_close()
