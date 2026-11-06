# -*- coding: utf-8 -*-
"""批量编排 / 历史去重与校准 / 结构化报告导出（全部本地，无网络）。"""
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

from core.config import AppConfig, PathsConfig
from core.constitution import TargetDef

from modules.recon.batch import load_manifest, run_batch
from modules.recon.config import load_recon_config
from modules.recon.history import (HistoryStore, calibrate, history_key,
                                   is_public_known, path_of)
from modules.recon.report_export import build_report, export_findings
from modules.recon.schema import Asset, Finding


def _target_file(tmp_path: Path, name: str) -> Path:
    p = tmp_path / f"{name}.yaml"
    p.write_text(yaml.safe_dump({
        "name": name, "vendor": "v",
        "authorization": "本地授权", "ips": ["127.0.0.1"],
    }, allow_unicode=True), encoding="utf-8")
    return p


def _fake_result(hits=1, requests=5):
    finding = Finding(template_id="t1", name="RCE", severity="high",
                      host="127.0.0.1", matched_at="http://127.0.0.1/x",
                      value={"score": 60, "grade": "A", "vuln_class": "远程代码执行"})
    return SimpleNamespace(findings=[finding] * hits, assets=[Asset(host="127.0.0.1")],
                           summary={"probe": {"requests": requests}},
                           elapsed_s=0.1, paths={"metrics": "m.json"})


def test_manifest_priority_sort(tmp_path):
    m = tmp_path / "batch.yaml"
    m.write_text(yaml.safe_dump({"targets": [
        {"file": str(_target_file(tmp_path, "b")), "priority": 2},
        {"file": str(_target_file(tmp_path, "a")), "priority": 1},
    ]}, allow_unicode=True), encoding="utf-8")
    entries = load_manifest(m)
    assert entries[0]["priority"] == 1
    assert entries[1]["priority"] == 2


def test_batch_isolation_and_resume(tmp_path, monkeypatch):
    recon = load_recon_config()
    recon.state.dir = str(tmp_path)
    app = AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                      reports=str(tmp_path / "rp"),
                                      db=str(tmp_path / "ws" / "d.db")))
    files = [_target_file(tmp_path, "ok1"), _target_file(tmp_path, "bad"), _target_file(tmp_path, "ok2")]
    manifest = tmp_path / "batch.yaml"
    manifest.write_text(yaml.safe_dump({"targets": [
        {"file": str(f), "priority": i} for i, f in enumerate(files)]}), encoding="utf-8")

    calls = []

    def fake_run(app_, target, cfg, **kw):
        calls.append(target.name)
        if target.name == "bad":
            raise RuntimeError("模拟目标失败")
        return _fake_result()

    monkeypatch.setattr("modules.recon.batch.run_target", fake_run)
    summary = run_batch(app, manifest, recon, console=lambda m: None)
    names = [r["name"] for r in summary["results"]]
    assert "bad" in names and any("error" in r for r in summary["results"])
    assert {"ok1", "ok2"} <= set(names)
    assert summary["targets_total"] == 3

    # 第二轮：已完成的不再执行，失败的不再重试（失败计数已达阈值则熔断）
    calls.clear()
    run_batch(app, manifest, recon, console=lambda m: None)
    assert "ok1" not in calls


def test_batch_global_quota_blocks(tmp_path, monkeypatch):
    recon = load_recon_config()
    recon.state.dir = str(tmp_path)
    app = AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                      reports=str(tmp_path / "rp"),
                                      db=str(tmp_path / "ws" / "d.db")))
    manifest = tmp_path / "b.yaml"
    manifest.write_text(yaml.safe_dump({"targets": [
        {"file": str(_target_file(tmp_path, "x"))}]}), encoding="utf-8")
    monkeypatch.setattr("modules.recon.batch._db_usage", lambda app_: 9999)
    monkeypatch.setattr("modules.recon.batch.run_target",
                        lambda *a, **k: pytest.fail("不应执行"))
    summary = run_batch(app, manifest, recon, global_daily_limit=100,
                        console=lambda m: None)
    assert summary["results"][0].get("skipped") == "全局日配额已用尽"


# ---------------------------------------------------------------- history
def _f(tid="t1", path="/x", cls="远程代码执行", host="a.com"):
    f = Finding(template_id=tid, name="n", severity="high", host=host,
                matched_at=f"http://{host}{path}")
    f.value = {"vuln_class": cls, "score": 60, "grade": "A"}
    return f


def test_history_key_and_dedupe(tmp_path):
    db = tmp_path / "h.db"
    st = HistoryStore(db)
    f1 = _f(tid="t1")
    f2 = _f(tid="t2")            # 同 host+路径+类型 → 同 key
    assert history_key(f1) == history_key(f2)
    assert st.check(f1)["status"] == "new"
    st.record("t", [f1])
    assert st.check(f2)["status"] == "new"
    assert st.check(f2)["times_seen"] == 1
    assert st.mark(history_key(f1), "reported")
    assert st.check(f2)["status"] == "reported"
    st.close()


def test_history_distinguishes_path_and_class(tmp_path):
    st = HistoryStore(tmp_path / "h2.db")
    a = _f(path="/a")
    b = _f(path="/b")
    c = _f(path="/a", cls="SQL注入")
    assert len({history_key(a), history_key(b), history_key(c)}) == 3
    st.close()


def test_calibration_suppresses_bad_template():
    findings = [_f(tid="bad") for _ in range(3)] + [_f(tid="good") for _ in range(3)]
    feedback = [{"template_id": "bad", "label": "false_positive"} for _ in range(3)]
    cal = calibrate(findings, feedback, min_samples=3, fp_rate_threshold=0.5)
    assert "bad" in cal["suppressed_templates"]
    assert "good" not in cal["suppressed_templates"]
    assert cal["per_template"]["bad"]["fp_rate"] == 0.5


def test_public_known_cve_and_list():
    old = _f(tid="CVE-2019-1234")
    new = _f(tid="CVE-2026-1234")
    assert is_public_known(old, {"templates": [], "products": []})
    assert not is_public_known(new, {"templates": [], "products": []})
    assert is_public_known(_f(tid="custom-1"),
                           {"templates": ["custom-1"], "products": []})


# ---------------------------------------------------------------- export
def test_build_report_fields():
    target = TargetDef(name="t", vendor="某某科技", authorization="补天SRC", ips=["a.com"])
    f = _f()
    f.product = "致远OA"
    f.value = {"score": 52, "grade": "B", "advice": "可提交", "vuln_class": "任意文件读取/下载",
               "reasons": ["high 40", "文件读取 12"], "history_status": "new"}
    f.curl_command = "curl http://a.com/x"
    f.evidence = {"request": "GET /x HTTP/1.1", "response": "HTTP/1.0 200\r\n\r\nroot:x",
                  "matcher": "word", "extracted": ["root"]}
    r = build_report(f, target)
    assert r["title"] == "某某科技致远OA存在n漏洞"
    assert r["risk_level"] == "高危"
    assert r["reproduction"]["curl"].startswith("curl")
    assert "root:x" in r["evidence"]["response"]
    assert r["history_status"] == "new"
    assert r["value"]["score"] == 52


def test_export_md_and_json(tmp_path):
    target = TargetDef(name="t", vendor="v", authorization="a", ips=["a.com"])
    findings = [_f(tid="t1"), _f(tid="t2", cls="敏感信息泄露")]
    findings[0].value["score"] = 70
    findings[1].value["score"] = 20
    md = export_findings(findings, [], target, tmp_path / "md", min_score=0,
                         console=lambda m: None)
    assert len(md) == 2 and (tmp_path / "md" / "index.md").exists()
    js = export_findings(findings, [], target, tmp_path / "js", fmt="json",
                         min_score=40, console=lambda m: None)
    assert len(js) == 1 and (tmp_path / "js" / "index.json").exists()
    data = json.loads(js[0].read_text(encoding="utf-8"))
    assert data["schema"] == "recon.report/v1"
