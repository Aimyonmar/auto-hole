# -*- coding: utf-8 -*-
"""进化回路：候选生成 / 靶场验证 / 版本化入库与回滚 / 指标口径。"""
import http.server
import json
import socketserver
import threading
from pathlib import Path

import pytest
import yaml

from modules.recon.config import load_recon_config
from modules.recon.evolution import (Candidate, approve, build_metrics,
                                     fingerprint_candidate, list_versions,
                                     rollback, template_candidate,
                                     validate_fingerprints)
from modules.recon.fingerprint import FingerprintEngine
from modules.recon.schema import Finding

BUILTIN = Path(__file__).resolve().parents[2] / "modules/recon/fingerprints/builtin.yaml"


class _H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        status, body = self.server.routes.get(self.path.split("?")[0], (404, "not found"))
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *a):
        pass


def _serve(routes: dict):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _H)
    srv.daemon_threads = True
    srv.routes = routes
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def samples():
    pos = _serve({"/": (200, "<html><title>致远OA 登录</title>seeyon portal</html>")})
    neg = _serve({"/": (200, "<html><title>Welcome</title><body>plain page</body></html>")})
    yield f"http://127.0.0.1:{pos.server_address[1]}/", \
          f"http://127.0.0.1:{neg.server_address[1]}/"
    pos.shutdown()
    neg.shutdown()


def _finding(**kw) -> Finding:
    base = dict(
        template_id="demo-path-traversal", name="Demo Path Traversal",
        severity="high", host="127.0.0.1",
        matched_at="http://127.0.0.1:18090/download?file=../../../../etc/passwd",
        curl_command="curl http://x", tags=["lfi"],
        evidence={"status": 200,
                  "request": "GET /download?file=../../../../etc/passwd HTTP/1.1",
                  "response": "HTTP/1.0 200 OK\r\n\r\nroot:x:0:0:root:/root:/bin/bash"},
        value={"score": 52, "grade": "B"},
    )
    base.update(kw)
    return Finding(**base)


def test_template_candidate_generation():
    c = template_candidate(_finding())
    assert c is not None
    raw = yaml.safe_load(c["yaml"])
    assert raw["info"]["tags"][0] == "candidate"
    assert raw["http"][0]["path"][0].endswith("/download?file=../../../../etc/passwd")
    assert raw["http"][0]["matchers"][1]["words"][0].startswith("root:x:0:0")
    assert c["candidate"]["kind"] == "template"


def test_template_candidate_skips_without_marker():
    f = _finding(evidence={"status": 200, "request": "GET /a HTTP/1.1",
                           "response": "HTTP/1.1 200 OK\r\n\r\n"})
    assert template_candidate(f) is None


def test_fingerprint_candidate_from_feedback():
    eng = FingerprintEngine.from_yaml(BUILTIN)
    entry = {"product": "致远OA", "marker_type": "body",
             "marker_value": "演练环境", "host": "a.example.com"}
    c = fingerprint_candidate(entry, eng)
    assert c is not None
    raw = yaml.safe_load(c["yaml"])
    assert any(n.get("contains") == "演练环境" for n in raw["negative"])
    # 无既有规则 / 无标记 → 不生成
    assert fingerprint_candidate({**entry, "product": "不存在产品"}, eng) is None
    assert fingerprint_candidate({**entry, "marker_value": ""}, eng) is None


def test_validate_fingerprints_positive_negative(samples):
    pos, neg = samples
    eng = FingerprintEngine.from_yaml(BUILTIN)
    entry = {"product": "致远OA", "marker_type": "body",
             "marker_value": "演练环境", "host": "a.example.com"}
    raw = yaml.safe_load(fingerprint_candidate(entry, eng)["yaml"])
    tmp = Path(__file__)
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cd = Path(d)
        (cd / "fingerprints").mkdir()
        (cd / "fingerprints" / f"{raw['id']}.yaml").write_text(
            yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
        cand = Candidate(id=raw["id"], kind="fingerprint",
                         file=f"fingerprints/{raw['id']}.yaml", product="致远OA")
        out = validate_fingerprints(cd, [cand], pos, neg)
        assert out[0].status == "passed"
        assert "致远OA" in out[0].validation["positive_products"]
        assert out[0].validation["negative_products"] == []


def test_validate_fingerprints_fails_when_negative_marker_in_positive(samples):
    pos, _ = samples
    eng = FingerprintEngine.from_yaml(BUILTIN)
    entry = {"product": "致远OA", "marker_type": "body",
             "marker_value": "seeyon", "host": "a.example.com"}
    raw = yaml.safe_load(fingerprint_candidate(entry, eng)["yaml"])
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        cd = Path(d)
        (cd / "fingerprints").mkdir()
        (cd / "fingerprints" / f"{raw['id']}.yaml").write_text(
            yaml.safe_dump(raw, allow_unicode=True), encoding="utf-8")
        cand = Candidate(id=raw["id"], kind="fingerprint",
                         file=f"fingerprints/{raw['id']}.yaml", product="致远OA")
        # 负条件命中正样本 → 正样本不再命中 → failed
        out = validate_fingerprints(cd, [cand], pos, pos)
        assert out[0].status == "failed"


def _tmp_recon(tmp_path):
    recon = load_recon_config()
    recon.state.dir = str(tmp_path)
    lib = tmp_path / "lib.yaml"
    lib.write_text(BUILTIN.read_text(encoding="utf-8"), encoding="utf-8")
    recon.fingerprint.library = str(lib)
    return recon


def test_approve_requires_passed(tmp_path):
    recon = _tmp_recon(tmp_path)
    cdir = tmp_path / "cand"
    cdir.mkdir()
    (cdir / "c1.validation.json").write_text(json.dumps(
        {"id": "c1", "kind": "fingerprint", "status": "failed"}), encoding="utf-8")
    with pytest.raises(ValueError):
        approve(recon, cdir, "c1")


def test_approve_and_rollback(tmp_path):
    recon = _tmp_recon(tmp_path)
    cdir = tmp_path / "cand"
    (cdir / "fingerprints").mkdir(parents=True)
    rule = {
        "id": "ah-fp-test", "product": "致远OA", "confidence": 0.9,
        "logic": "any", "tags": ["candidate"],
        "match": [{"type": "title", "contains": "致远"}],
        "negative": [{"type": "body", "contains": "演练"}],
    }
    (cdir / "fingerprints" / "ah-fp-test.yaml").write_text(
        yaml.safe_dump(rule, allow_unicode=True), encoding="utf-8")
    (cdir / "ah-fp-test.validation.json").write_text(json.dumps(
        {"id": "ah-fp-test", "kind": "fingerprint",
         "file": "fingerprints/ah-fp-test.yaml", "status": "passed"}), encoding="utf-8")

    before = recon.fingerprint_library().read_text(encoding="utf-8")
    index = approve(recon, cdir, "ah-fp-test", note="test")
    after = recon.fingerprint_library().read_text(encoding="utf-8")
    assert "ah-fp-test" in after and after != before
    assert index["versions"][-1]["action"] == "approve"
    assert (recon.state_dir() / "evolution" / "versions" / "index.json").exists()

    rollback(recon, 1)
    restored = recon.fingerprint_library().read_text(encoding="utf-8")
    assert restored == before
    assert list_versions(recon)["versions"][-1]["action"] == "rollback"


def test_metrics_shape():
    summary = {"target": "t", "assets": {"alive": 10},
               "probe": {"requests": 50},
               "discovery": {"urls": 5},
               "timing": {"probe": 0.5, "scan": 2.0, "total": 3.0},
               "findings": {"by_grade": {"B": 1}}}
    findings = [_finding(), _finding(template_id="t2")]
    fb = [{"key": findings[0].key, "label": "false_positive"}]
    m = build_metrics(summary, findings, fb)
    assert m["hits"] == 2 and m["false_positives"] == 1
    assert m["precision"] == 0.5
    assert m["cost_per_hit_requests"] == 25.0
    assert m["stage_timing_s"]["scan"] == 2.0
