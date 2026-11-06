# -*- coding: utf-8 -*-
"""只读越权检测：纯判定、凭据脱敏、会话失效、预算、单账号、GET-only、靶场验证。"""
import importlib.util
import json
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from core.constitution import TargetDef
from modules.recon import authz as azmod
from modules.recon.audit import AuditLog
from modules.recon.authz import (AuthzBudget, AuthzRunner, AuthzSessionError,
                                  Candidate, ProberFetch, Response, classify,
                                  object_tokens, redact_text, similarity,
                                  write_outputs)
from modules.recon.authz_creds import (AuthzConfigError, AuthzPlan, Identity,
                                       prepare_accounts, prepare_accounts_from_file)
from modules.recon.config import (AuditConfig, AuthzConfig, FingerprintConfig,
                                  LimitsConfig, ReconConfig, SourcesConfig,
                                  StateConfig)
from modules.recon.ledger import slugify
from modules.recon.probe import Prober
from modules.recon.ratelimit import AdaptiveLimiter, BudgetLedger


def _ids():
    a = Identity(name="A", role="high", cookie="sid=A",
                 start_urls=["http://127.0.0.1:1/orders"],
                 session_check_url="http://127.0.0.1:1/api/me")
    b = Identity(name="B", role="low", cookie="sid=B",
                 session_check_url="http://127.0.0.1:1/api/me")
    return a, b


def _plan(settings=None, vertical=None):
    a, b = _ids()
    s = {"max_requests": 20, "similarity_threshold": 0.90,
         "public_similarity": 0.92, "max_candidates": 20,
         "max_vertical_paths": 5, "max_collect_pages": 2,
         "response_truncate": 400}
    s.update(settings or {})
    return AuthzPlan(
        target_name="Authz Test", accounts_path=Path("accounts.yaml"),
        identities=[a, b], owner=a, attacker=b, high=a, low=b,
        start_urls=list(a.start_urls), vertical_paths=list(vertical or []),
        vertical_base="http://127.0.0.1:1/orders",
        default_check_url="http://127.0.0.1:1/api/me", settings=s)


class FakeFetch:
    def __init__(self, mapping):
        self.mapping = mapping
        self.calls = []

    def __call__(self, identity, url, case):
        self.calls.append((identity.name, url, case))
        return self.mapping.get((identity.name, url))


def _resp(text, status=200):
    return Response(status=status, text=text, length=len(text))


def test_get_only_source_has_no_write_methods():
    source = Path(azmod.__file__).read_text(encoding="utf-8").lower()
    for bad in (".post(", ".put(", ".delete(", ".patch(", "requests.request(",
                'method="post"', "method='post'"):
        assert bad not in source


def test_object_identifier_detection():
    kinds = {t["kind"] for t in object_tokens(
        "http://x/orders/550e8400-e29b-41d4-a716-446655440000?user_id=1")}
    assert "uuid" in kinds
    assert "numeric" in kinds
    assert not object_tokens("http://x/static/app.css")
    # 非对象参数不应被测
    assert not object_tokens("http://x/list?page=2&sort=desc")
    assert "numeric" in {t["kind"] for t in object_tokens("http://x/detail?id=1")}


def test_similarity_and_threshold_boundary(monkeypatch):
    assert similarity("same text here", "same text here")[0] == 1.0
    a = _resp('{"id":1,"name":"alice","role":"user"}')
    b = _resp('{"id":1,"name":"alice","role":"user"}')
    assert classify(a, b, threshold=0.90, public_similarity=0.92)["verdict"] == "suspect"
    # 直接卡阈值：0.900 命中，0.899 正常
    monkeypatch.setattr(azmod, "similarity", lambda x, y: (0.9, {"length_ratio": 1.0}))
    assert classify(a, b, threshold=0.90, public_similarity=0.92)["verdict"] == "suspect"
    monkeypatch.setattr(azmod, "similarity", lambda x, y: (0.899, {"length_ratio": 1.0}))
    assert classify(a, b, threshold=0.90, public_similarity=0.92)["verdict"] == "normal"
    # B 403 / 404 直接正常
    assert classify(a, _resp("forbidden", 403), threshold=0.9,
                    public_similarity=0.92)["verdict"] == "normal"
    assert classify(a, _resp("no", 404), threshold=0.9,
                    public_similarity=0.92)["verdict"] == "normal"


def test_public_page_suppression():
    a = _resp('{"notice_id":123,"title":"public notice","content":"welcome"}')
    b = _resp('{"notice_id":123,"title":"public notice","content":"welcome"}')
    anon = _resp('{"notice_id":123,"title":"public notice","content":"welcome"}')
    result = classify(a, b, threshold=0.9, public_similarity=0.92, anonymous=anon)
    assert result["verdict"] == "suppressed_public"


def test_session_expired_fails_before_replay():
    plan = _plan()
    fetch = FakeFetch({
        ("A", "http://127.0.0.1:1/api/me"): _resp('{"user":"A"}'),
        ("B", "http://127.0.0.1:1/api/me"): _resp("unauthorized", 401),
    })
    runner = AuthzRunner(plan=plan, fetch=fetch, target=TargetDef(
        name="t", vendor="t", authorization="x", ips=["127.0.0.1"]))
    with pytest.raises(AuthzSessionError) as e:
        runner.precheck()
    assert "身份 B" in str(e.value) and "401" in str(e.value)
    assert len(fetch.calls) == 2
    assert not any(c[2].startswith("horizontal") for c in fetch.calls)


def test_budget_exhausted_stops():
    plan = _plan({"max_requests": 2})
    fetch = FakeFetch({
        ("A", "http://127.0.0.1:1/api/me"): _resp('{"user":"A"}'),
        ("B", "http://127.0.0.1:1/api/me"): _resp('{"user":"B"}'),
    })
    runner = AuthzRunner(plan=plan, fetch=fetch, target=TargetDef(
        name="t", vendor="t", authorization="x", ips=["127.0.0.1"]))
    result = runner.run()
    assert result.summary["budget_exhausted"] is True
    assert result.summary["requests"] <= 2
    assert len(fetch.calls) <= 2


def test_single_account_rejected(tmp_path):
    target = TargetDef(name="单账号", vendor="单账号", authorization="x", ips=["127.0.0.1"])
    with pytest.raises(AuthzConfigError) as e:
        prepare_accounts(
            target_name=target.name, identities_raw=[
                {"name": "A", "role": "high", "cookie": "sid=A",
                 "session_check_url": "http://127.0.0.1:1/api/me"}],
            accounts_dir=tmp_path / "accounts", vault_path=tmp_path / "v.enc",
            key_path=tmp_path / "v.key", domains=[], ips=target.ips,
            vendor=target.vendor, authorization=target.authorization)
    assert "至少需要 2 个身份" in str(e.value)


def test_credentials_encrypted_and_redacted(tmp_path):
    target = TargetDef(name="凭据测试", vendor="凭据测试", authorization="x", ips=["127.0.0.1"])
    meta, data = prepare_accounts(
        target_name=target.name, identities_raw=[
            {"name": "A", "role": "high", "cookie": "sid=SECRET-A",
             "session_check_url": "http://127.0.0.1:1/api/me"},
            {"name": "B", "role": "low", "cookie": "sid=SECRET-B",
             "headers": "X-Api-Key: KEY-SECRET-B",
             "session_check_url": "http://127.0.0.1:1/api/me"}],
        accounts_dir=tmp_path / "accounts", vault_path=tmp_path / "v.enc",
        key_path=tmp_path / "v.key", domains=[], ips=target.ips,
        vendor=target.vendor, authorization=target.authorization)
    assert meta.exists()
    meta_text = meta.read_text(encoding="utf-8")
    assert "SECRET-A" not in meta_text and "SECRET-B" not in meta_text
    raw_vault = (tmp_path / "v.enc").read_bytes().decode("utf-8", "ignore")
    assert "SECRET-A" not in raw_vault and "KEY-SECRET-B" not in raw_vault
    assert (tmp_path / "v.key").exists()
    a, b = _ids()
    a.cookie, b.cookie = "sid=SECRET-A", "sid=SECRET-B"
    b.headers = {"X-Api-Key": "KEY-SECRET-B"}
    sample = redact_text(json.dumps({
        "order_id": 1, "email": "a@example.invalid",
        "debug_cookie": "sid=SECRET-A", "admin_token": "TOPSECRET",
    }), [a, b])
    assert "SECRET-A" not in sample and "KEY-SECRET-B" not in sample
    assert "a@example.invalid" not in sample and "TOPSECRET" not in sample
    assert len(sample) <= 401


def _lab_module():
    path = Path(__file__).resolve().parents[2] / "outputs" / "authz-demo" / "lab_server.py"
    spec = importlib.util.spec_from_file_location("authz_demo_lab", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _lab_recon(tmp_path):
    return ReconConfig(
        profile="light",
        audit=AuditConfig(enabled=True, path=str(tmp_path / "audit")),
        state=StateConfig(dir=str(tmp_path / "state")),
        sources=SourcesConfig(enabled=["seed"], path_dict=""),
        fingerprint=FingerprintConfig(library=str(Path(__file__).resolve().parents[2] /
                                                    "modules" / "recon" / "fingerprints" /
                                                    "builtin.yaml")),
        limits=LimitsConfig(daily_request_limit=500, failure_threshold=5,
                            cooldown_seconds=10),
        authz=AuthzConfig(
            enabled=True, auto_run=True, max_requests=60,
            similarity_threshold=0.90, public_similarity=0.92,
            accounts_dir=str(tmp_path / "accounts"),
            vault_path=str(tmp_path / "vault.enc"),
            key_path=str(tmp_path / "vault.key")),
    )


def _start_lab():
    mod = _lab_module()
    srv = ThreadingHTTPServer(("127.0.0.1", 0), mod.Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _lab_plan(tmp_path, port):
    target = TargetDef(name="Authz Lab", vendor="Authz Lab",
                       authorization="Company/9001", ips=["127.0.0.1"])
    plain = tmp_path / "plain.yaml"
    plain.write_text(yaml.safe_dump({
        "identities": [
            {"name": "A", "role": "high", "cookie": "sid=A",
             "start_urls": [f"http://127.0.0.1:{port}/orders"],
             "session_check_url": f"http://127.0.0.1:{port}/api/me"},
            {"name": "B", "role": "low", "cookie": "sid=B",
             "session_check_url": f"http://127.0.0.1:{port}/api/me"},
        ],
        "vertical": {"paths": ["/admin/audit", "/admin/users"]},
        "settings": {"max_requests": 60, "similarity_threshold": 0.90},
    }, allow_unicode=True), encoding="utf-8")
    recon = _lab_recon(tmp_path)
    meta, _ = prepare_accounts_from_file(
        target=target, plain_path=plain, accounts_dir=tmp_path / "accounts",
        vault_path=tmp_path / "vault.enc", key_path=tmp_path / "vault.key")
    from modules.recon.authz_creds import load_plan
    plan = load_plan(target, recon, required=True)
    return target, recon, meta, plan


def test_lab_true_idor_control_public_and_vertical(tmp_path):
    srv, port = _start_lab()
    try:
        target, recon, meta, plan = _lab_plan(tmp_path, port)
        limiter = AdaptiveLimiter(rps=20, concurrency=1, burst=1,
                                  min_rps=1, failure_threshold=5, cooldown_s=10)
        ledger = BudgetLedger(tmp_path / "budget.db", target.name, 500)
        audit = AuditLog(tmp_path / "audit" / "audit.jsonl", target.name, enabled=True)
        prober = Prober(recon=recon, target=target,
                        profile=recon.active_profile(), limiter=limiter,
                        ledger=ledger, audit=audit, engine=None,
                        console=lambda m: None)
        fetch = ProberFetch(prober, plan, console=lambda m: None)
        runner = AuthzRunner(plan=plan, fetch=fetch, target=target,
                             console=lambda m: None)
        runner.precheck()
        result = runner.run(precheck=False)
        summary = write_outputs(result, target_dir=tmp_path / "run",
                                audit=audit, plan=plan)
        assert summary["suspects"] == 2
        assert summary["horizontal_suspects"] == 1
        assert summary["vertical_suspects"] == 1
        assert summary["suppressed_public"] == 1
        assert summary["normal"] == 2
        assert summary["budget_exhausted"] is False
        urls = {s["url"] for s in result.suspects}
        assert any("/orders/1001" in u for u in urls)
        assert any("/admin/audit" in u for u in urls)
        assert not any("/orders/1002" in u for u in urls)
        assert not any("/admin/users" in u for u in urls)
        assert not any("/public/notice/123" in u for u in urls)
        # 凭据与敏感值不得出现在证据/审计/报告
        for p in [tmp_path / "run" / "authz.jsonl",
                  tmp_path / "run" / "authz-summary.json",
                  tmp_path / "run" / "authz-report.md",
                  tmp_path / "audit" / "audit.jsonl"]:
            text = p.read_text(encoding="utf-8")
            assert "sid=A" not in text and "sid=B" not in text
            assert "SUPER_SECRET_TOKEN" not in text
        ledger.close()
    finally:
        srv.shutdown()
        srv.server_close()


def test_plan_requires_two_identities(tmp_path):
    target = TargetDef(name="单账号", vendor="单账号", authorization="x", ips=["127.0.0.1"])
    recon = _lab_recon(tmp_path)
    meta = tmp_path / "accounts" / f"{slugify(target.name)}.yaml"
    meta.parent.mkdir(parents=True)
    meta.write_text(yaml.safe_dump({
        "target": target.name, "identities": [
            {"name": "A", "role": "high", "credential_id": "x",
             "session_check": {"url": "http://127.0.0.1:1/api/me"}}],
    }, allow_unicode=True), encoding="utf-8")
    from modules.recon.authz_creds import load_plan
    with pytest.raises(AuthzConfigError) as e:
        load_plan(target, recon, required=True)
    assert "至少需要 2 个身份" in str(e.value)
