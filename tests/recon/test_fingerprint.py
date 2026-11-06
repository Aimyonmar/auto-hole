# -*- coding: utf-8 -*-
"""指纹引擎：规则语义 / 误报抑制 / 前置过滤正确性 / 内置库可加载。"""
from pathlib import Path

import pytest

from modules.recon.fingerprint import (FingerprintEngine, FingerprintError,
                                       MatchContext, rule_from_dict)

BUILTIN = Path(__file__).resolve().parents[2] / "modules/recon/fingerprints/builtin.yaml"


def _engine(rules, **kw):
    return FingerprintEngine([rule_from_dict(r) for r in rules], **kw)


def test_any_logic_matches_title():
    eng = _engine([{
        "id": "seeyon", "product": "致远OA", "confidence": 0.95, "logic": "any",
        "match": [{"type": "title", "contains": "致远"},
                  {"type": "body", "contains": "seeyon"}],
    }])
    out = eng.match(MatchContext(title="致远OA 协同管理", body="<html>hello</html>"))
    assert [m.product for m in out] == ["致远OA"]
    assert out[0].matched == ["title~致远"]


def test_negative_rule_vetoes_false_positive():
    eng = _engine([{
        "id": "nginx", "product": "Nginx", "confidence": 0.95, "logic": "any",
        "match": [{"type": "header", "name": "Server", "contains": "nginx"}],
        "negative": [{"type": "header", "name": "Server", "contains": "openresty"}],
    }, {
        "id": "openresty", "product": "OpenResty", "confidence": 0.95, "logic": "any",
        "match": [{"type": "header", "name": "Server", "contains": "openresty"}],
    }])
    out = eng.match(MatchContext(headers={"server": "openresty/1.21.4.1"}))
    assert [m.product for m in out] == ["OpenResty"]   # nginx 规则被 negative 否决


def test_all_logic_requires_every_condition():
    eng = _engine([{
        "id": "jumpserver", "product": "JumpServer", "confidence": 0.9, "logic": "all",
        "match": [{"type": "title", "contains": "jumpserver"},
                  {"type": "body", "contains": "koko"}],
    }])
    assert eng.match(MatchContext(title="JumpServer", body="<html>nothing</html>")) == []
    out = eng.match(MatchContext(title="JumpServer", body="koko assets"))
    assert [m.product for m in out] == ["JumpServer"]


def test_min_matched_weak_penalty():
    eng = _engine([{
        "id": "wps", "product": "WPS Office", "confidence": 0.8, "logic": "any",
        "min_matched": 2,
        "match": [{"type": "title", "contains": "wps"},
                  {"type": "body", "contains": "wps office"}],
    }], min_confidence=0.6, weak_match_penalty=0.7)
    # 只命中 1 个条件 → 0.8 * 0.7 = 0.56 < 0.6，被过滤
    assert eng.match(MatchContext(title="wps", body="plain")) == []
    # 两个条件都命中 → 0.8，保留
    out = eng.match(MatchContext(title="wps", body="wps office suite"))
    assert [m.product for m in out] == ["WPS Office"]
    assert out[0].confidence == pytest.approx(0.8)


def test_body_literal_prefilter_equivalence():
    """前置过滤关闭/开启时结果必须一致（防漏报）。"""
    rules = [{
        "id": "seeyon", "product": "致远OA", "confidence": 0.9, "logic": "any",
        "match": [{"type": "body", "contains": "seeyon"}, {"type": "body", "contains": "致远oa"}],
    }, {
        "id": "zentao", "product": "禅道ZenTao", "confidence": 0.9, "logic": "any",
        "match": [{"type": "body", "contains": "zentao"}],
    }]
    ctx = MatchContext(body="<html><title>未知</title>" + "填充" * 1000 + "seeyon")
    fast = _engine(rules, enable_prefilter=True).match(ctx)
    naive = _engine(rules, enable_prefilter=False).match(ctx)
    assert [m.product for m in fast] == [m.product for m in naive] == ["致远OA"]


def test_regex_and_status_and_favicon():
    rules = [{
        "id": "jboss", "product": "JBoss", "confidence": 0.85, "logic": "any",
        "match": [{"type": "header", "name": "Server", "regex": r"jboss\s*eap"}],
    }, {
        "id": "health", "product": "自建服务", "confidence": 0.8, "logic": "all",
        "match": [{"type": "status", "value": "200-299"},
                  {"type": "url", "contains": "/health"}],
    }, {
        "id": "fav", "product": "已知图标系统", "confidence": 0.9, "logic": "any",
        "match": [{"type": "favicon", "sha256": "abc123"}],
    }]
    eng = _engine(rules)
    out = eng.match(MatchContext(
        headers={"server": "JBoss EAP 7.4"}, status=200,
        url="http://a.com/health", favicon_sha256="abc123"))
    products = {m.product for m in out}
    assert "JBoss" in products
    assert "自建服务" in products
    assert "已知图标系统" in products


def test_invalid_rule_raises():
    with pytest.raises(FingerprintError):
        _engine([{"id": "x", "product": "X", "match": [{"type": "unknown", "contains": "a"}]}])
    with pytest.raises(FingerprintError):
        _engine([{"id": "", "product": "X", "match": [{"type": "title", "contains": "a"}]}])


def test_builtin_library_loads_and_matches():
    eng = FingerprintEngine.from_yaml(BUILTIN)
    st = eng.stats()
    assert st["rules"] >= 30
    assert st["prefilter"] is True

    ctx = MatchContext(
        url="http://a.example.com", status=200,
        title="致远OA V8.1 登录",
        headers={"server": "nginx/1.20"},
        body="<html><script src='/seeyon/common/js'></script></html>",
    )
    products = {m.product for m in eng.match(ctx)}
    assert "致远OA" in products
    assert "Nginx" in products

    # 普通页面不应误报
    clean = MatchContext(url="http://b.com", status=200, title="Welcome",
                         headers={"server": "nginx"}, body="<html>plain page</html>")
    assert [m.product for m in eng.match(clean)] == ["Nginx"]


def test_template_dirs_mapping():
    eng = FingerprintEngine.from_yaml(BUILTIN)
    dirs = eng.template_dirs_for(["致远OA"])
    assert "http/cves" in dirs
