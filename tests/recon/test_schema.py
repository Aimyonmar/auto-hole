# -*- coding: utf-8 -*-
"""统一 schema：归一化 / 去重 / 合并 / 命中标准化。"""
from modules.recon.schema import (Asset, Finding, build_url, dedupe, extract_title,
                                  normalize_host, normalize_severity, normalize_url)


def test_normalize_host():
    assert normalize_host("HTTPS://A.Example.com:8443/x?y=1") == "a.example.com"
    assert normalize_host("http://example.com/") == "example.com"
    assert normalize_host("[::1]:8080") == "::1"
    assert normalize_host("  Example.COM  ") == "example.com"
    assert normalize_host("") == ""


def test_normalize_url():
    host, port, scheme, url = normalize_url("https://a.example.com")
    assert (host, port, scheme) == ("a.example.com", 443, "https")
    assert url == "https://a.example.com"

    host, port, scheme, url = normalize_url("a.example.com:8080")
    assert (host, port, scheme, url) == ("a.example.com", 8080, "http",
                                         "http://a.example.com:8080")


def test_build_url():
    assert build_url("a.com", 443, "https") == "https://a.com"
    assert build_url("a.com", 8080) == "http://a.com:8080"
    assert build_url("a.com", 8443) == "https://a.com:8443"


def test_dedupe_merge_union():
    a = Asset(host="a.com", port=8080, sources=["subfinder"], tech=["nginx"], status=200)
    b = Asset(host="A.com", port=8080, sources=["hunter"], tech=["PHP"], title="首页",
              products=[{"product": "Nginx", "rule_id": "nginx", "confidence": 0.95}])
    c = Asset(host="a.com", port=8080, sources=["subfinder"],
              products=[{"product": "Nginx", "rule_id": "nginx", "confidence": 0.9}])
    merged = dedupe([a, b, c])
    assert len(merged) == 1
    m = merged[0]
    assert m.sources == ["subfinder", "hunter"]
    assert m.tech == ["nginx", "PHP"]
    assert m.title == "首页"                      # 空值不覆盖已有值
    assert len(m.products) == 1 and m.products[0]["confidence"] == 0.95   # 取最高置信度


def test_asset_port_defaults_and_key():
    a = Asset(host="a.com", port=0)
    assert a.url == "http://a.com"
    assert a.key == "a.com|0"


def test_asset_roundtrip_keeps_unknown_port():
    """端口未知（0）的资产序列化再读回，不能被 URL 的默认端口覆盖成 80。"""
    a = Asset(host="a.com", port=0, url="http://a.com")
    back = Asset.from_dict(a.to_dict())
    assert back.port == 0 and back.key == "a.com|0"


def test_asset_url_with_explicit_port_sets_port():
    a = Asset(host="a.com", url="https://a.com:8443/x")
    assert a.port == 8443 and a.scheme == "https"
    assert a.url == "https://a.com:8443"


def test_finding_from_nuclei():
    line = {
        "template-id": "CVE-2021-1234", "type": "http",
        "info": {"name": "Test RCE", "severity": "High"},
        "host": "http://a.example.com:8080", "matched-at": "http://a.example.com:8080/x",
        "curl-command": "curl -X POST ...",
    }
    f = Finding.from_nuclei(line)
    assert f.template_id == "CVE-2021-1234"
    assert f.severity == "high"
    assert f.host == "a.example.com"
    assert f.key.startswith("CVE-2021-1234|a.example.com|")

    assert Finding.from_nuclei({"type": "stats", "template-id": ""}) is None


def test_severity_normalize():
    for raw, want in [("CRITICAL", "critical"), ("高危", "high"), ("", "unknown"),
                      ("weird", "unknown"), ("info", "info")]:
        assert normalize_severity(raw) == want


def test_extract_title():
    assert extract_title("<html><title> 致远 OA </title></html>") == "致远 OA"
    assert extract_title("<html>no title</html>") == ""
    assert extract_title("<TITLE>x</TITLE>") == "x"
