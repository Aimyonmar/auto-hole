# -*- coding: utf-8 -*-
"""按产品分组扫描：分组、模板定向、过滤与上限。"""
from pathlib import Path

from modules.recon.fingerprint import FingerprintEngine
from modules.recon.schema import Asset
from modules.recon.targeting import (estimate_requests, group_by_product,
                                     primary_product)

BUILTIN = Path(__file__).resolve().parents[2] / "modules/recon/fingerprints/builtin.yaml"


def _asset(host, url, product=None, status=200, confidence=0.9, rule="seeyon-oa"):
    return Asset(host=host, port=0, url=url, status=status,
                 products=([{"product": product, "rule_id": rule, "confidence": confidence}]
                           if product else []))


def test_primary_product_uses_highest_confidence():
    a = Asset(host="a.com", products=[
        {"product": "Nginx", "rule_id": "nginx", "confidence": 0.95},
        {"product": "致远OA", "rule_id": "seeyon-oa", "confidence": 0.7},
    ])
    assert primary_product(a) == "Nginx"
    assert primary_product(Asset(host="b.com")) == ""


def test_group_by_product_and_template_dirs():
    eng = FingerprintEngine.from_yaml(BUILTIN)
    assets = [
        _asset("a.com", "http://a.com", "致远OA"),
        _asset("b.com", "http://b.com", "致远OA"),
        _asset("c.com", "http://c.com", "Nginx", rule="nginx"),
        _asset("d.com", "http://d.com", None, rule=""),
    ]
    groups = group_by_product(assets, eng, include_unidentified=False)
    names = {g.product for g in groups}
    assert names == {"致远OA", "Nginx"}
    for g in groups:
        if g.product == "致远OA":
            assert "http/cves" in g.template_dirs
    assert len(groups[0].urls) == 2          # 组按 URL 数降序

    groups2 = group_by_product(assets, eng, include_unidentified=True)
    assert "unidentified" in {g.product for g in groups2}


def test_group_filters_status_and_processed():
    assets = [
        _asset("a.com", "http://a.com", "致远OA", status=0),     # 未存活
        _asset("b.com", "http://b.com", "致远OA", status=500),   # 服务端错误
        _asset("c.com", "http://c.com", "致远OA", status=200),
    ]
    groups = group_by_product(assets, None, processed=lambda u: "c.com" in u,
                              max_urls_per_group=10)
    assert groups == []                       # 唯一可用 URL 已被处理


def test_limits():
    assets = [_asset(f"h{i}.com", f"http://h{i}.com", "致远OA") for i in range(5)]
    g = group_by_product(assets, None, max_urls_per_group=2, max_groups=1)
    assert len(g) == 1 and len(g[0].urls) == 2
    assert estimate_requests(g[0]) == 30


def test_no_engine_still_groups():
    assets = [_asset("a.com", "http://a.com", "致远OA")]
    g = group_by_product(assets, None)
    assert g[0].product == "致远OA" and g[0].template_dirs == []


def test_require_template_dirs_skips_generic_component():
    """有指纹库时，纯 Nginx 这类“无模板目录”的产品不占用扫描配额。"""
    eng = FingerprintEngine.from_yaml(BUILTIN)
    assets = [
        _asset("a.com", "http://a.com", "致远OA"),
        _asset("c.com", "http://c.com", "Nginx", rule="nginx"),
    ]
    groups = group_by_product(assets, eng, require_template_dirs=True)
    assert {g.product for g in groups} == {"致远OA"}

    # 关闭该选项时仍会保留 Nginx 组（走默认标签）
    groups2 = group_by_product(assets, eng, require_template_dirs=False)
    assert {g.product for g in groups2} == {"致远OA", "Nginx"}
