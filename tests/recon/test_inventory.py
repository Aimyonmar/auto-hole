# -*- coding: utf-8 -*-
"""跨目标产品盘点：实例计数口径、通用门槛、报告渲染。"""
from modules.recon.inventory import (build_inventory, render_md,
                                     write_inventory)
from modules.recon.schema import Asset


def _asset(host: str, product: str, status: int = 200, port: int = 443,
           confidence: float = 0.9, rule: str = "r1") -> Asset:
    return Asset(host=host, port=port, status=status,
                 products=[{"product": product, "rule_id": rule,
                            "confidence": confidence}],
                 url=f"https://{host}")


def _targets():
    return [
        ("t1", [
            _asset("a.example.com", "致远OA"),
            _asset("b.example.com", "致远OA"),
            _asset("b.example.com", "致远OA", port=8080),   # 同主机不同端口 → 只算 1
            _asset("c.example.com", "Nginx"),
        ]),
        ("t2", [
            _asset("d.example.com", "致远OA"),
            _asset("e.example.com", "致远OA", status=0),    # 未存活 → 不计实例
            _asset("f.example.com", "Nginx"),
        ]),
    ]


def test_instances_count_distinct_alive_hosts():
    inv = build_inventory(_targets(), min_instances=100)
    by_name = {p["product"]: p for p in inv["products"]}
    assert by_name["致远OA"]["instances"] == 3          # a, b, d（多端口不重复）
    assert by_name["致远OA"]["discovered"] == 5         # 含未存活那条
    assert by_name["Nginx"]["instances"] == 2
    assert by_name["致远OA"]["targets"] == ["t1", "t2"]


def test_generic_ready_and_near_ready():
    inv = build_inventory(_targets(), min_instances=3)
    assert inv["generic_ready"] == ["致远OA"]
    assert {p["product"] for p in inv["products"] if p["generic_ready"]} == {"致远OA"}

    inv2 = build_inventory(_targets(), min_instances=4)
    assert inv2["generic_ready"] == []
    assert {"致远OA", "Nginx"} <= set(inv2["near_ready"])   # 3 与 2 都接近门槛


def test_samples_limited_and_unique():
    assets = [("t1", [_asset(f"h{i}.example.com", "致远OA") for i in range(20)])]
    inv = build_inventory(assets, min_instances=100)
    p = inv["products"][0]
    assert len(p["samples"]) == 10
    assert len(set(p["samples"])) == 10


def test_render_and_write(tmp_path):
    inv = build_inventory(_targets(), min_instances=3)
    md = render_md(inv)
    assert "已达门槛" in md and "致远OA" in md
    assert "通用1.0" in md
    out = write_inventory(inv, tmp_path / "inv.json", tmp_path / "inv.md")
    assert out.exists() and (tmp_path / "inv.json").exists()
    assert "致远OA" in out.read_text(encoding="utf-8")
