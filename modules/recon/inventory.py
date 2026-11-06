# -*- coding: utf-8 -*-
"""跨目标产品盘点（通用1.0 影响力证明的本地底稿）。

为什么单独做：
- 公益SRC 看“单点漏洞”，通用1.0 看“同一产品公网实例 ≥100”；
- 工具每个目标只保存自己的 assets.jsonl，没有全局产品视图 → 无法判断某个产品够不够规模。
- 本模块只读本地 JSONL，不发起任何请求，可随时重算。

计数口径：
- instances = 存活资产（status>0）的**去重 host 数**（同一主机多端口只算 1 台）
- 只统计已实探存活的资产；collect-only 未探测的资产计入 discovered 但不计入 instances
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

from core.config import AppConfig

from .adapters import read_assets_jsonl
from .config import ReconConfig, load_recon_config
from .fingerprint import FingerprintEngine, FingerprintError
from .schema import Asset

GENERIC_MIN_INSTANCES = 100


@dataclass
class ProductEntry:
    product: str
    instances: int = 0
    discovered: int = 0
    targets: list = field(default_factory=list)
    samples: list = field(default_factory=list)
    max_confidence: float = 0.0
    rules: list = field(default_factory=list)
    template_dirs: list = field(default_factory=list)

    @property
    def generic_ready(self) -> bool:
        return self.instances >= GENERIC_MIN_INSTANCES

    def to_dict(self) -> dict:
        return dict(self.__dict__)


def collect_target_assets(state_dir: Path) -> list[tuple[str, list[Asset]]]:
    """读取 workspace/recon/<target>/assets.jsonl，返回 (target, assets)。"""
    out: list[tuple[str, list[Asset]]] = []
    if not state_dir.exists():
        return out
    for d in sorted(state_dir.iterdir()):
        if not d.is_dir() or d.name.startswith("_"):
            continue
        assets = read_assets_jsonl(d / "assets.jsonl")
        if assets:
            out.append((d.name, assets))
    return out


def build_inventory(target_assets: Iterable[tuple[str, list[Asset]]],
                    engine: Optional[FingerprintEngine] = None,
                    min_instances: int = GENERIC_MIN_INSTANCES) -> dict:
    entries: dict[str, ProductEntry] = {}
    targets_meta: dict[str, dict] = {}

    for target, assets in target_assets:
        alive = [a for a in assets if a.status and a.status > 0]
        hosts_by_product: dict[str, set[str]] = {}
        targets_meta[target] = {"assets": len(assets), "alive": len(alive)}

        for a in assets:
            for p in a.products:
                name = p.get("product", "")
                if not name:
                    continue
                e = entries.setdefault(name, ProductEntry(product=name))
                e.discovered += 1
                if target not in e.targets:
                    e.targets.append(target)
                if a.status and a.status > 0:
                    hosts_by_product.setdefault(name, set()).add(a.host)
                    e.samples = _add_sample(e.samples, a.url or a.host)
                e.max_confidence = max(e.max_confidence, float(p.get("confidence", 0)))
                rid = p.get("rule_id", "")
                if rid and rid not in e.rules:
                    e.rules.append(rid)

        for name, hosts in hosts_by_product.items():
            entries[name].instances += len(hosts)

    if engine is not None:
        for name, e in entries.items():
            e.template_dirs = engine.template_dirs_for([name])

    products = []
    for e in entries.values():
        d = e.to_dict()
        d["generic_ready"] = e.instances >= min_instances   # 按本次阈值判定，便于自定义门槛
        products.append(d)
    products.sort(key=lambda x: (-x["instances"], x["product"]))
    return {
        "schema": "recon.inventory/v1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "min_instances": int(min_instances),
        "targets": targets_meta,
        "totals": {
            "targets": len(targets_meta),
            "products": len(products),
            "alive_assets": sum(t["alive"] for t in targets_meta.values()),
        },
        "generic_ready": [p["product"] for p in products if p["instances"] >= min_instances],
        "near_ready": [p["product"] for p in products
                       if min_instances // 2 <= p["instances"] < min_instances],
        "products": products,
    }


def _add_sample(samples: list, url: str) -> list:
    if not url:
        return samples
    if len(samples) < 10 and url not in samples:
        samples.append(url)
    return samples


def render_md(inv: dict) -> str:
    lines = [
        f"# 产品资产盘点 — {inv.get('generated_at', '')}",
        "",
        f"- 目标数：{inv['totals']['targets']}；产品数：{inv['totals']['products']}；"
        f"存活资产：{inv['totals']['alive_assets']}",
        f"- 通用1.0 门槛：同产品公网实例 ≥ {inv.get('min_instances')} 台（本工具按去重 host 计数）",
        "",
    ]

    ready = inv.get("generic_ready") or []
    lines += ["## 已达门槛（优先做定向扫描 + 取证）", ""]
    if ready:
        lines += ["| 产品 | 实例数 | 置信度 | 目标 | 模板目录 |", "|---|---|---|---|---|"]
        for p in inv["products"]:
            if p["product"] in ready:
                lines.append(f"| {p['product']} | {p['instances']} | "
                             f"{p['max_confidence']:.2f} | {', '.join(p['targets'])} | "
                             f"{', '.join(p['template_dirs']) or '-'} |")
    else:
        lines.append("（暂无。可先扩大采集规模，或导入测绘平台导出的资产清单）")

    near = inv.get("near_ready") or []
    if near:
        lines += ["", "## 接近门槛（补量收益最高）", "",
                  "| 产品 | 实例数 | 还差 | 目标 |", "|---|---|---|---|"]
        for p in inv["products"]:
            if p["product"] in near:
                gap = max(0, inv["min_instances"] - p["instances"])
                lines.append(f"| {p['product']} | {p['instances']} | {gap} | {', '.join(p['targets'])} |")

    lines += ["", "## 全部产品", "",
              "| 产品 | 存活实例 | 发现总数 | 最高置信度 | 规则 |", "|---|---|---|---|---|"]
    for p in inv["products"]:
        lines.append(f"| {p['product']} | {p['instances']} | {p['discovered']} | "
                     f"{p['max_confidence']:.2f} | {', '.join(p['rules']) or '-'} |")

    lines += [
        "", "## 使用建议", "",
        "1. 优先挑“已达门槛”的产品，跑 `main.py recon -t <目标> --stage scan` 做定向 POC；",
        "2. “接近门槛”的产品补量最划算：用测绘平台导出资产清单，放到 `workspace/import/<目标名>.txt`；",
        "3. 提交通用1.0 时附上本清单的实例数与截图，作为影响力证明；",
        "4. 本清单只统计本机已采集且存活的资产，不代表平台测绘总量。",
        "",
        "> 仅统计本地授权目标数据；不外传、不自动提交。",
    ]
    return "\n".join(lines) + "\n"


def write_inventory(inv: dict, json_path: Path, md_path: Path) -> Path:
    json_path.parent.mkdir(parents=True, exist_ok=True)
    tmp = json_path.with_suffix(".tmp")
    tmp.write_text(json.dumps(inv, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(json_path)
    md_path.write_text(render_md(inv), encoding="utf-8")
    return md_path


def _load_engine(recon: ReconConfig) -> Optional[FingerprintEngine]:
    lib = recon.fingerprint_library()
    if not lib.exists():
        return None
    try:
        return FingerprintEngine.from_yaml(lib)
    except FingerprintError:
        return None


def main(app: AppConfig, *, min_instances: int = GENERIC_MIN_INSTANCES,
         recon_config: str | None = None,
         console: Callable[[str], None] = print) -> int:
    recon = load_recon_config(recon_config)
    state_dir = recon.state_dir()
    target_assets = collect_target_assets(state_dir)
    if not target_assets:
        console(f"[!] {state_dir} 下没有可盘点的 assets.jsonl（先跑 recon collect/probe）")
        return 1

    inv = build_inventory(target_assets, _load_engine(recon), min_instances)
    md = write_inventory(inv, state_dir / "inventory.json", state_dir / "inventory.md")

    console(f"[*] 目标 {inv['totals']['targets']} 个 / 产品 {inv['totals']['products']} 个 / "
            f"存活资产 {inv['totals']['alive_assets']} 条")
    for p in inv["products"][:10]:
        flag = "已达通用门槛" if p["generic_ready"] else ""
        console(f"    - {p['product']}: {p['instances']} 台 {flag}")
    console(f"[✓] 盘点清单：{md}")
    console("[i] 通用1.0 提交需附影响力证明；本清单只统计本机已采集资产，不代表平台测绘总量")
    return 0
