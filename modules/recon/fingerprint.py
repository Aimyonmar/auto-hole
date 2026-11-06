# -*- coding: utf-8 -*-
"""指纹匹配引擎：规则库 + 条件短路 + 字面量前置过滤 + 负向规则抑制误报。

借鉴点（EHole / ObserverWard / Wappalyzer / finger）：
1. 规则结构：一条规则 = 产品 + 置信度 + 一组条件（any/all）+ 排除条件（negative）
2. 条件类型按成本分级：状态码/hash → 标题 → 响应头 → 正文子串 → 正文正则
   （finger 与 Wappalyzer 都是先比对便宜的特征，贵特征只在必要时执行）
3. 字面量前置过滤：把所有正文 contains 规则的字面量合成一条大正则，
   不命中即可断定“这批条件全不成立”，省掉 N 次正文扫描
4. 误报抑制：negative 规则可直接否决；any 逻辑下只命中部分条件时按惩罚系数降权；
   最终按 min_confidence 过滤
5. 输出附带命中依据（matched conditions），便于人工复核
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Optional

import yaml

COND_TYPES = {"header", "title", "body", "url", "status", "favicon"}
COST = {"status": 0, "favicon": 0, "url": 1, "title": 2, "header": 3, "body": 4}


class FingerprintError(ValueError):
    """规则库格式错误。"""


@dataclass
class Condition:
    type: str
    name: str = ""             # header 名称
    contains: str = ""
    regex: str = ""
    value: str = ""            # 精确匹配
    sha256: str = ""           # favicon hash
    _re: Optional[re.Pattern] = field(default=None, repr=False, compare=False)

    @property
    def cost(self) -> int:
        c = COST.get(self.type, 9)
        if self.regex:
            c = 5 if self.type != "body" else 6
        return c

    @property
    def literal(self) -> str:
        """用于索引的字面量（仅正文 contains 条件，长度 ≥ 3）。"""
        if self.type == "body" and self.contains and len(self.contains) >= 3:
            return self.contains.lower()
        return ""

    def compile(self) -> None:
        if self.regex:
            try:
                self._re = re.compile(self.regex, re.IGNORECASE)
            except re.error as e:
                raise FingerprintError(f"非法正则 {self.regex!r}: {e}") from e

    def describe(self) -> str:
        if self.type == "header":
            return f"header[{self.name}]{self._pattern_label()}"
        return f"{self.type}{self._pattern_label()}"

    def _pattern_label(self) -> str:
        if self.contains:
            return f"~{self.contains}"
        if self.regex:
            return f"/{self.regex}/"
        if self.sha256:
            return f"#{self.sha256[:8]}"
        if self.value:
            return f"={self.value}"
        return ""

    # ---- 求值 ----
    def eval(self, ctx: "MatchContext", literals_present: bool = True) -> bool:
        if self.type == "status":
            return _match_status(ctx.status, self.value or self.contains)
        if self.type == "favicon":
            want = (self.sha256 or self.value or self.contains).lower()
            return bool(want) and ctx.favicon_sha256.lower() == want

        if self.type == "header":
            text = ctx.headers.get(self.name.lower(), "")
            if not text:
                return False
        elif self.type == "title":
            text = ctx.title
        elif self.type == "url":
            text = ctx.url
        elif self.type == "body":
            text = ctx.body
            if self.contains and not literals_present:
                return False   # 前置过滤已证明所有字面量都不在正文里
        else:
            raise FingerprintError(f"未知条件类型: {self.type}")

        if not text:
            return False
        low = text.lower()
        if self.contains:
            return self.contains.lower() in low
        if self.regex:
            return bool(self._re and self._re.search(text))
        if self.value:
            return low.strip() == self.value.lower().strip()
        return bool(text)


def _match_status(actual: int, spec: str) -> bool:
    """状态码条件：200 / "200-299" / "200,301,404" / "2xx"。"""
    s = str(spec or "").strip().lower()
    if not s:
        return False
    if s.endswith("xx") and s[:-2].isdigit():
        base = int(s[:-2]) * 100
        return base <= actual < base + 100
    if "-" in s:
        a, _, b = s.partition("-")
        try:
            return int(a) <= actual <= int(b)
        except ValueError:
            return False
    if "," in s:
        return str(actual) in [x.strip() for x in s.split(",")]
    try:
        return int(s) == actual
    except ValueError:
        return False


@dataclass
class Rule:
    id: str
    product: str
    confidence: float = 0.9
    logic: str = "any"                 # any | all
    min_matched: int = 1               # any 逻辑下至少命中多少条才算“强命中”
    template_dirs: list = field(default_factory=list)
    tags: list = field(default_factory=list)
    conditions: list = field(default_factory=list)
    negatives: list = field(default_factory=list)
    source: str = "builtin"

    def sorted_conditions(self) -> list:
        """按成本升序，便于短路（贵条件尽量不执行）；结果缓存到规则对象。"""
        cached = getattr(self, "_sorted_conditions_cache", None)
        if cached is None:
            cached = sorted(self.conditions, key=lambda c: c.cost)
            self._sorted_conditions_cache = cached
        return cached


@dataclass
class ProductMatch:
    product: str
    rule_id: str
    confidence: float
    matched: list = field(default_factory=list)
    template_dirs: list = field(default_factory=list)
    tags: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "product": self.product,
            "rule_id": self.rule_id,
            "confidence": round(self.confidence, 3),
            "matched": self.matched,
        }


@dataclass
class MatchContext:
    url: str = ""
    status: int = 0
    title: str = ""
    headers: dict = field(default_factory=dict)     # 全小写键
    body: str = ""
    favicon_sha256: str = ""

    def __post_init__(self) -> None:
        self.headers = {str(k).lower(): str(v) for k, v in (self.headers or {}).items()}


def _parse_conditions(raw: object, where: str) -> list[Condition]:
    if raw in (None, ""):
        return []
    if not isinstance(raw, list):
        raise FingerprintError(f"{where} 必须是列表")
    out = []
    for item in raw:
        if not isinstance(item, dict):
            raise FingerprintError(f"{where} 中条件必须是字典: {item!r}")
        ctype = str(item.get("type") or "").lower()
        if ctype not in COND_TYPES:
            raise FingerprintError(f"{where} 条件类型非法: {ctype!r}（允许 {sorted(COND_TYPES)}）")
        cond = Condition(
            type=ctype,
            name=str(item.get("name") or ""),
            contains=str(item.get("contains") or ""),
            regex=str(item.get("regex") or ""),
            value=str(item.get("value") or ""),
            sha256=str(item.get("sha256") or ""),
        )
        if ctype == "header" and not cond.name:
            raise FingerprintError(f"{where} header 条件缺少 name")
        if not any((cond.contains, cond.regex, cond.value, cond.sha256,
                    cond.type in ("status", "favicon"))):
            raise FingerprintError(f"{where} 条件缺少匹配内容: {item!r}")
        cond.compile()
        out.append(cond)
    return out


def rule_from_dict(raw: dict, source: str = "builtin") -> Rule:
    rid = str(raw.get("id") or "").strip()
    product = str(raw.get("product") or "").strip()
    if not rid or not product:
        raise FingerprintError(f"规则缺少 id/product: {raw!r}")
    logic = str(raw.get("logic") or "any").lower()
    if logic not in ("any", "all"):
        raise FingerprintError(f"规则 {rid} logic 非法: {logic}")
    conds = _parse_conditions(raw.get("match"), f"规则 {rid} match")
    if not conds:
        raise FingerprintError(f"规则 {rid} 没有 match 条件")
    return Rule(
        id=rid,
        product=product,
        confidence=float(raw.get("confidence", 0.9)),
        logic=logic,
        min_matched=int(raw.get("min_matched", 1)),
        template_dirs=list(raw.get("template_dirs") or []),
        tags=list(raw.get("tags") or []),
        conditions=conds,
        negatives=_parse_conditions(raw.get("negative"), f"规则 {rid} negative"),
        source=source,
    )


class FingerprintEngine:
    """规则库 + 匹配。

    >>> eng = FingerprintEngine.from_yaml("modules/recon/fingerprints/builtin.yaml")
    >>> eng.match(MatchContext(headers={"server": "nginx/1.20"}, body="..."))
    """

    def __init__(self, rules: Iterable[Rule], min_confidence: float = 0.6,
                 weak_match_penalty: float = 0.7, body_limit: int = 262144,
                 enable_prefilter: bool = True):
        self.rules: list[Rule] = list(rules)
        self.min_confidence = float(min_confidence)
        self.weak_match_penalty = float(weak_match_penalty)
        self.body_limit = int(body_limit)
        self._literals: dict[str, list[int]] = {}
        self._prefilter: Optional[re.Pattern] = None
        self._build_index(enable_prefilter)

    # ---- 构建索引 ----
    def _build_index(self, enable_prefilter: bool) -> None:
        literals: set[str] = set()
        for idx, rule in enumerate(self.rules):
            for cond in rule.conditions:
                lit = cond.literal
                if lit:
                    self._literals.setdefault(lit, []).append(idx)
                    literals.add(lit)
        if literals and enable_prefilter:
            # 长字面量优先，避免短字面量抢先匹配造成的误判
            alts = sorted((re.escape(x) for x in literals), key=len, reverse=True)
            self._prefilter = re.compile("|".join(alts), re.IGNORECASE)

    @classmethod
    def from_yaml(cls, path: str | Path, **kwargs) -> "FingerprintEngine":
        p = Path(path)
        if not p.exists():
            raise FingerprintError(f"指纹库不存在: {p}")
        raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        items = raw.get("rules") if isinstance(raw, dict) else raw
        if not isinstance(items, list) or not items:
            raise FingerprintError(f"指纹库 {p} 没有 rules")
        rules = [rule_from_dict(item, source=p.stem) for item in items]
        return cls(rules, **kwargs)

    # ---- 匹配 ----
    def match(self, ctx: MatchContext) -> list[ProductMatch]:
        body = (ctx.body or "")[:self.body_limit]
        literals_present = True
        if self._prefilter is not None:
            literals_present = bool(body) and bool(self._prefilter.search(body))

        results: list[ProductMatch] = []
        for rule in self.rules:
            m = self._eval_rule(rule, ctx, literals_present)
            if m:
                results.append(m)

        # 同产品取最高置信度
        best: dict[str, ProductMatch] = {}
        for m in results:
            cur = best.get(m.product)
            if cur is None or m.confidence > cur.confidence:
                best[m.product] = m
        return sorted((m for m in best.values() if m.confidence >= self.min_confidence),
                      key=lambda x: (-x.confidence, x.product))

    def _eval_rule(self, rule: Rule, ctx: MatchContext,
                   literals_present: bool) -> Optional[ProductMatch]:
        # 1) 负向规则优先：命中即否决（误报抑制）
        for neg in rule.negatives:
            if neg.eval(ctx, literals_present):
                return None

        # 2) 按成本升序短路求值
        matched: list[Condition] = []
        failed = False
        # any 逻辑且要求多条件时不能短路，否则统计不到命中数
        short_circuit = rule.logic == "any" and rule.min_matched <= 1
        for cond in rule.sorted_conditions():
            ok = cond.eval(ctx, literals_present)
            if ok:
                matched.append(cond)
                if short_circuit:
                    break
            else:
                if rule.logic == "all":
                    failed = True
                    break

        if rule.logic == "all":
            if failed or len(matched) < len(rule.conditions):
                return None
            confidence = rule.confidence
        else:
            if not matched:
                return None
            # 弱命中惩罚：any 逻辑下命中数不足 min_matched 视为证据不足
            if len(matched) < rule.min_matched:
                confidence = rule.confidence * self.weak_match_penalty
            else:
                confidence = rule.confidence
        return ProductMatch(
            product=rule.product,
            rule_id=rule.id,
            confidence=max(0.0, min(1.0, confidence)),
            matched=[c.describe() for c in matched],
            template_dirs=list(rule.template_dirs),
            tags=list(rule.tags),
        )

    # ---- 基准实现（不做短路/前置过滤，仅供性能对比与回归） ----
    def match_naive(self, ctx: MatchContext) -> list[ProductMatch]:
        body = (ctx.body or "")[:self.body_limit]
        out = []
        for rule in self.rules:
            for neg in rule.negatives:
                if neg.eval(ctx, True):
                    break
            else:
                if rule.logic == "all":
                    ok = all(c.eval(ctx, True) for c in rule.conditions)
                    conf = rule.confidence
                else:
                    hit = [c for c in rule.conditions if c.eval(ctx, True)]
                    ok = bool(hit)
                    conf = rule.confidence if len(hit) >= rule.min_matched else rule.confidence * self.weak_match_penalty
                if ok:
                    out.append(ProductMatch(rule.product, rule.id, min(1.0, conf),
                                            [c.describe() for c in rule.conditions],
                                            list(rule.template_dirs), list(rule.tags)))
        best: dict[str, ProductMatch] = {}
        for m in out:
            if m.product not in best or m.confidence > best[m.product].confidence:
                best[m.product] = m
        return sorted((m for m in best.values() if m.confidence >= self.min_confidence),
                      key=lambda x: (-x.confidence, x.product))

    # ---- 辅助 ----
    def template_dirs_for(self, products: Iterable[str]) -> list[str]:
        """产品 → nuclei 模板目录映射（分级调度用）。"""
        dirs: list[str] = []
        for rule in self.rules:
            if rule.product in products:
                for d in rule.template_dirs:
                    if d not in dirs:
                        dirs.append(d)
        return dirs

    def tags_for(self, products: Iterable[str]) -> list[str]:
        """产品 → 具体 nuclei 标签（优先取非泛化标签，避免 oa/java 之类扩大范围）。"""
        generic = {"oa", "erp", "java", "php", "server", "cms", "monitor",
                   "ci", "mail", "iot", "vpn", "vm", "office", "panel",
                   "security", "network"}
        out: list[str] = []
        wanted = set(products)
        for rule in self.rules:
            if rule.product not in wanted:
                continue
            specific = [t for t in (rule.tags or [])
                        if str(t).strip().lower() not in generic]
            chosen = specific + [str(rule.id).strip().lower()]
            for t in chosen:
                t = str(t).strip().lower()
                if t and t not in out:
                    out.append(t)
        return out

    def stats(self) -> dict:
        return {
            "rules": len(self.rules),
            "products": len({r.product for r in self.rules}),
            "body_literals": len(self._literals),
            "prefilter": bool(self._prefilter),
        }
