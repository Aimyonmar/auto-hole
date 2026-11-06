# -*- coding: utf-8 -*-
"""指纹匹配性能对比：短路 + 字面量前置过滤 vs 逐条朴素遍历。

用 pytest -s 运行可看到实测数据：
    .venv-recon/Scripts/python.exe -m pytest tests/recon/test_fingerprint_bench.py -s
"""
import time

from modules.recon.fingerprint import (FingerprintEngine, MatchContext,
                                       rule_from_dict)


def _rules(n: int = 80) -> list[dict]:
    """构造 n 条规则：正文特写字面量 + 响应头特征（贴近真实指纹库形态）。"""
    out = []
    for i in range(n):
        out.append({
            "id": f"rule-{i}", "product": f"Product{i}", "confidence": 0.9,
            "logic": "any",
            "match": [
                {"type": "body", "contains": f"unique-needle-{i}-marker"},
                {"type": "header", "name": "Server", "contains": f"server-token-{i}-end"},
            ],
        })
    return out


def _engine(n: int, prefilter: bool) -> FingerprintEngine:
    return FingerprintEngine([rule_from_dict(r) for r in _rules(n)],
                             enable_prefilter=prefilter)


def _timed(fn, repeat: int = 5) -> float:
    best = float("inf")
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        best = min(best, time.perf_counter() - t0)
    return best


def test_prefilter_speedup():
    n_rules = 80
    # 典型“不命中”页面：正文 200KB 填充文本，不含任何指纹字面量
    ctx = MatchContext(url="http://a.example.com", status=200, title="Welcome",
                       headers={"server": "nginx/1.20.0"},
                       body=("lorem ipsum " * 16000)[:200_000])

    fast_eng = _engine(n_rules, prefilter=True)
    naive_eng = _engine(n_rules, prefilter=False)

    assert fast_eng.match(ctx) == []          # 无指纹命中
    assert naive_eng.match_naive(ctx) == []

    t_fast = _timed(lambda: fast_eng.match(ctx))
    t_naive = _timed(lambda: naive_eng.match_naive(ctx))
    speedup = t_naive / max(t_fast, 1e-9)

    print(f"\n[bench] 规则 {n_rules}，正文 {len(ctx.body)} 字节")
    print(f"[bench] 前置过滤+短路: {t_fast * 1000:.2f} ms")
    print(f"[bench] 朴素逐条遍历  : {t_naive * 1000:.2f} ms")
    print(f"[bench] 加速比        : {speedup:.1f}x")

    assert t_fast < t_naive, f"前置过滤未生效: fast={t_fast:.4f}s naive={t_naive:.4f}s"


def test_prefilter_speedup_on_hit():
    """命中路径也不能退化：结果正确且不慢于朴素实现。"""
    n_rules = 80
    body = ("lorem ipsum " * 8000) + "unique-needle-42-marker"
    ctx = MatchContext(url="http://a.com", status=200, title="App",
                       headers={"server": "server-token-42-end"}, body=body)

    fast_eng = _engine(n_rules, prefilter=True)
    naive_eng = _engine(n_rules, prefilter=False)

    fast = fast_eng.match(ctx)
    naive = naive_eng.match_naive(ctx)
    assert [m.product for m in fast] == [m.product for m in naive] == ["Product42"]

    t_fast = _timed(lambda: fast_eng.match(ctx))
    t_naive = _timed(lambda: naive_eng.match_naive(ctx))
    print(f"\n[bench] 命中场景 前置过滤 {t_fast * 1000:.2f} ms / 朴素 "
          f"{t_naive * 1000:.2f} ms")
    assert t_fast <= t_naive + 0.002          # 允许 2ms 抖动
