# -*- coding: utf-8 -*-
"""runner 扫描编排（不启动 nuclei）：分组、定向模板、配额截断、进度记录。"""
from pathlib import Path

import pytest

from core.config import AppConfig, PathsConfig
from core.constitution import TargetDef
from modules.recon.config import load_recon_config
from modules.recon.fingerprint import FingerprintEngine
from modules.recon.runner import _scan_stage
from modules.recon.schema import Asset
from modules.recon.state import RunState

BUILTIN = Path(__file__).resolve().parents[2] / "modules/recon/fingerprints/builtin.yaml"


class _FakeLimiter:
    def __init__(self, limit=100000, used=0):
        self.limit = limit
        self._used = used

    @property
    def used(self):
        return self._used

    def bump(self, n):
        self._used += n


def _assets():
    return [
        Asset(host="a.com", url="https://a.com", status=200,
              products=[{"product": "致远OA", "rule_id": "seeyon-oa", "confidence": 0.95}]),
        Asset(host="b.com", url="https://b.com", status=200,
              products=[{"product": "致远OA", "rule_id": "seeyon-oa", "confidence": 0.9}]),
        Asset(host="c.com", url="https://c.com", status=200,
              products=[{"product": "Jenkins", "rule_id": "jenkins", "confidence": 0.95}]),
    ]


@pytest.fixture
def fake_scan(monkeypatch):
    calls = []

    def _fake(**kwargs):
        calls.append(kwargs)
        # 模拟 legacy 记账：每个 URL 按 15 次估算
        kwargs["limiter"].bump(len(kwargs["urls"]) * 15)
        return {"new": 0, "findings": []}

    monkeypatch.setattr("modules.recon.runner.run_scan", _fake)
    return calls


def test_scan_stage_groups_by_product(tmp_path, fake_scan):
    app = AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                      reports=str(tmp_path / "rp"),
                                      db=str(tmp_path / "ws" / "d.db")))
    target = TargetDef(name="t", vendor="v", authorization="a", domains=["a.com"])
    recon = load_recon_config()
    profile = recon.active_profile()
    eng = FingerprintEngine.from_yaml(BUILTIN)
    state = RunState(tmp_path / "state.json", "t")
    limiter = _FakeLimiter()

    findings, warnings, stats = _scan_stage(app=app, target=target, profile=profile,
                                     engine=eng, assets=_assets(), db=None,
                                     limiter=limiter, state=state,
                                     console=lambda m: None)

    assert findings == [] and warnings == []
    assert len(fake_scan) == 2                       # 致远OA / Jenkins 两组
    products = {c["label"] for c in fake_scan}
    assert products == {"致远OA", "Jenkins"}
    by_label = {c["label"]: c for c in fake_scan}
    assert by_label["致远OA"]["extra_templates"], "已收录产品的定向模板目录不能为空"
    assert by_label["致远OA"]["urls"]
    assert by_label["Jenkins"]["urls"]
    assert state.is_processed("scan", "https://a.com")
    assert state.is_processed("scan", "https://c.com")


def test_scan_stage_respects_budget(tmp_path, fake_scan):
    app = AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                      reports=str(tmp_path / "rp"),
                                      db=str(tmp_path / "ws" / "d.db")))
    target = TargetDef(name="t", vendor="v", authorization="a", domains=["a.com"])
    recon = load_recon_config()
    profile = recon.active_profile()
    state = RunState(tmp_path / "s.json", "t")

    limiter = _FakeLimiter(limit=100, used=75)       # 只剩 25 → 2 个 URL 的组需截断为 1
    _, warnings, stats = _scan_stage(app=app, target=target, profile=profile,
                              engine=None, assets=_assets(), db=None,
                              limiter=limiter, state=state, console=lambda m: None)
    assert any("截断" in w for w in warnings)
    assert all(len(c["urls"]) <= 1 for c in fake_scan)


def test_scan_stage_stops_when_quota_empty(tmp_path, fake_scan):
    app = AppConfig(paths=PathsConfig(workspace=str(tmp_path / "ws"),
                                      reports=str(tmp_path / "rp"),
                                      db=str(tmp_path / "ws" / "d.db")))
    target = TargetDef(name="t", vendor="v", authorization="a", domains=["a.com"])
    recon = load_recon_config()
    profile = recon.active_profile()
    state = RunState(tmp_path / "s2.json", "t")
    limiter = _FakeLimiter(limit=100, used=100)

    _, warnings, stats = _scan_stage(app=app, target=target, profile=profile,
                              engine=None, assets=_assets(), db=None,
                              limiter=limiter, state=state, console=lambda m: None)
    assert any("配额已用尽" in w for w in warnings)
    assert fake_scan == []
