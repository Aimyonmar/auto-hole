# -*- coding: utf-8 -*-
"""模板定向策略：只传筛选后的具体模板，禁止全量回退。"""
import subprocess
from pathlib import Path

import pytest

from core.config import AppConfig, PathsConfig
from core.constitution import RateLimiter, TargetDef
from core.db import DB
from core.scanner import build_nuclei_cmd, scan_urls
from core.template_policy import (TemplatePolicyError, base_templates,
                                  select_templates)


def _make_templates(root: Path, count: int, *,
                    tags: str = "other", severity: str = "high") -> list[Path]:
    http = root / "http"
    http.mkdir(parents=True, exist_ok=True)
    out = []
    for i in range(count):
        p = http / f"t{i:03d}.yaml"
        p.write_text(
            f"id: t{i}\ninfo:\n  name: t{i}\n  severity: {severity}\n  tags: {tags}\n",
            encoding="utf-8")
        out.append(p)
    return out


def _tag_files(files: list[Path], tags: str) -> None:
    for p in files:
        p.write_text(
            f"id: {p.stem}\ninfo:\n  name: {p.stem}\n  severity: high\n  tags: {tags}\n",
            encoding="utf-8")


def _cfg(tmp_path: Path, *, base: bool = True) -> AppConfig:
    full = tmp_path / "full"
    _make_templates(full, 200)
    base_dir = tmp_path / "base"
    if base:
        _make_templates(base_dir, 30)
    return AppConfig(paths=PathsConfig(
        tools_dir=str(tmp_path / "tools"),
        nuclei_templates=str(full),
        nuclei_templates_base=str(base_dir),
        workspace=str(tmp_path / "ws"), reports=str(tmp_path / "rp"),
        db=str(tmp_path / "ws" / "db.sqlite")))


def _fake_nuclei(selected: dict[str, list[Path]], calls: list):
    def fake(cmd, **kwargs):
        calls.append(list(cmd))
        if "-tl" in cmd:
            key = cmd[cmd.index("-tags") + 1]
            return subprocess.CompletedProcess(
                cmd, 0, "\n".join(str(p) for p in selected.get(key, [])), "")
        out = cmd[cmd.index("-o") + 1]
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text("", encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return fake


def test_two_fingerprint_scenarios_are_far_below_full(tmp_path):
    cfg = _cfg(tmp_path)
    full = list((tmp_path / "full").rglob("*.yaml"))
    seeyon = full[:8]
    jenkins = full[8:23]
    _tag_files(seeyon, "seeyon")
    _tag_files(jenkins, "jenkins")
    intrusive = full[23]
    _tag_files([intrusive], "seeyon,intrusive")

    got_seeyon = select_templates(cfg, ["seeyon"], severity="high,critical",
                                  exclude_tags=["intrusive", "dos", "fuzz"])
    got_jenkins = select_templates(cfg, ["jenkins"], severity="high,critical",
                                   exclude_tags=["intrusive", "dos", "fuzz"])

    assert len(got_seeyon) == 8
    assert len(got_jenkins) == 15
    assert intrusive not in got_seeyon
    assert len(got_seeyon) < 50 and len(got_jenkins) < 50
    assert len(got_seeyon) < len(full) and len(got_jenkins) < len(full)


def test_build_cmd_uses_only_selected_files(tmp_path):
    cfg = _cfg(tmp_path)
    files = (tmp_path / "full").rglob("*.yaml")
    chosen = sorted(files)[:8]
    urls = tmp_path / "urls.txt"
    urls.write_text("http://127.0.0.1\n", encoding="utf-8")
    out = tmp_path / "out.jsonl"
    cmd = build_nuclei_cmd(
        cfg, urls, out, chosen,
        tags_include=["seeyon", "cve"], tags_exclude=["intrusive", "dos", "fuzz"],
        user_agent="auto-hole-recon/1.0 (authorized security testing)")
    assert "-templates" not in cmd
    assert cmd.count("-t") == 8
    assert cmd[cmd.index("-tags") + 1] == "cve,seeyon"
    exc = cmd[cmd.index("-exclude-tags") + 1]
    assert set(exc.split(",")) == {"dos", "fuzz", "intrusive"}
    assert cmd[cmd.index("-header") + 1] == (
        "User-Agent: auto-hole-recon/1.0 (authorized security testing)")


def test_scan_urls_targeted_never_uses_full_dir(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    selected = sorted((tmp_path / "full").rglob("*.yaml"))[:8]
    _tag_files(selected, "seeyon")
    calls: list = []
    monkeypatch.setattr(subprocess, "run", _fake_nuclei({}, calls))
    db = DB(tmp_path / "d.db")
    limiter = RateLimiter(tmp_path / "d.db", "t", 5000)
    target = TargetDef(name="t", vendor="v", authorization="unit", ips=["127.0.0.1"])
    n = scan_urls(cfg, target, ["http://127.0.0.1"], db, limiter,
                  target_tags=["seeyon"], user_agent="UA-test", console=lambda m: None)
    assert n == 0
    scan_cmd = [c for c in calls if "-o" in c][-1]
    assert "-templates" not in scan_cmd
    assert scan_cmd.count("-t") == 8
    assert "seeyon" in scan_cmd[scan_cmd.index("-tags") + 1]
    assert "intrusive" in scan_cmd[scan_cmd.index("-exclude-tags") + 1]
    assert scan_cmd[scan_cmd.index("-header") + 1] == "User-Agent: UA-test"
    db.close()
    limiter.close()


def test_scan_urls_without_fingerprint_uses_base_only(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    base_files = base_templates(cfg)
    assert len(base_files) == 30
    calls: list = []
    monkeypatch.setattr(subprocess, "run", _fake_nuclei({}, calls))
    db = DB(tmp_path / "d2.db")
    limiter = RateLimiter(tmp_path / "d2.db", "t2", 5000)
    target = TargetDef(name="t2", vendor="v", authorization="unit", ips=["127.0.0.1"])
    scan_urls(cfg, target, ["http://127.0.0.1"], db, limiter, console=lambda m: None)
    scan_cmd = [c for c in calls if "-o" in c][-1]
    assert "-templates" not in scan_cmd
    tpls = [scan_cmd[i + 1] for i, x in enumerate(scan_cmd) if x == "-t"]
    assert len(tpls) == 30
    assert len(tpls) < 50
    assert all(str(cfg.nuclei_templates_base_dir) in p for p in tpls)
    db.close()
    limiter.close()


def test_missing_base_refuses_instead_of_full_scan(tmp_path):
    cfg = _cfg(tmp_path, base=False)
    with pytest.raises(TemplatePolicyError):
        base_templates(cfg)


def test_light_profile_values_aligned():
    from modules.recon.config import BUILTIN_PROFILES, load_recon_config
    cfg = load_recon_config()
    light = cfg.profiles["light"]
    assert light.max_hosts == 300
    assert light.scan_max_urls == 100
    assert light.scan_severity == "high,critical"
    assert cfg.probe.user_agent.endswith("(authorized security testing)")
    builtin = BUILTIN_PROFILES["light"]
    assert builtin.max_hosts == 300
    assert builtin.scan_max_urls == 100
    assert builtin.scan_severity == "high,critical"
