# -*- coding: utf-8 -*-
"""legacy nuclei 结果解析回归测试（G1：http 类型命中不能被过滤）。

不启动 nuclei 进程：monkeypatch subprocess.run，按命令里的 -o 路径写入固定 JSONL。
"""
import json
import subprocess
from pathlib import Path

from core.config import AppConfig, PathsConfig
from core.constitution import RateLimiter, TargetDef
from core.db import DB
from core.scanner import scan_urls


def _cfg(tmp_path) -> AppConfig:
    return AppConfig(paths=PathsConfig(
        workspace=str(tmp_path / "ws"), reports=str(tmp_path / "rp"),
        db=str(tmp_path / "ws" / "db.sqlite")))


def _fake_run_factory(lines):
    def fake_run(cmd, **kwargs):
        out = cmd[cmd.index("-o") + 1]
        Path(out).parent.mkdir(parents=True, exist_ok=True)
        Path(out).write_text("\n".join(json.dumps(x, ensure_ascii=False) for x in lines),
                             encoding="utf-8")
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return fake_run


def test_http_type_finding_is_kept(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)
    target = TargetDef(name="t", vendor="v", authorization="unit", ips=["127.0.0.1"])
    db = DB(tmp_path / "d.db")
    limiter = RateLimiter(tmp_path / "d.db", "t", 5000)

    finding = {
        "template-id": "CVE-2021-1234", "type": "http",
        "info": {"name": "Test RCE", "severity": "high"},
        "host": "http://127.0.0.1:8765", "matched-at": "http://127.0.0.1:8765/x",
        "curl-command": "curl http://127.0.0.1:8765/x",
    }
    stats = {"type": "stats", "template-id": "stats", "info": {}}
    monkeypatch.setattr("core.scanner.subprocess.run", _fake_run_factory([finding, stats]))

    n = scan_urls(cfg, target, ["http://127.0.0.1:8765"], db, limiter,
                  console=lambda m: None)
    assert n == 1
    rows = db.findings("t")
    assert len(rows) == 1
    assert rows[0]["template_id"] == "CVE-2021-1234"

    # 同模板同 host 再次命中 → 去重
    assert scan_urls(cfg, target, ["http://127.0.0.1:8765"], db, limiter,
                     console=lambda m: None) == 0
    db.close()
    limiter.close()


def test_write_poc_still_filtered_in_readonly(tmp_path, monkeypatch):
    cfg = _cfg(tmp_path)             # 默认 strict_readonly
    target = TargetDef(name="t", vendor="v", authorization="unit", ips=["127.0.0.1"])
    db = DB(tmp_path / "d2.db")
    limiter = RateLimiter(tmp_path / "d2.db", "t", 5000)

    write_poc = {
        "template-id": "file-upload-test", "type": "http",
        "info": {"name": "Arbitrary File Upload", "severity": "critical"},
        "host": "http://127.0.0.1", "matched-at": "http://127.0.0.1/upload",
    }
    monkeypatch.setattr("core.scanner.subprocess.run", _fake_run_factory([write_poc]))
    assert scan_urls(cfg, target, ["http://127.0.0.1"], db, limiter,
                     console=lambda m: None) == 0
    db.close()
    limiter.close()
