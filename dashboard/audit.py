# -*- coding: utf-8 -*-
"""面板提交/执行审计：追加 JSONL 到 <exe目录>/logs/dashboard-audit.jsonl。"""
from __future__ import annotations

import json
import os
import time

from .paths import APP_DIR

AUDIT_PATH = APP_DIR / "logs" / "dashboard-audit.jsonl"
MAX_BYTES = 5 * 1024 * 1024


def _rotate() -> None:
    """超过上限时把当前审计日志改名为 .1（只保留一份备份）。"""
    try:
        if AUDIT_PATH.exists() and AUDIT_PATH.stat().st_size >= MAX_BYTES:
            backup = AUDIT_PATH.with_name(AUDIT_PATH.name + ".1")
            backup.unlink(missing_ok=True)
            AUDIT_PATH.rename(backup)
    except OSError:
        pass


def audit_event(event: str, **fields) -> None:
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "event": event, "pid": os.getpid(), **fields}
    try:
        AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
        _rotate()
        with AUDIT_PATH.open("a", encoding="utf-8") as f:
            f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    except OSError:
        pass
