# -*- coding: utf-8 -*-
"""启动日志：写入 <exe目录>/logs/startup.log，便于排查启动问题。"""
from __future__ import annotations

import os
import sys
import time
from pathlib import Path

from .paths import APP_DIR

LOG_PATH = APP_DIR / "logs" / "startup.log"
MAX_BYTES = 2 * 1024 * 1024


def _rotate() -> None:
    """超过上限时把当前日志改名为 .1（只保留一份备份）。"""
    try:
        if LOG_PATH.exists() and LOG_PATH.stat().st_size >= MAX_BYTES:
            backup = LOG_PATH.with_name(LOG_PATH.name + ".1")
            backup.unlink(missing_ok=True)
            LOG_PATH.rename(backup)
    except OSError:
        pass


def log(msg: str, level: str = "info") -> None:
    line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] pid={os.getpid()} {msg}"
    try:
        LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        _rotate()
        with LOG_PATH.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    stream = getattr(sys, "stdout", None)
    if stream is not None:
        try:
            stream.write(line + "\n")
            stream.flush()
        except (OSError, ValueError):
            pass
