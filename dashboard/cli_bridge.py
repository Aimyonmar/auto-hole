# -*- coding: utf-8 -*-
"""在桌面进程内以子进程参数运行 CLI（batch/recon），复用同一套授权与限速逻辑。

窗口化 exe 的 sys.stdout 可能为 None；这里先接上 fd1（父进程已重定向到日志），
异常也只写日志/返回非零，避免 PyInstaller 弹错误对话框把任务卡在 running。
"""
from __future__ import annotations

import os
import sys
import traceback
from typing import Iterable


def _ensure_streams() -> None:
    if sys.stdout is None:
        try:
            sys.stdout = open(1, "w", encoding="utf-8", errors="replace", closefd=False)
        except OSError:
            sys.stdout = open(os.devnull, "w", encoding="utf-8")
    if sys.stderr is None:
        sys.stderr = sys.stdout
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: Iterable[str]) -> int:
    _ensure_streams()
    os.environ.setdefault("PYTHONIOENCODING", "utf-8")
    os.environ.setdefault("PYTHONUTF8", "1")
    os.environ.setdefault("NO_COLOR", "1")
    os.environ.setdefault("TERM", "dumb")
    sys.argv = ["auto-hole"] + [str(x) for x in argv]
    try:
        from main import main as cli_main
        rc = cli_main()
        return int(rc or 0) if isinstance(rc, int) else 0
    except SystemExit as e:
        code = e.code
        return int(code) if isinstance(code, int) else (0 if code is None else 1)
    except BaseException:
        traceback.print_exc()
        return 1
