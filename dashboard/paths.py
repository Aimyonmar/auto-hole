# -*- coding: utf-8 -*-
"""路径解析：开发态与 PyInstaller 打包态的静态资源/数据目录。"""
from __future__ import annotations

import sys
from pathlib import Path

FROZEN = bool(getattr(sys, "frozen", False))
# 静态资源：打包后位于 sys._MEIPASS/dashboard/static；开发态是源码目录
BUNDLE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))
STATIC_DIR = BUNDLE_DIR / "dashboard" / "static"

# 数据目录：exe 所在目录（不写死开发机路径）；开发态为项目根目录
APP_DIR = Path(sys.executable).resolve().parent if FROZEN else BUNDLE_DIR


def ensure_workspace() -> list[Path]:
    """首次运行创建空目录，缺数据时面板显示空状态。"""
    created = []
    for rel in ("workspace", "targets/authorized", "outputs/recon-demo", "logs"):
        p = APP_DIR / rel
        p.mkdir(parents=True, exist_ok=True)
        created.append(p)
    return created
