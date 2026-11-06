# -*- coding: utf-8 -*-
"""auto-hole 只读桌面控制台启动入口（pywebview + WebView2）。

用法：
    双击 AutoHoleDashboard.exe                # 桌面窗口（随机回环端口）
    python dashboard_server.py                # 开发态同样进桌面窗口
    python dashboard_server.py --server-only  # 只起本地服务（默认 8080）
    python dashboard_server.py --selftest     # 服务自检后退出
"""
from __future__ import annotations

import sys

if len(sys.argv) > 1 and sys.argv[1] == "--run-cli":
    from dashboard.cli_bridge import main as cli_main
    sys.exit(cli_main(sys.argv[2:]))

from dashboard.server import main

if __name__ == "__main__":
    sys.exit(main())
