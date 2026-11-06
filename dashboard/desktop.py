# -*- coding: utf-8 -*-
"""桌面窗口：pywebview + 系统 WebView2；失败时降级为 tkinter 提示窗口。"""
from __future__ import annotations

import threading
import time
from typing import Callable

from .paths import APP_DIR
from .startlog import log

TITLE = "AutoHole 控制台"
# WebView2 用户数据目录：固定到 exe 同级，避免 pywebview 默认写入 %TEMP%
WEBVIEW_DATA_DIR = APP_DIR / "webview-data"


def focus_existing(title: str = TITLE) -> bool:
    """把已运行的同名窗口前置；找不到返回 False。"""
    try:
        import ctypes
        user32 = ctypes.windll.user32
        found: list[int] = []

        @ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)
        def _cb(hwnd, _):
            if not user32.IsWindowVisible(hwnd):
                return True
            buf = ctypes.create_unicode_buffer(256)
            user32.GetWindowTextW(hwnd, buf, 256)
            if buf.value == title:
                user32.ShowWindow(hwnd, 9)          # SW_RESTORE
                user32.SetForegroundWindow(hwnd)
                found.append(hwnd)
                return False
            return True

        user32.EnumWindows(_cb, 0)
        return bool(found)
    except Exception as e:
        log(f"focus_existing failed: {e}", "warn")
        return False


def notify_running(url: str) -> None:
    """无法前置窗口时，弹一个系统提示框。"""
    try:
        import ctypes
        ctypes.windll.user32.MessageBoxW(
            0, f"AutoHole 控制台已在运行。\n\n访问地址：{url}",
            TITLE, 0x40)
    except Exception as e:
        log(f"notify_running failed: {e}", "warn")


def run_webview(url: str, *, selftest_seconds: float = 0,
                logger: Callable[[str], None] = log) -> bool:
    """创建应用窗口；成功返回 True，缺 WebView2/pywebview 时返回 False。"""
    try:
        import webview
    except Exception as e:
        logger(f"pywebview 不可用：{e}")
        return False

    try:
        WEBVIEW_DATA_DIR.mkdir(parents=True, exist_ok=True)
        window = webview.create_window(
            TITLE, url, width=1280, height=800, min_size=(900, 600), resizable=True,
        )
        if selftest_seconds > 0:
            def closer():
                time.sleep(selftest_seconds)
                try:
                    window.destroy()
                except Exception as e:
                    logger(f"selftest 关闭窗口失败：{e}")
            webview.start(lambda: threading.Thread(target=closer, daemon=True).start(),
                          storage_path=str(WEBVIEW_DATA_DIR))
        else:
            webview.start(storage_path=str(WEBVIEW_DATA_DIR))
        logger("窗口已关闭")
        return True
    except Exception as e:
        logger(f"WebView2 启动失败：{type(e).__name__}: {e}", "error")
        return False


def run_fallback(url: str, *, selftest_seconds: float = 0,
                 logger: Callable[[str], None] = log) -> bool:
    """降级方案：tkinter 原生窗口，展示地址与手动打开按钮（不自动起浏览器）。"""
    try:
        import tkinter as tk
        import webbrowser
    except Exception as e:
        logger(f"tkinter 降级也不可用：{e}", "error")
        return False

    logger("进入 tkinter 降级模式（WebView2 缺失）")
    root = tk.Tk()
    root.title(f"{TITLE}（降级）")
    root.geometry("860x520")
    root.minsize(640, 360)
    tk.Label(root, text="WebView2 Runtime 不可用，无法内嵌网页。",
             font=("Microsoft YaHei", 14)).pack(pady=(60, 10))
    tk.Label(root, text="可安装 Microsoft Edge WebView2 Runtime 后重新打开；\n"
                        "或点击下方按钮用系统浏览器查看（由你手动触发）。",
             font=("Microsoft YaHei", 10), justify="center").pack()
    tk.Label(root, text=url, font=("Consolas", 12), fg="#1a5fb4").pack(pady=18)

    def _open():
        try:
            webbrowser.open(url)
        except Exception as e:
            logger(f"手动打开浏览器失败：{e}", "warn")

    tk.Button(root, text="用浏览器打开", command=_open, width=18).pack(pady=6)
    tk.Button(root, text="退出", command=root.destroy, width=18).pack(pady=6)
    if selftest_seconds > 0:
        root.after(int(selftest_seconds * 1000), root.destroy)
    root.mainloop()
    logger("降级窗口已关闭")
    return True
