# -*- mode: python ; coding: utf-8 -*-
# PyInstaller 打包配置：auto-hole 只读桌面控制台（pywebview + WebView2，one-dir）
# 用法：.venv-recon\Scripts\pyinstaller.exe dashboard.spec --noconfirm --clean

from PyInstaller.utils.hooks import collect_all, collect_submodules

EXCLUDES = ["tkinter.test", "pytest", "sqlalchemy", "alembic",
            "fastapi", "flask", "uvicorn", "jinja2"]

datas = [
    ("dashboard/static", "dashboard/static"),
    ("tools/nuclei.exe", "tools"),
    ("tools/nuclei-templates", "tools/nuclei-templates"),
    ("tools/nuclei-templates-engage/base", "tools/nuclei-templates-engage/base"),
    ("modules/recon/fingerprints", "modules/recon/fingerprints"),
    ("modules/recon/dicts", "modules/recon/dicts"),
    ("modules/recon/data", "modules/recon/data"),
]
binaries = []
hiddenimports = (["main"] + collect_submodules("modules.recon")
                 + collect_submodules("core")
                 + ["modules.recon.authz", "modules.recon.authz_creds",
                    "modules.recon.authz_cli", "modules.recon.triage",
                    "modules.recon.triage_cli"])

# pywebview 依赖 pythonnet/clr 与平台后端；cryptography 用于凭据库加密
for pkg in ("webview", "clr_loader", "cryptography"):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception:
        pass

hiddenimports += collect_submodules("webview")
hiddenimports += ["pythonnet", "clr", "webview.platforms.winforms"]

a = Analysis(
    ["dashboard_server.py"],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="AutoHoleDashboard",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,        # 桌面 App：不弹控制台窗口，日志写 logs/startup.log
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=False,
    name="AutoHoleDashboard",
)
