# 打包：临时目录与 PyInstaller 缓存固定到项目 .cache，避免写 C 盘
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'env.ps1')
Push-Location $ProjectRoot
try {
    & (Join-Path $ProjectRoot '.venv-recon\Scripts\pyinstaller.exe') dashboard.spec --noconfirm --clean
    exit $LASTEXITCODE
} finally {
    Pop-Location
}
