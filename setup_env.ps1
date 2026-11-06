# setup_env.ps1 - Constitution Art.7: all Python deps go into project .venv only
# Idempotent: re-run only reinstalls deps
$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $root

if (-not (Test-Path ".venv")) {
    Write-Host "[*] Creating venv .venv ..." -ForegroundColor Cyan
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw "python -m venv failed. Ensure Python 3.10+ is installed." }
}

$py = Join-Path $root ".venv\Scripts\python.exe"
Write-Host "[*] Upgrading pip and installing deps (inside .venv only) ..." -ForegroundColor Cyan
& $py -m pip install --upgrade pip -q --no-cache-dir
& $py -m pip install -r requirements.txt -q --no-cache-dir
if ($LASTEXITCODE -ne 0) { throw "Dependency install failed" }

Write-Host "[+] Environment ready: $py" -ForegroundColor Green
& $py --version
