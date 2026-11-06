# 用项目内缓存的 pip 包装：.\scripts\pip.ps1 install -r requirements.txt
$ProjectRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'env.ps1')
& (Join-Path $ProjectRoot '.venv-recon\Scripts\pip.exe') @args
exit $LASTEXITCODE
