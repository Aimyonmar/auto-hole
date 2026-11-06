# 用法：在脚本中 . "$ScriptDir\env.ps1" 引入，把缓存与临时目录固定到项目 .cache
if (-not $ProjectRoot) {
    $ScriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
    $ProjectRoot = Split-Path -Parent $ScriptDir
}
$CacheRoot = Join-Path $ProjectRoot '.cache'
$env:PIP_CACHE_DIR = Join-Path $CacheRoot 'pip'
$env:TMP = Join-Path $CacheRoot 'tmp'
$env:TEMP = $env:TMP
$env:PYINSTALLER_CONFIG_DIR = Join-Path $CacheRoot 'pyinstaller'
foreach ($p in @($env:PIP_CACHE_DIR, $env:TMP, $env:PYINSTALLER_CONFIG_DIR)) {
    New-Item -ItemType Directory -Force -Path $p | Out-Null
}
