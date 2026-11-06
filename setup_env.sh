#!/usr/bin/env bash
# setup_env.sh - Constitution Art.7: all Python deps go into project .venv only (Linux server)
set -e
cd "$(dirname "$0")"

if [ ! -d ".venv" ]; then
    echo "[*] Creating venv .venv ..."
    python3 -m venv .venv
fi

echo "[*] Installing deps (inside .venv only) ..."
.venv/bin/pip install --upgrade pip -q --no-cache-dir
.venv/bin/pip install -r requirements.txt -q --no-cache-dir

echo "[+] Environment ready: $(pwd)/.venv/bin/python"
.venv/bin/python --version
