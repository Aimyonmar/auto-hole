# -*- coding: utf-8 -*-
"""本地冒烟测试：起 http.server → probe_http → nuclei 扫描 → findings 入库。

不依赖外部 API key；全程 127.0.0.1，零外部请求，验证流水线机制本身。
"""
import http.server
import socketserver
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.config import load_config
from core.constitution import RateLimiter, TargetDef
from core.db import DB
from core.subdomain import probe_http
from core.scanner import scan_urls

PORT = 8765

# 1) 本地 HTTP 服务
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"<html><title>auto-hole smoke test - nginx/1.14.0</title></html>"
        self.send_response(200)
        self.send_header("Server", "nginx/1.14.0")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
    def log_message(self, *a):
        pass

srv = socketserver.TCPServer(("127.0.0.1", PORT), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
print(f"[+] 本地服务 http://127.0.0.1:{PORT}")

cfg = load_config()
target = TargetDef(name="smoke", vendor="本地测试", authorization="本地冒烟测试",
                   ips=["127.0.0.1"])
db = DB(cfg.workspace_dir / "smoke.db")
limiter = RateLimiter(cfg.db_path, "smoke", cfg.scan.daily_request_limit)

# 2) httpx 探测（带端口输入格式 host:port）
assets = probe_http([f"127.0.0.1:{PORT}"], cfg, target, limiter)
print(f"[+] httpx 存活资产: {len(assets)}")
assert assets, "httpx 未探测到本地服务"
assert assets[0]["port"] == PORT, f"端口不符: {assets[0]}"
print(f"    {assets[0]}")

# 3) nuclei 扫描（本地服务无漏洞，预期 0 命中，验证流程无报错）
n = scan_urls(cfg, target, [f"http://127.0.0.1:{PORT}"], db, limiter)
print(f"[+] nuclei 命中: {n}（预期 0，验证流程跑通）")

# 4) finding 机制验证（手动插一条测去重+AI字段更新）
db.insert_finding("smoke", "smoke-template-001", "冒烟测试漏洞", "high",
                  "127.0.0.1", "http://127.0.0.1", "http://127.0.0.1:8765/x",
                  "curl http://127.0.0.1:8765/x", "{}", "nginx")
dup = db.is_duplicate("smoke-template-001", "127.0.0.1")
assert dup, "去重失败"
db.update_finding_ai(1, {"real": True, "confidence": 0.9, "reason": "smoke"}, "100-200 KB")
row = db.findings("smoke")[0]
assert row["ai_verdict"] and "real" in row["ai_verdict"]
assert not db.is_duplicate("smoke-template-001", "10.10.10.10"), "不同host误判重复"
print("[+] findings 入库/去重/AI更新 机制 OK")

# 5) 报告生成验证
from core.report import gen_report
p = gen_report(cfg, target, db, row)
assert p and p.exists(), "报告未生成"
print(f"[+] 报告生成 OK: {p.name}")
head = p.read_text(encoding="utf-8").splitlines()[0]
print(f"    标题行: {head}")

srv.shutdown()
print("\n=== 冒烟测试全部通过 ===")
