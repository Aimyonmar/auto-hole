# -*- coding: utf-8 -*-
"""本地回环 mock 站点（仅用于验证，不会访问任何外部地址）。

用法：
    python tests/recon/mock_site.py --port 18081 --kind seeyon
    python tests/recon/mock_site.py --port 18082 --kind openresty

可选 kind：
    seeyon     致远OA 风格页面（标题 + seeyon 正文 + nginx Server）
    openresty  OpenResty 响应头，无产品指纹
    plain      普通页面（无指纹）
"""
from __future__ import annotations

import argparse
import http.server
import socketserver

KINDS = {
    "seeyon": {
        "server": "nginx/1.18.0",
        "title": "致远OA V8.1 SP2 登录",
        "body": "<html><head><title>{title}</title></head><body>"
                "<script src='/seeyon/common/js/jquery.js'></script>"
                "<p>Seeyon Collaborative Office</p></body></html>",
        "favicon": b"seeyon-favicon-bytes",
    },
    "openresty": {
        "server": "openresty/1.21.4.1",
        "title": "Welcome",
        "body": "<html><head><title>{title}</title></head><body>plain page</body></html>",
        "favicon": b"plain-favicon",
    },
    "plain": {
        "server": "Apache",
        "title": "Welcome",
        "body": "<html><head><title>{title}</title></head><body>plain page</body></html>",
        "favicon": b"",
    },
}


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        kind = self.server.kind
        if self.path == "/favicon.ico" and kind.get("favicon"):
            data = kind["favicon"]
            self.send_response(200)
            self.send_header("Content-Type", "image/x-icon")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        body = kind["body"].format(title=kind["title"]).encode("utf-8")
        self.send_response(200)
        self.send_header("Server", kind["server"])
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def main() -> None:
    ap = argparse.ArgumentParser(description="本地回环 mock 站点")
    ap.add_argument("--port", type=int, default=18081)
    ap.add_argument("--kind", default="seeyon", choices=sorted(KINDS))
    ap.add_argument("--host", default="127.0.0.1", help="只允许回环地址")
    args = ap.parse_args()
    if args.host not in ("127.0.0.1", "localhost"):
        raise SystemExit("[!] mock 站点只允许绑定回环地址")

    srv = socketserver.ThreadingTCPServer((args.host, args.port), Handler)
    srv.daemon_threads = True
    srv.kind = KINDS[args.kind]
    print(f"[+] mock {args.kind} 监听 http://{args.host}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        srv.shutdown()


if __name__ == "__main__":
    main()
