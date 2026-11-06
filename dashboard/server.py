# -*- coding: utf-8 -*-
"""本地面板 HTTP 服务：只读、仅回环、无外部请求。

接口全部 GET；POST/PUT/DELETE 一律 405。静态文件只从 dashboard/static 读取。
"""
from __future__ import annotations

import argparse
import json
import mimetypes
import os
import secrets
import signal
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .data import DashboardData
from .paths import APP_DIR, FROZEN, STATIC_DIR, ensure_workspace

LOCK_FILE = APP_DIR / "workspace" / "dashboard.lock"
LOOPBACK = {"127.0.0.1", "localhost", "::1"}


def _json(handler: BaseHTTPRequestHandler, data, status: int = 200) -> None:
    body = json.dumps(data, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.send_header("Content-Security-Policy",
                        "default-src 'self'; img-src 'self' data:; "
                        "style-src 'self'; script-src 'self'; connect-src 'self'")
    handler.end_headers()
    handler.wfile.write(body)


def _text(handler: BaseHTTPRequestHandler, body: bytes, ctype: str,
          status: int = 200) -> None:
    handler.send_response(status)
    handler.send_header("Content-Type", ctype)
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Content-Type-Options", "nosniff")
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    data: DashboardData = None  # 由 create_server 注入
    jobs = None
    token = ""

    def log_message(self, fmt, *args):      # 静默，避免终端刷屏
        return

    def do_GET(self):
        try:
            self._route()
        except Exception as e:              # 数据异常不崩服务
            _json(self, {"error": f"内部错误：{type(e).__name__}: {e}"}, 500)

    def do_POST(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        try:
            if not self._write_allowed():
                return _json(self, {"error": "CSRF 校验失败：token 或来源不合法"}, 403)
            if self.jobs is None:
                return _json(self, {"error": "任务队列未初始化"}, 503)
            if path == "/api/jobs":
                payload = self._json_body()
                try:
                    job = self.jobs.submit(payload)
                except Exception as e:
                    errors = getattr(e, "errors", None)
                    if errors:
                        return _json(self, {"errors": errors}, 400)
                    raise
                return _json(self, {
                    "job": self._public(job),
                    "queue_position": self.jobs.store.queue_position(job["id"]),
                }, 201)
            if path.startswith("/api/jobs/") and path.endswith("/cancel"):
                jid = path[len("/api/jobs/"):-len("/cancel")].strip("/")
                if not self.jobs.cancel(jid):
                    return _json(self, {"error": "任务不存在或已结束"}, 404)
                return _json(self, {"ok": True, "job": self._public(self.jobs.store.get(jid))})
            _json(self, {"error": "not found"}, 404)
        except json.JSONDecodeError:
            _json(self, {"error": "请求体不是合法 JSON"}, 400)
        except ValueError as e:
            _json(self, {"error": str(e)}, 400)
        except Exception as e:
            _json(self, {"error": f"内部错误：{type(e).__name__}: {e}"}, 500)

    do_PUT = do_POST
    do_DELETE = do_POST
    do_PATCH = do_POST

    def _write_allowed(self) -> bool:
        token = self.headers.get("X-AutoHole-Token") or ""
        if not self.token or token != self.token:
            return False
        origin = (self.headers.get("Origin") or "").rstrip("/")
        if origin:
            port = int(self.server.server_address[1])
            allowed = {f"http://127.0.0.1:{port}", f"http://localhost:{port}"}
            if origin not in allowed:
                return False
        return True

    def _json_body(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1024 * 1024:
            raise ValueError("请求体为空或过大")
        data = json.loads(self.rfile.read(length).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("请求体必须是对象")
        return data

    def _public(self, job: dict) -> dict:
        d = dict(job)
        d.pop("cancel_requested", None)
        d["queue_position"] = self.jobs.store.queue_position(d["id"])
        return d

    # ------------------------------------------------------------------
    def _route(self):
        parsed = urlsplit(self.path)
        path = parsed.path
        q = {k: v[-1] for k, v in parse_qs(parsed.query).items()}

        if path == "/" or path == "/index.html":
            return self._static("index.html")
        if path.startswith("/static/"):
            return self._static(path[len("/static/"):])
        if path == "/api/overview":
            return _json(self, self.data.overview())
        if path == "/api/targets":
            return _json(self, {"items": self.data.targets()})
        if path == "/api/runs":
            return _json(self, {"items": self.data.runs(refresh=True)})
        if path == "/api/run":
            return self._run(q)
        if path == "/api/assets":
            return _json(self, self.data.assets(q.get("id", ""),
                                               _int(q.get("page"), 1), _int(q.get("size"), 20)))
        if path == "/api/findings":
            return _json(self, self.data.findings(q.get("id", ""),
                                                  _int(q.get("page"), 1),
                                                  _int(q.get("size"), 20),
                                                  q.get("severity", "")))
        if path == "/api/authz":
            return _json(self, self.data.authz(q.get("id", ""),
                                               _int(q.get("page"), 1),
                                               _int(q.get("size"), 20)))
        if path == "/api/triage":
            rid = q.get("id", "")
            fmt = q.get("format", "")
            if fmt in ("md", "json"):
                body = self.data.triage_report(rid, fmt)
                if body is None:
                    return _json(self, {"error": "体检报告不存在"}, 404)
                ctype = ("text/markdown; charset=utf-8" if fmt == "md"
                         else "application/json; charset=utf-8")
                return _text(self, body.encode("utf-8"), ctype)
            report = self.data.triage(rid)
            if not report:
                return _json(self, {"error": "体检报告不存在"}, 404)
            return _json(self, {"report": report})
        if path == "/api/finding":
            return _json(self, self.data.finding_detail(
                q.get("id", ""), q.get("template", ""), q.get("host", ""),
                q.get("matched", "")))
        if path == "/api/reports":
            return _json(self, {"items": self.data.reports(q.get("id", ""))})
        if path == "/api/report":
            body = self.data.report_text(q.get("id", ""), q.get("file", ""))
            if body is None:
                return _json(self, {"error": "报告不存在"}, 404)
            return _text(self, body.encode("utf-8"), "text/markdown; charset=utf-8")
        if path == "/api/evolution":
            return _json(self, self.data.evolution())
        if path == "/api/audit":
            return _json(self, self.data.audit(q.get("id", ""),
                                               _int(q.get("page"), 1), _int(q.get("size"), 50)))
        if path == "/api/session":
            return _json(self, {"token": self.token})
        if path == "/api/jobs":
            if self.jobs is None:
                return _json(self, {"items": []})
            items = [self._public(j) for j in self.jobs.store.list()]
            return _json(self, {"items": items})
        if path.startswith("/api/jobs/"):
            if self.jobs is None:
                return _json(self, {"error": "任务队列未初始化"}, 503)
            from .jobs import read_log_tail
            jid = path[len("/api/jobs/"):].strip("/")
            job = self.jobs.store.get(jid)
            if not job:
                return _json(self, {"error": "任务不存在"}, 404)
            limit = min(_int(q.get("tail"), 200), 1000)
            return _json(self, {
                "job": self._public(job),
                "log_tail": read_log_tail(job["log_path"], limit),
            })
        if path == "/api/meta":
            return _json(self, {
                "schema": "recon.dashboard/v1",
                "data_dirs": [str(d) for d in self.data.data_dirs],
                "db": str(self.data.db_path),
                "targets_dir": str(self.data.targets_dir),
            })
        _json(self, {"error": "not found"}, 404)

    def _run(self, q: dict):
        detail = self.data.run_detail(q.get("id", ""))
        if not detail:
            return _json(self, {"error": "run 不存在"}, 404)
        return _json(self, detail)

    def _static(self, name: str):
        target = (STATIC_DIR / name).resolve()
        try:
            target.relative_to(STATIC_DIR.resolve())
        except ValueError:
            return _json(self, {"error": "forbidden"}, 403)
        if not target.is_file():
            return _json(self, {"error": "not found"}, 404)
        ctype = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
        _text(self, target.read_bytes(), ctype + ("; charset=utf-8"
                                                  if ctype.startswith("text/") or
                                                  ctype in ("application/javascript",
                                                            "application/json") else ""))


def _int(v, default: int) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class _DedicatedServer(ThreadingHTTPServer):
    # Windows 上 allow_reuse_address=True 会让两个进程共享同一端口，必须关闭
    allow_reuse_address = False
    daemon_threads = True


def create_server(host: str, port: int, data: DashboardData, *,
                  jobs=None, token: str = "") -> ThreadingHTTPServer:
    if host not in LOOPBACK:
        raise ValueError("面板只允许绑定回环地址（127.0.0.1/localhost/::1）")
    handler = type("BoundHandler", (Handler,), {
        "data": data, "jobs": jobs, "token": token or secrets.token_urlsafe(24),
    })
    srv = _DedicatedServer((host, port), handler)
    srv.daemon_threads = True
    return srv


def _pid_alive(pid: int) -> bool:
    try:
        import ctypes
        handle = ctypes.windll.kernel32.OpenProcess(0x1000, False, int(pid))
        if not handle:
            return False
        ctypes.windll.kernel32.CloseHandle(handle)
        return True
    except Exception:
        return False


def _read_lock() -> dict:
    try:
        data = json.loads(LOCK_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _acquire_lock() -> bool:
    try:
        LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(LOCK_FILE), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
    except FileExistsError:
        return False
    except OSError:
        return False
    try:
        os.write(fd, json.dumps({
            "pid": os.getpid(), "port": 0, "state": "starting",
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }).encode("utf-8"))
    finally:
        os.close(fd)
    return True


def _update_lock(port: int, state: str) -> None:
    try:
        LOCK_FILE.write_text(json.dumps({
            "pid": os.getpid(), "port": int(port), "state": state,
            "started_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }, ensure_ascii=False), encoding="utf-8")
    except OSError:
        pass


def _clear_lock(force: bool = False) -> None:
    try:
        if force:
            LOCK_FILE.unlink()
            return
        info = _read_lock()
        if int(info.get("pid") or 0) in (0, os.getpid()):
            LOCK_FILE.unlink()
    except OSError:
        pass


def _probe(port: int, timeout: float = 0.8) -> str:
    if int(port) <= 0:
        return ""
    url = f"http://127.0.0.1:{int(port)}"
    try:
        with urllib.request.urlopen(url + "/api/meta", timeout=timeout) as resp:
            if resp.status == 200:
                return url
    except Exception:
        return ""
    return ""


def _wait_existing(port: int) -> str:
    """等待已运行实例就绪（最多约 3 秒），返回可访问地址或空串。"""
    from .startlog import log
    for _ in range(12):
        info = _read_lock()
        p = int(info.get("port") or port or 0)
        url = _probe(p)
        if url:
            return url
        time.sleep(0.25)
    log(f"等待已有实例超时（port={port}）", "warn")
    return ""


def _bind(host: str, port: int, data: DashboardData, **kwargs
          ) -> tuple[ThreadingHTTPServer, int]:
    from .startlog import log
    if int(port) == 0:
        srv = create_server(host, 0, data, **kwargs)
        return srv, int(srv.server_address[1])
    last: Exception | None = None
    for p in range(int(port), int(port) + 20):
        try:
            if p != int(port):
                log(f"端口 {p - 1} 被占用，尝试 {p}")
            return create_server(host, p, data, **kwargs), p
        except OSError as e:
            last = e
            continue
    raise OSError(f"端口 {port}~{port + 19} 均不可用：{last}")


def _serve_forever(srv: ThreadingHTTPServer) -> None:
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    try:
        signal.signal(signal.SIGTERM, lambda *_: stop.set())
    except (AttributeError, ValueError):
        pass

    def waiter():
        stop.wait()
        srv.shutdown()

    threading.Thread(target=waiter, daemon=True, name="dashboard-stop").start()
    srv.serve_forever()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="auto-hole 只读桌面控制台")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=0,
                    help="0=随机端口（桌面模式）；--server-only 默认 8080")
    ap.add_argument("--db", default="", help="SQLite 路径（默认 <exe目录>/workspace/autohole.db）")
    ap.add_argument("--data-dir", action="append", default=[],
                    help="运行产物目录（可多次；默认 workspace/recon + outputs/recon-demo）")
    ap.add_argument("--targets-dir", default="", help="授权档案目录")
    ap.add_argument("--server-only", action="store_true", help="只起本地服务，不开窗口")
    ap.add_argument("--selftest", action="store_true", help="服务自检后退出")
    ap.add_argument("--selftest-window", action="store_true", help="开窗口 2 秒后自动关闭")
    ap.add_argument("--no-dialog", action="store_true", help="二次启动时不弹提示框（自动化用）")
    ap.add_argument("--no-browser", action="store_true", help="已废弃：桌面模式不再启动浏览器")
    ap.add_argument("--job-config", default="", help="任务子进程使用的主配置（默认自动生成）")
    ap.add_argument("--job-recon-config", default="", help="任务子进程使用的 recon 配置")
    args = ap.parse_args(argv)

    from .startlog import log
    ensure_workspace()
    log(f"app_start frozen={getattr(sys, 'frozen', False)} argv={argv or sys.argv[1:]}")

    if args.host not in LOOPBACK:
        log("拒绝非回环绑定", "error")
        return 2

    data = DashboardData(
        root=APP_DIR,
        db_path=Path(args.db) if args.db else None,
        data_dirs=args.data_dir or [APP_DIR / "workspace" / "recon",
                                    APP_DIR / "outputs" / "recon-demo"],
        targets_dir=Path(args.targets_dir) if args.targets_dir else None,
    )

    existing = _read_lock()
    if existing:
        pid = int(existing.get("pid") or 0)
        if _pid_alive(pid):
            url = _wait_existing(int(existing.get("port") or 0))
            log(f"检测到已有实例 pid={pid} url={url or '未就绪'}")
            if not args.selftest and not args.selftest_window:
                from .desktop import focus_existing, notify_running
                focused = focus_existing()
                log(f"focus_existing={focused}")
                if not focused and not args.no_dialog:
                    notify_running(url or "http://127.0.0.1（正在启动）")
                if url:
                    log(f"second_instance_exit url={url}")
                    return 0
                log("已有实例仍在启动，第二个进程退出", "warn")
                return 0
        else:
            log(f"清理陈旧锁 pid={pid}", "warn")
            _clear_lock(force=True)

    if not _acquire_lock():
        url = _wait_existing(int(_read_lock().get("port") or 0))
        log(f"锁竞争：已有实例启动中 url={url or '未就绪'}", "warn")
        if not args.selftest and not args.no_dialog:
            from .desktop import notify_running
            notify_running(url or "http://127.0.0.1（正在启动）")
        return 0
    log(f"lock acquired {LOCK_FILE}")

    from .audit import audit_event
    from .job_setup import ensure_runtime_configs
    from .jobs import JobManager, JobStore
    cfg_path, recon_path = ensure_runtime_configs(APP_DIR, frozen=FROZEN)
    if args.job_config:
        cfg_path = Path(args.job_config)
    if args.job_recon_config:
        recon_path = Path(args.job_recon_config)
    store = JobStore(APP_DIR / "workspace" / "jobs.db")
    manager = JobManager(
        store, app_dir=APP_DIR, frozen=FROZEN, config_path=cfg_path,
        recon_config=recon_path, authorized_dir=data.targets_dir,
        audit=audit_event, logger=log,
    )
    token = secrets.token_urlsafe(24)

    try:
        srv, port = _bind(args.host, args.port if not (args.server_only and args.port == 0)
                          else 8080, data, jobs=manager, token=token)
    except ValueError as e:
        log(f"绑定失败：{e}", "error")
        store.close()
        _clear_lock()
        return 2
    except OSError as e:
        log(f"绑定失败：{e}", "error")
        store.close()
        _clear_lock()
        return 2

    _update_lock(port, "running")
    url = f"http://{args.host}:{port}"
    log(f"server_bound port={port} url={url} data_dirs={[str(d) for d in data.data_dirs]}")

    if args.selftest:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        time.sleep(0.3)
        try:
            with urllib.request.urlopen(url + "/api/meta", timeout=2) as r:
                meta = json.loads(r.read().decode("utf-8"))
            with urllib.request.urlopen(url + "/api/overview", timeout=2) as r:
                ov = json.loads(r.read().decode("utf-8"))
            log(f"selftest ok http={r.status} runs={ov.get('runs')} "
                f"data_dirs={meta.get('data_dirs')}")
        except Exception as e:
            log(f"selftest failed: {e}", "error")
        finally:
            srv.shutdown()
            srv.server_close()
            manager.shutdown()
            store.close()
            _clear_lock()
        log("selftest exit")
        return 0

    manager.start()
    threading.Thread(target=srv.serve_forever, daemon=True,
                     name="dashboard-http").start()
    log("http thread started")

    try:
        if args.server_only:
            log("server-only 模式，无窗口；按 Ctrl+C 退出")
            _serve_forever(srv)
            return 0

        time.sleep(0.2)
        from .desktop import run_fallback, run_webview
        log("creating desktop window")
        seconds = 2.0 if args.selftest_window else 0
        if not run_webview(url, selftest_seconds=seconds):
            log("WebView2 不可用，进入降级模式", "warn")
            run_fallback(url, selftest_seconds=seconds)
        log("desktop window closed")
        return 0
    except KeyboardInterrupt:
        log("KeyboardInterrupt")
        return 0
    finally:
        try:
            srv.shutdown()
        except Exception:
            pass
        srv.server_close()
        manager.shutdown()
        store.close()
        _clear_lock()
        log("server stopped, lock cleared")


if __name__ == "__main__":
    sys.exit(main())
