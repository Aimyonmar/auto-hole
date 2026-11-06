# -*- coding: utf-8 -*-
"""面板内任务：表单校验 → 授权档案 → 串行队列 → 子进程执行 recon/batch。

选择 SQLite 而不是 JSON 队列：状态更新需要原子性、并发读写（HTTP 线程 + 工作线程），
JSON 文件在多写/崩溃时容易损坏；SQLite 单文件、无额外依赖，且与现有 DB 习惯一致。
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import sqlite3
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Callable, Optional

import yaml

from core.config import ROOT
from modules.recon.authz_creds import (AuthzConfigError, AuthzCredentialError,
                                     prepare_accounts)
from modules.recon.intake import parse_payload
from modules.recon.ledger import slugify

SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    vendor TEXT,
    ledger TEXT,
    tier TEXT,
    status TEXT DEFAULT 'queued',
    stage TEXT DEFAULT '',
    created_at TEXT,
    started_at TEXT,
    ended_at TEXT,
    pid INTEGER DEFAULT 0,
    exit_code INTEGER DEFAULT -1,
    error TEXT DEFAULT '',
    log_path TEXT DEFAULT '',
    cancel_requested INTEGER DEFAULT 0,
    kind TEXT DEFAULT 'recon',
    max_requests INTEGER DEFAULT 60
);
CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
"""

AUTOMATION_WORD = re.compile(r"自动化|扫描|脚本|爬虫")
NEGATION = re.compile(r"禁止|严禁|不得|不允许|无法|不可")
AUTOMATION_YES = re.compile(r"(允许|可以|可).{0,16}(自动化|扫描|脚本|爬虫)")
UNSTATED = re.compile(r"未明确|未说明|未声明|未提及")


class SubmissionError(Exception):
    def __init__(self, errors: list[str]):
        self.errors = errors
        super().__init__("；".join(errors))


def derive_automation(raw: str) -> str:
    """从平台禁止项原文推断自动化许可；按分句判断，避免“允许扫描；禁止 DoS”误判。"""
    text = str(raw or "")
    if not text.strip():
        return "unstated"
    yes = no = False
    for clause in re.split(r"[；;。\n，,]", text):
        c = clause.strip()
        if not c or UNSTATED.search(c):
            continue
        word = AUTOMATION_WORD.search(c)
        if word and NEGATION.search(c):
            no = True
        elif AUTOMATION_YES.search(c):
            yes = True
    if no:
        return "no"
    if yes:
        return "yes"
    return "unstated"


def validate_submission(payload: dict, authorized_dir: Path, *,
                        authz_dir: Optional[Path] = None,
                        vault_path: Optional[Path] = None,
                        key_path: Optional[Path] = None) -> tuple[Path, object]:
    """面板表单校验：与 CLI 使用同一套 parse_payload/Intake 规则。

    越权账号：只把 cookie/header 写入加密 vault；targets/authorized 里只留
    authz_accounts 元数据路径，绝不出现 secret。
    """
    vendor = str(payload.get("vendor") or "").strip()
    program = str(payload.get("program_url") or payload.get("program") or "").strip()
    scope_raw = payload.get("scope") or ""
    if isinstance(scope_raw, list):
        scope_lines = [str(x) for x in scope_raw]
    else:
        scope_lines = [x for x in str(scope_raw).splitlines() if x.strip()]

    domain_lines, ip_lines = [], []
    for line in scope_lines:
        s = line.strip()
        if not s:
            continue
        try:
            ipaddress.ip_network(s, strict=False)
            ip_lines.append(s)
        except ValueError:
            domain_lines.append(s)
    restrictions = str(payload.get("restrictions_raw") or payload.get("restrictions") or "").strip()
    tier = str(payload.get("tier") or "light").strip().lower()
    confirmed = bool(payload.get("authorized"))

    errors: list[str] = []
    if not confirmed:
        errors.append("请勾选“我确认对该资产有测试授权”")
    if tier not in ("light", "standard"):
        errors.append("档位只允许 light / standard")

    raw = {
        "name": vendor,
        "vendor": vendor,
        "program_url": program,
        "authorization_ref": program,
        "tier": tier,
        "scope": {
            "domains": domain_lines,
            "ips": ip_lines,
            "include_subdomains": bool(payload.get("include_subdomains")),
            "include_third_party": bool(payload.get("include_third_party")),
        },
        "restrictions": {
            "raw": restrictions,
            "automation_allowed": derive_automation(restrictions),
        },
    }
    try:
        it = parse_payload(raw, source="<dashboard-form>")
    except ValueError as e:
        raise SubmissionError(errors + [str(e)])
    errors += it.fatal_reasons()
    for r in it.rejected_entries:
        errors.append(f"资产范围被拒绝：{r['value']}（{r['reason']}）")
    if errors:
        raise SubmissionError(errors)

    # ---- 越权检测账号（可选）：secret 只进加密 vault ----
    authz_raw = payload.get("authz") if isinstance(payload.get("authz"), dict) else {}
    authz_enabled = bool(authz_raw.get("enabled"))
    authz_meta: dict = {}
    authz_accounts = ""
    if authz_enabled:
        root = authorized_dir.parent.parent
        accounts_dir = Path(authz_dir) if authz_dir else (authorized_dir.parent / "authz")
        vpath = Path(vault_path) if vault_path else (root / "workspace" / "authz" / "vault.enc")
        kpath = Path(key_path) if key_path else (root / "workspace" / "authz" / "vault.key")
        settings = {k: authz_raw[k] for k in (
            "max_requests", "similarity_threshold", "public_similarity",
            "max_candidates", "max_vertical_paths", "max_collect_pages",
            "response_truncate") if authz_raw.get(k) not in (None, "")}
        vertical = authz_raw.get("vertical_paths") or []
        if isinstance(vertical, str):
            vertical = [x for x in vertical.splitlines() if x.strip()]
        try:
            meta_path, authz_meta = prepare_accounts(
                target_name=it.name or vendor, identities_raw=authz_raw.get("identities") or [],
                accounts_dir=accounts_dir, vault_path=vpath, key_path=kpath,
                domains=it.domains, ips=it.ips, vendor=vendor, authorization=program,
                settings=settings, vertical_paths=list(vertical),
                vertical_base=str(authz_raw.get("vertical_base") or ""),
            )
        except (AuthzConfigError, AuthzCredentialError) as e:
            errors.append(f"越权检测配置无效：{e}")
        if errors:
            raise SubmissionError(errors)
        try:
            authz_accounts = str(meta_path.resolve().relative_to(ROOT.resolve())).replace("\\", "/")
        except ValueError:
            authz_accounts = str(meta_path)

    ref = program
    record = {
        "name": it.name or vendor,
        "slug": slugify(vendor),
        "vendor": vendor,
        "program_url": program,
        "program_id": "",
        "registration_status": "approved",
        "authorization_ref": f"{ref}（面板提交，用户已确认授权）",
        "scope": {
            "domains": list(it.domains), "ips": list(it.ips),
            "include_subdomains": it.include_subdomains,
            "include_third_party": False,
            "note": "由面板表单提交",
        },
        "restrictions": {"raw": restrictions,
                         "automation_allowed": it.automation_allowed},
        "tier": tier,
        "test_accounts": [],
        "authz_accounts": authz_accounts,
        "authz": ({"enabled": True,
                   "identities": [{"name": i.get("name"), "role": i.get("role")}
                                  for i in (authz_meta.get("identities") or [])],
                   "max_requests": (authz_meta.get("settings") or {}).get("max_requests"),
                   "similarity_threshold": (authz_meta.get("settings") or {}).get(
                       "similarity_threshold")}
                  if authz_meta else {"enabled": False}),
        "source": {
            "file": "<dashboard-form>",
            "imported_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "digest": hashlib.sha256(
                json.dumps(raw, ensure_ascii=False, sort_keys=True).encode()).hexdigest()[:16],
            "excerpt": f"{vendor} / {program} / {len(scope_lines)} 条范围",
        },
    }
    authorized_dir.mkdir(parents=True, exist_ok=True)
    path = authorized_dir / f"{slugify(vendor)}.yaml"
    path.write_text(yaml.safe_dump(record, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    return path, it


class JobStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        cols = {r[1] for r in self._conn.execute("PRAGMA table_info(jobs)").fetchall()}
        if "kind" not in cols:
            self._conn.execute("ALTER TABLE jobs ADD COLUMN kind TEXT DEFAULT 'recon'")
        if "max_requests" not in cols:
            self._conn.execute("ALTER TABLE jobs ADD COLUMN max_requests INTEGER DEFAULT 60")
        self._conn.commit()

    def add(self, *, job_id: str, vendor: str, ledger: str, tier: str,
            log_path: str, kind: str = "recon", max_requests: int = 60) -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        with self._lock:
            self._conn.execute(
                "INSERT INTO jobs(id,vendor,ledger,tier,status,created_at,log_path,"
                "kind,max_requests) VALUES(?,?,?,?,?,?,?,?,?)",
                (job_id, vendor, ledger, tier, "queued", now, log_path,
                 kind, int(max_requests)))
            self._conn.commit()
        return self.get(job_id) or {}

    def get(self, job_id: str) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute("SELECT * FROM jobs WHERE id=?", (job_id,)).fetchone()
        return self._row(row)

    def list(self, limit: int = 100) -> list[dict]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?",
                (limit,)).fetchall()
        return [self._row(r) for r in rows]

    def _row(self, row) -> Optional[dict]:
        if row is None:
            return None
        d = dict(row)
        for k in ("pid", "exit_code", "max_requests"):
            d[k] = int(d.get(k) or 0)
        d["cancel_requested"] = bool(d.get("cancel_requested"))
        d["kind"] = str(d.get("kind") or "recon")
        return d

    def next_queued(self) -> Optional[dict]:
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM jobs WHERE status='queued' "
                "ORDER BY rowid ASC LIMIT 1").fetchone()
        return self._row(row)

    def queue_position(self, job_id: str) -> int:
        job = self.get(job_id)
        if not job or job["status"] != "queued":
            return 0
        with self._lock:
            n = self._conn.execute(
                "SELECT COUNT(*) FROM jobs WHERE status='queued' AND rowid <= "
                "(SELECT rowid FROM jobs WHERE id=?)", (job_id,)).fetchone()[0]
        return int(n)

    def mark_running(self, job_id: str) -> None:
        self._update(job_id, status="running",
                     started_at=time.strftime("%Y-%m-%dT%H:%M:%S"))

    def set_pid(self, job_id: str, pid: int) -> None:
        self._update(job_id, pid=int(pid))

    def set_stage(self, job_id: str, stage: str) -> None:
        self._update(job_id, stage=stage)

    def finish(self, job_id: str, status: str, exit_code: int = -1,
               error: str = "") -> None:
        self._update(job_id, status=status, ended_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                     exit_code=int(exit_code), error=str(error)[:500])

    def request_cancel(self, job_id: str) -> None:
        self._update(job_id, cancel_requested=1)

    def cancel_queued(self, job_id: str) -> None:
        self._update(job_id, status="canceled",
                     ended_at=time.strftime("%Y-%m-%dT%H:%M:%S"),
                     error="任务在队列中取消")

    def cancel_requested(self, job_id: str) -> bool:
        job = self.get(job_id)
        return bool(job and job["cancel_requested"])

    def _update(self, job_id: str, **fields) -> None:
        if not fields:
            return
        cols = ", ".join(f"{k}=?" for k in fields)
        with self._lock:
            self._conn.execute(f"UPDATE jobs SET {cols} WHERE id=?",
                               (*fields.values(), job_id))
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()


class JobManager:
    def __init__(self, store: JobStore, *, app_dir: Path, frozen: bool,
                 config_path: Path, recon_config: Path,
                 authorized_dir: Path, timeout_s: int = 1800,
                 audit: Optional[Callable] = None,
                 logger: Optional[Callable] = None):
        self.store = store
        self.app_dir = Path(app_dir)
        self.frozen = frozen
        self.config_path = Path(config_path)
        self.recon_config = Path(recon_config)
        self.authorized_dir = Path(authorized_dir)
        self.timeout_s = int(timeout_s)
        self.audit = audit or (lambda *a, **k: None)
        self.log = logger or (lambda *a, **k: None)
        self.jobs_dir = self.app_dir / "logs" / "jobs"
        self.jobs_dir.mkdir(parents=True, exist_ok=True)
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._active_proc: Optional[subprocess.Popen] = None
        self._active_id = ""

    # ------------------------------------------------------------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._thread = threading.Thread(target=self._worker, daemon=True,
                                        name="dashboard-jobs")
        self._thread.start()

    def shutdown(self) -> None:
        self._stop.set()
        if self._active_proc and self._active_proc.poll() is None:
            self._kill_tree(self._active_proc.pid)
            try:
                self._active_proc.wait(timeout=5)
            except Exception:
                pass
            if self._active_id:
                self.store.finish(self._active_id, "canceled", -1, "面板关闭，任务终止")
        if self._thread:
            self._thread.join(timeout=3)

    # ------------------------------------------------------------------
    def submit(self, payload: dict) -> dict:
        path, it = validate_submission(
            payload, self.authorized_dir,
            authz_dir=self.app_dir / "targets" / "authz",
            vault_path=self.app_dir / "workspace" / "authz" / "vault.enc",
            key_path=self.app_dir / "workspace" / "authz" / "vault.key",
        )
        kind = "triage" if str(payload.get("kind") or "").lower() == "triage" else "recon"
        max_requests = 60
        if kind == "triage":
            try:
                max_requests = int(payload.get("max_requests") or 60)
            except (TypeError, ValueError):
                raise SubmissionError(["体检请求上限必须是整数"])
            if not (1 <= max_requests <= 200):
                raise SubmissionError(["体检请求上限必须在 1~200"])
        job_id = time.strftime("%Y%m%d_%H%M%S") + "_" + hashlib.sha1(
            f"{it.name}{time.time()}".encode()).hexdigest()[:6]
        log_path = self.jobs_dir / f"{job_id}.log"
        job = self.store.add(job_id=job_id, vendor=it.name or it.vendor,
                             ledger=str(path), tier=it.tier, log_path=str(log_path),
                             kind=kind, max_requests=max_requests)
        self.audit("job_submitted", job_id=job_id, vendor=it.name,
                   tier=it.tier, ledger=str(path), kind=kind)
        self.log(f"job submitted {job_id} vendor={it.name} kind={kind} tier={it.tier}")
        return job

    def cancel(self, job_id: str) -> bool:
        job = self.store.get(job_id)
        if not job:
            return False
        if job["status"] == "queued":
            self.store.cancel_queued(job_id)
            self.audit("job_canceled", job_id=job_id, vendor=job["vendor"],
                       stage="queued")
            return True
        if job["status"] == "running":
            self.store.request_cancel(job_id)
            self.audit("job_cancel_requested", job_id=job_id, vendor=job["vendor"])
            return True
        return False

    # ------------------------------------------------------------------
    def _worker(self) -> None:
        while not self._stop.is_set():
            job = self.store.next_queued()
            if not job:
                time.sleep(0.4)
                continue
            self._run_job(job)

    def _run_job(self, job: dict) -> None:
        job_id = job["id"]
        self.store.mark_running(job_id)
        log_path = Path(job["log_path"])
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self.audit("job_started", job_id=job_id, vendor=job["vendor"],
                   tier=job["tier"])
        started = time.monotonic()

        try:
            cmd = self._build_command(job)
            with log_path.open("a", encoding="utf-8", errors="replace") as lf:
                lf.write(f"# job {job_id}\n# cmd {' '.join(cmd)}\n")
                lf.flush()
                proc = subprocess.Popen(
                    cmd, cwd=str(self.app_dir), stdout=lf, stderr=subprocess.STDOUT,
                    env=self._env(), creationflags=self._creationflags(),
                )
        except Exception as e:
            self.store.finish(job_id, "failed", -1, f"启动子进程失败：{e}")
            self.audit("job_failed", job_id=job_id, error=str(e))
            return

        self._active_proc = proc
        self._active_id = job_id
        self.store.set_pid(job_id, proc.pid)

        while True:
            rc = proc.poll()
            self._update_stage(job_id, log_path)
            if self.store.cancel_requested(job_id) and rc is None:
                self._kill_tree(proc.pid)
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                self.store.finish(job_id, "canceled", -1, "用户取消任务")
                self.audit("job_canceled", job_id=job_id, vendor=job["vendor"])
                break
            if rc is not None:
                if rc == 0 and self._log_has_failure(log_path):
                    self.store.finish(job_id, "failed", 0,
                                      "批量执行完成，但存在失败目标（详见日志）")
                    self.audit("job_failed", job_id=job_id, vendor=job["vendor"],
                               error="target_failed")
                    self.log(f"job {job_id} failed (target failure)")
                else:
                    status = "done" if rc == 0 else "failed"
                    err = "" if rc == 0 else f"子进程退出码 {rc}"
                    self.store.finish(job_id, status, rc, err)
                    self.audit(f"job_{status}", job_id=job_id, vendor=job["vendor"],
                               exit_code=rc)
                    self.log(f"job {job_id} {status} rc={rc}")
                break
            if time.monotonic() - started > self.timeout_s:
                self._kill_tree(proc.pid)
                try:
                    proc.kill()
                except Exception:
                    pass
                try:
                    proc.wait(timeout=5)
                except Exception:
                    pass
                self.store.finish(job_id, "failed", -1,
                                  f"超时（>{self.timeout_s}s），已终止进程树")
                self.audit("job_timeout", job_id=job_id, vendor=job["vendor"])
                break
            time.sleep(0.4)
        self._active_proc = None
        self._active_id = ""

    # ------------------------------------------------------------------
    def _build_command(self, job: dict) -> list[str]:
        base = [sys.executable]
        if not self.frozen:
            base.append(str(self.app_dir / "dashboard_server.py"))
        base += ["--run-cli", "--config", str(self.config_path), "--yes"]
        if job.get("kind") == "triage":
            base += ["triage", "-t", job["ledger"], "--profile", "light",
                     "--max-requests", str(int(job.get("max_requests") or 60)),
                     "--fresh", "--recon-config", str(self.recon_config)]
            return base
        manifest = self.jobs_dir / job["id"] / "batch.yaml"
        manifest.parent.mkdir(parents=True, exist_ok=True)
        manifest.write_text(yaml.safe_dump({
            "targets": [{
                "file": job["ledger"], "priority": 1, "scan": True,
                "fresh": True, "daily_limit": 500,
            }],
        }, allow_unicode=True, sort_keys=False), encoding="utf-8")
        base += ["batch", "-m", str(manifest),
                 "--profile", job["tier"], "--fresh",
                 "--recon-config", str(self.recon_config)]
        return base

    def _update_stage(self, job_id: str, log_path: Path) -> None:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return
        tail = "\n".join(text.splitlines()[-80:])
        stage = ""
        for kw, name in (
            ("WAF", "WAF中止"), ("体检结论", "体检"), ("暴露面", "暴露面"),
            ("存活主机", "探测"), ("越权检测", "越权检测"), ("身份", "越权预检"),
            ("证据包", "取证"), ("扫描计划", "扫描"), ("nuclei 扫描", "扫描"),
            ("发现 URL", "发现"), ("探测", "探测"), ("累计去重", "采集"),
            ("批量完成", "完成"), ("[✓] 完成", "完成"),
        ):
            if kw in tail:
                stage = name
        if stage and self.store.get(job_id) and \
                self.store.get(job_id)["stage"] != stage:
            self.store.set_stage(job_id, stage)

    @staticmethod
    def _log_has_failure(log_path: Path) -> bool:
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return False
        if "失败（已隔离）" in text:
            return True
        import re
        for m in re.finditer(r"(\d+)\s*成功\s*/\s*(\d+)\s*失败", text):
            if int(m.group(2)) > 0:
                return True
        return False

    def _env(self) -> dict:
        env = dict(os.environ)
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        env["NO_COLOR"] = "1"
        env["TERM"] = "dumb"
        return env

    @staticmethod
    def _creationflags() -> int:
        return getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    @staticmethod
    def _kill_tree(pid: int) -> None:
        try:
            subprocess.run(["taskkill", "/T", "/F", "/PID", str(pid)],
                           capture_output=True, timeout=15)
        except Exception:
            try:
                os.kill(pid, 9)
            except Exception:
                pass


def read_log_tail(path: str, lines: int = 200) -> list[str]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    return text.splitlines()[-max(1, min(int(lines), 1000)):]
