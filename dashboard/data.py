# -*- coding: utf-8 -*-
"""只读数据访问层：SQLite + 运行产物（JSONL/JSON/YAML），不做任何网络请求。"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Iterable, Optional

import yaml

MAX_LIMIT = 200


def _read_json(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError, ValueError):
        return {}


def _read_jsonl(path: Path) -> list[dict]:
    out = []
    if not path.exists():
        return out
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return out
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict):
            out.append(item)
    return out


def _pct(part: float, total: float) -> float:
    return round(part / total * 100, 1) if total else 0.0


def _as_int(v, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


class DashboardData:
    def __init__(self, root: Path, db_path: Optional[Path] = None,
                 data_dirs: Optional[Iterable[str | Path]] = None,
                 targets_dir: Optional[Path] = None):
        self.root = Path(root)
        self.db_path = Path(db_path) if db_path else self.root / "workspace" / "autohole.db"
        self.data_dirs = [Path(d) for d in (data_dirs or [self.root / "workspace" / "recon"])]
        self.targets_dir = Path(targets_dir) if targets_dir else self.root / "targets" / "authorized"
        self._runs_cache: Optional[list[dict]] = None

    # ------------------------------------------------------------------
    # 运行发现
    # ------------------------------------------------------------------
    def _run_id(self, run_dir: Path) -> str:
        return hashlib.sha1(str(run_dir.resolve()).encode()).hexdigest()[:12]

    def runs(self, refresh: bool = False) -> list[dict]:
        if self._runs_cache is not None and not refresh:
            return self._runs_cache
        found: dict[str, dict] = {}
        for d in self.data_dirs:
            if not d.exists():
                continue
            for summary_path in d.rglob("summary.json"):
                self._add_run(summary_path, found)
            for assets_path in d.rglob("assets.jsonl"):
                if not (assets_path.parent / "summary.json").exists():
                    self._add_run(assets_path.parent / "summary.json", found,
                                  allow_missing_summary=True)
        runs = list(found.values())
        runs.sort(key=lambda r: r.get("generated_at") or "", reverse=True)
        self._runs_cache = runs
        return runs

    def _add_run(self, summary_path: Path, found: dict, allow_missing_summary: bool = False):
        run_dir = summary_path.parent
        summary = _read_json(summary_path)
        if not summary and not allow_missing_summary:
            return
        target = str(summary.get("target") or run_dir.name)
        generated = str(summary.get("generated_at") or
                        time.strftime("%Y-%m-%dT%H:%M:%S",
                                      time.localtime(summary_path.stat().st_mtime
                                                     if summary_path.exists() else time.time())))
        dedup_key = (target, generated)
        if dedup_key in found:
            return
        assets = summary.get("assets") or {}
        findings = summary.get("findings") or {}
        timing = summary.get("timing") or {}
        probe = summary.get("probe") or {}
        scan = summary.get("scan") or {}
        authz = _read_json(run_dir / "authz-summary.json")
        triage = _read_json(run_dir / "triage.json")
        found[dedup_key] = {
            "id": self._run_id(run_dir),
            "dir": str(run_dir),
            "kind": str(summary.get("kind") or ("triage" if triage else "recon")),
            "target": target,
            "generated_at": generated,
            "profile": (summary.get("profile") or {}).get("name", ""),
            "elapsed_s": float(summary.get("elapsed_s") or 0),
            "assets_total": _as_int(assets.get("total")),
            "assets_alive": _as_int(assets.get("alive")),
            "findings_total": _as_int(findings.get("total")),
            "requests_probe": _as_int(probe.get("requests")),
            "requests_scan_estimated": _as_int(scan.get("requests_estimated")),
            "stage_timing": timing if isinstance(timing, dict) else {},
            "warnings": len(summary.get("warnings") or []),
            "has_metrics": (run_dir / "metrics.json").exists(),
            "has_discovery": (run_dir / "discovered.jsonl").exists(),
            "has_authz": bool(authz),
            "authz_suspects": _as_int(authz.get("suspects")),
            "authz_horizontal": _as_int(authz.get("horizontal_suspects")),
            "authz_vertical": _as_int(authz.get("vertical_suspects")),
            "authz_suppressed": _as_int(authz.get("suppressed_public")),
            "authz_tested": _as_int(authz.get("horizontal_tested")) +
                            _as_int(authz.get("vertical_tested")),
            "has_triage": bool(triage),
            "triage_verdict": str((triage.get("conclusion") or {}).get("verdict") or ""),
            "triage_score": _as_int((triage.get("conclusion") or {}).get("score")),
        }

    def get_run(self, run_id: str) -> Optional[dict]:
        for r in self.runs():
            if r["id"] == run_id:
                return r
        return None

    def _run_dir(self, run_id: str) -> Optional[Path]:
        r = self.get_run(run_id)
        return Path(r["dir"]) if r else None

    # ------------------------------------------------------------------
    # 总览
    # ------------------------------------------------------------------
    def overview(self) -> dict:
        runs = self.runs(refresh=True)
        severity: dict[str, int] = {}
        hits = 0
        for r in runs:
            d = self._run_dir(r["id"])
            for f in _read_jsonl(d / "findings.jsonl"):
                hits += 1
                sev = str(f.get("severity") or "unknown")
                severity[sev] = severity.get(sev, 0) + 1
        if hits == 0:
            hits, severity = self._db_findings_stats()
        fp = self._feedback_fp_count()
        elapsed = [r["elapsed_s"] for r in runs if r["elapsed_s"] > 0]
        latest = runs[0] if runs else None
        return {
            "runs": len(runs),
            "assets": sum(r["assets_alive"] for r in runs),
            "findings": hits,
            "severity": severity,
            "false_positives": fp,
            "false_positive_rate": round(fp / hits * 100, 1) if hits else None,
            "authz_suspects": sum(r.get("authz_suspects", 0) for r in runs),
            "triage_runs": sum(1 for r in runs if r.get("has_triage")),
            "avg_elapsed_s": round(sum(elapsed) / len(elapsed), 2) if elapsed else None,
            "latest": latest,
            "status": ("有数据" if latest else "暂无运行数据"),
        }

    def _feedback_fp_count(self) -> int:
        count = 0
        seen: set[Path] = set()
        roots = list(self.data_dirs) + [self.root / "workspace" / "recon"]
        for root in roots:
            if not root.exists():
                continue
            for p in root.rglob("feedback.jsonl"):
                if p.resolve() in seen:
                    continue
                seen.add(p.resolve())
                for item in _read_jsonl(p):
                    if item.get("label") == "false_positive":
                        count += 1
        return count

    # ------------------------------------------------------------------
    # 目标清单
    # ------------------------------------------------------------------
    def targets(self) -> list[dict]:
        out = []
        runs = self.runs()
        if not self.targets_dir.exists():
            return out
        for p in sorted(self.targets_dir.glob("*.yaml")):
            try:
                raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            if not isinstance(raw, dict):
                continue
            vendor = str(raw.get("vendor") or raw.get("name") or p.stem)
            status = str(raw.get("registration_status") or "unknown").lower()
            scope = raw.get("scope") or {}
            domains = [str(x) for x in (scope.get("domains") or []) if str(x).strip()]
            ips = [str(x) for x in (scope.get("ips") or []) if str(x).strip()]
            automation = str((raw.get("restrictions") or {}).get("automation_allowed") or "")
            ref = str(raw.get("authorization_ref") or "").strip()
            reasons = []
            if status != "approved":
                reasons.append(f"报名状态={status}（需 approved）")
            if not ref:
                reasons.append("授权依据为空")
            if not domains and not ips:
                reasons.append("资产范围为空")
            if automation.lower() == "no":
                reasons.append("平台禁止自动化")
            executable = not reasons
            last_run, last_hits = "", 0
            for r in runs:
                if r["target"] in (vendor, raw.get("name")):
                    last_run, last_hits = r["generated_at"], r["findings_total"]
                    break
            out.append({
                "vendor": vendor, "slug": str(raw.get("slug") or ""),
                "status": status, "asset_count": len(domains) + len(ips),
                "executable": executable, "reasons": reasons,
                "last_run": last_run, "last_hits": last_hits,
                "tier": str(raw.get("tier") or "light"),
                "authz_configured": bool(raw.get("authz_accounts")) or
                                    bool((raw.get("authz") or {}).get("enabled")),
                "path": str(p),
            })
        return out

    # ------------------------------------------------------------------
    # 运行详情
    # ------------------------------------------------------------------
    def run_detail(self, run_id: str) -> dict:
        run = self.get_run(run_id)
        if not run:
            return {}
        d = Path(run["dir"])
        summary = _read_json(d / "summary.json")
        metrics = _read_json(d / "metrics.json")
        timing = run["stage_timing"]
        total = float(summary.get("elapsed_s") or timing.get("total") or 0)
        stages = [{"stage": k, "seconds": float(v), "percent": _pct(float(v), total)}
                  for k, v in timing.items() if k != "total" and isinstance(v, (int, float))]
        stages.sort(key=lambda x: -x["seconds"])
        probes = summary.get("probe") or {}
        scan = summary.get("scan") or {}
        limits = (summary.get("limits") or {}).get("runtime") or {}
        budget = (summary.get("limits") or {}).get("budget") or {}
        audit_counts = self._audit_counts(run)
        return {
            "run": run,
            "summary": summary,
            "metrics": metrics,
            "stages": stages,
            "requests": {
                "probe_measured": _as_int(probes.get("requests")),
                "scan_estimated": _as_int(scan.get("requests_estimated")),
                "scan_urls": _as_int(scan.get("urls")),
                "scan_note": "扫描请求数按 URL×15 保守估算，非实测",
            },
            "quota": {"daily_limit": _as_int(budget.get("daily_limit")),
                      "used": _as_int(budget.get("used")),
                      "remaining": _as_int(budget.get("remaining"))},
            "limiter": {"effective_rps": probes.get("effective_rps"),
                        "circuit": limits.get("circuit", "unknown"),
                        "throttled": audit_counts.get("throttled", 0),
                        "budget_stop": audit_counts.get("budget_stop", 0),
                        "errors": audit_counts.get("error", 0)},
            "warnings": summary.get("warnings") or [],
            "authz": _read_json(d / "authz-summary.json"),
            "triage": _read_json(d / "triage.json"),
        }

    def _audit_counts(self, run: dict) -> dict:
        rows = self._audit_rows_for_run(run)
        out: dict[str, int] = {}
        for r in rows:
            key = str(r.get("outcome") or r.get("event") or "")
            if key:
                out[key] = out.get(key, 0) + 1
        return out

    def _audit_rows_for_run(self, run: dict) -> list[dict]:
        """只取与该 run 时间窗相符的审计行（结束时间 - 耗时 - 30s 起）。"""
        rows = self._audit_rows(run["target"])
        try:
            from datetime import datetime, timedelta

            def _dt(s):
                d = datetime.fromisoformat(str(s))
                return d.astimezone().replace(tzinfo=None) if d.tzinfo else d

            end = _dt(run["generated_at"])
            start = end - timedelta(seconds=float(run.get("elapsed_s") or 0) + 30)
            out = []
            for r in rows:
                try:
                    ts = _dt(r.get("ts"))
                except (TypeError, ValueError):
                    out.append(r)
                    continue
                if ts >= start:
                    out.append(r)
            return out
        except (TypeError, ValueError):
            return rows

    # ------------------------------------------------------------------
    # 资产 / 命中
    # ------------------------------------------------------------------
    def assets(self, run_id: str, page: int = 1, size: int = 20) -> dict:
        run = self.get_run(run_id)
        items = []
        if run:
            items = _read_jsonl(Path(run["dir"]) / "assets.jsonl")
        if not items and run:
            items = self._db_assets(run["target"])
        items = [self._norm_asset(a) for a in items]
        return self._paginate(items, page, size)

    @staticmethod
    def _norm_asset(a: dict) -> dict:
        prods = a.get("products") or []
        if not isinstance(prods, list):
            prods = []
        return {
            "host": str(a.get("host") or ""),
            "port": _as_int(a.get("port")),
            "url": str(a.get("url") or ""),
            "status": _as_int(a.get("status")),
            "title": str(a.get("title") or ""),
            "server": str(a.get("server") or ""),
            "products": [{"product": str(p.get("product") or ""),
                          "confidence": float(p.get("confidence") or 0),
                          "rule_id": str(p.get("rule_id") or "")}
                         for p in prods if isinstance(p, dict)],
            "sources": [str(x) for x in (a.get("sources") or [])],
        }

    def findings(self, run_id: str, page: int = 1, size: int = 20,
                 severity: str = "") -> dict:
        run = self.get_run(run_id)
        items = []
        if run:
            items = _read_jsonl(Path(run["dir"]) / "findings.jsonl")
        if not items and run:
            items = self._db_findings(run["target"])
        norm = [self._norm_finding(f, run) for f in items]
        if severity:
            norm = [f for f in norm if f["severity"] == severity]
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "unknown": 0}
        norm.sort(key=lambda f: (-f["score"], -order.get(f["severity"], 0)))
        return self._paginate(norm, page, size)

    def _norm_finding(self, f: dict, run: Optional[dict]) -> dict:
        ev = f.get("evidence") or {}
        if not isinstance(ev, dict) and isinstance(f.get("raw"), str):
            ev = {"request": "", "response": "", "raw": f.get("raw")[:200]}
        value = f.get("value") or {}
        if not isinstance(value, dict):
            value = {}
        req = str(ev.get("request") or "")
        resp = str(ev.get("response") or "")
        return {
            "template_id": str(f.get("template_id") or ""),
            "name": str(f.get("name") or ""),
            "severity": str(f.get("severity") or "unknown"),
            "host": str(f.get("host") or ""),
            "matched_at": str(f.get("matched_at") or ""),
            "product": str(f.get("product") or ""),
            "tags": [str(t) for t in (f.get("tags") or [])],
            "score": float(value.get("score") or 0),
            "grade": str(value.get("grade") or ""),
            "advice": str(value.get("advice") or ""),
            "curl": str(f.get("curl_command") or ""),
            "request": req[:300],
            "response": resp[:300],
            "truncated": len(req) > 300 or len(resp) > 300,
            "has_report": bool(run) and self._has_report(run, str(f.get("template_id") or "")),
        }

    def _has_report(self, run: dict, template_id: str) -> bool:
        if not template_id:
            return False
        for edir in self._evidence_dirs(Path(run["dir"])):
            if any(template_id in p.name for p in edir.glob("*.md")):
                return True
        return False

    def _evidence_dirs(self, run_dir: Path) -> list[Path]:
        out = []
        for cand in (run_dir / "evidence",):
            if cand.is_dir():
                out.append(cand)
        recon = run_dir / "recon"
        if recon.is_dir():
            out += [p / "evidence" for p in recon.iterdir() if (p / "evidence").is_dir()]
        return out

    def finding_detail(self, run_id: str, template_id: str, host: str,
                       matched_at: str) -> dict:
        run = self.get_run(run_id)
        if not run:
            return {}
        for f in _read_jsonl(Path(run["dir"]) / "findings.jsonl"):
            if (str(f.get("template_id")) == template_id
                    and str(f.get("host")) == host
                    and str(f.get("matched_at")) == matched_at):
                return {"finding": self._norm_finding(f, run), "evidence": f.get("evidence") or {}}
        return {}

    # ------------------------------------------------------------------
    # 只读越权检测
    # ------------------------------------------------------------------
    def authz(self, run_id: str, page: int = 1, size: int = 20) -> dict:
        run = self.get_run(run_id)
        summary: dict = {}
        items: list = []
        if run:
            d = Path(run["dir"])
            summary = _read_json(d / "authz-summary.json")
            items = _read_jsonl(d / "authz.jsonl")
        norm = []
        for x in items:
            if not isinstance(x, dict):
                continue
            norm.append({
                "kind": str(x.get("kind") or ""),
                "url": str(x.get("url") or ""),
                "method": str(x.get("method") or "GET"),
                "identity_a": str(x.get("identity_a") or ""),
                "identity_b": str(x.get("identity_b") or ""),
                "a_status": _as_int(x.get("a_status")),
                "b_status": _as_int(x.get("b_status")),
                "a_len": _as_int(x.get("a_len")),
                "b_len": _as_int(x.get("b_len")),
                "similarity": float(x.get("similarity") or 0),
                "threshold": float(x.get("threshold") or 0),
                "reason": str(x.get("reason") or ""),
                "sensitive_fields": [str(s) for s in (x.get("sensitive_fields") or [])],
                "a_sample": str(x.get("a_sample") or ""),
                "b_sample": str(x.get("b_sample") or ""),
                "source": str(x.get("source") or ""),
                "object_tokens": x.get("object_tokens") or [],
                "evidence_score": float(x.get("evidence_score") or 0),
            })
        norm.sort(key=lambda y: (-y["evidence_score"], -y["similarity"], y["url"]))
        data = self._paginate(norm, page, size)
        data["summary"] = summary
        data["has_authz"] = bool(summary)
        return data

    # ------------------------------------------------------------------
    # 目标体检
    # ------------------------------------------------------------------
    def triage(self, run_id: str) -> dict:
        run = self.get_run(run_id)
        if not run:
            return {}
        p = Path(run["dir"]) / "triage.json"
        if not p.exists():
            return {}
        data = _read_json(p)
        return data

    def triage_report(self, run_id: str, fmt: str = "md") -> Optional[str]:
        run = self.get_run(run_id)
        if not run:
            return None
        name = "triage.json" if fmt == "json" else "triage.md"
        p = Path(run["dir"]) / name
        if not p.is_file():
            return None
        try:
            return p.read_text(encoding="utf-8")
        except OSError:
            return None

    def reports(self, run_id: str) -> list[dict]:
        run = self.get_run(run_id)
        if not run:
            return []
        out = []
        for edir in self._evidence_dirs(Path(run["dir"])):
            for p in sorted(edir.glob("*.md")):
                out.append({"name": p.name, "dir": str(edir), "size": p.stat().st_size})
        return out

    def report_text(self, run_id: str, name: str) -> Optional[str]:
        run = self.get_run(run_id)
        if not run:
            return None
        safe = Path(name).name
        for edir in self._evidence_dirs(Path(run["dir"])):
            p = edir / safe
            if p.is_file():
                try:
                    return p.read_text(encoding="utf-8")
                except OSError:
                    return None
        return None

    # ------------------------------------------------------------------
    # 进化
    # ------------------------------------------------------------------
    def evolution(self) -> dict:
        candidates: list[dict] = []
        versions: dict = {}
        seen_dirs: set[Path] = set()
        roots = list(self.data_dirs) + [self.root / "workspace" / "recon"]
        for root in roots:
            if not root.exists():
                continue
            for cdir in root.rglob("candidates"):
                for ts in sorted(cdir.iterdir(), reverse=True):
                    if not ts.is_dir() or ts in seen_dirs:
                        continue
                    seen_dirs.add(ts)
                    for val in sorted(ts.glob("*.validation.json")):
                        try:
                            d = json.loads(val.read_text(encoding="utf-8"))
                        except (OSError, json.JSONDecodeError):
                            continue
                        if isinstance(d, dict):
                            candidates.append({
                                "id": str(d.get("id") or val.stem),
                                "kind": str(d.get("kind") or ""),
                                "status": str(d.get("status") or "unknown"),
                                "product": str(d.get("product") or ""),
                                "template_id": str(d.get("template_id") or ""),
                                "source": str(d.get("source") or ""),
                                "reasons": d.get("reasons") or [],
                                "validation": d.get("validation") or {},
                                "dir": str(ts),
                            })
            for index in root.rglob("versions/index.json"):
                if index.is_file():
                    versions = _read_json(index)
                    break
            if versions:
                break
        return {"candidates": candidates, "versions": versions.get("versions", [])}

    # ------------------------------------------------------------------
    # 审计
    # ------------------------------------------------------------------
    def audit(self, run_id: str, page: int = 1, size: int = 50) -> dict:
        run = self.get_run(run_id)
        rows = self._audit_rows_for_run(run) if run else []
        rows = [r for r in rows if r.get("event") in ("request", "scope_reject",
                                                      "budget_stop", "error")]
        rows = sorted(rows, key=lambda r: str(r.get("ts") or ""), reverse=True)
        return self._paginate(rows, page, size)

    def _audit_rows(self, target: Optional[str] = None) -> list[dict]:
        rows: list[dict] = []
        seen: set[Path] = set()
        seen_rows: set[tuple] = set()
        for root in list(self.data_dirs) + [self.root / "workspace" / "recon"]:
            if not root.exists():
                continue
            for p in root.rglob("audit.jsonl"):
                if p.resolve() in seen:
                    continue
                seen.add(p.resolve())
                for item in _read_jsonl(p):
                    if target and str(item.get("target") or "") != target:
                        continue
                    key = (str(item.get("ts")), str(item.get("event")),
                           str(item.get("host")), str(item.get("url")), str(item.get("status")))
                    if key in seen_rows:
                        continue
                    seen_rows.add(key)
                    rows.append(item)
        return rows

    # ------------------------------------------------------------------
    # DB 兜底
    # ------------------------------------------------------------------
    def _db_query(self, sql: str, target: str) -> list[dict]:
        if not self.db_path.exists():
            return []
        try:
            conn = sqlite3.connect(str(self.db_path))
            conn.row_factory = sqlite3.Row
            rows = conn.execute(sql, (target,)).fetchall()
            conn.close()
            return [dict(r) for r in rows]
        except (sqlite3.Error, OSError):
            return []

    def _db_assets(self, target: str) -> list[dict]:
        return self._db_query(
            "SELECT host, port, url, title, status, webserver AS server, "
            "source FROM assets WHERE target=? LIMIT 10000", target)

    def _db_findings(self, target: str) -> list[dict]:
        rows = self._db_query(
            "SELECT template_id, name, severity, host, url, matched_at, "
            "curl_command, product, created_at FROM findings WHERE target=? "
            "LIMIT 10000", target)
        return rows

    def _db_findings_stats(self) -> tuple[int, dict]:
        if not self.db_path.exists():
            return 0, {}
        try:
            conn = sqlite3.connect(str(self.db_path))
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS c FROM findings GROUP BY severity").fetchall()
            conn.close()
            sev = {str(s): int(c) for s, c in rows}
            return sum(sev.values()), sev
        except sqlite3.Error:
            return 0, {}

    @staticmethod
    def _paginate(items: list, page: int, size: int) -> dict:
        size = max(1, min(_as_int(size, 20), MAX_LIMIT))
        page = max(1, _as_int(page, 1))
        start = (page - 1) * size
        return {"items": items[start:start + size], "total": len(items),
                "page": page, "size": size,
                "pages": max(1, (len(items) + size - 1) // size)}
