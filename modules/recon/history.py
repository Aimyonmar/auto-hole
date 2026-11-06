# -*- coding: utf-8 -*-
"""历史命中库、去重、公开披露比对、置信度校准。

去重口径（按任务要求）：host + 路径 + 漏洞类型。
- 同一漏洞重复跑：`status=reported/ignored` 直接压制，不再生成证据/报告；
- 同 host 同路径不同模板但属同一漏洞类型：也视作重复（避免拆洞刷分）；
- 新命中写库为 `new`，人工提交后可标记 `reported`。
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from pathlib import Path
from typing import Iterable, Optional
from urllib.parse import urlsplit

import yaml

from .schema import Finding
from .value import classify_vuln

SCHEMA = """
CREATE TABLE IF NOT EXISTS hit_history (
    key TEXT PRIMARY KEY,
    target TEXT,
    template_id TEXT,
    host TEXT,
    path TEXT,
    vuln_class TEXT,
    first_seen TEXT,
    last_seen TEXT,
    times_seen INTEGER DEFAULT 1,
    status TEXT DEFAULT 'new'
);
CREATE INDEX IF NOT EXISTS idx_hit_host ON hit_history(host);
"""

DEFAULT_DISCLOSURE_FILE = "modules/recon/data/known_disclosures.yaml"


def path_of(finding: Finding) -> str:
    try:
        p = urlsplit(finding.matched_at or "").path or "/"
    except ValueError:
        p = "/"
    return p.rstrip("/") or "/"


def vuln_class_of(finding: Finding) -> str:
    v = (finding.value or {}).get("vuln_class")
    if v:
        return str(v)
    return classify_vuln(finding)[0]


def history_key(finding: Finding) -> str:
    raw = f"{finding.host}|{path_of(finding)}|{vuln_class_of(finding)}".lower()
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


class HistoryStore:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    def check(self, finding: Finding) -> dict:
        key = history_key(finding)
        row = self.conn.execute(
            "SELECT status, times_seen, first_seen, last_seen FROM hit_history WHERE key=?",
            (key,)).fetchone()
        if not row:
            return {"key": key, "status": "new", "times_seen": 0}
        return {"key": key, "status": row["status"], "times_seen": row["times_seen"],
                "first_seen": row["first_seen"], "last_seen": row["last_seen"]}

    def record(self, target: str, findings: Iterable[Finding]) -> dict:
        now = time.strftime("%Y-%m-%dT%H:%M:%S")
        fresh, seen_repeat = 0, 0
        for f in findings:
            key = history_key(f)
            row = self.conn.execute(
                "SELECT status, times_seen FROM hit_history WHERE key=?", (key,)).fetchone()
            if row:
                seen_repeat += 1
                self.conn.execute(
                    "UPDATE hit_history SET last_seen=?, times_seen=times_seen+1 WHERE key=?",
                    (now, key))
            else:
                fresh += 1
                self.conn.execute(
                    "INSERT INTO hit_history(key,target,template_id,host,path,vuln_class,"
                    "first_seen,last_seen,times_seen,status) VALUES(?,?,?,?,?,?,?,?,1,'new')",
                    (key, target, f.template_id, f.host, path_of(f),
                     vuln_class_of(f), now, now))
        self.conn.commit()
        return {"new": fresh, "repeat": seen_repeat}

    def mark(self, key: str, status: str) -> bool:
        cur = self.conn.execute("UPDATE hit_history SET status=? WHERE key=?", (status, key))
        self.conn.commit()
        return bool(cur.rowcount)

    def close(self) -> None:
        self.conn.close()


# ------------------------------------------------------------------
# 公开披露比对
# ------------------------------------------------------------------
def load_disclosures(recon) -> dict:
    p = recon.abs_path(DEFAULT_DISCLOSURE_FILE)
    if not p.exists():
        return {"templates": [], "products": []}
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return {
        "templates": [str(x) for x in (raw.get("templates") or [])],
        "products": [str(x) for x in (raw.get("products") or [])],
    }


def is_public_known(finding: Finding, disclosures: dict) -> bool:
    """已公开披露：显式清单命中，或老 CVE（公开 POC 多）。"""
    tid = (finding.template_id or "").lower()
    if any(tid == str(t).lower() for t in disclosures.get("templates", [])):
        return True
    if any(str(p).lower() in tid for p in disclosures.get("products", [])):
        return True
    if tid.startswith("cve-"):
        try:
            year = int(tid.split("-")[1])
        except (IndexError, ValueError):
            return False
        return year <= time.localtime().tm_year - 3
    return False


# ------------------------------------------------------------------
# 置信度校准
# ------------------------------------------------------------------
def calibrate(findings: Iterable[Finding], feedback: Iterable[dict],
              *, min_samples: int = 3, fp_rate_threshold: float = 0.5) -> dict:
    findings = list(findings)
    hits: dict[str, int] = {}
    for f in findings:
        hits[f.template_id] = hits.get(f.template_id, 0) + 1
    fps: dict[str, int] = {}
    for entry in feedback:
        if entry.get("label") != "false_positive":
            continue
        tid = str(entry.get("template_id") or "")
        if tid:
            fps[tid] = fps.get(tid, 0) + 1

    per_template = {}
    suppressed = []
    for tid, n in hits.items():
        fp = fps.get(tid, 0)
        samples = n + fp
        rate = fp / samples if samples else 0.0
        per_template[tid] = {"hits": n, "false_positives": fp,
                             "fp_rate": round(rate, 3), "samples": samples}
        if fp >= min_samples and rate >= fp_rate_threshold:
            suppressed.append(tid)
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "per_template": per_template,
        "suppressed_templates": suppressed,
        "min_samples": min_samples,
        "fp_rate_threshold": fp_rate_threshold,
    }


def write_calibration(target_dir: Path, data: dict) -> Path:
    p = target_dir / "calibration.json"
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return p
