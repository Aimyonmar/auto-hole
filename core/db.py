# -*- coding: utf-8 -*-
"""SQLite 结果库：资产、指纹、漏洞、AI 判定全入库，支持增量与去重（宪法第5条）。"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Iterable, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS assets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,            -- 目标任务名
    host TEXT NOT NULL,              -- 域名或IP
    port INTEGER,
    url TEXT,
    title TEXT,
    tech TEXT,                       -- httpx 技术栈 JSON
    status INTEGER,                  -- httpx 状态码
    webserver TEXT,
    source TEXT,                     -- hunter / subfinder / manual
    first_seen TEXT,
    last_seen TEXT,
    UNIQUE(target, host, port)
);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    template_id TEXT NOT NULL,       -- nuclei template-id
    name TEXT,                       -- 漏洞名
    severity TEXT,
    host TEXT,
    url TEXT,
    matched_at TEXT,                 -- 命中 URL
    curl_command TEXT,               -- nuclei 提取的复现命令
    raw TEXT,                        -- nuclei 原始 JSON 行
    product TEXT,                    -- 归一化产品名（指纹对齐补天）
    ai_verdict TEXT,                 -- AI 判定 JSON
    value_estimate TEXT,             -- 价值预估文本
    created_at TEXT,
    reported INTEGER DEFAULT 0,      -- 是否已人工提交补天（手动标记）
    UNIQUE(target, template_id, host)
);
CREATE INDEX IF NOT EXISTS idx_assets_target ON assets(target);
CREATE INDEX IF NOT EXISTS idx_findings_target ON findings(target);
CREATE INDEX IF NOT EXISTS idx_findings_tpl ON findings(template_id);
"""


class DB:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(path))
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(SCHEMA)

    # ---------------- assets ----------------
    def upsert_asset(self, target: str, host: str, port: int, url: str = "",
                     title: str = "", tech=None, status: int = 0,
                     webserver: str = "", source: str = "") -> None:
        now = datetime.now().isoformat(timespec="seconds")
        self.conn.execute(
            "INSERT INTO assets(target,host,port,url,title,tech,status,webserver,source,"
            "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(target,host,port) DO UPDATE SET "
            "url=excluded.url, title=excluded.title, tech=excluded.tech, "
            "status=excluded.status, webserver=excluded.webserver, last_seen=excluded.last_seen",
            (target, host, port, url, title,
             json.dumps(tech, ensure_ascii=False) if tech else None,
             status, webserver, source, now, now))
        self.conn.commit()

    def assets(self, target: Optional[str] = None) -> list[sqlite3.Row]:
        if target:
            return self.conn.execute(
                "SELECT * FROM assets WHERE target=? ORDER BY last_seen DESC", (target,)).fetchall()
        return self.conn.execute("SELECT * FROM assets ORDER BY last_seen DESC").fetchall()

    def known_hosts(self, target: str) -> set[str]:
        rows = self.conn.execute(
            "SELECT DISTINCT host FROM assets WHERE target=?", (target,)).fetchall()
        return {r["host"] for r in rows}

    # ---------------- findings ----------------
    def insert_finding(self, target: str, template_id: str, name: str, severity: str,
                       host: str, url: str = "", matched_at: str = "",
                       curl_command: str = "", raw: str = "", product: str = "") -> int:
        created = datetime.now().isoformat(timespec="seconds")
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO findings(target,template_id,name,severity,host,url,"
            "matched_at,curl_command,raw,product,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (target, template_id, name, severity, host, url, matched_at,
             curl_command, raw, product, created))
        self.conn.commit()
        return cur.lastrowid or 0

    def update_finding_ai(self, finding_id: int, ai_verdict: dict, value_estimate: str) -> None:
        self.conn.execute(
            "UPDATE findings SET ai_verdict=?, value_estimate=? WHERE id=?",
            (json.dumps(ai_verdict, ensure_ascii=False), value_estimate, finding_id))
        self.conn.commit()

    def findings(self, target: Optional[str] = None, only_real: bool = False) -> list[sqlite3.Row]:
        q = "SELECT * FROM findings"
        cond, args = [], []
        if target:
            cond.append("target=?"); args.append(target)
        if only_real:
            cond.append("ai_verdict IS NOT NULL AND (ai_verdict LIKE '%\"real\": true%' OR ai_verdict LIKE '%\"real\":true%')")
        if cond:
            q += " WHERE " + " AND ".join(cond)
        return self.conn.execute(q + " ORDER BY created_at DESC", args).fetchall()

    def is_duplicate(self, template_id: str, host: str) -> bool:
        """宪法第5条：同产品同漏洞去重（同 template + 同 host 视为重复，跨目标也拦）。"""
        row = self.conn.execute(
            "SELECT id FROM findings WHERE template_id=? AND host=? LIMIT 1",
            (template_id, host)).fetchone()
        return row is not None

    def close(self):
        self.conn.close()
