# -*- coding: utf-8 -*-
"""请求审计日志（JSONL，逐条追加，可离线复核）。

底线要求：所有外部请求都要留痕 —— 目标、时间、阶段、来源、URL、状态码、
耗时、当时速率、结果类型（命中/普通/错误/被拦截）。审计写失败不影响主流程，
但会在汇总里标记 degraded。
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Optional


class AuditLog:
    def __init__(self, path: Path, target: str, enabled: bool = True):
        self.path = Path(path)
        self.target = target
        self.enabled = bool(enabled)
        self.degraded = False
        self._lock = threading.Lock()
        self._count = 0
        if self.enabled:
            self.path.parent.mkdir(parents=True, exist_ok=True)

    def write(self, event: str, **fields) -> None:
        """写一条审计事件。event 例：request / scope_reject / fingerprint_hit / finding。"""
        if not self.enabled:
            return
        rec = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
            "target": self.target,
            "event": event,
        }
        rec.update({k: v for k, v in fields.items() if v is not None})
        try:
            line = json.dumps(rec, ensure_ascii=False, default=str)
            with self._lock:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
                self._count += 1
        except OSError:
            self.degraded = True

    def count(self) -> int:
        return self._count

    def tail(self, n: int = 20) -> list[dict]:
        """读取最后 n 条（供 CLI 展示/排障）。"""
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8", errors="replace").splitlines()[-n:]
        out = []
        for line in lines:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out


def summarize_requests(entries: list[dict]) -> dict:
    """从审计记录汇总请求统计（供报告/验证用）。"""
    reqs = [e for e in entries if e.get("event") == "request"]
    if not reqs:
        return {"requests": 0}
    lat = [float(e.get("elapsed_ms") or 0) for e in reqs]
    statuses: dict[str, int] = {}
    for e in reqs:
        statuses[str(e.get("status"))] = statuses.get(str(e.get("status")), 0) + 1
    return {
        "requests": len(reqs),
        "avg_latency_ms": round(sum(lat) / len(lat), 1),
        "max_latency_ms": round(max(lat), 1),
        "statuses": statuses,
        "rejected": len([e for e in entries if e.get("event") == "scope_reject"]),
        "errors": len([e for e in reqs if e.get("outcome") == "error"]),
    }


def optional_int(v: Optional[int]) -> Optional[int]:
    return v
