# -*- coding: utf-8 -*-
"""断点续跑：分阶段 checkpoint（JSON，原子写入）。

借鉴点：
- amass 的 session/state 概念：阶段化进度而非“什么时候跑完”
- nuclei 的 -resume（按已处理目标续跑）：这里用 processed 集合实现同语义
- 状态文件只记进度，不存请求内容，便于人工检查/删除
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Iterable

STATE_VERSION = 1


class RunState:
    """一个目标一份状态文件：stage -> {status, processed[], counters{}}。"""

    def __init__(self, path: Path, target: str, profile: str = ""):
        self.path = Path(path)
        self.target = target
        self._lock = threading.RLock()
        self.data = {
            "version": STATE_VERSION,
            "target": target,
            "profile": profile,
            "created_at": _now(),
            "updated_at": _now(),
            "stages": {},
        }
        if self.path.exists():
            self._load()

    # ---- 持久化 ----
    def _load(self) -> None:
        try:
            loaded = json.loads(self.path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            return
        if isinstance(loaded, dict) and loaded.get("version") == STATE_VERSION:
            self.data.update(loaded)
            self.data.setdefault("stages", {})
            if self.data.get("target") != self.target:
                # 目标不匹配视为脏状态，重新开始
                self.data = {
                    "version": STATE_VERSION, "target": self.target,
                    "profile": self.data.get("profile", ""),
                    "created_at": _now(), "updated_at": _now(), "stages": {},
                }

    def save(self) -> None:
        with self._lock:
            self.data["updated_at"] = _now()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            try:
                tmp.write_text(json.dumps(self.data, ensure_ascii=False, indent=2), encoding="utf-8")
                os.replace(tmp, self.path)   # 原子替换，避免半写状态
            except OSError:
                pass

    def reset(self) -> None:
        with self._lock:
            self.data["stages"] = {}
            self.data["created_at"] = _now()
        self.save()

    # ---- 阶段 ----
    def _stage(self, name: str) -> dict:
        return self.data["stages"].setdefault(
            name, {"status": "pending", "processed": [], "counters": {},
                   "started_at": None, "finished_at": None})

    def stage_status(self, name: str) -> str:
        return self._stage(name).get("status", "pending")

    def start_stage(self, name: str) -> None:
        with self._lock:
            st = self._stage(name)
            if st.get("status") not in ("done",):
                st["status"] = "running"
                st["started_at"] = st.get("started_at") or _now()
        self.save()

    def finish_stage(self, name: str, status: str = "done") -> None:
        with self._lock:
            st = self._stage(name)
            st["status"] = status
            st["finished_at"] = _now()
        self.save()

    def fail_stage(self, name: str, reason: str) -> None:
        with self._lock:
            st = self._stage(name)
            st["status"] = "failed"
            st["error"] = str(reason)[:300]
            st["finished_at"] = _now()
        self.save()

    # ---- 进度 ----
    def is_processed(self, stage: str, key: str) -> bool:
        with self._lock:
            return key in self._stage(stage).get("processed", [])

    def mark_processed(self, stage: str, keys: Iterable[str], persist: bool = True) -> None:
        with self._lock:
            proc = self._stage(stage).setdefault("processed", [])
            existing = set(proc)
            for k in keys:
                if k and k not in existing:
                    proc.append(k)
                    existing.add(k)
        if persist:
            self.save()

    def processed_count(self, stage: str) -> int:
        with self._lock:
            return len(self._stage(stage).get("processed", []))

    def set_counter(self, stage: str, name: str, value) -> None:
        with self._lock:
            self._stage(stage).setdefault("counters", {})[name] = value

    def counter(self, stage: str, name: str, default=None):
        with self._lock:
            return self._stage(stage).get("counters", {}).get(name, default)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "target": self.target,
                "profile": self.data.get("profile", ""),
                "updated_at": self.data.get("updated_at", ""),
                "stages": {
                    name: {"status": st.get("status"), "processed": len(st.get("processed", [])),
                           "counters": st.get("counters", {})}
                    for name, st in self.data.get("stages", {}).items()
                },
            }


def _now() -> str:
    import time
    return time.strftime("%Y-%m-%dT%H:%M:%S")
