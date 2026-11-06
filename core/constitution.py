# -*- coding: utf-8 -*-
"""宪法执行器（CONSTITUTION.md 的代码化）。

- 第1条：授权范围校验 —— 目标必须登记授权依据，域名/IP 必须在 targets 文件声明的范围内
- 第3条：速率熔断 —— 单目标单日请求计数，超限拒绝
- 第7条：环境隔离 —— subprocess 一律显式指定项目内二进制路径
"""
from __future__ import annotations

import fnmatch
import ipaddress
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml

from .config import ROOT, AppConfig


class ScopeViolation(Exception):
    """目标不在授权范围内（宪法第1条）。"""


class RateLimitExceeded(Exception):
    """触发当日请求熔断（宪法第3条）。"""


# ------------------------------------------------------------------
# 第1条：目标定义与授权范围校验
# ------------------------------------------------------------------

@dataclass
class TargetDef:
    """一个授权目标（targets/*.yaml 的内存表示）。"""
    name: str
    vendor: str
    authorization: str          # 宪法第1条：授权依据必填
    domains: List[str] = field(default_factory=list)
    ips: List[str] = field(default_factory=list)
    hunter_query: str = ""
    scope_note: str = ""
    authz_accounts: str = ""       # 越权检测账号元数据（无 secret）
    authz_explicit: bool = False   # 目标文件是否显式写了 authz_accounts（空值 = 禁用）
    automation_allowed: str = ""   # yes / unstated / no（体检模式会拒绝 no）


def load_target(path: str | Path) -> TargetDef:
    """加载并校验目标定义。授权依据缺失 → 拒绝（宪法第1条）。"""
    p = Path(path)
    if not p.exists():
        raise ScopeViolation(f"目标文件不存在: {p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    auth = str(raw.get("authorization") or "").strip()
    if not auth:
        raise ScopeViolation(
            f"宪法第1条：{p.name} 缺少 authorization（授权依据），拒绝执行")
    domains = [str(d).lower().strip() for d in (raw.get("domains") or []) if str(d).strip()]
    ips = [str(i).strip() for i in (raw.get("ips") or []) if str(i).strip()]
    if not domains and not ips and not str(raw.get("hunter_query") or "").strip():
        raise ScopeViolation(
            f"宪法第1条：{p.name} 未声明任何资产范围（domains/ips/hunter_query）")
    return TargetDef(
        name=str(raw.get("name") or p.stem),
        vendor=str(raw.get("vendor") or p.stem),
        authorization=auth,
        domains=domains,
        ips=ips,
        hunter_query=str(raw.get("hunter_query") or "").strip(),
        scope_note=str(raw.get("scope_note") or ""),
        authz_accounts=str(raw.get("authz_accounts") or "").strip(),
        authz_explicit="authz_accounts" in raw,
        automation_allowed=str((raw.get("restrictions") or {}).get("automation_allowed")
                               or "").strip().lower()
        if isinstance(raw.get("restrictions"), dict) else "",
    )


def check_host_in_scope(host: str, target: TargetDef) -> bool:
    """host（域名或 IP）是否落在目标声明范围内。

    域名：等于声明域名，或为其任意层级子域（a.b.example.com ∈ example.com）
    IP：落在声明的 IP 或 CIDR 网段内
    """
    host = host.lower().strip()
    if not host:
        return False
    # IP 判断
    try:
        addr = ipaddress.ip_address(host)
        for item in target.ips:
            if "/" in item:
                try:
                    if addr in ipaddress.ip_network(item, strict=False):
                        return True
                except ValueError:
                    continue
            else:
                try:
                    if addr == ipaddress.ip_address(item):
                        return True
                except ValueError:
                    continue
    except ValueError:
        pass
    # 域名判断
    for d in target.domains:
        d = d.lower().strip()
        if host == d or host.endswith("." + d):
            return True
    return False


def assert_host_in_scope(host: str, target: TargetDef) -> None:
    if not check_host_in_scope(host, target):
        raise ScopeViolation(
            f"宪法第1条：{host} 不在目标「{target.name}」授权范围内，已拦截")


# ------------------------------------------------------------------
# 第3条：速率熔断（单目标单日请求计数，SQLite 持久化）
# ------------------------------------------------------------------

class RateLimiter:
    """极简持久化限流器：按 (target, date) 计数，超过 daily_limit 抛异常。"""

    def __init__(self, db_path: Path, target_name: str, daily_limit: int):
        self.db_path = db_path
        self.target = target_name
        self.limit = daily_limit
        db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(db_path))
        self._conn.execute(
            "CREATE TABLE IF NOT EXISTS request_counter ("
            " target TEXT, day TEXT, count INTEGER, PRIMARY KEY(target, day))")

    @property
    def _today(self) -> str:
        return time.strftime("%Y-%m-%d")

    @property
    def used(self) -> int:
        row = self._conn.execute(
            "SELECT count FROM request_counter WHERE target=? AND day=?",
            (self.target, self._today)).fetchone()
        return row[0] if row else 0

    def acquire(self, n: int = 1) -> None:
        """登记 n 次请求；当日累计超限 → 熔断（宪法第3条）。"""
        if self.used + n > self.limit:
            raise RateLimitExceeded(
                f"宪法第3条：目标「{self.target}」今日已登记 {self.used}/{self.limit} 次请求，熔断")
        self._conn.execute(
            "INSERT INTO request_counter(target, day, count) VALUES(?,?,?) "
            "ON CONFLICT(target, day) DO UPDATE SET count = count + ?",
            (self.target, self._today, n, n))
        self._conn.commit()

    def close(self):
        self._conn.close()


# ------------------------------------------------------------------
# 第6条：人工审核 —— 报告产出永远只是本地文件，代码里不存在任何提交平台的网络调用
# （以模块缺失的形式保证：不存在 submit/push 类函数）
# ------------------------------------------------------------------
