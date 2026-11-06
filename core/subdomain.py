# -*- coding: utf-8 -*-
"""subfinder / dnsx / httpx 三连编排（宪法第3条：并发受控；第7条：只用项目内二进制）。

流程：目标域名 → subfinder 被动子域枚举 → dnsx 解析有效 → httpx 存活探测+指纹
所有外部工具通过 subprocess 显式调用项目 tools/ 目录内二进制，不依赖系统 PATH。
宪法第7条：子进程 USERPROFILE/HOME 重定向到项目内 tools/home/，杜绝工具写用户目录。
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from typing import Iterable, Optional

from .config import ROOT, AppConfig
from .constitution import RateLimiter, TargetDef, assert_host_in_scope

# 宪法第7条：外部工具的家目录 → 项目内（所有配置/缓存/反馈文件零外泄）
SANDBOX_HOME = ROOT / "tools" / "home"


def isolated_env() -> dict:
    """构造隔离环境变量：USERPROFILE/HOME/AppData 全部指向项目内（宪法第7条）。"""
    SANDBOX_HOME.mkdir(parents=True, exist_ok=True)
    (SANDBOX_HOME / "tmp").mkdir(parents=True, exist_ok=True)
    (SANDBOX_HOME / "appdata").mkdir(parents=True, exist_ok=True)
    env = dict(os.environ)
    env["USERPROFILE"] = str(SANDBOX_HOME)
    env["HOME"] = str(SANDBOX_HOME)
    env["TEMP"] = str(SANDBOX_HOME / "tmp")
    env["TMP"] = str(SANDBOX_HOME / "tmp")
    # Windows 程序配置目录（nuclei/httpx 等写 %LocalAppData%/%AppData%）
    env["APPDATA"] = str(SANDBOX_HOME / "appdata")
    env["LOCALAPPDATA"] = str(SANDBOX_HOME / "appdata")
    return env


def _run(cmd: list[str], timeout: int = 600) -> str:
    """执行项目内工具（宪法第7条），返回 stdout。"""
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout,
                       encoding="utf-8", errors="replace", env=isolated_env())
    if r.returncode != 0 and not r.stdout.strip():
        raise RuntimeError(f"命令失败: {' '.join(cmd)}\n{r.stderr[:2000]}")
    return r.stdout


def _common_flags(cfg: AppConfig) -> list[str]:
    """ProjectDiscovery 工具通用限流参数（宪法第3条）。"""
    return ["-silent", "-rate-limit", str(cfg.scan.concurrency)]


def enumerate_subdomains(domains: list[str], cfg: AppConfig) -> set[str]:
    """subfinder 被动子域枚举（不调用付费 API，纯被动源）。"""
    if not domains:
        return set()
    exe = cfg.tool_path("subfinder")
    subs: set[str] = set()
    for d in domains:
        cmd = [str(exe), "-d", d, "-all", "-silent"] + _common_flags(cfg)
        out = _run(cmd)
        for line in out.splitlines():
            line = line.strip().lower()
            if line and "." in line:
                subs.add(line)
    return subs


def resolve_hosts(hosts: Iterable[str], cfg: AppConfig) -> set[str]:
    """dnsx 过滤出可解析主机。"""
    hosts = list(hosts)
    if not hosts:
        return set()
    exe = cfg.tool_path("dnsx")
    cmd = [str(exe), "-silent", "-a", "-resp"] + _common_flags(cfg)
    r = subprocess.run(cmd, input="\n".join(hosts), capture_output=True, text=True,
                       timeout=600, encoding="utf-8", errors="replace", env=isolated_env())
    resolved = set()
    for line in r.stdout.splitlines():
        # 输出格式：host [ip1, ip2] —— 取主机名
        host = line.split("[")[0].strip().lower()
        if host:
            resolved.add(host)
    return resolved


def _host_has_port(h: str) -> bool:
    """输入是否带端口（host:port，IPv6 的多冒号不算）。"""
    h = h.replace("http://", "").replace("https://", "").split("/")[0]
    return h.count(":") == 1


def probe_http(hosts: Iterable[str], cfg: AppConfig,
               target: Optional[TargetDef] = None,
               limiter: Optional[RateLimiter] = None) -> list[dict]:
    """httpx 存活探测 + 标题/技术栈指纹。

    输入约定：裸 host（如 a.example.com）→ 附常用端口探测；host:port → 只探指定端口。
    返回资产 dict 列表（host/port/url/title/tech/status/webserver）。
    宪法第1条：授权范围外的 host 丢弃；第3条：请求数登记限流。
    """
    hosts = [h for h in hosts if h]
    if not hosts:
        return []
    exe = cfg.tool_path("httpx")
    # httpx 行为：-ports 会覆盖输入自带端口 → 仅当输入全部为裸主机名时才加 -ports
    has_port = any(_host_has_port(h) for h in hosts)
    cmd = [
        str(exe), "-silent", "-json",
        "-title", "-tech-detect", "-status-code", "-web-server",
        "-rate-limit", str(cfg.scan.concurrency),
        "-timeout", "10", "-retries", "1",
    ]
    if not has_port:
        cmd += ["-ports", "80,443,8080,8443,8000,8888,9090,7001,7002"]
    r = subprocess.run(cmd, input="\n".join(hosts), capture_output=True, text=True,
                       timeout=900, encoding="utf-8", errors="replace", env=isolated_env())
    assets = []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            j = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (j.get("host") or j.get("input") or "").lower().strip()
        # host 可能带 scheme，规范化；剥离端口（IPv6 保留）
        host = host.replace("http://", "").replace("https://", "").split("/")[0]
        if host.count(":") == 1:  # host:port
            host = host.split(":")[0]
        url = j.get("url") or ""
        try:
            port = int(j.get("port") or (443 if url.startswith("https") else 80))
        except (TypeError, ValueError):
            port = 80
        if not host:
            continue
        # 宪法第1条：范围校验
        if target is not None:
            try:
                assert_host_in_scope(host, target)
            except Exception:
                continue
        if limiter is not None:
            try:
                limiter.acquire()
            except Exception:
                break  # 触发熔断，停止后续资产登记
        tech = j.get("tech") or []
        assets.append({
            "host": host,
            "port": port,
            "url": url,
            "title": j.get("title") or "",
            "tech": tech,
            "status": int(j.get("status_code") or 0),
            "webserver": j.get("webserver") or "",
            "source": "subfinder",
        })
    return assets
