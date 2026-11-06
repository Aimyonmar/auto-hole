# -*- coding: utf-8 -*-
"""Hunter 鹰图 API 封装（宪法第3条：配额监控，超 80% 告警暂停）。

API 文档：https://hunter.qianxin.com/home/helpCenter（API说明文档）
开放API：GET https://hunter.qianxin.com/openApi/search（付费账号；实测 2026-10：POST 该路径 404，必须 GET）
内部接口：POST https://hunter.qianxin.com/api/search（免费账号降级用：每页≤10条、仅首页）
参数：api-key, search(base64 语法), page, page_size, is_web(资产类型 3=全部)
"""
from __future__ import annotations

import base64
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

import requests

from .config import HunterConfig

OPEN_API_URL = "https://hunter.qianxin.com/openApi/search"  # 官方开放API（GET，需付费账号；POST 该路径 404）
API_URL = "https://hunter.qianxin.com/api/search"          # 网页内部接口（POST，免费账号游客模式：每页≤10条、仅首页）
# 官方查询语法示例：
#   domain="example.com"              —— 主域及子域资产
#   web.body="致远OA" && is_web=true  —— 正文含指定指纹的 WEB 资产
# 结果返回 total（总资产数）+ list（资产数组，含 ip/port/domain/web_title/component 等）


class HunterQuotaNearLimit(Exception):
    """宪法第3条：当日配额使用接近上限时告警暂停。"""


@dataclass
class HunterAsset:
    url: str
    ip: str
    port: int
    domain: str = ""
    title: str = ""
    component: list = field(default_factory=list)


class HunterClient:
    def __init__(self, cfg: HunterConfig, logger=None):
        if not cfg.api_key or cfg.api_key.startswith("YOUR_"):
            raise SystemExit("[!] config.yaml 中 hunter.api_key 未配置（鹰图个人中心获取）")
        self.cfg = cfg
        self.log = logger or (lambda msg: print(msg))
        self._guest = False  # 免费账号无开放API权限时，降级为网页内部接口游客模式

    def _search_once(self, query_b64: str, page: int, page_size: Optional[int] = None) -> dict:
        params = {
            "api-key": self.cfg.api_key,
            "search": query_b64,
            "page": page,
            "is_web": 3,        # 3 = 全部资产类型
            "start_time": "", "end_time": "",
        }
        if not self._guest:
            # 官方开放API（帮助中心文档）：GET /openApi/search。
            # 注意：POST 该路径 404（路由仅 GET）；认证 OK 但免费账号报「无 API 访问权限」。
            resp = requests.get(OPEN_API_URL, params={**params, "page_size": self.cfg.page_size}, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            code = data.get("code")
            if code == 200:
                return data.get("data") or {}
            msg = str(data.get("message") or "")
            if "无 API 访问权限" in msg or "付费" in msg:
                self.log("[!] Hunter 开放API需付费账号，本账号无权限；降级游客模式（每页≤10条，仅首页）")
                self._guest = True
            else:
                raise RuntimeError(f"Hunter API 错误 code={code}: {msg}")
        # 游客模式：网页内部接口 POST /api/search，page_size 上限 10
        resp = requests.post(API_URL, data={**params, "page_size": min(page_size or 10, 10)}, timeout=30)
        resp.raise_for_status()
        data = resp.json()
        code = data.get("code")
        if code != 200:
            raise RuntimeError(f"Hunter API 错误 code={code}: {data.get('message')}")
        return data.get("data") or {}

    def search(self, query: str, max_records: Optional[int] = None) -> Iterator[HunterAsset]:
        """按 Hunter 语法搜索资产，自动分页，带配额监控。"""
        max_records = max_records or self.cfg.max_records
        query_b64 = base64.b64encode(query.encode("utf-8")).decode()
        page, fetched = 1, 0

        while fetched < max_records:
            try:
                data = self._search_once(query_b64, page)
            except RuntimeError as e:
                # 游客模式/配额耗尽：翻页被拒（如「未登录仅支持查看10条资产」）。
                # 已拿到数据则温和降级止步，完全没拿到才上抛。
                if fetched > 0:
                    self.log(f"[!] Hunter 翻页受限，仅获取前 {fetched} 条（{e}）")
                    return
                raise
            # 2026-10 新版响应：total/list/web_title；兼容旧版 restotal/arr/web.title
            restotal = int(data.get("total") or data.get("restotal") or 0)
            arr = data.get("list") or data.get("arr") or []
            if not arr:
                break

            # 宪法第3条：配额监控（旧版 score_mode；新版 points/point_prompt 尽力读取）
            sm = data.get("score_mode") or {}
            self._check_quota(sm)
            if sm == {}:
                pts = data.get("points")
                if pts is not None and str(pts).strip() and str(pts) != "0":
                    self.log(f"[*] Hunter 剩余积分：{pts}")
                prompt = (data.get("point_prompt") or "").strip()
                if prompt:
                    self.log(f"[!] Hunter 配额提示：{prompt}")

            for item in arr:
                if fetched >= max_records:
                    return
                fetched += 1
                ip = str(item.get("ip") or "")
                port = str(item.get("port") or "")
                domain = str(item.get("domain") or "").lower()
                # 新版无 url 字段：按 protocol/ip/port 兜底拼接
                url = item.get("url") or ""
                if not url:
                    proto = str(item.get("protocol") or "").lower()
                    if proto not in ("http", "https"):
                        proto = "https" if port.endswith("443") else "http"
                    host = domain or ip
                    if host:
                        url = f"{proto}://{host}" if port in ("80", "443", "") else f"{proto}://{host}:{port}"
                title = item.get("web_title") or ""
                if not title and isinstance(item.get("web"), dict):
                    title = item.get("web").get("title") or ""
                try:
                    port_num = int(port) if port else 0
                except ValueError:
                    port_num = 0
                yield HunterAsset(
                    url=url,
                    ip=ip,
                    port=port_num,
                    domain=domain,
                    title=title,
                    component=item.get("component") or [],
                )

            if fetched >= restotal:
                break
            page += 1
            time.sleep(1.5)  # 温和翻页，不轰炸 API

    def _check_quota(self, score_mode: dict) -> None:
        """宪法第3条：单日用量超过配额 80% 时告警暂停。Hunter 返回的免费查询次数字段做尽力解析。"""
        if not score_mode:
            return
        # 防御性读取：不同账户类型字段不同
        daily_total = score_mode.get("daily_total") or score_mode.get("surplus_free") or 0
        daily_used = score_mode.get("daily_used") or score_mode.get("today_use_num") or 0
        if daily_total and daily_used:
            ratio = daily_used / daily_total
            if ratio >= self.cfg.quota_alert_ratio:
                raise HunterQuotaNearLimit(
                    f"宪法第3条：Hunter 当日配额已用 {daily_used}/{daily_total}（{ratio:.0%}），暂停拉取")

    def build_domain_query(self, domains: list[str]) -> str:
        """把目标域名列表拼成 Hunter 查询语法。"""
        parts = [f'domain="{d}"' for d in domains]
        return " || ".join(parts)
