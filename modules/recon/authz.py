# -*- coding: utf-8 -*-
"""只读越权检测（IDOR / 水平越权 + 垂直越权）。

严格边界：
- 只发 GET；本模块不含 POST/PUT/DELETE/PATCH 调用，也没有“开启写操作”的配置项；
- 不做竞态、金额篡改、写操作测试；
- 所有请求走 Prober.request（范围校验 → 配额 → 共享令牌桶 → 审计）；
- 凭据只在内存中解密，审计/证据/summary/report 全部脱敏。

流程：
1. 身份预检（每个身份 1 次轻量 GET，失效直接失败，不进入重放）
2. 采集候选（身份 A 的采集入口 + 现有 discovered/assets，筛对象标识）
3. 水平越权：A 基线 → B 重放 → 状态码/长度/相似度/匿名基线判定
4. 垂直越权：高权基线 → 低权重放（配置路径 + 高权页面里的管理链接）
5. 去重、证据、summary、报告
"""
from __future__ import annotations

import base64
import html
import json
import re
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Iterable, Optional

from core.constitution import TargetDef

from .audit import AuditLog
from .authz_creds import (AuthzConfigError, AuthzPlan, Identity, redact_text,
                          redact_url, safe_error)
from .config import Profile, ReconConfig
from .discovery import (STATIC_EXT, extract_js_endpoints, extract_links,
                        join_url, same_origin, url_key)
from .probe import ProbeAborted, Prober
from .schema import Asset, normalize_host

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
HEX_RE = re.compile(r"^[0-9a-f]{16,64}$", re.I)
NUM_RE = re.compile(r"^\d{3,12}$")
NUM_ANY_RE = re.compile(r"^\d{1,12}$")
BASE64_RE = re.compile(r"^[A-Za-z0-9_-]{12,}={0,2}$")
SLUG_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,}$")
OBJECT_PARAM_NAMES = {
    "id", "uid", "userid", "user_id", "account_id", "order_id", "orderid",
    "profile_id", "file_id", "item_id", "pid", "doc_id", "record_id",
    "resource_id", "project_id", "task_id", "no", "number",
}
NON_OBJECT_PARAMS = {
    "page", "p", "offset", "limit", "size", "q", "query", "search", "keyword",
    "sort", "order", "tab", "view", "lang", "locale", "t", "ts", "timestamp",
    "version", "ver", "v", "callback", "cb", "format", "type", "ref", "source",
}
COMMON_SEGMENTS = {
    "api", "v1", "v2", "v3", "v4", "static", "assets", "images", "img", "css",
    "js", "fonts", "login", "logout", "signin", "signup", "register", "admin",
    "user", "users", "account", "profile", "help", "about", "index", "home",
    "public", "notice", "docs", "swagger", "openapi",
}
LOGIN_RE = re.compile(
    r"(?is)(type\s*=\s*[\"']password[\"']|<form[^>]*(login|signin)|"
    r"请先登录|未登录|会话.{0,4}(过期|失效)|session\s+(expired|invalid)|"
    r"sign\s+in|log\s*in)")
ERROR_RE = re.compile(
    r"(?is)(404\s*not\s*found|page\s+not\s+found|access\s+denied|forbidden|"
    r"internal\s+server\s+error|页面不存在|无权访问|没有权限|系统错误|"
    r"请求的资源不存在)")
SENSITIVE_KEY_RE = re.compile(
    r"(?i)(password|passwd|token|secret|email|phone|mobile|user|role|audit|"
    r"config|key|session|cookie|address|balance|amount)")
ADMIN_PATH_RE = re.compile(
    r"(?i)(admin|manage|manager|console|system|setting|audit|user|role|permission|"
    r"后台|管理|用户|权限|审计|配置)")
STATIC_EXT_LOCAL = STATIC_EXT | {".js", ".map"}

DEFAULT_VERTICAL_PATHS = [
    "/admin", "/admin/", "/admin/users", "/admin/audit", "/manager",
    "/system", "/console", "/settings", "/api/admin", "/api/admin/users",
    "/api/v1/admin", "/api/users", "/user/list", "/role/list",
]


class AuthzError(RuntimeError):
    """越权检测配置/执行失败（消息中不含 secret）。"""


class AuthzSessionError(AuthzError):
    """身份会话失效，任务直接失败。"""


@dataclass
class Response:
    status: int = 0
    text: str = ""
    length: int = 0
    headers: dict = field(default_factory=dict)
    url: str = ""
    error: str = ""

    @property
    def ok(self) -> bool:
        return 200 <= self.status < 300


@dataclass
class Candidate:
    url: str
    source: str
    tokens: list = field(default_factory=list)


@dataclass
class AuthzResult:
    suspects: list = field(default_factory=list)
    summary: dict = field(default_factory=dict)
    paths: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


class AuthzBudget:
    """本次运行的越权请求上限（独立于全局日配额，但共享令牌桶与审计）。"""

    def __init__(self, limit: int):
        self.limit = max(0, int(limit))
        self.used = 0
        self.exhausted = False

    def take(self) -> bool:
        if self.used >= self.limit:
            self.exhausted = True
            return False
        self.used += 1
        return True


class ProberFetch:
    """生产用 fetcher：按身份隔离 session，注入 cookie/header，走 Prober.request。"""

    def __init__(self, prober: Prober, plan: AuthzPlan, console: Callable[[str], None] = print):
        self.prober = prober
        self.plan = plan
        self.log = console
        self.sessions = {i.name: prober.new_session() for i in plan.identities}
        self.sessions["anonymous"] = prober.new_session()
        self.aborted = False
        self.abort_reason = ""

    def __call__(self, identity: Identity, url: str, case: str) -> Optional[Response]:
        if self.aborted:
            return None
        session = self.sessions.get(identity.name)
        if session is None:
            session = self.prober.new_session()
            self.sessions[identity.name] = session
        # 每次请求前重置 cookie，防止响应 Set-Cookie 串到另一个身份
        try:
            session.cookies.clear()
        except Exception:
            pass
        for k, v in identity.cookie_dict.items():
            try:
                session.cookies.set(k, v)
            except Exception:
                pass
        try:
            res = self.prober.request(
                url, normalize_host(url), stage="authz",
                extra_headers=identity.headers or None, session=session,
                identity="" if identity.name == "anonymous" else identity.name,
                audit_url=redact_url(url), tag=case,
            )
        except ProbeAborted as e:
            self.aborted = True
            self.abort_reason = str(e)
            return None
        if not res:
            return None
        return Response(status=int(res.get("status") or 0),
                        text=str(res.get("text") or ""),
                        length=len(res.get("body") or b""),
                        headers=dict(res.get("headers") or {}),
                        url=str(res.get("url") or url))


def _norm_text(text: str) -> str:
    s = str(text or "")
    s = re.sub(r"(?is)<(script|style)\b.*?</\1>", " ", s)
    s = re.sub(r"(?is)<[^>]+>", " ", s)
    s = html.unescape(s)
    s = s.replace("\u00a0", " ")
    return re.sub(r"\s+", " ", s).strip().lower()


def _tokens(text: str) -> list[str]:
    return re.findall(r"[a-z0-9\u4e00-\u9fff]+", _norm_text(text))


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    return len(a & b) / len(a | b)


def _shingles(tokens: list[str], n: int = 3) -> set:
    if len(tokens) <= n:
        return set(tokens)
    return {tuple(tokens[i:i + n]) for i in range(len(tokens) - n + 1)}


def _canon_value(v) -> str:
    if isinstance(v, (dict, list)):
        return json.dumps(v, ensure_ascii=False, sort_keys=True)
    return str(v)


def similarity(a_text: str, b_text: str) -> tuple[float, dict]:
    """返回 (0..1 相似度, 说明)。优先 JSON 顶层字段，退回文本 token/shingle Jaccard。"""
    a_raw, b_raw = str(a_text or ""), str(b_text or "")
    a_len, b_len = len(a_raw), len(b_raw)
    ratio = (min(a_len, b_len) / max(a_len, b_len)) if max(a_len, b_len) else 0.0
    if not a_raw or not b_raw:
        return 0.0, {"method": "empty", "length_ratio": round(ratio, 4)}
    # JSON
    try:
        ja, jb = json.loads(a_raw), json.loads(b_raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        ja = jb = None
    if isinstance(ja, dict) and isinstance(jb, dict):
        ka, kb = set(ja.keys()), set(jb.keys())
        key_sim = _jaccard(ka, kb)
        common = ka & kb
        vals = []
        for k in common:
            ta, tb = _tokens(_canon_value(ja[k])), _tokens(_canon_value(jb[k]))
            vals.append(_jaccard(set(ta), set(tb)))
        val_sim = sum(vals) / len(vals) if vals else key_sim
        score = 0.6 * key_sim + 0.4 * val_sim
        return round(score, 4), {
            "method": "json_top_level", "keys_jaccard": round(key_sim, 4),
            "values_jaccard": round(val_sim, 4), "length_ratio": round(ratio, 4),
            "a_len": a_len, "b_len": b_len,
        }
    ta, tb = _tokens(a_raw), _tokens(b_raw)
    token_sim = _jaccard(set(ta), set(tb))
    shingle_sim = _jaccard(_shingles(ta), _shingles(tb))
    score = token_sim if len(ta) < 20 or len(tb) < 20 else 0.6 * token_sim + 0.4 * shingle_sim
    return round(score, 4), {
        "method": "token_shingle", "tokens_jaccard": round(token_sim, 4),
        "shingles_jaccard": round(shingle_sim, 4), "length_ratio": round(ratio, 4),
        "a_len": a_len, "b_len": b_len,
    }


def is_login_like(text: str) -> bool:
    return bool(LOGIN_RE.search(str(text or "")))


def is_error_like(text: str) -> bool:
    return bool(ERROR_RE.search(str(text or "")))


def sensitive_fields(text: str) -> list[str]:
    out: list[str] = []
    try:
        data = json.loads(str(text or ""))
    except (json.JSONDecodeError, TypeError, ValueError):
        data = None
    if isinstance(data, dict):
        for k in data.keys():
            if SENSITIVE_KEY_RE.search(str(k)):
                out.append(str(k))
    elif isinstance(data, list):
        for item in data[:5]:
            if isinstance(item, dict):
                out.extend(str(k) for k in item.keys() if SENSITIVE_KEY_RE.search(str(k)))
    for m in re.finditer(r"(?i)(password|token|email|phone|role|权限|用户|审计|配置)"
                         r"\s*[:=]\s*[^\s,;]{1,40}", str(text or "")):
        out.append(m.group(0)[:50])
    seen, res = set(), []
    for x in out:
        if x not in seen:
            seen.add(x)
            res.append(x)
    return res[:8]


def _is_base64_like(s: str) -> bool:
    if not BASE64_RE.match(s):
        return False
    if not any(c.isdigit() or c in "-_=" for c in s):
        return False
    try:
        raw = s + "=" * ((4 - len(s) % 4) % 4)
        dec = base64.urlsafe_b64decode(raw.encode())
    except Exception:
        return False
    return len(dec) >= 4


def _token_kind(value: str) -> str:
    v = urllib.parse.unquote(str(value or "").strip())
    if UUID_RE.match(v):
        return "uuid"
    if NUM_RE.match(v):
        return "numeric"
    if HEX_RE.match(v):
        return "hash"
    if _is_base64_like(v):
        return "base64"
    if (SLUG_RE.match(v) and (any(c.isdigit() for c in v) or "-" in v or "_" in v)
            and v.lower() not in COMMON_SEGMENTS):
        return "slug"
    return ""


def object_tokens(url: str) -> list[dict]:
    """筛出 URL 中的对象标识（路径段 / 对象型查询参数）。"""
    try:
        parts = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return []
    out: list[dict] = []
    for i, seg in enumerate([x for x in parts.path.split("/") if x]):
        s = urllib.parse.unquote(seg)
        if s.lower() in COMMON_SEGMENTS or s.lower() in STATIC_EXT_LOCAL:
            continue
        kind = _token_kind(s)
        if kind:
            out.append({"kind": kind, "value": s[:80], "where": f"path[{i}]"})
    for name, value in urllib.parse.parse_qsl(parts.query, keep_blank_values=True):
        n = name.lower()
        if n in NON_OBJECT_PARAMS or n.startswith("utm_"):
            continue
        kind = _token_kind(value)
        if not kind and n in OBJECT_PARAM_NAMES and NUM_ANY_RE.match(str(value or "")):
            kind = "numeric"   # 查询参数 id=1 这类短数字也接受
        if not kind:
            continue
        if kind == "numeric" and n not in OBJECT_PARAM_NAMES:
            continue
        if kind in ("uuid", "hash", "base64") or n in OBJECT_PARAM_NAMES:
            out.append({"kind": kind, "value": value[:80], "where": f"query:{name}"})
    # 去重（同一 token 在路径/查询重复出现）
    seen, res = set(), []
    for t in out:
        key = (t["kind"], t["value"])
        if key not in seen:
            seen.add(key)
            res.append(t)
    return res


def is_excluded_url(url: str) -> bool:
    try:
        u = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return True
    path = (u.path or "/").lower()
    if path.endswith(tuple(STATIC_EXT_LOCAL)):
        return True
    if any(x in path for x in ("/login", "/logout", "/signin", "/signup", "/register",
                               "/error", "/404", "/500", "/favicon")):
        return True
    return False


def canonical_resource_url(url: str) -> str:
    """去 fragment + 去非对象查询参数，用于同资源去重。"""
    try:
        u = urllib.parse.urlsplit(str(url or ""))
    except ValueError:
        return str(url or "")
    q = []
    for k, v in urllib.parse.parse_qsl(u.query, keep_blank_values=True):
        n = k.lower()
        if n in NON_OBJECT_PARAMS or n.startswith("utm_") or n in ("ref", "source"):
            continue
        q.append((k, v))
    query = urllib.parse.urlencode(q)
    return urllib.parse.urlunsplit((u.scheme.lower(), u.netloc.lower(), u.path, query, ""))


def _resolve_vertical_paths(plan: AuthzPlan, high: Identity,
                            console: Callable[[str], None],
                            extra: Iterable[str] = ()) -> list[str]:
    base = plan.vertical_base or plan.default_check_url
    configured = list(plan.vertical_paths or [])
    paths: list[str] = []
    if configured:
        for p in configured:
            if p.startswith(("http://", "https://")):
                paths.append(p)
            elif base:
                paths.append(join_url(base, p))
        for u in extra:
            paths.append(u)
    else:
        # 从高权采集入口/页面链接里的管理链接推断
        for u in high.start_urls:
            if ADMIN_PATH_RE.search(urllib.parse.urlsplit(u).path or ""):
                paths.append(u)
        paths.extend(extra)
        for p in DEFAULT_VERTICAL_PATHS:
            paths.append(join_url(base, p) if base else "")
    seen, out = set(), []
    for u in paths:
        if not u or not u.startswith(("http://", "https://")):
            continue
        key = canonical_resource_url(u)
        if key in seen:
            continue
        seen.add(key)
        out.append(u)
        if len(out) >= plan.settings.get("max_vertical_paths", 30):
            break
    return out


def classify(a: Response, b: Response, *, threshold: float, public_similarity: float,
             anonymous: Optional[Response] = None,
             kind: str = "horizontal") -> dict:
    """纯判定函数：返回 verdict/status/reason/similarity。"""
    sim, meta = similarity(a.text, b.text)
    base = {"similarity": sim, "meta": meta, "threshold": threshold,
            "kind": kind, "a_status": a.status, "b_status": b.status}
    if not a.ok:
        return {**base, "verdict": "skip", "reason": f"A 无法访问（HTTP {a.status}），无基线"}
    if is_login_like(a.text):
        return {**base, "verdict": "skip", "reason": "A 基线是登录页/登录跳转"}
    if is_error_like(a.text):
        return {**base, "verdict": "skip", "reason": "A 基线是统一错误页"}
    if b.status in (401, 403, 404):
        return {**base, "verdict": "normal",
                "reason": f"B 被正确拒绝（HTTP {b.status}）"}
    if 300 <= b.status < 400:
        return {**base, "verdict": "normal",
                "reason": f"B 被重定向到登录/其他页面（HTTP {b.status}）"}
    if b.status >= 500:
        return {**base, "verdict": "error", "reason": f"B 返回服务端错误（HTTP {b.status}）"}
    if not b.ok:
        return {**base, "verdict": "normal", "reason": f"B 返回 HTTP {b.status}，不构成数据泄露"}
    if is_login_like(b.text):
        return {**base, "verdict": "normal", "reason": "B 返回登录页，未获得资源"}
    if is_error_like(b.text):
        return {**base, "verdict": "normal", "reason": "B 返回统一错误页，未获得资源"}
    if sim < threshold:
        return {**base, "verdict": "normal",
                "reason": f"内容相似度 {sim:.3f} < 阈值 {threshold:.2f}，判定为不同内容"}
    if meta.get("length_ratio", 0) < 0.5:
        return {**base, "verdict": "normal",
                "reason": f"响应长度差异过大（ratio={meta.get('length_ratio')}）"}
    if anonymous is not None and anonymous.ok:
        anon_sim, _ = similarity(a.text, anonymous.text)
        if anon_sim >= public_similarity:
            return {**base, "verdict": "suppressed_public",
                    "reason": f"匿名访问相似度 {anon_sim:.3f} ≥ {public_similarity:.2f}，判定为公共页",
                    "anonymous_similarity": anon_sim}
    return {**base, "verdict": "suspect",
            "reason": (f"B 返回 200 且与 A 相似度 {sim:.3f} ≥ 阈值 {threshold:.2f}；"
                       f"匿名访问不可达或内容不同，疑似越权")}


def _evidence_score(item: dict) -> float:
    score = float(item.get("similarity") or 0)
    if item.get("a_sample") and item.get("b_sample"):
        score += 1.0
    if item.get("sensitive_fields"):
        score += 0.1
    return round(score, 4)


class AuthzRunner:
    """执行越权检测；fetch 可注入，便于单测不依赖真实网络。"""

    def __init__(self, *, plan: AuthzPlan, fetch: Callable[[Identity, str, str], Optional[Response]],
                 target: TargetDef, console: Callable[[str], None] = print,
                 in_scope: Optional[Callable[[str], bool]] = None,
                 budget: Optional[AuthzBudget] = None):
        self.plan = plan
        self.fetch = fetch
        self.target = target
        self.log = console
        self.in_scope = in_scope or (lambda h: True)
        self.settings = plan.settings
        self.budget = budget or AuthzBudget(int(self.settings.get("max_requests", 200)))
        self.prechecked = False
        self._cache: dict[tuple[str, str], Response] = {}
        self.errors: list[str] = []
        self.warnings: list[str] = []
        self.aborted = False
        self._admin_links: list[str] = []

    # ------------------------------------------------------------------
    def _get(self, identity: Identity, url: str, case: str) -> Optional[Response]:
        if self.aborted or self.budget.exhausted:
            return None
        key = (identity.name, canonical_resource_url(url))
        if key in self._cache:
            return self._cache[key]
        if not self.budget.take():
            self.aborted = True
            return None
        try:
            res = self.fetch(identity, url, case)
        except Exception as e:
            self.errors.append(safe_error(e, self.plan.identities))
            return None
        if res is None:
            self.errors.append(f"{identity.name} 请求失败：{redact_url(url)}")
            return None
        self._cache[key] = res
        return res

    def _anonymous(self, url: str) -> Optional[Response]:
        anon = Identity(name="anonymous", role="anon")
        return self._get(anon, url, "anonymous")

    # ------------------------------------------------------------------
    def precheck(self) -> None:
        """每个身份先做 1 次轻量 GET；失效直接抛错，不进入后续重放。"""
        if self.prechecked:
            return
        for ident in self.plan.identities:
            url = ident.session_check_url or self.plan.default_check_url
            if not url:
                raise AuthzConfigError(f"身份 {ident.name} 缺少会话校验 URL")
            res = self._get(ident, url, "precheck")
            if res is None:
                raise AuthzSessionError(
                    f"身份 {ident.name} 会话预检失败：无响应（{redact_url(url)}）")
            allowed = set(ident.expect_status or [200])
            if 300 <= res.status < 400 or res.status in (401, 403) or \
                    (res.status not in allowed and not res.ok):
                raise AuthzSessionError(
                    f"身份 {ident.name} 会话失效：HTTP {res.status}（{redact_url(url)}）")
            if is_login_like(res.text):
                raise AuthzSessionError(
                    f"身份 {ident.name} 会话失效：返回登录页（{redact_url(url)}）")
            if ident.expect_body_contains and ident.expect_body_contains not in res.text:
                raise AuthzSessionError(
                    f"身份 {ident.name} 会话失效：响应缺少标记 "
                    f"`{ident.expect_body_contains[:20]}`")
            self.log(f"[*] 身份 {ident.name}（{ident.role}）会话有效")
        self.prechecked = True

    # ------------------------------------------------------------------
    def run(self, *, discovered_urls: Iterable[str] = (),
            assets: Iterable[Asset] = (), precheck: bool = True) -> AuthzResult:
        t0 = time.monotonic()
        if precheck:
            self.precheck()
        candidates = self._collect(discovered_urls, assets)
        suspects: list[dict] = []
        counts = {"horizontal_tested": 0, "vertical_tested": 0,
                  "suppressed_public": 0, "normal": 0, "skipped": 0, "errors": 0}
        # ---- 水平越权 ----
        for cand in candidates:
            if self.aborted or self.budget.exhausted:
                break
            a = self._get(self.plan.owner, cand.url, "horizontal-owner")
            if a is None:
                counts["errors"] += 1
                continue
            decision = classify(a, a, threshold=self.settings["similarity_threshold"],
                                public_similarity=self.settings["public_similarity"])
            if decision["verdict"] != "suspect":
                # A 基线不可用（登录/错误/非 2xx）时不再重放
                if decision["verdict"] == "skip":
                    counts["skipped"] += 1
                continue
            b = self._get(self.plan.attacker, cand.url, "horizontal-attacker")
            if b is None:
                counts["errors"] += 1
                continue
            counts["horizontal_tested"] += 1
            anon = None
            # 先做廉价判定；只有相似才发匿名基线，节省预算
            pre = classify(a, b, threshold=self.settings["similarity_threshold"],
                           public_similarity=self.settings["public_similarity"])
            if pre["verdict"] == "suspect":
                anon = self._anonymous(cand.url)
            decision = classify(a, b, threshold=self.settings["similarity_threshold"],
                                public_similarity=self.settings["public_similarity"],
                                anonymous=anon)
            if decision["verdict"] == "suspect":
                suspects.append(self._evidence("horizontal", cand, a, b, decision))
            elif decision["verdict"] == "suppressed_public":
                counts["suppressed_public"] += 1
            elif decision["verdict"] == "normal":
                counts["normal"] += 1
            elif decision["verdict"] == "error":
                counts["errors"] += 1
            else:
                counts["skipped"] += 1
        # ---- 垂直越权 ----
        vertical = []
        if self.plan.high and self.plan.low:
            vertical = _resolve_vertical_paths(self.plan, self.plan.high, self.log,
                                               extra=self._admin_links)
        else:
            self.warnings.append("未配置 high/low 身份，跳过垂直越权")
        for url in vertical:
            if self.aborted or self.budget.exhausted:
                break
            a = self._get(self.plan.high, url, "vertical-high")
            if a is None:
                counts["errors"] += 1
                continue
            if not a.ok or is_login_like(a.text) or is_error_like(a.text):
                counts["skipped"] += 1
                continue
            b = self._get(self.plan.low, url, "vertical-low")
            if b is None:
                counts["errors"] += 1
                continue
            counts["vertical_tested"] += 1
            pre = classify(a, b, threshold=self.settings["similarity_threshold"],
                           public_similarity=self.settings["public_similarity"])
            anon = self._anonymous(url) if pre["verdict"] == "suspect" else None
            decision = classify(a, b, threshold=self.settings["similarity_threshold"],
                                public_similarity=self.settings["public_similarity"],
                                anonymous=anon, kind="vertical")
            if decision["verdict"] == "suspect":
                suspects.append(self._evidence("vertical", Candidate(url, "vertical", []),
                                               a, b, decision))
            elif decision["verdict"] == "suppressed_public":
                counts["suppressed_public"] += 1
            elif decision["verdict"] == "normal":
                counts["normal"] += 1
            elif decision["verdict"] == "error":
                counts["errors"] += 1
            else:
                counts["skipped"] += 1

        suspects = self._dedupe(suspects)
        counts["horizontal_suspects"] = sum(1 for s in suspects if s["kind"] == "horizontal")
        counts["vertical_suspects"] = sum(1 for s in suspects if s["kind"] == "vertical")
        duration = round(time.monotonic() - t0, 2)
        summary = {
            "schema": "recon.authz/v1",
            "target": self.plan.target_name,
            "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "identities": [i.public() for i in self.plan.identities],
            "owner": self.plan.owner.name, "attacker": self.plan.attacker.name,
            "high": self.plan.high.name if self.plan.high else "",
            "low": self.plan.low.name if self.plan.low else "",
            "threshold": self.settings["similarity_threshold"],
            "public_similarity": self.settings["public_similarity"],
            "max_requests": self.settings["max_requests"],
            "requests": self.budget.used,
            "budget_exhausted": bool(self.budget.exhausted),
            "aborted": bool(self.aborted),
            "candidates": len(candidates),
            **counts,
            "suspects": len(suspects),
            "errors_detail": self.errors[:20],
            "duration_s": duration,
        }
        return AuthzResult(suspects=suspects, summary=summary,
                           warnings=list(self.warnings))

    # ------------------------------------------------------------------
    def _collect(self, discovered_urls: Iterable[str], assets: Iterable[Asset]) -> list[Candidate]:
        seen: set[str] = set()
        out: list[Candidate] = []
        limit = int(self.settings.get("max_candidates", 100))

        def add(url: str, source: str) -> None:
            if len(out) >= limit:
                return
            if not url or not str(url).startswith(("http://", "https://")):
                return
            if is_excluded_url(url):
                return
            host = normalize_host(url)
            if not self.in_scope(host):
                return
            tokens = object_tokens(url)
            if not tokens:
                return
            key = canonical_resource_url(url)
            if key in seen:
                return
            seen.add(key)
            out.append(Candidate(url=url, source=source, tokens=tokens))

        pages = 0
        for start in self.plan.start_urls[:int(self.settings.get("max_collect_pages", 10))]:
            if self.aborted or self.budget.exhausted:
                break
            pages += 1
            res = self._get(self.plan.owner, start, "collect-owner")
            if res is None or not res.ok:
                continue
            add(start, "owner-start")
            links = extract_links(res.text, start)
            for link in links:
                add(link, "owner-link")
                if (same_origin(start, link) and
                        ADMIN_PATH_RE.search(urllib.parse.urlsplit(link).path or "") and
                        link not in self._admin_links):
                    self._admin_links.append(link)
            for ep in extract_js_endpoints(res.text):
                add(join_url(start, ep), "owner-js")
            js_files = [u for u in links if urllib.parse.urlsplit(u).path.lower().endswith(".js")][:2]
            for js in js_files:
                if not same_origin(start, js):
                    continue
                js_res = self._get(self.plan.owner, js, "collect-js")
                if js_res and js_res.ok:
                    for ep in extract_js_endpoints(js_res.text):
                        add(join_url(js, ep), "owner-js")
        for u in discovered_urls:
            add(str(u), "discovered")
        for a in assets:
            if getattr(a, "url", ""):
                add(str(a.url), "asset")
        if pages == 0:
            self.warnings.append("没有配置身份 A 的采集入口，仅使用已有 discovered/assets")
        if len(out) >= limit:
            self.warnings.append(f"候选达到上限 {limit}，后续 URL 未检测")
        return out

    def _evidence(self, kind: str, cand: Candidate, a: Response, b: Response,
                  decision: dict) -> dict:
        truncate = int(self.settings.get("response_truncate", 400))
        return {
            "schema": "recon.authz/v1",
            "kind": kind,
            "method": "GET",
            "url": cand.url,
            "source": cand.source,
            "object_tokens": cand.tokens,
            "identity_a": self.plan.owner.name,
            "identity_b": self.plan.attacker.name,
            "a_status": a.status, "b_status": b.status,
            "a_len": a.length, "b_len": b.length,
            "similarity": decision["similarity"],
            "similarity_meta": decision.get("meta") or {},
            "threshold": self.settings["similarity_threshold"],
            "verdict": "suspect",
            "reason": decision.get("reason", ""),
            "sensitive_fields": sensitive_fields(b.text),
            "a_sample": redact_text(a.text, self.plan.identities, truncate),
            "b_sample": redact_text(b.text, self.plan.identities, truncate),
            "evidence_score": 0.0,   # 下面统一补
        }

    @staticmethod
    def _dedupe(items: list[dict]) -> list[dict]:
        best: dict[str, dict] = {}
        for item in items:
            item["evidence_score"] = _evidence_score(item)
            key = f"{item.get('kind')}|{canonical_resource_url(item.get('url', ''))}"
            if key not in best or item["evidence_score"] > best[key]["evidence_score"]:
                best[key] = item
        return sorted(best.values(), key=lambda x: (-x["evidence_score"], x["url"]))


def write_outputs(result: AuthzResult, *, target_dir: Path, audit: AuditLog,
                  plan: AuthzPlan) -> dict:
    """落盘 authz.jsonl / authz-summary.json / authz-report.md；全部已脱敏。"""
    target_dir = Path(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    findings_path = target_dir / "authz.jsonl"
    summary_path = target_dir / "authz-summary.json"
    report_path = target_dir / "authz-report.md"
    with findings_path.open("w", encoding="utf-8") as f:
        for item in result.suspects:
            f.write(json.dumps(item, ensure_ascii=False) + "\n")
    summary = dict(result.summary)
    summary["warnings"] = list(result.warnings)
    summary["paths"] = {"findings": str(findings_path), "summary": str(summary_path),
                        "report": str(report_path)}
    summary["audit"] = {"path": str(audit.path), "records": audit.count(),
                        "degraded": audit.degraded}
    summary["accounts"] = {"path": str(plan.accounts_path),
                           "identities": [i.public() for i in plan.identities]}
    summary_path.write_text(json.dumps(summary, ensure_ascii=False, indent=2),
                            encoding="utf-8")
    report_path.write_text(_render_report(result, summary, plan), encoding="utf-8")
    result.summary = summary
    return summary


def _render_report(result: AuthzResult, summary: dict, plan: AuthzPlan) -> str:
    lines = ["# 只读越权检测报告", "",
             f"- 目标：{summary.get('target')}",
             f"- 生成时间：{summary.get('generated_at')}",
             f"- 身份：A={summary.get('owner')}（{plan.owner.role}） / "
             f"B={summary.get('attacker')}（{plan.attacker.role}）",
             f"- 阈值：相似度 ≥ {summary.get('threshold')}；公共页抑制 ≥ "
             f"{summary.get('public_similarity')}",
             f"- 请求：{summary.get('requests')} / 上限 {summary.get('max_requests')}"
             f"{'（已停止）' if summary.get('budget_exhausted') else ''}",
             f"- 候选 {summary.get('candidates')}；水平测试 {summary.get('horizontal_tested')}；"
             f"垂直测试 {summary.get('vertical_tested')}；疑似 {summary.get('suspects')}；"
             f"公共页抑制 {summary.get('suppressed_public')}；正常 {summary.get('normal')}",
             "",
             "> 仅 GET 重放；证据响应已脱敏并截断；凭据不写入本文件。", ""]
    if not result.suspects:
        lines += ["## 结果", "", "未发现疑似越权。", ""]
    for i, item in enumerate(result.suspects, 1):
        lines += [f"## {i}. [{item['kind']}] {item['url']}", "",
                  f"- A 状态 / B 状态：{item['a_status']} / {item['b_status']}",
                  f"- 相似度：{item['similarity']:.3f}（阈值 {item['threshold']}）",
                  f"- 判定依据：{item['reason']}",
                  f"- 敏感字段：{', '.join(item.get('sensitive_fields') or []) or '-'}",
                  "", "**A 响应（脱敏）**", "", "```", item.get("a_sample", ""), "```", "",
                  "**B 响应（脱敏）**", "", "```", item.get("b_sample", ""), "```", ""]
    if summary.get("warnings"):
        lines += ["## 警告", ""] + [f"- {w}" for w in summary["warnings"]] + [""]
    return "\n".join(lines)
