# -*- coding: utf-8 -*-
"""越权检测账号与凭据：元数据（无 secret）+ Fernet 本地加密库 + 输出脱敏。

安全底线：
- cookie / 自定义 header 只存在于内存与加密 vault 中，不写入元数据、审计、summary、report；
- vault 使用 Fernet（AES128-CBC + HMAC），密钥文件仅当前用户可读写（Windows 用 icacls 收紧）；
- 身份对象 repr 不包含 secret，异常信息统一脱敏；
- 面板只拿到身份名称/角色，不显示凭据。
"""
from __future__ import annotations

import base64
import json
import os
import re
import stat
import subprocess
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

import yaml
from cryptography.fernet import Fernet, InvalidToken

from core.constitution import TargetDef, check_host_in_scope

from .ledger import slugify

ACCOUNTS_SCHEMA = "recon.authz-accounts/v1"
ROLES = {"high", "low", "user"}
HEADER_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
SENSITIVE_QUERY = re.compile(
    r"(?i)(token|session|sessionid|jsessionid|phpsessid|auth|apikey|api_key|key|secret|csrf|xsrf)")
JSON_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|token|secret|email|phone|mobile|authorization|cookie|"
    r"session|api.?key|csrf|xsrf|debug_cookie)")
JSON_SECRET_VALUE_RE = re.compile(
    r'(?i)("[^"]*(?:password|passwd|token|secret|email|phone|mobile|authorization|'
    r'cookie|session|api.?key|csrf|xsrf|debug_cookie)[^"]*"\s*:\s*)"[^"]*"')
SECRET_PATTERNS = (
    (re.compile(r"(?i)(authorization|proxy-authorization)\s*[:=]\s*(?:bearer\s+)?[^\s,;\"']+"),
     r"\1: [REDACTED]"),
    (re.compile(r"(?i)(cookie|set-cookie)\s*[:=]\s*[^\r\n]+"), r"\1: [REDACTED]"),
    (re.compile(r"(?i)(x-api-key|api-key|apikey|access_token|refresh_token|token|session|"
                r"sessionid|jsessionid|phpsessid|csrf|xsrf)\s*[:=]\s*[^\s,;\"']+"),
     r"\1: [REDACTED]"),
    (re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]"),
    (re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
     "[REDACTED-JWT]"),
)


class AuthzConfigError(ValueError):
    """越权检测配置/账号不符合要求。"""


class AuthzCredentialError(RuntimeError):
    """凭据库无法读取/解密（不包含 secret 内容）。"""


def parse_cookie(raw: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for part in str(raw or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        k, v = part.split("=", 1)
        k = k.strip()
        if k:
            out[k] = v.strip()
    return out


def parse_headers(raw) -> dict[str, str]:
    if isinstance(raw, dict):
        items = [(str(k), str(v)) for k, v in raw.items()]
    else:
        items = []
        for line in str(raw or "").splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if ":" not in line:
                raise AuthzConfigError(f"自定义 Header 格式错误（需 Name: value）：{line[:24]}")
            k, v = line.split(":", 1)
            items.append((k.strip(), v.strip()))
    out: dict[str, str] = {}
    for k, v in items:
        if not k or not HEADER_NAME_RE.match(k):
            raise AuthzConfigError(f"非法 Header 名称：{k[:24]}")
        if "\r" in v or "\n" in v:
            raise AuthzConfigError("Header 值不能包含换行")
        if k.lower() == "cookie":
            raise AuthzConfigError("Cookie 请填到 cookie 字段，不要写进 headers")
        out[k] = v
    if len(out) > 20:
        raise AuthzConfigError("自定义 Header 不能超过 20 个")
    return out


def _restrict_file(path: Path) -> None:
    """尽量收紧文件权限：Unix 0600；Windows 去掉继承并只授权当前用户。"""
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    if os.name != "nt":
        return
    try:
        who = subprocess.run(["whoami"], capture_output=True, text=True, timeout=5)
        user = (who.stdout or "").strip()
        if not user:
            return
        subprocess.run(
            ["icacls", str(path), "/inheritance:r", "/grant:r", f"{user}:(F)"],
            capture_output=True, timeout=8)
    except Exception:
        pass


class SecretVault:
    """本地加密凭据库：credential_id -> {cookie, headers}。"""

    def __init__(self, path: Path, key_path: Path):
        self.path = Path(path)
        self.key_path = Path(key_path)
        self._lock = threading.Lock()

    # ---- 密钥 ----
    def _key(self, create: bool) -> bytes:
        if not self.key_path.exists():
            if not create:
                raise AuthzCredentialError(
                    "凭据密钥不存在（workspace/authz/vault.key），请重新配置账号")
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            self.key_path.write_bytes(Fernet.generate_key())
            _restrict_file(self.key_path)
        try:
            return self.key_path.read_bytes()
        except OSError as e:
            raise AuthzCredentialError(f"凭据密钥读取失败：{type(e).__name__}") from None

    def _fernet(self, create: bool) -> Fernet:
        try:
            return Fernet(self._key(create))
        except (ValueError, TypeError):
            raise AuthzCredentialError("凭据密钥格式非法，无法解密") from None

    # ---- 读写 ----
    def load(self) -> dict[str, dict]:
        if not self.path.exists():
            return {}
        with self._lock:
            try:
                token = self.path.read_bytes()
                data = json.loads(self._fernet(False).decrypt(token).decode("utf-8"))
            except InvalidToken:
                raise AuthzCredentialError("凭据库解密失败（密钥不匹配或文件损坏）") from None
            except (OSError, ValueError, TypeError, json.JSONDecodeError):
                raise AuthzCredentialError("凭据库读取失败（文件损坏）") from None
        return data if isinstance(data, dict) else {}

    def get(self, credential_id: str) -> dict:
        data = self.load()
        item = data.get(credential_id)
        if not isinstance(item, dict):
            raise AuthzCredentialError(f"凭据不存在：{credential_id}")
        return item

    def put_many(self, items: dict[str, dict]) -> None:
        if not items:
            return
        with self._lock:
            data = {}
            if self.path.exists():
                try:
                    token = self.path.read_bytes()
                    data = json.loads(self._fernet(False).decrypt(token).decode("utf-8"))
                except InvalidToken:
                    raise AuthzCredentialError("凭据库解密失败（密钥不匹配或文件损坏）") from None
                except (OSError, ValueError, TypeError, json.JSONDecodeError):
                    raise AuthzCredentialError("凭据库读取失败（文件损坏）") from None
            if not isinstance(data, dict):
                data = {}
            data.update(items)
            enc = self._fernet(True).encrypt(
                json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8"))
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_bytes(enc)
            os.replace(tmp, self.path)
            _restrict_file(self.path)


@dataclass
class Identity:
    """一个测试身份；secret 字段不参与 repr / 序列化。"""
    name: str
    role: str = "user"
    credential_id: str = ""
    start_urls: list = field(default_factory=list)
    session_check_url: str = ""
    expect_status: list = field(default_factory=lambda: [200])
    expect_body_contains: str = ""
    cookie: str = field(default="", repr=False, compare=False)
    headers: dict = field(default_factory=dict, repr=False, compare=False)

    def __repr__(self) -> str:
        return f"Identity(name={self.name!r}, role={self.role!r})"

    def public(self) -> dict:
        return {"name": self.name, "role": self.role,
                "start_urls": list(self.start_urls),
                "session_check_url": self.session_check_url}

    @property
    def cookie_dict(self) -> dict:
        return parse_cookie(self.cookie)

    @property
    def has_secret(self) -> bool:
        return bool(self.cookie.strip() or self.headers)


def _scope_target(target_name: str, vendor: str, authorization: str,
                 domains: Iterable[str], ips: Iterable[str]) -> TargetDef:
    return TargetDef(name=target_name, vendor=vendor or target_name,
                     authorization=authorization or "form",
                     domains=[str(x) for x in domains], ips=[str(x) for x in ips])


def _validate_url(url: str, target: TargetDef, field_name: str) -> str:
    u = str(url or "").strip()
    if not u:
        raise AuthzConfigError(f"{field_name}不能为空")
    if not u.startswith(("http://", "https://")):
        raise AuthzConfigError(f"{field_name}必须是 http/https URL")
    host = (urlsplit(u).hostname or "").lower()
    if not host:
        raise AuthzConfigError(f"{field_name}缺少主机名")
    if not check_host_in_scope(host, target):
        raise AuthzConfigError(f"{field_name}主机 {host} 不在授权范围")
    return u


def _default_check_url(identity: dict, target: TargetDef) -> str:
    starts = [str(x) for x in (identity.get("start_urls") or []) if str(x).strip()]
    if starts:
        return starts[0]
    if target.domains:
        return f"https://{target.domains[0]}/"
    if target.ips:
        return f"http://{target.ips[0]}/"
    raise AuthzConfigError("无法推断会话校验 URL，请为每个身份填写 session_check_url")


def normalize_identity(raw: dict, index: int, target: TargetDef, slug: str) -> tuple[Identity, dict]:
    """把表单/ YAML 中的身份规范化为内存对象 + 可落盘元数据（不含 secret）。"""
    if not isinstance(raw, dict):
        raise AuthzConfigError(f"第 {index + 1} 个身份必须是对象")
    name = str(raw.get("name") or f"identity-{index + 1}").strip()
    if not name:
        raise AuthzConfigError(f"第 {index + 1} 个身份名称为空")
    role = str(raw.get("role") or ("high" if index == 0 else "low")).strip().lower()
    if role not in ROLES:
        raise AuthzConfigError(f"身份 {name} 角色非法：{role}（只允许 high/low/user）")
    cookie = str(raw.get("cookie") or "").strip()
    headers = parse_headers(raw.get("headers") or {})
    if not cookie and not headers:
        raise AuthzConfigError(f"身份 {name} 必须配置 cookie 或自定义 header")
    starts = raw.get("start_urls") or []
    if isinstance(starts, str):
        starts = [x for x in starts.splitlines() if x.strip()]
    starts = [_validate_url(x, target, f"身份 {name} 采集入口") for x in starts if str(x).strip()]
    check_raw = raw.get("session_check") if isinstance(raw.get("session_check"), dict) else {}
    check_url = str(raw.get("session_check_url") or check_raw.get("url") or "").strip()
    check_url = _validate_url(check_url or _default_check_url(raw, target), target,
                              f"身份 {name} 会话校验 URL")
    expect = check_raw.get("expect_status") or raw.get("expect_status") or [200]
    if isinstance(expect, int):
        expect = [expect]
    try:
        expect_status = [int(x) for x in expect]
    except (TypeError, ValueError):
        raise AuthzConfigError(f"身份 {name} expect_status 非法")
    marker = str(check_raw.get("expect_body_contains") or
                 raw.get("expect_body_contains") or "").strip()
    cid = f"{slug}-{index + 1}-{abs(hash(name)) % 10 ** 6:06d}"
    ident = Identity(name=name, role=role, credential_id=cid, start_urls=starts,
                     session_check_url=check_url, expect_status=expect_status,
                     expect_body_contains=marker, cookie=cookie, headers=headers)
    meta = {"name": name, "role": role, "credential_id": cid, "start_urls": starts,
            "session_check": {"url": check_url, "expect_status": expect_status,
                              "expect_body_contains": marker}}
    return ident, meta


def prepare_accounts(*, target_name: str, identities_raw: list, accounts_dir: Path,
                     vault_path: Path, key_path: Path, domains: Iterable[str],
                     ips: Iterable[str], vendor: str = "", authorization: str = "",
                     settings: Optional[dict] = None,
                     vertical_paths: Optional[list] = None,
                     vertical_base: str = "") -> tuple[Path, dict]:
    """校验 >=2 个身份 → 加密 secret 写入 vault → 写无 secret 的元数据 YAML。

    返回 (元数据路径, 元数据字典)。任何失败都不会把 secret 写进异常信息。
    """
    if not isinstance(identities_raw, list):
        raise AuthzConfigError("identities 必须是数组")
    if len(identities_raw) < 2:
        raise AuthzConfigError(
            f"至少需要 2 个身份（当前 {len(identities_raw)} 个）；单账号会拒绝执行")
    target = _scope_target(target_name, vendor, authorization, domains, ips)
    slug = slugify(target_name)
    identities: list[Identity] = []
    metas: list[dict] = []
    seen: set[str] = set()
    for i, raw in enumerate(identities_raw):
        ident, meta = normalize_identity(raw, i, target, slug)
        if ident.name in seen:
            raise AuthzConfigError(f"身份名称重复：{ident.name}")
        seen.add(ident.name)
        identities.append(ident)
        metas.append(meta)

    roles = {i.role for i in identities}
    vertical = [str(x).strip() for x in (vertical_paths or []) if str(x).strip()]
    if vertical and not {"high", "low"}.issubset(roles):
        raise AuthzConfigError("配置垂直越权路径时，至少需要一个 high 和一个 low 身份")
    base = _validate_url(vertical_base, target, "垂直越权基准 URL") if vertical_base else ""
    if vertical and not base:
        # 用 high 身份的采集入口/会话校验 URL 推断 origin
        highs = [i for i in identities if i.role == "high"]
        if highs and highs[0].start_urls:
            base = highs[0].start_urls[0]
        elif highs:
            base = highs[0].session_check_url
        if not base:
            raise AuthzConfigError("配置了垂直越权路径时必须有基准 URL（high 身份采集入口）")
        base = _validate_url(base, target, "垂直越权基准 URL")

    secrets = {i.credential_id: {"cookie": i.cookie, "headers": dict(i.headers)}
               for i in identities}
    vault = SecretVault(Path(vault_path), Path(key_path))
    vault.put_many(secrets)

    meta = {
        "schema": ACCOUNTS_SCHEMA,
        "target": target_name,
        "slug": slug,
        "vendor": vendor or target_name,
        "identities": metas,
        "settings": dict(settings or {}),
        "vertical": {"paths": vertical, "base_url": base},
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    accounts_dir = Path(accounts_dir)
    accounts_dir.mkdir(parents=True, exist_ok=True)
    path = accounts_dir / f"{slug}.yaml"
    path.write_text(yaml.safe_dump(meta, allow_unicode=True, sort_keys=False),
                    encoding="utf-8")
    try:
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)
    except OSError:
        pass
    return path, meta


def prepare_accounts_from_file(*, target: TargetDef, plain_path: str | Path,
                               accounts_dir: Path, vault_path: Path, key_path: Path,
                               settings: Optional[dict] = None) -> tuple[Path, dict]:
    """从明文武器 YAML 导入账号；只把 secret 写入加密 vault，元数据落盘无 secret。"""
    p = Path(plain_path)
    if not p.exists():
        raise AuthzConfigError(f"账号文件不存在：{p}")
    raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise AuthzConfigError("账号文件顶层必须是字典")
    ids = raw.get("identities")
    if not isinstance(ids, list):
        raise AuthzConfigError("账号文件缺少 identities 数组")
    v = raw.get("vertical") or {}
    vertical_paths = v.get("paths") if isinstance(v, dict) else []
    base = str(v.get("base_url") or "") if isinstance(v, dict) else ""
    settings_in = dict(raw.get("settings") or {})
    settings_in.update(settings or {})
    return prepare_accounts(
        target_name=target.name, identities_raw=ids, accounts_dir=accounts_dir,
        vault_path=vault_path, key_path=key_path, domains=target.domains,
        ips=target.ips, vendor=target.vendor, authorization=target.authorization,
        settings=settings_in, vertical_paths=list(vertical_paths or []),
        vertical_base=base)


def _resolve_accounts_path(target: TargetDef, recon, accounts_dir: Path) -> Optional[Path]:
    if getattr(target, "authz_explicit", False):
        raw = str(getattr(target, "authz_accounts", "") or "").strip()
        return Path(recon.abs_path(raw)) if raw else None
    slug = slugify(target.name)
    p = accounts_dir / f"{slug}.yaml"
    if p.exists():
        return p
    if accounts_dir.is_dir():
        for cand in sorted(accounts_dir.glob("*.yaml")):
            try:
                data = yaml.safe_load(cand.read_text(encoding="utf-8")) or {}
            except (OSError, yaml.YAMLError):
                continue
            if isinstance(data, dict) and str(data.get("target") or "") == target.name:
                return cand
    return None


@dataclass
class AuthzPlan:
    target_name: str
    accounts_path: Path
    identities: list
    owner: Identity
    attacker: Identity
    high: Optional[Identity]
    low: Optional[Identity]
    start_urls: list
    vertical_paths: list
    vertical_base: str
    default_check_url: str
    settings: dict

    def public(self) -> dict:
        return {
            "accounts_path": str(self.accounts_path),
            "identities": [i.public() for i in self.identities],
            "owner": self.owner.name,
            "attacker": self.attacker.name,
            "high": self.high.name if self.high else "",
            "low": self.low.name if self.low else "",
            "settings": dict(self.settings),
        }


def load_plan(target: TargetDef, recon, *, required: bool = False,
              overrides: Optional[dict] = None) -> Optional[AuthzPlan]:
    """读取元数据 + 解密 vault，返回可执行计划；不足 2 身份直接拒绝。"""
    authz_cfg = recon.authz
    accounts_dir = recon.abs_path(authz_cfg.accounts_dir)
    vault_path = recon.abs_path(authz_cfg.vault_path)
    key_path = recon.abs_path(authz_cfg.key_path)
    path = _resolve_accounts_path(target, recon, accounts_dir)
    if path is None:
        if required:
            raise AuthzConfigError(
                "未配置越权检测账号（需要 >=2 个身份，先通过面板或 authz --accounts 导入）")
        return None
    if not path.exists():
        raise AuthzConfigError(f"越权账号元数据不存在：{path}")
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        raise AuthzConfigError(f"账号元数据读取失败：{type(e).__name__}") from None
    if not isinstance(raw, dict):
        raise AuthzConfigError("账号元数据顶层必须是字典")
    metas = raw.get("identities")
    if not isinstance(metas, list) or len(metas) < 2:
        raise AuthzConfigError(
            f"账号元数据至少需要 2 个身份（当前 {len(metas) if isinstance(metas, list) else 0} 个）")
    vault = SecretVault(vault_path, key_path)
    identities: list[Identity] = []
    seen: set[str] = set()
    for i, m in enumerate(metas):
        if not isinstance(m, dict):
            raise AuthzConfigError(f"第 {i + 1} 个身份元数据非法")
        name = str(m.get("name") or f"identity-{i + 1}").strip()
        if not name or name in seen:
            raise AuthzConfigError(f"身份名称缺失或重复：{name}")
        seen.add(name)
        try:
            secret = vault.get(str(m.get("credential_id") or ""))
        except AuthzCredentialError as e:
            raise AuthzConfigError(f"身份 {name} 凭据读取失败：{e}") from None
        check = m.get("session_check") or {}
        expect = check.get("expect_status") or [200]
        if isinstance(expect, int):
            expect = [expect]
        ident = Identity(
            name=name,
            role=str(m.get("role") or "user").lower(),
            credential_id=str(m.get("credential_id") or ""),
            start_urls=[str(x) for x in (m.get("start_urls") or [])],
            session_check_url=str(check.get("url") or ""),
            expect_status=[int(x) for x in expect],
            expect_body_contains=str(check.get("expect_body_contains") or ""),
            cookie=str(secret.get("cookie") or ""),
            headers=dict(secret.get("headers") or {}),
        )
        if ident.role not in ROLES:
            raise AuthzConfigError(f"身份 {name} 角色非法")
        if not ident.has_secret:
            raise AuthzConfigError(f"身份 {name} 没有可用凭据")
        identities.append(ident)

    settings = {
        "max_requests": int(recon.authz.max_requests),
        "similarity_threshold": float(recon.authz.similarity_threshold),
        "public_similarity": float(recon.authz.public_similarity),
        "max_candidates": int(recon.authz.max_candidates),
        "max_vertical_paths": int(recon.authz.max_vertical_paths),
        "max_collect_pages": int(recon.authz.max_collect_pages),
        "response_truncate": int(recon.authz.response_truncate),
    }
    def _coerce(target: dict, patch: dict) -> None:
        for k, v in (patch or {}).items():
            if k not in target or v in (None, ""):
                continue
            try:
                target[k] = float(v) if k in ("similarity_threshold", "public_similarity") \
                    else int(v)
            except (TypeError, ValueError):
                raise AuthzConfigError(f"authz 设置 {k} 非法：{v!r}") from None

    _coerce(settings, raw.get("settings") or {})
    _coerce(settings, overrides or {})
    if not (1 <= settings["max_requests"] <= 1000):
        raise AuthzConfigError("authz.max_requests 必须在 1~1000")
    if not (0.5 <= settings["similarity_threshold"] <= 1.0):
        raise AuthzConfigError("authz.similarity_threshold 必须在 0.5~1.0")
    if not (0.5 <= settings["public_similarity"] <= 1.0):
        raise AuthzConfigError("authz.public_similarity 必须在 0.5~1.0")
    if not (1 <= settings["max_candidates"] <= 500):
        raise AuthzConfigError("authz.max_candidates 必须在 1~500")

    highs = [i for i in identities if i.role == "high"]
    lows = [i for i in identities if i.role == "low"]
    owner = highs[0] if highs else identities[0]
    attacker = lows[0] if lows else identities[1]
    if owner.name == attacker.name:
        raise AuthzConfigError("越权检测需要两个不同身份")
    vertical = raw.get("vertical") or {}
    vpaths = [str(x) for x in (vertical.get("paths") or [])] if isinstance(vertical, dict) else []
    vbase = str(vertical.get("base_url") or "") if isinstance(vertical, dict) else ""
    if vpaths and (not highs or not lows):
        raise AuthzConfigError("垂直越权路径已配置，但身份缺少 high/low 角色")
    start_urls = list(owner.start_urls)
    base = vbase or (start_urls[0] if start_urls else "")
    if base:
        base = _validate_url(base, target, "越权检测基准 URL")
    else:
        base = _default_check_url({}, target)
    return AuthzPlan(
        target_name=target.name, accounts_path=path, identities=identities,
        owner=owner, attacker=attacker,
        high=highs[0] if highs else None, low=lows[0] if lows else None,
        start_urls=start_urls, vertical_paths=vpaths[:settings["max_vertical_paths"]],
        vertical_base=base, default_check_url=base, settings=settings)


def _secret_values(identities: Iterable[Identity]) -> list[str]:
    vals: set[str] = set()
    for i in identities:
        if i.cookie.strip():
            vals.add(i.cookie.strip())
            vals.update(v for v in i.cookie_dict.values() if v)
        for v in i.headers.values():
            if v:
                vals.add(str(v))
    return sorted((v for v in vals if len(v) >= 3), key=len, reverse=True)


def _redact_json_obj(data):
    if isinstance(data, dict):
        for k in list(data.keys()):
            if JSON_SECRET_KEY_RE.search(str(k)) and not isinstance(data[k], (dict, list)):
                data[k] = "[REDACTED]"
            else:
                _redact_json_obj(data[k])
    elif isinstance(data, list):
        for item in data:
            _redact_json_obj(item)
    return data


def redact_text(text: str, identities: Iterable[Identity] = (), max_chars: int = 400) -> str:
    """脱敏 + 归一化 + 截断；先替换已知 secret，再按 JSON 键/通用 token 规则。"""
    s = str(text or "")
    for v in _secret_values(identities):
        s = s.replace(v, "[REDACTED]")
    # JSON 响应按“敏感键”整值替换，避免 admin_token / email 等值残留
    try:
        data = json.loads(s)
    except (json.JSONDecodeError, TypeError, ValueError):
        data = None
    if isinstance(data, (dict, list)):
        data = _redact_json_obj(data)
        s = json.dumps(data, ensure_ascii=False)
    else:
        s = JSON_SECRET_VALUE_RE.sub(r'\1"[REDACTED]"', s)
    for rx, repl in SECRET_PATTERNS:
        s = rx.sub(repl, s)
    s = re.sub(r"\s+", " ", s).strip()
    if max_chars > 0 and len(s) > max_chars:
        s = s[:max_chars] + "…"
    return s


def redact_url(url: str) -> str:
    try:
        u = urlsplit(str(url or ""))
    except ValueError:
        return "[invalid-url]"
    q = []
    for k, v in parse_qsl(u.query, keep_blank_values=True):
        q.append((k, "[REDACTED]" if SENSITIVE_QUERY.search(k) else v))
    return urlunsplit((u.scheme, u.netloc, u.path, "&".join(f"{k}={v}" for k, v in q), ""))


def safe_error(e: BaseException, identities: Iterable[Identity] = ()) -> str:
    return f"{type(e).__name__}: {redact_text(str(e), identities, 300)}"
