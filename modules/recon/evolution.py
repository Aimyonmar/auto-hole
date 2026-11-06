# -*- coding: utf-8 -*-
"""进化回路：复盘指标 → 候选规则/模板 → 本地靶场验证 → 人工审核 → 版本化入库。

边界（刻意做成这样）：
- 自动只产出“候选”，永不自动改写生产规则库；
- 候选必须先在本地靶场通过正/负样本回归，才允许进入人工审核；
- 人工 `approve` 才会写入生产规则库，并生成版本快照，可 `rollback`；
- 所有验证只访问传入的回环地址，不访问外部资产。
"""
from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Iterable, Optional

import requests
import yaml

from core.config import AppConfig
from core.subdomain import isolated_env

from .config import ReconConfig
from .fingerprint import (FingerprintEngine, MatchContext, Rule,
                          rule_from_dict)
from .schema import Asset, Finding, extract_title
from .state import RunState

STOP_TOKENS = {
    "http", "server", "content", "date", "length", "type", "connection",
    "charset", "gzip", "close", "text", "html", "cache", "control", "pragma",
    "expires", "vary", "accept", "encoding", "language", "etag", "keep-alive",
}
MARKER_RE = re.compile(r"[A-Za-z0-9_./:\-]{8,60}")


# ------------------------------------------------------------------
# 指标
# ------------------------------------------------------------------
def build_metrics(summary: dict, findings: Iterable[Finding],
                  feedback: Iterable[dict]) -> dict:
    findings = list(findings)
    fb = list(feedback)
    fp_keys = {str(x.get("key", "")) for x in fb if x.get("label") == "false_positive"}
    fp_count = sum(1 for f in findings if f.key in fp_keys)
    hits = len(findings)
    probe_requests = int((summary.get("probe") or {}).get("requests", 0))
    scan_requests = int((summary.get("scan") or {}).get("requests_estimated", 0))
    requests = probe_requests + scan_requests
    assets = int((summary.get("assets") or {}).get("alive", 0))
    timing = dict(summary.get("timing") or {})
    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "target": summary.get("target", ""),
        "hits": hits,
        "false_positives": fp_count,
        "precision": round((hits - fp_count) / hits, 3) if hits else None,
        "covered_assets": assets,
        "http_requests_probe": probe_requests,
        "http_requests_scan_estimated": scan_requests,
        "http_requests_total_estimated": requests,
        "cost_per_hit_requests": round(requests / hits, 2) if hits else None,
        "stage_timing_s": timing,
        "urls_discovered": int((summary.get("discovery") or {}).get("urls", 0)),
        "value_grades": (summary.get("findings") or {}).get("by_grade", {}),
        "feedback_entries": len(fb),
    }


def write_metrics(target_dir: Path, metrics: dict) -> Path:
    p = target_dir / "metrics.json"
    p.write_text(json.dumps(metrics, ensure_ascii=False, indent=2), encoding="utf-8")
    hist = target_dir / "metrics-history.jsonl"
    with hist.open("a", encoding="utf-8") as f:
        f.write(json.dumps(metrics, ensure_ascii=False) + "\n")
    return p


# ------------------------------------------------------------------
# 误报反馈
# ------------------------------------------------------------------
def feedback_path(target_dir: Path) -> Path:
    return target_dir / "feedback.jsonl"


def load_feedback(target_dir: Path) -> list[dict]:
    p = feedback_path(target_dir)
    if not p.exists():
        return []
    out = []
    for line in p.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(item, dict) and item.get("key"):
            out.append(item)
    return out


def add_feedback(target_dir: Path, *, finding_key: str, template_id: str, host: str,
                 label: str = "false_positive", reason: str = "",
                 product: str = "", marker_type: str = "", marker_name: str = "",
                 marker_value: str = "") -> Path:
    rec = {
        "key": finding_key, "template_id": template_id, "host": host,
        "label": label, "reason": reason, "product": product,
        "marker_type": marker_type, "marker_name": marker_name,
        "marker_value": marker_value,
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
    }
    p = feedback_path(target_dir)
    p.parent.mkdir(parents=True, exist_ok=True)
    with p.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    return p


# ------------------------------------------------------------------
# 候选生成
# ------------------------------------------------------------------
@dataclass
class Candidate:
    id: str
    kind: str                     # fingerprint | template
    file: str
    product: str = ""
    template_id: str = ""
    name: str = ""
    severity: str = ""
    source: str = ""
    reasons: list = field(default_factory=list)
    status: str = "pending_validation"
    validation: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


def _request_line(finding: Finding) -> tuple[str, str]:
    """从证据请求行提取 (method, path)。"""
    req = (finding.evidence or {}).get("request") or ""
    first = req.splitlines()[0].strip() if req else ""
    m = re.match(r"(GET|POST|PUT|DELETE|PATCH|HEAD)\s+(\S+)", first)
    if m:
        return m.group(1), m.group(2)
    u = finding.matched_at
    if u:
        from urllib.parse import urlsplit
        parts = urlsplit(u)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        return "GET", path
    return "GET", "/"


def _response_body(finding: Finding) -> str:
    resp = (finding.evidence or {}).get("response") or ""
    if "\r\n\r\n" in resp:
        return resp.split("\r\n\r\n", 1)[1]
    if "\n\n" in resp:
        return resp.split("\n\n", 1)[1]
    return resp


def _marker_from_response(finding: Finding) -> str:
    frozen = (finding.evidence or {}).get("extracted") or []
    for x in frozen:
        s = str(x).strip()
        if len(s) >= 4:
            return s[:60]
    body = _response_body(finding)
    best = ""
    for tok in MARKER_RE.findall(body or ""):
        low = tok.lower()
        if low in STOP_TOKENS or sum(c.isalpha() for c in tok) < 3:
            continue
        if re.fullmatch(r"[0-9.:\-]+", tok):
            continue
        if len(tok) > len(best):
            best = tok
    return best[:60]


def template_candidate(finding: Finding) -> Optional[dict]:
    """把一条已确认命中转成可复现的 nuclei 模板（候选）。"""
    marker = _marker_from_response(finding)
    if not marker:
        return None
    method, path = _request_line(finding)
    if not path.startswith("/"):
        path = "/" + path
    cid = "ah-cand-" + hashlib.sha256(
        f"{finding.template_id}|{finding.matched_at}|{marker}".encode()).hexdigest()[:10]
    tpl = {
        "id": cid,
        "info": {
            "name": f"[candidate] {finding.name or finding.template_id}",
            "author": "auto-hole-evolve",
            "severity": finding.severity or "medium",
            "description": (f"由 {finding.template_id} 的复盘证据自动生成；"
                            f"主匹配器基于响应中的稳定片段，待人工审核"),
            "tags": ["candidate", "derived"] + [t for t in (finding.tags or [])][:4],
        },
        "http": [{
            "method": method,
            "path": ["{{BaseURL}}" + path],
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [int((finding.evidence or {}).get("status") or 200)]},
                {"type": "word", "part": "body", "words": [marker]},
            ],
        }],
    }
    return {
        "candidate": Candidate(
            id=cid, kind="template", file=f"templates/{cid}.yaml",
            template_id=finding.template_id, name=finding.name,
            severity=finding.severity, source=finding.host,
            reasons=[f"原模板 {finding.template_id} 命中 {finding.matched_at}",
                     f"响应稳定片段：{marker}"],
        ).to_dict(),
        "yaml": yaml.safe_dump(tpl, allow_unicode=True, sort_keys=False),
    }


def fingerprint_candidate(entry: dict, engine: FingerprintEngine) -> Optional[dict]:
    """从人工误报反馈生成“加 negative 条件”的指纹规则候选。"""
    product = str(entry.get("product") or "")
    marker_type = str(entry.get("marker_type") or "")
    marker_value = str(entry.get("marker_value") or "")
    if not product or not marker_type or not marker_value:
        return None
    base: Optional[Rule] = next((r for r in engine.rules if r.product == product), None)
    if base is None:
        return None      # 没有既有规则时不臆造新规则（避免生成弱特征）
    raw = {
        "id": "ah-fp-" + hashlib.sha256(f"{base.id}|{marker_value}".encode()).hexdigest()[:8],
        "product": base.product,
        "confidence": base.confidence,
        "logic": base.logic,
        "min_matched": base.min_matched,
        "tags": list(dict.fromkeys(list(base.tags) + ["candidate", "fp-fix"])),
        "template_dirs": list(base.template_dirs),
        "match": [
            {k: v for k, v in {
                "type": c.type, "name": c.name, "contains": c.contains,
                "regex": c.regex, "value": c.value, "sha256": c.sha256,
            }.items() if v}
            for c in base.conditions
        ],
        "negative": [
            {k: v for k, v in {
                "type": c.type, "name": c.name, "contains": c.contains,
                "regex": c.regex, "value": c.value, "sha256": c.sha256,
            }.items() if v}
            for c in base.negatives
        ],
    }
    neg = {"type": marker_type, "contains": marker_value}
    if marker_type == "header":
        neg["name"] = str(entry.get("marker_name") or "Server")
    raw["negative"] = list(raw.get("negative") or []) + [neg]

    cid = raw["id"]
    return {
        "candidate": Candidate(
            id=cid, kind="fingerprint", file=f"fingerprints/{cid}.yaml",
            product=product, source=entry.get("host", ""),
            reasons=[f"人工标记误报，附加排除条件 {marker_type}:{marker_value}"],
        ).to_dict(),
        "yaml": yaml.safe_dump(raw, allow_unicode=True, sort_keys=False),
    }


# ------------------------------------------------------------------
# 本地靶场验证
# ------------------------------------------------------------------
def _fetch_local(url: str) -> Optional[MatchContext]:
    try:
        r = requests.get(url, timeout=8, verify=False, allow_redirects=True)
        body = r.text[:262144]
        return MatchContext(url=url, status=r.status_code, title=extract_title(body),
                            headers={k.lower(): v for k, v in r.headers.items()},
                            body=body)
    except requests.RequestException:
        return None


def validate_fingerprints(cand_dir: Path, candidates: list[Candidate],
                          positive_url: str, negative_url: str) -> list[Candidate]:
    pos = _fetch_local(positive_url)
    neg = _fetch_local(negative_url)
    if pos is None or neg is None:
        for c in candidates:
            c.status = "blocked"
            c.validation = {"reason": "无法访问本地正/负样本地址"}
        return candidates
    for c in candidates:
        try:
            rule_raw = yaml.safe_load((cand_dir / c.file).read_text(encoding="utf-8"))
            eng = FingerprintEngine([rule_from_dict(rule_raw)], min_confidence=0.0)
        except Exception as e:
            c.status, c.validation = "failed", {"reason": f"规则无法加载: {e}"}
            continue
        positives = [m.product for m in eng.match(pos)]
        negatives = [m.product for m in eng.match(neg)]
        ok = bool(positives) and not negatives
        c.status = "passed" if ok else "failed"
        c.validation = {
            "positive_url": positive_url, "positive_products": positives,
            "negative_url": negative_url, "negative_products": negatives,
        }
    return candidates


def validate_templates(app: AppConfig, cand_dir: Path, candidates: list[Candidate],
                       positive_url: str, negative_url: str,
                       console: Callable[[str], None] = print) -> list[Candidate]:
    nuclei = app.tool_path("nuclei")
    if not nuclei.exists():
        for c in candidates:
            c.status, c.validation = "blocked", {"reason": f"缺少 {nuclei}"}
        return candidates
    tpl_dir = cand_dir / "templates"
    if not tpl_dir.exists() or not any(tpl_dir.glob("*.yaml")):
        return candidates

    work = cand_dir / "_validate"
    work.mkdir(parents=True, exist_ok=True)

    def run_one(url: str, tag: str) -> Optional[dict]:
        out = work / f"{tag}.jsonl"
        cmd = [str(nuclei), "-t", str(tpl_dir), "-u", url, "-jsonl", "-o", str(out),
               "-silent", "-disable-update-check", "-no-interactsh",
               "-rate-limit", "5", "-timeout", "8", "-retries", "0"]
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=180,
                           encoding="utf-8", errors="replace", env=isolated_env())
        except subprocess.TimeoutExpired:
            return None
        if not out.exists():
            return {}
        hits = {}
        for line in out.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                j = json.loads(line)
            except json.JSONDecodeError:
                continue
            tid = j.get("template-id") or ""
            if tid:
                hits[tid] = j.get("matched-at") or ""
        return hits

    pos = run_one(positive_url, "positive")
    neg = run_one(negative_url, "negative")
    if pos is None or neg is None:
        for c in candidates:
            c.status, c.validation = "blocked", {"reason": "nuclei 验证超时/异常"}
        return candidates

    for c in candidates:
        cid = c.id
        hit_pos = pos.get(cid)
        hit_neg = neg.get(cid)
        ok = bool(hit_pos) and not hit_neg
        c.status = "passed" if ok else "failed"
        c.validation = {"positive_url": positive_url, "positive_hit": hit_pos,
                        "negative_url": negative_url, "negative_hit": hit_neg}
        if not ok:
            console(f"    [validate] {cid} 未通过（pos={bool(hit_pos)} neg={bool(hit_neg)}）")
    return candidates


# ------------------------------------------------------------------
# 候选落盘与审核
# ------------------------------------------------------------------
def propose(app: AppConfig, recon: ReconConfig, target_dir: Path,
            findings: list[Finding], assets: list[Asset],
            *, positive_url: str, negative_url: str,
            console: Callable[[str], None] = print) -> dict:
    engine = FingerprintEngine.from_yaml(recon.fingerprint_library())
    feedback = load_feedback(target_dir)
    fp_keys = {str(x.get("key")) for x in feedback if x.get("label") == "false_positive"}

    ts = time.strftime("%Y%m%d_%H%M%S")
    out_dir = recon.state_dir() / "evolution" / "candidates" / ts
    out_dir.mkdir(parents=True, exist_ok=True)

    tpl_candidates: list[Candidate] = []
    for f in findings:
        if f.key in fp_keys:
            continue
        if float(f.value.get("score", 0)) < recon.value.min_score_to_submit:
            continue
        c = template_candidate(f)
        if not c:
            continue
        cand = Candidate(**c["candidate"])
        tpl_candidates.append(cand)
        path = out_dir / c["candidate"]["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(c["yaml"], encoding="utf-8")

    tpl_candidates = validate_templates(
        app, out_dir, tpl_candidates, positive_url, negative_url, console)

    fps: list[Candidate] = []
    for entry in feedback:
        if entry.get("label") != "false_positive":
            continue
        c = fingerprint_candidate(entry, engine)
        if not c:
            continue
        cand = Candidate(**c["candidate"])
        fps.append(cand)
        path = out_dir / c["candidate"]["file"]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(c["yaml"], encoding="utf-8")
    fps = validate_fingerprints(out_dir, fps, positive_url, negative_url)
    candidates = tpl_candidates + fps

    passed = [c for c in candidates if c.status == "passed"]
    pending = [c for c in candidates if c.status != "passed"]
    for c in candidates:
        (out_dir / f"{c.id}.validation.json").write_text(
            json.dumps(c.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")

    _write_review(out_dir, candidates, positive_url, negative_url)
    return {
        "dir": str(out_dir),
        "total": len(candidates),
        "passed": len(passed),
        "blocked_or_failed": len(pending),
        "candidates": [c.to_dict() for c in candidates],
    }


def _write_review(out_dir: Path, candidates: list[Candidate],
                  pos: str, neg: str) -> None:
    lines = ["# 候选规则/模板待审清单", "",
             f"- 生成时间：{time.strftime('%Y-%m-%d %H:%M:%S')}",
             f"- 正样本：{pos}", f"- 负样本：{neg}",
             "- 规则：**只有 passed 的候选才允许 approve**；approve 前请人工阅读验证结果", ""]
    for c in candidates:
        lines += [f"## {c.id}（{c.kind}）", "",
                  f"- 状态：**{c.status}**",
                  f"- 来源：{c.source or '-'}",
                  f"- 产品：{c.product or '-'}；原模板：{c.template_id or '-'}",
                  f"- 生成依据：{'；'.join(c.reasons) or '-'}",
                  f"- 验证：`{json.dumps(c.validation, ensure_ascii=False)}`", ""]
    (out_dir / "REVIEW.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


# ------------------------------------------------------------------
# 版本化入库 / 回滚
# ------------------------------------------------------------------
def versions_dir(recon: ReconConfig) -> Path:
    return recon.state_dir() / "evolution" / "versions"


def _index(recon: ReconConfig) -> dict:
    p = versions_dir(recon) / "index.json"
    if p.exists():
        try:
            return json.loads(p.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return {"versions": []}


def list_versions(recon: ReconConfig) -> dict:
    return _index(recon)


def _snapshot(recon: ReconConfig, index: dict) -> tuple[int, Path]:
    vdir = versions_dir(recon)
    vdir.mkdir(parents=True, exist_ok=True)
    version = len(index.get("versions", [])) + 1
    src = recon.fingerprint_library()
    dst = vdir / f"v{version}.yaml"
    dst.write_text(src.read_text(encoding="utf-8"), encoding="utf-8")
    return version, dst


def approve(recon: ReconConfig, candidate_dir: Path, candidate_id: str,
            *, note: str = "", metrics: Optional[dict] = None,
            console: Callable[[str], None] = print) -> dict:
    side = candidate_dir / f"{candidate_id}.validation.json"
    if not side.exists():
        raise ValueError(f"找不到候选 {candidate_id} 的验证结果")
    data = json.loads(side.read_text(encoding="utf-8"))
    if data.get("status") != "passed":
        raise ValueError(f"候选 {candidate_id} 未通过靶场回归（{data.get('status')}），禁止入库")

    index = _index(recon)
    version, snap = _snapshot(recon, index)
    lib = recon.fingerprint_library()

    if data["kind"] == "fingerprint":
        raw = yaml.safe_load((candidate_dir / data["file"]).read_text(encoding="utf-8"))
        text = yaml.safe_dump([raw], allow_unicode=True, sort_keys=False)
        with lib.open("a", encoding="utf-8") as f:
            f.write("\n# ---- approved candidate (auto-hole evolve) ----\n")
            f.write(text)
    else:
        target = (recon.state_dir() / "evolution" / "approved_templates")
        target.mkdir(parents=True, exist_ok=True)
        (target / Path(data["file"]).name).write_text(
            (candidate_dir / data["file"]).read_text(encoding="utf-8"), encoding="utf-8")

    index.setdefault("versions", []).append({
        "version": version, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "action": "approve", "candidate": candidate_id, "kind": data["kind"],
        "product": data.get("product", ""), "note": note,
        "snapshot": snap.name, "metrics": metrics or {},
    })
    (versions_dir(recon) / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    console(f"[✓] 已入库（版本 v{version}，快照 {snap.name}）")
    return index


def rollback(recon: ReconConfig, version: int, *, note: str = "",
             console: Callable[[str], None] = print) -> dict:
    index = _index(recon)
    snap = versions_dir(recon) / f"v{int(version)}.yaml"
    if not snap.exists():
        raise ValueError(f"版本 v{version} 快照不存在")
    recon.fingerprint_library().write_text(snap.read_text(encoding="utf-8"), encoding="utf-8")
    new_version = len(index.get("versions", [])) + 1
    index.setdefault("versions", []).append({
        "version": new_version, "created_at": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "action": "rollback", "to_version": int(version), "note": note,
        "snapshot": snap.name,
    })
    (versions_dir(recon) / "index.json").write_text(
        json.dumps(index, ensure_ascii=False, indent=2), encoding="utf-8")
    console(f"[✓] 已回滚到 v{version}（记录为 v{new_version}）")
    return index


def compute_key(template_id: str, host: str, matched_at: str) -> str:
    return f"{template_id}|{host}|{hashlib.sha256((matched_at or '').encode()).hexdigest()[:8]}"
