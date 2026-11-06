# -*- coding: utf-8 -*-
"""证据包：补天标题规范、价值评级、证据截断、低分不生成。"""
from modules.recon.evidence import build_bundle, generate_bundles
from modules.recon.schema import Finding
from modules.recon.value import ValueAssessment, ValueModel


def _finding(**kw) -> Finding:
    base = dict(
        template_id="CVE-2023-1234", name="致远OA 任意文件上传",
        severity="critical", host="a.example.com",
        matched_at="http://a.example.com/seeyon/upload",
        curl_command="curl -X POST http://a.example.com/seeyon/upload",
    )
    base.update(kw)
    return Finding(**base)


def _assessment(score=85, grade="S") -> ValueAssessment:
    return ValueAssessment(score=score, grade=grade, advice="优先提交",
                           reasons=["危害等级 critical：55 分"],
                           reward_hint="约 800–3000 元（粗估）",
                           vuln_class="文件上传", program="public")


def test_bundle_contains_submission_sections(tmp_path):
    p = build_bundle(finding=_finding(product="致远OA"), assessment=_assessment(),
                     target_name="demo", vendor="某某科技",
                     authorization="补天公益SRC",
                     out_dir=tmp_path, product_instances=120)
    text = p.read_text(encoding="utf-8")
    assert "某某科技致远OA存在致远OA 任意文件上传漏洞" in text
    assert "curl -X POST" in text
    assert "优先提交" in text and "S" in text
    assert "提交前检查清单" in text and "- [ ]" in text
    assert "只读取证" in text
    assert "已达标" in text              # 120 ≥ 100


def test_bundle_truncates_and_masks(tmp_path):
    f = _finding(evidence={
        "request": "GET / HTTP/1.1 Authorization: Bearer abcdefg123456",
        "response": "x" * 5000,
    })
    p = build_bundle(finding=f, assessment=_assessment(), target_name="demo",
                     vendor="v", authorization="auth", out_dir=tmp_path)
    text = p.read_text(encoding="utf-8")
    assert "Bearer ***" in text
    assert "x" * 401 not in text        # 响应被截断（400 + 省略号）


def test_low_score_not_generated(tmp_path):
    low = _finding(template_id="low-1", name="Some Info Leak", severity="info")
    low.value = {"score": 20, "grade": "D"}
    high = _finding(template_id="high-1", name="RCE", severity="critical")
    high.value = {"score": 88, "grade": "S"}
    msgs = []
    paths = generate_bundles([low, high], target_name="demo", vendor="v",
                             authorization="a", out_dir=tmp_path,
                             model=ValueModel(min_score_for_evidence=40),
                             console=msgs.append)
    assert len(paths) == 1
    assert any("skip" in m for m in msgs)
    assert "high_RCE" in paths[0].name or "RCE" in paths[0].name


def test_bundle_without_curl_still_renders(tmp_path):
    f = _finding(template_id="t2", name="未授权访问", curl_command="",
                 evidence={"matcher": "status", "extracted": ["admin"]})
    p = build_bundle(finding=f, assessment=_assessment(65, "A"),
                     target_name="demo", vendor="v", authorization="a",
                     out_dir=tmp_path)
    assert "（模板未提供 curl 命令" in p.read_text(encoding="utf-8")
