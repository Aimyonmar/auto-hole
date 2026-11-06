# -*- coding: utf-8 -*-
"""价值评分：排序是否合理、惩罚是否生效、等级/建议是否自洽。"""
from modules.recon.schema import Finding
from modules.recon.value import (ValueModel, classify_vuln, rank_findings,
                                 scale_bonus)


def _f(tid="CVE-2024-0001", name="", severity="high", **kw) -> Finding:
    return Finding(template_id=tid, name=name, severity=severity,
                   host="a.example.com", matched_at="http://a.example.com/x",
                   curl_command="curl http://a.example.com/x", **kw)


def test_rce_scores_higher_than_info():
    m = ValueModel()
    rce = m.assess(_f(name="Apache RCE (Remote Code Execution)", severity="critical"))
    info = m.assess(_f(name="Server Version Exposure", severity="info"))
    assert rce.score > info.score
    assert rce.vuln_class == "远程代码执行"
    assert info.grade == "D" and info.advice == "不建议提交"


def test_classify_vuln_priority():
    assert classify_vuln(_f(name="SQL Injection"))[0] == "SQL注入"
    assert classify_vuln(_f(name="Arbitrary File Upload"))[0] == "文件上传"
    assert classify_vuln(_f(name="Unauthenticated API"))[0] == "未授权访问/越权"
    assert classify_vuln(_f(name="Unknown thing"))[0] == "其他"


def test_generic_program_bonus():
    f = _f(name="SQL Injection", severity="high")
    pub = ValueModel().assess(f, program="public")
    gen = ValueModel(generic_bonus=10).assess(f, program="generic")
    assert gen.score >= pub.score + 9.9
    assert gen.program == "generic"


def test_scale_bonus_thresholds():
    assert scale_bonus(5) == (0.0, "")
    assert scale_bonus(50)[0] == 4.0
    b100, note = scale_bonus(100)
    assert b100 == 16.0 and "≥100" in note
    assert scale_bonus(100000)[0] <= 20.0


def test_duplicate_and_old_cve_penalties():
    f = _f(tid="CVE-2019-1234", name="SQL Injection", severity="high")
    base = ValueModel().assess(f, program="generic", product_instances=0)
    dup = ValueModel().assess(f, program="generic", product_instances=0,
                              duplicate_hits=1)
    rep = ValueModel().assess(f, program="generic", product_instances=0,
                              reported=True)
    assert dup.score < base.score and rep.score < dup.score
    assert any("老 CVE" in r for r in base.reasons)


def test_evidence_missing_penalty():
    f = _f(name="Weird bug", severity="medium")
    f.curl_command = ""
    f.evidence = {}
    a = ValueModel().assess(f)
    assert any("curl" in r for r in a.reasons)
    assert a.score < ValueModel().assess(_f(name="Weird bug", severity="medium")).score


def test_grade_and_advice_boundaries():
    m = ValueModel(min_score_to_submit=45, min_score_for_evidence=40)
    # 构造：critical 55 + RCE 20 + generic 10 + 120 实例 16 → 100 封顶
    s = m.assess(_f(name="RCE", severity="critical"), program="generic",
                 product_instances=120)
    assert s.grade == "S" and s.advice == "优先提交"
    # medium 25 + xss 3 → 28 → D
    d = m.assess(_f(name="XSS", severity="medium"))
    assert d.grade == "D"


def test_rank_findings_orders_by_value():
    a = _f(tid="t-low", name="XSS", severity="low")
    a.value = {"score": 10, "grade": "D"}
    b = _f(tid="t-high", name="RCE", severity="critical")
    b.value = {"score": 90, "grade": "S"}
    c = _f(tid="t-mid", name="SQL Injection", severity="high")
    c.value = {"score": 60, "grade": "A"}
    assert [x.template_id for x in rank_findings([a, b, c])] == ["t-high", "t-mid", "t-low"]


def test_reward_hint_present():
    for grade in ("S", "A", "B", "C", "D"):
        assert ValueModel._reward_hint(grade)
