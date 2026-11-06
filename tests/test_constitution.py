# -*- coding: utf-8 -*-
"""宪法负向测试（计划验证标准第6条：非法目标必须被拦截）。"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.constitution import (ScopeViolation, TargetDef, check_host_in_scope,
                               load_target, assert_host_in_scope)
from core.config import (AppConfig, ConstitutionViolation, ScanConfig,
                         enforce_constitution)

PASS, FAIL = 0, 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [PASS] {desc}")
    else:
        FAIL += 1
        print(f"  [FAIL] {desc}")


print("== 宪法第1条：授权范围 ==")

# 1. 无授权依据的 target 文件 → 拒绝
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
    f.write("name: t1\nvendor: v\ndomains:\n  - a.com\n")
    t1 = f.name
try:
    load_target(t1)
    check("无授权依据目标被拒绝", False)
except ScopeViolation:
    check("无授权依据目标被拒绝", True)

# 2. 合法 target + 范围外 host → 拦截
with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8") as f:
    f.write("name: t2\nvendor: v\nauthorization: 补天公益SRC\ndomains:\n  - example.com\n")
    t2 = f.name
tgt = load_target(t2)
check("合法目标可加载", tgt.name == "t2")
check("子域在范围内", check_host_in_scope("sub.example.com", tgt))
check("主域在范围内", check_host_in_scope("example.com", tgt))
check("无关域名被拦截", not check_host_in_scope("evil.com", tgt))
check("仿冒域名被拦截", not check_host_in_scope("notexample.com", tgt))
try:
    assert_host_in_scope("evil.com", tgt)
    check("assert 拦截范围外域名", False)
except ScopeViolation:
    check("assert 拦截范围外域名", True)

# 3. IP 范围
tgt3 = TargetDef(name="t3", vendor="v", authorization="x", ips=["10.0.0.0/24", "192.168.1.5"])
check("CIDR 内 IP 放行", check_host_in_scope("10.0.0.77", tgt3))
check("CIDR 外 IP 拦截", not check_host_in_scope("10.0.1.1", tgt3))
check("单 IP 放行", check_host_in_scope("192.168.1.5", tgt3))

print("== 宪法第2/3条：配置硬校验 ==")
base = ScanConfig()

# 温和档：未填授权依据时不得超过 20 / 5000
c = ScanConfig(concurrency=50)
try:
    enforce_constitution(AppConfig(scan=c))
    check("并发>20 且无授权依据 被拒绝", False)
except ConstitutionViolation:
    check("并发>20 且无授权依据 被拒绝", True)

c = ScanConfig(daily_request_limit=99999)
try:
    enforce_constitution(AppConfig(scan=c))
    check("日请求>5000 且无授权依据 被拒绝", False)
except ConstitutionViolation:
    check("日请求>5000 且无授权依据 被拒绝", True)

# 按授权范围可配置：填了授权依据即可放宽（仍在绝对上限内）
c = ScanConfig(concurrency=50, daily_request_limit=20000,
               authorization_ref="https://www.butian.net/xxx 授权测试")
try:
    enforce_constitution(AppConfig(scan=c))
    check("填授权依据后可放宽到 50 并发", True)
except ConstitutionViolation:
    check("填授权依据后可放宽到 50 并发", False)

# 绝对上限：任何配置都不能突破（保证有界并发）
c = ScanConfig(concurrency=100, authorization_ref="fake")
try:
    enforce_constitution(AppConfig(scan=c))
    check("并发超过代码级绝对上限 64 被拒绝", False)
except ConstitutionViolation:
    check("并发超过代码级绝对上限 64 被拒绝", True)

c = ScanConfig(daily_request_limit=200000, authorization_ref="fake")
try:
    enforce_constitution(AppConfig(scan=c))
    check("日请求超过代码级绝对上限 被拒绝", False)
except ConstitutionViolation:
    check("日请求超过代码级绝对上限 被拒绝", True)

c = ScanConfig(concurrency=0)
try:
    enforce_constitution(AppConfig(scan=c))
    check("并发为 0（无界/非法）被拒绝", False)
except ConstitutionViolation:
    check("并发为 0（无界/非法）被拒绝", True)

c = ScanConfig(evidence_mode="destroy_everything")
try:
    enforce_constitution(AppConfig(scan=c))
    check("非法取证模式被拒绝", False)
except ConstitutionViolation:
    check("非法取证模式被拒绝", True)

c = ScanConfig(tags_exclude=[])
try:
    enforce_constitution(AppConfig(scan=c))
    check("tags 缺 dos/fuzz 被拒绝", False)
except ConstitutionViolation:
    check("tags 缺 dos/fuzz 被拒绝", True)

try:
    enforce_constitution(AppConfig(scan=ScanConfig()))
    check("标准配置通过", True)
except ConstitutionViolation:
    check("标准配置通过", False)

print(f"\n结果: {PASS} 通过 / {FAIL} 失败")
sys.exit(1 if FAIL else 0)
