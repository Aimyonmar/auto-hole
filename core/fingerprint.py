# -*- coding: utf-8 -*-
"""指纹聚合与产品名归一化（对齐补天收录产品名，通用1.0/公益SRC 提交用）。

数据源：
- httpx tech-detect 结果（资产库 assets.tech）
- Hunter component 结果（鹰图组件指纹）
- nuclei 模板 info.classification/标签（扫描命中后回填）

归一化：把各种写法（Seeyon/seeyon/致远OA）映射到补天收录标准产品名（致远OA）。
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

# 补天通用收录产品名 → 常见指纹写法（来源：补天通用2.0产品表 + 常见国产组件）
# 命中任意关键词即归一化为标准名
PRODUCT_ALIASES: dict[str, list[str]] = {
    "致远OA":         ["seeyon", "致远oa", "致远oa"],
    "蓝凌OA":         ["landray", "蓝凌", "ekp"],
    "通达OA":         ["tongda", "通达oa", "tdoa"],
    "泛微OA":         ["weaver", "泛微", "e-office", "e9", "ecology"],
    "用友YonBIP":     ["yonbip", "用友", "yonsuite", "nc-cloud", "nc cloud"],
    "用友GRP-U8":     ["grp-u8", "grpu8"],
    "新点智慧招采":    ["xindian", "新点", "epoint"],
    "海康威视安防平台": ["hikvision", "海康", "isecure"],
    "大汉JCMS":       ["jcms", "大汉"],
    "JEECMS":         ["jeecms"],
    "若依RuoYi":      ["ruoyi", "若依"],
    "ThinkPHP":       ["thinkphp"],
    "Apache-Struts2": ["struts", "s2-0"],
    "fastjson":       ["fastjson"],
    "Shiro":          ["shiro", "rememberme"],
    "SpringBoot":     ["spring", "springboot", "whitelabel error"],
    "GitLab":         ["gitlab"],
    "Jenkins":        ["jenkins"],
    "Jira":           ["jira"],
    "Zabbix":         ["zabbix"],
    "Grafana":        ["grafana"],
    "JumpServer":     ["jumpserver", "堡垒机"],
    "Zimbra":         ["zimbra"],
    "Coremail":       ["coremail"],
    "XXL-JOB":        ["xxl-job", "xxljob"],
    "Nacos":          ["nacos"],
    "Druid":          ["druid"],
    "Nginx":          ["nginx"],
    "Apache":         ["apache httpd", "apache/"],
    "IIS":            ["iis", "microsoft-iis"],
    "Tomcat":         ["tomcat"],
    "WebLogic":       ["weblogic", "oracle weblogic"],
    "JBoss":          ["jboss", "wildfly"],
    "深信服SSL-VPN":   ["sangfor ssl", "深信服"],
    "华为USG防火墙":   ["huawei usg", "usg6000"],
    "FortiGate":      ["fortigate", "fortios"],
    "VMware ESXi":    ["vmware esxi", "esxi"],
    "WPS Office":     ["wps"],
}


def normalize_product(raw: str) -> Optional[str]:
    """把原始指纹串归一化为补天标准产品名。"""
    if not raw:
        return None
    low = raw.lower()
    for std, aliases in PRODUCT_ALIASES.items():
        for a in aliases:
            if a in low:
                return std
    return None


def extract_products(tech: Iterable[str], title: str = "",
                     component: Iterable[str] = ()) -> list[str]:
    """从 httpx tech / Hunter component / 页面标题聚合产品指纹。"""
    products: list[str] = []
    cand = list(tech or []) + list(component or [])
    if title:
        cand.append(title)
    for c in cand:
        std = normalize_product(str(c))
        if std and std not in products:
            products.append(std)
    return products


# 指纹 → nuclei 模板定向扫描目录映射（tools/nuclei-templates 下的路径）
PRODUCT_TEMPLATE_DIRS: dict[str, list[str]] = {
    "致远OA":         ["http/cves", "http/exposures"],
    "通达OA":         ["http/cves"],
    "泛微OA":         ["http/cves"],
    "蓝凌OA":         ["http/cves"],
    "用友YonBIP":     ["http/cves"],
    "JumpServer":     ["http/cves"],
    "Zabbix":         ["http/cves", "http/exposures"],
    "Grafana":        ["http/cves"],
    "GitLab":         ["http/cves"],
    "Jenkins":        ["http/cves"],
    "Jira":           ["http/cves"],
    "Zimbra":         ["http/cves"],
    "Coremail":       ["http/cves"],
    "XXL-JOB":        ["http/cves", "http/exposures"],
    "WebLogic":       ["http/cves"],
    "ThinkPHP":       ["http/cves"],
    "若依RuoYi":      ["http/cves", "http/exposures"],
    "fastjson":       ["http/cves"],
    "Shiro":          ["http/cves"],
    "VMware ESXi":    ["http/cves"],
}

# 标题/指纹兜底关键词（补天收录重点国产产品，任何资产命中即标注）
KEY_TITLE_HINTS: dict[str, str] = {
    "seeyon": "致远OA", "致远": "致远OA",
    "通达oa": "通达OA", "tongda": "通达OA",
    "泛微": "泛微OA", "weaver": "泛微OA",
    "蓝凌": "蓝凌OA", "landray": "蓝凌OA",
    "用友": "用友YonBIP",
    "海康": "海康威视安防平台", "hikvision": "海康威视安防平台",
    "新点": "新点智慧招采",
    "jumpserver": "JumpServer", "堡垒机": "JumpServer",
    "深信服": "深信服SSL-VPN",
}


def guess_from_title(title: str) -> list[str]:
    """页面标题兜底识别（指纹识别不到时）。"""
    out = []
    if not title:
        return out
    for kw, std in KEY_TITLE_HINTS.items():
        if kw in title.lower() and std not in out:
            out.append(std)
    return out
