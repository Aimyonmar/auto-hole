# -*- coding: utf-8 -*-
"""recon —— 增强采集 / 指纹 / 限速 / 断点续跑。

设计目标（详见 docs/recon/）：
1. 数据源插件化 + 统一 Asset/Finding schema + 归一化去重
2. 单次请求多维度提取（存活 + 标题 + 头 + 正文 + 指纹），减少请求总量
3. 有界并发 + 令牌桶 + 自适应降速 + 熔断 + 逐请求审计
4. 分阶段 checkpoint，可断点续跑
5. light/standard/deep 分级策略，默认温和（并发 8）
"""
__version__ = "1.0.0"
