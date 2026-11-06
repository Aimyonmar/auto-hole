# -*- coding: utf-8 -*-
"""recon 测试用路径配置：保证从仓库根导入 core / modules。"""
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
