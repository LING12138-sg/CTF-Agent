"""
CTF Agent - Plan-Attack 架构自动化 CTF 解题系统

参考 CHYing-agent 架构风格重构：
- Plan Agent: 分析目标、制定攻击计划、人类可介入参考信息与思路
- Attack Agent: 并行赛马执行不同计划，新思路快速试探再汇报
- Runner: 编排 Plan → Attack → 反馈循环
"""

from pathlib import Path
import sys

# 确保项目根目录在 sys.path 中，使 `from prompts import load_prompt` 可工作
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

__version__ = "2.0.0"