"""
CTF Agent - Plan-Attack 架构自动化 CTF 解题系统

参考 CHYing-agent 架构风格重构：
- Plan Agent: 分析目标、制定攻击计划、人类可介入参考信息与思路
- Attack Agent: 并行赛马执行不同计划，新思路快速试探再汇报
- Runner: 编排 Plan → Attack → 反馈循环
"""

__version__ = "2.0.0"