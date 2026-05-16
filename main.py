"""
CTF Agent 主入口
================

支持两种运行模式：
1. Plan-Attack 自动模式（默认）：Plan Agent 规划 + Attack Agent 并行赛马
2. 单目标模式 (-t): 直接对目标进行 Plan-Attack

示例：
  python main.py -t http://target:8080
  python main.py -t http://target:8080 -p "题目是 SQL 注入"
  python main.py -t http://target:8080 --rounds 5 --attackers 4
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

# 确保项目根目录在 Python 路径中
_project_root = Path(__file__).resolve().parent
if str(_project_root) not in sys.path:
    sys.path.insert(0, str(_project_root))

from ctf_agent.common import log_system_event
from ctf_agent.config import AgentConfig
from ctf_agent.runner import Runner


def main():
    """主入口"""
    parser = argparse.ArgumentParser(
        description="CTF Agent - Plan-Attack 架构自动化解题系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  python main.py -t http://target:8080             # 默认模式
  python main.py -t http://target:8080 -p "SQL注入"  # 带人类提示
  python main.py -t target:8080 --attackers 4       # 4 个 Attack Agent 赛马
        """,
    )

    parser.add_argument("-t", "--target", required=True, help="目标 URL")
    parser.add_argument("-p", "--prompt", type=str, default="", help="人类提示/参考信息")
    parser.add_argument("--rounds", type=int, default=0, help="最大规划轮数（默认: 3）")
    parser.add_argument("--attackers", type=int, default=0, help="并行 Attack Agent 数（默认: 3）")
    parser.add_argument("--timeout", type=int, default=0, help="Attack Agent 超时秒数（默认: 600）")
    parser.add_argument("--state-dir", type=str, default="", help="状态文件保存目录")

    args = parser.parse_args()

    # 加载配置
    config = AgentConfig.from_env()

    # 命令行参数覆盖
    if args.rounds > 0:
        config.runner.max_plan_rounds = args.rounds
    if args.attackers > 0:
        config.runner.max_attackers = args.attackers
    if args.timeout > 0:
        config.runner.attack_timeout = args.timeout
    if args.state_dir:
        config.paths.state_dir = Path(args.state_dir)

    # 检查 API 配置
    if not config.llm.is_configured:
        log_system_event("API 未配置！请检查 .claude/settings.local.json")
        log_system_event("需要设置: ANTHROPIC_AUTH_TOKEN 和 ANTHROPIC_BASE_URL")
        sys.exit(1)

    # 运行 Runner
    runner = Runner(
        target_url=args.target,
        config=config,
        human_prompt=args.prompt,
    )
    result = runner.run()

    # 输出结果
    if result.get("success"):
        print(f"\nFlag: {result['flag']}")
    else:
        print("\n未找到 Flag")


if __name__ == "__main__":
    main()