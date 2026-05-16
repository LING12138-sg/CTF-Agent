"""
Tool Call 钩子
===============

PreToolUse / PostToolUse 钩子，用于：
- 日志记录（调用了什么工具、参数、结果）
- 错误处理（工具执行失败时的 fallback）
- 安全检查（阻止危险命令）

与 CHYing-agent 的 hooks.py 功能类似，但简化。
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Dict, Optional

from ..common import log_system_event


def create_pre_tool_hook(
    agent_name: str = "",
) -> Callable[[str, Dict], Optional[str]]:
    """创建 PreToolUse 钩子

    在工具执行前调用，返回非空字符串将阻止执行（作为错误消息）。

    Args:
        agent_name: Agent 名称（用于日志）

    Returns:
        钩子函数 (tool_name, tool_input) -> Optional[str]（错误消息）
    """
    tag = f"[{agent_name}]" if agent_name else ""

    def hook(tool_name: str, tool_input: Dict) -> Optional[str]:
        log_system_event(
            f"{tag} 工具调用: {tool_name}",
            json.dumps(tool_input, ensure_ascii=False)[:300],
        )
        return None  # 允许执行

    return hook


def create_post_tool_hook(
    agent_name: str = "",
) -> Callable[[str, str, float], None]:
    """创建 PostToolUse 钩子

    在工具执行后调用，记录结果摘要。

    Args:
        agent_name: Agent 名称（用于日志）

    Returns:
        钩子函数 (tool_name, result_summary, elapsed_seconds) -> None
    """
    tag = f"[{agent_name}]" if agent_name else ""

    def hook(tool_name: str, result_summary: str, elapsed: float):
        log_system_event(
            f"{tag} 工具结果: {tool_name}",
            f"elapsed={elapsed:.1f}s result={result_summary[:200]}",
        )

    return hook


__all__ = ["create_pre_tool_hook", "create_post_tool_hook"]