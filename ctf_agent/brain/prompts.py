"""
Orchestrator System Prompt 组装
=================================

从 prompts/ 目录加载 .md 文件，组装成完整的 System Prompt。
"""

from __future__ import annotations

from prompts import load_prompt


def get_brain_prompt() -> str:
    """组装 Plan Agent 的 System Prompt

    从 identity + strategy + constraints 三个文件加载并拼接。
    """
    parts = [
        load_prompt("plan_agent_identity.md"),
        load_prompt("plan_agent_strategy.md"),
        load_prompt("plan_agent_constraints.md"),
    ]
    content = "\n\n".join(parts)
    return f"<system_prompt>\n{content}\n</system_prompt>"


def get_attack_prompt() -> str:
    """组装 Attack Agent 的 System Prompt

    从 identity + strategy 两个文件加载并拼接。
    """
    parts = [
        load_prompt("attack_agent_identity.md"),
        load_prompt("attack_agent_strategy.md"),
    ]
    content = "\n\n".join(parts)
    return f"<system_prompt>\n{content}\n</system_prompt>"


__all__ = ["get_brain_prompt", "get_attack_prompt"]