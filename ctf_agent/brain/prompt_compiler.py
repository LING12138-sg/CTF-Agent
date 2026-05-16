"""
PromptCompiler — 侦察数据编译器（轻量化）
========================================

在 Plan Agent 分析前，将原始侦察数据编译为结构化 XML，
减少 Plan Agent 第一轮的信息噪音，提升攻击计划质量。

与 CHYing-agent 的 PromptCompiler 不同：
- 无 RAG 知识库集成
- 无 category 纠正
- 无 multi-flag 约束注入
- 单轮推理，无工具，纯文本输出
"""

from __future__ import annotations

import logging
from typing import Optional

from prompts import load_prompt

from ..common import log_system_event
from ..llm.base import LLMBase
from ..types import ChallengeContext

_logger = logging.getLogger(__name__)

SYSTEM_PROMPT = f"<system_prompt>\n{load_prompt('prompt_compiler.md')}\n</system_prompt>"


async def compile_recon(llm: LLMBase, ctx: ChallengeContext) -> str:
    """将原始侦察数据编译为结构化 XML

    Args:
        llm: LLMBase 实例（无工具，纯文本推理）
        ctx: 当前题目上下文（含目标信息、技术栈、侦察数据）

    Returns:
        编译后的 XML 字符串，失败时返回空字符串
    """
    target = ctx.target
    ts = ctx.tech_stack

    # 组装输入
    lines = [
        "<raw_recon_data>",
        f"target_url: {target.url}",
        f"target_ip: {target.ip}",
        f"target_ports: {target.ports}",
        f"protocol: {target.protocol}",
        "",
    ]

    if ts.server:
        lines.append(f"server: {ts.server}")
    if ts.language:
        lines.append(f"language: {ts.language}")
    if ts.framework:
        lines.append(f"framework: {ts.framework}")
    if ts.database:
        lines.append(f"database: {ts.database}")

    lines.append("")
    lines.append("</raw_recon_data>")

    message = "\n".join(lines)

    try:
        result = await llm.execute(message, system_prompt=SYSTEM_PROMPT)
        compiled = result.strip()

        # 检验输出是否为有效 XML（至少包含根标签）
        if compiled.startswith("<") and len(compiled) > 50:
            log_system_event(
                "[PromptCompiler] 编译成功",
                f"input_len={len(message)} compiled_len={len(compiled)}",
            )
            return compiled

        log_system_event(
            "[PromptCompiler] 输出无效，跳过",
            f"compiled_len={len(compiled)}",
            level=logging.WARNING,
        )
        return ""

    except Exception as e:
        log_system_event(
            f"[PromptCompiler] 编译失败: {e}",
            level=logging.WARNING,
        )
        return ""


__all__ = ["compile_recon"]