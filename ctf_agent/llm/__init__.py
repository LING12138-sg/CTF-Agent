"""
LLM 模块
=========

基于 claude-agent-sdk 的 ClaudeSDKClient 封装。
参照 CHYing-agent claude_sdk/ 结构组织，简化版。

## 模块组成

- **base.py**: LLMBase 基类，封装 ClaudeSDKClient，提供 execute() / execute_structured()
- **hooks.py**: PreToolUse/PostToolUse 钩子工厂
- **schemas.py**: 结构化输出 Schema 定义
- **token_tracking.py**: Token 用量追踪
"""

from .base import LLMBase
from .schemas import ORCHESTRATOR_OUTPUT_SCHEMA, AgentOutputSchema, PLANS_OUTPUT_SCHEMA

__all__ = [
    "LLMBase",
    "ORCHESTRATOR_OUTPUT_SCHEMA",
    "AgentOutputSchema",
    "PLANS_OUTPUT_SCHEMA",
]