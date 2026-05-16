"""
LLM 模块
=========

基于 claude-agent-sdk 的 ClaudeSDKClient 封装。
参照 CHYing-agent claude_sdk/ 结构组织，简化版。

## 模块组成

- **base.py**: LLMBase 基类，封装 ClaudeSDKClient，提供 execute() / execute_structured()
- **hooks.py**: PreToolUse/PostToolUse/SubagentStop 钩子工厂
- **schemas.py**: 结构化输出 Schema 定义
- **token_tracking.py**: Token 用量追踪
- **reflection_tracker.py**: 停滞检测与 ABANDON 机制
- **file_guards.py**: 文件读取防护
- **compact.py**: ProgressCompiler — 紧凑恢复上下文编译
"""

from .base import LLMBase
from .hooks import (
    create_pre_tool_use_hook,
    create_post_tool_use_hook,
    create_subagent_stop_hook,
)
from .reflection_tracker import ReflectionTracker
from .schemas import ORCHESTRATOR_OUTPUT_SCHEMA, AgentOutputSchema, PLANS_OUTPUT_SCHEMA
from .compact import compile_handoff, should_use_handoff, log_compact_boundary

__all__ = [
    "LLMBase",
    "create_pre_tool_use_hook",
    "create_post_tool_use_hook",
    "create_subagent_stop_hook",
    "ReflectionTracker",
    "ORCHESTRATOR_OUTPUT_SCHEMA",
    "AgentOutputSchema",
    "PLANS_OUTPUT_SCHEMA",
    "compile_handoff",
    "should_use_handoff",
    "log_compact_boundary",
]