"""
LLMBase - Claude SDK Agent 基类（简化版）
=========================================

基于 claude-agent-sdk 的 ClaudeSDKClient，提供简化的 LLM 通信基类。
参照 CHYing-agent 的 BaseClaudeAgent 设计，但去除持久会话、Guidance Loop、模型轮换等复杂功能。

核心功能：
- execute(): 一次性文本执行（支持实时流式输出到文件）
- execute_structured(): 结构化输出执行
- 工具支持（通过 allowed_tools / MCP servers 配置）

流式输出：
- 每个 Agent 实例可以指定 log_file，实时输出写入独立文件
- 适合赛马模式：每个 Attack Agent 一个日志文件，不互相干扰
- 用户可以通过 tail -f 跟踪特定 Agent 的执行过程
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, Dict, List, Optional

from claude_agent_sdk import (
    ClaudeSDKClient,
    ClaudeAgentOptions,
    AssistantMessage,
    ResultMessage,
    UserMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    ToolResultBlock,
)

from ..common import log_system_event

_logger = logging.getLogger(__name__)


class LLMBase:
    """基于 ClaudeSDKClient 的 LLM 通信基类

    提供一次性执行能力，每次 execute() 创建新连接并自动断开。
    工具能力通过构造参数配置（allowed_tools / MCP servers）。

    示例:
        llm = LLMBase(
            model="deepseek-v4-flash",
            api_key="...",
            base_url="https://api.deepseek.com",
            log_file="shared/logs/agent.log",
        )
        result = await llm.execute("Hello")
        # 实时输出会写入 shared/logs/agent.log
    """

    def __init__(
        self,
        model: Optional[str] = None,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        system_prompt: str = "",
        allowed_tools: Optional[List[str]] = None,
        disallowed_tools: Optional[List[str]] = None,
        max_turns: int = 100,
        mcp_servers: Optional[Any] = None,
        output_format: Optional[Dict[str, Any]] = None,
        hooks: Optional[Dict[str, List[Any]]] = None,
        env: Optional[Dict[str, str]] = None,
        cwd: Optional[str] = None,
        permission_mode: str = "bypassPermissions",
        max_thinking_tokens: Optional[int] = None,
        agent_label: str = "",
        log_file: Optional[str] = None,
    ):
        self.model = model or os.getenv("ANTHROPIC_MODEL", "")
        self.api_key = api_key or os.getenv("ANTHROPIC_AUTH_TOKEN", "")
        self.base_url = base_url or os.getenv("ANTHROPIC_BASE_URL", "")
        self.system_prompt = system_prompt
        self.allowed_tools = allowed_tools or []
        self.disallowed_tools = disallowed_tools or []
        self.max_turns = max_turns
        self.mcp_servers = mcp_servers
        self.output_format = output_format
        self.hooks = hooks
        self.cwd = cwd or os.getcwd()
        self.permission_mode = permission_mode
        self.max_thinking_tokens = max_thinking_tokens
        self.agent_label = agent_label
        self.log_file = log_file
        self._tag = f"[{agent_label}]" if agent_label else ""

        self._env = self._build_env()
        if env:
            self._env.update(env)

    # ── 文件日志输出 ──

    def _write(self, text: str = ""):
        """写入日志文件（追加 + 自动换行 + 实时 flush）"""
        if not self.log_file:
            return
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(text + "\n")
                f.flush()
        except OSError:
            pass

    def _write_stream(self, text: str):
        """流式写入（不换行，实时 flush）"""
        if not self.log_file:
            return
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(text)
                f.flush()
        except OSError:
            pass

    def _write_block(self, title: str, content: str = "", width: int = 60):
        """写入分隔块"""
        self._write(f"\n{'─' * width}")
        self._write(f" {title}")
        self._write(f"{'─' * width}")
        if content:
            self._write(content)

    def _write_tool_call(self, name: str, inp: Any):
        """写入工具调用"""
        inp_str = json.dumps(inp, ensure_ascii=False)[:500]
        self._write(f">>> [TOOL:{name}] {inp_str}")

    def _write_tool_result(self, content: Any, is_error: bool = False):
        """写入工具结果"""
        content_str = str(content)[:500]
        icon = "[ERR]" if is_error else "[OK]"
        self._write(f"{icon} {content_str}")

    # ── 环境变量 ──

    def _build_env(self) -> Dict[str, str]:
        """构建环境变量，映射 API 配置到 CLI 环境变量"""
        env: Dict[str, str] = {}
        env["CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"] = "1"
        env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"

        if self.api_key:
            env["ANTHROPIC_AUTH_TOKEN"] = self.api_key
        if self.base_url:
            url = self.base_url.rstrip("/")
            if url.endswith("/v1"):
                url = url[:-3]
            env["ANTHROPIC_BASE_URL"] = url
        if self.model:
            env["ANTHROPIC_MODEL"] = self.model
            env["ANTHROPIC_DEFAULT_OPUS_MODEL"] = self.model
            env["ANTHROPIC_DEFAULT_SONNET_MODEL"] = self.model
            env["ANTHROPIC_DEFAULT_HAIKU_MODEL"] = self.model
            env["CLAUDE_CODE_SUBAGENT_MODEL"] = self.model
        return env

    # ── Options 构建 ──

    def _build_options(
        self,
        system_override: Optional[str] = None,
        output_format: Optional[Dict[str, Any]] = None,
    ) -> ClaudeAgentOptions:
        """构建 ClaudeAgentOptions"""
        kwargs: Dict[str, Any] = {
            "system_prompt": (
                system_override if system_override is not None else self.system_prompt
            ),
            "allowed_tools": self.allowed_tools,
            "disallowed_tools": self.disallowed_tools,
            "max_turns": self.max_turns,
            "cwd": self.cwd,
            "permission_mode": self.permission_mode,
        }
        if self.model:
            kwargs["model"] = self.model
        if self._env:
            kwargs["env"] = self._env
        if self.mcp_servers is not None:
            kwargs["mcp_servers"] = self.mcp_servers
        if self.hooks is not None:
            kwargs["hooks"] = self.hooks
        if self.max_thinking_tokens is not None:
            kwargs["max_thinking_tokens"] = self.max_thinking_tokens

        fmt = output_format or self.output_format
        if fmt is not None:
            kwargs["output_format"] = {"type": "json_schema", "schema": fmt}

        return ClaudeAgentOptions(**kwargs)

    # ── 执行方法 ──

    async def execute(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """一次性文本执行

        创建临时会话 → 发送 prompt → 收集文本响应 → 自动断开。
        如果配置了 log_file，会将 LLM 的思考、工具调用、结果实时写入文件。

        Args:
            prompt: 用户提示词
            system_prompt: 临时覆盖系统提示词（可选）

        Returns:
            LLM 文本响应
        """
        options = self._build_options(system_override=system_prompt)
        log_system_event(f"{self._tag} LLMBase execute | prompt_len={len(prompt)}")

        if self.log_file:
            self._write()
            self._write_block(f">>> [{self.agent_label or 'LLM'}] 开始执行")

        try:
            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                text_parts: List[str] = []

                async for msg in client.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for block in msg.content:
                            if isinstance(block, TextBlock):
                                if self.log_file:
                                    self._write_stream(block.text)
                                text_parts.append(block.text)
                            elif isinstance(block, ThinkingBlock):
                                if self.log_file and block.thinking.strip():
                                    self._write_stream(
                                        f"\n--- THINK {block.thinking[:500]}...\n"
                                    )
                            elif isinstance(block, ToolUseBlock):
                                text_parts.append(
                                    f"[TOOL_CALL: {block.name}]"
                                )
                                if self.log_file:
                                    self._write_tool_call(block.name, block.input)

                    elif isinstance(msg, UserMessage):
                        if self.log_file and isinstance(msg.content, list):
                            for item in msg.content:
                                if isinstance(item, ToolResultBlock):
                                    self._write_tool_result(
                                        item.content, item.is_error
                                    )

                    elif isinstance(msg, ResultMessage):
                        if self.log_file:
                            if msg.is_error:
                                self._write(
                                    f"\n[ERR] [{self.agent_label or 'LLM'}] "
                                    f"错误: {msg.error_message or msg.result}"
                                )
                            else:
                                cost = msg.total_cost_usd
                                cost_str = (
                                    f"(${cost:.4f})" if cost is not None else ""
                                )
                                tools_count = self._count_tool_calls(text_parts)
                                self._write(
                                    f"\n[OK] [{self.agent_label or 'LLM'}] "
                                    f"完成 {cost_str}"
                                )
                        if msg.is_error:
                            log_system_event(
                                f"{self._tag} LLM 执行错误",
                                msg.error_message or msg.result or "未知",
                                level=logging.WARNING,
                            )
                        break

                result = "".join(text_parts)
                log_system_event(
                    f"{self._tag} LLMBase 完成 | response_len={len(result)}"
                )
                return result

        except Exception as e:
            log_system_event(
                f"{self._tag} LLMBase 异常", str(e), level=logging.ERROR
            )
            if self.log_file:
                self._write(f"\n[ERR] [{self.agent_label or 'LLM'}] 异常: {e}")
            raise

    def _count_tool_calls(self, text_parts: List[str]) -> int:
        """统计文本中的工具调用标记数量"""
        return sum(1 for p in text_parts if p.startswith("[TOOL_CALL:"))

    # ── 结构化输出 ──

    async def execute_structured(
        self,
        prompt: str,
        output_format: Optional[Dict[str, Any]] = None,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """一次性结构化输出执行

        Args:
            prompt: 用户提示词
            output_format: JSON Schema（可选）
            system_prompt: 临时覆盖系统提示词（可选）

        Returns:
            {"text": str, "structured": dict | None}
        """
        options = self._build_options(
            system_override=system_prompt, output_format=output_format
        )
        log_system_event(f"{self._tag} LLMBase execute_structured")

        if self.log_file:
            self._write()
            self._write_block(f">>> [{self.agent_label or 'LLM'}] 开始执行（结构化）")

        try:
            async with ClaudeSDKClient(options=options) as client:
                await client.query(prompt)
                text_parts: List[str] = []
                structured_data = None

                async for msg in client.receive_response():
                    if isinstance(msg, AssistantMessage):
                        for block in msg.content:
                            if isinstance(block, TextBlock):
                                if self.log_file:
                                    self._write_stream(block.text)
                                text_parts.append(block.text)
                            elif isinstance(block, ThinkingBlock):
                                if self.log_file and block.thinking.strip():
                                    self._write_stream(
                                        f"\n--- THINK {block.thinking[:500]}...\n"
                                    )
                            elif (
                                isinstance(block, ToolUseBlock)
                                and block.name == "StructuredOutput"
                                and isinstance(block.input, dict)
                            ):
                                structured_data = block.input
                            elif isinstance(block, ToolUseBlock):
                                if self.log_file:
                                    self._write_tool_call(block.name, block.input)

                    elif isinstance(msg, UserMessage):
                        if self.log_file and isinstance(msg.content, list):
                            for item in msg.content:
                                if isinstance(item, ToolResultBlock):
                                    self._write_tool_result(
                                        item.content, item.is_error
                                    )

                    elif isinstance(msg, ResultMessage):
                        if structured_data is None:
                            if (
                                hasattr(msg, "structured_output")
                                and msg.structured_output is not None
                            ):
                                structured_data = msg.structured_output
                            elif msg.result:
                                try:
                                    structured_data = json.loads(msg.result)
                                except (json.JSONDecodeError, TypeError):
                                    pass
                        if self.log_file:
                            cost = msg.total_cost_usd
                            cost_str = (
                                f"(${cost:.4f})" if cost is not None else ""
                            )
                            self._write(
                                f"\n[OK] [{self.agent_label or 'LLM'}] "
                                f"完成 {cost_str}"
                            )
                        break

                return {"text": "".join(text_parts), "structured": structured_data}

        except Exception as e:
            log_system_event(
                f"{self._tag} LLMBase 异常", str(e), level=logging.ERROR
            )
            if self.log_file:
                self._write(f"\n[ERR] [{self.agent_label or 'LLM'}] 异常: {e}")
            raise


__all__ = ["LLMBase"]