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
from typing import Any, Dict, List, Optional, Tuple

from claude_agent_sdk import (
    ClaudeSDKClient,
    ClaudeAgentOptions,
    AssistantMessage,
    ResultMessage,
    UserMessage,
    SystemMessage,
    TextBlock,
    ThinkingBlock,
    ToolUseBlock,
    ToolResultBlock,
    HookMatcher,
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
        use_executor: bool = False,
        max_guidance_rounds: int = 0,
        shared_dir: Optional[str] = None,
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
        self.use_executor = use_executor
        self.max_guidance_rounds = max_guidance_rounds
        self.shared_dir = shared_dir or os.path.join(self.cwd, "shared", "logs")
        self._tag = f"[{agent_label}]" if agent_label else ""

        self._env = self._build_env()
        if env:
            self._env.update(env)

        # 持久会话支持
        self._persistent_client: Optional[ClaudeSDKClient] = None
        self._persistent_session_active = False

        # Executor MCP 服务器（懒加载）
        self._executor_server = None

        # 反射追踪器（懒加载，用于 hooks）
        self._reflection_tracker = None

        # Hooks 缓存
        self._hooks_built = None

    # ── 持久会话管理 ──

    async def _ensure_connected(
        self,
        system_prompt: Optional[str] = None,
        output_format: Optional[Dict[str, Any]] = None,
    ):
        """确保持久会话已建立（客户端保持连接，支持多轮对话）

        Args:
            system_prompt: 可选的 system prompt 覆盖
            output_format: JSON Schema，持久会话期间固定（不可在 query() 时变更）
        """
        if self._persistent_client is not None and self._persistent_session_active:
            return
        options = self._build_options(
            system_override=system_prompt, output_format=output_format
        )
        client = ClaudeSDKClient(options=options)
        await client.__aenter__()
        self._persistent_client = client
        self._persistent_session_active = True
        log_system_event(f"{self._tag} 持久会话已建立")

    async def reset_session(self):
        """关闭持久会话"""
        if self._persistent_client is not None:
            try:
                await self._persistent_client.__aexit__(None, None, None)
            except Exception:
                pass
            self._persistent_client = None
            self._persistent_session_active = False
        self._reflection_tracker = None
        self._hooks_built = None
        log_system_event(f"{self._tag} 持久会话已关闭")

    async def query(
        self,
        prompt: str,
        output_format: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """在持久会话中发送消息并等待完整响应

        当 max_guidance_rounds > 0 时自动运行 Guidance Loop：
        每轮检查 _guidance_is_solved()，未完成则用 _guidance_build_query()
        构建追加 query 继续。多轮结果自动合并。

        Args:
            prompt: 用户消息
            output_format: JSON Schema（可选，仅用于 _process_stream 解析回退）
                          结构化 schema 必须在 _ensure_connected() 时设定，
                          query() 时不可变更。

        Returns:
            {"text": str, "structured": dict | None, "is_error": bool, "error_message": str | None}
        """
        if not self._persistent_client or not self._persistent_session_active:
            raise RuntimeError("没有活跃的持久会话，请先调用 _ensure_connected()")

        log_system_event(
            f"{self._tag} query | prompt_len={len(prompt)}"
        )

        if self.log_file:
            self._write()
            self._write_block(
                f">>> [{self.agent_label or 'LLM'}] query"
            )

        # ── 第一轮 ──
        await self._persistent_client.query(prompt)
        result = await self._process_stream(
            self._persistent_client, output_format=output_format
        )

        # ── Guidance Loop（max_guidance_rounds > 0 时启用） ──
        if self.max_guidance_rounds > 0:
            round_count = 0
            while (
                not result.get("is_error", False)
                and not self._guidance_is_solved(result)
                and round_count < self.max_guidance_rounds
            ):
                round_count += 1

                guidance_msg, should_stop = self._guidance_build_query(
                    result, round_count
                )
                if should_stop:
                    break

                log_system_event(
                    f"{self._tag} Guidance round {round_count}/{self.max_guidance_rounds}"
                    f" | msg_len={len(guidance_msg)}"
                )
                if self.log_file:
                    self._write_block(
                        f"Guidance Round {round_count}/{self.max_guidance_rounds}",
                        guidance_msg,
                    )

                await self._persistent_client.query(guidance_msg)
                new_result = await self._process_stream(
                    self._persistent_client, output_format=output_format
                )

                # 合并结果：文本追加，结构化取最新，错误取最新
                text_parts = [
                    result.get("text", ""),
                    new_result.get("text", ""),
                ]
                result["text"] = "\n".join(p for p in text_parts if p)
                if new_result.get("structured"):
                    result["structured"] = new_result["structured"]
                if new_result.get("is_error"):
                    result["is_error"] = new_result["is_error"]
                    result["error_message"] = new_result.get("error_message")
                    break

        return result

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

    # ── Guidance Loop 钩子 ──
    #
    # 子类或调用方可以覆盖这些方法来定制 Guidance Loop 行为。
    # 默认实现：无结构化数据时不循环；有结构化数据时检查 solved/success 字段。
    #
    # 使用方式（PlanAgent 示例）：
    #   self.llm.max_guidance_rounds = 3
    #   self.llm._guidance_is_solved = my_check
    #   self.llm._guidance_build_query = my_build

    def _guidance_is_solved(self, result: Dict[str, Any]) -> bool:
        """检查本轮结果是否已达到目标（结束循环）。"""
        structured = result.get("structured")
        if not structured or not isinstance(structured, dict):
            return False
        return bool(structured.get("solved") or structured.get("success"))

    def _guidance_build_query(
        self, result: Dict[str, Any], round_count: int
    ) -> Tuple[str, bool]:
        """分析本轮结果，构建下一轮指导 query。

        Returns:
            (guidance_message, should_stop):
            - guidance_message: 追加给 Agent 的指导 prompt
            - should_stop: True 表示立即终止循环
        """
        return ("", True)

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
            "allowed_tools": self.allowed_tools if not self.use_executor else [],
            "disallowed_tools": self.disallowed_tools,
            "max_turns": self.max_turns,
            "cwd": self.cwd,
            "permission_mode": self.permission_mode,
        }
        if self.model:
            kwargs["model"] = self.model
        if self._env:
            kwargs["env"] = self._env

        # ── MCP Servers（Executor 模式自动合并） ──
        mcp_servers: dict = {}

        if isinstance(self.mcp_servers, dict):
            mcp_servers.update(self.mcp_servers)
        elif isinstance(self.mcp_servers, (str, os.PathLike)):
            try:
                import json as _json
                with open(self.mcp_servers) as _f:
                    _ext = _json.load(_f)
                for _name, _cfg in _ext.get("mcpServers", {}).items():
                    if isinstance(_cfg, dict):
                        mcp_servers[_name] = _cfg  # pass through raw dict
            except Exception:
                pass

        if self.use_executor:
            if self._executor_server is None:
                from ..executor import create_executor_server
                self._executor_server = create_executor_server(
                    shared_dir=self.shared_dir,
                )
            from ..executor import executor_mcp_config
            mcp_servers.update(executor_mcp_config(self._executor_server))

            # 禁用 SDK 内置 Bash，所有命令执行走 executor MCP（必经 Docker 沙箱）
            current_disallowed = set(kwargs.get("disallowed_tools") or [])
            current_disallowed.add("Bash")
            kwargs["disallowed_tools"] = list(current_disallowed)

        if mcp_servers:
            kwargs["mcp_servers"] = mcp_servers

        # ── Hooks ──
        hooks = self._build_hooks()
        if hooks is not None:
            kwargs["hooks"] = hooks
        if self.max_thinking_tokens is not None:
            kwargs["max_thinking_tokens"] = self.max_thinking_tokens

        fmt = output_format or self.output_format
        if fmt is not None:
            kwargs["output_format"] = {"type": "json_schema", "schema": fmt}

        return ClaudeAgentOptions(**kwargs)

    # ── Hooks 构建 ──

    def _build_hooks(self):
        """构建 PreToolUse/PostToolUse 钩子配置

        当 use_executor=True 时自动构建完整 hooks。
        否则使用用户传入的 hooks（如果有）。
        """
        if not self.use_executor:
            return self.hooks

        # 使用缓存
        if self._hooks_built is not None:
            return self._hooks_built

        from .hooks import (
            create_pre_tool_use_hook,
            create_post_tool_use_hook,
            create_subagent_stop_hook,
        )
        from .reflection_tracker import ReflectionTracker

        # 懒加载反射追踪器
        if self._reflection_tracker is None:
            self._reflection_tracker = ReflectionTracker(shared_dir=self.shared_dir)

        hooks = {
            "PreToolUse": [
                HookMatcher(hooks=[
                    create_pre_tool_use_hook(
                        shared_dir=self.shared_dir,
                        allowed_tools=self.allowed_tools or None,
                        disallowed_tools=self.disallowed_tools or None,
                        tools_requiring_args=(),
                        reflection_tracker=self._reflection_tracker,
                    )
                ])
            ],
            "PostToolUse": [
                HookMatcher(hooks=[
                    create_post_tool_use_hook(
                        shared_dir=self.shared_dir,
                        reflection_tracker=self._reflection_tracker,
                        agent_name=self.agent_label,
                    )
                ])
            ],
            "SubagentStop": [
                HookMatcher(hooks=[
                    create_subagent_stop_hook(
                        agent_name=self.agent_label,
                    )
                ])
            ],
        }
        self._hooks_built = hooks
        return hooks

    # ── 执行方法 ──

    async def _process_stream(
        self,
        client: ClaudeSDKClient,
        output_format: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """处理响应流，提取文本、工具调用、结构化数据

        Args:
            client: ClaudeSDKClient 实例（已 query 过的）
            output_format: JSON Schema（可选）

        Returns:
            {"text": str, "structured": dict | None}
        """
        text_parts: List[str] = []
        structured_data = None
        is_error = False
        error_message: Optional[str] = None

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
                        if block.name == "StructuredOutput" and isinstance(block.input, dict):
                            structured_data = block.input
                        text_parts.append(f"[TOOL_CALL: {block.name}]")
                        if self.log_file:
                            self._write_tool_call(block.name, block.input)

            elif isinstance(msg, UserMessage):
                if self.log_file and isinstance(msg.content, list):
                    for item in msg.content:
                        if isinstance(item, ToolResultBlock):
                            self._write_tool_result(item.content, item.is_error)

            elif isinstance(msg, SystemMessage):
                # Compact 检测：CLI auto-compact 触发时发送 status="compacting"
                if (
                    hasattr(msg, 'subtype') and msg.subtype == "status"
                    and hasattr(msg, 'data') and isinstance(msg.data, dict)
                    and msg.data.get("status") == "compacting"
                    and self._reflection_tracker is not None
                ):
                    self._reflection_tracker.enter_compact_recovery()
                    log_system_event(
                        "Compact detected, entering recovery mode "
                        "(will block write tools until context is restored)",
                    )
                    # 异步编译 compact_handoff.md
                    try:
                        from .compact import compile_handoff, log_compact_boundary
                        log_compact_boundary(self.shared_dir, "start")
                        handoff = compile_handoff(self.shared_dir)
                        if handoff:
                            log_system_event(f"ProgressCompiler: handoff written to {handoff}")
                    except Exception as exc:
                        log_system_event(f"ProgressCompiler 编译失败: {exc}")

            elif isinstance(msg, ResultMessage):
                # ResultMessage 不一定有 error_message 属性
                err_msg = getattr(msg, 'error_message', None) or msg.result or ""

                if self.log_file:
                    if msg.is_error:
                        self._write(
                            f"\n[ERR] [{self.agent_label or 'LLM'}] "
                            f"错误: {err_msg}"
                        )
                    else:
                        cost = msg.total_cost_usd
                        cost_str = f"(${cost:.4f})" if cost is not None else ""
                        tools_count = self._count_tool_calls(text_parts)
                        self._write(f"\n[OK] [{self.agent_label or 'LLM'}] 完成 {cost_str}")

                # 尝试从 ResultMessage 提取结构化输出
                if structured_data is None:
                    if hasattr(msg, 'structured_output') and msg.structured_output is not None:
                        structured_data = msg.structured_output
                    elif msg.result:
                        try:
                            parsed = json.loads(msg.result)
                            if isinstance(parsed, dict):
                                structured_data = parsed
                        except (json.JSONDecodeError, TypeError):
                            pass

                if msg.is_error:
                    log_system_event(
                        f"{self._tag} LLM 执行错误",
                        err_msg or "未知",
                        level=logging.WARNING,
                    )
                is_error = msg.is_error
                error_message = err_msg if msg.is_error else None
                break

        return {
            "text": "".join(text_parts), "structured": structured_data,
            "is_error": is_error, "error_message": error_message,
        }

    async def execute(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> str:
        """一次性文本执行（自动开/关临时会话）

        创建临时会话 → 发送 prompt → 收集文本响应 → 自动断开。
        不影响持久会话状态。

        Args:
            prompt: 用户提示词
            system_prompt: 临时覆盖系统提示词（可选）

        Returns:
            LLM 文本响应
        """
        options = self._build_options(system_override=system_prompt)
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            result = await self._process_stream(client)
            return result["text"]

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
        """一次性结构化输出执行（自动开/关临时会话）

        创建临时会话 → 发送 prompt（结构化 schema） → 收集响应 → 自动断开。
        不影响持久会话状态。

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
        async with ClaudeSDKClient(options=options) as client:
            await client.query(prompt)
            result = await self._process_stream(client, output_format=output_format)
            return result


__all__ = ["LLMBase"]