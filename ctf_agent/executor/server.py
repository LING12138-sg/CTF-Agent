"""
Executor MCP Server
=====================

基于 claude_agent_sdk @tool() + create_sdk_mcp_server 的工具代理服务。
（CHYing 模式：通过 SDK 原生 MCP server 注册工具，取代 FastMCP + McpSdkServerConfig，
  确保工具对 Agent 可见）
"""

from __future__ import annotations

from claude_agent_sdk import tool, create_sdk_mcp_server

from ..knowledge import (
    format_kb_results,
    format_wiki_results,
    query_kb,
    query_wiki,
)

from . import tools

_shared_dir = ""


def _as_text_result(text: str, *, is_error: bool = False) -> dict:
    return {
        "content": [{"type": "text", "text": text}],
        "is_error": is_error,
    }


# ── 工具定义 ──


@tool(
    name="bash",
    description="执行 shell 命令或 Python 脚本（通过 Kali Docker 沙箱）。"
    "language=shell(默认): shell 命令，支持管道/重定向。"
    "language=python: Python 脚本，自动注入工作目录到 os.environ['WORK_DIR'] 和 os.chdir()。",
    input_schema={
        "type": "object",
        "properties": {
            "command": {
                "type": "string",
                "description": "shell 命令或 Python 代码",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数 (default 60)",
                "default": 60,
            },
            "language": {
                "type": "string",
                "enum": ["shell", "python"],
                "description": "执行模式: shell（默认）或 python",
                "default": "shell",
            },
        },
        "required": ["command"],
    },
)
async def bash_tool(args: dict) -> dict:
    command = str(args.get("command", ""))
    timeout = int(args.get("timeout", 60))
    is_python = str(args.get("language", "shell")).lower() == "python"
    try:
        result = await tools.bash(command, timeout=timeout, is_python=is_python)
        return _as_text_result(result)
    except Exception as e:
        return _as_text_result(f"[ERROR] {e}", is_error=True)


@tool(
    name="web_fetch",
    description="获取 URL 的文本内容",
    input_schema={
        "type": "object",
        "properties": {
            "url": {
                "type": "string",
                "description": "要获取的 URL",
            },
            "timeout": {
                "type": "integer",
                "description": "超时秒数 (default 15)",
                "default": 15,
            },
        },
        "required": ["url"],
    },
)
async def web_fetch_tool(args: dict) -> dict:
    url = str(args.get("url", ""))
    timeout = int(args.get("timeout", 15))
    try:
        result = await tools.web_fetch(url, timeout=timeout)
        return _as_text_result(result)
    except Exception as e:
        return _as_text_result(f"[ERROR] {e}", is_error=True)


@tool(
    name="web_search",
    description="搜索网络信息（DuckDuckGo）",
    input_schema={
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "搜索关键词",
            },
        },
        "required": ["query"],
    },
)
async def web_search_tool(args: dict) -> dict:
    query = str(args.get("query", ""))
    try:
        result = await tools.web_search(query)
        return _as_text_result(result)
    except Exception as e:
        return _as_text_result(f"[ERROR] {e}", is_error=True)


@tool(
    name="kb_search",
    description="搜索历史解题经验知识库。根据目标技术栈（server/language/tags）查找类似题目的"
    "攻击方法和攻击链。同时返回 Wiki 技术页面（按 tags 匹配通用攻击方法）。",
    input_schema={
        "type": "object",
        "properties": {
            "server": {
                "type": "string",
                "description": "目标服务器 (e.g. openresty, nginx, apache)",
            },
            "language": {
                "type": "string",
                "description": "编程语言 (e.g. PHP, Java, Python)",
            },
            "tags": {
                "type": "string",
                "description": "逗号分隔的标签 (e.g. lfi, sqli, rce)",
            },
            "top_k": {
                "type": "integer",
                "description": "返回结果数量 (default 5)",
                "default": 5,
            },
        },
    },
)
async def kb_search_tool(args: dict) -> dict:
    server = str(args.get("server", ""))
    language = str(args.get("language", ""))
    tags = str(args.get("tags", ""))
    top_k = int(args.get("top_k", 5))

    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

    raw_results = query_kb(server=server, language=language, tags=tag_list, top_k=top_k)
    raw_section = format_kb_results(raw_results) if raw_results else ""

    wiki_results = query_wiki(tags=tag_list, top_k=top_k)
    wiki_section = format_wiki_results(wiki_results) if wiki_results else ""

    parts = []
    if raw_section:
        parts.append(raw_section)
    if wiki_section:
        parts.append(wiki_section)

    if not parts:
        return _as_text_result("知识库未找到相关历史经验或 Wiki 技术页面。")
    return _as_text_result("\n\n".join(parts))


@tool(
    name="record_key_finding",
    description="记录关键发现。在发现漏洞、凭据、重要信息或确认死胡同时调用此工具。"
    "持久化到 findings.log 和 progress.md，供其他 Agent 和评审流程使用。",
    input_schema={
        "type": "object",
        "properties": {
            "kind": {
                "type": "string",
                "description": "发现类型: vulnerability, credential, info, dead_end, endpoint, config",
            },
            "title": {
                "type": "string",
                "description": "发现标题（用于去重）",
            },
            "evidence": {
                "type": "string",
                "description": "核心证据（必填）",
            },
            "status": {
                "type": "string",
                "description": "状态: hypothesis, tested, confirmed, exploited, dead_end",
            },
            "verification_method": {
                "type": "string",
                "description": "验证方式: executed, observed, inferred",
            },
            "commands_and_results": {
                "type": "string",
                "description": "执行的命令与输出",
            },
            "confidence": {
                "type": "number",
                "description": "置信度 (0.0-1.0)",
            },
            "next_action": {
                "type": "string",
                "description": "建议下一步",
            },
            "details": {
                "type": "string",
                "description": "详细推导/利用过程",
            },
        },
        "required": ["kind", "title", "evidence"],
    },
)
async def record_key_finding_tool(args: dict) -> dict:
    finding = {
        "kind": str(args.get("kind", "info")),
        "title": str(args.get("title", "")),
        "evidence": str(args.get("evidence", "")),
        "status": str(args.get("status", "hypothesis")),
        "verification_method": str(args.get("verification_method", "inferred")),
        "commands_and_results": str(args.get("commands_and_results", "")),
        "confidence": float(args.get("confidence", 0.5)),
        "next_action": str(args.get("next_action", "")),
        "details": str(args.get("details", "")),
    }
    try:
        result = await tools.record_key_finding(finding, shared_dir=_shared_dir)
        return _as_text_result(result)
    except Exception as e:
        return _as_text_result(f"[ERROR] {e}", is_error=True)


_TOOLS = [
    bash_tool,
    web_fetch_tool,
    web_search_tool,
    kb_search_tool,
    record_key_finding_tool,
]


def create_executor_server(
    name: str = "ctf-executor",
    shared_dir: str = "",
):
    """创建 Executor MCP 服务器实例（通过 create_sdk_mcp_server）

    Args:
        name: MCP 服务器名称
        shared_dir: 共享目录路径（用于 record_key_finding 持久化）

    Returns:
        MCP server 实例（直接塞进 mcp_servers 字典即可）
    """
    global _shared_dir
    _shared_dir = shared_dir or ""

    return create_sdk_mcp_server(
        name=name,
        version="1.0.0",
        tools=_TOOLS,
    )
