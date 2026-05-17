"""
Executor MCP Server
=====================

基于 FastMCP 的工具代理服务。
以 MCP 服务器形式暴露工具，供 Agent 调用（取代直接 allowed_tools）。

用法:
    from ctf_agent.executor.server import create_executor_server
    mcp = create_executor_server()
"""

from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from . import tools


def create_executor_server(
    name: str = "ctf-executor",
    shared_dir: str = "",
) -> FastMCP:
    """创建 Executor MCP 服务器实例

    Args:
        name: MCP 服务器名称
        shared_dir: 共享目录路径（用于 record_key_finding 持久化）

    Returns:
        FastMCP 实例
    """
    mcp = FastMCP(name)
    _shared = shared_dir or ""

    # ── 注册工具 ──

    @mcp.tool(
        description=(
            "执行 shell 命令或 Python 脚本（通过 Kali Docker 沙箱）。"
            "language=shell(默认): shell 命令，支持管道/重定向。"
            "language=python: Python 脚本，自动注入工作目录到 os.environ['WORK_DIR'] 和 os.chdir()。"
        )
    )
    async def bash(
        command: str,
        timeout: int = 60,
        language: str = "shell",
    ) -> str:
        """Execute a command in the Docker sandbox

        Args:
            command: shell 命令或 Python 代码
            timeout: Timeout in seconds (default 60)
            language: 执行模式 — shell（默认）或 python
        """
        return await tools.bash(
            command, timeout=timeout,
            is_python=language.lower() == "python",
        )

    @mcp.tool(description="获取 URL 的文本内容")
    async def web_fetch(
        url: str,
        timeout: int = 15,
    ) -> str:
        """Fetch a URL and return its text content

        Args:
            url: The URL to fetch
            timeout: Timeout in seconds (default 15)
        """
        return await tools.web_fetch(url, timeout=timeout)

    @mcp.tool(description="搜索网络信息（DuckDuckGo）")
    async def web_search(
        query: str,
    ) -> str:
        """Search the web for information

        Args:
            query: Search query string
        """
        return await tools.web_search(query)

    @mcp.tool(
        description=(
            "搜索历史解题经验知识库。根据目标技术栈（server/language/tags）查找类似题目的"
            "攻击方法和攻击链。同时返回 Wiki 技术页面（按 tags 匹配通用攻击方法）。"
        )
    )
    async def kb_search(
        server: str = "",
        language: str = "",
        tags: str = "",
        top_k: int = 5,
    ) -> str:
        """Search knowledge base for historical experience + wiki techniques

        Args:
            server: Target server (e.g. openresty, nginx, apache)
            language: Programming language (e.g. PHP, Java, Python)
            tags: Comma-separated tags (e.g. lfi, sqli, rce)
            top_k: Number of results (default 5)
        """
        from ..knowledge import (
            format_kb_results, format_wiki_results,
            query_kb, query_wiki,
        )

        tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []

        # 1. 查 raw 经验
        raw_results = query_kb(server=server, language=language, tags=tag_list, top_k=top_k)
        raw_section = format_kb_results(raw_results) if raw_results else ""

        # 2. 查 wiki 页面
        wiki_results = query_wiki(tags=tag_list, top_k=top_k)
        wiki_section = format_wiki_results(wiki_results) if wiki_results else ""

        # 3. 合并
        parts = []
        if raw_section:
            parts.append(raw_section)
        if wiki_section:
            parts.append(wiki_section)

        if not parts:
            return "知识库未找到相关历史经验或 Wiki 技术页面。"
        return "\n\n".join(parts)

    @mcp.tool(
        description=(
            "记录关键发现。在发现漏洞、凭据、重要信息或确认死胡同时调用此工具。"
            "持久化到 findings.log 和 progress.md，供其他 Agent 和评审流程使用。"
        )
    )
    async def record_key_finding(
        kind: str = "info",
        title: str = "",
        evidence: str = "",
        status: str = "hypothesis",
        verification_method: str = "inferred",
        commands_and_results: str = "",
        confidence: float = 0.5,
        next_action: str = "",
        details: str = "",
    ) -> str:
        """记录关键发现

        Args:
            kind: 发现类型 — vulnerability, credential, info, dead_end, endpoint, config
            title: 发现标题（用于 progress.md 去重）
            evidence: 核心证据（必填）
            status: 状态 — hypothesis, tested, confirmed, exploited, dead_end
            verification_method: 验证方式 — executed, observed, inferred
            commands_and_results: 执行的命令与输出
            confidence: 置信度 (0.0-1.0)
            next_action: 建议下一步
            details: 详细推导/利用过程
        """
        finding = {
            "kind": kind,
            "title": title,
            "evidence": evidence,
            "status": status,
            "verification_method": verification_method,
            "commands_and_results": commands_and_results,
            "confidence": confidence,
            "next_action": next_action,
            "details": details,
        }
        return await tools.record_key_finding(
            finding, shared_dir=_shared,
        )

    return mcp