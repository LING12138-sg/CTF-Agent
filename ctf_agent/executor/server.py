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


def create_executor_server(name: str = "ctf-executor") -> FastMCP:
    """创建 Executor MCP 服务器实例

    Args:
        name: MCP 服务器名称（用于 SDK 配置中的 key）

    Returns:
        FastMCP 实例，可通过 McpSdkServerConfig 注入 Agent
    """
    mcp = FastMCP(name)

    # ── 注册工具 ──

    @mcp.tool(description="执行 shell 命令并返回输出（支持管道、重定向等）")
    async def bash(
        command: str,
        timeout: int = 60,
    ) -> str:
        """Execute a shell command

        Args:
            command: The shell command to execute
            timeout: Timeout in seconds (default 60)
        """
        return await tools.bash(command, timeout=timeout)

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

    return mcp