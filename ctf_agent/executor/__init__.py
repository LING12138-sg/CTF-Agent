"""
Executor — 独立工具代理层
==========================

职责：
- 集中管理所有工具调用（bash / web_fetch / web_search）
- 提供结构化返回结果
- 安全审计（命令拦截、超时控制、限流）
- 以 MCP SDK Server 形式注入 Agent（通过 create_sdk_mcp_server）

用法:
    from ctf_agent.executor import create_executor_server, executor_mcp_config

    mcp = create_executor_server()
    # 在 LLMBase 的 mcp_servers 中直接使用:
    # mcp_servers = executor_mcp_config(mcp)
"""

from __future__ import annotations

from .server import create_executor_server


def executor_mcp_config(
    mcp_instance=None,
    server_name: str = "ctf-executor",
) -> dict:
    """生成 Executor MCP 配置字典，用于 LLMBase 的 mcp_servers 参数

    Args:
        mcp_instance: create_sdk_mcp_server 实例（不传则自动创建）
        server_name: MCP 服务器名称

    Returns:
        {server_name: mcp_instance} — 直接供 mcp_servers 使用
    """
    if mcp_instance is None:
        mcp_instance = create_executor_server(server_name, shared_dir="")
    return {server_name: mcp_instance}


__all__ = [
    "create_executor_server",
    "executor_mcp_config",
]
