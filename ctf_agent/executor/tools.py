"""
Executor Tool Implementations
===============================

实际工具执行逻辑：bash、web_fetch、web_search。
被 MCP 服务器调用，而非直接暴露给 LLM。
"""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from typing import Optional

import requests

_logger = logging.getLogger(__name__)

# ── 安全拦截 ──

BLOCKED_PATTERNS = [
    "rm -rf /",
    "rm -rf ~",
    "mkfs",
    "dd if=",
    ":(){",
    "> /dev/",
    "| shutdown",
    "| reboot",
    "| poweroff",
    "> /dev/sd",
]


def _is_blocked(command: str) -> str | None:
    """检查命令是否被拦截，返回匹配的模式或 None"""
    cmd_lower = command.lower()
    for pattern in BLOCKED_PATTERNS:
        if pattern.lower() in cmd_lower:
            return pattern
    return None


# ── Bash 执行 ──

async def bash(
    command: str,
    timeout: int = 60,
    cwd: Optional[str] = None,
) -> str:
    """执行 shell 命令并返回输出

    Args:
        command: shell 命令
        timeout: 超时秒数
        cwd: 工作目录

    Returns:
        命令输出（stdout + stderr）
    """
    blocked = _is_blocked(command)
    if blocked:
        return f"[BLOCKED] 命令包含禁止模式: {blocked}"

    try:
        proc = await asyncio.create_subprocess_exec(
            "bash", "-c",
            command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd or os.getcwd(),
        )
        try:
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=timeout
            )
        except asyncio.TimeoutError:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
            return f"[TIMEOUT] 命令执行超时 ({timeout}s)"

        parts = []
        if stdout:
            parts.append(stdout.decode(errors="replace")[:20000])
        if stderr:
            parts.append(f"\n[STDERR]\n{stderr.decode(errors='replace')[:5000]}")
        if not parts:
            return "(无输出)"

        return "".join(parts)
    except FileNotFoundError:
        return "[ERROR] bash 未找到，请确认 Git Bash 或 WSL 已安装"
    except Exception as e:
        return f"[ERROR] {e}"


# ── Web Fetch ──

async def web_fetch(url: str, timeout: int = 15) -> str:
    """获取 URL 内容

    Args:
        url: 目标 URL
        timeout: 超时秒数

    Returns:
        页面文本内容
    """
    try:
        loop = asyncio.get_event_loop()

        def _fetch() -> str:
            try:
                resp = requests.get(
                    url,
                    timeout=timeout,
                    verify=False,
                    allow_redirects=True,
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"
                        )
                    },
                )
                return resp.text[:15000]
            except requests.exceptions.Timeout:
                return f"[TIMEOUT] 请求超时 ({timeout}s)"
            except requests.exceptions.ConnectionError as e:
                return f"[ERROR] 连接失败: {e}"
            except Exception as e:
                return f"[ERROR] {e}"

        return await asyncio.wait_for(
            loop.run_in_executor(None, _fetch),
            timeout=timeout + 5,
        )
    except asyncio.TimeoutError:
        return f"[ERROR] web_fetch 整体超时"


# ── Record Key Finding ──

async def record_key_finding(
    finding: dict,
    shared_dir: str,
) -> str:
    """记录关键发现（持久化到 findings.log 和 progress.md）

    由 MCP 工具 record_key_finding 调用，不直接暴露给 LLM。
    原因：shared_dir 路径应由框架注入而非 LLM 指定。

    Args:
        finding: 发现字典（kind, title, evidence, status 等）
        shared_dir: 共享目录路径

    Returns:
        状态消息
    """
    from ..recorder.persistence import record_finding as _record
    return _record(finding, shared_dir)


# ── Web Search ──

async def web_search(query: str) -> str:
    """搜索网络信息

    使用 DuckDuckGo HTML 搜索（全文搜索，返回真实结果）。
    如需更强大的搜索能力，可扩展为 Tavily API。

    Args:
        query: 搜索关键词

    Returns:
        搜索结果摘要
    """
    import re

    try:
        loop = asyncio.get_event_loop()

        def _search() -> str:
            try:
                resp = requests.post(
                    "https://html.duckduckgo.com/html/",
                    data={"q": query},
                    timeout=15,
                    headers={
                        "User-Agent": (
                            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                            "AppleWebKit/537.36 (KHTML, like Gecko) "
                            "Chrome/120.0.0.0 Safari/537.36"
                        ),
                    },
                )
                html = resp.text

                results = []
                # 提取搜索结果块
                for article in re.finditer(
                    r'<a rel="nofollow" class="result__a" href="(.*?)">(.*?)</a>'
                    r'.*?<a class="result__snippet"(.*?)>(.*?)</a>',
                    html, re.DOTALL,
                ):
                    url = article.group(1)
                    title = re.sub(r"<[^>]+>", "", article.group(2)).strip()
                    snippet = re.sub(r"<[^>]+>", "", article.group(4)).strip()
                    results.append(f"[{title}]({url})\n  {snippet}")
                    if len(results) >= 8:
                        break

                if results:
                    return f"搜索结果: '{query}'\n\n" + "\n\n".join(results)
                return f"未找到 '{query}' 的相关结果"
            except requests.exceptions.Timeout:
                return f"[TIMEOUT] 搜索超时 (15s)"
            except Exception as e:
                return f"[ERROR] 搜索失败: {e}"

        return await asyncio.wait_for(
            loop.run_in_executor(None, _search),
            timeout=20,
        )
    except asyncio.TimeoutError:
        return "[ERROR] 搜索超时"