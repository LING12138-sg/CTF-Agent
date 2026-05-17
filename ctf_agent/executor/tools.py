"""
Executor Tool Implementations
===============================

实际工具执行逻辑：bash、web_fetch、web_search。
底层命令执行改用沙箱执行器（Docker 隔离 / Local 回退），
不再直接创建 subprocess。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Optional

import requests

from ..sandbox import get_executor

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


# ── Bash 执行（通过沙箱）──

async def bash(
    command: str,
    timeout: int = 60,
    cwd: Optional[str] = None,
    is_python: bool = False,
    workdir: Optional[str] = None,
) -> str:
    """通过沙箱执行 shell 命令或 Python 脚本并返回输出

    Args:
        command: shell 命令 或 Python 代码（is_python=True 时）
        timeout: 超时秒数
        cwd: 工作目录（兼容旧接口）
        is_python: True 时以 Python 脚本执行 command（base64 pipe + workdir 注入）
        workdir: Python 模式的工作目录（注入到脚本中）

    Returns:
        命令输出（stdout + stderr）
    """
    blocked = _is_blocked(command)
    if blocked:
        return f"[BLOCKED] 命令包含禁止模式: {blocked}"

    try:
        executor = get_executor()
    except Exception as e:
        return f"[SANDBOX_ERROR] 沙箱初始化失败: {e}"

    _cwd = cwd or os.getcwd()

    # Python 模式：base64 pipe 执行（避免 Docker/Host 文件系统隔离问题）
    if is_python:
        try:
            compile(command, "<poc>", "exec")
        except SyntaxError as e:
            return f"[SYNTAX ERROR] 第 {e.lineno} 行: {e.msg}"

        _workdir = workdir or _cwd
        wrapper = (
            "import os\n"
            f"os.chdir({json.dumps(_workdir)})\n"
            f"os.environ['WORK_DIR'] = {json.dumps(_workdir)}\n"
        )
        full_code = wrapper + command

        # 存档 PoC（写 scripts/ 目录，该目录在 Docker 中可见）
        try:
            from datetime import datetime
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            scripts_dir = Path(_cwd) / "scripts"
            scripts_dir.mkdir(parents=True, exist_ok=True)
            (scripts_dir / f"poc_{ts}.py").write_text(full_code, encoding="utf-8")
        except Exception:
            pass

        # base64 pipe 执行（避免 temp file 跨容器路径映射问题）
        import base64
        encoded = base64.b64encode(full_code.encode()).decode()
        exec_cmd = f"echo {encoded} | base64 -d | python3"

        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(
            None,
            lambda: executor.execute(exec_cmd, timeout=timeout, caller="executor_tools[python]"),
        )

        parts = []
        if result.stdout:
            parts.append(result.stdout[:20000])
        if result.stderr:
            parts.append(f"\n[STDERR]\n{result.stderr[:5000]}")
        if result.timed_out:
            parts.append(f"\n[TIMEOUT] 命令执行超时 ({timeout}s)")
        if not parts:
            return "(无输出)"
        return "".join(parts)

    # Shell 模式：直接执行
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: executor.execute(command, timeout=timeout, workdir=_cwd, caller="executor_tools"),
    )

    parts = []
    if result.stdout:
        parts.append(result.stdout[:20000])
    if result.stderr:
        parts.append(f"\n[STDERR]\n{result.stderr[:5000]}")
    if result.timed_out:
        parts.append(f"\n[TIMEOUT] 命令执行超时 ({timeout}s)")
    if not parts:
        return "(无输出)"

    return "".join(parts)


# ── Web Fetch ──

async def web_fetch(url: str, timeout: int = 15) -> str:
    """获取 URL 内容"""
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
        return "[ERROR] web_fetch 整体超时"


# ── Record Key Finding ──

async def record_key_finding(
    finding: dict,
    shared_dir: str,
) -> str:
    """记录关键发现"""
    from ..recorder.persistence import record_finding as _record
    return _record(finding, shared_dir)


# ── Web Search ──

async def web_search(query: str) -> str:
    """搜索网络信息"""
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