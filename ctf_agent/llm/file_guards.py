"""
文件读取防护
=============

防止 Agent 读取大文件、二进制文件，避免浪费 token 和破坏上下文。
"""

from __future__ import annotations

import os
from typing import Optional

# 最大允许读取的文件大小（字节）
MAX_FILE_SIZE = 200 * 1024  # 200KB

# 禁止直接读取的二进制/无关扩展名
BINARY_EXTENSIONS = frozenset({
    ".elf", ".so", ".dll", ".dylib", ".exe", ".bin",
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg", ".webp", ".bmp",
    ".woff", ".woff2", ".ttf", ".eot", ".otf",
    ".zip", ".tar", ".gz", ".bz2", ".xz", ".7z", ".rar", ".zst",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".mp3", ".mp4", ".avi", ".mov", ".wav", ".flac", ".ogg",
    ".db", ".sqlite", ".sqlite3", ".db3",
    ".pyc", ".pyo", ".class", ".jar", ".dex",
    ".o", ".a", ".lib", ".obj",
    ".iso", ".img", ".qcow2", ".vmdk",
    ".ttf", ".otf",
    ".min.js", ".min.css",  # 压缩后的前端文件通常极大
})


def check_file_read(tool_name: str, tool_input: dict) -> Optional[str]:
    """检查文件读取操作是否安全。

    Args:
        tool_name: 工具名称
        tool_input: 工具参数

    Returns:
        如果应该阻止读取，返回拒绝理由字符串；否则返回 None
    """
    if tool_name not in ("Read",):
        return None

    if not isinstance(tool_input, dict):
        return None

    file_path = tool_input.get("file_path", "") or ""
    if not file_path:
        return None

    # 检查文件是否存在
    if not os.path.exists(file_path):
        return None

    # 检查文件大小
    try:
        size = os.path.getsize(file_path)
        if size > MAX_FILE_SIZE:
            return (
                f"文件过大 ({size / 1024:.0f}KB)，超过 {MAX_FILE_SIZE / 1024:.0f}KB 限制。"
                f"请用 bash 命令分段处理：head -c 2000 '{file_path}'"
            )
    except OSError:
        pass

    # 检查扩展名
    lower_path = file_path.lower()
    for ext in BINARY_EXTENSIONS:
        if lower_path.endswith(ext):
            return (
                f"文件 '{os.path.basename(file_path)}' 是二进制文件，"
                f"不应直接用 Read 工具读取。请用 bash 的 strings/file 命令分析。"
            )

    return None