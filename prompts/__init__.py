"""
Prompt 加载器
=============

所有 Prompt 以 .md 文件形式存放在本目录。
Python 模块通过 ``load_prompt("filename.md")`` 加载原始文本。
"""

from __future__ import annotations

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load_prompt(name: str) -> str:
    """加载 Prompt 文件

    Args:
        name: 文件名（含 .md 后缀），如 "plan_agent_identity.md"

    Returns:
        Prompt 文件完整文本

    Raises:
        FileNotFoundError: Prompt 文件不存在
    """
    path = _PROMPTS_DIR / name
    if not path.exists():
        raise FileNotFoundError(f"Prompt 文件不存在: {path}")
    return path.read_text(encoding="utf-8")


__all__ = ["load_prompt"]