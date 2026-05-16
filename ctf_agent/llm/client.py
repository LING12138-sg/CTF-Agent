"""
LLM 客户端（兼容层）
====================

此模块替换了旧版基于 raw anthropic SDK 的 LLMClient。
所有功能已迁移到 base.py 中的 LLMBase。
保留此文件仅用于兼容旧导入路径。

新代码请直接:
    from ..llm.base import LLMBase
"""

from __future__ import annotations

from .base import LLMBase  # noqa: F401

__all__ = ["LLMBase"]