"""
Agent 基类
===========

提供所有 Agent 类型的公共功能：
- LLM 客户端引用
- 日志记录
- 上下文读写
"""

from __future__ import annotations

from typing import Optional

from ..common import log_system_event
from ..llm.base import LLMBase


class BaseAgent:
    """Agent 基类

    所有 Agent（Plan / Attack / QuickCheck）继承自此基类。
    提供 LLM 客户端、日志、上下文访问等公共功能。
    """

    def __init__(
        self,
        llm_client: LLMBase,
        agent_id: str,
        challenge_id: str = "",
    ):
        self.llm = llm_client
        self.agent_id = agent_id
        self.challenge_id = challenge_id

    def log(self, message: str, payload: Optional[str] = None):
        """记录 Agent 日志"""
        tag = f"[{self.agent_id}]"
        msg = f"{tag} {message}" if payload is None else f"{tag} {message} | {payload}"
        log_system_event(msg)


__all__ = ["BaseAgent"]