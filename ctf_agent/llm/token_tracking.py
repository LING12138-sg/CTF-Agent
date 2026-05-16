"""
Token 用量追踪
===============

追踪 API 调用的 Token 消耗和费用估算。
"""

from __future__ import annotations

import os
import logging
from typing import Any, Dict, Optional

from ..common import log_system_event

_logger = logging.getLogger(__name__)


# 模型 → 每百万 Token 价格 (USD)
_MODEL_PRICING = {
    "deepseek-v4-flash": {"input": 0.15, "output": 0.60},
    "claude-sonnet-4-6": {"input": 3.00, "output": 15.00},
    "claude-opus-4-7": {"input": 15.00, "output": 75.00},
}


def _get_model_pricing(model: str) -> Dict[str, float]:
    """获取模型定价（USD/百万 token）"""
    return _MODEL_PRICING.get(model, {"input": 1.00, "output": 4.00})


class TokenTracker:
    """Token 用量追踪器"""

    def __init__(self, model: str = ""):
        self.model = model
        self.total_input = 0
        self.total_output = 0

    def add_usage(self, input_tokens: int, output_tokens: int):
        """累加 Token 用量"""
        self.total_input += input_tokens
        self.total_output += output_tokens

    @property
    def total_cost(self) -> float:
        """估算总费用（USD）"""
        pricing = _get_model_pricing(self.model)
        return (self.total_input / 1_000_000) * pricing["input"] + \
               (self.total_output / 1_000_000) * pricing["output"]

    def log_summary(self, tag: str = ""):
        """输出 Token 用量摘要"""
        prefix = f"[{tag}] " if tag else ""
        log_system_event(
            f"{prefix}Token 用量",
            f"input={self.total_input} output={self.total_output} cost=${self.total_cost:.4f}",
        )


__all__ = ["TokenTracker"]