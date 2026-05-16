"""
Quick Check - 快速试探智能体
==============================

轻量级验证工具：当 Attack Agent 发现新方向时，
Quick Check 快速验证思路是否可行，再决定是否报告给 Plan Agent。

设计目标：
- 轻量：一个 API 调用 + 一个 HTTP 请求
- 快速：超时短（默认 60s）
- 三档结论：可行 / 不可行 / 不确定
"""

from __future__ import annotations

import asyncio
import re
import time
from typing import Optional

from ..common import log_attack_event, now_str
from ..llm.base import LLMBase
from ..types import ChallengeContext, Finding, FindingType, Severity
from ..utils.http import get_with_retry
from .base import BaseAgent


class QuickCheckAgent(BaseAgent):
    """快速试探智能体

    验证一个攻击假设是否可行，返回三档结论。
    不执行完整攻击，只做轻量验证。
    """

    def __init__(
        self,
        llm_client: LLMBase,
        challenge_id: str = "",
        timeout: int = 60,
    ):
        super().__init__(llm_client, "quick_check", challenge_id)
        self.timeout = timeout

    async def check(self, hypothesis: str, ctx: ChallengeContext) -> dict:
        """快速验证攻击假设

        Args:
            hypothesis: 攻击假设描述
            ctx: 当前上下文

        Returns:
            {"feasible": bool, "confidence": float, "evidence": str, "reason": str}
            feasible=True 表示思路可行
        """
        log_attack_event(f"Quick Check: {hypothesis[:80]}")

        try:
            result = await asyncio.wait_for(
                self._run_check(hypothesis, ctx),
                timeout=self.timeout,
            )
            return result
        except asyncio.TimeoutError:
            return {
                "feasible": False,
                "confidence": 0,
                "evidence": "",
                "reason": "Quick Check 超时",
            }

    async def _run_check(self, hypothesis: str, ctx: ChallengeContext) -> dict:
        """执行快速验证"""
        target = ctx.target

        # 1. 先发一个探测请求，验证目标可达
        try:
            resp = get_with_retry(target.url, timeout=8, max_retries=1)
            status = resp.status_code
            body_preview = resp.text[:500]
        except Exception as e:
            return {
                "feasible": False,
                "confidence": 0,
                "evidence": "",
                "reason": f"目标不可达: {e}",
            }

        # 2. 用 LLM 判断假设可行性
        user_message = f"""# Quick Check
目标: {target.url}
HTTP 状态: {status}
假设: {hypothesis}

页面预览:
{body_preview}

请快速判断这个攻击假设是否可行。
只输出 JSON:
```json
{{"feasible": true/false, "confidence": 0-100, "reason": "简短原因"}}
```"""

        response = await self.llm.execute(
            user_message,
            system_prompt="你是一个 CTF 安全专家，快速判断攻击思路的可行性。",
        )

        # 3. 解析 LLM 判断
        try:
            json_match = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", response)
            if json_match:
                import json
                data = json.loads(json_match.group(1))
                return {
                    "feasible": data.get("feasible", False),
                    "confidence": data.get("confidence", 0),
                    "evidence": "",
                    "reason": data.get("reason", ""),
                }
        except Exception:
            pass

        return {
            "feasible": False,
            "confidence": 0,
            "evidence": "",
            "reason": "无法判断",
        }


__all__ = ["QuickCheckAgent"]