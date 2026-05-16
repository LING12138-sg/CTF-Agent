"""
Plan Agent - 攻击规划智能体
=============================

职责：
1. 分析目标信息（URL、技术栈、端点）
2. 通过 LLM 生成攻击计划（AttackPlan）
3. 评审 Attack Agent 返回的发现，决定重规划还是继续
4. 支持人类介入：接受外部提示/参考信息

与 CHYing-agent 的 PromptCompiler 不同：
- Plan Agent 是全流程参与的，不只是初始生成
- 可以在任意轮次介入，根据新发现调整策略
- 支持人类提供参考思路和信息
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

from ..common import log_plan_event, log_system_event
from ..llm.base import LLMBase
from ..llm.schemas import PLANS_OUTPUT_SCHEMA
from ..types import (
    AttackPlan, ChallengeContext, Finding, FindingType,
    PlanStatus, Severity, TargetInfo,
)
from .prompts import get_brain_prompt


class PlanAgent:
    """攻击规划智能体

    接收 ChallengeContext，产出新的 AttackPlan 列表。
    每次调用都是 stateless 的 —— 从 ChallengeContext 读取当前状态，
    生成计划后写入 Context。
    """

    def __init__(self, llm_client: LLMBase, challenge_id: str = ""):
        self.llm = llm_client
        self.challenge_id = challenge_id
        self.system_prompt = get_brain_prompt()

    async def analyze_and_plan(self, ctx: ChallengeContext, human_hint: str = "") -> List[AttackPlan]:
        """分析目标并生成攻击计划

        使用持久会话：建立连接 → query（Guidance Loop） → 断开连接。

        Args:
            ctx: 当前题目上下文（含目标信息、已有发现）
            human_hint: 人类提供的参考信息或思路

        Returns:
            新的攻击计划列表
        """
        log_plan_event(f"开始分析: {ctx.challenge_id}", f"target={ctx.target.url}")

        # 1. 构建 LLM 输入
        target_summary = self._build_target_summary(ctx)
        findings_summary = self._build_findings_summary(ctx)
        existing_plans = self._build_existing_plans_summary(ctx)

        user_message = f"""# 目标信息
{target_summary}

# 已有发现
{findings_summary}

# 已有计划
{existing_plans}
"""

        if human_hint:
            user_message += f"\n# 人类参考信息\n{human_hint}\n"

        user_message += """
请分析以上目标并制定攻击计划。
你可以使用 Bash、WebFetch、WebSearch 等工具浏览目标、搜索已知漏洞信息。
分析完成后，输出攻击计划。"""

        # 2. 建立持久会话 + Guidance Loop
        plans: List[AttackPlan] = []
        max_rounds = 3
        guidance = user_message

        await self.llm._ensure_connected(
            system_prompt=self.system_prompt, output_format=PLANS_OUTPUT_SCHEMA
        )
        try:
            for round_idx in range(max_rounds):
                log_plan_event(f"Guidance Round {round_idx + 1}/{max_rounds}")
                result = await self.llm.query(guidance, output_format=PLANS_OUTPUT_SCHEMA)

                structured = result.get("structured") or {}
                plans_data = structured.get("plans", []) if isinstance(structured, dict) else []

                if plans_data:
                    plans = self._parse_plans_from_data(plans_data, ctx)
                    if plans:
                        break

                # 没有有效计划 → 构造 guidance 重试
                text = result.get("text", "")
                if round_idx < max_rounds - 1:
                    guidance = (
                        "上一轮没有输出有效的攻击计划。请重新分析目标，"
                        "并使用工具的返回值制定至少 2 个具体的攻击计划。\n\n"
                        f"原始目标信息:\n{user_message}\n\n"
                        f"你上一轮的回复:\n{text[:2000]}"
                    )
                else:
                    # 最后一轮仍失败，回退文本解析
                    log_plan_event("Guidance Loop 耗尽，回退文本解析", level=logging.WARNING)
                    plans = self._parse_plans_from_response(text, ctx) if text else []
        finally:
            # 3. 确保持久会话始终断开
            await self.llm.reset_session()

        log_plan_event(f"生成 {len(plans)} 个攻击计划", f"plans={[p.title for p in plans]}")
        return plans

    async def review_findings(
        self,
        ctx: ChallengeContext,
        new_findings: List[Finding],
    ) -> Dict:
        """评审新发现，决定下一步

        Args:
            ctx: 当前上下文
            new_findings: 本轮新增的发现

        Returns:
            {"action": "continue"|"replan"|"stop", "reason": str}
        """
        # 如果发现了 Flag，直接停止
        for f in new_findings:
            if f.type == FindingType.FLAG:
                log_plan_event(f"发现 Flag，停止规划", f"flag={f.description}")
                return {"action": "stop", "reason": f"Flag 已找到: {f.description}"}

        # 如果有高置信度的漏洞发现，让 Attack Agent 继续深入
        has_high_confidence = any(
            f.confidence >= 80 for f in new_findings
        )
        if has_high_confidence:
            return {"action": "continue", "reason": "高置信度发现，Attack Agent 继续深入"}

        # 如果还有很多待执行计划，继续
        active_count = len(ctx.get_active_plans())
        if active_count > 0:
            return {"action": "continue", "reason": f"还有 {active_count} 个计划待执行"}

        # 没有可用计划且没有关键发现，需要重规划
        if not ctx.get_flag():
            return {"action": "replan", "reason": "当前计划执行完毕，需要新的攻击方向"}

        return {"action": "stop", "reason": "无进一步行动"}

    def _build_target_summary(self, ctx: ChallengeContext) -> str:
        """构建目标信息摘要"""
        t = ctx.target
        lines = [
            f"- URL: {t.url}",
            f"- IP: {t.ip}",
            f"- 端口: {t.ports}",
            f"- 协议: {t.protocol}",
        ]
        if ctx.tech_stack.server:
            lines.append(f"- 服务器: {ctx.tech_stack.server}")
        if ctx.tech_stack.framework:
            lines.append(f"- 框架: {ctx.tech_stack.framework}")
        if ctx.tech_stack.language:
            lines.append(f"- 语言: {ctx.tech_stack.language}")
        return "\n".join(lines)

    def _build_findings_summary(self, ctx: ChallengeContext) -> str:
        """构建已有发现摘要"""
        if not ctx.findings:
            return "暂无发现"
        lines = []
        for f in ctx.findings:
            lines.append(f"- [{f.severity.value}] {f.title} (confidence: {f.confidence}%)")
            if f.description:
                lines.append(f"  {f.description}")
        return "\n".join(lines)

    def _build_existing_plans_summary(self, ctx: ChallengeContext) -> str:
        """构建已有计划摘要"""
        if not ctx.plans:
            return "暂无计划"
        lines = []
        for p in ctx.plans:
            lines.append(f"- [{p.status.value}] {p.id}: {p.title}")
        return "\n".join(lines) if lines else "暂无计划"

    def _parse_plans_from_data(self, data: List[Dict], ctx: ChallengeContext) -> List[AttackPlan]:
        """从结构化输出的 plans 数据解析 AttackPlan 列表"""
        plans = []
        for item in data:
            if not isinstance(item, dict) or "title" not in item:
                continue
            plan = AttackPlan(
                id=item.get("id", f"plan_{len(ctx.plans) + len(plans) + 1:03d}"),
                title=item["title"],
                hypothesis=item.get("hypothesis", ""),
                approach=item.get("approach", ""),
                priority=item.get("priority", 5),
                prerequisites=item.get("prerequisites", []),
                expected_outcome=item.get("expected_outcome", ""),
            )
            plans.append(plan)
        return plans

    def _parse_plans_from_response(self, response: str, ctx: ChallengeContext) -> List[AttackPlan]:
        """解析 LLM 输出的 JSON 计划列表"""
        # 尝试提取 JSON 块
        json_match = re.search(r"```(?:json)?\s*(\[[\s\S]*?\])\s*```", response)
        if json_match:
            content = json_match.group(1)
        else:
            # 如果没有 ``` 包裹，尝试直接解析
            content = response.strip()

        try:
            data = json.loads(content)
            if isinstance(data, dict):
                data = [data]
        except json.JSONDecodeError:
            log_plan_event("解析 LLM 输出失败，尝试提取 JSON 数组", level=logging.WARNING)
            try:
                # 尝试提取 [ ... ] 中的内容
                array_match = re.search(r"\[[\s\S]*\]", content)
                if array_match:
                    data = json.loads(array_match.group())
                else:
                    raise
            except (json.JSONDecodeError, AttributeError):
                log_plan_event("无法解析 LLM 输出", response[:200], level=logging.ERROR)
                return []

        plans = []
        for item in data:
            if not isinstance(item, dict) or "title" not in item:
                continue
            plan = AttackPlan(
                id=item.get("id", f"plan_{len(ctx.plans) + len(plans) + 1:03d}"),
                title=item["title"],
                hypothesis=item.get("hypothesis", ""),
                approach=item.get("approach", ""),
                priority=item.get("priority", 5),
                prerequisites=item.get("prerequisites", []),
                expected_outcome=item.get("expected_outcome", ""),
            )
            plans.append(plan)

        return plans


__all__ = ["PlanAgent"]