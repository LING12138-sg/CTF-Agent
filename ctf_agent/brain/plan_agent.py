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
from typing import Any, Dict, List, Optional, Tuple

from ..common import log_plan_event
from ..knowledge import (
    format_kb_results, format_wiki_results,
    query_kb, query_wiki,
)
from ..llm.schemas import PLANS_OUTPUT_SCHEMA
from ..types import (
    AgentStatus, AttackPlan, ChallengeContext, Finding, FindingType,
    PlanStatus, Severity, TargetInfo,
)
from .prompts import get_brain_prompt


class PlanAgent:
    """攻击规划智能体

    接收 ChallengeContext，产出新的 AttackPlan 列表。
    每次调用都是 stateless 的 —— 从 ChallengeContext 读取当前状态，
    生成计划后写入 Context。
    """

    def __init__(self, llm_client: LLMBase, challenge_id: str = "", shared_dir: str = ""):
        self.llm = llm_client
        self.challenge_id = challenge_id
        self.shared_dir = shared_dir
        self.system_prompt = get_brain_prompt()

    async def analyze_and_plan(self, ctx: ChallengeContext, human_hint: str = "") -> List[AttackPlan]:
        """分析目标并生成攻击计划

        使用持久会话 + 框架级 Guidance Loop（通过 LLMBase.query() 内置）。
        将 Guidance 钩子挂载到 LLM 实例上，loop 自动运行最多 max_rounds 轮。

        Args:
            ctx: 当前题目上下文（含目标信息、已有发现）
            human_hint: 人类提供的参考信息或思路

        Returns:
            新的攻击计划列表
        """
        log_plan_event(f"开始分析: {ctx.challenge_id}", f"target={ctx.target.url}")

        # 1. 构建 LLM 输入
        if ctx.compiled_recon:
            target_summary = ctx.compiled_recon
        else:
            target_summary = self._build_target_summary(ctx)
        findings_summary = self._build_findings_summary(ctx)
        existing_plans = self._build_existing_plans_summary(ctx)

        # 知识库关联经验（raw + wiki）
        ts = ctx.tech_stack
        kb_results = query_kb(server=ts.server, language=ts.language, top_k=3)
        kb_section = ""
        if kb_results:
            kb_section = "\n# 相关历史经验\n" + format_kb_results(kb_results) + "\n"
            log_plan_event(f"知识库命中 {len(kb_results)} 条相关经验")

        # Wiki 技术页面（按 tags 匹配通用攻击方法）
        kb_tags = [t for t in [ts.language, ts.server, ts.framework] if t]
        wiki_results = query_wiki(tags=kb_tags, top_k=3)
        wiki_section = ""
        if wiki_results:
            wiki_section = "\n" + format_wiki_results(wiki_results) + "\n"
            log_plan_event(f"Wiki 命中 {len(wiki_results)} 条技术页面")

        # findings.log 中的持久化发现（Attack Agent 通过 record_key_finding 写入）
        recorded_section = ""
        if self.shared_dir:
            try:
                from ..recorder import get_findings_summary
                recorded = get_findings_summary(self.shared_dir)
                if recorded:
                    recorded_section = "\n# Agent 实时记录的关键发现\n" + recorded + "\n"
            except Exception:
                pass

        user_message = f"""# 目标信息
{target_summary}
{kb_section}
{wiki_section}
{recorded_section}
# 已有发现
{findings_summary}

# 已有计划
{existing_plans}
"""

        if human_hint:
            user_message += f"\n# 人类参考信息\n{human_hint}\n"

        user_message += """
请分析以上目标并制定攻击计划。

你可以使用 WebSearch 搜索目标相关的已知漏洞信息。
**你绝不直接对目标执行任何攻击操作**（不 curl、不 sqlmap、不探测 payload）。
发现漏洞线索后，将其写入攻击计划中，由 Attack Agent 去执行。

分析完成后，输出攻击计划。"""

        # 2. 持久会话 + 框架级 Guidance Loop
        # 先保存原始设置，finally 中恢复
        _orig_is_solved = self.llm._guidance_is_solved
        _orig_build = self.llm._guidance_build_query
        _orig_max_rounds = self.llm.max_guidance_rounds
        _orig_disallowed = self.llm.disallowed_tools

        # Plan Agent 只用 WebSearch 做信息搜集，不直接与目标交互
        self.llm.disallowed_tools = list(set(_orig_disallowed) | {"Bash", "WebFetch"})
        self.llm.max_guidance_rounds = 3
        self.llm._guidance_is_solved = self._guidance_check_solved
        self.llm._guidance_build_query = self._guidance_build_query
        self._last_user_message = user_message

        await self.llm._ensure_connected(
            system_prompt=self.system_prompt, output_format=PLANS_OUTPUT_SCHEMA
        )
        plans: List[AttackPlan] = []
        try:
            result = await self.llm.query(user_message, output_format=PLANS_OUTPUT_SCHEMA)

            # 3. 解析结果
            structured = result.get("structured") or {}
            plans_data = structured.get("plans", [])
            if plans_data:
                plans = self._parse_plans_from_data(plans_data, ctx)

            if not plans:
                text = result.get("text", "")
                if text:
                    log_plan_event("结构化输出为空，回退文本解析", level=logging.WARNING)
                    plans = self._parse_plans_from_response(text, ctx)

        finally:
            # 4. 清理：断开持久会话 + 恢复 LLM 默认设置
            await self.llm.reset_session()
            self.llm.max_guidance_rounds = _orig_max_rounds
            self.llm._guidance_is_solved = _orig_is_solved
            self.llm._guidance_build_query = _orig_build
            self.llm.disallowed_tools = _orig_disallowed

        log_plan_event(f"生成 {len(plans)} 个攻击计划", f"plans={[p.title for p in plans]}")
        return plans

    def _guidance_check_solved(self, result: Dict[str, Any]) -> bool:
        """Guidance Loop 完成条件：输出包含有效 plans 数组"""
        structured = result.get("structured") or {}
        return bool(structured.get("plans"))

    def _guidance_build_query(
        self, result: Dict[str, Any], round_count: int
    ) -> Tuple[str, bool]:
        """未输出有效计划时，构造重试指导"""
        structured = result.get("structured") or {}
        if structured.get("plans"):
            return ("", True)

        text = result.get("text", "")
        guidance_msg = (
            "上一轮没有输出有效的攻击计划。请重新分析目标，"
            "并使用工具的返回值制定至少 2 个具体的攻击计划。\n\n"
            f"原始目标信息:\n{self._last_user_message}\n\n"
            f"你上一轮的回复:\n{text[:2000]}"
        )
        return (guidance_msg, False)

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

        # 检查上轮 Agent 是否全部执行失败（崩溃/超时/无发现）
        if ctx.agent_results:
            # 找出本轮的 agent results（plan_id 在现有 plans 中且有对应）
            plan_ids = {p.id for p in ctx.plans}
            round_results = [r for r in ctx.agent_results if r.plan_id in plan_ids]
            # 如果本轮有 2+ 个 agent 且全部失败 → 执行层出问题，强制重规划
            if len(round_results) >= 2 and all(
                r.status == AgentStatus.FAILED for r in round_results[-3:]
            ):
                reasons = "; ".join(
                    f"{r.agent_id}: {r.error or '超时'}" for r in round_results[-3:]
                )
                return {"action": "replan", "reason": f"本轮 Agent 全部执行失败: {reasons}"}

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
        """构建已有计划摘要（含执行结果）"""
        if not ctx.plans:
            return "暂无计划"
        lines = []
        for p in ctx.plans:
            line = f"- [{p.status.value}] {p.id}: {p.title}"
            # 找到对应的 agent result，拼接执行结果
            for r in ctx.agent_results:
                if r.plan_id == p.id:
                    if r.status == AgentStatus.FOUND_FLAG:
                        line += " ✅ 已找到 Flag"
                    elif r.status == AgentStatus.FAILED:
                        reason = r.error or "执行超时"
                        if r.findings:
                            reason += f"（有 {len(r.findings)} 个发现但未利用）"
                        line += f" ❌ {reason}"
                    break
            lines.append(line)
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