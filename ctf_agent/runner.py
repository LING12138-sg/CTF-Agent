"""
Runner - 主编排器
==================

负责完整 Pipeline 编排：
1. 创建 ChallengeContext
2. Plan Agent 分析目标 → 生成计划
3. Attack Agent 并行执行（赛马）
4. 收集结果 → Plan Agent 评审 → 重规划 / 继续 / 停止
5. 输出最终结果

使用 Plan-Attack 双层架构替代单 Orchestrator 模式。
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

from .agents.attack_agent import AttackAgent
from .agents.quick_check import QuickCheckAgent
from .brain.plan_agent import PlanAgent
from .common import log_finding_event, log_system_event, now_str
from .config import AgentConfig, LLMConfig, get_default_state_path
from .llm.base import LLMBase
from .types import (
    AgentResult, AgentStatus, AttackPlan, ChallengeContext,
    Finding, FindingType, PlanStatus, Severity, TargetInfo,
)
from .utils.http import get_with_retry, probe_endpoint


class Runner:
    """主编排器

    管理一道题的完整生命周期。

    示例：
        runner = Runner(target_url="http://example.com:8080")
        result = runner.run()
        print(result.get("flag"))
    """

    def __init__(
        self,
        target_url: str,
        challenge_id: str = "",
        config: Optional[AgentConfig] = None,
        human_prompt: str = "",
    ):
        self.config = config or AgentConfig.from_env()
        self.target_url = target_url
        self.challenge_id = challenge_id or self._make_challenge_id(target_url)
        self.human_prompt = human_prompt

        # LLM 客户端（共享实例，供 PlanAgent / QuickCheckAgent 使用）
        llm_config = self.config.llm
        logs_dir = self.config.paths.logs_dir
        logs_dir.mkdir(parents=True, exist_ok=True)
        self.llm = LLMBase(
            api_key=llm_config.api_key,
            base_url=llm_config.base_url,
            model=llm_config.model,
            agent_label="runner",
            log_file=str(logs_dir / "plan_agent.log"),
        )

        # 上下文
        self.ctx = ChallengeContext(
            challenge_id=self.challenge_id,
            target=TargetInfo.from_url(target_url),
        )

        # 子组件
        self.plan_agent = PlanAgent(self.llm, self.challenge_id)
        self.quick_check = QuickCheckAgent(self.llm, self.challenge_id)

        # 状态
        self.state_path = get_default_state_path(self.challenge_id)
        self.results: List[AgentResult] = []

    def run(self) -> Dict:
        """运行完整 Pipeline（同步接口）"""
        return asyncio.run(self._run_pipeline())

    async def _run_pipeline(self) -> Dict:
        """异步 Pipeline 主循环"""
        log_system_event("=" * 60)
        log_system_event(f"开始解题: {self.challenge_id}")
        log_system_event(f"目标: {self.target_url}")
        log_system_event("=" * 60)

        # ==================== Phase 1: 自动侦察 ====================
        await self._do_recon()

        # ==================== Phase 2: Plan → Attack 循环 ====================
        plan_round = 0
        max_rounds = self.config.runner.max_plan_rounds

        while plan_round < max_rounds:
            plan_round += 1
            log_system_event(f"--- Plan-Attack Round {plan_round}/{max_rounds} ---")

            # Step 1: Plan Agent 生成计划
            plans = await self.plan_agent.analyze_and_plan(
                self.ctx,
                human_hint=self.human_prompt if plan_round == 1 else "",
            )

            if not plans:
                log_system_event("Plan Agent 未生成新计划")
                break

            for p in plans:
                self.ctx.add_plan(p)
            self._save_state()

            # Step 2: Attack Agent 并行执行（赛马）
            results = await self._race_attackers(plans)

            # Step 3: 收集发现
            new_findings: List[Finding] = []
            for r in results:
                self.results.append(r)
                self.ctx.agent_results.append(r)
                new_findings.extend(r.findings)

                if r.flag:
                    log_finding_event(f"Flag 已找到!", r.flag)
                    self._save_state()
                    return {
                        "success": True,
                        "flag": r.flag,
                        "agent": r.agent_id,
                        "plan": r.plan_id,
                        "summary": r.summary,
                    }

            # Step 4: Plan Agent 评审
            review = await self.plan_agent.review_findings(self.ctx, new_findings)
            log_system_event(f"Plan Agent 评审: {review['action']} | {review['reason']}")

            if review["action"] == "stop":
                break
            if review["action"] == "replan":
                continue  # 进入下一轮规划

        # ==================== Phase 3: 输出结果 ====================
        flag = self.ctx.get_flag()
        self._save_state()

        log_system_event("=" * 60)
        if flag:
            log_system_event(f"Flag: {flag}")
        else:
            log_system_event("未找到 Flag")
        log_system_event("=" * 60)

        return {
            "success": bool(flag),
            "flag": flag,
            "findings_count": len(self.ctx.findings),
            "plans_tried": len(self.ctx.plans),
            "agent_results": len(self.ctx.agent_results),
        }

    async def _do_recon(self):
        """自动侦察阶段

        类似 CHYing-agent 的 auto_recon_web_target，
        在 Agent 决策前先收集基础信息。
        """
        target = self.ctx.target
        log_system_event(f"开始自动侦察: {target.url}")

        # 1. 基础探测
        result = probe_endpoint(target.url)
        if result.get("error"):
            log_system_event(f"侦察失败", result["error"], level=logging.WARNING)
            return

        # 2. 提取技术栈
        headers = result.get("headers", {})
        server = headers.get("Server", "")
        content_type = headers.get("Content-Type", "")

        self.ctx.tech_stack.server = server

        if "php" in server.lower():
            self.ctx.tech_stack.language = "PHP"
        elif "python" in content_type.lower() or "wsgi" in server.lower():
            self.ctx.tech_stack.language = "Python"
        elif "java" in server.lower() or "tomcat" in server.lower():
            self.ctx.tech_stack.language = "Java"
        elif "go" in server.lower() or "gin" in server.lower():
            self.ctx.tech_stack.language = "Go"

        log_system_event(f"技术栈: {self.ctx.tech_stack.server} / {self.ctx.tech_stack.language}")

    async def _race_attackers(self, plans: List[AttackPlan]) -> List[AgentResult]:
        """多个 Attack Agent 并行执行（赛马）

        使用 asyncio.create_task + FIRST_COMPLETED 实现赛马。
        类似 ctf-agent 的 ChallengeSwarm.run() 模式。
        """
        max_workers = self.config.runner.max_attackers
        active_plans = plans[:max_workers]

        if not active_plans:
            return []

        log_system_event(f"启动 {len(active_plans)} 个 Attack Agent 赛马")

        # MCP 配置文件路径
        mcp_json = self.config.paths.project_root / ".mcp.json"
        mcp_path = str(mcp_json) if mcp_json.exists() else ""

        # 日志目录（每个 Agent 的实时输出独立文件）
        logs_dir = str(self.config.paths.logs_dir)

        # 创建 Task（立即开始执行）
        tasks = []
        for i, plan in enumerate(active_plans):
            agent = AttackAgent(
                llm_client=self.llm,
                agent_id=f"attacker_{i + 1}",
                plan=plan,
                ctx=self.ctx,
                timeout=self.config.runner.attack_timeout,
                mcp_path=mcp_path,
                logs_dir=logs_dir,
            )
            tasks.append(asyncio.create_task(agent.execute()))

        done_results: List[AgentResult] = []
        pending = set(tasks)

        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending,
                    return_when=asyncio.FIRST_COMPLETED,
                )

                for task in done:
                    try:
                        result = task.result()
                        done_results.append(result)

                        # 某个 Agent 找到 Flag → 取消所有 pending
                        if result.status == AgentStatus.FOUND_FLAG:
                            for p in pending:
                                p.cancel()
                            return done_results
                    except Exception as e:
                        log_system_event(f"Attack Agent 异常", str(e), level=logging.ERROR)
        finally:
            # 确保所有未完成的 Task 被清理
            for t in pending:
                if not t.done():
                    t.cancel()

        return done_results

    def _save_state(self):
        """保存当前状态到 JSON 文件"""
        try:
            self.ctx.save(self.state_path)
        except Exception as e:
            log_system_event(f"保存状态失败", str(e), level=logging.WARNING)

    @staticmethod
    def _make_challenge_id(url: str) -> str:
        """从 URL 生成挑战 ID"""
        from urllib.parse import urlparse
        parsed = urlparse(url)
        host = parsed.hostname or "unknown"
        port = parsed.port or 80
        path = parsed.path.strip("/").replace("/", "_") or "root"
        return f"{host}_{port}_{path}"


__all__ = ["Runner"]