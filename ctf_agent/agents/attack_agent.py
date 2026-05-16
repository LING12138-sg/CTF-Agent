"""
Attack Agent - 漏洞利用执行智能体
===================================

基于 claude-agent-sdk 的 Attack Agent，通过 LLMBase 使用 Claude Code CLI
内置工具（Bash、Read、Write 等）和 MCP 工具执行攻击。

职责：
1. 接收一个 AttackPlan，通过 LLM 工具调用真正执行攻击
2. 使用 SDK 内置工具（bash、文件读写）和 MCP 工具与目标交互
3. 尝试 2-3 个变体如果初始方法不成功
4. 发现 Flag 立即返回
5. 遇到新方向时 Quick Check 后再汇报

赛马机制：
- 多个 Attack Agent 并行执行不同 Plan
- 第一个返回 Flag 的获胜
- 通过 ChallengeContext 共享发现
"""

from __future__ import annotations

import asyncio
import logging
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Optional

from ..brain.prompts import get_attack_prompt
from ..common import log_attack_event, log_finding_event, now_str
from ..llm.base import LLMBase
from ..llm.schemas import ORCHESTRATOR_OUTPUT_SCHEMA
from ..types import (
    AgentResult, AgentStatus, AttackPlan, ChallengeContext,
    Finding, FindingType, Severity,
)
from .base import BaseAgent


class AttackAgent(BaseAgent):
    """攻击执行智能体

    每个实例独立执行一个 AttackPlan。
    内部创建带工具权限的 LLMBase 实例，通过 SDK 内置工具执行攻击。
    """

    def __init__(
        self,
        llm_client: LLMBase,
        agent_id: str,
        plan: AttackPlan,
        ctx: ChallengeContext,
        timeout: int = 600,
        mcp_path: str = "",
        attack_max_turns: int = 50,
        logs_dir: str = "",
    ):
        super().__init__(llm_client, agent_id, ctx.challenge_id)
        self.plan = plan
        self.ctx = ctx
        self.timeout = timeout
        self.mcp_path = mcp_path
        self.attack_max_turns = attack_max_turns
        self.logs_dir = logs_dir
        self.findings: List[Finding] = []

        # 保存 LLM 配置供工具 Agent 使用
        self._model = llm_client.model
        self._api_key = llm_client.api_key
        self._base_url = llm_client.base_url
        self._shared_dir = getattr(llm_client, 'shared_dir', '')

    async def execute(self) -> AgentResult:
        """执行攻击计划

        Returns:
            AgentResult: 执行结果
        """
        start_time = time.time()
        log_attack_event(
            f"开始执行 Plan: {self.plan.id}",
            f"{self.plan.title} | target={self.ctx.target.url}",
        )

        try:
            result = await asyncio.wait_for(
                self._run_attack(),
                timeout=self.timeout,
            )
            return result
        except asyncio.TimeoutError:
            elapsed = int(time.time() - start_time)
            log_attack_event(f"Attack Agent 超时", f"timeout={self.timeout}s elapsed={elapsed}s")
            return AgentResult(
                agent_id=self.agent_id,
                plan_id=self.plan.id,
                status=AgentStatus.FAILED,
                error=f"执行超时 ({self.timeout}s)",
                findings=self.findings,
                started_at=now_str(),
                finished_at=now_str(),
            )

    async def _run_attack(self) -> AgentResult:
        """核心攻击逻辑

        创建带工具权限的 LLMBase 实例，通过 Claude Code CLI 内置工具
        （Bash、Read、Write、Glob、Grep 等）和 MCP 工具执行攻击。
        SDK 自动处理工具调用循环，Agent 只需要描述攻击步骤。
        """
        target_info = self.ctx.target

        # 构建上下文
        findings_context = ""
        if self.ctx.findings:
            findings_context = "\n已有发现:\n" + "\n".join(
                f"- [{f.severity.value}] {f.title}: {f.description}"
                for f in self.ctx.findings[-5:]
            )

        user_message = f"""## 目标
{target_info.url} | IP: {target_info.ip} | 端口: {target_info.ports}
{self._build_tech_guidance()}

## 攻击计划
标题: {self.plan.title}
假设: {self.plan.hypothesis}
方法: {self.plan.approach}
{findings_context}

## 规则
1. 逐步执行，每步报告结果
2. 初始方法不奏效时尝试 2-3 个变体
3. 找到 flag 时，在最终结构化输出中设置 success=true 并填入 flag 值
4. 全部失败时，设置 success=false 并在 blocked_reason 中说明原因
5. 重要发现用 record_key_finding 记录
6. 每条新发现请在最终结构化输出的 findings 数组中描述

## 当前题目路径
题目标识: {self.ctx.challenge_id}
Python: .venv/Scripts/python.exe（勿用 python3/python）
脚本目录: scripts/{self.ctx.challenge_id}/
Writeup: wp/{self.ctx.challenge_id}/
附件: challenges/{self.ctx.challenge_id}/"""

        # system_prompt 从 prompts/ 文件加载（纯静态）
        system_prompt = get_attack_prompt()

        # 构造实时日志文件路径（每个 Agent 独立，赛马不冲突）
        log_file = ""
        if self.logs_dir:
            log_dir = Path(self.logs_dir)
            log_dir.mkdir(parents=True, exist_ok=True)
            log_file = str(log_dir / f"{self.agent_id}_{self.plan.id}.log")

        log_attack_event(
            f"启动 SDK 工具 Agent", f"{self.plan.id} | log={log_file or '(none)'}"
        )

        # 创建带工具权限的 LLMBase 实例（通过 Executor 统一管理工具调用）
        tool_agent = LLMBase(
            model=self._model,
            api_key=self._api_key,
            base_url=self._base_url,
            system_prompt=system_prompt,
            max_turns=self.attack_max_turns,
            permission_mode="bypassPermissions",
            agent_label=self.agent_id,
            mcp_servers=self.mcp_path if self.mcp_path else None,
            log_file=log_file or None,
            use_executor=True,
            shared_dir=self._shared_dir,
            output_format=ORCHESTRATOR_OUTPUT_SCHEMA,
        )

        try:
            result = await tool_agent.execute_structured(
                user_message,
                output_format=ORCHESTRATOR_OUTPUT_SCHEMA,
            )
        except Exception as e:
            log_attack_event(f"LLM 调用异常", str(e), level=logging.WARNING)
            return AgentResult(
                agent_id=self.agent_id,
                plan_id=self.plan.id,
                status=AgentStatus.FAILED,
                error=str(e),
                findings=self.findings,
                started_at=now_str(),
                finished_at=now_str(),
            )

        response = result.get("text", "")
        structured = result.get("structured") or {}

        # 解析结果：优先结构化输出，失败回退正则
        flag = structured.get("flag") or self._extract_flag(response)
        gave_up = not flag and (structured.get("blocked_reason") or self._extract_give_up(response))

        raw_findings = structured.get("findings", [])
        findings = self._findings_from_structured(raw_findings) if raw_findings else self._extract_findings(response)
        self.findings.extend(findings)

        if flag:
            log_finding_event(f"Flag 已找到!", f"agent={self.agent_id} plan={self.plan.id}")
            self.findings.append(Finding(
                type=FindingType.FLAG,
                title="Flag 已找到",
                description=flag,
                severity=Severity.CRITICAL,
                confidence=100.0,
                evidence=response[:500],
            ))
            return AgentResult(
                agent_id=self.agent_id,
                plan_id=self.plan.id,
                status=AgentStatus.FOUND_FLAG,
                flag=flag,
                findings=self.findings,
                summary=structured.get("summary", "攻击成功，Flag 已找到"),
                steps_taken=1,
                started_at=now_str(),
                finished_at=now_str(),
            )

        if gave_up:
            reason = structured.get("blocked_reason") or self._extract_give_up(response) or "未知原因"
            log_attack_event(f"攻击放弃", f"agent={self.agent_id} reason={reason}")
            return AgentResult(
                agent_id=self.agent_id,
                plan_id=self.plan.id,
                status=AgentStatus.FAILED,
                findings=self.findings,
                summary=f"放弃: {reason}",
                steps_taken=1,
                started_at=now_str(),
                finished_at=now_str(),
            )

        return AgentResult(
            agent_id=self.agent_id,
            plan_id=self.plan.id,
            status=AgentStatus.FAILED,
            findings=self.findings,
            summary=structured.get("summary", "执行完毕，未找到 Flag"),
            steps_taken=1,
            started_at=now_str(),
            finished_at=now_str(),
        )

    @staticmethod
    def _findings_from_structured(findings_data: List[Dict]) -> List[Finding]:
        """从结构化输出解析发现列表"""
        results = []
        for fd in findings_data:
            if not isinstance(fd, dict):
                continue
            ftype_str = fd.get("type", "info")
            try:
                ftype = FindingType(ftype_str.lower())
            except ValueError:
                ftype = FindingType.INFO
            results.append(Finding(
                type=ftype,
                title=(fd.get("description", "") or "")[:80],
                description=fd.get("description", ""),
                confidence=float(fd.get("confidence", 50)),
            ))
        return results

    @staticmethod
    def _extract_flag(text: str) -> Optional[str]:
        """从 LLM 输出中提取 Flag（正则回退）"""
        patterns = [
            r"FOUND_FLAG:\s*(flag\{[^}]+\})",
            r"FLAG:\s*(flag\{[^}]+\})",
            r"(flag\{[^}]+\})",
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1)
        return None

    @staticmethod
    def _extract_give_up(text: str) -> Optional[str]:
        """提取放弃原因（正则回退）"""
        match = re.search(r"GIVE_UP:\s*(.+?)(?:\n|$)", text)
        return match.group(1).strip() if match else None

    @staticmethod
    def _extract_findings(text: str) -> List[Finding]:
        """提取行内发现的 FINDING 信息（正则回退）"""
        findings = []
        for match in re.finditer(r"FINDING:\s*(\w+)\s*\|\s*(.+?)(?:\n|$)", text):
            ftype_str, desc = match.group(1), match.group(2).strip()
            try:
                ftype = FindingType(ftype_str.lower())
            except ValueError:
                ftype = FindingType.INFO
            findings.append(Finding(
                type=ftype,
                title=desc[:80],
                description=desc,
                confidence=50.0,
            ))
        return findings

    def _build_tech_guidance(self) -> str:
        """根据技术栈提供针对性指导"""
        ts = self.ctx.tech_stack
        guidance = []
        if "php" in (ts.language or "").lower():
            guidance.append("- PHP: 关注文件包含、反序列化、LFI/RFI")
        if "java" in (ts.language or "").lower():
            guidance.append("- Java: 关注 SSTI、表达式注入、反序列化")
        if "go" in (ts.language or "").lower():
            guidance.append("- Go: 关注 SSTI、路径遍历")
        if "sqlite" in (ts.database or "").lower():
            guidance.append("- SQLite: ATTACH DATABASE, VACUUM INTO 可写文件")
        if "mysql" in (ts.database or "").lower():
            guidance.append("- MySQL: 关注 SQL 注入、文件读写")
        return "\n".join(guidance)


__all__ = ["AttackAgent"]