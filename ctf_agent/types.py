"""
核心数据结构 - Target Model
=============================

追踪目标状态：信息收集结果、攻击计划、发现、Agent 执行状态。

设计思路：
- 统一的 ChallengeContext 贯穿 Run → Plan → Attack 全流程
- 支持 JSON 序列化/反序列化，通过文件系统在进程间共享状态
- AttackPlan 包含 hypothesis 和 approach，明确每个计划要验证什么
- Finding 覆盖 endpoint/vulnerability/credential/flag 等类型
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Dict, List, Optional
from urllib.parse import urlparse

# 北京时间 (UTC+8)
BJT = timezone(timedelta(hours=8))


def _now_bjt() -> str:
    """获取当前北京时间字符串"""
    return datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S")


# ==================== 枚举 ====================


class PlanStatus(str, Enum):
    """攻击计划状态：待执行 / 执行中 / 已验证可行 / 已验证不可行"""
    PENDING = "pending"
    RUNNING = "running"
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class FindingType(str, Enum):
    """发现类型：端点 / 漏洞 / 凭证 / Flag / 技术栈 / 信息"""
    ENDPOINT = "endpoint"
    VULNERABILITY = "vulnerability"
    CREDENTIAL = "credential"
    FLAG = "flag"
    TECH = "tech_stack"
    INFO = "info"


class AgentStatus(str, Enum):
    """Agent 执行状态"""
    IDLE = "idle"
    RUNNING = "running"
    FOUND_FLAG = "found_flag"
    FAILED = "failed"
    BLOCKED = "blocked"


class Severity(str, Enum):
    """严重级别"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ==================== 核心数据类 ====================


@dataclass
class TargetInfo:
    """目标基本信息"""

    url: str
    ip: str = ""
    ports: List[int] = field(default_factory=lambda: [80])
    protocol: str = "http"

    @classmethod
    def from_url(cls, url: str) -> "TargetInfo":
        """从 URL 字符串构造 TargetInfo

        自动补全 scheme 和端口，提取 host 信息。
        """
        if not url.startswith(("http://", "https://")):
            url = f"http://{url}"
        parsed = urlparse(url)
        return cls(
            url=url,
            ip=parsed.hostname or "127.0.0.1",
            ports=[parsed.port or (443 if parsed.scheme == "https" else 80)],
            protocol=parsed.scheme,
        )

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TechStack:
    """技术栈信息"""
    server: str = ""
    language: str = ""
    framework: str = ""
    database: str = ""
    os: str = ""
    middleware: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {k: v for k, v in asdict(self).items() if v}


@dataclass
class Finding:
    """关键发现（漏洞 / 凭证 / Flag 等）

    - confidence: 置信度 0-100
    - evidence: 支撑证据（HTTP 响应、源码行号等）
    """

    type: FindingType
    title: str
    description: str = ""
    severity: Severity = Severity.INFO
    confidence: float = 0.0
    evidence: str = ""
    endpoint: str = ""
    created_at: str = field(default_factory=_now_bjt)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["type"] = self.type.value
        d["severity"] = self.severity.value
        return d


@dataclass
class AttackPlan:
    """攻击计划

    由 Plan Agent 生成，Attack Agent 执行。
    - hypothesis: 攻击假设（怀疑存在什么漏洞，为什么）
    - approach: 具体实施方法（含 Payload、端点、步骤）
    - priority: 优先级（0 最高，数字越大越不优先）
    """

    id: str
    title: str
    hypothesis: str
    approach: str
    priority: int = 0
    status: PlanStatus = PlanStatus.PENDING
    prerequisites: List[str] = field(default_factory=list)
    expected_outcome: str = ""
    created_at: str = field(default_factory=_now_bjt)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        return d


@dataclass
class AgentResult:
    """单个 Agent 执行结果"""

    agent_id: str
    plan_id: str
    status: AgentStatus
    flag: Optional[str] = None
    findings: List[Finding] = field(default_factory=list)
    summary: str = ""
    steps_taken: int = 0
    error: str = ""
    started_at: str = field(default_factory=_now_bjt)
    finished_at: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["findings"] = [f.to_dict() for f in self.findings]
        return d


@dataclass
class ChallengeContext:
    """完整题目上下文 - Target Model 核心

    一个 ChallengeContext 实例贯穿一道题的完整生命周期：
    Runner 创建 → Plan Agent 分析 → Attack Agent 执行 → 结果归档。
    通过 .save() / .load() 在文件系统上持久化。
    """

    challenge_id: str
    target: TargetInfo
    tech_stack: TechStack = field(default_factory=TechStack)
    findings: List[Finding] = field(default_factory=list)
    plans: List[AttackPlan] = field(default_factory=list)
    agent_results: List[AgentResult] = field(default_factory=list)
    notes: str = ""
    created_at: str = field(default_factory=_now_bjt)
    updated_at: str = field(default_factory=_now_bjt)

    def add_finding(self, finding: Finding):
        """添加发现并更新时间戳"""
        self.findings.append(finding)
        self.updated_at = _now_bjt()

    def add_plan(self, plan: AttackPlan):
        """添加计划并更新时间戳"""
        self.plans.append(plan)
        self.updated_at = _now_bjt()

    def get_flag(self) -> Optional[str]:
        """获取已发现的 Flag"""
        for r in self.agent_results:
            if r.flag:
                return r.flag
        for f in self.findings:
            if f.type == FindingType.FLAG:
                return f.description
        return None

    def get_active_plans(self) -> List[AttackPlan]:
        """获取待执行的计划（按优先级排序）"""
        active = [p for p in self.plans if p.status == PlanStatus.PENDING]
        active.sort(key=lambda p: p.priority)
        return active

    def to_dict(self) -> dict:
        return {
            "challenge_id": self.challenge_id,
            "target": self.target.to_dict(),
            "tech_stack": self.tech_stack.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "plans": [p.to_dict() for p in self.plans],
            "agent_results": [r.to_dict() for r in self.agent_results],
            "notes": self.notes,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
        }

    def save(self, path: str):
        """保存到 JSON 文件"""
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.to_dict(), f, ensure_ascii=False, indent=2)

    @classmethod
    def load(cls, path: str) -> "ChallengeContext":
        """从 JSON 文件加载"""
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

        ctx = cls(
            challenge_id=data["challenge_id"],
            target=TargetInfo(**data["target"]),
        )
        ctx.tech_stack = TechStack(**data.get("tech_stack", {}))
        ctx.findings = [Finding(**f) for f in data.get("findings", [])]
        ctx.plans = [AttackPlan(**p) for p in data.get("plans", [])]
        for r_data in data.get("agent_results", []):
            r = AgentResult(
                agent_id=r_data["agent_id"],
                plan_id=r_data["plan_id"],
                status=AgentStatus(r_data["status"]),
                flag=r_data.get("flag"),
                summary=r_data.get("summary", ""),
                steps_taken=r_data.get("steps_taken", 0),
                error=r_data.get("error", ""),
                started_at=r_data.get("started_at", ""),
                finished_at=r_data.get("finished_at", ""),
            )
            r.findings = [Finding(**f) for f in r_data.get("findings", [])]
            ctx.agent_results.append(r)
        ctx.notes = data.get("notes", "")
        ctx.created_at = data.get("created_at", _now_bjt())
        ctx.updated_at = data.get("updated_at", _now_bjt())
        return ctx


__all__ = [
    "PlanStatus", "FindingType", "AgentStatus", "Severity",
    "TargetInfo", "TechStack", "Finding", "AttackPlan",
    "AgentResult", "ChallengeContext",
]