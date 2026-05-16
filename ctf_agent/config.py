"""
统一配置管理
============

集中管理所有 Agent 配置：
- LLM API 配置（从 .claude/settings.local.json 读取）
- 运行时参数（超时、并发、重试次数）
- 路径配置（shared/、state/、logs/ 等目录）

环境变量命名规范：
- ANTHROPIC_* / LLM_* : LLM API 配置
- MAX_* / ATTACK_* : 运行时参数
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


@dataclass
class LLMConfig:
    """LLM API 配置"""

    model: Optional[str] = None
    api_key: Optional[str] = None
    base_url: Optional[str] = None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        """从环境变量加载配置"""
        return cls(
            model=os.getenv("LLM_MODEL") or None,
            api_key=os.getenv("LLM_API_KEY") or None,
            base_url=os.getenv("LLM_BASE_URL") or None,
        )

    @property
    def is_configured(self) -> bool:
        """检查 API 是否已配置"""
        return bool(self.api_key)


@dataclass
class RunnerConfig:
    """运行时配置"""

    max_plan_rounds: int = 3       # Plan Agent 最大重规划次数
    max_attackers: int = 3         # 并行 Attack Agent 数量
    attack_timeout: int = 600      # 单个 Attack Agent 超时（秒）
    quick_check_timeout: int = 60  # Quick Check 超时（秒）
    max_retries: int = 2           # 最大重试次数
    concurrency: int = 5           # 总体并发数

    @classmethod
    def from_env(cls) -> "RunnerConfig":
        return cls(
            max_plan_rounds=int(os.getenv("MAX_PLAN_ROUNDS", "3")),
            max_attackers=int(os.getenv("MAX_ATTACKERS", "3")),
            attack_timeout=int(os.getenv("ATTACK_TIMEOUT", "600")),
            quick_check_timeout=int(os.getenv("QUICK_CHECK_TIMEOUT", "60")),
            max_retries=int(os.getenv("MAX_RETRIES", "2")),
            concurrency=int(os.getenv("CONCURRENCY", "5")),
        )


@dataclass
class PathConfig:
    """路径配置"""

    project_root: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent)
    shared_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "shared")
    state_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "shared" / "state")
    plans_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "shared" / "plans")
    logs_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "shared" / "logs")
    skills_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "skills")
    memory_dir: Path = field(default_factory=lambda: Path(__file__).resolve().parent.parent / "memory")


@dataclass
class SandboxConfig:
    """沙箱执行器配置"""

    mode: str = "auto"           # auto / docker / local
    image: str = "kalilinux/kali-rolling"
    container_name: str = "ctf-agent-sandbox"
    mount_target: str = "/root/agent-work"

    @classmethod
    def from_env(cls) -> "SandboxConfig":
        return cls(
            mode=os.getenv("SANDBOX_MODE", "auto"),
            image=os.getenv("SANDBOX_IMAGE", "kalilinux/kali-rolling"),
            container_name=os.getenv("SANDBOX_CONTAINER", "ctf-agent-sandbox"),
            mount_target=os.getenv("SANDBOX_MOUNT_TARGET", "/root/agent-work"),
        )


@dataclass
class AgentConfig:
    """统一配置类"""

    llm: LLMConfig
    runner: RunnerConfig
    paths: PathConfig
    sandbox: SandboxConfig

    @classmethod
    def from_env(cls) -> "AgentConfig":
        """从环境变量和 settings 文件加载配置"""
        llm = _load_api_config()
        return cls(
            llm=llm,
            runner=RunnerConfig.from_env(),
            paths=PathConfig(),
            sandbox=SandboxConfig.from_env(),
        )


def _load_api_config() -> LLMConfig:
    """从 .claude/settings.local.json 读取 API 配置

    优先读取 settings 文件，fallback 到环境变量。
    """
    settings_path = Path(__file__).resolve().parent.parent / ".claude" / "settings.local.json"
    if settings_path.exists():
        try:
            data = json.loads(settings_path.read_text(encoding="utf-8"))
            env = data.get("env", {})
            return LLMConfig(
                api_key=env.get("ANTHROPIC_AUTH_TOKEN") or None,
                base_url=env.get("ANTHROPIC_BASE_URL") or None,
                model=env.get("ANTHROPIC_MODEL") or None,
            )
        except Exception:
            pass
    return LLMConfig.from_env()


def get_default_state_path(challenge_id: str) -> str:
    """获取默认的 state JSON 文件路径"""
    paths = PathConfig()
    paths.state_dir.mkdir(parents=True, exist_ok=True)
    return str(paths.state_dir / f"{challenge_id}.json")


__all__ = [
    "LLMConfig", "RunnerConfig", "PathConfig", "AgentConfig",
    "get_default_state_path",
]