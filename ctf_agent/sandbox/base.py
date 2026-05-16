"""执行器基类"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class ExecutionResult:
    """命令执行结果"""
    exit_code: int
    stdout: str
    stderr: str
    command: str
    timed_out: bool = False
    container_name: str = ""


class BaseExecutor(ABC):
    """执行器抽象基类"""

    @abstractmethod
    def execute(
        self,
        command: str,
        *,
        timeout: int = 60,
        workdir: Optional[str] = None,
        caller: str = "",
    ) -> ExecutionResult:
        ...

    @abstractmethod
    def is_available(self) -> bool:
        ...

    @property
    @abstractmethod
    def name(self) -> str:
        ...


__all__ = ["ExecutionResult", "BaseExecutor"]