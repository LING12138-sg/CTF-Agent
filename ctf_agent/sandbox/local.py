"""LocalExecutor — 本地直接执行（回退方案）"""
from __future__ import annotations

import logging
import os
import subprocess
from typing import Optional

from .base import BaseExecutor, ExecutionResult

_logger = logging.getLogger(__name__)

# ── 安全拦截（与 executor/tools.py 同步） ──
_BLOCKED_PATTERNS = [
    "rm -rf /",
    "rm -rf ~",
    "mkfs",
    "dd if=",
    ":(){",
    "> /dev/",
    "| shutdown",
    "| reboot",
    "| poweroff",
    "> /dev/sd",
]


class LocalExecutor(BaseExecutor):
    """本地 subprocess 执行器

    没有 Docker 隔离，直接在宿主机执行命令。
    作为 Docker 不可用时的回退方案。
    """

    def __init__(self, cwd: Optional[str] = None):
        self._cwd = cwd or os.getcwd()
        self._container_name = "(local)"

    @property
    def name(self) -> str:
        return "local"

    def is_available(self) -> bool:
        return True

    def execute(
        self,
        command: str,
        *,
        timeout: int = 60,
        workdir: Optional[str] = None,
        caller: str = "",
    ) -> ExecutionResult:
        """同步执行命令（在线程池中调用，不阻塞事件循环）"""
        # 安全拦截
        cmd_lower = command.lower()
        for pattern in _BLOCKED_PATTERNS:
            if pattern.lower() in cmd_lower:
                return ExecutionResult(
                    exit_code=-1,
                    stdout="",
                    stderr=f"[BLOCKED] 命令包含禁止模式: {pattern}",
                    command=command,
                    container_name=self._container_name,
                )

        try:
            result = subprocess.run(
                ["bash", "-c", command],
                capture_output=True,
                timeout=timeout,
                cwd=workdir or self._cwd,
            )
            return ExecutionResult(
                exit_code=result.returncode,
                stdout=result.stdout.decode("utf-8", errors="replace").strip(),
                stderr=result.stderr.decode("utf-8", errors="replace").strip(),
                command=command,
                container_name=self._container_name,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"[TIMEOUT] 命令执行超时 ({timeout}s)",
                command=command,
                timed_out=True,
                container_name=self._container_name,
            )
        except FileNotFoundError:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr="[ERROR] bash not found",
                command=command,
                container_name=self._container_name,
            )
        except Exception as e:
            return ExecutionResult(
                exit_code=-1,
                stdout="",
                stderr=f"[ERROR] {e}",
                command=command,
                container_name=self._container_name,
            )