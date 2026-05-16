"""沙箱执行器工厂 — 自动检测 Docker 可用性并选择最佳执行器"""
from __future__ import annotations

import logging
import os
from typing import Optional

from .base import BaseExecutor

_logger = logging.getLogger(__name__)

# 全局单例
_executor: Optional[BaseExecutor] = None


def get_executor() -> BaseExecutor:
    """获取沙箱执行器（单例，懒加载）

    优先级：
    1. SANDBOX_MODE=local → 强制本地执行
    2. Docker 可用 → DockerExecutor（自动创建 Kali 容器）
    3. 回退 → LocalExecutor
    """
    global _executor

    if _executor is not None:
        return _executor

    mode = os.getenv("SANDBOX_MODE", "auto").lower()

    # ── 强制本地模式 ──
    if mode == "local":
        _logger.info("[Sandbox] SANDBOX_MODE=local，使用本地执行器")
        from .local import LocalExecutor
        _executor = LocalExecutor()
        return _executor

    # ── Docker 模式（默认 / auto） ──
    try:
        docker_avail = False
        try:
            import docker  # noqa: F401
            docker_avail = True
        except ImportError:
            pass

        if not docker_avail:
            if mode == "docker":
                raise RuntimeError(
                    "SANDBOX_MODE=docker 但 docker Python SDK 未安装。"
                    "请运行: pip install docker"
                )
            _logger.info("[Sandbox] docker SDK 未安装，回退到本地执行")
            raise ImportError("skip")

        from .docker import DockerExecutor

        executor = DockerExecutor()
        status = executor.ensure_running()
        _logger.info("[Sandbox] DockerExecutor 就绪: %s", status)
        _executor = executor
        return executor

    except Exception as e:
        msg = str(e)
        if "skip" in msg:
            pass  # 预期回退
        elif mode == "docker":
            raise RuntimeError(
                f"Docker 模式初始化失败: {e}\n"
                "请确保:\n"
                "1. Docker 已安装并运行\n"
                "2. pip install docker\n"
                "3. 或设置 SANDBOX_MODE=local 跳过 Docker"
            ) from e
        else:
            _logger.warning("[Sandbox] Docker 不可用 (%s)，回退本地执行", e)

        from .local import LocalExecutor
        _executor = LocalExecutor()
        return _executor


def ensure_sandbox() -> str:
    """确保沙箱就绪，返回状态描述"""
    ex = get_executor()
    if ex.name.startswith("docker"):
        from .docker import DockerExecutor
        assert isinstance(ex, DockerExecutor)
        return ex.ensure_running()
    return f"本地执行器 (无隔离)"


def shutdown_sandbox():
    """关闭沙箱（停止 Docker 容器）"""
    global _executor
    if _executor is not None and _executor.name.startswith("docker"):
        try:
            from .docker import DockerExecutor
            assert isinstance(_executor, DockerExecutor)
            _executor.stop()
        except Exception:
            pass
    _executor = None
