"""沙箱执行器：Docker 隔离 + Local 回退"""
from .base import ExecutionResult, BaseExecutor
from .factory import get_executor, ensure_sandbox, shutdown_sandbox

__all__ = ["ExecutionResult", "BaseExecutor", "get_executor", "ensure_sandbox", "shutdown_sandbox"]