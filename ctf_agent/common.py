"""
通用工具与日志
==============

提供日志记录、时间工具等公共功能。
日志格式与 CHYing-agent 类似，带颜色分类输出。
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime, timezone, timedelta
from typing import Optional

# 北京时间 (UTC+8)
BJT = timezone(timedelta(hours=8))

LOG_FORMAT = "%(asctime)s [%(levelname)s] | %(message)s"
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"

# 终端颜色
_RESET = "\033[0m"
_LEVEL_STYLES = {
    "DEBUG": "\033[37m",
    "INFO": "\033[38;2;180;250;114m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
}
_CATEGORY_STYLES = {
    "SYSTEM": "\033[94m",    # 蓝色
    "PLAN": "\033[95m",      # 紫色
    "ATTACK": "\033[96m",    # 青色
    "FINDING": "\033[92m",   # 绿色
    "STATE": "\033[93m",     # 黄色
}


def _color_supported() -> bool:
    return sys.stdout.isatty()


_COLOR = _color_supported()


def now_str() -> str:
    """获取当前北京时间字符串"""
    return datetime.now(BJT).strftime("%Y-%m-%d %H:%M:%S")


# 全局 logger（单例）
_logger: Optional[logging.Logger] = None


def get_logger() -> logging.Logger:
    """获取全局 logger"""
    global _logger
    if _logger is not None:
        return _logger

    _logger = logging.getLogger("CTFAgent")
    _logger.setLevel(logging.INFO)
    _logger.handlers.clear()

    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))
    _logger.addHandler(handler)
    _logger.propagate = False
    return _logger


def _log(category: str, title: str, payload: Optional[str] = None, *, level: int = logging.INFO):
    """统一日志入口"""
    logger = get_logger()
    style = _CATEGORY_STYLES.get(category, "")
    label = f"{style}[{category}]{_RESET}" if _COLOR and style else f"[{category}]"

    if payload:
        message = f"{label} {title} | {payload}"
    else:
        message = f"{label} {title}"

    logger.log(level, message)


def log_system_event(title: str, payload: Optional[str] = None, *, level: int = logging.INFO):
    """记录系统事件"""
    _log("SYSTEM", title, payload, level=level)


def log_plan_event(title: str, payload: Optional[str] = None, *, level: int = logging.INFO):
    """记录 Plan Agent 事件"""
    _log("PLAN", title, payload, level=level)


def log_attack_event(title: str, payload: Optional[str] = None, *, level: int = logging.INFO):
    """记录 Attack Agent 事件"""
    _log("ATTACK", title, payload, level=level)


def log_finding_event(title: str, payload: Optional[str] = None, *, level: int = logging.INFO):
    """记录发现"""
    _log("FINDING", title, payload, level=level)


__all__ = [
    "now_str", "get_logger",
    "log_system_event", "log_plan_event", "log_attack_event", "log_finding_event",
]