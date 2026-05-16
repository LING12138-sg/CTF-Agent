"""
停滞检测与 ABANDON 机制
=========================

跟踪 Agent 工具调用模式，检测停滞状态，维护紧凑恢复状态。
供 hooks.py 和 base.py 使用。
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


# ── 操作分类正则 ──
_RE_PATH_SCAN = re.compile(
    r"\b(curl|wget|ffuf|gobuster|dirsearch|feroxbuster|dirb|nikto)\b", re.I
)
_RE_CREDENTIAL_GUESS = re.compile(
    r"\b(hydra|medusa|john|hashcat|login|auth|brute)\b", re.I
)
_RE_CONFIG_QUERY = re.compile(
    r"\?(versioning|logging|encryption|acl|policy|cors|lifecycle)\b", re.I
)
_RE_API_VARIANT = re.compile(
    r"\bcurl\b.*\b(POST|PUT|PATCH|DELETE)\b.*(-d|--data)", re.I | re.S
)


class ReflectionTracker:
    """Agent 反射追踪器

    跟踪工具调用模式，提供：
    - 同类操作连续检测 L1（软提醒）/ L2（硬阻断）
    - 紧凑恢复状态跟踪
    - ABANDON 标记
    - Dead end 关键词匹配
    """

    # L2 硬阻断只对高重复/低语义依赖的 class 启用
    L2_ENABLED_CLASSES = frozenset({"path_scan", "config_read"})
    L1_THRESHOLD = 3
    L2_THRESHOLD = 5

    # 不参与 streak 统计的工具
    _SKIP_STREAK_TOOLS = frozenset({
        "Read", "Glob", "Grep", "Write", "Edit", "TodoWrite", "Skill",
        "WebFetch", "WebSearch", "StructuredOutput",
    })

    def __init__(self, shared_dir: str = ""):
        self.shared_dir = shared_dir

        # 工具调用历史
        self._call_history: List[Dict[str, Any]] = []

        # Streak 跟踪
        self._class_buckets: Dict[str, int] = defaultdict(int)
        self._last_class: Optional[str] = None
        self._consecutive_count: int = 0

        # 紧凑恢复状态
        self._compact_deny_remaining: int = 0  # 0=正常, 1=恢复中
        self._compact_confirmed_reads: Set[str] = set()

        # ABANDON 状态
        self._abandon_active: bool = False

        # 错误计数
        self._consecutive_errors: int = 0

        # 提示计数（防刷屏）
        self._streak_l1_warned: bool = False

    # ── 工具调用记录 ──

    def record_tool_call(self, tool_name: str, tool_input: Dict[str, Any]):
        """记录一次工具调用"""
        self._call_history.append({
            "tool": tool_name,
            "input_summary": self._summarize_input(tool_input),
            "index": len(self._call_history),
        })

    @staticmethod
    def _summarize_input(tool_input: Dict[str, Any]) -> str:
        """生成工具输入的摘要签名"""
        if not tool_input or not isinstance(tool_input, dict):
            return ""
        keys = sorted(tool_input.keys())
        return ",".join(f"{k}={str(tool_input[k])[:60]}" for k in keys[:3])

    # ── 操作分类 ──

    def classify_tool_call(self, tool_name: str, tool_input: Dict[str, Any]) -> Optional[str]:
        """对工具调用进行分类，返回 class 名称或 None（不参与分类）"""
        short = tool_name.split("__")[-1] if "__" in tool_name else tool_name

        if short in self._SKIP_STREAK_TOOLS:
            return None

        if short in ("bash", "exec", "execute_command"):
            cmd = ""
            if isinstance(tool_input, dict):
                cmd = tool_input.get("command", "") or tool_input.get("cmd", "")
            if not isinstance(cmd, str):
                return None
            if _RE_PATH_SCAN.search(cmd):
                return "path_scan"
            if _RE_CREDENTIAL_GUESS.search(cmd):
                return "credential_guess"
            if _RE_CONFIG_QUERY.search(cmd):
                return "config_read"
            if _RE_API_VARIANT.search(cmd):
                return "api_variant"
            return None

        if short in ("WebFetch", "WebSearch"):
            return "web_probe"

        # MCP 工具作为工具整体统计
        if tool_name.startswith("mcp__"):
            parts = tool_name.split("__")
            if len(parts) >= 3:
                return f"mcp:{parts[-1]}"

        return None

    def classify_and_increment(self, tool_name: str, tool_input: Dict[str, Any]):
        """分类并递增 bucket 计数"""
        cls = self.classify_tool_call(tool_name, tool_input)
        if cls is None:
            self._last_class = None
            self._consecutive_count = 0
            return

        if cls == self._last_class:
            self._consecutive_count += 1
        else:
            self._last_class = cls
            self._consecutive_count = 1
            self._streak_l1_warned = False

        self._class_buckets[cls] += 1

    # ── Streak 检测 ──

    def get_streak_l1_warning(self) -> Optional[str]:
        """L1 软提醒：同类工具连续 3+ 次（仅提醒一次）"""
        if self._last_class is None or self._consecutive_count < self.L1_THRESHOLD:
            return None
        if self._streak_l1_warned:
            return None
        self._streak_l1_warned = True
        return (
            f"⚠️ 你已经连续 {self._consecutive_count} 次执行 '{self._last_class}' 类操作。"
            f"如果当前方向没有进展，请换一个思路。"
        )

    def check_streak_l2(self) -> Optional[str]:
        """L2 硬阻断：同类工具连续 5+ 次"""
        if self._last_class is None or self._last_class not in self.L2_ENABLED_CLASSES:
            return None
        if self._consecutive_count >= self.L2_THRESHOLD:
            cls = self._last_class
            if cls == "path_scan":
                return (
                    f"已连续 {self._consecutive_count} 次执行路径扫描，目标路径可能不存在。"
                    f"请换一个思路（如检查已有 findngs.log 中的线索），而不是继续盲目探测。"
                )
            if cls == "config_read":
                return (
                    f"已尝试多种配置读取方式但均无效。请换一个攻击方向。"
                )
        return None

    def get_stagnation_signatures(self) -> List[str]:
        """返回最后 N 个工具调用的签名模式"""
        recent = self._call_history[-5:]
        return [f'{e["tool"]}:{e["input_summary"][:60]}' for e in recent]

    @staticmethod
    def _make_call_signature(tool_name: str, tool_input: Dict[str, Any]) -> str:
        """生成调用签名（用于 dead end 匹配）"""
        short = tool_name.split("__")[-1] if "__" in tool_name else tool_name
        if isinstance(tool_input, dict):
            cmd = tool_input.get("command", "") or tool_input.get("cmd", "")
            if cmd:
                return f"{short}:{str(cmd)[:80]}"
        return short

    # ── 工具结果处理 ──

    def on_tool_result(self, tool_name: str, is_error: bool, result_str: str = "") -> str:
        """处理工具执行结果，返回动作: 'none' | 'reflect'"""
        if is_error:
            self._consecutive_errors += 1
        else:
            self._consecutive_errors = 0

        if self._consecutive_errors >= 5:
            return "reflect"
        return "none"

    # ── 紧凑恢复 ──

    def enter_compact_recovery(self):
        """进入紧凑恢复模式"""
        self._compact_deny_remaining = 1
        self._compact_confirmed_reads = set()

    def is_in_compact_recovery(self) -> bool:
        """是否在紧凑恢复模式"""
        return self._compact_deny_remaining > 0

    def confirm_file_read(self, file_path: str, recovery_files: Set[str]):
        """确认已经读取了一个恢复文件"""
        matched = next(
            (f for f in recovery_files if file_path.endswith(f"/{f}") or file_path == f),
            None,
        )
        if matched:
            self._compact_confirmed_reads.add(matched)
            if recovery_files <= self._compact_confirmed_reads:
                self._compact_deny_remaining = 0

    def exit_compact_recovery(self):
        """退出紧凑恢复模式（快速路径）"""
        self._compact_deny_remaining = 0

    def get_missing_recovery_files(self, recovery_files: Set[str]) -> List[str]:
        """获取尚未读取的恢复文件列表"""
        missing = recovery_files - self._compact_confirmed_reads
        return list(missing)

    # ── ABANDON ──

    def activate_abandon(self):
        """激活 ABANDON 模式"""
        self._abandon_active = True

    @property
    def abandon_active(self) -> bool:
        return self._abandon_active

    # ── 指标 ──

    @property
    def tool_call_count(self) -> int:
        return len(self._call_history)

    @property
    def consecutive_count(self) -> int:
        return self._consecutive_count

    @property
    def last_class(self) -> Optional[str]:
        return self._last_class


def extract_dead_ends(work_dir: Path) -> List[str]:
    """从 progress.md 提取 Dead Ends 标题列表"""
    if not work_dir:
        return []
    progress_file = Path(work_dir) / "progress.md"
    if not progress_file.exists():
        return []
    try:
        content = progress_file.read_text(encoding="utf-8")
        lines = content.split("\n")
        in_dead_ends = False
        dead_ends = []
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("## Dead Ends"):
                in_dead_ends = True
                continue
            if in_dead_ends:
                if stripped.startswith("## "):
                    break
                if stripped.startswith("### "):
                    dead_ends.append(stripped[4:].strip())
        return dead_ends
    except Exception:
        return []


def extract_prior_findings(work_dir: Path) -> List[str]:
    """从 findings.log 提取发现摘要列表"""
    if not work_dir:
        return []
    findings_file = Path(work_dir) / "findings.log"
    if not findings_file.exists():
        return []
    try:
        content = findings_file.read_text(encoding="utf-8")
        lines = []
        for line in content.split("\n"):
            stripped = line.strip()
            if stripped.startswith("- **Title**"):
                lines.append(stripped.replace("- **Title**: ", ""))
            elif stripped.startswith("**Title**:"):
                lines.append(stripped.split(":", 1)[1].strip())
        return lines[:20]
    except Exception:
        return []


__all__ = [
    "ReflectionTracker",
    "extract_dead_ends",
    "extract_prior_findings",
]