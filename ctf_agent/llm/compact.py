"""
ProgressCompiler — 紧凑恢复上下文编译
======================================

在 CLI auto-compact 触发时，异步将 progress.md + findings.log + attack_timeline.md
编译为 compact_handoff.md，为 Agent 提供快速恢复路径。
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

_logger = logging.getLogger(__name__)

_HANDOFF_FILENAME = "compact_handoff.md"
_MAX_TIMELINE_LINES = 60


def get_handoff_path(shared_dir: str) -> Optional[Path]:
    """返回 compact_handoff.md 的完整路径"""
    if not shared_dir:
        return None
    return Path(shared_dir) / _HANDOFF_FILENAME


def should_use_handoff(shared_dir: str) -> bool:
    """检查 compact_handoff.md 是否存在且可用"""
    path = get_handoff_path(shared_dir)
    if not path or not path.exists():
        return False
    try:
        return path.stat().st_size > 50
    except OSError:
        return False


def log_compact_boundary(shared_dir: str, event: str):
    """记录 compact 边界事件到 compact_boundary.log

    Args:
        shared_dir: 共享目录
        event: "start" | "end" | "compile"
    """
    if not shared_dir:
        return
    try:
        log_path = Path(shared_dir) / "compact_boundary.log"
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(f"[{ts}] compact_{event}\n")
    except Exception:
        pass


def compile_handoff(shared_dir: str) -> Optional[str]:
    """编译 compact_handoff.md

    聚合 progress.md、findings.log、attack_timeline.md 中的关键信息，
    生成 Agent 可以单次 Read 恢复上下文的紧凑摘要。

    Args:
        shared_dir: 共享目录路径

    Returns:
        写入的 handoff 文件路径，失败返回 None
    """
    if not shared_dir:
        return None

    work_dir = Path(shared_dir)
    handoff_path = work_dir / _HANDOFF_FILENAME

    try:
        sections: list[str] = []
        sections.append(f"# Compact Handoff\n")
        sections.append(f"> 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        sections.append("")

        # ── progress.md: 当前阶段 & Dead Ends ──
        progress_file = work_dir / "progress.md"
        if progress_file.exists():
            content = progress_file.read_text(encoding="utf-8")
            lines = content.split("\n")

            in_current = False
            in_dead_ends = False
            current_lines: list[str] = []
            dead_end_lines: list[str] = []

            for line in lines:
                stripped = line.strip()
                if stripped.startswith("## Current Phase"):
                    in_current = True
                    in_dead_ends = False
                    continue
                if stripped.startswith("## Dead Ends"):
                    in_current = False
                    in_dead_ends = True
                    continue
                if stripped.startswith("## "):
                    in_current = False
                    in_dead_ends = False
                    continue

                if in_current:
                    current_lines.append(line)
                elif in_dead_ends:
                    dead_end_lines.append(line)

            if current_lines:
                sections.append("## 当前阶段")
                sections.extend(current_lines)
                sections.append("")
            if dead_end_lines:
                sections.append("## 已确认的失败方向 (DO NOT RETRY)")
                sections.extend(dead_end_lines)
                sections.append("")
        else:
            sections.append("## 当前阶段\n无 progress.md\n")

        # ── findings.log: 关键发现摘要 ──
        findings_file = work_dir / "findings.log"
        if findings_file.exists():
            content = findings_file.read_text(encoding="utf-8")
            finding_lines = [
                line for line in content.split("\n")
                if line.strip() and ("**Title**" in line or "**Kind**" in line or "**Status**" in line)
            ]
            if finding_lines:
                sections.append("## 关键发现")
                sections.extend(finding_lines[:15])  # 最多 15 条
                sections.append("")
            else:
                sections.append("## 关键发现\n（findings.log 无结构化条目）\n")
        else:
            sections.append("## 关键发现\n无 findings.log\n")

        # ── attack_timeline.md: 最近操作时间线 ──
        timeline_file = work_dir / "attack_timeline.md"
        if timeline_file.exists():
            content = timeline_file.read_text(encoding="utf-8")
            all_lines = [l for l in content.split("\n") if l.strip()]
            recent = all_lines[-_MAX_TIMELINE_LINES:]
            if recent:
                sections.append("## 最近操作时间线")
                sections.extend(recent)
                sections.append("")
        else:
            sections.append("## 最近操作时间线\n无 attack_timeline.md\n")

        # ── 写入 ──
        handoff_path.write_text("\n".join(sections), encoding="utf-8")
        log_compact_boundary(shared_dir, "compile")

        return str(handoff_path)

    except Exception as exc:
        _logger.warning("ProgressCompiler 编译失败: %s", exc)
        return None