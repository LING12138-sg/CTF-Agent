"""
发现持久化层 — findings.log + progress.md
==========================================

findings.log: append-only 结构化日志，记录所有发现的完整信息
progress.md:  按段落组织的状态摘要，支持 Attack Tree upsert 和 Dead Ends 追加

与 CHYing-agent 的 mcp_tools.py 中 record_key_finding 对应，
但简化了：去掉 DB persistence，保留文件持久化。
"""
# TODO 后续增加DB记录持久化

from __future__ import annotations

import os
import re
from datetime import datetime
from typing import Any, Dict, List, Optional


# ── 常量 ──

FINDINGS_LOG = "findings.log"
PROGRESS_MD = "progress.md"

VALID_KINDS = {
    "vulnerability", "credential", "info", "dead_end",
    "endpoint", "config", "note",
}

VALID_STATUSES = {
    "hypothesis", "tested", "confirmed", "exploited", "dead_end",
}

VALID_VERIFICATION = {
    "executed", "observed", "inferred",
}


# ── 主入口 ──

def record_finding(finding: Dict[str, Any], shared_dir: str) -> str:
    """四路持久化记录关键发现

    Args:
        finding: 发现字典
            - kind: 类型 (vulnerability/credential/info/dead_end/endpoint/config)
            - title: 标题（用于 progress.md 去重）
            - evidence: 核心证据
            - status: hypothesis/tested/confirmed/exploited/dead_end
            - verification_method: executed/observed/inferred
            - commands_and_results: 执行的命令与输出
            - confidence: 置信度 0.0-1.0
            - next_action: 建议下一步
            - details: 详细推导过程
        shared_dir: 共享目录路径（存放 findings.log 和 progress.md）

    Returns:
        状态消息: "OK: recorded {kind}/{title} (status=..., verification=...)"
    """
    # 验证
    error = _validate_finding(finding)
    if error:
        return f"record_key_finding failed: {error}"

    os.makedirs(shared_dir, exist_ok=True)

    _append_to_findings_log(finding, shared_dir)
    _sync_to_progress_md(finding, shared_dir)

    kind = finding.get("kind", "?")
    title = _truncate(finding.get("title", ""), 60)
    status = finding.get("status", "?")
    verification = finding.get("verification_method", "?")
    return (
        f"OK: recorded {kind}/{title} "
        f"(status={status}, verification={verification})"
    )


def get_findings_summary(shared_dir: str, max_lines: int = 20) -> str:
    """读取 findings.log 摘要

    Args:
        shared_dir: 共享目录
        max_lines: 最大返回行数

    Returns:
        最新发现的摘要文本
    """
    path = os.path.join(shared_dir, FINDINGS_LOG)
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        # 取最后 max_lines 行
        tail = lines[-max_lines:] if len(lines) > max_lines else lines
        return "".join(tail)
    except (OSError, UnicodeDecodeError):
        return ""


# ── 验证 ──

def _validate_finding(finding: Dict[str, Any]) -> Optional[str]:
    """验证发现的完整性，返回错误消息或 None"""
    kind = finding.get("kind", "")
    title = finding.get("title", "")
    evidence = finding.get("evidence", "")
    status = finding.get("status", "")
    verification = finding.get("verification_method", "")

    if not kind or kind not in VALID_KINDS:
        return f"invalid kind '{kind}', must be one of {VALID_KINDS}"
    if not title:
        return "title is required"
    if not evidence:
        return "evidence is required"
    if status and status not in VALID_STATUSES:
        return f"invalid status '{status}', must be one of {VALID_STATUSES}"
    if verification and verification not in VALID_VERIFICATION:
        return (
            f"invalid verification_method '{verification}', "
            f"must be one of {VALID_VERIFICATION}"
        )

    # confirmed/exploited 必须基于实际验证
    if status in ("confirmed", "exploited") and verification == "inferred":
        return (
            "status=confirmed/exploited requires "
            "verification_method=executed or observed, not inferred"
        )

    # dead_end 必须基于实际验证
    is_dead = kind == "dead_end" or status == "dead_end"
    if is_dead and verification == "inferred":
        return (
            "dead_end requires verification_method=executed or observed, "
            "not inferred"
        )

    return None


# ── 时间戳 ──

def _timestamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# ── findings.log ──

def _confidence_tag(confidence: float, verification: str) -> str:
    if verification == "executed":
        return "VERIFIED-BY-EXECUTION"
    elif verification == "observed":
        return "OBSERVED"
    elif verification == "inferred":
        return "UNVERIFIED-INFERENCE"
    return "UNKNOWN"


def _append_to_findings_log(finding: Dict[str, Any], shared_dir: str):
    """追加结构化发现到 findings.log"""
    path = os.path.join(shared_dir, FINDINGS_LOG)

    ts = _timestamp()
    kind = finding.get("kind", "?")
    status = finding.get("status", "?")
    confidence = float(finding.get("confidence", 0.0))
    verification = finding.get("verification_method", "?")
    tag = _confidence_tag(confidence, verification)
    title = finding.get("title", "")
    evidence = finding.get("evidence", "")
    commands = finding.get("commands_and_results", "")
    next_action = finding.get("next_action", "")
    details = finding.get("details", "")

    parts = [
        f"## [{ts}] kind={kind} | status={status} | [{tag}]",
        f"- **Title**: {title}",
        f"- **Confidence**: {confidence:.2f}",
        f"- **Evidence**: {evidence}",
    ]
    if commands:
        parts.append(f"- **Commands**: {commands}")
    if next_action:
        parts.append(f"- **Next Action**: {next_action}")
    if details:
        parts.append(f"- **Details**: {_truncate(details, 500)}")
    parts.append("---\n")

    entry = "\n".join(parts)

    with open(path, "a", encoding="utf-8") as f:
        f.write(entry + "\n")


# ── progress.md ──

def _sync_to_progress_md(finding: Dict[str, Any], shared_dir: str):
    """同步发现到 progress.md

    - dead_end → ## Dead Ends 段落（去重追加）
    - 其他      → ## Attack Tree 段落（按 title upsert）
    """
    path = os.path.join(shared_dir, PROGRESS_MD)

    kind = finding.get("kind", "")
    status = finding.get("status", "")
    is_dead = kind == "dead_end" or status == "dead_end"
    title = finding.get("title", "")

    content = ""
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

    if is_dead:
        entry = _format_dead_end(finding)
        content = _append_to_section(content, "Dead Ends", entry, title)
    else:
        entry = _format_attack_entry(finding)
        content = _upsert_in_section(content, "Attack Tree", entry, title)

    with open(path, "w", encoding="utf-8") as f:
        f.write(content)


def _format_attack_entry(finding: Dict[str, Any]) -> str:
    """格式化一条 Attack Tree 条目"""
    status = finding.get("status", "hypothesis").upper()
    title = finding.get("title", "")
    confidence = float(finding.get("confidence", 0.0))
    verification = finding.get("verification_method", "?")
    evidence = finding.get("evidence", "")
    next_action = finding.get("next_action", "")
    details = finding.get("details", "")

    lines = [f"### [{status}] {title}"]
    lines.append(
        f"- Status: {status.lower()} | Confidence: {confidence:.2f} "
        f"| Verification: {verification}"
    )
    lines.append(f"- Evidence: {evidence}")
    if next_action:
        lines.append(f"- Next Action: {next_action}")
    if details:
        lines.append(f"- Details: {_truncate(details, 300)}")
    return "\n".join(lines)


def _format_dead_end(finding: Dict[str, Any]) -> str:
    """格式化一条 Dead End 条目"""
    title = finding.get("title", "")
    evidence = finding.get("evidence", "")
    details = finding.get("details", "")

    lines = [f"### [DEAD_END] {title}"]
    lines.append(f"- Evidence: {evidence}")
    if details:
        lines.append(f"- Details: {_truncate(details, 300)}")
    return "\n".join(lines)


# ── 段落管理 ──

def _find_section_bounds(
    lines: List[str], section_name: str,
) -> tuple[int, int]:
    """找到指定段落的起止行号（左闭右开）

    Returns:
        (start_line, end_line) — start 是 ## 标题行号, end 是下一段落或文件末尾
    """
    header = f"## {section_name}"
    start = -1
    end = len(lines)

    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == header:
            start = i
        elif start >= 0 and stripped.startswith("## "):
            end = i
            break

    return start, end


def _append_to_section(
    content: str, section_name: str, entry: str, title: str,
) -> str:
    """在段落末尾追加条目（按 title 去重）"""
    target_header = entry.split("\n")[0] if entry else ""

    lines = content.split("\n") if content else []
    # 检查重复
    for line in lines:
        if target_header and line.strip() == target_header.strip():
            return content

    start, end = _find_section_bounds(lines, section_name)

    if start < 0:
        # 段落不存在，在文件末尾创建
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"\n## {section_name}\n\n{entry}\n"
        return content

    # 在段落末尾插入
    insert_at = end
    new_lines = lines[:insert_at] + [""] + [entry] + lines[insert_at:]
    return "\n".join(new_lines)


def _upsert_in_section(
    content: str, section_name: str, entry: str, title: str,
) -> str:
    """在段落中按 title 更新或追加条目"""
    target_header = entry.split("\n")[0] if entry else ""

    lines = content.split("\n") if content else []
    start, end = _find_section_bounds(lines, section_name)

    if start < 0:
        # 段落不存在，创建
        if content and not content.endswith("\n"):
            content += "\n"
        content += f"\n## {section_name}\n\n{entry}\n"
        return content

    # 在 [start, end) 范围内找同 title 条目
    for i in range(start + 1, end):
        stripped = lines[i].strip() if i < len(lines) else ""
        if stripped == target_header.strip():
            # 找到已有条目，替换之
            entry_start = i
            entry_end = _find_entry_end(lines, i, end)
            new_lines = (
                lines[:entry_start] + [entry] + lines[entry_end:]
            )
            return "\n".join(new_lines)

    # 没找到，在段落末尾追加
    insert_at = end
    new_lines = lines[:insert_at] + [""] + [entry] + lines[insert_at:]
    return "\n".join(new_lines)


def _find_entry_end(lines: List[str], start: int, section_end: int) -> int:
    """找到从 start 开始的条目结束位置"""
    for j in range(start + 1, section_end):
        if lines[j].strip().startswith("### "):
            return j
    return section_end


# ── 工具函数 ──

def _truncate(text: str, max_len: int) -> str:
    return text if len(text) <= max_len else text[:max_len] + "..."


__all__ = ["record_finding", "get_findings_summary"]