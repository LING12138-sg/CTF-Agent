"""
完整 Hooks 系统
================

PreToolUse / PostToolUse / SubagentStop 钩子，提供：

PreToolUse:
- 紧凑恢复拦截：compact 后强制 Agent 先读 progress.md/findings.log 恢复上下文
- ABANDON 强制执行：阻止已确认的失败方向
- Same-class streak L2 硬阻断
- 文件路径修正（相对路径 → work_dir）
- 文件读取防护
- Tool allow/deny lists 校验
- 参数完整性检查

PostToolUse:
- Timeline 自动记录到 attack_timeline.md
- 紧凑恢复读取进度跟踪
- 停滞检测 → additionalContext 注入（SOFT_WARN）
- 工具调用模式跟踪

SubagentStop:
- 日志记录
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, cast

from ..common import log_system_event

from .compact import should_use_handoff

_logger = logging.getLogger(__name__)

# TODO 后续转到Linux Docker执行可以删掉这个逻辑
# ── Python 命令正则：匹配行首或管道后的 python3/python 调用 ──
_RE_PYTHON_CMD = re.compile(
    r'(^|&&|\||;)\s*python(3)?(\s|<<|\')',
)

# ═══════════════════════════════════════════════════════════════════
# 紧凑恢复文件
# ═══════════════════════════════════════════════════════════════════

def get_compact_recovery_files(shared_dir: str = "") -> frozenset[str]:
    """返回 compact 恢复时必须读取的文件集合。

    如果 compact_handoff.md 存在，优先使用它（单文件快速恢复）。
    否则回退到 progress.md + findings.log + hint.md。
    """
    if shared_dir and should_use_handoff(shared_dir):
        return frozenset({"compact_handoff.md"})

    required: Set[str] = {"progress.md", "findings.log"}
    if shared_dir:
        hint_file = Path(shared_dir) / "hint.md"
        if hint_file.exists() and hint_file.read_text(encoding="utf-8").strip():
            required.add("hint.md")
    return frozenset(required)


# ═══════════════════════════════════════════════════════════════════
# Dead End 匹配
# ═══════════════════════════════════════════════════════════════════

_STOPWORDS = frozenset({
    "the", "and", "for", "with", "from", "that", "this", "not", "all",
    "any", "has", "was", "are", "but", "been", "have", "will", "can",
    "each", "which", "their", "there", "some", "returns",
    "using", "when", "command", "function", "true", "false", "none",
    "null", "error", "failed", "success", "request", "response",
})


def _extract_keywords(text: str) -> Set[str]:
    """从文本中提取关键匹配词（URL路径、端口、CVE、技术名词等）"""
    import re
    keywords: Set[str] = set()
    lower = text.lower()

    # URL 路径
    for m in re.finditer(r"(/[\w./-]{3,})", lower):
        keywords.add(m.group(1))
    # 域名/主机名
    for m in re.finditer(r"\b([\w.-]+\.(?:com|org|net|io|local|internal))\b", lower):
        keywords.add(m.group(1))
    # 端口号
    for m in re.finditer(r":(\d{2,5})\b", lower):
        keywords.add(f":{m.group(1)}")
    # CVE 编号
    for m in re.finditer(r"(cve-\d{4}-\d+)", lower):
        keywords.add(m.group(1))
    # 技术名词 token
    for m in re.finditer(r"\b([a-z][a-z0-9_-]{2,})\b", lower):
        token = m.group(1)
        if token not in _STOPWORDS:
            keywords.add(token)

    return keywords


def matches_dead_end(
    tool_name: str,
    tool_input: Optional[Dict[str, Any]],
    dead_ends: List[str],
    stagnation_signatures: Optional[List[str]] = None,
) -> Optional[str]:
    """检查工具调用是否匹配已确认的 Dead End 方向。

    策略：从 dead end 文本和工具 input 中提取关键词，
    2+ 个关键词交集命中即匹配。

    Returns:
        匹配到的 dead end 描述，未匹配返回 None
    """
    if not tool_input or not dead_ends:
        return None

    if not isinstance(tool_input, dict):
        return None

    input_str = json.dumps(tool_input, ensure_ascii=False).lower()
    input_keywords = _extract_keywords(input_str)

    if not input_keywords:
        return None

    for dead_end in dead_ends:
        dead_keywords = _extract_keywords(dead_end.lower())
        overlap = input_keywords & dead_keywords
        if len(overlap) >= 2:
            return f"{dead_end} [匹配关键词: {', '.join(sorted(list(overlap))[:5])}]"

    return None


# ═══════════════════════════════════════════════════════════════════
# Timeline 辅助
# ═══════════════════════════════════════════════════════════════════

def _get_timeline_path(shared_dir: str) -> Optional[Path]:
    """返回 attack_timeline.md 路径"""
    if not shared_dir:
        return None
    return Path(shared_dir) / "attack_timeline.md"


def _sanitize_for_markdown(text: str) -> str:
    """清理写入 markdown 的文本"""
    if not text:
        return ""
    text = text.replace("\r\n", "\n").replace("\r", "\n").replace("\x00", "")
    return "".join(ch for ch in text if ch in ("\n", "\t") or ord(ch) >= 32)


def _append_timeline(timeline_path: Path, entry: str) -> None:
    """追加一行到 timeline 文件"""
    try:
        safe = _sanitize_for_markdown(entry).strip()
        if safe:
            with open(timeline_path, "a", encoding="utf-8") as f:
                f.write(safe + "\n")
    except Exception:
        pass


def _format_timeline_entry(
    tool_name: str,
    tool_input: dict,
    result_text: str,
    is_error: bool,
    shared_dir: str,
) -> List[str]:
    """从工具调用生成 timeline 条目。

    记录关键操作：bash/exec、record_key_finding、Task/Agent 委派等。
    跳过 Read/Glob/Grep/WebSearch 等辅助工具。
    """
    now = datetime.now().strftime("%H:%M")
    short = tool_name.split("__")[-1] if "__" in tool_name else tool_name

    # 跳过的工具
    if short in ("Read", "Glob", "Grep", "WebSearch", "WebFetch",
                  "TodoWrite", "Skill", "StructuredOutput",
                  "Edit", "Write", "EnterPlanMode", "ExitPlanMode"):
        return []

    lines: List[str] = []
    err_mark = " ❌" if is_error else ""

    if short in ("bash", "exec", "execute_command"):
        cmd = ""
        if isinstance(tool_input, dict):
            cmd = tool_input.get("command", "") or tool_input.get("cmd", "")
        if cmd:
            lines.append(f"{now} `{short}` {str(cmd)[:120]}{err_mark}")
        return lines

    if short == "record_key_finding" or "record_key_finding" in tool_name:
        kind = tool_input.get("kind", "?") if isinstance(tool_input, dict) else "?"
        title = tool_input.get("title", "")[:80] if isinstance(tool_input, dict) else ""
        lines.append(f"{now} `record_key_finding` [{kind}] {title}{err_mark}")
        return lines

    if short in ("Task", "Agent"):
        desc = tool_input.get("description", "")[:80] if isinstance(tool_input, dict) else ""
        prompt = tool_input.get("prompt", "")[:100] if isinstance(tool_input, dict) else ""
        lines.append(f"{now} `{short}` {desc}")
        if prompt:
            lines.append(f"  prompt: {prompt}")
        return lines

    # 其他 MCP 工具
    if tool_name.startswith("mcp__"):
        params = json.dumps(tool_input, ensure_ascii=False)[:100] if tool_input else ""
        lines.append(f"{now} `{short}` {params}{err_mark}")
        return lines

    # 默认：记录工具名
    lines.append(f"{now} `{short}` {err_mark}")
    return lines


# ═══════════════════════════════════════════════════════════════════
# PreToolUse Hook
# ═══════════════════════════════════════════════════════════════════

def create_pre_tool_use_hook(
    *,
    shared_dir: str = "",
    allowed_tools: Optional[List[str]] = None,
    disallowed_tools: Optional[List[str]] = None,
    tools_requiring_args: tuple = (),
    reflection_tracker=None,
) -> Callable:
    """创建 PreToolUse Hook 回调函数

    在工具执行前调用，可以拦截或修改工具调用。

    Args:
        shared_dir: 共享目录路径（用于 timeline 和恢复文件）
        allowed_tools: 允许的工具列表（None 表示不检查白名单）
        disallowed_tools: 禁止的工具列表
        tools_requiring_args: 需要参数的工具名称元组
        reflection_tracker: ReflectionTracker 实例

    Returns:
        Hook 回调函数
    """
    async def pre_tool_use_hook(
        input_data: Dict[str, Any],
        tool_use_id: Optional[str],
        context: Any,
    ) -> Dict[str, Any]:
        tool_name = input_data.get("tool_name", "unknown")
        tool_input = input_data.get("tool_input", {})
        is_structured_output = tool_name == "StructuredOutput"

        # 判断是否是子代理（SDK agent_id 非空表示子代理触发）
        agent_id = input_data.get("agent_id", "")
        is_subagent = bool(agent_id)

        # ── TodoWrite → 同步 progress.md ──
        if tool_name == "TodoWrite" and isinstance(tool_input, dict):
            todos = tool_input.get("todos", [])
            if todos and reflection_tracker and reflection_tracker.shared_dir:
                _sync_todos_to_progress(todos, reflection_tracker.shared_dir)

        # ── 记录工具调用 → ReflectionTracker ──
        if reflection_tracker and not is_structured_output and not is_subagent:
            reflection_tracker.record_tool_call(tool_name, tool_input)
            reflection_tracker.classify_and_increment(tool_name, tool_input)

        # ── 紧凑恢复拦截 ──
        _READ_TOOLS = frozenset({
            "Read", "Glob", "Grep", "Skill", "TodoWrite",
            "WebFetch", "WebSearch",
        })
        if (
            reflection_tracker
            and reflection_tracker.is_in_compact_recovery()
            and not is_subagent
            and not is_structured_output
            and tool_name not in _READ_TOOLS
            and not tool_name.startswith("mcp__record_key_finding")
        ):
            recovery_files = get_compact_recovery_files(shared_dir)
            ordered_missing = reflection_tracker.get_missing_recovery_files(recovery_files)
            # 拼出完整路径帮助 Agent
            work_dir = reflection_tracker.shared_dir
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": (
                        "CONTEXT COMPACTED — 攻击历史可能丢失。在继续操作前必须恢复上下文：\n"
                        + "\n".join(
                            f"{i+1}. Read {Path(work_dir) / f}"
                            for i, f in enumerate(ordered_missing)
                        )
                        + "\n\n恢复后继续执行。注意：不要重新分析已读过的内容，直接继续攻击。"
                    ),
                }
            }

        # ── ABANDON 强制执行 ──
        _ABANDON_EXEMPT = frozenset({
            "Read", "Glob", "Grep", "WebSearch", "WebFetch",
            "TodoWrite", "Skill", "Agent", "Task", "StructuredOutput",
        })
        if (
            reflection_tracker
            and reflection_tracker.abandon_active
            and not is_subagent
            and not is_structured_output
            and tool_name not in _ABANDON_EXEMPT
            and not tool_name.startswith("mcp__record_key_finding")
        ):
            dead_ends = _load_dead_ends(reflection_tracker.shared_dir)
            sigs = reflection_tracker.get_stagnation_signatures()
            reason = matches_dead_end(tool_name, tool_input, dead_ends, sigs)
            if reason:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": (
                            f"此操作匹配已确认的失败方向（{reason}），系统已禁止重试。"
                            f"请尝试完全不同的方法。阅读 progress.md 寻找未探索的方向。"
                        ),
                    }
                }

        # ── Same-class streak L2 deny ──
        if (
            reflection_tracker
            and not is_subagent
            and not is_structured_output
        ):
            deny_reason = reflection_tracker.check_streak_l2()
            if deny_reason:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": deny_reason,
                    }
                }

        # ── 文件路径修正（Write/Edit 的相对路径 → work_dir） ──
        if tool_name in ("Write", "Edit") and not is_subagent and isinstance(tool_input, dict):
            file_path = tool_input.get("file_path", "")
            if file_path and not os.path.isabs(file_path) and shared_dir:
                corrected = os.path.join(shared_dir, file_path)
                updated_input = dict(tool_input)
                updated_input["file_path"] = corrected
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "updatedInput": updated_input,
                    }
                }

        # TODO 后期转到Linux这段代码可以删掉了，通过docker启用
        # ── Python 路径修正（python3/python → .venv/Scripts/python.exe） ──
        if tool_name == "Bash" and isinstance(tool_input, dict):
            cmd = tool_input.get("command", "")
            if isinstance(cmd, str) and _RE_PYTHON_CMD.search(cmd):
                corrected = _RE_PYTHON_CMD.sub(
                    r'\1.venv/Scripts/python.exe', cmd
                )
                updated_input = dict(tool_input)
                updated_input["command"] = corrected
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "allow",
                        "updatedInput": updated_input,
                    }
                }

        # ── 文件读取防护 ──
        if not is_subagent:
            from .file_guards import check_file_read
            guard_reason = check_file_read(tool_name, tool_input)
            if guard_reason:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": guard_reason,
                    }
                }

        # ── 工具禁止列表 ──
        if (
            not is_structured_output
            and disallowed_tools
            and tool_name in disallowed_tools
        ):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"工具 {tool_name} 被禁止使用，请使用其他工具。",
                }
            }

        # ── 工具允许列表 ──
        if (
            not is_structured_output
            and allowed_tools
            and tool_name not in allowed_tools
            and not tool_name.startswith("mcp__")
        ):
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": f"工具 {tool_name} 不在允许列表中。",
                }
            }

        # ── 参数完整性检查 ──
        if (
            not is_structured_output
            and tools_requiring_args
        ):
            actual = tool_name.split("__")[-1] if "__" in tool_name else tool_name
            if actual in tools_requiring_args and not tool_input:
                return {
                    "hookSpecificOutput": {
                        "hookEventName": "PreToolUse",
                        "permissionDecision": "deny",
                        "permissionDecisionReason": f"工具 {actual} 需要参数。",
                    }
                }

        return {}

    return pre_tool_use_hook


# ═══════════════════════════════════════════════════════════════════
# PostToolUse Hook
# ═══════════════════════════════════════════════════════════════════

def create_post_tool_use_hook(
    *,
    shared_dir: str = "",
    reflection_tracker=None,
    agent_name: str = "",
) -> Callable:
    """创建 PostToolUse Hook 回调函数

    在工具执行后调用，用于记录、跟踪和注入上下文。

    Args:
        shared_dir: 共享目录路径
        reflection_tracker: ReflectionTracker 实例
        agent_name: Agent 名称（用于日志）

    Returns:
        Hook 回调函数
    """
    _timeline_path = _get_timeline_path(shared_dir)

    async def post_tool_use_hook(
        input_data: Dict[str, Any],
        tool_use_id: Optional[str],
        context: Any,
    ) -> Dict[str, Any]:
        tool_name = input_data.get("tool_name", "unknown")
        tool_input = input_data.get("tool_input", {})
        tool_response = input_data.get("tool_response", "")

        # 判断子代理
        agent_id = input_data.get("agent_id", "")
        is_subagent = bool(agent_id)

        # 格式化结果字符串
        if isinstance(tool_response, str):
            result_str = tool_response
        elif isinstance(tool_response, dict):
            result_str = json.dumps(tool_response, ensure_ascii=False)
        elif isinstance(tool_response, list):
            result_str = json.dumps(tool_response, ensure_ascii=False)
        else:
            result_str = str(tool_response)

        # ── Timeline 记录 ──
        if _timeline_path and not is_subagent:
            try:
                err = _detect_tool_error(tool_response)
                entries = _format_timeline_entry(
                    tool_name, tool_input, result_str, err, shared_dir,
                )
                for entry in entries:
                    _append_timeline(_timeline_path, entry)
            except Exception:
                pass

        # ── 紧凑恢复状态跟踪 ──
        try:
            if (
                tool_name == "Read"
                and not is_subagent
                and reflection_tracker
                and reflection_tracker.is_in_compact_recovery()
                and not _detect_tool_error(tool_response)
                and isinstance(tool_input, dict)
            ):
                file_path = tool_input.get("file_path", "") or ""
                recovery_files = get_compact_recovery_files(shared_dir)
                reflection_tracker.confirm_file_read(file_path, recovery_files)
        except Exception:
            pass

        # ── 停滞检测 ──
        additional_parts: List[str] = []

        # 紧凑恢复完成后自动注入发现摘要
        if (
            reflection_tracker
            and not is_subagent
            and not reflection_tracker.is_in_compact_recovery()
            and reflection_tracker.tool_call_count == 1
        ):
            # 刚退出恢复模式：注入 context 摘要
            recovery_summary = _build_recovery_context_summary(shared_dir)
            if recovery_summary:
                additional_parts.append(recovery_summary)

        # 工具结果 -> 停滞检测
        if reflection_tracker and not is_subagent:
            is_error = _detect_tool_error(tool_response)
            action = reflection_tracker.on_tool_result(tool_name, is_error, result_str)

            if action == "reflect" and not reflection_tracker.abandon_active:
                # ── ABANDON 激活（仅首次触发生效，避免重复写入） ──
                sigs = reflection_tracker.get_stagnation_signatures()
                dead_end_desc = _build_dead_end_description(sigs)
                reflection_tracker.activate_abandon()
                _append_dead_end(shared_dir, dead_end_desc)
                _record_abandon_to_findings(shared_dir, dead_end_desc)

                additional_parts.append(
                    "🚫 ABANDON ACTIVATED — 当前方向已确认失败"
                    f"（连续 {reflection_tracker._consecutive_errors} 个工具调用错误）。\n"
                    f"尝试的操作: {dead_end_desc}\n\n"
                    "系统已将此方向标记为 Dead End 并写入 progress.md。"
                    "后续同类工具调用将被阻止。\n"
                    "请切换到完全不同的方法。阅读 findings.log 和 progress.md 寻找其他线索。"
                )

            # Streak L1 软提醒
            streak = reflection_tracker.get_streak_l1_warning()
            if streak:
                additional_parts.append(streak)

        # ── additionalContext 返回 ──
        if additional_parts:
            return {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": "\n\n".join(additional_parts),
                }
            }

        return {}

    return post_tool_use_hook


# ═══════════════════════════════════════════════════════════════════
# SubagentStop Hook
# ═══════════════════════════════════════════════════════════════════

def create_subagent_stop_hook(
    agent_name: str = "",
) -> Callable:
    """创建 SubagentStop Hook 回调函数

    当子代理通过 Task/Agent 工具完成时触发。
    """
    async def subagent_stop_hook(
        input_data: Dict[str, Any],
        tool_use_id: Optional[str],
        context: Any,
    ) -> Dict[str, Any]:
        agent_type = input_data.get("agent_type", "")
        agent_id = input_data.get("agent_id", "")
        log_system_event(
            f"SubagentStop: {agent_type} ({agent_id})",
        )
        return {}

    return subagent_stop_hook


# ═══════════════════════════════════════════════════════════════════
# 辅助函数
# ═══════════════════════════════════════════════════════════════════

def _detect_tool_error(tool_response: Any) -> bool:
    """判断工具返回是否为错误"""
    if isinstance(tool_response, dict):
        if tool_response.get("is_error"):
            return True
        # MCP 格式: {"content": [{"text": "Exit Code: 1\n..."}]}
        content = tool_response.get("content", [])
        if isinstance(content, list) and content:
            first = content[0] if isinstance(content[0], dict) else {}
            text = first.get("text", "")
            if text.startswith("Exit Code: "):
                try:
                    return int(text.split("\n")[0].split(": ")[1]) != 0
                except (ValueError, IndexError):
                    pass
    elif isinstance(tool_response, list) and tool_response:
        first = tool_response[0]
        if isinstance(first, dict):
            text = first.get("text", "")
            if text.startswith("Exit Code: "):
                try:
                    return int(text.split("\n")[0].split(": ")[1]) != 0
                except (ValueError, IndexError):
                    pass
    elif isinstance(tool_response, str):
        return tool_response.startswith("Error") or tool_response.startswith("error")
    return False


def _load_dead_ends(shared_dir: str) -> List[str]:
    """从 shared_dir/progress.md 加载 Dead Ends"""
    if not shared_dir:
        return []
    try:
        from .reflection_tracker import extract_dead_ends
        return extract_dead_ends(Path(shared_dir))
    except Exception:
        return []


def _build_recovery_context_summary(shared_dir: str) -> Optional[str]:
    """紧凑恢复后，构建 context 摘要注入帮助 Agent 快速恢复"""
    if not shared_dir:
        return None
    try:
        from .reflection_tracker import extract_dead_ends, extract_prior_findings
        work_dir = Path(shared_dir)
        dead_ends = extract_dead_ends(work_dir)
        findings = extract_prior_findings(work_dir)

        parts: List[str] = []
        if findings:
            parts.append("### 已有发现\n" + "\n".join(f"- {f}" for f in findings))
        if dead_ends:
            parts.append("### 已确认的失败方向 (DO NOT RETRY)\n" + "\n".join(f"- {d}" for d in dead_ends))
        if parts:
            return "## 恢复摘要\n\n" + "\n\n".join(parts)
        return None
    except Exception:
        return None


def _sync_todos_to_progress(todos: List[dict], shared_dir: str) -> None:
    """将 TodoWrite 的 todos 同步写入 progress.md 的当前阶段段落"""
    if not shared_dir:
        return
    try:
        progress_file = Path(shared_dir) / "progress.md"
        if not progress_file.exists():
            return

        content = progress_file.read_text(encoding="utf-8")
        total = len(todos)
        done = sum(1 for t in todos if isinstance(t, dict) and t.get("status") == "completed")
        current_items = [t for t in todos if isinstance(t, dict) and t.get("status") == "in_progress"]
        current_desc = current_items[0].get("content", "?") if current_items else "无"

        lines = []
        for t in todos:
            if not isinstance(t, dict):
                continue
            status = t.get("status", "pending")
            text = t.get("content", "")
            if status == "completed":
                lines.append(f"- [x] {text}")
            elif status == "in_progress":
                lines.append(f"- [ ] **{text}** ← 当前")
            else:
                lines.append(f"- [ ] {text}")

        new_section = (
            f"进度: {current_desc} ({done}/{total} 完成)\n\n"
            f"### 攻击计划 (auto-synced)\n\n"
            + "\n".join(lines)
        )

        # 替换 ## Current Phase 段落
        import re
        pattern = re.compile(r"(## Current Phase\n\n).*?(?=\n## |\Z)", re.DOTALL)
        if pattern.search(content):
            content = pattern.sub(r"\g<1>" + new_section, content)
        else:
            content = content.rstrip() + f"\n\n## Current Phase\n\n{new_section}\n"
        progress_file.write_text(content, encoding="utf-8")
    except Exception:
        pass


# ═══════════════════════════════════════════════════════════════════
# ABANDON 持久化辅助函数
# ═══════════════════════════════════════════════════════════════════

def _build_dead_end_description(sigs: List[str]) -> str:
    """从停滞签名构建 Dead End 描述"""
    if not sigs:
        return "连续工具调用错误"
    summary = "; ".join(sigs[-3:])
    return summary[:120]


def _append_dead_end(shared_dir: str, description: str) -> None:
    """追加一条 Dead End 到 progress.md"""
    if not shared_dir:
        return
    try:
        progress_file = Path(shared_dir) / "progress.md"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = (
            f"### {description}\n"
            f"- **触发时间**: {now}\n"
            f"- **原因**: 连续工具调用错误 (ABANDON 自动触发)\n"
        )

        if progress_file.exists():
            content = progress_file.read_text(encoding="utf-8")
            if "## Dead Ends" in content:
                # 在已有的 Dead Ends 节首追加新条目（兼容任意数量换行）
                import re
                content = re.sub(
                    r'(## Dead Ends\n*)',
                    r'\g<1>' + entry,
                    content,
                    count=1,
                )
            else:
                content += f"\n## Dead Ends\n\n{entry}"
            progress_file.write_text(content, encoding="utf-8")
        else:
            # progress.md 不存在时创建并写入 Dead Ends
            progress_file.parent.mkdir(parents=True, exist_ok=True)
            progress_file.write_text(f"## Dead Ends\n\n{entry}", encoding="utf-8")
    except Exception:
        pass


def _record_abandon_to_findings(shared_dir: str, description: str) -> None:
    """记录 ABANDON 事件到 findings.log"""
    if not shared_dir:
        return
    try:
        findings_file = Path(shared_dir) / "findings.log"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        entry = (
            f"---\n"
            f"**Title**: ABANDON - {description}\n"
            f"**Kind**: abandon\n"
            f"**Status**: closed\n"
            f"**Description**: 连续工具调用错误，系统自动标记为 Dead End\n"
            f"**Timestamp**: {now}\n"
        )
        with open(findings_file, "a", encoding="utf-8") as f:
            f.write(entry + "\n")
    except Exception:
        pass


__all__ = [
    "create_pre_tool_use_hook",
    "create_post_tool_use_hook",
    "create_subagent_stop_hook",
    "get_compact_recovery_files",
    "matches_dead_end",
    "_sync_todos_to_progress",
]