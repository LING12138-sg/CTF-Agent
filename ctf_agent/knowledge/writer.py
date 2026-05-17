"""
知识条目写入器
==============

Runner 在 Pipeline 结束后调用，自动把解题经验写入 knowledge/。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

from ..common import log_system_event
from ..types import ChallengeContext
from .compiled_kb import KnowledgeEntry, save_entry

_logger = logging.getLogger(__name__)


def write_experience(ctx: ChallengeContext, result: Dict) -> None:
    """将解题经验写入知识库

    在 Pipeline 结束后（无论是否找到 Flag）调用。
    未解的题也会写入（标记 solved=false），
    供 future 参考"哪些方向走不通"。

    Args:
        ctx: 完整题目上下文
        result: Runner.run() 返回的结果字典
    """
    if not ctx.challenge_id:
        return

    flag = result.get("flag") or ctx.get_flag()
    solved = bool(flag)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # 构建 tags：从 tech_stack + findings 提取关键词
    tags = _build_tags(ctx)

    # 构建攻击链
    chain_parts: list[str] = []
    for r in ctx.agent_results:
        if r.summary and r.summary.startswith("放弃"):
            continue

        # 找到对应的 plan，注入攻击方法作为上下文
        plan = next((p for p in ctx.plans if p.id == r.plan_id), None)
        if plan:
            chain_parts.append(f"## 攻击计划: {plan.title}")
            chain_parts.append(f"方法: {plan.approach}")

        # Agent 总结
        if r.summary:
            chain_parts.append(f"\n### 执行总结 [{r.agent_id}]")
            chain_parts.append(r.summary)

        # Agent 完整响应（精简为 3000 字符）
        if r.response_text:
            # 提取工具调用和关键输出，跳过思考过程
            lines = []
            for line in r.response_text.split("\n"):
                stripped = line.strip()
                if stripped and not stripped.startswith("--- THINK"):
                    lines.append(stripped)
            clean_text = "\n".join(lines)
            if len(clean_text) > 3000:
                clean_text = clean_text[:3000] + "\n...(截断)"
            chain_parts.append(f"\n### 详细执行过程 [{r.agent_id}]")
            chain_parts.append(clean_text)

        # 发现的证据（不截断）
        for f in r.findings:
            if f.evidence:
                chain_parts.append(f"\n- **{f.title}**: {f.evidence[:2000]}")

    # 构建 key_commands
    cmd_parts: list[str] = []
    for r in ctx.agent_results:
        for f in r.findings:
            if f.evidence and any(kw in f.evidence.lower() for kw in
                                  ("curl", "sqlmap", "python", "nmap", "ffuf",
                                   "nuclei", "hydra", "gobuster", "commix")):
                cmd_parts.append(f"# {f.title}\n{f.evidence[:2000]}")
        # 从 response_text 提取工具调用标记 + 命令描述行
        if r.response_text:
            tool_names: set[str] = set()
            cmd_lines: list[str] = []
            for line in r.response_text.split("\n"):
                stripped = line.strip()
                if stripped.startswith("[TOOL_CALL:"):
                    name = stripped[len("[TOOL_CALL:"):].rstrip("]").strip()
                    tool_names.add(name)
                    continue
                # 检测 LLM 文本块中描述的命令（含常见 Kali 工具名）
                lower = stripped.lower()
                for kw in ("sqlmap", "curl ", "nmap", "ffuf", "nuclei", "hydra",
                           "python3", "gobuster", "commix", "dirb", "john ",
                           "hashcat", "steghide", "binwalk", "jwt_tool"):
                    if kw in lower and not stripped.startswith("[") and 15 < len(stripped) < 500:
                        cmd_lines.append(stripped[:300])
                        break
            if cmd_lines:
                cmd_parts.append("# 攻击命令\n" + "\n".join(cmd_lines[:15]))
            if tool_names:
                cmd_parts.append(f"# 使用工具: {', '.join(sorted(tool_names))}")
        # 从 Agent 日志文件提取实际执行的命令
        log_cmds = _extract_cmds_from_log(r.agent_id, r.plan_id)
        if log_cmds:
            cmd_parts.append("# 实际执行命令\n" + "\n".join(log_cmds[:20]))

    # 构建已放弃方向
    abandon_parts: list[str] = []
    for r in ctx.agent_results:
        if r.summary and r.summary.startswith("放弃"):
            abandon_parts.append(f"- {r.summary}")
        for f in r.findings:
            if f.type.value == "info" and "dead" in f.title.lower():
                abandon_parts.append(f"- {f.title}: {f.description[:200]}")

    entry = KnowledgeEntry(
        challenge_id=ctx.challenge_id,
        title=f"{ctx.target.url}",
        server=ctx.tech_stack.server,
        language=ctx.tech_stack.language,
        framework=ctx.tech_stack.framework,
        tags=tags,
        solved=solved,
        flag=flag or "",
        summary=_build_summary(ctx, result),
        attack_chain="\n".join(chain_parts) if chain_parts else "",
        key_commands="\n".join(cmd_parts) if cmd_parts else "",
        abandoned="\n".join(abandon_parts) if abandon_parts else "",
        created_at=now,
    )

    save_entry(entry)
    log_system_event(
        f"知识条目已写入",
        f"challenge_id={ctx.challenge_id} solved={solved} tags={tags}",
    )


def _extract_cmds_from_log(agent_id: str, plan_id: str) -> list[str]:
    """从 Agent 日志文件提取实际执行的命令（>>> [TOOL:...] 行）"""
    log_dir = Path(__file__).resolve().parent.parent.parent / "shared" / "logs"
    log_file = log_dir / f"{agent_id}_{plan_id}.log"
    if not log_file.exists():
        return []
    try:
        cmds: list[str] = []
        with open(log_file, "r", encoding="utf-8") as f:
            for line in f:
                if ">>> [TOOL:" in line:
                    # 格式: >>> [TOOL:name] {"command": "...", "language": "..."}
                    try:
                        json_str = line.split("] ", 1)[1] if "] " in line else ""
                        if json_str:
                            inp = json.loads(json_str)
                            cmd = inp.get("command", "")
                            if cmd:
                                cmds.append(cmd[:500])
                    except (ValueError, json.JSONDecodeError):
                        pass
        return cmds
    except OSError:
        return []


def _build_tags(ctx: ChallengeContext) -> list:
    """从上下文提取标签关键词"""
    tags: list[str] = []

    if ctx.tech_stack.language:
        tags.append(ctx.tech_stack.language.lower())
    if ctx.tech_stack.server:
        tags.append(ctx.tech_stack.server.split("/")[0].lower())

    # 从 findings 提取漏洞类型
    vuln_keywords = {
        "sqli": ["sql", "injection", "database"],
        "lfi": ["lfi", "file inclusion", "directory traversal", "../", "..\\"],
        "rce": ["rce", "command", "shell", "exec"],
        "xss": ["xss", "cross-site"],
        "ssrf": ["ssrf"],
        "ssti": ["ssti", "template"],
        "upload": ["upload", "file upload", "webshell"],
        "weak_password": ["weak password", "brute", "bruteforce", "弱口令"],
        "deserialize": ["deserialize", "反序列化", "pickle"],
        "jwt": ["jwt", "json web token"],
    }

    text_for_tags = " ".join(
        [f.title for r in ctx.agent_results for f in r.findings]
        + [r.summary or "" for r in ctx.agent_results]
    ).lower()

    for tag, keywords in vuln_keywords.items():
        if any(kw in text_for_tags for kw in keywords):
            if tag not in tags:
                tags.append(tag)

    return tags[:8]


def _build_summary(ctx: ChallengeContext, result: Dict) -> str:
    """构建 Summary 摘要"""
    lines = [f"目标: {ctx.target.url}"]
    lines.append(f"技术栈: {ctx.tech_stack.server or '?'} / {ctx.tech_stack.language or '?'}")

    if result.get("summary"):
        lines.append(f"结果: {result['summary']}")

    # 找出关键发现
    key_findings = []
    for r in ctx.agent_results:
        for f in r.findings:
            if f.severity.value in ("critical", "high", "medium"):
                key_findings.append(f"- [{f.severity.value}] {f.title}")

    if key_findings:
        lines.append("关键发现:")
        lines.extend(key_findings)

    return "\n".join(lines)