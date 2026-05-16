"""
知识条目写入器
==============

Runner 在 Pipeline 结束后调用，自动把解题经验写入 knowledge/。
"""

from __future__ import annotations

import logging
from datetime import datetime
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
        if r.summary:
            chain_parts.append(f"- [{r.agent_id}] {r.summary}")
        for f in r.findings:
            if f.evidence:
                chain_parts.append(f"  - {f.title}: {f.evidence[:200]}")

    # 构建 key_commands
    cmd_parts: list[str] = []
    for r in ctx.agent_results:
        for f in r.findings:
            if f.evidence and ("curl" in f.evidence or "sqlmap" in f.evidence or "python" in f.evidence):
                cmd_parts.append(f"# {f.title}\n{f.evidence}")

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