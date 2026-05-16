"""
Recorder — 关键发现持久化模块
==============================

提供 record_key_finding 机制，将 Attack Agent 的结构化发现
写入 findings.log 和 progress.md，实现进程间发现共享和状态追踪。

用法:
    from ctf_agent.recorder import record_finding
    record_finding(finding, shared_dir="shared/logs")
"""

from .persistence import record_finding, get_findings_summary

__all__ = ["record_finding", "get_findings_summary"]