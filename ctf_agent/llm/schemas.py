"""
结构化输出 Schema 定义
========================

提供 Agent 输出 Schema，用于 Attack Agent 的最终结构化输出。
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional


# ============== Attack Agent 输出 Schema ==============
#
# 用于 Attack Agent 的最终输出，供 Runner 稳定解析。
#
ORCHESTRATOR_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "description": "Agent 执行结果输出结构",
    "properties": {
        "success": {
            "type": "boolean",
            "description": "是否成功拿到 flag",
        },
        "flag": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": "FLAG 值",
        },
        "summary": {
            "type": "string",
            "description": "简要总结执行过程和结果",
        },
        "findings": {
            "type": "array",
            "description": "关键发现列表",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string", "enum": ["vulnerability", "endpoint", "credential", "flag", "info"]},
                    "description": {"type": "string"},
                    "confidence": {"type": "number", "minimum": 0, "maximum": 100},
                },
                "required": ["type", "description"],
            },
        },
        "blocked_reason": {
            "anyOf": [{"type": "string"}, {"type": "null"}],
            "description": "失败阻塞点",
        },
    },
    "required": ["success", "flag", "summary"],
}


class AgentOutputSchema:
    """Schema 包装器，提供便捷方法"""

    @staticmethod
    def make_success(flag: str, summary: str = "", findings: Optional[List[Dict]] = None) -> Dict:
        return {
            "success": True,
            "flag": flag,
            "summary": summary or "Flag 已找到",
            "findings": findings or [],
            "blocked_reason": None,
        }

    @staticmethod
    def make_failure(reason: str = "", findings: Optional[List[Dict]] = None) -> Dict:
        return {
            "success": False,
            "flag": None,
            "summary": "执行完成但未找到 Flag",
            "findings": findings or [],
            "blocked_reason": reason or None,
        }


# ============== PlanAgent 攻击计划输出 Schema ==============
#
# PlanAgent 用 execute_structured() 保证输出始终是有效 JSON。
# LLM 在执行过程中可以使用工具浏览/搜索，但最终输出强制为结构化 JSON。
#
PLANS_OUTPUT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "plans": {
            "type": "array",
            "description": "攻击计划列表",
            "items": {
                "type": "object",
                "properties": {
                    "id": {"type": "string", "description": "计划标识, 如 plan_001"},
                    "title": {"type": "string", "description": "简短的攻击标题"},
                    "hypothesis": {"type": "string", "description": "攻击假设——怀疑存在什么漏洞，为什么"},
                    "approach": {"type": "string", "description": "逐步攻击方法，含具体 Payload 和端点"},
                    "priority": {
                        "type": "integer", "description": "优先级，0 最高",
                        "minimum": 0, "maximum": 5,
                    },
                    "prerequisites": {
                        "type": "array", "items": {"type": "string"},
                        "description": "前置条件",
                    },
                    "expected_outcome": {
                        "type": "string", "description": "成功标志",
                    },
                },
                "required": ["id", "title", "hypothesis", "approach"],
            },
        },
    },
    "required": ["plans"],
}


__all__ = [
    "ORCHESTRATOR_OUTPUT_SCHEMA", "AgentOutputSchema",
    "PLANS_OUTPUT_SCHEMA",
]