"""
知识库（Knowledge Base）
========================

Agent 解完题后自动总结经验写入 knowledge/raw/，
新题 Plan Agent 按 tech_stack 检索关联经验。

长期积累后，通过 WikiCompiler 将 raw 经验编译为
knowledge/wiki/techniques/ 下的通用技术页面。

用法:
    from ctf_agent.knowledge import query_kb, save_entry, format_kb_results
    from ctf_agent.knowledge import WikiCompiler, WikiPage

    # Plan Agent 查关联经验
    results = query_kb(server="openresty", language="PHP")
    prompt_fragment = format_kb_results(results)

    # 解题后写入经验
    save_entry(KnowledgeEntry(challenge_id="xxx", ...))

    # 编译 Wiki
    compiler = WikiCompiler(llm, kb)
    await compiler.compile_all()
"""

from .compiled_kb import (
    CompiledKB,
    KnowledgeEntry,
    WikiEntry,
    WikiKB,
    RAW_DIR,
    format_kb_results,
    format_wiki_results,
    parse_frontmatter,
    query_kb,
    query_wiki,
    save_entry,
)
from .wiki_compiler import WikiCompiler, WikiPage

__all__ = [
    "CompiledKB",
    "KnowledgeEntry",
    "WikiEntry",
    "WikiKB",
    "RAW_DIR",
    "WikiCompiler",
    "WikiPage",
    "format_kb_results",
    "format_wiki_results",
    "parse_frontmatter",
    "query_kb",
    "query_wiki",
    "save_entry",
]
