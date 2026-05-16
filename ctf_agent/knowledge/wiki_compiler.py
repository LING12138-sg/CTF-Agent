"""
Wiki Compiler — 经验编译引擎
=============================

从 knowledge/raw/ 读取原始解题经验，通过 LLM 编译为结构化 Wiki 技术页面，
写入 knowledge/wiki/techniques/{category}/{slug}.md。

遵循 Karpathy "LLM Knowledge Bases" 模式：
知识是编译出来的，不是检索出来的。
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Dict, List, Optional

from ..common import log_system_event
from ..llm.base import LLMBase
from ..llm.schemas import WIKI_PAGE_OUTPUT_SCHEMA
from .compiled_kb import CompiledKB, KnowledgeEntry

_logger = logging.getLogger(__name__)

# wiki 页面存放根目录（相对 knowledge/）
WIKI_DIR = "wiki/techniques"

# 分类映射（按 tags 自动归类）
CATEGORY_KEYWORDS = {
    "web": ["sqli", "lfi", "rce", "xss", "ssrf", "ssti", "upload",
            "jwt", "idor", "xxe", "deserialize", "command_injection",
            "file_read", "file_upload", "auth_bypass", "nosql",
            "prototype", "webshell", "php", "thinkphp", "laravel"],
    "pwn": ["pwn", "buffer overflow", "rop", "ret2libc", "format_string",
            "shellcode", "heap", "uaf", "canary", "pie", "seccomp"],
    "crypto": ["crypto", "rsa", "aes", "hash", "padding", "lattice",
               "xor", "stream cipher", "block cipher"],
    "misc": ["misc", "stego", "encode", "morse", "base64", "pyjail",
             "sandbox"],
}


def _detect_category(entry: KnowledgeEntry) -> str:
    """根据经验条目的 tags + tech_stack 自动判断分类"""
    text = " ".join(entry.tags).lower()
    text += f" {entry.server.lower()} {entry.language.lower()}"
    text += f" {entry.framework.lower()}"

    scores: Dict[str, int] = {}
    for cat, keywords in CATEGORY_KEYWORDS.items():
        score = sum(2 if kw in text else 0 for kw in keywords)
        if score > 0:
            scores[cat] = score

    if not scores:
        return "misc"
    return max(scores, key=scores.get)  # type: ignore


def _slugify(title: str) -> str:
    """从标题生成 URL 友好的 slug"""
    slug = re.sub(r"[^a-zA-Z0-9一-鿿_-]", "_", title.lower())
    slug = re.sub(r"_+", "_", slug).strip("_")
    return slug[:60]


class WikiPage:
    """一个 Wiki 技术页面"""

    def __init__(
        self,
        category: str = "",
        slug: str = "",
        title: str = "",
        tags: Optional[List[str]] = None,
        triggers: Optional[List[str]] = None,
        related: Optional[List[str]] = None,
        sources: Optional[List[str]] = None,
        body: str = "",
    ):
        self.category = category
        self.slug = slug
        self.title = title
        self.tags = tags or []
        self.triggers = triggers or []
        self.related = related or []
        self.sources = sources or []
        self.body = body

    @property
    def path_relative(self) -> str:
        """相对于 knowledge/ 的路径"""
        return f"{WIKI_DIR}/{self.category}/{self.slug}.md"

    def to_markdown(self) -> str:
        """序列化为含 frontmatter 的 markdown"""
        lines = ["---"]
        lines.append(f"category: {self.category}")
        lines.append(f"slug: {self.slug}")
        if self.title:
            lines.append(f"title: {self.title}")
        if self.tags:
            lines.append(f"tags: [{', '.join(self.tags)}]")
        if self.triggers:
            lines.append(f"triggers: [{', '.join(self.triggers)}]")
        if self.related:
            lines.append(f"related: [{', '.join(self.related)}]")
        if self.sources:
            lines.append(f"sources: [{', '.join(self.sources)}]")
        lines.append("---")
        lines.append("")
        lines.append(self.body.strip())
        return "\n".join(lines)

    @classmethod
    def from_markdown(cls, text: str) -> Optional["WikiPage"]:
        """从 markdown 解析（含 frontmatter）"""
        from .compiled_kb import parse_frontmatter

        meta, body = parse_frontmatter(text)
        if not meta:
            return None

        return cls(
            category=meta.get("category", ""),
            slug=meta.get("slug", ""),
            title=meta.get("title", ""),
            tags=meta.get("tags", []),
            triggers=meta.get("triggers", []),
            related=meta.get("related", []),
            sources=meta.get("sources", []),
            body=body.strip(),
        )


class WikiCompiler:
    """Wiki 编译器

    读取 raw/ 经验，调用 LLM 生成结构化的 Wiki 技术页面。
    """

    def __init__(
        self,
        llm: LLMBase,
        kb: CompiledKB,
        kb_dir: str = "",
    ):
        self.llm = llm
        self.kb = kb
        self.kb_dir = Path(kb_dir) if kb_dir else Path.cwd() / "knowledge"
        self.wiki_root = self.kb_dir / WIKI_DIR
        self.system_prompt = self._load_system_prompt()

    def _load_system_prompt(self) -> str:
        """加载 Wiki 编译器的 System Prompt"""
        from prompts import load_prompt
        return load_prompt("wiki_compiler.md")

    # ── 编译入口 ──

    async def compile_all(self) -> List[WikiPage]:
        """编译所有未 inget 的 raw 经验为一个或多个 Wiki 页面

        1. 收集 raw/ 中所有经验
        2. 按 category 分组
        3. 每组调用一次 LLM 编译
        4. 写入 wiki/techniques/{category}/
        """
        self.kb.load()
        entries = list(self.kb.list_raw_entries())
        if not entries:
            log_system_event("没有 raw 经验可编译")
            return []

        # 按 category 分组
        groups: Dict[str, List[KnowledgeEntry]] = {}
        for e in entries:
            cat = _detect_category(e)
            groups.setdefault(cat, []).append(e)

        pages: List[WikiPage] = []
        for cat, group in groups.items():
            page = await self._compile_group(cat, group)
            if page:
                pages.append(page)

        # 写入 & 更新 index
        saved = []
        for p in pages:
            path = self._save_page(p)
            saved.append(str(path))
        self._update_index()

        log_system_event(f"Wiki 编译完成", f"pages={len(pages)} paths={saved}")
        return pages

    async def compile_category(self, category: str) -> Optional[WikiPage]:
        """编译单个分类的 Wiki 页面"""
        self.kb.load()
        entries = [e for e in self.kb.list_raw_entries()
                   if _detect_category(e) == category]
        if not entries:
            log_system_event(f"分类 {category} 没有经验可编译")
            return None

        page = await self._compile_group(category, entries)
        if page:
            self._save_page(page)
            self._update_index()
        return page

    async def compile_single(
        self, entry_id: str, category: str = ""
    ) -> Optional[WikiPage]:
        """编译单条经验为一个 Wiki 页面"""
        self.kb.load()
        entry = self.kb.get(entry_id)
        if not entry:
            log_system_event(f"经验条目不存在: {entry_id}", level=logging.WARNING)
            return None

        cat = category or _detect_category(entry)
        page = await self._compile_group(cat, [entry])
        if page:
            self._save_page(page)
            self._update_index()
        return page

    # ── 核心编译逻辑 ──

    async def _compile_group(
        self, category: str, entries: List[KnowledgeEntry]
    ) -> Optional[WikiPage]:
        """调用 LLM 编译一组经验为一个 Wiki 页面"""
        # 构建输入：所有经验的摘要
        input_text = f"# 分类: {category}\n\n"
        input_text += f"基于以下 {len(entries)} 条解题经验编译 wiki 页面：\n\n"
        for i, e in enumerate(entries, 1):
            input_text += f"---\n### 经验 {i}: {e.title}\n"
            input_text += f"技术栈: {e.server or '?'} / {e.language or '?'}\n"
            input_text += f"标签: {', '.join(e.tags) if e.tags else '无'}\n"
            input_text += f"解题: {'✅' if e.solved else '❌'}\n\n"
            if e.summary:
                input_text += f"{e.summary}\n\n"
            if e.attack_chain:
                input_text += f"攻击链:\n{e.attack_chain}\n\n"
            if e.key_commands:
                input_text += f"关键命令:\n{e.key_commands}\n\n"
            if e.abandoned:
                input_text += f"已放弃方向:\n{e.abandoned}\n\n"

        input_text += (
            "\n请根据以上经验，编译为结构化的 Wiki 技术页面。"
            "输出 YAML frontmatter + Markdown 正文。"
        )

        # 调用 LLM
        await self.llm._ensure_connected(
            system_prompt=self.system_prompt,
            output_format=WIKI_PAGE_OUTPUT_SCHEMA,
        )

        try:
            result = await self.llm.query(
                input_text, output_format=WIKI_PAGE_OUTPUT_SCHEMA
            )
            return self._parse_result(result, category, entries)
        finally:
            await self.llm.reset_session()

    def _parse_result(
        self,
        result: dict,
        default_category: str,
        entries: List[KnowledgeEntry],
    ) -> Optional[WikiPage]:
        """解析 LLM 返回的结构化结果"""
        structured = result.get("structured") or {}
        text = result.get("text", "")

        # 优先从结构化输出获取
        title = structured.get("title", "")
        body = structured.get("body", "")

        if not body and text:
            # 回退：从文本提取 frontmatter + body
            page = WikiPage.from_markdown(text)
            if page:
                return page
            body = text
            title = title or entries[0].title if entries else "unknown"

        if not body:
            _logger.warning("Wiki 编译结果为空")
            return None

        slug = structured.get("slug", _slugify(title))
        tags = structured.get("tags", [])
        triggers = structured.get("triggers", [])
        related = structured.get("related", [])
        sources = [e.challenge_id for e in entries]

        return WikiPage(
            category=default_category,
            slug=slug,
            title=title,
            tags=tags,
            triggers=triggers,
            related=related,
            sources=sources,
            body=body,
        )

    # ── 文件持久化 ──

    def _save_page(self, page: WikiPage) -> Path:
        """保存 Wiki 页面到 knowledge/wiki/techniques/{category}/"""
        category_dir = self.wiki_root / page.category
        category_dir.mkdir(parents=True, exist_ok=True)
        path = category_dir / f"{page.slug}.md"
        path.write_text(page.to_markdown(), encoding="utf-8")
        _logger.info("Wiki 页面已写入: %s", path)
        return path

    def _update_index(self):
        """更新 index.md"""
        from .compiled_kb import parse_frontmatter

        if not self.wiki_root.exists():
            return

        lines = [
            "# Knowledge Index",
            "",
            "## Raw Experiences",
            "| ID | Title | Tech | Solved |",
            "|---|---|---|---|",
        ]
        # raw 条目
        for cid, e in sorted(self.kb.get_all_entries().items()):
            tech = f"{e.language} / {e.server}"[:40]
            solved = "✅" if e.solved else "❌"
            lines.append(f"| {cid} | {e.title[:40]} | {tech} | {solved} |")

        # wiki 页面
        wiki_pages = sorted(self.wiki_root.glob("**/*.md"))
        if wiki_pages:
            lines.extend(["", "## Wiki Pages", "| Path | Category | Tags |", "|---|---|---|"])
            for f in wiki_pages:
                text = f.read_text(encoding="utf-8")
                meta, _ = parse_frontmatter(text)
                if meta:
                    cat = meta.get("category", "")
                    tags = ", ".join(meta.get("tags", []) or [])[:40]
                    rel = str(f.relative_to(self.kb_dir))
                    lines.append(f"| {rel} | {cat} | {tags} |")

        index_path = self.kb_dir / "index.md"
        index_path.write_text("\n".join(lines), encoding="utf-8")


__all__ = ["WikiCompiler", "WikiPage"]