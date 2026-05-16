"""
Compiled Knowledge Base — Agent 经验编译引擎
============================================

每次解题完成后，Agent 自动总结经验写入 knowledge/<id>.md。
新题目来时按 tech_stack 关键词匹配检索。

遵循 Karpathy "LLM Knowledge Bases" 模式：
知识是编译出来的（Agent 解题后总结），不是检索出来的（无 embedding/vector DB）。
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

# =====================================================
# YAML frontmatter 解析（无 pyyaml 依赖）
# =====================================================

_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n(?:---|\.\.\.)\s*\n", re.DOTALL)


def parse_frontmatter(text: str) -> tuple[dict, str]:
    """解析 markdown 文件中的 YAML frontmatter"""
    match = _FRONTMATTER_RE.match(text)
    if not match:
        return {}, text

    raw = match.group(1)
    body = text[match.end() :]
    meta: dict = {}

    for line in raw.split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        # key: [v1, v2, ...] 列表
        lm = re.match(r"(\w+):\s*\[(.*?)\]", line)
        if lm:
            key = lm.group(1)
            items = [x.strip().strip("\"'") for x in lm.group(2).split(",") if x.strip()]
            meta[key] = items
            continue

        # key: value
        km = re.match(r"(\w+):\s*(.+)", line)
        if km:
            key = km.group(1)
            val = km.group(2).strip().strip("\"'")
            meta[key] = val
            continue

    return meta, body


# =====================================================
# 数据结构
# =====================================================


@dataclass
class KnowledgeEntry:
    """一条知识条目（对应一道题/一个靶机的经验总结）"""

    challenge_id: str = ""
    title: str = ""
    server: str = ""
    language: str = ""
    framework: str = ""
    tags: List[str] = field(default_factory=list)
    solved: bool = False
    flag: str = ""
    summary: str = ""
    attack_chain: str = ""
    key_commands: str = ""
    abandoned: str = ""
    created_at: str = ""

    @classmethod
    def from_file(cls, path: Path) -> Optional["KnowledgeEntry"]:
        """从 markdown 文件解析"""
        if not path.exists():
            return None
        try:
            text = path.read_text(encoding="utf-8")
            meta, body = parse_frontmatter(text)

            e = cls()
            e.challenge_id = meta.get("challenge_id", path.stem)
            e.title = meta.get("title", "")
            e.server = meta.get("server", "")
            e.language = meta.get("language", "")
            e.framework = meta.get("framework", "")
            raw_tags = meta.get("tags", [])
            e.tags = raw_tags if isinstance(raw_tags, list) else []
            e.solved = str(meta.get("solved", "false")).lower() in ("true", "yes", "1")
            e.flag = meta.get("flag", "")
            e.created_at = meta.get("created_at", "")

            # 按标题提取各节
            sections = re.split(r"\n## ", body)
            for sec in sections:
                sec = sec.strip()
                if sec.startswith("Summary"):
                    e.summary = sec.split("\n", 1)[1].strip() if "\n" in sec else ""
                elif sec.startswith("Attack Chain"):
                    e.attack_chain = sec.split("\n", 1)[1].strip() if "\n" in sec else ""
                elif sec.startswith("Key Commands"):
                    e.key_commands = sec.split("\n", 1)[1].strip() if "\n" in sec else ""
                elif sec.startswith("ABANDONED"):
                    e.abandoned = sec.split("\n", 1)[1].strip() if "\n" in sec else ""

            if not e.summary:
                e.summary = body[:300]

            return e
        except Exception as exc:
            _logger.warning("解析知识条目失败 %s: %s", path.name, exc)
            return None

    def to_markdown(self) -> str:
        """序列化为含 frontmatter 的 markdown"""
        lines = ["---"]
        lines.append(f"challenge_id: {self.challenge_id}")
        lines.append(f"title: {self.title}")
        lines.append(f"server: {self.server}")
        lines.append(f"language: {self.language}")
        lines.append(f"framework: {self.framework}")
        lines.append(f"tags: [{', '.join(self.tags)}]")
        lines.append(f"solved: {str(self.solved).lower()}")
        if self.flag:
            lines.append(f"flag: {self.flag}")
        lines.append(f"created_at: {self.created_at}")
        lines.append("---")
        lines.append("")
        lines.append(f"## Summary\n\n{self.summary}")
        if self.attack_chain:
            lines.append(f"\n## Attack Chain\n\n{self.attack_chain}")
        if self.key_commands:
            lines.append(f"\n## Key Commands\n\n{self.key_commands}")
        if self.abandoned:
            lines.append(f"\n## ABANDONED\n\n{self.abandoned}")
        return "\n".join(lines)


# =====================================================
# CompiledKB — 内存索引引擎
# =====================================================


# raw 经验存放子目录
RAW_DIR = "raw"


class CompiledKB:
    """知识库索引

    懒加载 knowledge/raw/ 下所有 .md 文件，建立内存索引。
    按 tech_stack + tags 做关键词评分匹配。
    """

    _instance: Optional["CompiledKB"] = None

    def __init__(self, kb_dir: str = ""):
        self._kb_dir = Path(kb_dir) if kb_dir else Path(os.getcwd()) / "knowledge"
        self._entries: Dict[str, KnowledgeEntry] = {}
        self._loaded = False

    @property
    def raw_dir(self) -> Path:
        """raw 经验目录的完整路径"""
        return self._kb_dir / RAW_DIR

    # ── 加载 ──

    def load(self):
        """扫描 knowledge/raw/*.md 加载所有经验条目"""
        if self._loaded:
            return
        self._entries = {}
        raw = self.raw_dir
        if not raw.exists():
            raw.mkdir(parents=True, exist_ok=True)
            _logger.info("raw 经验目录已创建: %s", raw)
        else:
            for f in sorted(raw.glob("*.md")):
                entry = KnowledgeEntry.from_file(f)
                if entry:
                    self._entries[entry.challenge_id] = entry
        self._loaded = True
        _logger.info("知识库已加载: %d 条经验", len(self._entries))

    def reload(self):
        """强制重新加载（新增文件后调用）"""
        self._loaded = False
        self.load()

    # ── 写入 ──

    def save(self, entry: KnowledgeEntry) -> Path:
        """保存一条 raw 经验条目（新增或覆盖）"""
        self.load()
        path = self.raw_dir / f"{entry.challenge_id}.md"
        path.write_text(entry.to_markdown(), encoding="utf-8")
        self._entries[entry.challenge_id] = entry
        _logger.info("raw 经验已写入: %s", path.name)
        self._update_index()
        return path

    def list_raw_entries(self) -> List[KnowledgeEntry]:
        """列出所有 raw 经验条目"""
        self.load()
        return list(self._entries.values())

    def _update_index(self):
        """更新 index.md 目录"""
        if not self._entries:
            return
        index_path = self._kb_dir / "index.md"
        lines = [
            "# Knowledge Index",
            "",
            "## Raw Experiences",
            "| ID | Title | Tech | Solved |",
            "|---|---|---|---|",
        ]
        for cid, e in sorted(self._entries.items()):
            tech = f"{e.language} / {e.server}"[:40]
            solved = "✅" if e.solved else "❌"
            lines.append(f"| {cid} | {e.title[:40]} | {tech} | {solved} |")
        index_path.write_text("\n".join(lines), encoding="utf-8")

    # ── 查询 ──

    def query(
        self,
        *,
        server: str = "",
        language: str = "",
        tags: Optional[List[str]] = None,
        top_k: int = 5,
    ) -> List[KnowledgeEntry]:
        """按技术栈匹配知识条目

        评分：
          server 相同:   +10
          language 相同: +8
          framework 相同:+5
          tag 重叠:       +3/个
          未解:           -2（降权但不排除）
        """
        self.load()
        tags = tags or []

        scored: List[tuple[int, KnowledgeEntry]] = []
        for entry in self._entries.values():
            score = 0

            if server and entry.server and server.lower() in entry.server.lower():
                score += 10
            if language and entry.language and language.lower() == entry.language.lower():
                score += 8
            if entry.framework:
                score += 5

            if tags and entry.tags:
                overlap = set(t.lower() for t in tags) & set(t.lower() for t in entry.tags)
                score += len(overlap) * 3

            if not entry.solved:
                score -= 2

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:top_k]]

    @property
    def count(self) -> int:
        self.load()
        return len(self._entries)

    def get(self, challenge_id: str) -> Optional[KnowledgeEntry]:
        self.load()
        return self._entries.get(challenge_id)

    def get_all_entries(self) -> Dict[str, KnowledgeEntry]:
        """获取所有 raw 经验条目（字典：challenge_id → entry）"""
        self.load()
        return dict(self._entries)


# =====================================================
# WikiKB — Wiki 技术页面索引引擎
# =====================================================


@dataclass
class WikiEntry:
    """一条 Wiki 技术页面条目（用于索引和匹配）"""

    slug: str = ""
    category: str = ""
    title: str = ""
    tags: List[str] = field(default_factory=list)
    triggers: List[str] = field(default_factory=list)
    related: List[str] = field(default_factory=list)
    sources: List[str] = field(default_factory=list)
    body: str = ""
    path: str = ""  # 相对 knowledge/ 的路径

    @classmethod
    def from_page(cls, page_path: Path, kb_root: Path) -> Optional["WikiEntry"]:
        """从 wiki markdown 文件解析"""
        if not page_path.exists():
            return None
        try:
            text = page_path.read_text(encoding="utf-8")
            meta, body = parse_frontmatter(text)
            if not meta:
                return None
            rel = str(page_path.relative_to(kb_root))
            return cls(
                slug=meta.get("slug", page_path.stem),
                category=meta.get("category", ""),
                title=meta.get("title", meta.get("slug", page_path.stem)),
                tags=meta.get("tags", []),
                triggers=meta.get("triggers", []),
                related=meta.get("related", []),
                sources=meta.get("sources", []),
                body=body.strip()[:500],
                path=rel,
            )
        except Exception as exc:
            _logger.warning("解析 wiki 页面失败 %s: %s", page_path.name, exc)
            return None


class WikiKB:
    """Wiki 知识库索引

    懒加载 knowledge/wiki/techniques/**/*.md，建立内存索引。
    按 tags + triggers + category 做关键词评分匹配。
    """

    _instance: Optional["WikiKB"] = None

    # wiki 存放子目录（相对 knowledge/）
    WIKI_DIR = "wiki/techniques"

    def __init__(self, kb_dir: str = ""):
        self._kb_dir = Path(kb_dir) if kb_dir else Path(os.getcwd()) / "knowledge"
        self._wiki_root = self._kb_dir / self.WIKI_DIR
        self._entries: Dict[str, WikiEntry] = {}
        self._loaded = False

    def load(self):
        """扫描 wiki/techniques/**/*.md 加载所有页面"""
        if self._loaded:
            return
        self._entries = {}
        if not self._wiki_root.exists():
            _logger.info("wiki 目录不存在: %s", self._wiki_root)
        else:
            for f in sorted(self._wiki_root.glob("**/*.md")):
                entry = WikiEntry.from_page(f, self._kb_dir)
                if entry:
                    self._entries[entry.slug] = entry
        self._loaded = True
        _logger.info("WikiKB 已加载: %d 条", len(self._entries))

    def reload(self):
        """强制重新加载"""
        self._loaded = False
        self.load()

    def get_all_pages(self) -> Dict[str, WikiEntry]:
        """获取所有 wiki 页面"""
        self.load()
        return dict(self._entries)

    def query(
        self,
        *,
        tags: Optional[List[str]] = None,
        category: str = "",
        top_k: int = 5,
    ) -> List[WikiEntry]:
        """按 tags + category 匹配 wiki 页面

        评分：
          tag 重叠:       +3/个
          trigger 匹配:   +5/个
          category 相同:  +5
          标题含 tag:     +2/个
        """
        self.load()
        tags = tags or []

        scored: List[tuple[int, WikiEntry]] = []
        for entry in self._entries.values():
            score = 0

            tag_set = set(t.lower() for t in tags)

            # tag 重叠
            if tags and entry.tags:
                overlap = tag_set & set(t.lower() for t in entry.tags)
                score += len(overlap) * 3

            # trigger 匹配（triggers 是更精确的线索）
            if tags and entry.triggers:
                entry_triggers = set(t.lower() for t in entry.triggers)
                trig_overlap = tag_set & entry_triggers
                score += len(trig_overlap) * 5

            # category 精确匹配
            if category and entry.category and category.lower() == entry.category.lower():
                score += 5

            # 标题包含任意 tag
            if tags and entry.title:
                title_lower = entry.title.lower()
                title_matches = sum(1 for t in tags if t.lower() in title_lower)
                score += title_matches * 2

            if score > 0:
                scored.append((score, entry))

        scored.sort(key=lambda x: -x[0])
        return [e for _, e in scored[:top_k]]

    @property
    def count(self) -> int:
        self.load()
        return len(self._entries)

    def get(self, slug: str) -> Optional[WikiEntry]:
        self.load()
        return self._entries.get(slug)


# =====================================================
# 模块级单例 + 公开 API
# =====================================================

_KB: Optional[CompiledKB] = None
_KB_DIR: str = ""  # 记录首次创建的 kb_dir，用于冲突检测


def _get_kb(kb_dir: str = "") -> CompiledKB:
    """获取 CompiledKB 单例（首次调用时懒加载）"""
    global _KB, _KB_DIR
    if _KB is None:
        _KB = CompiledKB(kb_dir)
        _KB_DIR = kb_dir
    elif kb_dir and kb_dir != _KB_DIR:
        _logger.warning(
            "CompiledKB 单例已存在 (kb_dir=%r)，忽略新的 kb_dir=%r",
            _KB_DIR, kb_dir,
        )
    return _KB


def query_kb(
    *,
    server: str = "",
    language: str = "",
    tags: Optional[List[str]] = None,
    top_k: int = 5,
    kb_dir: str = "",
) -> List[KnowledgeEntry]:
    """查询知识库

    Args:
        server: 目标服务器（如 openresty, nginx）
        language: 开发语言（如 PHP, Java, Python）
        tags: 标签（如 lfi, sqli, rce）
        top_k: 返回条数
        kb_dir: 知识库目录（默认 knowledge/）

    Returns:
        按匹配度排序的知识条目列表
    """
    return _get_kb(kb_dir).query(server=server, language=language, tags=tags, top_k=top_k)


def save_entry(entry: KnowledgeEntry, kb_dir: str = "") -> Path:
    """保存知识条目到 knowledge/"""
    return _get_kb(kb_dir).save(entry)


# =====================================================
# WikiKB 模块级单例 + 公开 API
# =====================================================

_WIKI_KB: Optional[WikiKB] = None


def _get_wiki_kb(kb_dir: str = "") -> WikiKB:
    """获取 WikiKB 单例"""
    global _WIKI_KB
    if _WIKI_KB is None:
        _WIKI_KB = WikiKB(kb_dir)
    return _WIKI_KB


def query_wiki(
    *,
    tags: Optional[List[str]] = None,
    category: str = "",
    top_k: int = 5,
    kb_dir: str = "",
) -> List[WikiEntry]:
    """查询 wiki 技术页面

    Args:
        tags: 技术标签（如 lfi, sqli, rce）
        category: 分类过滤（web, pwn, crypto, misc）
        top_k: 返回条数
        kb_dir: 知识库目录（默认 knowledge/）

    Returns:
        按匹配度排序的 wiki 页面列表
    """
    return _get_wiki_kb(kb_dir).query(tags=tags, category=category, top_k=top_k)


def format_wiki_results(results: List[WikiEntry], max_body: int = 300) -> str:
    """格式化 wiki 查询结果为 prompt 片段"""
    if not results:
        return ""
    lines = ["## 相关 Wiki 技术页面"]
    for i, e in enumerate(results, 1):
        body = e.body[:max_body]
        if len(e.body) > max_body:
            body = body.rsplit("\n", 1)[0] + "..."

        tags_str = ", ".join(e.tags[:5]) if e.tags else ""
        lines.extend([
            "",
            f"### {i}. {e.title} ({e.category})",
        ])
        if tags_str:
            lines.append(f"- 标签: {tags_str}")
        if e.path:
            lines.append(f"- 路径: {e.path}")
        lines.append(f"- {body}")

    return "\n".join(lines)


def format_kb_results(results: List[KnowledgeEntry], max_summary: int = 250) -> str:
    """格式化查询结果为 prompt 片段"""
    if not results:
        return ""
    lines = ["## 相关历史经验"]
    for i, e in enumerate(results, 1):
        summary = e.summary[:max_summary]
        if len(e.summary) > max_summary:
            summary = summary.rsplit("\n", 1)[0] + "..."

        tags_str = ", ".join(e.tags[:5]) if e.tags else ""
        status = "✅" if e.solved else "❌"
        lines.extend([
            "",
            f"### {i}. {e.title} {status}",
            f"- 技术栈: {e.server or '?'} / {e.language or '?'}",
        ])
        if tags_str:
            lines.append(f"- 标签: {tags_str}")
        lines.append(f"- {summary}")

    return "\n".join(lines)


__all__ = [
    "CompiledKB",
    "KnowledgeEntry",
    "WikiEntry",
    "WikiKB",
    "RAW_DIR",
    "format_kb_results",
    "format_wiki_results",
    "parse_frontmatter",
    "query_kb",
    "query_wiki",
    "save_entry",
]