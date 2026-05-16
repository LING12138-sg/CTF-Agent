# CTF Knowledge Base — 操作手册

> 给 Claude 的操作手册。每次处理知识库相关任务时先读这个文件。

## 架构

基于 Karpathy "LLM Knowledge Bases" 模式：

```
knowledge/                  ← 和 CTF_Agent/ 同级
├── CLAUDE.md               ← 你正在读的这个文件
├── index.md                ← 全局目录
├── log.md                  ← 操作日志（只增不减）
│
├── raw/                    ← Layer 1: 原始解题经验（Agent 自动写入）
│   └── <challenge_id>.md   ← 每道题一条，只读
│
└── wiki/                   ← Layer 2: LLM 编译的知识
    └── techniques/         ← 技术 wiki 页面
        ├── web/            ← Web 类漏洞
        ├── pwn/            ← 二进制利用
        ├── crypto/         ← 密码学
        └── misc/           ← 其他
```

核心原则：**知识是编译出来的，不是检索出来的。**

Agent 解题后自动写 raw/ 经验，用户（或定时任务）触发 ingest 时，
LLM 读取 raw/ 中的多条经验，提炼为 wiki/techniques/ 下的通用技术页面。

---

## 两个操作

### 1. Ingest（编译新知识）

**触发**：用户说 "ingest"、"编译"、"更新知识库"等。

**来源**：`raw/` 里的原始解题经验。

**流程**：
1. 读 `raw/` 中所有（或未 inget 的）经验文件
2. 按技术分类（web/pwn/crypto/misc），提炼通用攻击方法
3. 写/更新 `wiki/techniques/{category}/` 下的页面
4. 更新 `index.md`
5. 追加 `log.md`
6. 一条经验可能贡献多个 wiki 页面

**关键**：
- wiki 页面只**更新**不**堆积**——新认知替换旧段落
- 不编造：没有足够经验支撑的技术点不要强行写

### 2. Query（在线检索）

由 `ctf_agent/knowledge/compiled_kb.py` 的 `CompiledKB` 自动完成。
- `raw/` 条目按 tech_stack 匹配（"有没有做过类似技术的题"）
- `wiki/` 页面按 tags/category 匹配（"这个漏洞怎么利用"）

Agent 通过 `kb_search` MCP 工具或 Plan Agent 自动注入调用。

---

## 页面格式

### raw 经验格式（Agent 自动写入）

```yaml
---
challenge_id: host_port_path
title: http://target:8080
server: nginx
language: PHP
framework: thinkphp
tags: [rce, thinkphp, unauth]
solved: true
flag: flag{...}
created_at: 2026-05-16
---
```

```
## Summary

## Attack Chain

## Key Commands

## ABANDONED
```

### wiki 技术页面格式

```yaml
---
category: web | pwn | crypto | misc
tags: [小写标签, 技术关键词]
triggers: [题目中可能出现的关键词或短语]
related: [相关页面的 slug]
sources: [<challenge_id>, <challenge_id>]  ← 编译自哪些经验
---
```

正文结构：

```markdown
# 技术名称

## 什么时候用
## 前提条件
## 攻击步骤
## 常见坑
## 变体
## 相关技术
```

页面 ID 格式: `techniques/{category}/{slug}`，如 `techniques/web/lfi`, `techniques/pwn/ret2libc`

---

## 铁律

1. **原始文档永远不改** — `raw/` 中的文件是只读的，Agent 产生后不再编辑
2. **wiki 页面只更新不堆积** — 新认知替换旧段落，不 append
3. **矛盾不覆盖** — 标注 ⚠️ 矛盾，等人确认
4. **保留所有命令** — 攻击步骤里的 curl/sqlmap/python 命令是最核心的知识
5. **不编造** — 没有实际经验的领域不强行写 wiki 页面

---

## 当前覆盖状态

- **WEB**: 待编译
- **PWN**: 待编译
- **CRYPTO**: 待编译
- **MISC**: 待编译

当 `raw/` 中有 3+ 条同类技术经验时，应考虑 ingest 到 wiki。