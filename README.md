# CTF Agent

自用的项目，全程AI编写代码，基于 **Plan-Attack 双层架构** 的自动化 Web CTF 解题系统

参考了 [CHYing-agent](https://github.com/your-repo) 的 brain/agents 分层设计和 ctf-agent 的赛马并行机制。

## 项目结构

```
CTF_Agent/
├── main.py                      # 入口: python main.py -t <url>
├── CLAUDE.md                    # Claude Code 指令协议
├── requirements.txt             # 依赖
├── ctf_agent/                   # 核心 Python 包
│   ├── runner.py                # 主编排器（Plan-Attack 循环）
│   ├── types.py                 # Target Model 核心数据结构
│   ├── config.py                # 统一配置管理
│   ├── common.py                # 日志 / 时间工具
│   ├── llm/
│   │   └── client.py            # LLM API 客户端（Anthropic SDK）
│   ├── brain/
│   │   ├── plan_agent.py        # Plan Agent 规划智能体
│   │   └── prompts.py           # 系统提示词组装
│   ├── agents/
│   │   ├── base.py              # Agent 基类
│   │   ├── attack_agent.py      # Attack Agent 攻击执行
│   │   └── quick_check.py       # Quick Check 快速试探
│   └── utils/
│       └── http.py              # HTTP 工具
├── prompts/                     # System Prompt 模板 (.md)
│   ├── __init__.py              # load_prompt() 加载器
│   ├── plan_agent_identity.md   # Plan Agent 角色定义
│   ├── plan_agent_strategy.md   # Plan Agent 策略
│   ├── plan_agent_constraints.md
│   ├── attack_agent_identity.md # Attack Agent 角色定义
│   └── attack_agent_strategy.md # Attack Agent 策略
├── shared/                      # 共享状态目录
│   ├── state/                   # JSON 状态文件
│   ├── plans/                   # 计划文件
│   ├── logs/                    # 执行日志
│   ├── recon/                   # 侦察报告
│   └── exploits/                # 利用记录
├── scripts/                     # 用户脚本
├── memory/                      # 经验记忆
├── skills/                      # 技能知识库
├── mcp_server/                  # MCP 服务器
└── wp/                          # WriteUps
```

## 架构

```
目标 URL
    │
    ▼
┌─────────────────────────────────────────────────┐
│  Runner (主编排器)                                 │
│                                                   │
│  Phase 1: 自动侦察                                │
│  (HTTP 探测、技术栈识别)                            │
│                                                   │
│  Phase 2: Plan → Attack 循环                      │
│                                                   │
│  ┌──────────┐    plans     ┌──────────────────┐   │
│  │ Plan     │ ────────→    │ Attack Agent 赛马 │   │
│  │ Agent    │              │ ┌─ attacker_1 ─┐ │   │
│  │ (分析/   │  ← 评审反馈  │ ├─ attacker_2 ─┤ │   │
│  │  规划)   │              │ ├─ attacker_3 ─┤ │   │
│  └──────────┘              │ └──────────────┘ │   │
│                                   │                │
│                            Flag / 继续 / 重规划    │
│                                                   │
│  Phase 3: 输出结果                                │
└─────────────────────────────────────────────────┘
```

### 工作流程

1. **Runner** 创建 ChallengeContext，执行自动侦察
2. **Plan Agent** 分析目标信息，生成 2-3 个 AttackPlan
3. **Attack Agent** 并行赛马执行不同 Plan
4. 首个找到 Flag 的 Agent 获胜并终止其他 Agent
5. **Plan Agent** 评审新发现：继续 / 重规划 / 停止
6. 循环直到找到 Flag 或达到最大轮数

## 使用方式

```bash
# 安装依赖
pip install -r requirements.txt

# 基础用法
python main.py -t http://target:8080

# 带人类提示（参考信息/思路）
python main.py -t http://target:8080 -p "题目是 Java 框架，关注 SSTI，参考这个思路: ..."

# 调整赛马参数
python main.py -t target:8080 --attackers 4 --rounds 5 --timeout 1200
```

### 参数说明

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-t` | 必填 | 目标 URL |
| `-p` | "" | 人类提示/参考信息 |
| `--rounds` | 3 | Plan Agent 最大规划轮数 |
| `--attackers` | 3 | 并行 Attack Agent 数 |
| `--timeout` | 600 | Attack Agent 超时秒数 |

## 核心数据结构

详见 `ctf_agent/types.py`：

- **ChallengeContext** — 完整题目上下文，贯穿全流程
- **AttackPlan** — 攻击计划（id, hypothesis, approach, priority）
- **Finding** — 发现（endpoint/vulnerability/credential/flag）
- **AgentResult** — Agent 执行结果

### Target Model

```python
@dataclass
class ChallengeContext:
    challenge_id: str
    target: TargetInfo        # URL, IP, 端口
    tech_stack: TechStack     # 服务器/语言/框架/数据库
    findings: List[Finding]   # 发现列表
    plans: List[AttackPlan]   # 攻击计划
    agent_results: List[AgentResult]
    notes: str
```

## 环境变量

可在 `.claude/settings.local.json` 中设置，或通过环境变量覆盖：

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `ANTHROPIC_AUTH_TOKEN` | — | API Key（必填） |
| `ANTHROPIC_BASE_URL` | https://api.anthropic.com | API 地址 |
| `ANTHROPIC_MODEL` | deepseek-v4-flash | 模型名称 |
| `MAX_PLAN_ROUNDS` | 3 | 最大规划轮数 |
| `MAX_ATTACKERS` | 3 | 并行 Attack Agent 数 |
| `ATTACK_TIMEOUT` | 600 | Attack Agent 超时(秒) |
| `QUICK_CHECK_TIMEOUT` | 60 | Quick Check 超时(秒) |
| `MAX_RETRIES` | 2 | 最大重试次数 |

## 设计参考

- **CHYing-agent**: brain/agents 分层设计、Prompt 模板化、Target Model 数据结构
- **ctf-agent**: 赛马并行机制、FIRST_COMPLETED 调度模式