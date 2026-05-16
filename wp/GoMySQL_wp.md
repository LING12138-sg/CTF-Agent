# GoMySQL 解题报告

## 题目信息
- **题目名称**: GoMySQL
- **题目描述**: Go!!!!! MySQL plus your lucky number
- **题目类型**: Web
- **比赛**: ADWorld / XCTF (2026-05-10)
- **最终状态**: 未解出（应用易崩溃，隐藏路由未找到）

## 考点总结
1. **Go Web 应用逆向分析** — 从 Go 编译二进制提取关键函数名、路由信息
2. **SQL 注入 + 黑名单绕过** — 多语句注入 + `EXECUTE IMMEDIATE X'hex'` 绕过关键字过滤
3. **MySQL UDF 提权到系统命令执行** — 写 .so 到插件目录，注册 sys_exec/sys_eval
4. **CRC32/"lucky number" 线索利用** — 题目暗示 CRC32 在 MySQL 中扮演关键角色
5. **Go template SSTI 可能路径** — 发现 `commandHandler` + `parseTemplateString` 隐藏功能

## 详细解题过程

### 1. 信息收集
目标环境两个端点:
- `GET /` — 首页
- `POST /calc` — SQL 计算器，输入表达式 → `SELECT <input> AS result` 发给 MySQL
- `GET /draw?name=undefined` — 计算 CRC32(name)，默认 "undefined"=4275843151

后端: Go Web 应用 + MariaDB 10.11.14 (root@localhost, secure_file_priv=NULL)
反向代理: openresty (nginx + Lua)

### 2. SQL 注入发现与黑名单绕过

输入 `'` 触发 MySQL 语法错误，确认注入点。

**黑名单**: SELECT、UNION、=、_、DROP、CREATE、PREPARE、FLAG、INTO 全被过滤。

**绕过技巧**: 利用 MariaDB 10.11+ 的 `EXECUTE IMMEDIATE X'hex'` 语法 + 多语句注入：
```
原始输入: 1; EXECUTE IMMEDIATE X'53454C4543542031'#
生成 SQL: SELECT 1; EXECUTE IMMEDIATE X'53454C4543542031'#' AS result
```
Hex 字符串仅含 0-9、A-F，完全不触发黑名单。

### 3. MySQL UDF 命令执行（成功）
1. 下载 Metasploit 的 `lib_mysqludf_sys_64.so`（8040 字节）
2. 分为 41 个 200 字节块，通过 `UNHEX()` 逐块 INSERT
3. 设置 `group_concat_max_len=100000`
4. 用 `GROUP_CONCAT` + `INTO DUMPFILE` 写出完整 .so 到 `/usr/lib/mysql/plugin/mysqludf.so`
5. 注册 `sys_exec`/`sys_eval` 函数
6. 执行系统命令成功（id → mysql用户，可读目录列表）

### 4. Go 二进制逆向分析（部分完成）

通过 `LOAD_FILE()` 读取 Go 二进制（~7.5MB），名称为 `70783635_myapp` 位于 `/usr/local/bin/`。

**已知的关键函数**（从上一次环境的分析）:
- `myapp/internal/challenge.calcHandler` — /calc 处理器
- `myapp/internal/challenge.drawHandler` — /draw 处理器
- `myapp/internal/challenge.runCommand` — 执行命令
- `myapp/internal/challenge.commandHandler` — **隐藏命令处理器**（路由未知）
- `myapp/internal/challenge.parseTemplateString` — 解析 Go 模板（可能 SSTI）
- `myapp/internal/challenge.strrot` — 字符串 ROT13 混淆
- `myapp/internal/challenge.getVar` — 获取 HTTP 参数
- `myapp/internal/challenge.checkInput` — 黑名单过滤
- `myapp/internal/challenge.executeQuery` — MySQL 查询执行
- `myapp/internal/challenge.parseTemplateVars` — 解析模板变量
- `myapp/internal/challenge.validateTemplateVars` — 验证模板变量

### 5. /flag 文件状态
- `/flag` 存在，49 字节
- 权限 `-rw------- root root`，仅 root 可读
- mysql 用户无法读取

### 6. 环境稳定性问题
Go 应用在多次 SQL 注入/UDF 命令执行后崩溃（PID 1 无响应），openresty 返回 404。
需要平台手动重启环境。
mysql 用户无法重启 Go 应用（无法绑定端口或连接 MySQL）。

## 未解问题
1. **commandHandler 的隐藏路由路径是什么？** — 可能是 strrot(ROT13) 混淆后的路径。二进制中的路由注册字符串可能被编码。
2. **CRC32 "lucky number" 具体用法** — 题目描述暗示 CRC32 是关键，但未发现具体用途。
3. **如何从 mysql 提权读取 /flag** — auth_pam_tool SUID 漏洞可能已被修补。
4. **Go 应用频繁崩溃** — 每次进入深入利用阶段都会崩溃，可能是有意为之的难度设计。

## 工具链
- Python requests — 自动化注入与利用
- EXECUTE IMMEDIATE X'hex' — 黑名单绕过
- MySQL LOAD_FILE — 读取世界可读文件（包括 Go 二进制）
- UDF lib_mysqludf_sys — 系统命令执行
- Go 二进制字符串搜索 — 发现隐藏功能
