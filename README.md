# sql_ragel

用 ragel 把 SQL 语法写成状态机的小实验。输入一条 SQL，先用词法切出 token，
再在 token 流上跑语法骨架，识别 `expr` / `select_stmt` / `constant_value`。
`select_stmt` 能整条覆盖输入时，说明输入是一条结构完整的 SELECT 语句。

## 目录

```
rules/ragel/        规则源（.rl + 配套 .h）
  sql_tokens.rl     词法：SQL 文本 -> token 流
  rule_sql.rl       语法骨架：expr / select_stmt / constant_value
sql_scan.c          驱动：打印 token 流和各骨架的最长命中
test.sh             骨架断言
CMakeLists.txt      构建入口（产物在 build/ragel/）
Makefile            不依赖 cmake 的等价构建
misc/               历史归档（早期 ANTLR4 后端等）
```

## 构建与测试

需要 ragel 和 gcc/cmake。

```
cmake -S . -B build && cmake --build build -j
make -j                # 或直接用 Makefile，产物一致
make test              # 跑 test.sh 断言
```

## 运行

```
./build/ragel/sql_scan 'SELECT * FROM users WHERE 1=1'
./build/ragel/sql_scan 'SELECT * FROM (SELECT id FROM t) WHERE 1=1'
```

输出示例：

```
input: SELECT * FROM (SELECT id FROM t) WHERE 1=1
tokens(13): SELECT STAR FROM LPAREN SELECT IDENT FROM IDENT RPAREN WHERE NUMBER EQ NUMBER
  expr [10,13)
  select_stmt [0,13) (whole)
```

`(whole)` 表示 `select_stmt` 覆盖了全部 token，即一整条 SELECT。

## 说明

- 规则改动只需编辑 `.rl` 重新构建，生成 C 是中间产物，不要手工改。
- `sql_scan.c` 只 include 头（`sql_tokens.h` / `rule_sql.h`）并链接
  `libragel_sql.a`，不直接接触生成的 `.c`。
- 递归（括号嵌套、子查询）由 ragel 的 fcall/fret 实现，细节见
  `rules/ragel/rule_sql.rl` 头注释。

## 历史

早期实现过一套 ANTLR4 后端（.g4 -> 插件 -> engine），已归档到
`misc/archive_antlr4/`，不参与构建。sqli / log4j 相关的 ragel 实验在
精简为"单条 SQL 识别"时移除。
