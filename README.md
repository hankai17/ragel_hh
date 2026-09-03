# 编译型规则引擎

一个"规则可编译、插件化、高性能、语义级检测"的规则引擎平台，内置**两套独立实现**，
判定语义一致（sqli 24 条 / xss / log4j 查找表达式），可按需选用：

| | ANTLR4 后端 | Ragel 后端 |
|---|---|---|
| 规则语言 | 标准 ANTLR 语法（`.g4`） | Ragel 状态机语言（`.rl`，生成 C） |
| 匹配方式 | 每条规则编译成独立 C++ 解析器插件（`.so`），引擎逐位置匹配 | 词法 + 骨架 + 规则各自编译为 C 状态机，驱动在 token 流上逐位置匹配 |
| 判定 | `engine` 输出 ALLOW / BLOCK / UNKNOWN | `sql_scan` / `sqli_scan` / `log4j_scan` 输出命中与分类 |
| 实现目录 | `tools/antlr4/` | `tools/ragel/` |
| 规则目录 | `rules/antlr4/`（`.g4`） | `rules/ragel/`（`.rl` + 共享头） |
| 构建期依赖 | java + ANTLR4 C++ runtime | ragel |

ANTLR4 后端：安全人员用**标准 ANTLR 语法（.g4）**写攻击检测规则，`rulec` 编译器把每条规则
编译成独立的 C++ 匹配插件（.so），主引擎 `dlopen` 热加载，在归一化文本的 token 流上逐位置
匹配，判定 ALLOW / BLOCK / UNKNOWN，全程不需要修改、重新编译主引擎。

Ragel 后端：同一套检测面用 **Ragel 状态机**实现——`.rl` 是纯规则（与调用方解耦，放
`rules/ragel/`），可独立生成 C、可被任何库/驱动链接；`tools/ragel/` 只放调用驱动的
`.c` 与测试脚本。Ragel 是确定有限自动机：token 流逐位置判定、每步按规则短路，无
ANTLR 运行时的解析/恢复开销；词法（`sql_tokens.rl`）、共享骨架（`rule_sql.rl`）、
攻击规则（`sqli_rules.rl`）分层生成，同一份代码可同时服务演示驱动与更高层库。

## 整体架构与数据流

```
HTTP Request
   |
   v
Normalization       解码 / 去注释 / 空白折叠 / 关键字混淆还原
   |
   v
Fast Path           廉价预筛（子串扫描），无命中直接 ALLOW
   | 命中
   +------------------------+---------------------------+
   v                        v                           v
ANTLR4 后端           Ragel 后端（SQL）            Ragel 后端（log4j）
MiniSQL.g4 解析        sql_tokens.rl 词法          log4j_lookup.rl 状态机
(完整 SQL 门控)        rule_sql.rl 骨架           识别 ${...} 并分类
   + 逐条插件 .so        sqli_rules.rl 24 条        JNDI/SENSITIVE/
   dlopen 匹配          逐位置匹配（fcall/fret）    CHAIN/EXPR
   v                        v                           v
ALLOW/BLOCK/UNKNOWN    输出命中与攻击类型             输出分类
```

verdict 规则（ANTLR4 `engine`）：完整 SQL 或命中任意规则 → ALLOW；命中 BLOCK 规则 → BLOCK；
两者都不满足 → UNKNOWN（`--fail-closed` 可转 BLOCK，不静默放行）。

## 核心设计原则

### 规则即标准语法，与引擎实现解耦

- `tools/antlr4/MiniSQL.g4`：只判定"是否完整可解析的 SQL"（fullSqlOk 门控 + UNKNOWN 判定），
  不含任何安全语义。
- `rules/antlr4/_shared/`：`SQLTokens.g4` / `RuleSQL.g4` / `Log4jTokens.g4` / `Log4jLookup.g4`
  是规则共享的词法、表达式语法与语义谓词，各 `.g4` `import` 复用。
- 攻击规则（`rules/antlr4/**/*.g4`）是**标准 ANTLR parser grammar**，只描述攻击形状，
  头部注释携带元数据，不依赖引擎实现。
- Ragel 侧同理：`rules/ragel/` 是纯规则（`sql_tokens.rl` 词法 / `rule_sql.rl` SQL 骨架 /
  `sqli_rules.rl` 24 条规则 / `log4j_lookup.rl` log4j 查找），共享头（`sql_tokens.h` /
  `log4j_lookup.h`）是规则与调用方之间的契约；生成、编译、链接全部在调用方侧完成，
  规则目录本身零依赖，新增规则 = 新增一个 `.rl`。

### 判定语义（无 AST 层）

规则匹配直接作用于归一化文本的 token 流，不经过 AST；语义条件（如 `1=1` vs `1=2`、
函数名识别）由规则语言直接表达：ANTLR 侧用**语法谓词**（`isIdent` / `numbersEqual` /
`stringsEqual` 等共享于 RuleSQL），Ragel 侧用**生成 C 的动作代码**（同一定义，
谓词复核后再下结论，两边判定一致）。

### Fast Path 与 Deep Path 分层

| 层 | ANTLR4 后端 | Ragel 后端 |
|---|---|---|
| Fast Path | 子串扫描，无攻击特征直接 ALLOW | 同（驱动侧可选接入） |
| Deep Path | 共享词法 + 规则插件逐位置匹配 | token 流 + 规则状态机逐位置匹配（每步短路） |

### 片段（不完整 SQL）防护

真实请求大多是参数值、注入后缀等**不完整 SQL**（如 `1 OR 1=1`、`admin' OR '1'='1'`、
`UNION SELECT 1,2,3`），完整解析必然失败。系统按四层递进处理：

1. **Fast Path**：无攻击特征直接 ALLOW（性能关键路径）
2. **完整解析**：能解析则直接进入规则判定
3. **规则匹配**：对所有规则在归一化文本 token 流上逐位置匹配（含语义谓词），
   引号不平衡（`admin'`）由共享词法容错处理
4. **UNKNOWN 兜底**：完整 SQL 与规则都不识别时返回 UNKNOWN

片段场景实测（ANTLR4 `engine`）：

```bash
./build/engine "1 OR 1=1"              # BLOCK（always_true + boolean_injection）
./build/engine "2=2"                   # BLOCK（always_true）
./build/engine "UNION SELECT 1,2,3"    # BLOCK（union_select）
./build/engine "admin' OR '1'='1' --"  # BLOCK（string_tautology，引号容错）
./build/engine "id=1"                  # UNKNOWN（无法识别且无规则命中）
```

同一批样本用 Ragel `sqli_scan`（进程内逐位置扫描，输出命中规则）：

```bash
./build/ragel/sqli_scan "1 OR 1=1" "2=2" "UNION SELECT 1,2,3" "admin' OR '1'='1' --" "id=1"
```

已知边界：生产环境仍需对 charset、双重编码、嵌套引号等做升级
（见 misc/DESIGN.md Roadmap）。

## 目录结构

```
├── CMakeLists.txt           # 顶层：双后端聚合入口（add_subdirectory 两套实现）
├── README.md
├── rules/                   # 规则（按引擎分目录，高内聚低耦合）
│   ├── antlr4/              # *.g4 规则
│   │   ├── _shared/         # SQLTokens / RuleSQL / Log4jTokens / Log4jLookup .g4
│   │   ├── sqli/            # sqli_rules.g4（合并 24 条 SQLi 攻击，单插件）
│   │   ├── xss/             # XSS 规则（raw 画像）
│   │   └── log4j/           # log4j 查找表达式规则
│   └── ragel/               # *.rl 规则 + 共享头（纯规则，零依赖，可独立生成/被库调用）
│       ├── sql_tokens.h/.rl # SQL 词法（生成 lex_sql）
│       ├── rule_sql.rl      # SQL 表达式/语句骨架（fcall/fret 递归入口 + 谓词）
│       ├── sqli_rules.rl    # 24 条 SQLi 规则（对齐 sqli_rules.g4 判定）
│       └── log4j_lookup.h/.rl  # log4j ${...} 识别状态机（导出 log4j_scan()）
├── tools/
│   ├── antlr4/              # ANTLR4 后端实现（自含 CMakeLists.txt）
│   │   ├── engine.cc        # 主引擎（Normalization→Fast Path→解析→插件→Verdict）
│   │   ├── rule_compiler.cc # rulec：g4 -> ANTLR 解析器 -> .so 插件
│   │   ├── rule_plugin.h    # 插件 ABI（rule_abi / rule_attack_count / rule_attack / rule_check_text）
│   │   ├── MiniSQL.g4       # 完整 SQL 判定语法（构建期生成解析器到 build/gen/）
│   │   └── examples/        # call_plugin.c / call_log4j_plugin.c（最小 dlopen 示例）
│   └── ragel/               # Ragel 后端驱动 + 构建 + 测试（自含 CMakeLists.txt + Makefile）
│       ├── sql_scan.c       # 驱动：词法 + RuleSQL 骨架扫描
│       ├── sqli_scan.c      # 驱动：24 条规则全量扫描（谓词复核）
│       ├── log4j_scan.c     # 驱动：log4j 查找分类（消费 log4j_lookup.h 契约）
│       └── test.sh / test_sqli.sh / test_log4j.sh
├── misc/                    # 公共：设计文档、antlr jar、演示/校验/压测脚本
└── build/                   # 构建产物（不入库）
    ├── engine / rulec       # ANTLR4 后端二进制
    ├── plugins/             # lib*.so 插件（热加载目录）
    ├── gen/minisql/         # MiniSQL 解析器生成物
    └── ragel/               # gen/*.c + sql_scan / sqli_scan / log4j_scan
```

`tools/log4j_ragel_fcall/`（log4j 的 fcall 变体实验）与 `tools/ragel_fcall/`（fcall 递归
建模试验）保留作参考，不参与构建；迁移前的 `tools/sql_ragel/`、`tools/log4j_ragel/`
已并入上述结构（文件系统残留目录已在 .gitignore 忽略，待 root 权限清理）。

## 组件与职责

| 组件 | 文件 | 职责 |
|---|---|---|
| 完整 SQL 判定 | `tools/antlr4/MiniSQL.g4` | fullSqlOk 门控与 UNKNOWN 判定 |
| 共享规则语法 | `rules/antlr4/_shared/` | SQLTokens / RuleSQL（词法 + 表达式/语句 + 语义谓词） |
| 规则编译器 | `tools/antlr4/rule_compiler.cc` | .g4 → 生成解析器 → `g++ -shared` → `.so` |
| 插件 ABI | `tools/antlr4/rule_plugin.h` | `rule_abi / rule_attack_count / rule_attack / rule_check_text` |
| 主引擎 | `tools/antlr4/engine.cc` | Normalization → Fast Path → 解析判定 → Rule Engine → Verdict |
| 规则集(g4) | `rules/antlr4/` | sqli(24) + xss(1) + log4j(4 类) |
| 规则集(rl) | `rules/ragel/` | sql_tokens + rule_sql + sqli_rules(24) + log4j_lookup |
| Ragel 驱动 | `tools/ragel/` | sql_scan / sqli_scan / log4j_scan（调用方示例） |
| 校验逻辑 | `misc/*.sh` + `tools/ragel/test*.sh` | 正/负样本断言（见下） |

## 规则集

### ANTLR4 后端（`rules/antlr4/`，构建为 .so 插件）

- 拦截型（命中即 BLOCK）：`always_true`（`1=1` / `2=2` / `1=1.0` 恒真）、`string_tautology`
  （`'a'='a'`）、`boolean_injection`（OR/AND 一侧为常量比较）、`union_select`、
  `stacked_query`、`sleep`、`load_file`、`benchmark`、`pg_sleep`、`script_tag`（XSS）
- 检测型（`action: ALLOW` 只告警，避免误伤合法 SQL）：子查询、EXISTS/IN、LIKE、BETWEEN、
  数值表达式（`1+1=2`）、ORDER BY、LIMIT、字符串拼接（`||`）、
  INSERT/UPDATE/DELETE/SELECT 语句片段、information_schema 枚举
- log4j：`jndi`（Log4Shell 类：直接 `${jndi:...}` 或任意深度嵌套混淆）、`sensitive`
  （env/sys/docker/k8s/aws/spring/main 前缀）、`nested_chain`（多层 ${...} 递归）、
  `expr`（结构识别，LOW/ALLOW）
- profile 门控：`sql` 始终参与匹配；`fragment` / `raw` 仅在输入**不是完整 SQL** 时参与

### Ragel 后端（`rules/ragel/`，与上同源同语义）

- `sqli_rules.rl`：24 条 SQLi 规则（`always_true` / `string_tautology` /
  `boolean_injection` / `union_select` / `stacked_query` / `sleep` / `load_file` 等，
  语义谓词与 g4 版一致）
- `log4j_lookup.rl`：log4j 四类判定（JNDI > SENSITIVE > CHAIN > EXPR，与
  `log4j_rules.g4` 分类一致），导出 `log4j_scan()` 库接口

## 快速开始

前置：g++、make、cmake、java（ANTLR4 解析器构建期生成）、ANTLR4 C++ runtime
（缺省前缀查找；特殊位置用 `cmake -DANTLR4_RUNTIME_DIR=/opt/antlr`）、
ragel（构建 Ragel 后端；未安装时顶层 cmake 会跳过 ragel 目标并提示）。

```bash
cmake -S . -B build                       # 配置（默认 Debug；加 -DCMAKE_BUILD_TYPE=Release）
cmake --build build -j                    # 构建 engine + rulec + 全部插件 + ragel 扫描器
cmake --build build --target demo         # antlr4 端到端演示（11 个样本）
cmake --build build --target validate     # antlr4 sqli 规则校验（49 正/负样本断言）
cmake --build build --target validate_log4j  # antlr4 log4j 规则校验（23 样本）
cmake --build build --target validate_ragel  # ragel 规则校验（40 + 93 + 25 断言）
```

手工检测：

```bash
# ANTLR4 后端
./build/engine "SELECT * FROM users WHERE 1=1"                    # BLOCK: always_true
./build/engine "SELECT * FROM t WHERE a=1 OR 1=2"                 # BLOCK: boolean_injection
./build/engine "SELECT id FROM a UNION SELECT pwd FROM admin"     # BLOCK: union_select
./build/engine "1;DROP TABLE users"                               # BLOCK: stacked_query
./build/engine "GET /q?x=<script>alert(1)</script>"               # BLOCK: script_tag
./build/engine --fail-closed "hello union world"                  # 解析失败 -> BLOCK
./build/engine '${jndi:ldap://evil/x}'                            # BLOCK: log4j_jndi

# Ragel 后端（进程内批处理）
./build/ragel/sqli_scan "SELECT * FROM users WHERE 1=1" "1 OR 1=1" "id=1"
./build/ragel/log4j_scan '${jndi:ldap://evil/x}' '${env:HOME}'
```

Ragel 后端也可脱离 cmake 直接构建（产物与 cmake 一致，输出到 `build/ragel/`）：

```bash
cd tools/ragel && make            # 或 make all
make test                         # RuleSQL 骨架断言（40）
make test-sqli                    # 24 条规则断言（93）
make test-log4j                   # log4j 分类断言（25）
```

## 规则写法

### ANTLR4 后端（标准 ANTLR 语法）

```g4
// rule: always_true
// severity: HIGH
// action: BLOCK
// description: 恒真条件：两侧等值常量（1=1 / 2=2 / 1=1.0）
// profile: sql

parser grammar always_true;

options { tokenVocab = SQLTokens; }

import RuleSQL;

// 语义谓词 numbersEqual 做数值规范化比较：1=1、2=2、1=1.0 命中，1=2 不命中
pattern : l=NUMBER EQ r=NUMBER {numbersEqual($l, $r)}? ;
```

新增一条攻击（安全人员视角，不碰 C++）：编辑 `rules/antlr4/sqli/sqli_rules.g4`
追加 parser rule（含 `// rule:/severity:/action:/description:` 元数据），然后
`cmake --build build --target plugins` 即生成新插件，`./build/engine` 立即可测。

### Ragel 后端（状态机规则 + 谓词动作，与 g4 同一条规则对应）

`rules/ragel/sqli_rules.rl` 里 `1=1` 恒真条件与 `always_true.g4` 对应：

```
  # 恒真条件：NUMBER EQ NUMBER 且两侧数值相等（1=1 / 2=2 / 1=1.0 命中，1=2 不命中）
  always_true_rule := |*
      NUMBER EQ NUMBER => {
          if (const_numbers_equal()) { attack_sqli(N_ALWAYS_TRUE, "always_true",
              "恒真条件：两侧等值常量（1=1 / 2=2 / 1=1.0）"); }
      };
      any => {};
  *|;
```

要点：状态机负责形状（token 类型是字母表），`const_numbers_equal()` 等谓词是生成 C
里的共享函数（与 g4 版 `numbersEqual` 同一判定）；新增规则 = 在 `sqli_rules.rl` 加一个
`*_rule :=` 状态机并登记入口。词法（`sql_tokens.rl`）与骨架（`rule_sql.rl`）不需改动。

## 验证结果

- antlr4 `demo` 11 例：良性 SQL ALLOW；恒真 / UNION / SLEEP / LOAD_FILE / BENCHMARK /
  XSS / 堆叠 / 片段（`1 OR 1=1`、`UNION SELECT`、`admin' OR '1'='1'`）均 BLOCK
- antlr4 `validate` 49 例：拦截/检测正例 + 危险函数/XSS 正例 + 片段正例全部命中；
  负样本（`id=1`、`a=1 AND b=2`、`age > 18` 等）零误报
- antlr4 `validate_log4j` 23 例：Log4Shell 直接/嵌套/大小写变体命中，敏感前缀命中，
  普通文本（`${date}` 等）不误报
- ragel `validate_ragel`：`test.sh` 40（骨架语义）+ `test_sqli.sh` 93
  （24 条规则正/负/对抗样本）+ `test_log4j.sh` 25（分类与大小写）全部通过；
  与 antlr4 版 validate 断言逐条同语义
- 性能参考：Ragel 逐位置匹配为编译期确定 DFA，无 ANTLR 运行时开销；
  对抗输入（如 `1=1` 重复）扩展性近线性，进程内单请求可达 µs 级
  （压测脚本见 `misc/bench_sqli.sh`（engine）与 `tools/ragel/` 说明）

## 设计文档与需求原文

- 完整设计（架构、规则语法、编译流水线、插件 ABI、Roadmap、Ragel 后端对比）：
  [misc/DESIGN.md](misc/DESIGN.md)
- 原始需求：[misc/README](misc/README)
- 引擎 QA 记录：[misc/antlr_engine_qa_summary.md](misc/antlr_engine_qa_summary.md)
