# antlr4_hh 规则引擎问答总结（生成代码 / ATN / 性能 / 对抗与修复）

> 归档说明：本文汇总一次完整的设计问答链，覆盖 rulec 生成的插件代码
> （`rule_check_text` / `sqli_rules.cpp` / ATN）、WAF 语义引擎性能评估、
> 滑窗重解析的对抗案例、实测与修复（快速失败 + 预算）与 ANTLR4 规则匹配
> 复杂度。内容自包含，可整体归档到其他目录。

## 0. 关联信息

相关提交：

- `c2cfbc4` docs: 补充生成代码详解（rule_check_text / sqli_rules.cpp / ATN）
  —— 写入 `misc/DESIGN.md` §12
- `e736107` test: 添加对抗性滑窗重解析用例与性能基准脚本
  —— 新增 `misc/bench_sqli.sh`，`misc/validate_sqli.sh` 加对抗用例
- `8fb26ca` fix: 规则插件快速失败并加尝试/耗时预算
  —— `rule_compiler.cc` wrapper 模板修复

相关文件：

- `rule_compiler.cc`：rulec（wrapper 模板）
- `engine.cc`：主引擎（Normalization / Fast Path / 规则引擎）
- `rules/sqli/sqli_rules.g4`、`rules/_shared/`：规则语法与共享词法
- `build/plugins/gen/sqli_rules_rule.cc`、`sqli_rules.cpp`：生成产物
- `misc/DESIGN.md` §12：生成代码详解（长期文档）
- `misc/bench_sqli.sh`：性能基准；`misc/validate_sqli.sh`：正确性校验
- `misc/antlr_trycatch_notes.md`：第 13 节的单独归档版

---

## 1. Q：解释生成的 rule_check_text 代码

`rule_check_text` 是插件 `.so` 暴露的 C ABI 入口，主引擎通过 `dlsym` 调用；
由 `rule_compiler.cc` 的 `generateWrapper()` 按模板生成到 `*_rule.cc`。

```c
int rule_check_text(const char* text, int* matched,
                    int* startOff, int* endOff, int max_matches)
```

一句话：**对归一化文本，在任意 token 位置尝试解析每个攻击子规则，能完整解析
出来就记一次命中，返回命中总数和每个命中的字符区间。**

流程：

1. 词法：`ANTLRInputStream`（容忍空指针）→ `SQLTokens` 词法 →
   `CommonTokenStream` + `tokens.fill()`；`removeErrorListeners()` 关闭默认报错。
2. 过滤可见 token：只保留 `DEFAULT_CHANNEL` 上的 token（丢弃空白/注释），
   遇 EOF 停止。
3. 双重循环：外层是每个可见 token 起点 `i`，内层是每条规则 `k`；
   `done[k]`（每条规则最多命中一次）与 `startsOk(k, t)`（按 `// start:`
   元数据做的首 token 过滤）两个快速跳过条件；`tokens.seek()` 回退到候选起点，
   新建 parser，`switch (k)` 调用 `parser.xxx_pat()`。
4. 命中判定：`getNumberOfSyntaxErrors() != 0` 即未命中（当前模板为无异常控制流）。
5. 记录：`matched[count]=k`（规则索引）、`startOff`（首个 token 字符偏移）、
   `endOff`（最后一个被消费 token 的 stop index，区间含端点）、`count++`；
   `count < max_matches` 保护输出数组。
6. 返回值 = 命中数；拦截与否由引擎读 `AttackInfo`（severity/action）决定。

语义要点：

- 命中不锚定：每个 token 起点都试，`UNION SELECT` 藏在中间也能命中；
- `done` 数组：同一攻击类型只报告一次；
- 版本差异：`build-release/` 里是旧模板（规则外层循环 + BailErrorStrategy +
  try/catch），`build/` 与当前源码是新模板（startsOk + done + 无异常判定）；
  差异是模板演进，不是代码损坏。

## 2. Q：每个 token 分配一个 parser？parser 是临时对象，奇怪

纠正：不是"每个 token 一个 parser"，而是**每个（token 起点 × 规则）一次尝试各新建
一个 parser**（在内层循环里构造）。临时对象没问题：

1. 构造便宜：ATN / DFA 预测缓存是**静态共享**的（`OnceFlag` 只初始化一次），
   每次构造只是接 token 流与错误处理器。
2. 复用有风险：parser 持有 `_syntaxErrors` 计数、token 索引、解析上下文、错误
   恢复状态等；复用会累积错误计数导致误判。ANTLR 有 `Parser::reset()`，但
   "用完即弃"最不容易出错。
3. 作用域刚好覆盖用途：`switch` → 查错 → 取 token 位置 → 写数组，信息在析构前
   全部提取，无状态逃逸、无泄漏。

真正开销在**滑窗式重解析**本身（见第 7 节），`startsOk` / `done` 是剪枝手段。

## 3. Q：tokens.seek 是截取后面所有 tokens 吗

不是截取，是**移动读指针**：

```cpp
void BufferedTokenStream::seek(size_t index) {
  lazyInit();
  _p = adjustSeekIndex(index);   // 只把游标 _p 指到 index
}
```

- 缓冲 `_tokens` 一个不删，parser 从 `_p` 开始往后读，前面的 token 只是不可见；
- `CommonTokenStream::adjustSeekIndex` 实现为 `nextTokenOnChannel`：seek 会跳到
  指定位置后第一个默认通道 token（传入的本来就是 `visible[i]`，通常即它自己）；
- parser 从 `_p` 开始读**不一定读到 EOF**——规则匹配完即停，剩余 token 留在
  缓冲供下一次尝试。

## 4. Q：xxx_pat 函数中有静态的东西？做什么工作

`static` 不在 `xxx_pat()` 函数体里，而在生成 parser 文件**顶部与初始化函数里**：

- `sqli_rulesParserOnceFlag`（`OnceFlag`）+ `thread_local unique_ptr<
  Sqli_rulesStaticData>`：一次性初始化锁与共享数据；
- `static const int32_t serializedATNSegment[]`：序列化 ATN 表。

`sqli_rulesParserInitialize()` 只执行一次，做四件事：

1. 组装规则名/字面量名/符号名表并构造 `Vocabulary`；
2. `ATNDeserializer::deserialize()` 把紧凑整数表还原成 `ATN` 对象；
3. 为 ATN 每个 decision 预建 `DFA` 放进 `decisionToDFA`（自适应预测缓存）；
4. 建 `sharedContextCache`（预测上下文缓存）。

每个 parser 构造函数：`initialize()` + `new ParserATNSimulator(...)`——模拟器
按实例新建，ATN/DFA/缓存全部共享。这就是"新建 parser 便宜"的原因。

`xxx_pat()` 调用时（普通运行时解析工作）：

1. `_tracker.createInstance<XxxContext>()` 分配解析树节点（parser 析构统一回收）；
2. `enterRule` 压栈设起始状态；
3. 按语法 `match` token、求语义谓词（如 `isIdent($i, "sleep")`，大小写不敏感）、
   处理可选片段；
4. `finally { exitRule(); }` 保证异常下也正确退出；
5. `catch (RecognitionException)` → `reportError` + `recover` —— 这是
   `_syntaxErrors` 增加、判定"未命中"的依据。

分工：**静态部分 = 语法本体的缓存，一次性建好共享；`xxx_pat()` = 每次解析的
执行体**。`rule_check_text` 不用解析树，只关心错误计数与 token 位置。

## 5. Q：详细讲讲 sqli_rules.cpp 以及 ATN

`sqli_rules.cpp` 由 ANTLR 4.13.2 从 `rules/sqli/sqli_rules.g4` 生成（24 条攻击、
41 个语法规则），配套 `sqli_rules.h`（声明）、`SQLTokens.cpp`（共享词法）、
`sqli_rules_rule.cc`（wrapper）。结构自上而下：

1. 匿名命名空间 `Sqli_rulesStaticData`：`ruleNames` / `literalNames` /
   `symbolicNames` / `vocabulary` / `decisionToDFA` / `sharedContextCache` /
   `serializedATN` / `atn`；
2. 静态初始化：`OnceFlag` + `thread_local` + `sqli_rulesParserInitialize()`；
3. Parser 构造函数：`initialize()` + `new ParserATNSimulator(...)`，元数据访问器
   （`getATN` / `getRuleNames` / `getVocabulary` ...）；
4. Context 类群：每规则一个解析树节点类及访问器；
5. 规则函数：执行体；简单决策用生成器预计算的 bitset 判断
   （如 `(1ULL << _la) & 294717317185536`），复杂决策走 ATN 自适应预测；
6. Sempred 谓词函数：`.g4` 里 `{...}?` 的谓词在解析与预测两处都要能求值。

**ATN（Augmented Transition Network）= 整部语法的编译产物：一张状态转移图。**
每条规则、每个 alternative、每次 token 匹配、每个子规则调用、每个循环都映射成
图里的状态与转移。sqli_rules 有 **396 个状态**（`serializedATNSegment` 开头
`4,1,55,396` = 版本 4 / PARSER / 最大 token 类型 55 / 状态数 396）。

关键设计是**序列化**：不生成几百行 `new State()`，而是压成 `int32_t` 数组，
运行时 `ATNDeserializer` 一次还原，全插件共享。

ATN 两大运行时职责：

1. 语法识别（recognize）：预测定路径后按方案 `match`；
2. **ALL(\*) 自适应预测**：决策点时 `ParserATNSimulator` 在 ATN 图上做图遍历 +
   试探性消费 token，动态决定 lookahead（而非固定 LL(k)），结果缓存进该决策点
   的 DFA。

ATN 与 DFA 的关系：**ATN = 语法蓝图（静态、完整）；DFA = 运行时预测缓存
（每个决策点一个，随解析学习变厚）。**

为什么适合 WAF 碎片匹配：ANTLR parser 允许**从任意规则作为起始规则**解析，
因此 wrapper 能对每个 token 起点调用 `sleep_pat()` 等碎片规则；命中与否只由
"该规则是否无错解析完"决定，不依赖解析树。

## 6. Q：这套基于 ATN 的语义分析引擎性能如何？作为 WAF 产品怎么评判

### 6.1 从代码看性能特征

便宜的（设计好的）：

- Fast Path 全流量门控：归一化后 O(n) 子串扫描，无命中直接 ALLOW，不进语义层
  （`engine.cc`：`kFastPathTokens` 特征表）；
- ATN/DFA 静态共享、一次性构建；
- `startsOk` 首 token 过滤 + `done` 数组剪枝；
- 碎片规则本身很小，命中路径快。

贵的（瓶颈）：

1. **每插件独立分词**：每个 `rule_check_text` 各自 `SQLTokens` + `tokens.fill()`，
   N 个插件 = N 次 O(n) 词法；
2. **滑窗重解析**：每个候选起点 × 每条规则从该位置重解析，失败尝试也付全价
   （修复前还叠加错误恢复吞到 EOF，见第 7 节）；
3. **每尝试两次堆分配**：新 parser + `new ParserATNSimulator`，外加上下文节点；
4. 当前模板（修复前）无 BailErrorStrategy，失败尝试走默认错误恢复，比快速失败贵；
5. DFA 缓存无上限：长跑对抗性多样输入可能无限增长；`thread_local` 模式每线程
   各一份，内存放大；
6. 原型引擎每次请求 dlopen 全部插件（原型代价，生产必然去掉）。

复杂度模型：请求 ≈ O(n) 归一化 + O(n) fast path +（命中时）Σ插件
[O(n) 分词 + Σ位置×Σ规则 O(单次解析)]。良性流量大多停在 fast path——这个
分层符合 WAF 流量分布，方向正确。

### 6.2 作为产品怎么评判

1. **分阶段打点**：归一化 / fast path / SQL 解析 / 每插件 `rule_check_text`
   分开计时，看 p50/p95/p99/p999（不是平均），并记录分配次数/字节；
2. **输入长度伸缩**：1K/4K/16K/64K/256K 画 latency-vs-length 曲线，重点构造
   对抗样本（`1=1` 重复、分号/IDENT/括号风暴、深嵌套）找二次方/爆炸点；
3. **规则/插件数伸缩**：1/10/100 条、1/N 个插件，验证加法成本；
4. **并发与缓存**：线程 × QPS、DFA 缓存命中率、`thread_local` 内存增长、
   长跑 RSS 是否单调上涨；
5. **对照基准**：libinjection（微秒级字符串检测）、ModSecurity 类正则引擎；
   必须配套 TPR/FPR——纯比速度无意义，语义层贵的部分要买到准确率；
6. **产品 KPI**：附加延迟预算（如 <1ms 或 <5%）、饱和 QPS、超时/熔断行为、
   每百万请求 CPU 成本、48h p99 漂移与内存曲线。

判断：架构站得住，但当前实现要上高 QPS 边缘部署，会先死在"每插件重分词、
每尝试重分配、失败路径错误恢复、无性能预算"四件事上，而不是 ANTLR 本身。
好 WAF 语义引擎的标准是：**正常流量几乎无感、可疑流量才付语义代价，最坏输入
下有界、可控、可预测**。

## 7. Q：滑动窗口重解析的对抗案例

攻击思路：让很多规则以**合法开头 token** 开始尝试、然后全部失败——失败尝试
既不会被 `done` 标记，又会触发错误恢复。

### 案例：`1=1 1=1 ...`（重复 1000 次，3000 token）

词法：`NUMBER EQ NUMBER NUMBER EQ NUMBER ...`。NUMBER 是 8 条规则的首 token
（`always_true` / `string_tautology` / `boolean_injection` / `in_subquery` /
`like_expr` / `between_expr` / `numeric_expr` / `string_concat`），`startsOk`
全部放行。

位置 0 逐条行为：

| 规则 | 过程 | 结果 | 代价 |
|---|---|---|---|
| always_true_pat | `constant_value EQ constant_value` + 谓词通过 | 命中 | 3 token |
| numeric_expr_pat | `arith EQ add_expr` | 命中 | 便宜 |
| string_tautology_pat | 首个 `match(STRING)` 遇 NUMBER | 失败 → recover 吞到 EOF | O(n) |
| boolean_injection_pat | `const_cmp` 后要 AND/OR，遇 `1` | 失败 → 吞到 EOF | O(n) |
| in_subquery / like / between / string_concat | 匹配 `1` 后要 IN/LIKE/BETWEEN/`\|\|` | 失败 → 吞到 EOF | O(n) |

**为什么吞到 EOF**：生成的 catch 调 `recover()`；`getErrorRecoverySet` 对顶层
起始规则（无 invoking state）返回空集，`consumeUntil` 只能一路吞到 EOF——
位置 i 的一次失败尝试成本 O(n-i)。

**放大**：6 条失败规则在**每一个 NUMBER 位置**重复尝试（2000 个），总量
≈ 6 × Σ O(n-i) ≈ 6 × n²/2。n=3000 时约 2700 万次 token 消费 + 约 12000 次
parser/simulator 堆分配。输入翻倍 → 成本 4 倍（O(n²) 形状）。

变体：

- `;` × 1000：仅 `stacked_query_pat`（SEMI 起始），单规则 n²/2，常数小；
- `x x x ...`：IDENT 约在 10 条规则起始集合里（`isIdent` 谓词失败同样走
  recover），但若 fast path 无命中则根本不进深检；
- `x=1` / `1=1;x` 混合：覆盖 NUMBER+SEMI+IDENT 起始集合，放大更狠。

## 8. Q：添加这个测试案例，看看时间消耗

实施（提交 `e736107`）：

- `misc/validate_sqli.sh`：新增 `1=1`×200 组对抗用例，断言 `BLOCK always_true`
  （正确性回归哨兵）；
- `misc/bench_sqli.sh`：基准脚本（基线 + 规模扫描 + 变体），单次计时。

修复前实测（Debug 构建，进程级 wall time 含 dlopen/初始化）：

| 用例 | 耗时 |
|---|---|
| 良性 fast path | 4 ms |
| 良性 SQL 深检 | 9 ms |
| 短攻击 SLEEP(5) | 6 ms |
| 1=1 × 100 | 46 ms |
| 1=1 × 250 | 141 ms |
| 1=1 × 500 | 416 ms |
| 1=1 × 1000 | 1544 ms |
| 1=1 × 2000 | 6508 ms |
| `;` × 1000 | 80 ms |
| `x=1` × 1000 | 2068 ms |
| `1=1;x` × 500 | 1186 ms |

结论：二次方实锤（1000→2000 约 ×4.2）；正常流量个位数毫秒；对抗输入把单请求
成本抬高 100~1000 倍。

## 9. Q：怎么修复这种问题

按收益从大到小：

1. **失败快速退出**（收益最大）：wrapper 设 `BailErrorStrategy` + try/catch，
   首个错误立即抛出，不做 EOF 恢复——单条规则总成本从 O(n²) 降到 O(n × 规则长)；
2. **尝试次数预算**：单次 `rule_check_text` 限制尝试数，超限返回已命中，
   引擎按 fail-closed 处理（截断日志）；
3. **输入长度上限**：进入深检的 payload 限长（如 4/8KB），超出走 fast path +
   fail-closed；
4. **parser 对象池**：`reset()` 复用，省每尝试两次堆分配；
5. **规则外层循环 + 每规则独立候选位置**：结构性梳理，收益被前两项覆盖；
6. **共享分词**：引擎分词后跨插件复用（需动 ABI），规则多了以后是主要开销。

推荐顺序：立即做 1+2+3 → 用 bench 脚本固化前后对比 → 中期做 4、6。

## 10. Q：频繁的 try/catch 会不会不太好

要点：

- 现代 C++（Itanium ABI）零成本异常处理：**try 本身几乎免费，贵的是 throw**；
- 每次 throw：异常对象分配 + 栈展开 + handler 查找 + 沿途析构，约几百 ns 到
  几 µs；12000 次尝试纯异常开销约 5~30ms 量级；
- 本场景对比：默认恢复吞 EOF（实测 6.4s）≫ bail+异常（估计几十 ms）≫
  bail+预算（有界）。
- 三个降成本杠杆：预算限制 throw 次数；规则栈浅（2~3 层）unwind 便宜；
  成功路径不 throw，生产流量大多停 fast path；
- 不抛异常的替代：ANTLR 的失败语义建立在异常上（`match()` 无返回码通道），
  自定义错误策略"不抛只置标志"可行但要处理循环进度陷阱（见 13 节）；
- 结论：bail + 预算是对的取舍，不是硬规避异常；用 bench 验证而非猜测。

## 11. Q：当前逻辑有问题吗？匹配失败不 throw 直接尝试下一条规则

先纠正：**底层其实抛了**——ANTLR 生成的规则函数自带
`catch (RecognitionException) { reportError; recover; }`，`match()` 错配时运行时
抛 `InputMismatchException` 被规则函数接住再恢复；wrapper 层不抛，只看
`getNumberOfSyntaxErrors() != 0`。

判定正确性方面没有 bug：

- 错误计数是可靠信号：出过错误计数 ≥1 且**永不回退**，即使恢复后"继续解析成功"
  也不会清零；
- 每次尝试新 parser，计数不跨尝试累积；
- 每轮尝试前 `tokens.seek(visible[i])`，上个 parser 吞到 EOF 不影响下一轮起点；
- `done[k]` 只在成功时置位（失败规则重复尝试是性能浪费，不是判定错误）。

真正的缺陷在性能与结构性：

- `recover()` 对顶层规则吞到 EOF → 失败成本 O(n-i)，滑窗叠成 O(n²)；
- 无任何预算（尝试数/耗时均无上限），最坏情况不可控；
- 语义耦合：ANTLR 规则函数模板是"容错解析"语义（面向完整输入恢复继续），
  与"匹配尝试"语义（失败即放弃起点）不匹配。

结论：能判对，但最坏情况不可控；修复 = 快速失败 + 预算（第 9、12 节）。

## 12. Q：你改一下（实施与验证）

改动（提交 `8fb26ca`，`rule_compiler.cc` 的 `generateWrapper` 模板）：

1. 每次尝试设置 `BailErrorStrategy` + `try/catch`——首个语法错误立即抛出，
   不再默认恢复吞到 EOF；
2. 尝试预算：`kMaxAttempts = 1024`，超限 `return count`；
3. 耗时预算：`kMaxMillis = 5`（steady_clock 每尝试检查），超时提前返回。

验证：

- 校验 48/48 PASS，判定语义无回归；
- `1=1`×2000 仍命中 `always_true` → BLOCK（预算截断发生在位置 0 命中之后）。

修复后基准：

| 用例 | 修复前 | 修复后 |
|---|---|---|
| 1=1 × 100 | 46 ms | 17 ms |
| 1=1 × 500 | 416 ms | 42 ms |
| 1=1 × 1000 | 1544 ms | 72 ms |
| 1=1 × 2000 | 6508 ms | 134 ms |
| `;` × 1000 | 80 ms | 46 ms |
| `x=1` × 1000 | 2068 ms | 74 ms |
| `1=1;x` × 500 | 1186 ms | 59 ms |

关键变化：二次方消失（输入翻倍 ×1.9 且受预算封顶），对抗输入从秒级降到百毫秒内。
剩余成本主要是 lexing、位置扫描、每尝试分配与异常。注意：预算截断返回部分命中，
ABI 暂无"扫描被截断"标志，靠 fail-closed 兜底（可后续扩展）。

## 13. Q：ANTLR 靠 try/catch 表示匹配失败，太重了吧

（详细归档见 `misc/antlr_trycatch_notes.md`，要点如下）

直觉成立：异常作为高频失败信号是重的；修复后对抗输入仍比良性深检贵约 20 倍，
剩余开销主要是每尝试堆分配 + 异常 throw/unwind。

但这是 ANTLR 架构下唯一简单且必然正确的失败通道：

- 生成的规则函数是递归下降代码，`match()` 成功返回 token，**失败无返回值通道**，
  只能靠异常从嵌套调用中"炸"出来；
- `Parser::match()` 不匹配即走 `_errHandler->recoverInline()`，默认/BAIL 策略
  都 throw；`BailErrorStrategy` 是官方"快速失败"工具，Java/C#/C++ 一致，
  yacc 系同样用异常。

成本构成：零成本 EH（不抛时 try 零开销）；每次 throw 几百 ns~几 µs；本项目
栈浅但频率高（预算封顶 1024 次/调用）。

更轻的替代（按激进程度）：

1. **自定义短路错误策略**：首次错误只置标志、后续 `match()` 快速返回，规则
   "跑完"后查标志——单次失败降为 O(规则长度) token 检查；但 match 不消费 token
   时 `(expr)*` 循环会原地打转，必须保证 token 推进（failsafe consume），
   这是 ANTLR 用异常的深层原因之一；
2. **减少失败频率**：预算已封顶；更细的首 token 索引、每规则候选位置推进；
3. **parser 对象池**：`reset()` 复用，省每尝试两次 `new`；
4. **热门规则手写匹配器**：返回码表达失败，最快；代价是规则集分裂、失去
   "安全人员只写 .g4"的定位。

结论：当前 bail + 预算是对的取舍；产品级下一步顺序 = 对象池 → 短路错误策略 →
手写匹配器，每步用 `bench_sqli.sh` 验证；最终目标不是消除异常，而是**最坏输入
开销接近良性输入**。

## 14. 复现方法

```bash
# 构建（含插件生成；改 rule_compiler.cc 后重新 cmake --build 即重新生成）
cmake -S . -B build && cmake --build build -j

# 正确性校验（含对抗用例）
./misc/validate_sqli.sh build/engine build/plugins

# 性能基准（基线 + 1=1 规模扫描 + 变体）
./misc/bench_sqli.sh build/engine build/plugins

# 单次对抗输入验证
payload=$(printf '1=1 %.0s' $(seq 1 2000))
./build/engine --rules build/plugins "$payload"
```

注意：engine 对 BLOCK 返回非 0 退出码，bench 脚本只计时不计成败。

## 15. Q：antlr4 rules 里的规则匹配复杂度是多少

### 15.1 结论先行

ANTLR4 规则匹配的复杂度要拆成两部分：**确定性匹配**（便宜）和**决策预测**
（开销大头）。整体上：对 LL(k)/无歧义/有界前瞻的语法接近 O(n) 线性；理论
最坏上界是 **O(n⁴)**（论文 Theorem 6.3）；对常见语言论文实测"几乎总是线性"。
落到本引擎的滑窗重解析场景，规则级匹配最坏是 **O(R·n²)**（R = 规则数，
n = 可见 token 数），这正是对抗输入退化的来源。

### 15.2 单条规则的匹配本身

ANTLR4 生成递归下降 parser，每个 rule 对应一个函数。规则体内按 sequence 顺序
匹配子规则和 token：

- 单个 token 比对是 O(1)；
- 一段规则的顺序匹配是 O(规则体长度)；
- 这部分是确定性的，不会成为瓶颈。

### 15.3 决策点（decision）的预测是开销大头

规则里只要有分支（`a | b`、`(...)*`、可选块），就会调用 `adaptivePredict`，
做 ATN 模拟：

- 并行模拟所有 viable alternatives，用配置集合（ATNConfig set）合并去重，
  边消费 lookahead 边淘汰候选；
- 结果缓存到**每个 decision 独立的 prediction DFA**（key = decision + 输入
  位置），下次同位置直接命中；
- SLL 预测冲突时回退到 full-context LL 预测（带调用栈/图结构栈），更贵。

复杂度概括：

| 场景 | 复杂度 |
|---|---|
| LL(k)、有界前瞻、无歧义的 decision | 单次预测 O(k)，摊销后整次解析 O(n) |
| 需要扫到输入末尾才能定论的 decision | 单次预测最坏 O(n) |
| 理论最坏上界（Parr et al., OOPSLA 2014, Theorem 6.3） | **O(n⁴)**：最坏情况下每个输入符号都要做一次预测，单次预测的符号检查可达 O(n²) 量级 |
| 论文实测 | 对常见语言"几乎总是线性"（consistently performs linearly on grammars used in practice） |

直观口径（Terence Parr 对 LL(*) 的说明）：单次决策最坏 O(n)（扫到输入末尾），
如果每个 token 都触发一次这种决策，整体就是 O(n²)。ALL(*) 加 DFA 缓存与配置
合并后实际好得多，但理论最坏上界是 O(n⁴)。

### 15.4 匹配失败的成本

"规则匹配失败"不是快速返回：ANTLR4 会走**错误恢复**（单 token 插入/删除、
异常抛出、resync），再被 try/catch 接住。一次失败尝试的成本 = 从该位置开始的
完整解析 + 错误恢复 + 异常处理，不是 O(1)。详见 `misc/antlr_trycatch_notes.md`。

### 15.5 落到本引擎的滑窗场景

```
总成本 ≈ 候选位置数 × 规则数 × 单次规则匹配的失败成本
```

单次匹配最坏 O(m)（m = 剩余长度），整体最坏 **O(R·n²)**；若某条规则内部有
歧义、触发 SLL→LL 回退，理论上还可更糟。第 7 节的对抗输入（`1=1 1=1 ...`
重复、`;` 洪泛、括号堆叠）恰好同时满足两个最坏条件：startsOk 让大量位置
"看似能开头"，而每个位置都要付接近全长的解析才失败——O(n²) 退化被攻击者
利用的典型形态。对比 SQLChop 那种手写 tokenizer + 自动机是单遍 O(N)。

### 15.6 衡量建议

定位耗时规则时统计三个指标：

1. `adaptivePredict` 调用次数；
2. 每次预测消费的 lookahead 长度（是否扫到末尾）；
3. 有多少 decision 发生 SLL→LL 回退。

这三个指标能定位到具体是哪条规则在拖时间。
