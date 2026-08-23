# log4j 规则测试报告（校验 / 正则对比 / 性能对比）

> 归档说明：log4j 场景三组测试的结论与复现方法——规则校验
> （23/23 + SQLi 回归 49/49）、生产正则 vs 语法规则检出对比、
> 正则 vs ANTLR 性能对比。内容自包含，可整体归档到其他目录。

## 0. 被测对象

- 规则集：`rules/log4j/log4j_rules.g4`（4 条：log4j_jndi / log4j_sensitive /
  log4j_nested_chain / log4j_expr）
- 共享语法：`rules/_shared/Log4jTokens.g4`（`${}` 结构词法）、
  `rules/_shared/Log4jLookup.g4`（递归查找子语法 + 语义谓词）
- 引擎链路：`rulec` 按 `tokenVocab` 选择共享词法 -> `liblog4j_rules.so` ->
  `engine` fast-path + 插件深检
- 构建：Debug（-O0）/ Release（-O3 -flto）
- 生产正则（线上提供，JSON 反序列化后的 PCRE）：

```
\${((.*jndi:((ldap://)|(rmi://)).+)|(.*\${((ower)|(upper)):.+)|(.*\${.*:.*:-.+)|(.*\${date:.+))}
```

## 1. 规则校验

`misc/validate_log4j.sh`：**23/23 通过**

| 分组 | 用例 | 期望 |
|---|---|---|
| 直接 JNDI（ldap/rmi/ldaps/dns、嵌入请求行） | 5 | log4j_jndi BLOCK |
| 嵌套子语法混淆（lower/::-/逐字母拆分/env 包裹/值内嵌套/$$ 转义前缀） | 7 | log4j_jndi BLOCK |
| 敏感前缀（env/sys/docker/aws） | 4 | log4j_sensitive BLOCK |
| 无 jndi 嵌套链 | 1 | log4j_nested_chain BLOCK |
| 结构识别（java/date） | 2 | log4j_expr ALLOW |
| 负样本（普通文本 / user=jndi / price=10） | 4 | 无命中 |

SQLi 回归 `misc/validate_sqli.sh`：**49/49 通过**（共享词法改造未破坏老规则）。

边界行为（手工验证）：

- 大小写不敏感：`${JNDI:LDAP://X}` 命中；
- `${jndi:}` 空值命中；未闭合 `${jndi:ldap://x` 不误报；
- `$${...}` 转义前缀保守命中；
- 载荷嵌入长文本（`x=${jndi:rmi://y}&&y=1`）命中；
- 多层嵌套无 jndi（`${a:${b:${c:${d:${e:1}}}}}`）命中 nested_chain。

## 2. 检出对比：生产正则 vs 语法规则

`misc/compare_log4j_regex.sh`（18 攻击 + 8 良性样本）：

| 检测器 | TP | FP | FN | 精确率 | 召回率 |
|---|---|---|---|---|---|
| engine（语法规则） | 18 | 0 | 0 | 1.00 | 1.00 |
| 生产正则 | 8 | 1 | 10 | 0.89 | 0.44 |

生产正则 10 个漏报的根因：

1. 只覆盖 `ldap://` 与 `rmi://`：`ldaps://`、`dns://` 漏；
2. `(ower)|(upper)` 缺字母 `l`：`${lower:...}` 全漏——包括
   `${${lower:j}ndi:...}`、逐字母拆分、`${jndi:${lower:l}dap://...}`
   （这三类字面上连 "jndi" 连续子串都没有，宽松分支也救不回）；
3. 大小写敏感：`${JNDI:LDAP://...}` 漏；
4. 结构怪癖：`ower/upper`、`:-`、`date` 分支内部是 `.*\${...`
   （要求第二个 `${`），单层 `${date:...}` 不命中，反而命中良性
   双 `${` 结构 `${x${date:y}}`（即那个 FP）；
5. env/sys/docker/aws 敏感前缀不在正则覆盖内。

## 3. 性能对比（Release，每请求深检 µs）

`misc/bench_log4j.sh build-release/engine build-release/plugins`

| 载荷 | 正则 | ANTLR 引擎 | 倍数 |
|---|---|---|---|
| classic `${jndi:ldap://...}` | 0.20 | 5.03 | 25x |
| nested `${${lower:j}ndi:...}` | 0.57 | 6.63 | 12x |
| `${env:${jndi:...}}` | 0.20 | 6.66 | 33x |
| benign hello | 0.33 | 1.21 | 3.6x |
| benign `${java:version}` | 0.33 | 28.5 | 86x |
| 10KB 长载荷 | 13.5 | 395 | 29x |
| 100 层深嵌套 | 96.0 | 495 | 5.2x |
| `${jndi:...}` ×1000 | 8.0 | 1948 | 244x |

要点：

1. 绝对成本都很小：攻击命中路径 5–7µs，1000 个 JNDI 的对抗输入约 2ms，
   对 WAF 延迟预算无感；正则便宜 4–240 倍，但召回率只有 0.44；
2. 引擎开销大头是词法不是匹配：`×1000` 仅首个 `${jndi:` 命中即返回，
   1.9ms 基本是 ANTLR 词法扫 22KB 的成本；
3. 良性深检比攻击命中贵（`${java:version}` 28µs vs 攻击 5µs）：4 条规则
   全部尝试失败 + 一次 ALLOW 命中后继续扫描；fast-path 拦不住含 `${` 的输入；
4. 正则的隐藏风险在深嵌套：100 层时正则 0.2µs -> 96µs（约 500 倍），
   `.*` 交替回溯特征，加深有 ReDoS 风险；引擎有 1024 次 / 5ms 预算硬封顶；
5. Debug（-O0）插件约再慢 1.5–2 倍，对比需统一构建类型。

## 4. 复现方法

```bash
# 构建（Debug / Release）
cmake -S . -B build && cmake --build build -j
cmake -S . -B build-release -DCMAKE_BUILD_TYPE=Release && cmake --build build-release -j

# 规则校验 + SQLi 回归
./misc/validate_log4j.sh build/engine build/plugins
./misc/validate_sqli.sh build/engine build/plugins

# 检出对比（生产正则单条 vs 语法规则）
./misc/compare_log4j_regex.sh build/engine build/plugins

# 性能对比（建议 Release）
./misc/bench_log4j.sh build-release/engine build-release/plugins
```

## 5. 已知限制

- `engine` 的 normalize 目前不做 URL 解码，`%24%7Bjndi%3A...%7D` 编码载荷
  不命中；生产版需在归一化层先解码；
- 递归子语法对极端深度嵌套（数千层）无显式深度限制，单次解析可能超预算
  甚至栈溢出（log4j 自身有 recursion limit，这里对应 nested_chain 检测层）；
- 性能数字是插件深检成本（词法 + 滑窗 + 解析），不含 fast-path 预筛；
  正则侧为裸匹配，不含请求外围处理。
