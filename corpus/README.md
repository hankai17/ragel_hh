# corpus — OWASP XSS 攻击语料库

完整收录 OWASP XSS Filter Evasion Cheat Sheet 的 48+ 章节、上百条 payload，
范式化为 YAML，驱动 `xss_rules` 的规则产生与回归测试。

## 来源

- 主源（Markdown 源码，脚本直接解析）：
  https://raw.githubusercontent.com/OWASP/CheatSheetSeries/master/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.md
- 官网（人类阅读）：
  https://cheatsheetseries.owasp.org/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.html

## 文件

| 文件 | 作用 |
|---|---|
| `owasp_xss.yaml` | 语料数据（范式化，机器可 load） |
| `generate.py`    | 生成脚本：拉取 Markdown → 解析 → 分类 → 自动解码 → 生成 YAML |
| `check.py`       | 回归脚本：逐条跑 `xss_scan`，输出覆盖矩阵 + 待补清单 |

## YAML 结构

```yaml
meta:            # 版本 / 来源 / 生成时间
categories:      # 7 类语义层（见下）
rules:           # 规则登记：status=impl 已实现 / todo 待补
tests:           # 148 条 payload，每条：
  - id: xxx
    category: tag|event|uri|attr|css|enc|server
    raw: ...       # Cheat Sheet 原始 payload（含混淆）
    decoded: ...   # 上游解码后的规范形式（引擎实际输入）
    rules: [..]    # 预期命中规则；空 [] = 负向测试（不误报）
    source: ...    # 来源章节名
    section: ...   # 所属大节（Tests / WAF...）
event_handlers:  # on* 事件处理器词汇表（102 个）
char_escapes_lt: # < 的字符转义变体词汇表（70 个）
```

## 分类体系（语义层）

```
tag    危险标签        script/iframe/object/embed/frame/svg/math/meta/link/base/style/...
event  事件属性        on* 全列表
uri    危险 URI        javascript: / vbscript: / data:
attr   危险 URI 属性   background/dynsrc/lowsrc/action/poster/formaction
css    CSS 注入        expression()/@import/url(javascript:)/-moz-binding/behavior:
enc    编码混淆        实体/URL/空白/字符转义（解码后归入上述类）
server 服务器端/示例   SSI/PHP/.htaccess/WAF 示例代码（引擎范围外，参考）
```

## 解码（generate.py 内置）

`decode()` 模拟上游解码层，自动生成 `decoded` 字段：

1. HTML 实体（`&#60;` / `&#x3c;` / `&lt;` / `&colon;` / `&NewLine;`，含无分号）
2. URL 编码（`%3C` / `%77`）
3. JS 转义（`\u0065` / `\x65`）
4. scheme 字母间空白折叠（`jav\tascript` → `javascript`）

解码不了的极少数（US-ASCII 7-bit 编码等）在 `OVERRIDES` 表里人工标注。

## rules 字段语义

| 值 | 含义 |
|---|---|
| `script_tag` `dangerous_tag` `event_handler` `js_uri` `entity_lt` | 引擎已实现规则 |
| `TODO_*` | 待补规则，`check.py` 计为"待补"而非失败 |
| `[]`（空） | 负向测试：预期引擎不误报 |

## 用法

```bash
# 生成（从 GitHub 拉最新 Markdown）
python3 generate.py --fetch

# 或从本地缓存
python3 generate.py --md /tmp/xss_cheat.md

# 回归 + 覆盖矩阵
python3 check.py

# 只看下一批要实现的规则清单
python3 check.py --list-todo
```

## 扩充（官方更新时）

```bash
python3 generate.py --fetch   # 拉最新 Markdown 重新生成
python3 check.py              # 看新增条目命中还是落入 TODO_
```

结构、脚本都不用改，纯增量。分类/解码/规则推导的个别偏差，往 `generate.py` 的
`OVERRIDES` 表里按「章节名」或「`raw:` 子串」加一行即可，不碰主体逻辑。
