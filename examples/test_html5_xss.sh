#!/usr/bin/env bash
# ============================================================
# xss Ragel 状态机测试（对齐 libinjection is_xss，精细化版）
# ------------------------------------------------------------
# 断言每个载荷首个命中的规则：
#   black_tag / black_attr / black_url / style_expr /
#   dangerous_comment / NONE
# 用例覆盖 rules/html5_xss/corpus/xss.log 的典型 XSS 样本。
# usage: test.sh [scan_binary]
# ============================================================
set -u

SCAN="${1:-./html5_xss_scan}"
pass=0
fail=0

check() {
    local payload="$1" expect="$2"
    local out ok=1
    out=$("$SCAN" "$payload" 2>&1)
    if [[ "$expect" == "NONE" ]]; then
        printf '%s\n' "$out" | grep -q '!!' && ok=0
    else
        printf '%s\n' "$out" | grep -q "!! $expect" || ok=0
    fi
    if [[ $ok == 1 ]]; then
        printf '[PASS] %-18s %s\n' "$expect" "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] %-18s %s\n' "$expect" "$payload"
        printf '%s\n' "$out" | head -5
        fail=$((fail + 1))
    fi
}

# ---- black_tag：黑标签 ----
check '<script>alert(1)</script>'                    black_tag
check '<SCRIPT SRC=https://x.com/a.js></SCRIPT>'     black_tag
check '<svg/onload=alert(42)>'                       black_tag
check '<iframe src=x></iframe>'                      black_tag
check '<object data=x></object>'                     black_tag
check '<embed src=x>'                                black_tag
# IE 反引号容错：<SCRIPT a=`>` ...> 结构可辨 + src 外链，正文为空
check '<SCRIPT a=`>` SRC="http://xss.rocks/xss.js"></SCRIPT>' black_tag
# `<<` 畸形开标签：规范输出 '<' 为文本并退回重读，仍解析出真标签
check '<<SCRIPT>alert("XSS");//\<</SCRIPT>'          black_tag
check '<<img src=x onerror=alert(1)>'                black_attr

# ---- black_attr：on* 事件等黑属性 ----
check '<img onerror=alert(1)>'                       black_attr
check '<a onmouseover="alert(1)">x</a>'              black_attr
check '<body onload=alert(1)>'                       black_attr
check '<input onfocus=alert(1)>'                     black_attr

# ---- black_url：URI 属性 + 黑 URL ----
check '<a href="javascript:alert(1)">Click</a>'      black_url
check '<img src="javascript:alert(1)">'              black_url
check '<form action="vbscript:msgbox(1)">'           black_url
check '<img src="data:text/html,<script>">'          black_url
# 引号错配（= 与引号间有空白）+ &#14; 实体 + 控制字符折叠
check '<IMG SRC= " &#14; javascript:alert("XSS");">' black_url
# HTML 数字实体解码（十进制/十六进制）还原 javascript: 前缀
check '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click Me!</a>' black_url
check $'<a href="jav&#x09;ascript:alert(\'XSS\');">Click Me</a>' black_url
# 字母间 tab / 前导 &#14; 控制字符 + 空白折叠
check $'<a href="jav\tascript:alert(\'XSS\');">Click Me</a>'     black_url
check $'<a href=" &#14;  javascript:alert(\'XSS\');">Click Me</a>' black_url
# 空格实体 &#32; / &#x20; 解码后同样折叠（与字面空格行为一致）
check '<a href="&#32;javascript:alert(1)">'          black_url
check '<a href="&#x20;javascript:alert(1)">'         black_url
# 命名实体：&colon; / &Tab; / &NewLine;（分号必需、大小写敏感，对齐规范）
check '<a href="javascript&colon;alert(1)">'         black_url
check '<a href="java&Tab;script:alert(1)">'          black_url
check '<a href="java&NewLine;script:alert(1)">'      black_url
# 数字实体 + 命名实体混用
check '<a href="&#106;avascript&colon;alert(1)">'    black_url
# 大小写敏感：&COLON; 不是实体，black_url 不命中，但 alert( 仍被语义层抓到
check '<a href="javascript&COLON;alert(1)">'         dangerous_js

# ---- style_expr：style + expression/javascript: ----
check '<div style="expression(alert(1))">'           style_expr
check '<div style="background:url(javascript:alert(1))">' style_expr

# ---- dangerous_comment ----
check '<!--[if gte IE 4]><script>alert(1)</script><![endif]-->' dangerous_comment
check '<!--import x-->'                               dangerous_comment

# ---- dangerous_js：属性值含危险 JS 调用（语义分析）----
check '<img onerror="alert(1)">'                     dangerous_js
check '<img onerror="String.fromCharCode(88,83,83)">' dangerous_js
check '<img onerror="document.cookie">'              dangerous_js
check '<img onerror="a[&quot;eval&quot;](&quot;alert(1)&quot;)">' dangerous_js
# 语义层独立可用：属性值先解 HTML 实体再分析，不依赖 black_url
check '<a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#39;&#88;&#83;&#83;&#39;&#41;">Click Me!</a>' dangerous_js
check '<a href="&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29">Click Me</a>' dangerous_js
check '<img src=x onerror="&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041">' dangerous_js
check '<a href="javascript&colon;alert(1)">'         dangerous_js
check '<a href="jav&#x09;ascript:alert(1)">'         dangerous_js
check '<IMG SRC= " &#14; javascript:alert("XSS");">' dangerous_js
check '<<SCRIPT>alert("XSS");//\<</SCRIPT>'         dangerous_js
# 标识符 Unicode 转义（ES5/ES6 允许）：\u0061lert 还原后就是 alert
check '<img src=x onerror="\u0061lert(1)">'         dangerous_js
check '<img src=x onerror="\u{61}lert(1)">'         dangerous_js
check '<img src=x onerror="document.\u0063ookie">'  dangerous_js
# 反例：\x61 不是合法的标识符转义（JS 会 SyntaxError），不该按危险 JS 判
check '<img src="\x61lert(1)">'                      NONE
# 字符串字面量转义：a["\u0065val"] 与 a["eval"] 等价
check '<img src=x onerror="a[&quot;\u0065val&quot;](&quot;alert(1)&quot;)">' dangerous_js
check '<img src=x onerror="a[&quot;\x65val&quot;](&quot;alert(1)&quot;)">'  dangerous_js
check '<img src=x onerror="a[&quot;constr\u0075ctor&quot;](&quot;alert(1)&quot;)">' dangerous_js

# ---- 负样本：不应命中（精细化，不误报）----
check '<div>hello</div>'                             NONE
check '<p class="x">text</p>'                        NONE
check '<a title="hello">'                            NONE
check '<div data-x="foo(1)">'                        NONE
check '<a href="/foo">link</a>'                      NONE
# 实体解码不得引入误报：普通路径/查询串里的 &colon; &amp; 无害
check '<a href="/foo&colon;bar">'                    NONE
check '<a href="https://example.com?a=1&amp;b=2">'   NONE
check '<a href="&sect=1">'                           NONE
check '<!DOCTYPE html>'                              NONE
check '<div style="color:red">x</div>'               NONE
check '<img src="logo.png">'                         NONE
check '<a href="https://example.com">ok</a>'         NONE
check 'hello world'                                  NONE
# `<` 后跟非字母（改动了 tag_open 兜底分支）：应纯文本，不误报
check 'a < b'                                        NONE
check '1<2'                                          NONE

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
