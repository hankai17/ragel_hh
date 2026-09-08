#!/usr/bin/env bash
# ============================================================
# xss Ragel 状态机测试（对齐 libinjection is_xss，精细化版）
# ------------------------------------------------------------
# 断言每个载荷首个命中的规则：
#   black_tag / black_attr / black_url / style_expr /
#   dangerous_comment / NONE
# 用例覆盖 rules/xss/corpus/xss.log 的典型 XSS 样本。
# usage: test.sh [scan_binary]
# ============================================================
set -u

SCAN="${1:-./xss_scan}"
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

# ---- style_expr：style + expression/javascript: ----
check '<div style="expression(alert(1))">'           style_expr
check '<div style="background:url(javascript:alert(1))">' style_expr

# ---- dangerous_comment ----
check '<!--[if gte IE 4]><script>alert(1)</script><![endif]-->' dangerous_comment
check '<!--import x-->'                               dangerous_comment

# ---- 负样本：不应命中（精细化，不误报）----
check '<div>hello</div>'                             NONE
check '<p class="x">text</p>'                        NONE
check '<a href="/foo">link</a>'                      NONE
check '<!DOCTYPE html>'                              NONE
check '<div style="color:red">x</div>'               NONE
check '<img src="logo.png">'                         NONE
check '<a href="https://example.com">ok</a>'         NONE
check 'hello world'                                  NONE

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
