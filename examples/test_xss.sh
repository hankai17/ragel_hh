#!/usr/bin/env bash
# xss_rules.rl（5 条 XSS 攻击规则）测试
# 断言：hit <payload> <rule> 至少命中 rule；miss 不命中；none 无任何命中
set -u

SCAN="${1:-./xss_scan}"
pass=0
fail=0

check_hit() {
    local payload="$1" expect="$2" out ok=1
    out=$("$SCAN" "$payload")
    printf '%s\n' "$out" | grep -q "!! ${expect} " || ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] hit  %-34s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] hit  %-34s expect %s\n%s\n' "$payload" "$expect" "$out"
        fail=$((fail + 1))
    fi
}

check_miss() {
    local payload="$1" expect="$2" out ok=1
    out=$("$SCAN" "$payload")
    printf '%s\n' "$out" | grep -q "!! ${expect} " && ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] miss %-34s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] miss %-34s expect no %s\n%s\n' "$payload" "$expect" "$out"
        fail=$((fail + 1))
    fi
}

check_none() {
    local payload="$1" out ok=1
    out=$("$SCAN" "$payload")
    printf '%s\n' "$out" | grep -q '!! ' && ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] none %-34s\n' "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] none %-34s expect no hit\n%s\n' "$payload" "$out"
        fail=$((fail + 1))
    fi
}

# script 标签
check_hit '<script>alert(1)</script>'          script_tag
check_hit '<script src=x>'                     script_tag
check_hit '<SCRIPT>alert(1)</SCRIPT>'          script_tag
check_miss '<scriipt>'                         script_tag

# 注释绕过（<!-- --> 拆标签名/属性名/URI）
check_hit '<scr<!-- -->ipt>alert(1)</scr<!-- -->ipt>'    script_tag
check_hit '<s<!--c-->cript>alert(1)</s<!--c-->cript>'    script_tag
check_hit '<img oner<!-- -->ror=alert(1)>'               event_handler
check_hit '<a href="java<!-- -->script:alert(1)">x</a>'  js_uri

# 危险标签
check_hit '<iframe src=x>'                     dangerous_tag
check_hit '<object data=x>'                    dangerous_tag
check_hit '<embed src=x>'                      dangerous_tag
check_hit '<svg onload=x>'                     dangerous_tag
check_hit '<meta http-equiv=refresh>'          dangerous_tag
check_miss '<div>'                             dangerous_tag

# 事件处理器
check_hit '<img onerror=alert(1)>'             event_handler
check_hit '<body onload=x>'                    event_handler
check_miss '<img src=x>'                       event_handler

# 危险 URI
check_hit '<a href="javascript:alert(1)">'     js_uri
check_hit '<img src="JaVaScRiPt:x">'           js_uri
check_hit "<iframe src='vbscript:x'>"          js_uri
check_miss '<a href="https://x">'              js_uri

# 实体编码
check_hit '&#60;script&#62;'                   entity_lt
check_hit '&#x3c;script&#x3e;'                 entity_lt
check_hit '&lt;script&gt;'                     entity_lt
check_miss '&amp;'                             entity_lt

# 负样本
check_none 'hello world'
check_none '<div>text</div>'
check_none '<a href="https://example.com">x</a>'

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
