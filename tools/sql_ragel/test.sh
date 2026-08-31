#!/usr/bin/env bash
# ============================================================
# SQLTokens + RuleSQL（Ragel 模拟）测试
# ------------------------------------------------------------
# 断言：
#   1. 词法层 token 序列（tokens: ... 行）
#   2. 语法层规则命中（!! <rule> 行），语料对齐 misc/validate_sqli.sh
# usage: test.sh [scan_binary]
# ============================================================
set -u

SCAN="${1:-./sql_scan}"
pass=0
fail=0

# check_tokens <payload> <期望 token 序列（空格分隔）>
check_tokens() {
    local payload="$1" expect="$2" got
    got=$("$SCAN" "$payload" | grep -oP '^tokens\(\d+\):.*' | head -1)
    if printf '%s\n' "$got" | grep -q "$expect"; then
        printf '[PASS] tokens  %-28s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] tokens  %-28s expect "%s"\n       got: %s\n' \
            "$payload" "$expect" "$got"
        fail=$((fail + 1))
    fi
}

# check_rule <payload> <期望规则名>；RULE_NONE 表示无任何命中
check_rule() {
    local payload="$1" expect="$2" out ok=1
    out=$("$SCAN" "$payload")
    if [[ "$expect" == "NONE" ]]; then
        printf '%s\n' "$out" | grep -q '!! ' && ok=0
    else
        printf '%s\n' "$out" | grep -q "!! ${expect} " || ok=0
    fi
    if [[ $ok == 1 ]]; then
        printf '[PASS] rule    %-28s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] rule    %-28s expect %s\n%s\n' \
            "$payload" "$expect" "$out"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# 词法层：token 序列
# ------------------------------------------------------------
check_tokens "SELECT * FROM users WHERE 1=1"   "SELECT STAR FROM IDENT WHERE NUMBER EQ NUMBER"
check_tokens "1;DROP TABLE users"              "NUMBER SEMI DROP IDENT IDENT"
check_tokens "SELECT id FROM a UNION SELECT pwd FROM admin" \
             "SELECT IDENT FROM IDENT UNION SELECT IDENT FROM IDENT"
check_tokens "'a'='a'"                         "STRING EQ STRING"
check_tokens "SELECT 1+1=2"                    "SELECT NUMBER PLUS NUMBER EQ NUMBER"
check_tokens "a <= b"                          "IDENT LE IDENT"
check_tokens "x || y"                          "IDENT PIPE2 IDENT"
check_tokens "1; -- comment
SELECT 2"                                      "NUMBER SEMI SELECT NUMBER"

# 悬空引号容错：admin' 中引号被跳过，UNION 等仍被识别
check_tokens "admin' OR '1'='1'"               "IDENT OR STRING EQ STRING"

# 大小写不敏感关键字映射
check_tokens "SeLeCt * FrOm t WhErE 1=1"       "SELECT STAR FROM IDENT WHERE NUMBER EQ NUMBER"

# ------------------------------------------------------------
# 语法层：规则命中（正样本）
# ------------------------------------------------------------
check_rule "SELECT * FROM users WHERE 1=1"     always_true
check_rule "2=2"                               always_true
check_rule "1=(1)"                             always_true
check_rule "SELECT * FROM t WHERE 'a'='a'"     string_tautology
check_rule "'a'='a'"                           string_tautology
check_rule "SELECT * FROM t WHERE a=1 OR 1=2"  boolean_injection
check_rule "1 OR 1=1"                          boolean_injection
check_rule "admin' OR '1'='1' --"              boolean_injection
check_rule "SELECT id,name FROM users UNION SELECT user,password FROM admin" union_select
check_rule "UNION SELECT 1,2,3"                union_select
check_rule "x' UNION SELECT 1,2,3"             union_select
check_rule "SELECT SLEEP(5)"                   sleep
check_rule "pg_sleep(5)"                       pg_sleep
check_rule "SELECT LOAD_FILE('/etc/passwd')"   load_file
check_rule "SELECT BENCHMARK(10000000, MD5('x'))" benchmark

# ------------------------------------------------------------
# 负样本：不误报
# ------------------------------------------------------------
check_rule "SELECT name FROM users WHERE id = 1" NONE
check_rule "SELECT 42"                         NONE
check_rule "SELECT * FROM t WHERE a = 1 AND b = 2" NONE
check_rule "hello world"                       NONE
check_rule "id=1"                              NONE
check_rule "abc"                               NONE
check_rule "age > 18"                          NONE

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
