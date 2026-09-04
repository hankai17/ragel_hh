#!/usr/bin/env bash
# sql_tokens + sql_syntax 骨架测试
# 三类断言：
#   1. 词法：tokens(n): 行内容
#   2. 骨架：从位置 0 能否命中 expr / select_stmt / constant_value
#   3. whole：select_stmt 是否整条覆盖（识别为完整 SELECT 语句）
# 用法：test.sh [scan_binary]
set -u

SCAN="${1:-./sql_scan}"
pass=0
fail=0

# check_tokens <payload> <期望的 token 序列片段>
check_tokens() {
    local payload="$1" expect="$2" got
    got=$("$SCAN" "$payload" | sed -n 's/^tokens([0-9]*): //p' | head -1)
    if printf '%s\n' "$got" | grep -qF "$expect"; then
        printf '[PASS] tokens  %-34s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] tokens  %-34s expect "%s"\n       got: %s\n' \
            "$payload" "$expect" "$got"
        fail=$((fail + 1))
    fi
}

# check_skeleton <payload> <expr|select_stmt|constant_value|NONE>
# 期望该骨架从位置 0 命中；NONE 表示三个骨架都不命中
check_skeleton() {
    local payload="$1" kind="$2" out
    out=$("$SCAN" "$payload")
    if [[ "$kind" == "NONE" ]]; then
        if printf '%s\n' "$out" | grep -qE '^  (expr|select_stmt|constant_value) \['; then
            printf '[FAIL] skeleton %-34s expect none\n%s\n' "$payload" "$out"
            fail=$((fail + 1))
        else
            printf '[PASS] skeleton %-34s none\n' "$payload"
            pass=$((pass + 1))
        fi
    elif printf '%s\n' "$out" | grep -qE "^  ${kind} \[0,"; then
        printf '[PASS] skeleton %-34s %s\n' "$payload" "$kind"
        pass=$((pass + 1))
    else
        printf '[FAIL] skeleton %-34s expect %s\n%s\n' "$payload" "$kind" "$out"
        fail=$((fail + 1))
    fi
}

# check_whole <payload> <yes|no>：select_stmt 是否整条覆盖
check_whole() {
    local payload="$1" want="$2" out
    out=$("$SCAN" "$payload")
    if printf '%s\n' "$out" | grep -qE '^  select_stmt \[0,.*\(whole\)$'; then
        got=yes
    else
        got=no
    fi
    if [[ "$got" == "$want" ]]; then
        printf '[PASS] whole   %-34s %s\n' "$payload" "$want"
        pass=$((pass + 1))
    else
        printf '[FAIL] whole   %-34s expect %s, got %s\n%s\n' \
            "$payload" "$want" "$got" "$out"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# 词法：token 序列
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
check_tokens "admin' OR '1'='1'"               "IDENT OR STRING EQ STRING"
check_tokens "SeLeCt * FrOm t WhErE 1=1"       "SELECT STAR FROM IDENT WHERE NUMBER EQ NUMBER"

# ------------------------------------------------------------
# 骨架：从位置 0 命中的类型
# ------------------------------------------------------------
check_skeleton "1=1"                           expr
check_skeleton "1=(1)"                         expr
check_skeleton "a=1 OR 1=2"                    expr
check_skeleton "(1+2)*3"                       expr
check_skeleton "age > 18"                      expr
check_skeleton "'a'='a'"                       expr
check_skeleton "(1)=(1)"                 constant_value
check_skeleton "(1)"                           constant_value
check_skeleton "SELECT * FROM users WHERE 1=1" select_stmt
check_skeleton "SELECT * FROM (SELECT * FROM t) WHERE 1=1" select_stmt
check_skeleton "SELECT"                        NONE
check_skeleton ";"                             NONE
check_skeleton "*"                             NONE

# ------------------------------------------------------------
# whole：识别为一条完整 SELECT
# ------------------------------------------------------------
check_whole "SELECT * FROM users WHERE 1=1"       yes
check_whole "SELECT id FROM a"                    yes
check_whole "SELECT 1+1=2"                        yes
check_whole "SELECT id,name FROM users"           yes
check_whole "SELECT * FROM (SELECT * FROM t) WHERE 1=1" yes
check_whole "SELECT * FROM (SELECT * FROM (SELECT * FROM t)) WHERE 1=1" yes
check_whole "SELECT * FROM t WHERE (1)=(1)"       yes
check_whole "SELECT ((1+2))*3 FROM t"             yes
check_whole "SeLeCt * FrOm t WhErE 1=1"           yes
check_whole "SELECT * FROM (SELECT * FROM t WHERE 1=1)" yes
check_whole "SELECT * FROM t UNION SELECT id FROM u" no
check_whole "1=1"                                 no
check_whole "SELECT"                              no
check_whole "SELECT 1;DROP TABLE users"           no
check_whole "1;DROP TABLE users"                  no
check_whole "(SELECT id FROM t)"                  no

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
