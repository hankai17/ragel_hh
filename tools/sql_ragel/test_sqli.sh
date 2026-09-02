#!/usr/bin/env bash
# ============================================================
# sqli_rules.g4（24 条攻击规则）Ragel 移植测试
# ------------------------------------------------------------
# 断言（sqli_scan 输出 `!! <rule> [s,e) "..."` 行）：
#   hit  <payload> <rule>   至少命中 rule
#   miss <payload> <rule>   不命中 rule
#   none <payload>          无任何规则命中
# usage: test_sqli.sh [scan_binary]
# ============================================================
set -u

SCAN="${1:-./sqli_scan}"
pass=0
fail=0

check_hit() {
    local payload="$1" expect="$2" out ok=1
    out=$("$SCAN" "$payload")
    printf '%s\n' "$out" | grep -q "!! ${expect} " || ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] hit  %-30s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] hit  %-30s expect %s\n%s\n' "$payload" "$expect" "$out"
        fail=$((fail + 1))
    fi
}

check_miss() {
    local payload="$1" expect="$2" out ok=1
    out=$("$SCAN" "$payload")
    printf '%s\n' "$out" | grep -q "!! ${expect} " && ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] miss %-30s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] miss %-30s expect no %s\n%s\n' "$payload" "$expect" "$out"
        fail=$((fail + 1))
    fi
}

check_none() {
    local payload="$1" out ok=1
    out=$("$SCAN" "$payload")
    printf '%s\n' "$out" | grep -q '!! ' && ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] none %-30s\n' "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] none %-30s expect no hit\n%s\n' "$payload" "$out"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# always_true / string_tautology（含括号递归 + 谓词复核）
# ------------------------------------------------------------
check_hit "1=1"                              always_true
check_hit "2=2"                              always_true
check_hit "1=(1)"                            always_true
check_hit "(1)=(1)"                          always_true
check_hit "1=1.0"                            always_true
check_hit "SELECT * FROM t WHERE 1=1"        always_true
check_miss "1=2"                             always_true
check_miss "a=1"                             always_true
check_hit "'a'='a'"                          string_tautology
check_hit "('a')='a'"                        string_tautology
check_miss "'a'='b'"                         string_tautology
check_miss "'a'=1"                           string_tautology

# ------------------------------------------------------------
# boolean_injection（const_cmp 在 OR/AND 一侧）
# ------------------------------------------------------------
check_hit "1=1 OR 1=2"                       boolean_injection
check_hit "a=1 OR 1=1"                       boolean_injection
check_hit "1=1 AND b=2"                      boolean_injection
check_miss "a=1 OR b=2"                      boolean_injection
check_miss "a OR b"                          boolean_injection

# ------------------------------------------------------------
# union_select / stacked_query
# ------------------------------------------------------------
check_hit "UNION SELECT 1,2,3"               union_select
check_hit "UNION ALL SELECT a"               union_select
check_hit "x UNION SELECT 1"                 union_select
check_miss "UNION ALL"                       union_select
check_miss "UNION DELETE"                    union_select
check_hit "1;DROP TABLE t"                   stacked_query
check_hit ";SELECT 1"                        stacked_query
check_hit "x;UPDATE t"                       stacked_query
check_hit "1;SELECT"                         stacked_query

# ------------------------------------------------------------
# 危险函数调用（isIdent 谓词）
# ------------------------------------------------------------
check_hit "SLEEP(5)"                         sleep
check_hit "sleep (1)"                        sleep
check_hit "SELECT SLEEP(5)"                  sleep
check_miss "sleeping(5)"                     sleep
check_miss "sleep"                           sleep
check_hit "LOAD_FILE('/etc/passwd')"         load_file
check_hit "SELECT LOAD_FILE('/etc/passwd')"  load_file
check_hit "BENCHMARK(10000000,MD5('x'))"     benchmark
check_hit "pg_sleep(5)"                      pg_sleep

# ------------------------------------------------------------
# 子查询结构（fcall/fret 递归）
# ------------------------------------------------------------
check_hit "(SELECT * FROM t)"                subquery
check_hit "(SELECT 1)"                       subquery
check_hit "(SELECT * FROM (SELECT 1))"       subquery
check_miss "(1+1)"                           subquery
check_hit "EXISTS (SELECT 1)"                exists_subquery
check_hit "NOT EXISTS (SELECT 1)"            exists_subquery
check_miss "NOT (SELECT 1)"                  exists_subquery
check_hit "id IN (SELECT id FROM t)"         in_subquery
check_hit "id NOT IN (SELECT 1)"             in_subquery
check_miss "id IN (1,2)"                     in_subquery

# ------------------------------------------------------------
# LIKE / BETWEEN / 数值比较 / 排序 / 分页 / 拼接
# ------------------------------------------------------------
check_hit "a LIKE 'x%'"                      like_expr
check_hit "a NOT LIKE 'x'"                   like_expr
check_hit "a LIKE b"                         like_expr
check_hit "a BETWEEN 1 AND 10"               between_expr
check_hit "a NOT BETWEEN 1 AND 2"            between_expr
check_miss "a BETWEEN 1"                     between_expr
check_hit "1+1=2"                            numeric_expr
check_hit "2+3=5"                            numeric_expr
check_miss "2*3=6"                           numeric_expr
check_miss "1=2"                             numeric_expr
check_hit "ORDER BY id"                      order_by_expr
check_hit "ORDER BY id DESC"                 order_by_expr
check_miss "ORDER id"                        order_by_expr
check_hit "LIMIT 10"                         limit_expr
check_hit "LIMIT 10 OFFSET 5"                limit_expr
check_miss "LIMIT"                           limit_expr
check_hit "a || b"                           string_concat
check_hit "1 || 2"                           string_concat
check_miss "a + b"                           string_concat

# ------------------------------------------------------------
# 语句片段
# ------------------------------------------------------------
check_hit "INSERT INTO t"                    insert_fragment
check_hit "INSERT INTO t (a,b) VALUES (1,2)" insert_fragment
check_hit "INSERT t"                         insert_fragment
check_hit "INSERT INTO"                      insert_fragment
check_hit "UPDATE t SET a=1"                 update_fragment
check_hit "UPDATE t"                         update_fragment
check_miss "UPDATE"                          update_fragment
check_hit "DELETE FROM t"                    delete_fragment
check_hit "DELETE t"                         delete_fragment
check_miss "DELETE"                          delete_fragment
check_hit "SELECT 1"                         select_fragment
check_hit "SELECT a FROM t WHERE id=1"       select_fragment
check_hit "SELECT *"                         select_fragment
check_miss "SELECT"                          select_fragment
check_hit "SELECT * FROM t"                  select_from_fragment
check_hit "SELECT a,b FROM t"                select_from_fragment
check_miss "SELECT a WHERE b=1"              select_from_fragment

# ------------------------------------------------------------
# 数据库结构枚举
# ------------------------------------------------------------
check_hit "information_schema.tables"        db_enumeration
check_hit "SELECT * FROM information_schema.schemata" db_enumeration
check_miss "SELECT * FROM users"             db_enumeration

# ------------------------------------------------------------
# 负样本：无任何命中
# ------------------------------------------------------------
check_none "hello world"
check_none "id=1"
check_none "1"
check_none "1=2"
check_none "a=b"
check_none "x + y"
check_none "FROM t"
check_none "SELECT"
check_none "sleeping(5)"

echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
