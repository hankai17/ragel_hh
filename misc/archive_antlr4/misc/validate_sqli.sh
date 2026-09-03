#!/usr/bin/env bash
# ============================================================
# SQLi 规则校验器
# ------------------------------------------------------------
# 对每个样本运行 engine，断言：
#   BLOCK  <rule>  期望命中规则并拦截
#   ALLOW  <rule>  期望命中规则但放行（检测型规则）
#   UNKNOWN <rule> 期望命中规则但解析失败（fragment 检测）
#   NONE          期望无规则命中且 ALLOW（负样本）
#
# usage: validate_sqli.sh <engine_binary> <rules_dir>
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
    # 取最后一个判定词（VERDICT: xxx 或 FAST PATH ... -> ALLOW）
    got=$(printf '%s\n' "$out" | grep -Eo 'ALLOW|BLOCK|UNKNOWN' | tail -1)

    if [[ "$expect_rule" == "NONE" ]]; then
        # 负样本：无规则命中；判词为 ALLOW（完整 SQL / Fast Path）或
        # UNKNOWN（无法识别的裸片段，如 id=1）
        if [[ "$got" != "ALLOW" && "$got" != "UNKNOWN" ]]; then ok=0; fi
        if printf '%s\n' "$out" | grep -q '!! '; then ok=0; fi
    else
        if [[ "$got" != "$expect_verdict" ]]; then ok=0; fi
        if ! printf '%s\n' "$out" | grep -q "!! ${expect_rule}"; then ok=0; fi
    fi

    if [[ $ok == 1 ]]; then
        printf '[PASS] %-12s %s\n' "$expect_rule" "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] %-12s %s   (verdict=%s, expect=%s)\n' \
            "$expect_rule" "$payload" "$got" "$expect_verdict"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# 正样本：BLOCK 型规则（高置信度，拦截）
# ------------------------------------------------------------
check "SELECT * FROM users WHERE 1=1"                    BLOCK   always_true
check "SELECT * FROM t WHERE a=1 OR 1=2"                 BLOCK   boolean_injection
check "SELECT * FROM t WHERE a=1 AND 1=1"                BLOCK   boolean_injection
# 注：命中 BLOCK 规则即终止匹配（首个 BLOCK 决定报告与裁决）。
# 2=2 在位置 0 先命中 always_true（k=0），故报告 always_true；
# boolean_injection 覆盖见 "a=1 OR 1=2" / "1 OR 1=1"。
check "SELECT * FROM t WHERE 2=2 OR b=3"                 BLOCK   always_true
# 回归哨兵：位置 0 先命中 ALLOW 规则（numeric_expr），BLOCK 规则（union_select）
# 在后面——必须继续扫描，禁止"任意命中即停"把 BLOCK 漏成 ALLOW。
check "1+1=2 UNION SELECT 1,2,3"                         BLOCK   union_select
check "SELECT id,name FROM users UNION SELECT user,password FROM admin" BLOCK union_select
check "1;SELECT * FROM users"                            BLOCK   stacked_query
check "1;DROP TABLE users"                               BLOCK   stacked_query
check "SELECT SLEEP(5)"                                  BLOCK   sleep
check "SELECT LOAD_FILE('/etc/passwd')"                  BLOCK   load_file
check "SELECT BENCHMARK(10000000, MD5('x'))"             BLOCK   benchmark
check "SELECT pg_sleep(5)"                               BLOCK   pg_sleep
check "SELECT * FROM t WHERE 'a'='a'"                    BLOCK   string_tautology
check "GET /q?x=<script>alert(1)</script>"               BLOCK   script_tag
# 对抗性滑窗重解析：大量"看似合法起点"（1=1 重复 200 组）。
# 语义上仍应命中 always_true -> BLOCK；同时是 O(n^2) 最坏路径的回归哨兵
# （1=1 x 200 约为 100ms 量级，若误引入更慢的错误恢复会明显放大）。
adv_payload=$(printf '1=1 %.0s' $(seq 1 200))
check "$adv_payload" BLOCK always_true

# ------------------------------------------------------------
# 正样本：检测型规则（命中但按 action 放行 / 解析失败）
# ------------------------------------------------------------
check "SELECT * FROM t WHERE id IN (SELECT id FROM s)"   ALLOW   subquery
check "SELECT * FROM t WHERE id IN (SELECT id FROM s)"   ALLOW   in_subquery
check "SELECT * FROM t WHERE EXISTS (SELECT 1 FROM s)"   ALLOW   exists_subquery
check "SELECT * FROM t WHERE NOT EXISTS (SELECT 1 FROM s)" ALLOW exists_subquery
check "SELECT * FROM t WHERE name LIKE '%x%'"            ALLOW   like_expr
check "SELECT * FROM t WHERE id BETWEEN 1 AND 5"         ALLOW   between_expr
check "SELECT * FROM t WHERE 1+1=2"                      ALLOW   numeric_expr
check "SELECT * FROM t ORDER BY 1"                       ALLOW   order_by_expr
check "SELECT * FROM t LIMIT 10"                         ALLOW   limit_expr
check "SELECT * FROM t WHERE a='x' || 'y'"               ALLOW   string_concat
check "INSERT INTO users VALUES (1)"                     ALLOW   insert_fragment
check "UPDATE users SET name='x'"                        ALLOW   update_fragment
check "DELETE FROM users"                                ALLOW   delete_fragment
check "x' UNION SELECT 1,2,3"                            BLOCK   union_select
check "foo SELECT a FROM b"                              ALLOW   select_from_fragment

# ------------------------------------------------------------
# 片段（不完整 SQL）正样本：包装进合法上下文后语义规则生效
# ------------------------------------------------------------
check "1 OR 1=1"                                         BLOCK   boolean_injection
check "2=2"                                              BLOCK   always_true
check "'a'='a'"                                          BLOCK   string_tautology
check "UNION SELECT 1,2,3"                               BLOCK   union_select
check "ORDER BY 1"                                       ALLOW   order_by_expr
check "LIMIT 1"                                          ALLOW   limit_expr
check "EXISTS (SELECT 1 FROM s)"                         ALLOW   exists_subquery
check "x = (SELECT 1)"                                   ALLOW   subquery
# 同上：admin 处先命中 boolean_injection（comparison OR const_cmp），
# 故报告 boolean_injection；string_tautology 覆盖见 "'a'='a'"。
check "admin' OR '1'='1' --"                             BLOCK   boolean_injection
check "SELECT * FROM information_schema.tables"          ALLOW   db_enumeration
check "SELECT * FROM INFORMATION_SCHEMA"                 ALLOW   db_enumeration
check "pg_sleep(5)"                                      BLOCK   pg_sleep

# ------------------------------------------------------------
# 负样本：不误报（ALLOW 且无任何规则命中）
# ------------------------------------------------------------
check "SELECT name FROM users WHERE id = 1"              ALLOW   NONE
check "SELECT 42"                                        ALLOW   NONE
check "SELECT * FROM t WHERE a = 1 AND b = 2"            ALLOW   NONE
check "hello world"                                      ALLOW   NONE
check "id=1"                                             UNKNOWN NONE
check "abc"                                              ALLOW   NONE
check "age > 18"                                         ALLOW   NONE

# ------------------------------------------------------------
echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
