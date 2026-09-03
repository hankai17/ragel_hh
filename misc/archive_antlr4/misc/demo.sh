#!/usr/bin/env bash
# 端到端演示：良性 / SQLi / XSS 样本
# usage: demo.sh <engine_binary> <rules_dir>
set -u

ENGINE="$1"
RULES_DIR="$2"

run() {
    echo
    echo "#### $1"
    shift
    "$ENGINE" --rules "$RULES_DIR" "$@" || true
}

run "1. 良性 SQL（期望 ALLOW）"                  "SELECT name FROM users WHERE id = 1"
run "2. WHERE 1=1 恒真（期望 BLOCK: always_true）" "SELECT * FROM users WHERE 1=1"
run "3. UNION SELECT（期望 BLOCK: union_select）"  "SELECT id, name FROM users UNION SELECT user, password FROM admin"
run "4. SLEEP 时间盲注（期望 BLOCK: sleep）"        "SELECT SLEEP(5)"
run "5. LOAD_FILE 文件读取（期望 BLOCK: load_file）" "SELECT LOAD_FILE('/etc/passwd')"
run "6. XSS <script>（期望 BLOCK: script_tag）"     "GET /q?x=<script>alert(1)</script>"
run "7. 非 SQL 良性请求（期望 FAST PATH ALLOW）"    "GET /index.html HTTP/1.1"
run "8. BENCHMARK 性能消耗（期望 BLOCK: benchmark）" "SELECT BENCHMARK(10000000, MD5('x'))"
run "9. 片段 1 OR 1=1（期望 BLOCK: boolean_injection）" "1 OR 1=1"
run "10. 片段 UNION SELECT（期望 BLOCK: union_select）" "UNION SELECT 1,2,3"
run "11. 引号不平衡 admin' OR '1'='1'（期望 BLOCK）" "admin' OR '1'='1' --"
