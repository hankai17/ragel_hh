#!/usr/bin/env bash
# ============================================================
# 规则引擎性能基准：滑窗重解析对抗输入
# ------------------------------------------------------------
# 测量 rule_check_text 在"大量看似合法起点"输入上的耗时，验证最坏
# 复杂度（1=1 重复 -> 二次方放大：输入翻倍，耗时约 4 倍）。
# 注意：engine 对 BLOCK 返回非 0 退出码，本脚本只计时不计成败。
#
# usage: bench_sqli.sh [engine_binary] [rules_dir]
# ============================================================
set -u

ENGINE="${1:-build/engine}"
RULES="${2:-build/plugins}"

time_case() {
    local label="$1" payload="$2"
    local start end ms
    start=$(date +%s%N)
    "$ENGINE" --rules "$RULES" "$payload" >/dev/null 2>&1
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    printf '%-30s %6d ms\n' "$label" "$ms"
}

echo "== 对照基线 =="
time_case "benign fast path (hello world)" "hello world"
time_case "benign sql deep (WHERE id=1)" "SELECT name FROM users WHERE id = 1"
time_case "short attack (SLEEP(5))" "SELECT SLEEP(5)"

echo
echo "== 对抗输入：1=1 重复（NUMBER 起始集合 × 失败恢复）=="
for n in 100 250 500 1000 2000; do
    time_case "1=1 x $n" "$(printf '1=1 %.0s' $(seq 1 $n))"
done

echo
echo "== 变体 =="
time_case "; x 1000 (SEMI)" "$(printf '; %.0s' $(seq 1 1000))"
time_case "x=1 x 1000 (IDENT+NUMBER)" "$(printf 'x=1 %.0s' $(seq 1 1000))"
time_case "1=1;x x 500 (混合)" "$(printf '1=1;x %.0s' $(seq 1 500))"
