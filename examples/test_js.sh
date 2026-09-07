#!/usr/bin/env bash
# ============================================================
# js_syntax.rl（JavaScript 表达式语法骨架）测试
# ------------------------------------------------------------
# 断言（js_scan 输出 `expr [s,e)` 行，完整覆盖时带 (whole)）：
#   whole <payload>          整段是一个完整 JS 表达式
#   expr  <payload> <s,e>    expr 命中指定区间 [s,e)
#   none  <payload>          无任何 expr 命中
# usage: test_js.sh [scan_binary]
# ============================================================
set -u

SCAN="${1:-./js_scan}"
pass=0
fail=0

check_whole() {
    local payload="$1" out ok=1
    out=$("$SCAN" "$payload" 2>&1)
    printf '%s\n' "$out" | grep -q '(whole)' || ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] whole %-34s\n' "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] whole %-34s expect whole expr\n%s\n' "$payload" "$out"
        fail=$((fail + 1))
    fi
}

check_expr() {
    local payload="$1" expect="$2" out ok=1
    out=$("$SCAN" "$payload" 2>&1)
    printf '%s\n' "$out" | grep -qF "expr $expect" || ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] expr  %-30s %s\n' "$payload" "$expect"
        pass=$((pass + 1))
    else
        printf '[FAIL] expr  %-30s expect expr %s\n%s\n' "$payload" "$expect" "$out"
        fail=$((fail + 1))
    fi
}

check_none() {
    local payload="$1" out ok=1
    out=$("$SCAN" "$payload" 2>&1)
    printf '%s\n' "$out" | grep -q 'expr \[' && ok=0
    if [[ $ok == 1 ]]; then
        printf '[PASS] none  %-34s\n' "$payload"
        pass=$((pass + 1))
    else
        printf '[FAIL] none  %-34s expect no expr\n%s\n' "$payload" "$out"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# OOM 回归：合并版 js_syntax.rl 应快速编译成功。
# 19 层完整分离版（examples/js_oom_full.rl）会 NFA 状态爆炸 OOM，
# 本检查防"token 级递归 CFG 层数过多"回归。
# ------------------------------------------------------------
check_build() {
    local rl rc t0 t1 dt
    rl="$(cd "$(dirname "$0")/../rules/js" && pwd)/js_syntax.rl"
    t0=$(date +%s)
    ragel -C -o /tmp/_js_syntax_check.c "$rl" 2>/dev/null
    rc=$?
    t1=$(date +%s)
    dt=$((t1 - t0))
    if [[ $rc == 0 && $dt -lt 10 ]]; then
        printf '[PASS] OOM   js_syntax.rl 编译 %ds（<10s，无状态爆炸）\n' "$dt"
        pass=$((pass + 1))
    else
        printf '[FAIL] OOM   js_syntax.rl rc=%d 耗时%ds（疑似 OOM 回归）\n' "$rc" "$dt"
        fail=$((fail + 1))
    fi
}

# ------------------------------------------------------------
# 字面量
# ------------------------------------------------------------
check_whole "42"
check_whole "3.14"
check_whole "1e10"
check_whole "2.5e-3"
check_whole "'hello'"
check_whole '"world"'
check_whole "'it is'"
check_whole "true"
check_whole "false"
check_whole "null"
check_whole "undefined"
check_whole "this"

# ------------------------------------------------------------
# 标识符
# ------------------------------------------------------------
check_whole "foo"
check_whole "_bar"
check_whole '$jq'
check_whole "foo123"
check_whole "camelCaseName"

# ------------------------------------------------------------
# 成员访问
# ------------------------------------------------------------
check_whole "a.b"
check_whole "a.b.c"
check_whole "document.cookie"
check_whole "window.location.href"
check_whole "a[0]"
check_whole "a['key']"
check_whole 'a["key"]'
check_whole "a.b[0].c"
check_whole "a[b[c]]"

# ------------------------------------------------------------
# 函数调用
# ------------------------------------------------------------
check_whole "alert()"
check_whole "alert(1)"
check_whole "alert('x')"
check_whole "f(a, b)"
check_whole "f(1, 'x', true)"
check_whole "String.fromCharCode(88,83,83)"
check_whole "f(g(x))"
check_whole "f(g(h(x)))"
check_whole "eval('alert(1)')"
check_whole "document.write(x)"
check_whole "this.foo()"

# ------------------------------------------------------------
# 算术运算符
# ------------------------------------------------------------
check_whole "a + b"
check_whole "a - b"
check_whole "a * b"
check_whole "a / b"
check_whole "a % b"
check_whole "a ** b"
check_whole "a + b * c"
check_whole "a * b + c * d"

# ------------------------------------------------------------
# 比较 / 相等
# ------------------------------------------------------------
check_whole "a == b"
check_whole "a === b"
check_whole "a != b"
check_whole "a !== b"
check_whole "a < b"
check_whole "a <= b"
check_whole "a > b"
check_whole "a >= b"
check_whole "a < b && b < c"

# ------------------------------------------------------------
# 逻辑 / 位
# ------------------------------------------------------------
check_whole "a && b"
check_whole "a || b"
check_whole "!a"
check_whole "!!a"
check_whole "a && b || c"
check_whole "a ?? b"
check_whole "a & b"
check_whole "a | b"
check_whole "a ^ b"
check_whole "~a"
check_whole "a << b"
check_whole "a >> b"
check_whole "a >>> b"

# ------------------------------------------------------------
# 一元 / typeof / void / delete / new
# ------------------------------------------------------------
check_whole "-a"
check_whole "+a"
check_whole "typeof a"
check_whole "void 0"
check_whole "delete a.b"
check_whole "new Foo()"
check_whole "new Foo(1, 2)"
check_whole "- -x"

# ------------------------------------------------------------
# 括号嵌套 / 三元 / 赋值
# ------------------------------------------------------------
check_whole "(a)"
check_whole "((a))"
check_whole "(a + b) * c"
check_whole "f((a + b))"
check_whole "a ? b : c"
check_whole "a = b"
check_whole "a = 1"
check_whole "a = b + c"

# ------------------------------------------------------------
# 部分匹配（expr 从中间开始，如 var 声明后的表达式）
# ------------------------------------------------------------
check_expr "var x = 1 + 2"  "[1,6)"
check_expr "let y = a * b"  "[1,6)"
check_expr "return f(x)"    "[1,5)"
check_expr "x; y"           "[0,1)"

# ------------------------------------------------------------
# 负样本：非表达式，无任何命中
# ------------------------------------------------------------
check_none "var"
check_none "let"
check_none "const"
check_none "if"
check_none "else"
check_none "while"
check_none "for"
check_none "function"
check_none "return"
check_none "+"
check_none "="
check_none "&&"
check_none ";"
check_none "{"
check_none "}"
check_none "[]"
check_none "{}"

# ------------------------------------------------------------
# 更多嵌套 / 组合 / 字符串 / 一元
# ------------------------------------------------------------
check_whole "a.b.c.d.e"
check_whole "a[b][c][d]"
check_whole "f(g(h(i(x))))"
check_whole "a + b * c - d / e"
check_whole "(a && b) || (c && d)"
check_whole "a === b && c !== d"
check_whole "'say \"hi\"'"
check_whole '"it is"'
check_whole "typeof typeof a"
check_whole "-(-x)"
check_whole "a.b[c].d(e)"
check_whole "(a + b) * (c - d)"

# ------------------------------------------------------------
# 空 / 注释 负样本（词法层跳过，无 token -> 无 expr）
# ------------------------------------------------------------
check_none ""
check_none "// comment"
check_none "/* comment */"

echo
check_build
echo
echo "summary: $pass passed, $fail failed"
[[ $fail == 0 ]]
