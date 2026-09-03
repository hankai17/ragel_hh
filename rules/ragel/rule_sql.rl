/* ============================================================
 * rule_sql.rl — RuleSQL.g4 的 Ragel 移植（语法层 / token 级状态机）
 * ------------------------------------------------------------
 * 对应 rules/_shared/RuleSQL.g4 的匹配骨架：
 *   expr / or_expr / and_expr / not_expr / comparison / cmp_op /
 *   add_expr / add_op / mul_expr / mul_op / unary_expr / primary /
 *   expr_list / select_stmt / table_ref / constant_value
 *
 * 实现方式：Ragel 是字符级 DFA，这里把"token 类型"当作字母表
 * （8 位），在词法层输出的 token 数组上直接跑状态机。
 *
 * CFG 递归（括号嵌套 / 子查询）用 Ragel 的 fcall/fret 实现：
 *   primary 的 (expr)          -> fcall expr_call
 *   primary 的 f(expr_list)    -> fcall elist_call
 *   table_ref 的 (select_stmt) -> fcall select_call
 *   constant_value 的 (...)... -> fcall const_call
 *
 * 递归的关键设计（避免 ragel 的"提前结束"陷阱）：
 *   ragel 的结束动作 @act 挂在"规则可能结束"的转移上。若规则结尾
 *   有可选/重复结构（如 select_stmt 的 (FROM ..)? / (WHERE ..)?），
 *   该动作会在第一个可能结束点触发 —— 对 fret 是灾难：弹出调用帧后
 *   后续结构全部丢失。解决办法：
 *     (1) 被调 entry 以强制 token 结尾：expr_call := expr ')' 等，
 *         RPAREN 是被调方消费，entry 的结束点无歧义；
 *     (2) fret 手动实现（不用 @ret 包装），出栈后仅在栈空
 *         （top==0，即最外层调用完成）时写 match_len，此时 p 恰好
 *         落在整个递归体的真正末尾。
 *   main 的结束动作 note_* 同样加 top==0 守卫，避免嵌套中途写入
 *   错误的局部长度。
 *
 * 三个顶层结构（expr / select_stmt / constant_value）各占一个
 * 独立 machine，run_*() 中用
 *     %%{ machine <name>; write exec; }%%
 * 显式绑定 exec 到对应 machine，避免默认展开到最后一个 machine。
 *
 * 公共片段（token 编号 / 运算符 / expr 递归骨架）抽到
 * rule_shared.rl，各机器用 include 按名并入，避免三份复制。
 *
 * 语义谓词（isIdent / numbersEqual / stringsEqual /
 * constNumbersEqual / constStringsEqual）在 C 层实现，判定与
 * RuleSQL.g4 的 @parser::members 完全一致。
 *
 * 生成：ragel -C -o rule_sql.c rule_sql.rl
 * ============================================================ */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sql_tokens.h"

/* fcall/fret 运行期栈大小。最深输入为纯括号串：n 个 token 最多
 * n/2 层调用（每层至少消耗 LPAREN+RPAREN 两个 token），
 * MAX_TOK=1024 时取 1024 留足余量。 */
#define CFG_STACKSZ 1024

/* ------------------------------------------------------------
 * 语义层：规则共享语义谓词（对齐 RuleSQL.g4 @parser::members）
 * ------------------------------------------------------------ */

static int ci_eq(const char* s, int len, const char* expected) {
    size_t elen = strlen(expected);
    if (len != (int)elen) return 0;
    for (size_t i = 0; i < elen; ++i) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)expected[i]))
            return 0;
    }
    return 1;
}

/* isIdent($i, "sleep") 等价 */
int sql_is_ident(const Token* t, const char* expected) {
    return t && t->type == T_IDENT && ci_eq(t->s, t->len, expected);
}

/* canonicalNumber 等价：strtod -> %.17g；解析失败原样返回 */
static char* canonical_number(const Token* t, char* buf, size_t cap) {
    char raw[128];
    size_t l = (size_t)t->len;
    if (l >= sizeof(raw)) l = sizeof(raw) - 1;
    memcpy(raw, t->s, l);
    raw[l] = '\0';
    char* end = NULL;
    double v = strtod(raw, &end);
    if (end == raw || *end != '\0') {
        size_t n = l;
        if (n >= cap) n = cap - 1;
        memcpy(buf, raw, n);
        buf[n] = '\0';
        return buf;
    }
    snprintf(buf, cap, "%.17g", v);
    return buf;
}

/* numbersEqual 等价：1=1 / 2=2 / 1=1.0 命中，1=2 不命中 */
int sql_numbers_equal(const Token* a, const Token* b) {
    char ba[64], bb[64];
    return strcmp(canonical_number(a, ba, sizeof(ba)),
                  canonical_number(b, bb, sizeof(bb))) == 0;
}

static char* unquote(const Token* t, char* buf, size_t cap) {
    size_t l = (size_t)t->len;
    if (l >= 2 && t->s[0] == '\'' && t->s[l - 1] == '\'') {
        l -= 2;
        if (l >= cap) l = cap - 1;
        memcpy(buf, t->s + 1, l);
        buf[l] = '\0';
        return buf;
    }
    if (l >= cap) l = cap - 1;
    memcpy(buf, t->s, l);
    buf[l] = '\0';
    return buf;
}

/* stringsEqual 等价：'a'='a' 命中（内容比较，剥引号） */
int sql_strings_equal(const Token* a, const Token* b) {
    char ba[256], bb[256];
    return strcmp(unquote(a, ba, sizeof(ba)), unquote(b, bb, sizeof(bb))) == 0;
}

/* 区间 [s,e) 内查找指定类型 token（constant_value 可含任意层括号） */
static const Token* find_in_range(const Token* tk, int s, int e, TokType ty) {
    for (int i = s; i < e; ++i) {
        if (tk[i].type == ty) return &tk[i];
    }
    return NULL;
}

/* constNumbersEqual / constStringsEqual 等价：
 * 两侧 constant_value 区间内取 NUMBER / STRING 做规范化比较 */
int sql_const_numbers_equal(const Token* tk, int s0, int e0, int s1, int e1) {
    const Token* a = find_in_range(tk, s0, e0, T_NUMBER);
    const Token* b = find_in_range(tk, s1, e1, T_NUMBER);
    return a && b && sql_numbers_equal(a, b);
}

int sql_const_strings_equal(const Token* tk, int s0, int e0, int s1, int e1) {
    const Token* a = find_in_range(tk, s0, e0, T_STRING);
    const Token* b = find_in_range(tk, s1, e1, T_STRING);
    return a && b && sql_strings_equal(a, b);
}

/* ------------------------------------------------------------
 * Ragel token 级状态机：三个独立入口机器（expr / select / const），
 * 每个机器两个入口：main（顶层匹配入口）+ 递归 entry（fcall 目标）。
 *
 * 手动 fret（不用 @ret 包装）：
 *     if (top > 0) cs = stack[--top];
 *     if (top == 0) match_len = (int)(p - types) + 1 - start;
 *     goto _again;
 * 出栈后仅当栈空（最外层调用结束）才记录长度 —— 内层 ret 不会留下
 * 错误的局部长度；最外层 ret 触发时 p 恰为整个递归体的末尾。
 * ------------------------------------------------------------ */

%%{
    machine rule_expr;
    include rule_shared_tok  "rule_shared.rl";
    include rule_shared_expr "rule_shared.rl";

    action note_expr { if (top == 0) match_len = (int)(p - types) + 1 - start; }
    main := expr @note_expr;
    write data noerror nofinal noentry;
}%%

%%{
    machine rule_select;
    include rule_shared_tok  "rule_shared.rl";
    include rule_shared_expr "rule_shared.rl";

    action call_sel { fcall select_call; }
    action ret_sel  { if (top > 0) cs = stack[--top];
                      if (top == 0) match_len = (int)(p - types) + 1 - start;
                      goto _again; }

    # table_ref：IDENT 或 (select_stmt) 递归子查询（任意深度嵌套）
    table_ref = IDENT | LPAREN @call_sel;
    select_stmt = SELECT ( STAR | expr_list )
                  ( FROM table_ref )?
                  ( WHERE expr )?;

    action note_select { if (top == 0) match_len = (int)(p - types) + 1 - start; }
    main := select_stmt @note_select;
    select_call := select_stmt RPAREN @ret_sel;
    write data noerror nofinal noentry;
}%%

%%{
    machine rule_const;
    include rule_shared_tok "rule_shared.rl";

    # 常量值括号递归：字面量或任意层括号包裹（1 / (1) / ((1))）
    action call_const { fcall const_call; }
    action ret_const  { if (top > 0) cs = stack[--top];
                        if (top == 0) match_len = (int)(p - types) + 1 - start;
                        goto _again; }

    constant_value = NUMBER | STRING | TRUE | FALSE | NULL
                   | LPAREN @call_const;

    action note_const { if (top == 0) match_len = (int)(p - types) + 1 - start; }
    main := constant_value @note_const;
    const_call := constant_value RPAREN @ret_const;
    write data noerror nofinal noentry;
}%%
static int run_expr(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = rule_expr_start;
    int match_len = 0;
    int stack[CFG_STACKSZ];
    int top = 0;

    %%{
        machine rule_expr;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}
static int run_select(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = rule_select_start;
    int match_len = 0;
    int stack[CFG_STACKSZ];
    int top = 0;

    %%{
        machine rule_select;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}
static int run_const(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = rule_const_start;
    int match_len = 0;
    int stack[CFG_STACKSZ];
    int top = 0;

    %%{
        machine rule_const;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}

int sql_match_expr(const int* types, int n, int start, int* len) {
    return run_expr(types, n, start, len);
}

int sql_match_select(const int* types, int n, int start, int* len) {
    return run_select(types, n, start, len);
}

int sql_match_const(const int* types, int n, int start, int* len) {
    return run_const(types, n, start, len);
}
