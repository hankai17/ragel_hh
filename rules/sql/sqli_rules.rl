/* ============================================================
 * sqli_rules.rl — sqli_rules.g4（24 条 SQLi 攻击规则）的 Ragel 移植
 * ------------------------------------------------------------
 * 每条 <name>_pat 攻击规则对应一个独立机器入口（<name> 同名），
 * 驱动逐位置逐规则匹配并上报命中区间。
 *
 * 复用 sql_shared.rl 的 token 编号 / 运算符 / expr 规则链；
 * 递归入口与返回动作在本文件定义（act_ret 只弹栈不写长度，
 * 命中长度由 %note 在规则完成时记录）。
 *
 * 生成：ragel -C -o sqli_rules.c sqli_rules.rl
 * ============================================================ */

#include <stddef.h>

#include "sql_tokens.h"

/* 语义谓词（sql_syntax.rl 实现，对齐 RuleSQL.g4 @parser::members） */
extern int sql_is_ident(const Token* t, const char* expected);

/* fcall/fret 运行期栈大小（同 sql_syntax.rl 的 CFG_STACKSZ） */
#define CFG_STACKSZ 1024

%%{
    machine sqli;
    include sql_shared_tok  "sql_shared.rl";
    include sql_shared_expr "sql_shared.rl";

    # 递归返回：只弹栈不写长度（内部递归返回并非规则完成）
    action act_ret    { if (top > 0) cs = stack[--top]; goto _again; }
    action call_sel   { fcall select_call; }
    action call_const { fcall const_call; }

    expr_call := expr RPAREN @act_ret;
    elist_call := expr_list? RPAREN @act_ret;

    table_ref = IDENT | LPAREN @call_sel;
    select_stmt = SELECT ( STAR | expr_list )
                  ( FROM table_ref )?
                  ( WHERE expr )?;
    constant_value = NUMBER | STRING | TRUE | FALSE | NULL
                   | LPAREN @call_const;

    select_call := select_stmt RPAREN @act_ret;
    const_call := constant_value RPAREN @act_ret;

    # 命中记录（leaving）：离开规则终态时记录长度
    action note { if (top == 0) match_len = (int)(p - types) - start; }
    action is_sleep       { if (!sql_is_ident(&tk[(int)(p - types)], "sleep"))
                                { cs = 0; goto _out; } }
    action is_load_file   { if (!sql_is_ident(&tk[(int)(p - types)], "load_file"))
                                { cs = 0; goto _out; } }
    action is_benchmark   { if (!sql_is_ident(&tk[(int)(p - types)], "benchmark"))
                                { cs = 0; goto _out; } }
    action is_pg_sleep    { if (!sql_is_ident(&tk[(int)(p - types)], "pg_sleep"))
                                { cs = 0; goto _out; } }
    action is_info_schema { if (!sql_is_ident(&tk[(int)(p - types)], "information_schema"))
                                { cs = 0; goto _out; } }

    # HIGH: 恒真条件（常量相等谓词在 C 层复核）
    always_true := constant_value EQ constant_value %note any*;
    string_tautology := constant_value EQ constant_value %note any*;
    # MEDIUM: 布尔型注入 OR/AND 一侧为常量比较
    const_cmp = constant_value EQ constant_value;
    boolean_injection := ( const_cmp (OR | AND) comparison
                         | comparison (OR | AND) const_cmp ) %note any*;
    # CRITICAL: UNION SELECT 联合查询
    union_select := UNION ALL? SELECT expr_list? %note any*;
    # CRITICAL: 堆叠查询
    stacked_query := SEMI (SELECT | INSERT | UPDATE | DELETE | DROP | ALTER | CREATE) %note any*;
    # CRITICAL: 时间盲注函数调用（isIdent 谓词）
    sleep     := IDENT $is_sleep LPAREN expr_list? RPAREN %note any*;
    load_file := IDENT $is_load_file LPAREN expr_list? RPAREN %note any*;
    benchmark := IDENT $is_benchmark LPAREN expr_list? RPAREN %note any*;
    pg_sleep  := IDENT $is_pg_sleep LPAREN expr_list? RPAREN %note any*;
    # MEDIUM: 子查询结构
    subquery := LPAREN @call_sel %note any*;
    exists_subquery := ( EXISTS | NOT EXISTS ) LPAREN @call_sel %note any*;
    in_subquery := add_expr NOT? IN LPAREN @call_sel %note any*;
    # LOW: LIKE / BETWEEN / 数值比较 / 排序 / 分页 / 字符串拼接
    like_expr      := add_expr NOT? LIKE add_expr %note any*;
    between_expr   := add_expr NOT? BETWEEN add_expr AND add_expr %note any*;
    numeric_expr   := ( mul_expr ( add_op mul_expr )+ ) EQ add_expr %note any*;
    order_by_expr  := ORDER BY expr ( ASC | DESC )? %note any*;
    limit_expr     := LIMIT expr ( OFFSET expr )? %note any*;
    string_concat  := add_expr PIPE2 add_expr %note any*;
    # MEDIUM: 语句片段
    insert_fragment := INSERT INTO? IDENT?
                       ( LPAREN expr_list RPAREN )?
                       ( VALUES LPAREN expr_list RPAREN )? %note any*;
    update_fragment := UPDATE IDENT ( SET expr_list? )? %note any*;
    delete_fragment := DELETE FROM? IDENT %note any*;
    select_fragment := SELECT ( STAR | expr_list )
                       ( FROM table_ref )?
                       ( WHERE expr )?
                       ( ORDER BY expr )?
                       ( LIMIT expr )? %note any*;
    select_from_fragment := SELECT ( STAR | expr_list ) FROM table_ref %note any*;
    # MEDIUM: 数据库结构枚举（information_schema 访问）
    db_enumeration := IDENT $is_info_schema %note any*;

    write data noerror nofinal;
}%%

/* ------------------------------------------------------------
 * 运行期：一个通用 run（cs0 指定入口状态）+ 每个规则一个导出函数。
 * 谓词动作需要 Token 数组（isIdent），故 tk 一并传入。
 * ------------------------------------------------------------ */
static int run_sqli(const int* types, int n, int start, int cs0,
                    const Token* tk, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    const int* eof = pe;
    int cs = cs0;
    int match_len = 0;
    int stack[CFG_STACKSZ];
    int top = 0;

    %%{
        machine sqli;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}

/* ragel 为每个 `:=` 入口生成 sqli_en_<name> 起始状态常量 */
#define SQLI_ENTRY(name) \
    int sql_match_sqli_##name(const int* types, int n, int start, \
                              const Token* tk, int* len) { \
        return run_sqli(types, n, start, sqli_en_##name, tk, len); \
    }

SQLI_ENTRY(always_true)
SQLI_ENTRY(string_tautology)
SQLI_ENTRY(boolean_injection)
SQLI_ENTRY(union_select)
SQLI_ENTRY(stacked_query)
SQLI_ENTRY(sleep)
SQLI_ENTRY(load_file)
SQLI_ENTRY(benchmark)
SQLI_ENTRY(pg_sleep)
SQLI_ENTRY(subquery)
SQLI_ENTRY(exists_subquery)
SQLI_ENTRY(in_subquery)
SQLI_ENTRY(like_expr)
SQLI_ENTRY(between_expr)
SQLI_ENTRY(numeric_expr)
SQLI_ENTRY(order_by_expr)
SQLI_ENTRY(limit_expr)
SQLI_ENTRY(string_concat)
SQLI_ENTRY(insert_fragment)
SQLI_ENTRY(update_fragment)
SQLI_ENTRY(delete_fragment)
SQLI_ENTRY(select_fragment)
SQLI_ENTRY(select_from_fragment)
SQLI_ENTRY(db_enumeration)
