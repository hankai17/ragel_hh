/* ============================================================
 * sqli_rules.rl — sqli_rules.g4（24 条 SQLi 攻击规则）的 Ragel 移植
 * ------------------------------------------------------------
 * 对齐 rules/sqli/sqli_rules.g4：每条 <attack>_pat 对应一个独立
 * 机器入口（attack 同名），C 层（sqli_scan.c）逐位置逐规则匹配
 * 并上报命中区间，语义与 rulec/wrapper 逐条独立匹配一致。
 *
 * 共享骨架（expr / select_stmt / constant_value / table_ref 等）
 * 与 rule_sql.rl 相同：token 类型为字母表，CFG 递归（括号/子查询）
 * 用 fcall/fret，被调 entry 以强制 RPAREN 结尾消除结束点歧义。
 *
 * 命中记录用 leaving action（%note），不用 to-state（@）：
 *   - @ 只挂在"最后子结构被匹配"的进入转移上，可选分支（?）被
 *     跳过时（如 `SELECT *` 缺 FROM/WHERE/ORDER/LIMIT）不触发，
 *     且与 fcall 同转移时被 fcall 抢先；
 *   - % 在"离开规则终态"时触发（eof 或继续转移），跳过可选分支
 *     的合法最短匹配同样记录；触发时 p 指向离开点（已消费匹配
 *     token），故长度记 (p - types) - start。
 * 每条规则末尾追加 `any*` 兜底：规则终态无出边时（如
 * `db_enumeration` 匹配完 information_schema 后跟 `.tables`、或
 * `stacked_query` 匹配完 ;DROP 后跟 TABLE），Ragel 只给 %note
 * 生成 eof 动作、失败路径不触发；any* 使终态拥有任意 token 的
 * 出边，后续无关 token 也能触发 leaving 记录长度，长度停在规则
 * 结构结束处（any* 本身不带动作，不影响 match_len）。
 * fcall/fret 的返回（act_ret）不写长度——内部递归返回并非规则
 * 完成，否则 `sleeping(5)` 这类"函数调用前缀"会误报。
 *
 * 语义谓词分工：
 *   - isIdent（sleep / load_file / benchmark / pg_sleep /
 *     db_enumeration）在规则动作内直接判定 —— IDENT 是叶子 token，
 *     动作触发时 p 正指向该 token；
 *   - constNumbersEqual / constStringsEqual（always_true /
 *     string_tautology）依赖两侧 constant_value 的区间，本文件只做
 *     结构匹配，由 C 层在命中后复核（谓词本就是 g4 的 @parser::members
 *     C 方法）。
 * 
 * any* 像"前缀匹配 + 任意后缀"
 *
 * 生成：ragel -C -o sqli_rules.c sqli_rules.rl
 * ============================================================ */

#include <stddef.h>

#include "sql_tokens.h"

/* 语义谓词（rule_sql.rl 实现，对齐 RuleSQL.g4 @parser::members） */
extern int sql_is_ident(const Token* t, const char* expected);

/* fcall/fret 运行期栈大小（同 rule_sql.rl 的 CFG_STACKSZ） */
#define CFG_STACKSZ 1024

%%{
    machine sqli;
    NUMBER = 1;  STRING = 2;  TRUE = 3;   FALSE = 4;  NULL = 5;  IDENT = 6;
    SELECT = 7;  UNION = 8;   ALL = 9;    FROM = 10;  WHERE = 11; ORDER = 12;
    BY = 13;     LIMIT = 14;  OFFSET = 15; INSERT = 16; INTO = 17; VALUES = 18;
    UPDATE = 19; SET = 20;    DELETE = 21; DROP = 22;  ALTER = 23; CREATE = 24;
    EXISTS = 25; IN = 26;     LIKE = 27;  BETWEEN = 28; IS = 29;  NOT = 30;
    AND = 31;    OR = 32;     ASC = 33;   DESC = 34;
    EQ = 35;     NE = 36;     LE = 37;    GE = 38;    LT = 39;    GT = 40;
    PLUS = 41;   MINUS = 42;  STAR = 43;  DIV = 44;   MOD = 45;   PIPE2 = 46;
    LPAREN = 47; RPAREN = 48; COMMA = 49; SEMI = 50;

    cmp_op = EQ | NE | LE | GE | LT | GT;
    add_op = PLUS | MINUS | PIPE2;
    mul_op = STAR | DIV | MOD;

    # ------------------------------------------------------------
    # 共享骨架（同 rule_sql.rl）：CFG 递归走 fcall/fret。
    # act_ret 只弹栈返回，不记录长度（内部递归返回并非规则完成）。
    # ------------------------------------------------------------
    action call_expr  { fcall expr_call; }
    action call_elist { fcall elist_call; }
    action call_sel   { fcall select_call; }
    action call_const { fcall const_call; }
    action act_ret    { if (top > 0) cs = stack[--top]; goto _again; }

    primary = NUMBER | STRING | TRUE | FALSE | NULL
            | IDENT ( LPAREN @call_elist )?
            | LPAREN @call_expr;
    unary_expr = ( PLUS | MINUS )* primary;
    mul_expr = unary_expr ( mul_op unary_expr )*;
    add_expr = mul_expr ( add_op mul_expr )*;
    comparison = add_expr ( cmp_op add_expr )?;
    not_expr = NOT* comparison;
    and_expr = not_expr ( AND not_expr )*;
    or_expr = and_expr ( OR and_expr )*;
    expr = or_expr;
    expr_list = expr ( COMMA expr )*;
    table_ref = IDENT | LPAREN @call_sel;
    select_stmt = SELECT ( STAR | expr_list )
                  ( FROM table_ref )?
                  ( WHERE expr )?;
    constant_value = NUMBER | STRING | TRUE | FALSE | NULL
                   | LPAREN @call_const;

    expr_call := expr RPAREN @act_ret;
    elist_call := expr_list? RPAREN @act_ret;
    select_call := select_stmt RPAREN @act_ret;
    const_call := constant_value RPAREN @act_ret;

    # ------------------------------------------------------------
    # 24 条攻击规则入口（对齐 sqli_rules.g4 的 <name>_pat）
    # 命中用 leaving（%note）：离开规则终态时（eof 或继续转移）
    # 记录长度；触发时 p 指向离开点，长度 = (p - types) - start。
    # ------------------------------------------------------------
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

    # HIGH: 恒真条件（结构匹配，数值相等谓词在 C 层复核）
    always_true := constant_value EQ constant_value %note any*;
    # HIGH: 恒真字符串条件（字符串相等谓词在 C 层复核）
    string_tautology := constant_value EQ constant_value %note any*;
    # MEDIUM: 布尔型注入 OR/AND 一侧为常量比较
    const_cmp = constant_value EQ constant_value;
    boolean_injection := ( const_cmp (OR | AND) comparison
                         | comparison (OR | AND) const_cmp ) %note any*;
    # CRITICAL: UNION SELECT 联合查询
    union_select := UNION ALL? SELECT expr_list? %note any*;
    # CRITICAL: 堆叠查询 ; 后跟 SQL 关键字
    stacked_query := SEMI (SELECT | INSERT | UPDATE | DELETE | DROP | ALTER | CREATE) %note any*;
    # CRITICAL: 时间盲注函数调用（isIdent 谓词）
    sleep     := IDENT $is_sleep LPAREN expr_list? RPAREN %note any*;
    load_file := IDENT $is_load_file LPAREN expr_list? RPAREN %note any*;
    benchmark := IDENT $is_benchmark LPAREN expr_list? RPAREN %note any*;
    pg_sleep  := IDENT $is_pg_sleep LPAREN expr_list? RPAREN %note any*;
    # MEDIUM: 子查询结构（fcall select_call，返回点即终态）
    subquery := LPAREN @call_sel %note any*;
    # MEDIUM: EXISTS / NOT EXISTS 子查询
    exists_subquery := ( EXISTS | NOT EXISTS ) LPAREN @call_sel %note any*;
    # MEDIUM: IN 子查询
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
