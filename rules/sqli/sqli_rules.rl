/* ============================================================
 * sqli_rules.rl — sqli_rules.g4（24 条 SQLi 攻击规则）的 Ragel 移植
 * ------------------------------------------------------------
 * 每条 <name>_pat 攻击规则对应一个独立机器入口（<name> 同名）。
 *
 * 状态机层是"无位置的流式消费者"：SqliCtx 只存状态机内部状态（cs + fcall
 * 栈 + 命中长度）与"已消费计数"，不记录任何绝对 token 下标 —— token 流的
 * 顺序与位置由调用方（用户层）维护。
 *   - ctx_run() 是唯一执行体；
 *   - sqli_ctx_feed() 喂"接下来"的 n 个 token（可续跑）；
 *   - sqli_ctx_finish() 表示输入结束。
 *
 * 复用 sql_shared.rl 的 token 编号 / 运算符 / expr 规则链；
 * 递归入口与返回动作在本文件定义（act_ret 只弹栈不写长度，
 * 命中长度由 %note 在规则完成时记录）。
 *
 * 生成：ragel -C -I src/sql -o sqli_rules.c sqli_rules.rl
 * ============================================================ */

#include <stddef.h>

#include "sql_tokens.h"
#include "sqli_rules.h"

/* 语义谓词（sql_syntax.rl 实现，对齐 RuleSQL.g4 @parser::members） */
extern int sql_is_ident(const Token* t, const char* expected);

/* fcall/fret 栈上限。sql_shared.rl 的 call_expr/call_elist 与本文件的
 * call_sel/call_const 都用这个名字做栈满判断（各宿主自己定义）——
 * 超限即判当前实例失败，避免 fcall 写出栈外。 */
#define SQL_FRAME_MAX SQLI_CTX_STACK

%%{
    machine sqli;
    include sql_shared_tok  "sql_shared.rl";
    include sql_shared_expr "sql_shared.rl";

    # 递归返回：只弹栈不写长度（内部递归返回并非规则完成）
    action act_ret    { if (top > 0) cs = stack[--top]; goto _again; }
    action call_sel   { if (top >= SQL_FRAME_MAX) { cs = 0; goto _out; }
                        fcall select_call; }
    action call_const { if (top >= SQL_FRAME_MAX) { cs = 0; goto _out; }
                        fcall const_call; }

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

    # 命中记录（leaving）：离开规则终态时记录长度。
    # consumed = 本段之前已消费的 token 数（ctx_run 的局部变量），
    # p - types = 本段内的相对偏移，二者相加 = 从本次尝试起点起已消费的
    # token 数 = 匹配长度。全程只用相对计数，不出现绝对位置。
    action note { if (top == 0) match_len = consumed + (int)(p - types); }
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
 * 运行期
 * ------------------------------------------------------------
 * ctx_run 是唯一的执行体：状态从 CTX 读入、跑完写回；输入就是"接下来"
 * 的 n 个 token（本段）。不出现任何绝对 token 下标 —— 位置由调用方维护。
 *
 *   types/tk : 本段（接下来）的 token 类型数组与原文数组（等长对齐）
 *   n        : 本段 token 数
 *   at_eof   : 非 0 才让 ragel 的 eof 动作触发。喂中间段传 0，最后一段
 *              （或 finish）传 1。
 *
 * %note 里 match_len = consumed + (p - types)：
 *   consumed  = 本段之前已消费的 token 数（相对计数）
 *   p - types = 本段内的相对偏移
 * 相加即"从本次尝试起点起已消费的 token 数" = 匹配长度。
 * ------------------------------------------------------------ */
static int ctx_run(SqliCtx* c, const int* types, const Token* tk,
                   int n, int at_eof, int* hit_len) {
    const int* p = types;
    const int* pe = p + n;
    /* eof 在生成的代码里只出现于 `if (p == eof)`：给它一个永远不等于 p
     * 的值即可抑制 eof 动作（types 恒非空，p 不可能为 NULL）。 */
    const int* eof = at_eof ? pe : (const int*)0;
    int cs = c->cs;
    int top = c->top;
    int match_len = c->match_len;
    int consumed = c->consumed;
    int* stack = c->stack;

    %%{
        machine sqli;
        write exec;
    }%%

    c->cs = cs;
    c->top = top;
    c->match_len = match_len;
    c->consumed = consumed + (int)(p - types);   /* 本段实际消费了几个 */

    if (match_len > 0) {
        if (hit_len) *hit_len = match_len;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------
 * 1) 初始化 / 清除 / 重置
 * ------------------------------------------------------------
 * 规则下标 -> ragel 入口状态。ragel 把入口状态生成成文件级
 * `static const int`，C 里它不算常量表达式，没法用于文件作用域的静态
 * 初始化，所以这里用一张局部数组在运行期取（自动存储期允许非常量初始化）。
 * ------------------------------------------------------------ */
static int entry_state(int rule) {
    const int tbl[SQLI_NUM_ENTRIES] = {
#define SQLI_ENTRY_OF(name, pred) sqli_en_##name,
        SQLI_RULE_LIST(SQLI_ENTRY_OF)
#undef SQLI_ENTRY_OF
    };
    if (rule < 0 || rule >= SQLI_NUM_ENTRIES) return 0;
    return tbl[rule];
}

void sqli_ctx_init(SqliCtx* c, int rule) {
    c->entry = entry_state(rule);
    sqli_ctx_reset(c);
}

void sqli_ctx_clean(SqliCtx* c) {
    c->entry = 0;
    c->cs = 0;               /* 0 = 不可再喂 */
    c->top = 0;
    c->match_len = 0;
    c->consumed = 0;
}

/* 开始一次新尝试：拨回入口态，清空命中与已消费计数。每次换起点（或新
 * 请求复用同一 ctx）前调一次。 */
void sqli_ctx_reset(SqliCtx* c) {
    c->cs = c->entry;
    c->top = 0;
    c->match_len = 0;
    c->consumed = 0;
}

/* ------------------------------------------------------------
 * 2) 匹配
 * ------------------------------------------------------------ */
int sqli_ctx_feed(SqliCtx* c, const int* types, const Token* tk, int n,
                  int* hit_len) {
    if (!sqli_ctx_alive(c)) return 0;
    return ctx_run(c, types, tk, n, 0, hit_len);   /* 收尾交给 finish */
}

int sqli_ctx_finish(SqliCtx* c, int* hit_len) {
    static const int empty_types = 0;   /* n = 0，不会被读 */
    static Token empty_tk;              /* 同上（零初始化） */
    return ctx_run(c, &empty_types, &empty_tk, 0, 1, hit_len);
}

int sqli_ctx_alive(const SqliCtx* c) {
    return c->cs != 0;
}

/* ------------------------------------------------------------
 * 规则表：与 SQLI_RULE_LIST 同序（名字 + 谓词复核类型，供上报）
 * ------------------------------------------------------------ */
const SqliRuleDef SQLI_RULES[SQLI_NUM_ENTRIES] = {
#define SQLI_TAB(name, pred) { #name, pred },
    SQLI_RULE_LIST(SQLI_TAB)
#undef SQLI_TAB
};
