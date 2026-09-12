/* ============================================================
 * sqli_rules.h — sqli_rules.rl（24 条 SQLi 攻击规则）库接口
 * ------------------------------------------------------------
 * 一个 CTX = "一条规则在一个输入（请求）上的匹配上下文"。它自持
 * 状态机的运行状态（cs / 递归栈 / 命中长度）与位置（本次起点 / 喂入游标 /
 * 扫描游标），因此调用方不用记住任何位置，只管"初始化 -> 喂/扫 -> 清除"：
 *
 *     // 每个请求：每条规则一个 CTX
 *     SqliCtx ctx[SQLI_NUM_ENTRIES];
 *     for (int r = 0; r < SQLI_NUM_ENTRIES; ++r)
 *         sqli_ctx_init(&ctx[r], r);          // 1) 初始化：绑定规则
 *
 *     for (int r = 0; r < SQLI_NUM_ENTRIES; ++r)
 *         while (sqli_ctx_scan(&ctx[r], types, tk, n, chunk))   // 2) 匹配/扫描
 *             ;   // 命中：起点 ctx[r].start，长度 ctx[r].match_len
 *
 *     for (int r = 0; r < SQLI_NUM_ENTRIES; ++r)
 *         sqli_ctx_clean(&ctx[r]);             // 3) 清除/释放
 *
 * 两种用法：
 *   - sqli_ctx_scan：高内聚的"扫描器"——从 ctx 记住的游标逐个起点试，命中
 *     即返回；驱动不需要写起点循环。
 *   - sqli_ctx_feed：底层"续跑"——从 ctx 记住的位置喂一段 token，后续 token
 *     到达时接着这个位置继续跑（可中断）。
 *
 * 喂入单位是 token（types[] + 原文 tk[]）。
 * 调用方只需 include 本头并链接 libragel_sql，无需 ragel。
 * ============================================================ */
#ifndef SQLI_RULES_H
#define SQLI_RULES_H

#include "sql_tokens.h"

/* fcall/fret 栈深上限（随 CTX 走）。超限即判该 CTX 失败（cs = 0），
 * 不会越界写。实 SQL 的括号嵌套极少超过个位数，128 足够宽松。 */
#define SQLI_CTX_STACK 128

/* 一条规则在一个输入上的匹配上下文（自推进扫描器） */
typedef struct {
    int entry;                  /* 该规则的状态机入口（init 绑定后不变） */
    int cs;                     /* 状态机当前状态；0 = 已失败 / 已结束 */
    int top;                    /* fcall/fret 调用栈深度 */
    int match_len;              /* >0 = 已命中（长度按 token 数） */
    int start;                  /* 本次尝试的起点（喂入期不变，供算长度） */
    int pos;                    /* 已喂到的位置（下一个待喂 token 下标） */
    int next;                   /* 扫描游标：下一个要试的起点 */
    int stack[SQLI_CTX_STACK];  /* fcall/fret 返回栈 */
} SqliCtx;

/* ------------------------------------------------------------
 * 规则清单 —— 唯一真源。
 * 规则表与入口状态映射都从这份清单展开，增删规则只改这里一处：
 * X(规则名, 谓词复核类型)。
 *   谓词复核：0 = 无需复核 / 1 = 数值常量相等 / 2 = 字符串常量相等
 *   （always_true / string_tautology 的 rl 只保证结构，相等性在 C 层判）
 * ------------------------------------------------------------ */
#define SQLI_RULE_LIST(X)                                                     \
    X(always_true,             1)                                            \
    X(string_tautology,        2)                                            \
    X(boolean_injection,       0)                                            \
    X(union_select,            0)                                            \
    X(stacked_query,           0)                                            \
    X(sleep,                   0)                                            \
    X(load_file,               0)                                            \
    X(benchmark,               0)                                            \
    X(pg_sleep,                0)                                            \
    X(subquery,                0)                                            \
    X(exists_subquery,         0)                                            \
    X(in_subquery,             0)                                            \
    X(like_expr,               0)                                            \
    X(between_expr,            0)                                            \
    X(numeric_expr,            0)                                            \
    X(order_by_expr,           0)                                            \
    X(limit_expr,              0)                                            \
    X(string_concat,           0)                                            \
    X(insert_fragment,         0)                                            \
    X(update_fragment,         0)                                            \
    X(delete_fragment,         0)                                            \
    X(select_fragment,         0)                                            \
    X(select_from_fragment,    0)                                            \
    X(db_enumeration,          0)

/* 规则条数（由清单推出，不手数） */
#define SQLI_RULE_COUNT_(name, pred) + 1
enum { SQLI_NUM_ENTRIES = 0 SQLI_RULE_LIST(SQLI_RULE_COUNT_) };
#undef SQLI_RULE_COUNT_

/* ---- 1) 初始化 / 清除 ---- */

/* 绑定规则（rule = 0 .. SQLI_NUM_ENTRIES-1），游标与状态全部归零，从头扫描。
 * 每个请求、每条规则调一次。rule 越界则 CTX 被置为"已失败"。 */
void sqli_ctx_init(SqliCtx* c, int rule);

/* 清空 CTX（cs 归 0，之后不可再喂/扫）。CTX 是值语义、不持有堆资源，
 * 故这里是"清除"；将来若持有堆内存，释放点就在这里。 */
void sqli_ctx_clean(SqliCtx* c);

/* ---- 2) 匹配 ---- */

/* 扫描：从 ctx 记住的游标（next）起逐个起点试，命中即停下。
 *   types/tk : 整个输入的 token 类型数组与原文数组（等长对齐）
 *   n        : 整个输入的 token 数
 *   cnt      : 每次喂几个 token；<= 0 表示一次喂到末尾
 * 返回 1 = 命中：起点与长度读 c->start / c->match_len；
 * 返回 0 = 已扫完，没有更多命中。起点循环由 ctx 自己推进，调用方不传起点。 */
int sqli_ctx_scan(SqliCtx* c, const int* types, const Token* tk, int n, int cnt);

/* 续跑（底层）：从 ctx 记住的位置（pos）起喂一段 token，喂完自动推进 pos。
 * 参数同 scan；cnt <= 0 = 喂到末尾。返回 1 = 本段内完成一次匹配（*hit_len
 * 给长度），0 = 尚未完成。喂到输入末尾的那一次会自动收尾。 */
int sqli_ctx_feed(SqliCtx* c, const int* types, const Token* tk, int n,
                  int cnt, int* hit_len);

/* cs != 0 即可继续喂 */
int sqli_ctx_alive(const SqliCtx* c);

/* ------------------------------------------------------------
 * 规则表：名字 / 谓词复核类型（与清单同序）。供驱动上报命中时取规则名
 * 与判是否要做常量相等复核。 */
typedef struct {
    const char* name;
    int  pred;
} SqliRuleDef;

extern const SqliRuleDef SQLI_RULES[SQLI_NUM_ENTRIES];

#endif /* SQLI_RULES_H */
