/* ============================================================
 * sqli_rules.h — sqli_rules.rl（24 条 SQLi 攻击规则）库接口
 * ------------------------------------------------------------
 * 状态机层是"无位置的流式消费者"：只负责按顺序吃 token、推进内部状态、
 * 上报匹配长度（token 数）。它不关心"这是第几个 token"，也不记录任何
 * 绝对位置 —— token 流的顺序与位置由调用方（用户层）维护。
 *
 * 典型用法（调用方决定起点与喂法，状态机只吃 token）：
 *
 *     SqliCtx ctx;
 *     sqli_ctx_init(&ctx, rule);                   // 1) 绑定规则
 *
 *     for (int s = 0; s < n; ++s) {                // 起点循环在调用方
 *         sqli_ctx_reset(&ctx);                    //    开始一次新尝试
 *         sqli_ctx_feed(&ctx, types + s, tk + s, n - s, NULL);  // 2) 喂
 *         sqli_ctx_finish(&ctx, NULL);             //    输入结束
 *         if (ctx.match_len > 0) ...               // 命中 [s, s + match_len)
 *     }
 *
 *     sqli_ctx_clean(&ctx);                        // 3) 清除
 *
 * 续跑（可中断）：把"接下来"的 token 分几次喂，状态跨 feed 保留；
 * 喂完最后一段再调 finish()。
 *
 * 调用方只需 include 本头并链接 libragel_sql，无需 ragel。
 * ============================================================ */
#ifndef SQLI_RULES_H
#define SQLI_RULES_H

#include "sql_tokens.h"

/* fcall/fret 栈深上限（随 CTX 走）。超限即判该 CTX 失败（cs = 0），
 * 不会越界写。实 SQL 的括号嵌套极少超过个位数，128 足够宽松。 */
#define SQLI_CTX_STACK 128

/* 一条规则的状态机上下文。只含状态机内部状态与"已消费计数"（计数，
 * 不是位置），不含任何 token 下标。 */
typedef struct {
    int entry;                  /* 该规则的状态机入口（init 绑定后不变） */
    int cs;                     /* DFA 当前状态；0 = 已失败 / 已结束 */
    int top;                    /* fcall/fret 调用栈深度 */
    int match_len;              /* >0 = 已命中（长度按 token 数） */
    int consumed;               /* 本次尝试已消费的 token 数（算 match_len 用） */
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

/* ---- 1) 初始化 / 清除 / 重置 ---- */

/* 绑定规则（rule = 0 .. SQLI_NUM_ENTRIES-1）并置为初始态。
 * 每个请求、每条规则调一次。rule 越界则 CTX 被置为"已失败"。 */
void sqli_ctx_init(SqliCtx* c, int rule);

/* 清空 CTX（cs 归 0，之后不可再喂）。CTX 是值语义、不持有堆资源，
 * 故这里是"清除"；将来若持有堆内存，释放点就在这里。 */
void sqli_ctx_clean(SqliCtx* c);

/* 开始一次新尝试：拨回入口态，命中长度与已消费计数归零。
 * 每次换起点（或新请求复用同一 CTX）前调一次。 */
void sqli_ctx_reset(SqliCtx* c);

/* ---- 2) 匹配 ---- */

/* 喂"接下来"的 n 个 token（调用方保证顺序输入）。types 与 tk 等长对齐
 * （tk 是 token 原文，谓词要用）。返回 1 = 本段内完成一次匹配（*hit_len
 * 给长度），0 = 尚未完成。喂完所有 token 后调 sqli_ctx_finish 收尾。 */
int sqli_ctx_feed(SqliCtx* c, const int* types, const Token* tk, int n,
                  int* hit_len);

/* 输入结束：让 ragel 的 eof 动作触发，处理"模式刚好在输入末尾完成、
 * 没有后续 token 触发离开动作"的情况。喂完最后一段后调一次。 */
int sqli_ctx_finish(SqliCtx* c, int* hit_len);

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
