/* ============================================================
 * html5_xss_rules.h — XSS 黑名单规则库接口（对齐 libinjection is_xss）
 * ------------------------------------------------------------
 * 规则真源 rules/html5_xss/html5_xss_rules.rl，每条 <name> 规则 = 一个独立
 * 机器入口。
 *
 * 状态机层是"无位置的流式消费者"：只负责按顺序吃 token、推进内部状态、
 * 上报匹配长度（token 数）。它不关心"这是第几个 token"，也不记录任何
 * 绝对位置 —— token 流的顺序与位置由调用方（用户层）维护。
 *
 * 典型用法（调用方决定起点与喂法，状态机只吃 token）：
 *
 *     H5XssCtx ctx;
 *     h5xss_ctx_init(&ctx, rule);                    // 1) 绑定规则
 *
 *     for (int s = 0; s < n; ++s) {                  // 起点循环在调用方
 *         h5xss_ctx_reset(&ctx);                     //    开始一次新尝试
 *         h5xss_ctx_feed(&ctx, types + s, tk + s, n - s, NULL);  // 2) 喂
 *         h5xss_ctx_finish(&ctx, NULL);              //    输入结束
 *         if (ctx.match_len > 0) ...                 // 命中 [s, s + match_len)
 *     }
 *
 *     h5xss_ctx_clean(&ctx);                         // 3) 清除
 *
 * 续跑（可中断）：把"接下来"的 token 分几次喂，状态跨 feed 保留；
 * 喂完最后一段再调 finish()。
 *
 * 六条规则（对齐 libinjection_xss.c 的 is_xss 主循环，精细化版）：
 *   black_tag          黑标签（script/iframe/object/svg* 等）
 *   black_attr         黑属性（on* 事件 / xmlns / xlink 等，直接危险）
 *   black_url          URI 属性 + 黑 URL（href=javascript: 等）
 *   style_expr         style/filter 属性值含 expression(/javascript:
 *   dangerous_comment  注释含反引号 / [if / xml / import / entity
 *   dangerous_js       属性值/脚本正文含危险 JS 调用（语义）
 *
 * 调用方只需 include 本头并链接 libragel_sql（含 html5_tokens +
 * html5_xss_rules），无需 ragel。
 * ============================================================ */
#ifndef HTML5_XSS_RULES_H
#define HTML5_XSS_RULES_H

#include "html5_tokens.h"

/* ------------------------------------------------------------
 * 规则清单 —— 唯一真源。
 * 规则表与入口状态映射都从这份清单展开，增删规则只改这里一处：
 * X(规则名)。html5 规则无 fcall 递归，故 CTX 无需调用栈（top/stack）。
 * ------------------------------------------------------------ */
#define H5XSS_RULE_LIST(X)     \
    X(black_tag)               \
    X(black_attr)              \
    X(black_url)               \
    X(style_expr)              \
    X(dangerous_comment)       \
    X(dangerous_js)

/* 规则条数（由清单推出，不手数） */
#define H5XSS_RULE_COUNT_(name) + 1
enum { H5XSS_NUM_ENTRIES = 0 H5XSS_RULE_LIST(H5XSS_RULE_COUNT_) };
#undef H5XSS_RULE_COUNT_

/* 一条规则的状态机上下文。只含状态机内部状态与"已消费计数"（计数，
 * 不是位置），不含任何 token 下标。 */
typedef struct {
    int entry;                  /* 该规则的状态机入口（init 绑定后不变） */
    int cs;                     /* DFA 当前状态；0 = 已失败 / 已结束 */
    int match_len;              /* >0 = 已命中（长度按 token 数） */
    int consumed;               /* 本次尝试已消费的 token 数（算 match_len 用） */
} H5XssCtx;

/* ---- 1) 初始化 / 清除 / 重置 ---- */

/* 绑定规则（rule = 0 .. H5XSS_NUM_ENTRIES-1）并置为初始态。
 * 每个请求、每条规则调一次。rule 越界则 CTX 被置为"已失败"。 */
void h5xss_ctx_init(H5XssCtx* c, int rule);

/* 清空 CTX（cs 归 0，之后不可再喂）。CTX 是值语义、不持有堆资源，
 * 故这里是"清除"；将来若持有堆内存，释放点就在这里。 */
void h5xss_ctx_clean(H5XssCtx* c);

/* 开始一次新尝试：拨回入口态，命中长度与已消费计数归零。
 * 每次换起点（或新请求复用同一 CTX）前调一次。 */
void h5xss_ctx_reset(H5XssCtx* c);

/* ---- 2) 匹配 ---- */

/* 喂"接下来"的 n 个 token（调用方保证顺序输入）。types 与 tk 等长对齐
 * （tk 是 token 原文，谓词要用）。返回 1 = 本段内完成一次匹配（*hit_len
 * 给长度），0 = 尚未完成。喂完所有 token 后调 h5xss_ctx_finish 收尾。 */
int h5xss_ctx_feed(H5XssCtx* c, const int* types, const H5Tok* tk, int n,
                   int* hit_len);

/* 输入结束：让 ragel 的 eof 动作触发，处理"模式刚好在输入末尾完成、
 * 没有后续 token 触发离开动作"的情况。喂完最后一段后调一次。 */
int h5xss_ctx_finish(H5XssCtx* c, int* hit_len);

/* cs != 0 即可继续喂 */
int h5xss_ctx_alive(const H5XssCtx* c);

/* ------------------------------------------------------------
 * 规则表：名字（与清单同序）。供驱动上报命中时取规则名。 */
typedef struct {
    const char* name;
} H5XssRuleDef;

extern const H5XssRuleDef H5XSS_RULES[H5XSS_NUM_ENTRIES];

#endif /* HTML5_XSS_RULES_H */
