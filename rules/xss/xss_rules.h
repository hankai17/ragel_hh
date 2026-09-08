/* ============================================================
 * xss_rules.h — XSS 黑名单规则库接口（对齐 libinjection is_xss）
 * ------------------------------------------------------------
 * 规则真源 rules/xss/xss_rules.rl，每条 <name> 规则 = 一个独立
 * 机器入口 xss_match_<name>()。
 *
 * 匹配语义：输入为 token 类型数组（先经 lex_html5 词法，见
 * html5_tokens.h），从 start 逐位置独立匹配；命中写 *len 并返回 1，
 * 否则返回 0。
 *
 * 五条规则（对齐 libinjection_xss.c 的 is_xss 主循环，精细化版）：
 *   black_tag          黑标签（script/iframe/object/svg* 等）
 *   black_attr         黑属性（on* 事件 / xmlns / xlink 等，直接危险）
 *   black_url          URI 属性 + 黑 URL（href=javascript: 等）
 *   style_expr         style/filter 属性值含 expression(/javascript:
 *   dangerous_comment  注释含反引号 / [if / xml / import / entity
 *
 * 用法：include 本头并链接 libragel_sql（含 html5_tokens + xss_rules）。
 * ============================================================ */
#ifndef XSS_RULES_H
#define XSS_RULES_H

#include "html5_tokens.h"

#define XSS_DECL(name)                                                     \
    int xss_match_##name(const int* types, int n, int start,               \
                         const H5Tok* tk, int* len);

XSS_DECL(black_tag)
XSS_DECL(black_attr)
XSS_DECL(black_url)
XSS_DECL(style_expr)
XSS_DECL(dangerous_comment)

#undef XSS_DECL

#endif /* XSS_RULES_H */
