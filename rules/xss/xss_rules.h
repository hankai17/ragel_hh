/* ============================================================
 * xss_rules.h — xss_rules.rl（5 条 XSS 攻击规则）库接口
 * ------------------------------------------------------------
 * 对应规则真源 rules/ragel/xss_rules.rl。每条攻击规则 =
 * 一个独立机器入口 xss_match_<name>()。
 *
 * 匹配语义：输入为 token 类型数组（先经 lex_xss 词法，见
 * xss_tokens.h），从 start 逐位置独立匹配；命中写 *len 并返回 1，
 * 否则返回 0。语义谓词（标签名 / 事件属性 / URI）已在 rl 内判定。
 *
 * 用法：include 本头并链接 libragel_sql（含 xss_rules）。
 * ============================================================ */
#ifndef XSS_RULES_H
#define XSS_RULES_H

#include "xss_tokens.h"

#define XSS_DECL(name) \
    int xss_match_##name(const int* types, int n, int start, \
                         const XssTok* tk, int* len);

XSS_DECL(script_tag)
XSS_DECL(dangerous_tag)
XSS_DECL(event_handler)
XSS_DECL(js_uri)
XSS_DECL(entity_lt)

#undef XSS_DECL

#endif /* XSS_RULES_H */
