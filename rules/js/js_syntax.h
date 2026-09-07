/* ============================================================
 * js_syntax.h — JavaScript 表达式语法骨架接口
 * ------------------------------------------------------------
 * 对应规则真源 rules/js/js_syntax.rl。expr 骨架匹配：
 * 输入为 token 类型 int 数组（见 js_tokens.h）。
 *
 * 用法：include 本头并链接（js_tokens + js_syntax 打包），
 * 调用方无需接触 .rl 与生成物。
 * ============================================================ */
#ifndef JS_SYNTAX_H
#define JS_SYNTAX_H

#include "js_tokens.h"

/* ------------------------------------------------------------
 * CFG 骨架匹配（js_syntax.rl 单个机器：expr）
 * ------------------------------------------------------------
 * types[n] 为 token 类型数组；从 start 位置尝试匹配，命中写 *len
 * （匹配长度，绝对区间 [start, start+len)）并返回 1，否则返回 0。
 */
int js_match_expr(const int* types, int n, int start, int* len);

#endif /* JS_SYNTAX_H */
