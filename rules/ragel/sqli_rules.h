/* ============================================================
 * sqli_rules.h — sqli_rules.rl（24 条 SQLi 攻击规则）库接口
 * ------------------------------------------------------------
 * 对应规则真源 rules/ragel/sqli_rules.rl（对齐归档的 ANTLR 规则
 * sqli_rules.g4）。每条 <name>_pat 攻击规则 = 一个独立机器入口
 *   sql_match_sqli_<name>()
 *
 * 匹配语义：输入为 token 类型数组（先经 lex_sql 词法，见
 * sql_tokens.h），从 start 逐位置独立匹配；命中写 *len 并返回 1，
 * 否则返回 0。
 *
 * 谓词分工：
 *   - always_true / string_tautology 需在 C 层用 rule_sql.h 的
 *     sql_match_const + sql_const_*_equal 做常量相等复核
 *     （rl 只保证 constant_value EQ constant_value 结构）；
 *   - 其余规则的 isIdent（sleep/load_file/...）已在 rl 内判定。
 *
 * 用法：include 本头并链接 libragel_sql（含 sqli_rules）。
 * ============================================================ */
#ifndef SQLI_RULES_H
#define SQLI_RULES_H

#include "sql_tokens.h"

#define SQLI_DECL(name)                                                   \
    int sql_match_sqli_##name(const int* types, int n, int start,         \
                              const Token* tk, int* len);

SQLI_DECL(always_true)
SQLI_DECL(string_tautology)
SQLI_DECL(boolean_injection)
SQLI_DECL(union_select)
SQLI_DECL(stacked_query)
SQLI_DECL(sleep)
SQLI_DECL(load_file)
SQLI_DECL(benchmark)
SQLI_DECL(pg_sleep)
SQLI_DECL(subquery)
SQLI_DECL(exists_subquery)
SQLI_DECL(in_subquery)
SQLI_DECL(like_expr)
SQLI_DECL(between_expr)
SQLI_DECL(numeric_expr)
SQLI_DECL(order_by_expr)
SQLI_DECL(limit_expr)
SQLI_DECL(string_concat)
SQLI_DECL(insert_fragment)
SQLI_DECL(update_fragment)
SQLI_DECL(delete_fragment)
SQLI_DECL(select_fragment)
SQLI_DECL(select_from_fragment)
SQLI_DECL(db_enumeration)

#undef SQLI_DECL

#endif /* SQLI_RULES_H */
