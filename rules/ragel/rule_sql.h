/* ============================================================
 * rule_sql.h — RuleSQL 骨架 + 语义谓词库接口
 * ------------------------------------------------------------
 * 对应规则真源 rules/ragel/rule_sql.rl（对齐归档的 ANTLR 共享骨架
 * RuleSQL.g4）。本头是驱动/调用方与 rule_sql.rl 之间的唯一契约：
 *   1) CFG 骨架匹配：expr / select_stmt / constant_value
 *      （输入为 token 类型 int 数组，见 sql_tokens.h）
 *   2) 语义谓词：isIdent 与常量规范化相等（谓词复核用）
 *
 * 用法：include 本头并链接 libragel_sql（sql_tokens + rule_sql +
 * sqli_rules 打包），调用方无需接触 .rl 与生成物。
 * ============================================================ */
#ifndef RULE_SQL_H
#define RULE_SQL_H

#include "sql_tokens.h"

/* ------------------------------------------------------------
 * CFG 骨架匹配（rule_sql.rl 三个独立机器：expr / select / const）
 * ------------------------------------------------------------
 * types[n] 为 token 类型数组；从 start 位置尝试匹配，命中写 *len
 * （匹配长度，绝对区间 [start, start+len)）并返回 1，否则返回 0。
 */
int sql_match_expr(const int* types, int n, int start, int* len);
int sql_match_select(const int* types, int n, int start, int* len);
int sql_match_const(const int* types, int n, int start, int* len);

/* ------------------------------------------------------------
 * 语义谓词（rule_sql.rl 实现，对齐 RuleSQL.g4 @parser::members）
 * ------------------------------------------------------------ */
/* IDENT token 是否等于 expected（大小写不敏感关键字映射） */
int sql_is_ident(const Token* t, const char* expected);
/* NUMBER 规范化相等（可含前导零） */
int sql_numbers_equal(const Token* a, const Token* b);
/* STRING 内容相等（剥引号后比较） */
int sql_strings_equal(const Token* a, const Token* b);
/* 区间 [s0,e0) 与 [s1,e1) 内取 NUMBER 规范化比较（括号包裹容忍） */
int sql_const_numbers_equal(const Token* tk, int s0, int e0, int s1, int e1);
/* 区间 [s0,e0) 与 [s1,e1) 内取 STRING 内容比较 */
int sql_const_strings_equal(const Token* tk, int s0, int e0, int s1, int e1);

#endif /* RULE_SQL_H */
