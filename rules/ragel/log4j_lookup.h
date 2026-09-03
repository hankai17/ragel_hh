/* ============================================================
 * log4j_lookup.h — log4j 查找表达式识别库接口
 * ------------------------------------------------------------
 * 对应 rules/antlr4/_shared/{Log4jTokens,Log4jLookup}.g4 与
 * rules/antlr4/log4j/log4j_rules.g4 覆盖的判定面，Ragel 实现：
 *   状态机层识别 ${...} 查找表达式（有界深度嵌套），
 *   语义层归约前缀并分类：JNDI / SENSITIVE / CHAIN / EXPR。
 *
 * 本头是驱动/调用方与 log4j_lookup.rl（规则）之间的唯一契约：
 * 驱动只需 include 本头并链接由 log4j_lookup.rl 生成的 .c。
 * ============================================================ */
#ifndef LOG4J_LOOKUP_H
#define LOG4J_LOOKUP_H

#include <stddef.h>

/* 一个 ${...} 查找表达式命中的分类结果 */
typedef struct {
    const char* cls;   /* "JNDI" / "SENSITIVE" / "CHAIN" / "EXPR"（静态串） */
    char detail[64];   /* SENSITIVE 时为首个前缀关键字，如 "env"；其余为空 */
    const char* s;     /* 表达式起始（指向输入 data 内部） */
    int len;           /* 表达式长度（含 ${ 与 }） */
} Log4jHit;

/* 对 data[0..len) 扫描，识别出的查找表达式写入 hits（最多 cap 个），
 * 返回命中数。cls 分类与 antlr4 版 log4j_rules.g4 判定对齐：
 *   JNDI / SENSITIVE / CHAIN / EXPR（分类见 log4j_lookup.rl 注释）。 */
int log4j_scan(const char* data, size_t len, Log4jHit* hits, int cap);

#endif /* LOG4J_LOOKUP_H */
