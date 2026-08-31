/* ============================================================
 * sql_tokens.h — 共享 token 类型（对应 rules/_shared/SQLTokens.g4
 * 的 tokens{...} 声明 + 词法输出结构）
 * ------------------------------------------------------------
 * 固定枚举值（显式赋值）：rule_sql.rl 的 Ragel 机器用数字字面量
 * 引用这些值，两者必须保持一致。
 * ============================================================ */
#ifndef SQL_TOKENS_H
#define SQL_TOKENS_H

#include <stddef.h>

typedef enum {
    T_NONE = 0,
    /* 字面量 / 标识符 */
    T_NUMBER = 1, T_STRING = 2, T_TRUE = 3, T_FALSE = 4, T_NULL = 5, T_IDENT = 6,
    /* 关键字（IDENT 运行时映射，大小写不敏感） */
    T_SELECT = 7, T_UNION = 8, T_ALL = 9, T_FROM = 10, T_WHERE = 11,
    T_ORDER = 12, T_BY = 13, T_LIMIT = 14, T_OFFSET = 15,
    T_INSERT = 16, T_INTO = 17, T_VALUES = 18, T_UPDATE = 19, T_SET = 20,
    T_DELETE = 21, T_DROP = 22, T_ALTER = 23, T_CREATE = 24,
    T_EXISTS = 25, T_IN = 26, T_LIKE = 27, T_BETWEEN = 28,
    T_IS = 29, T_NOT = 30, T_AND = 31, T_OR = 32, T_ASC = 33, T_DESC = 34,
    /* 操作符 */
    T_EQ = 35, T_NE = 36, T_LE = 37, T_GE = 38, T_LT = 39, T_GT = 40,
    T_PLUS = 41, T_MINUS = 42, T_STAR = 43, T_DIV = 44, T_MOD = 45, T_PIPE2 = 46,
    T_LPAREN = 47, T_RPAREN = 48, T_COMMA = 49, T_SEMI = 50,
    T_EOF = 51
} TokType;

typedef struct {
    TokType type;   /* 指向输入缓冲区的文本区间 */
    const char* s;
    int len;
} Token;

/* 词法扫描：对 data[0..len) 做 SQLTokens 式切分（注释/空白/未知跳过，
 * 悬空引号跳过），结果写入 out（最多 cap 个），返回 token 数。 */
int lex_sql(const char* data, size_t len, Token* out, int cap);

/* token 类型名（调试用） */
const char* tok_name(TokType t);

#endif /* SQL_TOKENS_H */
