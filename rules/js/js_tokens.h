/* ============================================================
 * js_tokens.h — JavaScript 词法 token 类型（对齐 ECMAScript 词法层）
 * ------------------------------------------------------------
 * 固定枚举值（显式赋值）：js_syntax.rl 的 Ragel 机器用数字字面量
 * 引用这些值，两者必须保持一致。
 *
 * 覆盖"最小关键字集 + 基本运算符"，词法层（js_tokens.rl）把文本
 * 切成 token 流，空白/注释/未知字符跳过。IDENT 同时承担标识符、
 * 属性名等角色，由语法层按位置区分。
 * ============================================================ */
#ifndef JS_TOKENS_H
#define JS_TOKENS_H

#include <stddef.h>

typedef enum {
    J_NONE = 0,
    /* 字面量 / 标识符 */
    J_NUMBER = 1, J_STRING = 2,
    J_TRUE = 3, J_FALSE = 4, J_NULL = 5, J_UNDEFINED = 6, J_IDENT = 7,
    /* 关键字（IDENT 运行时映射，大小写敏感） */
    J_VAR = 8, J_LET = 9, J_CONST = 10, J_FUNCTION = 11, J_RETURN = 12,
    J_IF = 13, J_ELSE = 14, J_WHILE = 15, J_FOR = 16,
    J_NEW = 17, J_TYPEOF = 18, J_VOID = 19, J_DELETE = 20, J_THIS = 21,
    /* 赋值 / 算术 */
    J_EQ = 22,
    J_PLUS = 23, J_MINUS = 24, J_STAR = 25, J_DIV = 26, J_MOD = 27, J_EXP = 28,
    /* 比较 / 相等 */
    J_EQEQ = 29, J_EQEQEQ = 30, J_NE = 31, J_NEEQ = 32,
    J_LT = 33, J_LE = 34, J_GT = 35, J_GE = 36,
    /* 逻辑 / 位 */
    J_AND = 37, J_OR = 38, J_NOT = 39, J_NULLISH = 40,
    J_AND_BIT = 41, J_OR_BIT = 42, J_XOR = 43, J_NOT_BIT = 44,
    J_SHL = 45, J_SHR = 46, J_SHRU = 47,
    /* 标点 */
    J_LPAREN = 48, J_RPAREN = 49, J_LBRACK = 50, J_RBRACK = 51,
    J_LBRACE = 52, J_RBRACE = 53, J_COMMA = 54, J_SEMI = 55,
    J_COLON = 56, J_DOT = 57, J_QUESTION = 58,
    J_EOF = 59
} JsTokType;

typedef struct {
    JsTokType type;   /* 指向输入缓冲区的文本区间 */
    const char* s;
    int len;
} JsTok;

/* 词法扫描：对 data[0..len) 做 JS 切分（空白/注释/未知字符跳过），
 * 结果写入 out（最多 cap 个），返回 token 数。 */
int lex_js(const char* data, size_t len, JsTok* out, int cap);

/* token 类型名（调试用） */
const char* js_tok_name(JsTokType t);

#endif /* JS_TOKENS_H */
