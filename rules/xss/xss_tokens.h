/* ============================================================
 * xss_tokens.h — HTML 词法 token 类型与接口
 * ------------------------------------------------------------
 * 只输出 XSS 检测关心的 token：标签 / 属性 / 引号值 / 实体。
 * 空白与其余字符跳过。IDENT 同时承担标签名、属性名、裸值三种
 * 角色，由语法层按位置区分。
 * 固定枚举值：xss_shared.rl / xss_rules.rl 的 Ragel 机器用数字
 * 字面量引用这些值，两者必须保持一致。
 * ============================================================ */
#ifndef XSS_TOKENS_H
#define XSS_TOKENS_H

#include <stddef.h>

typedef enum {
    X_NONE = 0,
    X_LT = 1,      /* < */
    X_GT = 2,      /* > */
    X_SLASH = 3,   /* / */
    X_EQ = 4,      /* = */
    X_IDENT = 5,   /* 标签名 / 属性名 / 裸值 */
    X_STRING = 6,  /* 引号值 "..." 或 '...' */
    X_ENTITY = 7,  /* HTML 实体 &...; */
    X_EOF = 8
} XssTokType;

typedef struct {
    XssTokType type;   /* 指向输入缓冲区的文本区间 */
    const char* s;
    int len;
} XssTok;

/* 词法扫描：对 data[0..len) 做 HTML 结构切分（空白/无关字符跳过），
 * 结果写入 out（最多 cap 个），返回 token 数。 */
int lex_xss(const char* data, size_t len, XssTok* out, int cap);

/* token 类型名（调试用） */
const char* xss_tok_name(XssTokType t);

#endif /* XSS_TOKENS_H */
