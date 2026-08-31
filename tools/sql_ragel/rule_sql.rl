/* ============================================================
 * rule_sql.rl — RuleSQL.g4 的 Ragel 移植（语法层 / token 级状态机）
 * ------------------------------------------------------------
 * 对应 rules/_shared/RuleSQL.g4 的匹配骨架：
 *   expr / or_expr / and_expr / not_expr / comparison / cmp_op /
 *   add_expr / add_op / mul_expr / mul_op / unary_expr / primary /
 *   expr_list / select_stmt / table_ref / constant_value
 *
 * 实现方式：Ragel 是字符级 DFA，这里把"token 类型"当作字母表
 * （8 位），在词法层输出的 token 数组上直接跑状态机。括号嵌套
 * 按深度展开（primaryN -> expr(N-1)），深度受 DFA 规模约束。
 * 三个顶层结构（expr / select_stmt / constant_value）各占一个
 * 独立 machine（避免 join 子集构造导致状态爆炸），每个 machine
 * 块内完整定义所需的深度链；run_*() 中用
 *   %%{ machine <name>; write exec; }%%
 * 显式绑定 exec 到对应 machine，避免默认展开到最后一个 machine。
 *
 * 语义谓词（isIdent / numbersEqual / stringsEqual /
 * constNumbersEqual / constStringsEqual）在 C 层实现，判定与
 * RuleSQL.g4 的 @parser::members 完全一致。
 *
 * 生成：ragel -C -o rule_sql.c rule_sql.rl
 * ============================================================ */

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sql_tokens.h"

/* ------------------------------------------------------------
 * 语义层：规则共享语义谓词（对齐 RuleSQL.g4 @parser::members）
 * ------------------------------------------------------------ */

static int ci_eq(const char* s, int len, const char* expected) {
    size_t elen = strlen(expected);
    if (len != (int)elen) return 0;
    for (size_t i = 0; i < elen; ++i) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)expected[i]))
            return 0;
    }
    return 1;
}

/* isIdent($i, "sleep") 等价 */
int sql_is_ident(const Token* t, const char* expected) {
    return t && t->type == T_IDENT && ci_eq(t->s, t->len, expected);
}

/* canonicalNumber 等价：strtod -> %.17g；解析失败原样返回 */
static char* canonical_number(const Token* t, char* buf, size_t cap) {
    char raw[128];
    size_t l = (size_t)t->len;
    if (l >= sizeof(raw)) l = sizeof(raw) - 1;
    memcpy(raw, t->s, l);
    raw[l] = '\0';
    char* end = NULL;
    double v = strtod(raw, &end);
    if (end == raw || *end != '\0') {
        size_t n = l;
        if (n >= cap) n = cap - 1;
        memcpy(buf, raw, n);
        buf[n] = '\0';
        return buf;
    }
    snprintf(buf, cap, "%.17g", v);
    return buf;
}

/* numbersEqual 等价：1=1 / 2=2 / 1=1.0 命中，1=2 不命中 */
int sql_numbers_equal(const Token* a, const Token* b) {
    char ba[64], bb[64];
    return strcmp(canonical_number(a, ba, sizeof(ba)),
                  canonical_number(b, bb, sizeof(bb))) == 0;
}

static char* unquote(const Token* t, char* buf, size_t cap) {
    size_t l = (size_t)t->len;
    if (l >= 2 && t->s[0] == '\'' && t->s[l - 1] == '\'') {
        l -= 2;
        if (l >= cap) l = cap - 1;
        memcpy(buf, t->s + 1, l);
        buf[l] = '\0';
        return buf;
    }
    if (l >= cap) l = cap - 1;
    memcpy(buf, t->s, l);
    buf[l] = '\0';
    return buf;
}

/* stringsEqual 等价：'a'='a' 命中（内容比较，剥引号） */
int sql_strings_equal(const Token* a, const Token* b) {
    char ba[256], bb[256];
    return strcmp(unquote(a, ba, sizeof(ba)), unquote(b, bb, sizeof(bb))) == 0;
}

/* 区间 [s,e) 内查找指定类型 token（constant_value 可含任意层括号） */
static const Token* find_in_range(const Token* tk, int s, int e, TokType ty) {
    for (int i = s; i < e; ++i) {
        if (tk[i].type == ty) return &tk[i];
    }
    return NULL;
}

/* constNumbersEqual / constStringsEqual 等价：
 * 两侧 constant_value 区间内取 NUMBER / STRING 做规范化比较 */
int sql_const_numbers_equal(const Token* tk, int s0, int e0, int s1, int e1) {
    const Token* a = find_in_range(tk, s0, e0, T_NUMBER);
    const Token* b = find_in_range(tk, s1, e1, T_NUMBER);
    return a && b && sql_numbers_equal(a, b);
}

int sql_const_strings_equal(const Token* tk, int s0, int e0, int s1, int e1) {
    const Token* a = find_in_range(tk, s0, e0, T_STRING);
    const Token* b = find_in_range(tk, s1, e1, T_STRING);
    return a && b && sql_strings_equal(a, b);
}

/* ------------------------------------------------------------
 * Ragel token 级状态机：三个独立入口机器（expr / select / const），
 * 状态图。action note_* 记录匹配区间：
 * p 指向最后一个消费 token，len = p - start + 1。
 * ------------------------------------------------------------ */

%%{
    machine rule_expr;
        NUMBER = 1;  STRING = 2;  TRUE = 3;   FALSE = 4;  NULL = 5;  IDENT = 6;
    SELECT = 7;  UNION = 8;   ALL = 9;    FROM = 10;  WHERE = 11; ORDER = 12;
    BY = 13;     LIMIT = 14;  OFFSET = 15; INSERT = 16; INTO = 17; VALUES = 18;
    UPDATE = 19; SET = 20;    DELETE = 21; DROP = 22;  ALTER = 23; CREATE = 24;
    EXISTS = 25; IN = 26;     LIKE = 27;  BETWEEN = 28; IS = 29;  NOT = 30;
    AND = 31;    OR = 32;     ASC = 33;   DESC = 34;
    EQ = 35;     NE = 36;     LE = 37;    GE = 38;    LT = 39;    GT = 40;
    PLUS = 41;   MINUS = 42;  STAR = 43;  DIV = 44;   MOD = 45;   PIPE2 = 46;
    LPAREN = 47; RPAREN = 48; COMMA = 49; SEMI = 50;

        cmp_op = EQ | NE | LE | GE | LT | GT;
    add_op = PLUS | MINUS | PIPE2;
    mul_op = STAR | DIV | MOD;

    # ---- 深度 0 ----
    primary0 = NUMBER | STRING | TRUE | FALSE | NULL | IDENT;
    unary0   = ( PLUS | MINUS )* primary0;
    mul0     = unary0 ( mul_op unary0 )*;
    add0     = mul0 ( add_op mul0 )*;
    comparison0 = add0 ( cmp_op add0 )?;
    not0     = NOT* comparison0;
    and0     = not0 ( AND not0 )*;
    or0      = and0 ( OR and0 )*;
    expr0    = or0;
    expr_list0 = expr0 ( COMMA expr0 )*;
    # ---- 深度 1 ----
    primary1 = NUMBER | STRING | TRUE | FALSE | NULL
             | IDENT ( LPAREN expr_list0? RPAREN )?
             | LPAREN expr0 RPAREN;
    unary1   = ( PLUS | MINUS )* primary1;
    mul1     = unary1 ( mul_op unary1 )*;
    add1     = mul1 ( add_op mul1 )*;
    comparison1 = add1 ( cmp_op add1 )?;
    not1     = NOT* comparison1;
    and1     = not1 ( AND not1 )*;
    or1      = and1 ( OR and1 )*;
    expr1    = or1;
    expr_list1 = expr1 ( COMMA expr1 )*;
    # ---- 深度 2 ----
    primary2 = NUMBER | STRING | TRUE | FALSE | NULL
             | IDENT ( LPAREN expr_list1? RPAREN )?
             | LPAREN expr1 RPAREN;
    unary2   = ( PLUS | MINUS )* primary2;
    mul2     = unary2 ( mul_op unary2 )*;
    add2     = mul2 ( add_op mul2 )*;
    comparison2 = add2 ( cmp_op add2 )?;
    not2     = NOT* comparison2;
    and2     = not2 ( AND not2 )*;
    or2      = and2 ( OR and2 )*;
    expr2    = or2;
    expr_list2 = expr2 ( COMMA expr2 )*;
    action note_expr { match_len = (int)(p - types) + 1 - start; }
    main := expr2 @note_expr;
    write data noerror nofinal noentry;
}%%

%%{
    machine rule_select;
        NUMBER = 1;  STRING = 2;  TRUE = 3;   FALSE = 4;  NULL = 5;  IDENT = 6;
    SELECT = 7;  UNION = 8;   ALL = 9;    FROM = 10;  WHERE = 11; ORDER = 12;
    BY = 13;     LIMIT = 14;  OFFSET = 15; INSERT = 16; INTO = 17; VALUES = 18;
    UPDATE = 19; SET = 20;    DELETE = 21; DROP = 22;  ALTER = 23; CREATE = 24;
    EXISTS = 25; IN = 26;     LIKE = 27;  BETWEEN = 28; IS = 29;  NOT = 30;
    AND = 31;    OR = 32;     ASC = 33;   DESC = 34;
    EQ = 35;     NE = 36;     LE = 37;    GE = 38;    LT = 39;    GT = 40;
    PLUS = 41;   MINUS = 42;  STAR = 43;  DIV = 44;   MOD = 45;   PIPE2 = 46;
    LPAREN = 47; RPAREN = 48; COMMA = 49; SEMI = 50;

        cmp_op = EQ | NE | LE | GE | LT | GT;
    add_op = PLUS | MINUS | PIPE2;
    mul_op = STAR | DIV | MOD;

    # ---- 深度 0 ----
    primary0 = NUMBER | STRING | TRUE | FALSE | NULL | IDENT;
    unary0   = ( PLUS | MINUS )* primary0;
    mul0     = unary0 ( mul_op unary0 )*;
    add0     = mul0 ( add_op mul0 )*;
    comparison0 = add0 ( cmp_op add0 )?;
    not0     = NOT* comparison0;
    and0     = not0 ( AND not0 )*;
    or0      = and0 ( OR and0 )*;
    expr0    = or0;
    expr_list0 = expr0 ( COMMA expr0 )*;
    # ---- 深度 1 ----
    primary1 = NUMBER | STRING | TRUE | FALSE | NULL
             | IDENT ( LPAREN expr_list0? RPAREN )?
             | LPAREN expr0 RPAREN;
    unary1   = ( PLUS | MINUS )* primary1;
    mul1     = unary1 ( mul_op unary1 )*;
    add1     = mul1 ( add_op mul1 )*;
    comparison1 = add1 ( cmp_op add1 )?;
    not1     = NOT* comparison1;
    and1     = not1 ( AND not1 )*;
    or1      = and1 ( OR and1 )*;
    expr1    = or1;
    expr_list1 = expr1 ( COMMA expr1 )*;
        # ---- 最小 SELECT 形状（省略子查询递归 table_ref；WHERE/子句内嵌
    # 2 层表达式。ANTLR 版支持任意深子查询，此处为控制 DFA 规模
    # 做了限制，可按需展开恢复）----
    select_stmt = SELECT ( STAR | expr_list1 )
                  ( FROM IDENT )?
                  ( WHERE expr1 )?;
    action note_select { match_len = (int)(p - types) + 1 - start; }
    main := select_stmt @note_select;
    write data noerror nofinal noentry;
}%%

%%{
    machine rule_const;
        NUMBER = 1;  STRING = 2;  TRUE = 3;   FALSE = 4;  NULL = 5;  IDENT = 6;
    SELECT = 7;  UNION = 8;   ALL = 9;    FROM = 10;  WHERE = 11; ORDER = 12;
    BY = 13;     LIMIT = 14;  OFFSET = 15; INSERT = 16; INTO = 17; VALUES = 18;
    UPDATE = 19; SET = 20;    DELETE = 21; DROP = 22;  ALTER = 23; CREATE = 24;
    EXISTS = 25; IN = 26;     LIKE = 27;  BETWEEN = 28; IS = 29;  NOT = 30;
    AND = 31;    OR = 32;     ASC = 33;   DESC = 34;
    EQ = 35;     NE = 36;     LE = 37;    GE = 38;    LT = 39;    GT = 40;
    PLUS = 41;   MINUS = 42;  STAR = 43;  DIV = 44;   MOD = 45;   PIPE2 = 46;
    LPAREN = 47; RPAREN = 48; COMMA = 49; SEMI = 50;

        cmp_op = EQ | NE | LE | GE | LT | GT;
    add_op = PLUS | MINUS | PIPE2;
    mul_op = STAR | DIV | MOD;

        # ---- 常量值：字面量或任意层括号包裹 ----
    constant_value0 = NUMBER | STRING | TRUE | FALSE | NULL;
    constant_value1 = NUMBER | STRING | TRUE | FALSE | NULL
                    | LPAREN constant_value0 RPAREN;
    constant_value2 = NUMBER | STRING | TRUE | FALSE | NULL
                    | LPAREN constant_value1 RPAREN;
    action note_const { match_len = (int)(p - types) + 1 - start; }
    main := constant_value2 @note_const;
    write data noerror nofinal noentry;
}%%
static int run_expr(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = rule_expr_start;
    int match_len = 0;

    %%{
        machine rule_expr;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}
static int run_select(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = rule_select_start;
    int match_len = 0;

    %%{
        machine rule_select;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}
static int run_const(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = rule_const_start;
    int match_len = 0;

    %%{
        machine rule_const;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}

int sql_match_expr(const int* types, int n, int start, int* len) {
    return run_expr(types, n, start, len);
}

int sql_match_select(const int* types, int n, int start, int* len) {
    return run_select(types, n, start, len);
}

int sql_match_const(const int* types, int n, int start, int* len) {
    return run_const(types, n, start, len);
}
