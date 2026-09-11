/* ============================================================
 * sql_tokens.rl — SQLTokens.g4 的 Ragel 移植（词法层）
 * ------------------------------------------------------------
 * 对应 rules/_shared/SQLTokens.g4：
 *   * 关键字大小写不敏感（IDENT 运行时映射）
 *   * 引号容错：字面量风格 -> STRING，否则引号跳过（QUOTE 通道）
 *   * 注释 / 空白 / 未知字符跳过，词法永不失败
 *
 * Ragel 状态机（语法层）识别 token 形状；C 动作（语义层）做
 * 关键字映射与 literalLikeAhead 引号判定，动作将 token 写入
 * 调用方数组。与 ANTLR 版的差异仅在于实现载体（DFA vs LL(*)），
 * 输出 token 序列与 SQLTokens.g4 一致。
 *
 * 生成：ragel -C -o sql_tokens.c sql_tokens.rl
 * ============================================================ */

#include <ctype.h>
#include <string.h>

#include "sql_tokens.h"

/* ------------------------------------------------------------
 * 语义层：关键字映射 / 引号容错 / token 收集
 * ------------------------------------------------------------ */

/* 大小写不敏感关键字 -> 类型；非关键字返回 T_IDENT */
static TokType keyword_type(const char* s, int len) {
    static const struct { const char* kw; TokType t; } map[] = {
        {"select", T_SELECT}, {"union", T_UNION}, {"all", T_ALL},
        {"from", T_FROM}, {"where", T_WHERE}, {"order", T_ORDER}, {"by", T_BY},
        {"limit", T_LIMIT}, {"offset", T_OFFSET},
        {"insert", T_INSERT}, {"into", T_INTO}, {"values", T_VALUES},
        {"update", T_UPDATE}, {"set", T_SET},
        {"delete", T_DELETE}, {"drop", T_DROP}, {"alter", T_ALTER}, {"create", T_CREATE},
        {"exists", T_EXISTS}, {"in", T_IN}, {"like", T_LIKE},
        {"between", T_BETWEEN}, {"is", T_IS}, {"not", T_NOT},
        {"and", T_AND}, {"or", T_OR},
        {"null", T_NULL}, {"true", T_TRUE}, {"false", T_FALSE},
        {"asc", T_ASC}, {"desc", T_DESC},
    };
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); ++i) {
        if (len != (int)strlen(map[i].kw)) continue;
        size_t k = 0;
        for (; k < (size_t)len; ++k) {
            if (tolower((unsigned char)s[k]) != map[i].kw[k]) break;
        }
        if (k == (size_t)len) return map[i].t;
    }
    return T_IDENT;
}

/* literalLikeAhead 等价实现：引号内容含空白/操作符等"结构字符"
 * 则视为分隔引号（% 与 / 常见于 LIKE 模式与路径字符串，不算） */
static int literal_like(const char* s, int len) {
    static const char structural[] = " \t\n\r=<>!()+-*,;|&~";
    for (int i = 0; i < len; ++i) {
        if (strchr(structural, s[i])) return 0;
    }
    return 1;
}

static Token* tok_out;
static int tok_cap;
static int tok_n;

static void emit(TokType t, const char* s, int len) {
    if (tok_n < tok_cap) {
        tok_out[tok_n].type = t;
        tok_out[tok_n].s = s;
        tok_out[tok_n].len = len;
        tok_n++;
    }
}

const char* tok_name(TokType t) {
    switch (t) {
        case T_NUMBER:  return "NUMBER";
        case T_STRING:  return "STRING";
        case T_TRUE:    return "TRUE";
        case T_FALSE:   return "FALSE";
        case T_NULL:    return "NULL";
        case T_IDENT:   return "IDENT";
        case T_SELECT:  return "SELECT";
        case T_UNION:   return "UNION";
        case T_ALL:     return "ALL";
        case T_FROM:    return "FROM";
        case T_WHERE:   return "WHERE";
        case T_ORDER:   return "ORDER";
        case T_BY:      return "BY";
        case T_LIMIT:   return "LIMIT";
        case T_OFFSET:  return "OFFSET";
        case T_INSERT:  return "INSERT";
        case T_INTO:    return "INTO";
        case T_VALUES:  return "VALUES";
        case T_UPDATE:  return "UPDATE";
        case T_SET:     return "SET";
        case T_DELETE:  return "DELETE";
        case T_DROP:    return "DROP";
        case T_ALTER:   return "ALTER";
        case T_CREATE:  return "CREATE";
        case T_EXISTS:  return "EXISTS";
        case T_IN:      return "IN";
        case T_LIKE:    return "LIKE";
        case T_BETWEEN: return "BETWEEN";
        case T_IS:      return "IS";
        case T_NOT:     return "NOT";
        case T_AND:     return "AND";
        case T_OR:      return "OR";
        case T_ASC:     return "ASC";
        case T_DESC:    return "DESC";
        case T_EQ:      return "EQ";
        case T_NE:      return "NE";
        case T_LE:      return "LE";
        case T_GE:      return "GE";
        case T_LT:      return "LT";
        case T_GT:      return "GT";
        case T_PLUS:    return "PLUS";
        case T_MINUS:   return "MINUS";
        case T_STAR:    return "STAR";
        case T_DIV:     return "DIV";
        case T_MOD:     return "MOD";
        case T_PIPE2:   return "PIPE2";
        case T_LPAREN:  return "LPAREN";
        case T_RPAREN:  return "RPAREN";
        case T_COMMA:   return "COMMA";
        case T_SEMI:    return "SEMI";
        default:        return "?";
    }
}

/* ------------------------------------------------------------
 * Ragel 词法扫描器（scanner：长匹配优先，逐 token 输出）
 * ------------------------------------------------------------ */

%%{
    machine sql_tokens;

    # 数字：DIGIT+ ('.' DIGIT+)?（1. 不匹配，. 走 UNKNOWN 跳过）
    number = [0-9]+ ('.' [0-9]+)?;

    # 引号段：'...'（不含换行/引号）。ANTLR 为 lazy，这里 [^'] 已保证
    # 停在第一个闭合引号，两者一致。闭合后由 action 判 literal_like：
    #   字面量风格 -> STRING；否则 -> 悬空/分隔引号，跳过引号本身
    #   并把扫描位置回退到 ts+1 重新扫描（等价 QUOTE -> HIDDEN）。
    quoted = '\'' ( any - ( '\'' | '\n' | '\r' ) )* '\'';

    ident  = [a-zA-Z_] [a-zA-Z0-9_]*;

    main := |*
        number                  => { emit(T_NUMBER, ts, te - ts); };
        quoted                  => {
            int clen = (int)(te - ts) - 2;
            if (literal_like(ts + 1, clen)) {
                emit(T_STRING, ts, te - ts);
            } else {
                /* 分隔/悬空引号：只跳过引号本身，内容重新扫描 */
                p = ts + 1;
                fgoto main;
            }
        };
        ident                   => { emit(keyword_type(ts, te - ts), ts, te - ts); };
        '||'                    => { emit(T_PIPE2, ts, 2); };
        '!=' | '<>'             => { emit(T_NE, ts, 2); };
        '<='                    => { emit(T_LE, ts, 2); };
        '>='                    => { emit(T_GE, ts, 2); };
        '='                     => { emit(T_EQ, ts, 1); };
        '<'                     => { emit(T_LT, ts, 1); };
        '>'                     => { emit(T_GT, ts, 1); };
        '+'                     => { emit(T_PLUS, ts, 1); };
        '-'                     => { emit(T_MINUS, ts, 1); };
        '*'                     => { emit(T_STAR, ts, 1); };
        '/'                     => { emit(T_DIV, ts, 1); };
        '%'                     => { emit(T_MOD, ts, 1); };
        '('                     => { emit(T_LPAREN, ts, 1); };
        ')'                     => { emit(T_RPAREN, ts, 1); };
        ','                     => { emit(T_COMMA, ts, 1); };
        ';'                     => { emit(T_SEMI, ts, 1); };
        # 注释 / 空白：跳过
        ( '--' [^\r\n]* | '#' [^\r\n]* ) => {};
        '/*' any* :>> '*/'      => {};
        [ \t\r\n]+              => {};
        # 未知字符容错跳过，词法永不失败
        any                     => {};
    *|;

    write data noerror nofinal noentry;
}%%

/* ------------------------------------------------------------
 * 词法入口
 * ------------------------------------------------------------ */

int lex_sql(const char* data, size_t len, Token* out, int cap) {
    const char* p = data;
    const char* pe = data + len;
    const char* eof = pe;
    int cs;
    /* scanner 模式：ts/te/act 需调用方声明（本词法规则互斥、无优先级
     * 消歧，act 由生成的扫描代码维护但不会被读取） */
    const char* ts = 0;
    const char* te = 0;
    int act = 0;
    (void)act;

    tok_out = out;
    tok_cap = cap;
    tok_n = 0;

    %% write init;
    %% write exec;

    return tok_n;
}
