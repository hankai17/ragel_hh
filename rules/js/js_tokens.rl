/* ============================================================
 * js_tokens.rl — JavaScript 词法：文本 -> token 流
 * ------------------------------------------------------------
 * scanner 长匹配优先，逐 token 输出。空白/注释/未知字符跳过。
 *
 * 关键字大小写敏感（JS 语义），字面量 true/false/null/undefined
 * 一并映射；数字覆盖十进制整数/浮点/科学计数法；字符串覆盖
 * 单/双引号及反斜杠转义。
 *
 * 生成：ragel -C -o js_tokens.c js_tokens.rl
 * ============================================================ */

#include <string.h>

#include "js_tokens.h"

static JsTok* j_out;
static int j_cap;
static int j_n;

static void j_emit(JsTokType t, const char* s, int len) {
    if (j_n < j_cap) {
        j_out[j_n].type = t;
        j_out[j_n].s = s;
        j_out[j_n].len = len;
        j_n++;
    }
}

const char* js_tok_name(JsTokType t) {
    switch (t) {
        case J_NUMBER:    return "NUMBER";
        case J_STRING:    return "STRING";
        case J_TRUE:      return "TRUE";
        case J_FALSE:     return "FALSE";
        case J_NULL:      return "NULL";
        case J_UNDEFINED: return "UNDEFINED";
        case J_IDENT:     return "IDENT";
        case J_VAR:       return "VAR";
        case J_LET:       return "LET";
        case J_CONST:     return "CONST";
        case J_FUNCTION:  return "FUNCTION";
        case J_RETURN:    return "RETURN";
        case J_IF:        return "IF";
        case J_ELSE:      return "ELSE";
        case J_WHILE:     return "WHILE";
        case J_FOR:       return "FOR";
        case J_NEW:       return "NEW";
        case J_TYPEOF:    return "TYPEOF";
        case J_VOID:      return "VOID";
        case J_DELETE:    return "DELETE";
        case J_THIS:      return "THIS";
        case J_EQ:        return "EQ";
        case J_PLUS:      return "PLUS";
        case J_MINUS:     return "MINUS";
        case J_STAR:      return "STAR";
        case J_DIV:       return "DIV";
        case J_MOD:       return "MOD";
        case J_EXP:       return "EXP";
        case J_EQEQ:      return "EQEQ";
        case J_EQEQEQ:    return "EQEQEQ";
        case J_NE:        return "NE";
        case J_NEEQ:      return "NEEQ";
        case J_LT:        return "LT";
        case J_LE:        return "LE";
        case J_GT:        return "GT";
        case J_GE:        return "GE";
        case J_AND:       return "AND";
        case J_OR:        return "OR";
        case J_NOT:       return "NOT";
        case J_NULLISH:   return "NULLISH";
        case J_AND_BIT:   return "AND_BIT";
        case J_OR_BIT:    return "OR_BIT";
        case J_XOR:       return "XOR";
        case J_NOT_BIT:   return "NOT_BIT";
        case J_SHL:       return "SHL";
        case J_SHR:       return "SHR";
        case J_SHRU:      return "SHRU";
        case J_LPAREN:    return "LPAREN";
        case J_RPAREN:    return "RPAREN";
        case J_LBRACK:    return "LBRACK";
        case J_RBRACK:    return "RBRACK";
        case J_LBRACE:    return "LBRACE";
        case J_RBRACE:    return "RBRACE";
        case J_COMMA:     return "COMMA";
        case J_SEMI:      return "SEMI";
        case J_COLON:     return "COLON";
        case J_DOT:       return "DOT";
        case J_QUESTION:  return "QUESTION";
        default:          return "?";
    }
}

/* 关键字 -> 类型（大小写敏感）；非关键字返回 J_IDENT */
static JsTokType keyword_type(const char* s, int len) {
    static const struct { const char* kw; JsTokType t; } map[] = {
        {"var", J_VAR}, {"let", J_LET}, {"const", J_CONST},
        {"function", J_FUNCTION}, {"return", J_RETURN},
        {"if", J_IF}, {"else", J_ELSE}, {"while", J_WHILE}, {"for", J_FOR},
        {"new", J_NEW}, {"typeof", J_TYPEOF}, {"void", J_VOID},
        {"delete", J_DELETE}, {"this", J_THIS},
        {"true", J_TRUE}, {"false", J_FALSE}, {"null", J_NULL},
        {"undefined", J_UNDEFINED},
    };
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); ++i) {
        if (len == (int)strlen(map[i].kw) &&
            strncmp(s, map[i].kw, (size_t)len) == 0)
            return map[i].t;
    }
    return J_IDENT;
}

%%{
    machine js_tokens;

    # 数字：十进制整数 / 浮点 / 科学计数法
    number = [0-9]+ ( '.' [0-9]+ )? ( [eE] [+\-]? [0-9]+ )?;
    # 字符串：单/双引号，反斜杠转义，不含裸换行
    dstring = '"' ( ( any - ( '"' | '\\' | '\n' | '\r' ) ) | ( '\\' any ) )* '"';
    sstring = '\'' ( ( any - ( '\'' | '\\' | '\n' | '\r' ) ) | ( '\\' any ) )* '\'';
    ident = [a-zA-Z_$] [a-zA-Z0-9_$]*;

    main := |*
        number  => { j_emit(J_NUMBER, ts, te - ts); };
        dstring => { j_emit(J_STRING, ts, te - ts); };
        sstring => { j_emit(J_STRING, ts, te - ts); };
        ident   => { j_emit(keyword_type(ts, te - ts), ts, te - ts); };
        '==='   => { j_emit(J_EQEQEQ, ts, 3); };
        '!=='   => { j_emit(J_NEEQ, ts, 3); };
        '>>>'   => { j_emit(J_SHRU, ts, 3); };
        '**'    => { j_emit(J_EXP, ts, 2); };
        '=='    => { j_emit(J_EQEQ, ts, 2); };
        '!='    => { j_emit(J_NE, ts, 2); };
        '<='    => { j_emit(J_LE, ts, 2); };
        '>='    => { j_emit(J_GE, ts, 2); };
        '&&'    => { j_emit(J_AND, ts, 2); };
        '||'    => { j_emit(J_OR, ts, 2); };
        '??'    => { j_emit(J_NULLISH, ts, 2); };
        '<<'    => { j_emit(J_SHL, ts, 2); };
        '>>'    => { j_emit(J_SHR, ts, 2); };
        '='     => { j_emit(J_EQ, ts, 1); };
        '+'     => { j_emit(J_PLUS, ts, 1); };
        '-'     => { j_emit(J_MINUS, ts, 1); };
        '*'     => { j_emit(J_STAR, ts, 1); };
        '/'     => { j_emit(J_DIV, ts, 1); };
        '%'     => { j_emit(J_MOD, ts, 1); };
        '<'     => { j_emit(J_LT, ts, 1); };
        '>'     => { j_emit(J_GT, ts, 1); };
        '!'     => { j_emit(J_NOT, ts, 1); };
        '&'     => { j_emit(J_AND_BIT, ts, 1); };
        '|'     => { j_emit(J_OR_BIT, ts, 1); };
        '^'     => { j_emit(J_XOR, ts, 1); };
        '~'     => { j_emit(J_NOT_BIT, ts, 1); };
        '?'     => { j_emit(J_QUESTION, ts, 1); };
        ':'     => { j_emit(J_COLON, ts, 1); };
        '.'     => { j_emit(J_DOT, ts, 1); };
        ','     => { j_emit(J_COMMA, ts, 1); };
        ';'     => { j_emit(J_SEMI, ts, 1); };
        '('     => { j_emit(J_LPAREN, ts, 1); };
        ')'     => { j_emit(J_RPAREN, ts, 1); };
        '['     => { j_emit(J_LBRACK, ts, 1); };
        ']'     => { j_emit(J_RBRACK, ts, 1); };
        '{'     => { j_emit(J_LBRACE, ts, 1); };
        '}'     => { j_emit(J_RBRACE, ts, 1); };
        # 注释 / 空白：跳过
        '//' [^\r\n]*      => {};
        '/*' any* :>> '*/' => {};
        [ \t\r\n]+         => {};
        # 未知字符容错跳过，词法永不失败
        any                 => {};
    *|;

    write data noerror nofinal noentry;
}%%

int lex_js(const char* data, size_t len, JsTok* out, int cap) {
    const char* p = data;
    const char* pe = data + len;
    const char* eof = pe;
    int cs;
    const char* ts = 0;
    const char* te = 0;
    int act = 0;
    (void)act;

    j_out = out;
    j_cap = cap;
    j_n = 0;

    %% write init;
    %% write exec;

    return j_n;
}
