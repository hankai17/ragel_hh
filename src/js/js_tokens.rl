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
#include "utf8.h"

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

/* ------------------------------------------------------------
 * 标识符的 Unicode 转义还原
 * ------------------------------------------------------------
 * ES5/ES6 允许标识符里写 \uXXXX（ES6 另有 \u{XXXXXX}）：
 *   \u0061lert  ==  alert
 *   \u0076ar    ==  var
 * 浏览器先把转义还原再当标识符用，所以关键字/危险名比对前也必须还原，
 * 否则 onerror="\u0061lert(1)" 这类写法能绕过语义分析。
 * ------------------------------------------------------------ */
static int j_hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* 解析 \uXXXX 或 \u{XXXXXX} 形式的转义（p 指向反斜杠）。
 * 成功返回码点并令 *adv = 消耗字节数；不是合法转义返回 -1。
 * 标识符与字符串字面量的还原共用这一份。 */
static int j_parse_u_esc(const char* p, int len, int* adv) {
    int cp = -1, a = 0;

    if (len < 2 || p[0] != '\\' || p[1] != 'u') return -1;

    if (len > 2 && p[2] == '{') {          /* \u{XXXXXX}：花括号内任意位 */
        int j = 3, v = 0, any = 0;
        while (j < len && p[j] != '}') {
            int h = j_hex_val(p[j]);
            if (h < 0) break;
            v = (v << 4) | h;
            any = 1;
            ++j;
        }
        if (any && j < len && p[j] == '}') { cp = v; a = j + 1; }
    } else if (len >= 6) {                 /* \uXXXX：固定 4 位 */
        int k, v = 0, ok = 1;
        for (k = 0; k < 4; ++k) {
            int h = j_hex_val(p[2 + k]);
            if (h < 0) { ok = 0; break; }
            v = (v << 4) | h;
        }
        if (ok) { cp = v; a = 6; }
    }

    if (cp < 0 || cp > 0x10FFFF) return -1;
    *adv = a;
    return cp;
}

/* 还原标识符里的 \u 转义。无转义时直接返回 s（不拷贝）；有转义时写入
 * buf（cap 字节）并返回 buf。*out_len 为还原后的字节长度。 */
const char* js_decode_ident(const char* s, int len, char* buf, int cap, int* out_len) {
    int i, o = 0;

    /* 快速路径：没有反斜杠就不必动 */
    for (i = 0; i < len; ++i)
        if (s[i] == '\\') break;
    if (i == len) {
        *out_len = len;
        return s;
    }

    for (i = 0; i < len; ) {
        if (s[i] == '\\' && i + 1 < len && s[i + 1] == 'u') {
            int adv = 0;
            int cp = j_parse_u_esc(s + i, len - i, &adv);
            if (cp >= 0) {
                if (o + 4 >= cap) break;
                o += utf8_put(buf + o, cp);
                i += adv;
                continue;
            }
        }
        if (o + 1 >= cap) break;
        buf[o++] = s[i++];
    }
    buf[o] = '\0';
    *out_len = o;
    return buf;
}

/* 还原 JS 字符串字面量（含首尾引号）里的转义，输出不含引号的内容：
 *   "\u0065val"  -> eval
 *   "\x65val"    -> eval
 *   "a\\tb"      -> a<TAB>b
 * 覆盖 \uXXXX / \u{XXXXXX} / \xXX / \n \r \t \b \f \v \0 / 行继续 / \\ \' \" \/
 * 其余认不出的转义原样保留。无转义时直接返回内容区指针（不拷贝）；
 * 有转义时写入 buf（cap 字节）并返回 buf；*out_len 为还原后的长度。 */
const char* js_decode_string(const char* s, int len, char* buf, int cap, int* out_len) {
    const char* body;
    int blen, i, o = 0;

    if (len < 2) {
        *out_len = 0;
        return buf;
    }
    body = s + 1;                 /* 跳过开引号 */
    blen = len - 2;               /* 去掉两端引号 */

    /* 快速路径：内容里没有反斜杠就不必动 */
    for (i = 0; i < blen; ++i)
        if (body[i] == '\\') break;
    if (i == blen) {
        *out_len = blen;
        return body;
    }

    for (i = 0; i < blen; ) {
        int cp = -1, adv = 2, skip = 0;
        char e;

        if (body[i] != '\\' || i + 1 >= blen) {
            if (o + 1 >= cap) break;
            buf[o++] = body[i++];
            continue;
        }

        e = body[i + 1];
        switch (e) {
            case 'n': cp = 0x0A; break;
            case 'r': cp = 0x0D; break;
            case 't': cp = 0x09; break;
            case 'b': cp = 0x08; break;
            case 'f': cp = 0x0C; break;
            case 'v': cp = 0x0B; break;
            case '0': cp = 0x00; break;
            case 'x': {
                if (i + 4 <= blen) {
                    int h1 = j_hex_val(body[i + 2]);
                    int h2 = j_hex_val(body[i + 3]);
                    if (h1 >= 0 && h2 >= 0) { cp = (h1 << 4) | h2; adv = 4; }
                }
                break;
            }
            case 'u': {
                int a = 0;
                int v = j_parse_u_esc(body + i, blen - i, &a);
                if (v >= 0) { cp = v; adv = a; }
                break;
            }
            case '\r':                     /* 行继续：不产出字符 */
                skip = 1;
                if (i + 2 < blen && body[i + 2] == '\n') adv = 3;
                break;
            case '\n':
                skip = 1;
                break;
            default:                       /* \\ \' \" \/ 等 */
                cp = (unsigned char)e;
                break;
        }

        if (skip) { i += adv; continue; }
        if (cp >= 0 && cp <= 0x10FFFF) {
            if (o + 4 >= cap) break;
            o += utf8_put(buf + o, cp);
        } else {                           /* 认不出的转义：原样保留 */
            if (o + 2 >= cap) break;
            buf[o++] = body[i];
            buf[o++] = body[i + 1];
        }
        i += adv;
    }
    buf[o] = '\0';
    *out_len = o;
    return buf;
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
    char buf[32];
    int dlen;
    const char* d = js_decode_ident(s, len, buf, (int)sizeof(buf), &dlen);
    for (size_t i = 0; i < sizeof(map) / sizeof(map[0]); ++i) {
        if (dlen == (int)strlen(map[i].kw) &&
            strncmp(d, map[i].kw, (size_t)dlen) == 0)
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
    # 标识符：允许 ES5/ES6 的 \uXXXX / \u{XXXXXX} 转义（\u0061lert == alert），
    # 原始文本（含反斜杠）完整保留成一个 token，还原交给 js_decode_ident。
    hex   = [0-9a-fA-F];
    hex4  = hex hex hex hex;
    uesc  = '\\u' hex4 | '\\u{' hex+ '}';
    ident = ( [a-zA-Z_$] | uesc ) ( [a-zA-Z0-9_$] | uesc )*;

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
