/* ============================================================
 * xss_tokens.rl — HTML 词法：文本 -> token 流
 * ------------------------------------------------------------
 * scanner 长匹配优先，逐 token 输出。空白与无关字符跳过。
 *
 * 生成：ragel -C -o xss_tokens.c xss_tokens.rl
 * ============================================================ */

#include <string.h>

#include "xss_tokens.h"

static XssTok* x_out;
static int x_cap;
static int x_n;

static void x_emit(XssTokType t, const char* s, int len) {
    if (x_n < x_cap) {
        x_out[x_n].type = t;
        x_out[x_n].s = s;
        x_out[x_n].len = len;
        x_n++;
    }
}

const char* xss_tok_name(XssTokType t) {
    switch (t) {
        case X_LT:     return "LT";
        case X_GT:     return "GT";
        case X_SLASH:  return "SLASH";
        case X_EQ:     return "EQ";
        case X_IDENT:  return "IDENT";
        case X_STRING: return "STRING";
        case X_ENTITY: return "ENTITY";
        default:       return "?";
    }
}

%%{
    machine xss_tokens;

    lt = '<';
    gt = '>';
    slash = '/';
    eq = '=';
    # HTML 注释：整体跳过，且可作为标识符内部成分被吞掉，
    # 从而还原注释拆标签名/属性名的绕过（<scr<!-- -->ipt> -> script）
    comment = '<!--' any* :>> '-->';
    ident = [a-zA-Z_] ( [a-zA-Z0-9_] | '-' | comment )*;
    dstring = '"' ( ( any - ( '"' | '\\' ) ) | ( '\\' any ) )* '"';
    sstring = '\'' ( ( any - ( '\'' | '\\' ) ) | ( '\\' any ) )* '\'';
    entity = '&' ( '#' [0-9]+ | '#x' [0-9a-fA-F]+ | [a-zA-Z]+ ) ';';

    main := |*
        comment => {};
        lt      => { x_emit(X_LT, ts, te - ts); };
        gt      => { x_emit(X_GT, ts, te - ts); };
        slash   => { x_emit(X_SLASH, ts, te - ts); };
        eq      => { x_emit(X_EQ, ts, te - ts); };
        entity  => { x_emit(X_ENTITY, ts, te - ts); };
        ident   => { x_emit(X_IDENT, ts, te - ts); };
        dstring => { x_emit(X_STRING, ts, te - ts); };
        sstring => { x_emit(X_STRING, ts, te - ts); };
        [ \t\r\n]+ => {};
        any     => {};
    *|;

    write data noerror nofinal noentry;
}%%

int lex_xss(const char* data, size_t len, XssTok* out, int cap) {
    const char* p = data;
    const char* pe = data + len;
    const char* eof = pe;
    int cs;
    const char* ts = 0;
    const char* te = 0;
    int act = 0;
    (void)act;

    x_out = out;
    x_cap = cap;
    x_n = 0;

    %% write init;
    %% write exec;

    return x_n;
}
