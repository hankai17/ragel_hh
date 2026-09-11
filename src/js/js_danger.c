/* ============================================================
 * js_danger.c — JS 危险调用检测（供 html5_xss 属性值语义分析）
 * ------------------------------------------------------------
 * 用 lex_js 切 token，检测危险调用，两阶段：
 *
 * 第一阶段（危险标识符）：危险名作为 IDENT 出现，且处于调用或
 *   成员访问上下文（后跟 ( / . / [，或前接 .）：
 *     alert(1)  eval(x)  document.cookie  String.fromCharCode(...)
 *
 * 第二阶段（最简单案例——字符串属性访问）：危险名藏在字符串里，
 *   通过方括号访问（jsfuck 的中间态）：
 *     a["constructor"]["constructor"]("alert(1)")()
 *     window["eval"]("alert(1)")
 *
 * 这是「比 libinjection 更强」的一层：libinjection 只认
 * javascript:/on* 这些固定字符串，这里能看透属性值里的 JS 语义。
 * ============================================================ */

#include <ctype.h>
#include <string.h>

#include "js_tokens.h"
#include "js_danger.h"

/* 危险标识符（危险函数 / 危险对象 / 危险属性，统一集合） */
static const char* DANGEROUS_IDENTS[] = {
    /* 危险函数 */
    "alert", "eval", "prompt", "confirm", "atob", "btoa",
    "fetch", "open", "setTimeout", "setInterval", "Function",
    /* 危险对象 */
    "document", "window", "self", "top", "parent", "globalThis",
    /* 危险属性 */
    "cookie", "write", "writeln", "innerHTML", "outerHTML",
    "fromCharCode", "domain", "location", "constructor",
    /* 危险构造 */
    "XMLHttpRequest", "ActiveXObject",
    NULL
};

/* 大小写不敏感的完整匹配 */
static int ci_eq(const char* s, int len, const char* pat) {
    if ((int)strlen(pat) != len) return 0;
    for (int i = 0; i < len; ++i) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)pat[i])) return 0;
    }
    return 1;
}

static int ci_in_list(const char* s, int len) {
    for (int i = 0; DANGEROUS_IDENTS[i]; ++i) {
        if (ci_eq(s, len, DANGEROUS_IDENTS[i])) return 1;
    }
    return 0;
}

/* 字符串内容（跳过首尾引号）是否是危险名。
 * 比对前先还原 JS 字符串转义：a["\u0065val"] 与 a["eval"] 等价。 */
static int dangerous_str(const char* s, int len) {
    char buf[128];
    int dlen;
    const char* d;
    if (len < 2) return 0;
    d = js_decode_string(s, len, buf, (int)sizeof(buf), &dlen);
    return ci_in_list(d, dlen);
}

int js_is_dangerous(const char* code, int len) {
    JsTok toks[256];
    int n = lex_js(code, (size_t)len, toks, 256);

    for (int i = 0; i < n; ++i) {
        /* 第一阶段：危险标识符 + 调用/成员访问上下文
         * 比对前先还原标识符里的 \u 转义：\u0061lert(1) 与 alert(1) 等价，
         * 不还原的话浏览器会执行、我们却看不见。 */
        if (toks[i].type == J_IDENT) {
            char ibuf[128];
            int ilen;
            const char* nm = js_decode_ident(toks[i].s, toks[i].len, ibuf,
                                             (int)sizeof(ibuf), &ilen);
            if (ci_in_list(nm, ilen)) {
                if (i + 1 < n && (toks[i + 1].type == J_LPAREN ||
                                  toks[i + 1].type == J_DOT ||
                                  toks[i + 1].type == J_LBRACK))
                    return 1;
                if (i > 0 && toks[i - 1].type == J_DOT)
                    return 1;
            }
        }
        /* 第二阶段：字符串属性访问 ["dangerous"] */
        if (toks[i].type == J_LBRACK && i + 2 < n &&
            toks[i + 1].type == J_STRING && toks[i + 2].type == J_RBRACK) {
            if (dangerous_str(toks[i + 1].s, toks[i + 1].len))
                return 1;
        }
    }
    return 0;
}
