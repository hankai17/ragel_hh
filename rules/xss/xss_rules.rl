/* ============================================================
 * xss_rules.rl — XSS 攻击防护规则（Ragel）
 * ------------------------------------------------------------
 * 5 条规则，每条对应一个独立机器入口：
 *   script_tag     <script ...>
 *   dangerous_tag  <iframe>/<object>/<embed>/<frame>/<svg>/<math>/<meta>
 *   event_handler  on* 事件属性（onerror/onload/...）
 *   js_uri         =javascript: / =vbscript: 危险 URI
 *   entity_lt      &#60; / &#x3c; / &lt; 实体编码的 <
 *
 * 复用 xss_shared.rl 的 token 编号与标签结构；命中用 %note
 * （leaving）记录长度，语义谓词在 C 层判定。
 *
 * 生成：ragel -C -o xss_rules.c xss_rules.rl
 * ============================================================ */

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "xss_tokens.h"

/* ------------------------------------------------------------
 * 语义谓词（C 层，供 ragel action 调用）
 * ------------------------------------------------------------ */

static int x_ci_eq(const char* s, int len, const char* expected) {
    size_t elen = strlen(expected);
    if (len != (int)elen) return 0;
    for (size_t i = 0; i < elen; ++i) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)expected[i]))
            return 0;
    }
    return 1;
}

/* 前缀比较（大小写不敏感） */
static int x_ci_prefix(const char* s, int len, const char* prefix) {
    size_t plen = strlen(prefix);
    if (len < (int)plen) return 0;
    for (size_t i = 0; i < plen; ++i) {
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)prefix[i]))
            return 0;
    }
    return 1;
}

/* IDENT 等于指定标签名（大小写不敏感） */
int xss_is_tag(const XssTok* t, const char* expected) {
    return t && t->type == X_IDENT && x_ci_eq(t->s, t->len, expected);
}

/* IDENT 是危险标签 */
int xss_is_dangerous(const XssTok* t) {
    static const char* set[] = {"iframe", "object", "embed", "frame",
                                "svg", "math", "meta"};
    if (!t || t->type != X_IDENT) return 0;
    for (size_t i = 0; i < sizeof(set) / sizeof(set[0]); ++i)
        if (x_ci_eq(t->s, t->len, set[i])) return 1;
    return 0;
}

/* IDENT 是事件处理器属性（on 开头且长度 > 2） */
int xss_is_event(const XssTok* t) {
    if (!t || t->type != X_IDENT || t->len <= 2) return 0;
    return tolower((unsigned char)t->s[0]) == 'o' &&
           tolower((unsigned char)t->s[1]) == 'n';
}

/* STRING 是 javascript: / vbscript: URI（剥引号，大小写不敏感） */
int xss_is_js_uri(const XssTok* t) {
    if (!t || t->type != X_STRING) return 0;
    const char* s = t->s;
    int len = t->len;
    if (len >= 2 && (s[0] == '"' || s[0] == '\'') && s[len - 1] == s[0]) {
        s++;
        len -= 2;
    }
    return x_ci_prefix(s, len, "javascript:") || x_ci_prefix(s, len, "vbscript:");
}

/* ENTITY 是 < 的编码（&lt; / &#60; / &#x3c;） */
int xss_is_lt_entity(const XssTok* t) {
    if (!t || t->type != X_ENTITY) return 0;
    if (x_ci_eq(t->s, t->len, "&lt;")) return 1;
    if (t->len >= 4 && t->s[0] == '&' && t->s[1] == '#') {
        const char* p = t->s + 2;
        int base = 10;
        if (*p == 'x' || *p == 'X') { base = 16; p++; }
        char buf[32];
        int k = 0;
        while (k < 31 && *p && *p != ';') buf[k++] = *p++;
        buf[k] = '\0';
        char* end = NULL;
        long v = strtol(buf, &end, base);
        if (end != buf && v == 60) return 1;
    }
    return 0;
}

%%{
    machine xss;
    include xss_shared "xss_shared.rl";

    action note { match_len = (int)(p - types) - start; }
    action is_script    { if (!xss_is_tag(&tk[(int)(p - types)], "script"))
                              { cs = 0; goto _out; } }
    action is_dangerous { if (!xss_is_dangerous(&tk[(int)(p - types)]))
                              { cs = 0; goto _out; } }
    action is_event     { if (!xss_is_event(&tk[(int)(p - types)]))
                              { cs = 0; goto _out; } }
    action is_js_uri    { if (!xss_is_js_uri(&tk[(int)(p - types)]))
                              { cs = 0; goto _out; } }
    action is_lt_entity { if (!xss_is_lt_entity(&tk[(int)(p - types)]))
                              { cs = 0; goto _out; } }

    script_tag    := LT IDENT $is_script %note any*;
    dangerous_tag := LT IDENT $is_dangerous %note any*;
    event_handler := IDENT $is_event EQ %note any*;
    js_uri        := EQ STRING $is_js_uri %note any*;
    entity_lt     := ENTITY $is_lt_entity %note any*;

    write data noerror nofinal;
}%%

/* ------------------------------------------------------------
 * 运行期：一个通用 run（cs0 指定入口状态）+ 每个规则一个导出函数。
 * 谓词动作需要 XssTok 数组，故 tk 一并传入。
 * ------------------------------------------------------------ */
static int run_xss(const int* types, int n, int start, int cs0,
                   const XssTok* tk, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    const int* eof = pe;
    int cs = cs0;
    int match_len = 0;

    %%{
        machine xss;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}

/* ragel 为每个 `:=` 入口生成 xss_en_<name> 起始状态常量 */
#define XSS_ENTRY(name) \
    int xss_match_##name(const int* types, int n, int start, \
                         const XssTok* tk, int* len) { \
        return run_xss(types, n, start, xss_en_##name, tk, len); \
    }

XSS_ENTRY(script_tag)
XSS_ENTRY(dangerous_tag)
XSS_ENTRY(event_handler)
XSS_ENTRY(js_uri)
XSS_ENTRY(entity_lt)
