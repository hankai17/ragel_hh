/* ============================================================
 * html5_xss_rules.rl — XSS 黑名单规则（对齐 libinjection_xss.c is_xss）
 * ------------------------------------------------------------
 * 输入：token 类型数组（lex_html5 产出，见 html5_tokens.h）。
 * 每条 <name> 规则 = 一个独立机器入口，驱动逐位置逐规则匹配，
 * 命中上报 [start, start+len) 的 token 区间。
 *
 * 规则语义（对齐 libinjection is_xss 主循环，精细化版）：
 *   black_tag         TAG_NAME_OPEN 标签名 ∈ 黑标签          -> 危险
 *   black_attr        ATTR_NAME 属性名 ∈ 黑属性（on* 等）      -> 危险
 *   black_url         ATTR_NAME(URI) + ATTR_VALUE(黑 URL)      -> 危险
 *   style_expr        ATTR_NAME(style/filter) + 值含 expression -> 危险
 *   dangerous_comment TAG_COMMENT 含反引号 / [if / xml / import -> 危险
 *   dangerous_js      ATTR_VALUE / SCRIPT_TEXT 含危险 JS 调用（语义）-> 危险
 *
 * 相对 libinjection 的两处"精细化"（不激进，避免误报）：
 *   1. DOCTYPE 不再直接判危险（正常页面都有 <!DOCTYPE html>）；
 *   2. STYLE/FILTER 属性不再"有值即危险"，只查值内 expression( /
 *      javascript: / vbscript: / -moz-binding。
 *
 * 相对 libinjection 的一处"暂不做"（解码留后续阶段）：
 *   is_black_url 不做 HTML 实体解码（&#106;ascript:）、不做字母间
 *   空白折叠（jav\tascript:）、不做 null 跳过；只跳过前导空白。
 *
 * 生成：ragel -C -o html5_xss_rules.c html5_xss_rules.rl
 * ============================================================ */

#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "html5_tokens.h"
#include "js_danger.h"

/* ------------------------------------------------------------
 * 语义层：黑名单数据 + 匹配谓词（C 层，供 Ragel 动作调用）
 * ------------------------------------------------------------ */

/* 大小写不敏感的完整匹配：s[0..len) 与 pattern 完全相等 */
static int ci_full_eq(const char* s, int len, const char* pattern) {
    for (int i = 0; i < len; ++i) {
        if (pattern[i] == '\0') return 0;
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)pattern[i])) return 0;
    }
    return pattern[len] == '\0';
}

/* 大小写不敏感的前缀匹配：s[0..len) 以 prefix 开头 */
static int ci_prefix(const char* s, int len, const char* prefix) {
    for (int i = 0; prefix[i]; ++i) {
        if (i >= len) return 0;
        if (tolower((unsigned char)s[i]) != tolower((unsigned char)prefix[i])) return 0;
    }
    return 1;
}

/* 黑标签（libinjection BLACKTAG）：本身即危险的标签 */
static const char* BLACK_TAGS[] = {
    "applet", "base", "comment", "embed", "frame", "frameset", "handler",
    "iframe", "import", "isindex", "link", "listener", "meta", "noscript",
    "object", "script", "style", "vmlframe", "xml", "xss", NULL
};

static int is_black_tag(const char* s, int len) {
    /* svg / xsl 前缀（libinjection：任意 SVG/XSL 相关标签都危险） */
    if (len >= 3) {
        if (tolower((unsigned char)s[0]) == 's' &&
            tolower((unsigned char)s[1]) == 'v' &&
            tolower((unsigned char)s[2]) == 'g') return 1;
        if (tolower((unsigned char)s[0]) == 'x' &&
            tolower((unsigned char)s[1]) == 's' &&
            tolower((unsigned char)s[2]) == 'l') return 1;
    }
    for (int i = 0; BLACK_TAGS[i]; ++i) {
        if (ci_full_eq(s, len, BLACK_TAGS[i])) return 1;
    }
    return 0;
}

/* 黑属性（TYPE_BLACK）：命中即危险，不看值 */
static int is_black_attr(const char* s, int len) {
    /* JavaScript on* 事件（onload/onerror/onmouseover/...） */
    if (len >= 2 &&
        tolower((unsigned char)s[0]) == 'o' &&
        tolower((unsigned char)s[1]) == 'n') return 1;
    /* XMLNS / XLINK 可制造任意标签 */
    if (ci_prefix(s, len, "xmlns")) return 1;
    if (ci_prefix(s, len, "xlink")) return 1;
    /* IE 专有危险属性 */
    if (ci_full_eq(s, len, "dataformatas")) return 1;
    if (ci_full_eq(s, len, "datasrc")) return 1;
    return 0;
}

/* URI 属性（TYPE_ATTR_URL）：值取 URL，需进一步查黑 URL */
static const char* URL_ATTRS[] = {
    "action", "by", "background", "dynsrc", "formaction", "folder",
    "from", "handler", "href", "lowsrc", "poster", "src", "to",
    "values", "xlink:href", NULL
};

static int is_url_attr(const char* s, int len) {
    for (int i = 0; URL_ATTRS[i]; ++i) {
        if (ci_full_eq(s, len, URL_ATTRS[i])) return 1;
    }
    return 0;
}

/* style / filter 属性（TYPE_STYLE）：值需查 CSS 注入 */
static int is_style_attr(const char* s, int len) {
    return ci_full_eq(s, len, "style") || ci_full_eq(s, len, "filter");
}

/* 黑 URL：javascript: / vbscript: / data:（跳过前导空白，不做实体解码） */
static int is_black_url(const char* s, int len) {
    const char* p = s;
    int n = len;
    while (n > 0 && (*p == ' ' || *p == '\t' || *p == '\n' ||
                     *p == '\r' || *p == '\f' || *p == '\v')) {
        ++p; --n;
    }
    if (ci_prefix(p, n, "javascript:")) return 1;
    if (ci_prefix(p, n, "vbscript:")) return 1;
    if (ci_prefix(p, n, "data:")) return 1;
    return 0;
}

/* style 值内的 CSS 注入：expression( / javascript: / vbscript: / -moz-binding */
static int ci_strstr(const char* hay, int haylen, const char* needle) {
    int nlen = (int)strlen(needle);
    if (nlen == 0) return 1;
    for (int i = 0; i + nlen <= haylen; ++i) {
        int j;
        for (j = 0; j < nlen; ++j) {
            if (tolower((unsigned char)hay[i + j]) != tolower((unsigned char)needle[j])) break;
        }
        if (j == nlen) return 1;
    }
    return 0;
}

static int is_style_value(const char* s, int len) {
    if (ci_strstr(s, len, "expression(")) return 1;
    if (ci_strstr(s, len, "javascript:")) return 1;
    if (ci_strstr(s, len, "vbscript:")) return 1;
    if (ci_strstr(s, len, "-moz-binding")) return 1;
    return 0;
}

/* 危险注释：反引号 / IE 条件注释 [if / xml / import / entity */
static int is_dangerous_comment(const char* s, int len) {
    for (int i = 0; i < len; ++i) {
        if (s[i] == '`') return 1;
    }
    if (len > 3) {
        if (s[0] == '[' && (s[1] == 'i' || s[1] == 'I') && (s[2] == 'f' || s[2] == 'F')) return 1;
        if ((s[0] == 'x' || s[0] == 'X') &&
            (s[1] == 'm' || s[1] == 'M') && (s[2] == 'l' || s[2] == 'L')) return 1;
    }
    if (len > 5) {
        if (ci_prefix(s, len, "import")) return 1;
        if (ci_prefix(s, len, "entity")) return 1;
    }
    return 0;
}

%%{
    machine html5_xss;
    include html5_shared "html5_shared.rl";

    # 命中记录（leaving）：离开规则终态时记录 token 长度
    action note { match_len = (int)(p - types) - start; }

    # 语义谓词：不满足即终止本位置匹配（cs=0 表示失败）
    action is_btag {
        if (!is_black_tag(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_battr {
        if (!is_black_attr(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_url_attr_p {
        if (!is_url_attr(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_burl {
        if (!is_black_url(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_style_attr_p {
        if (!is_style_attr(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_style_val {
        if (!is_style_value(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_dcomment {
        if (!is_dangerous_comment(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }
    action is_djs {
        if (!js_is_dangerous(tk[(int)(p - types)].s, tk[(int)(p - types)].len))
            { cs = 0; goto _out; }
    }

    # 规则（每条独立入口，any* 吞掉剩余 token）
    black_tag        := TAG_NAME_OPEN $is_btag %note any*;
    black_attr       := ATTR_NAME $is_battr %note any*;
    black_url        := ATTR_NAME $is_url_attr_p ATTR_VALUE $is_burl %note any*;
    style_expr       := ATTR_NAME $is_style_attr_p ATTR_VALUE $is_style_val %note any*;
    dangerous_comment := TAG_COMMENT $is_dcomment %note any*;
    dangerous_js     := ( ATTR_VALUE | SCRIPT_TEXT ) $is_djs %note any*;

    write data noerror nofinal;
}%%

/* ------------------------------------------------------------
 * 运行期：通用 run（cs0 指定入口）+ 每个规则一个导出函数
 * ------------------------------------------------------------ */
static int run_html5_xss(const int* types, int n, int start, int cs0,
                   const H5Tok* tk, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    const int* eof = pe;
    int cs = cs0;
    int match_len = 0;

    %%{
        machine html5_xss;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}

/* ragel 为每个 `:=` 入口生成 html5_xss_en_<name> 起始状态常量 */
#define HTML5_XSS_ENTRY(name) \
    int html5_xss_match_##name(const int* types, int n, int start, \
                         const H5Tok* tk, int* len) { \
        return run_html5_xss(types, n, start, html5_xss_en_##name, tk, len); \
    }

HTML5_XSS_ENTRY(black_tag)
HTML5_XSS_ENTRY(black_attr)
HTML5_XSS_ENTRY(black_url)
HTML5_XSS_ENTRY(style_expr)
HTML5_XSS_ENTRY(dangerous_comment)
HTML5_XSS_ENTRY(dangerous_js)
