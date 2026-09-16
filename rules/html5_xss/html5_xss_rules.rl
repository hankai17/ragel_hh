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
 * 本文件只放"规则"本身：黑名单数据 + 命中策略。HTML 侧的通用能力
 * （字符实体解码、属性值归一化）在 src/html5/html5_entities.c，
 * JS 侧的语义分析在 src/js/js_danger.c。
 *
 *   black_url   在归一化后的属性值上匹配（实体解码 + 空白折叠），
 *               归一化由 h5_norm_next 提供；
 *   dangerous_js 对属性值先 h5_decode_entities（只解实体、保留空白），
 *               再交给 js_is_dangerous 做 JS 语义分析。
 *
 * 生成：ragel -C -o html5_xss_rules.c html5_xss_rules.rl
 * ============================================================ */

#include <ctype.h>
#include <stddef.h>
#include <string.h>

#include "cistr.h"
#include "html5_tokens.h"
#include "html5_entities.h"
#include "js_danger.h"
#include "html5_xss_rules.h"

/* ------------------------------------------------------------
 * 语义层：黑名单数据 + 匹配谓词（C 层，供 Ragel 动作调用）
 * ------------------------------------------------------------ */

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
        if (ci_eq(s, len, BLACK_TAGS[i])) return 1;
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
    if (ci_eq(s, len, "dataformatas")) return 1;
    if (ci_eq(s, len, "datasrc")) return 1;
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
        if (ci_eq(s, len, URL_ATTRS[i])) return 1;
    }
    return 0;
}

/* style / filter 属性（TYPE_STYLE）：值需查 CSS 注入 */
static int is_style_attr(const char* s, int len) {
    return ci_eq(s, len, "style") || ci_eq(s, len, "filter");
}

/* ------------------------------------------------------------
 * 黑 URL 前缀：在归一化后的属性值上匹配
 * ------------------------------------------------------------
 * 归一化（实体解码 + 空白/控制字符折叠 + 转小写）的实现放在
 * src/html5/html5_entities.c —— 那是 HTML 解析器的职责，不是规则本身。
 * 这里只留"哪些 scheme 算危险"这条策略。
 * ------------------------------------------------------------ */

/* 归一化流剩余部分是否与 prefix[1..] 逐字符相等（首字符已在调用前判定） */
static int norm_rest_is(H5UrlNorm* st, const char* prefix) {
    for (int i = 1; prefix[i]; ++i) {
        if (h5_norm_next(st) != tolower((unsigned char)prefix[i])) return 0;
    }
    return 1;
}

/* 黑 URL：javascript: / vbscript: / data: */
static int is_black_url(const char* s, int len) {
    H5UrlNorm st;
    h5_norm_init(&st, s, len);
    int c = h5_norm_next(&st);
    if (c == 'j') return norm_rest_is(&st, "javascript:");
    if (c == 'v') return norm_rest_is(&st, "vbscript:");
    if (c == 'd') return norm_rest_is(&st, "data:");
    return 0;
}

/* style 值内的 CSS 注入：expression( / javascript: / vbscript: / -moz-binding */
static int is_style_value(const char* s, int len) {
    if (ci_find(s, len, "expression(") >= 0) return 1;
    if (ci_find(s, len, "javascript:") >= 0) return 1;
    if (ci_find(s, len, "vbscript:") >= 0) return 1;
    if (ci_find(s, len, "-moz-binding") >= 0) return 1;
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

    # 命中记录（leaving）：离开规则终态时记录 token 长度。
    # consumed = 本段之前已消费的 token 数（ctx_run 局部变量），
    # p - types = 本段内的相对偏移，二者相加 = 从本次尝试起点起已消费的
    # token 数 = 匹配长度。全程只用相对计数，不出现绝对位置。
    action note { match_len = consumed + (int)(p - types); }

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
    # 语义层：属性值先解码 HTML 实体再交给 JS 分析（SCRIPT_TEXT 是 raw
    # text，浏览器不解其中的实体，保持原样）
    action is_djs {
        int di = (int)(p - types);
        int dok;
        if (tk[di].type == H5_ATTR_VALUE) {
            char dbuf[1024];
            int dn = h5_decode_entities(tk[di].s, tk[di].len, dbuf, (int)sizeof(dbuf));
            dok = js_is_dangerous(dbuf, dn);
        } else {
            dok = js_is_dangerous(tk[di].s, tk[di].len);
        }
        if (!dok) { cs = 0; goto _out; }
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
 * 运行期
 * ------------------------------------------------------------
 * ctx_run 是唯一的执行体：状态从 CTX 读入、跑完写回；输入就是"接下来"
 * 的 n 个 token（本段）。不出现任何绝对 token 下标 —— 位置由调用方维护。
 *
 *   types/tk : 本段（接下来）的 token 类型数组与原文数组（等长对齐）
 *   n        : 本段 token 数
 *   at_eof   : 非 0 才让 ragel 的 eof 动作触发。喂中间段传 0，最后一段
 *              （或 finish）传 1。
 *
 * %note 里 match_len = consumed + (p - types)：
 *   consumed  = 本段之前已消费的 token 数（相对计数）
 *   p - types = 本段内的相对偏移
 * 相加即"从本次尝试起点起已消费的 token 数" = 匹配长度。
 * ------------------------------------------------------------ */
static int ctx_run(H5XssCtx* c, const int* types, const H5Tok* tk,
                   int n, int at_eof, int* hit_len) {
    const int* p = types;
    const int* pe = p + n;
    /* eof 在生成的代码里只出现于 `if (p == eof)`：给它一个永远不等于 p
     * 的值即可抑制 eof 动作（types 恒非空，p 不可能为 NULL）。 */
    const int* eof = at_eof ? pe : (const int*)0;
    int cs = c->cs;
    int match_len = c->match_len;
    int consumed = c->consumed;

    %%{
        machine html5_xss;
        write exec;
    }%%

    c->cs = cs;
    c->match_len = match_len;
    c->consumed = consumed + (int)(p - types);   /* 本段实际消费了几个 */

    if (match_len > 0) {
        if (hit_len) *hit_len = match_len;
        return 1;
    }
    return 0;
}

/* ------------------------------------------------------------
 * 1) 初始化 / 清除 / 重置
 * ------------------------------------------------------------
 * 规则下标 -> ragel 入口状态。ragel 把入口状态生成成文件级
 * `static const int`，C 里它不算常量表达式，没法用于文件作用域的静态
 * 初始化，所以这里用一张局部数组在运行期取（自动存储期允许非常量初始化）。
 * ------------------------------------------------------------ */
static int entry_state(int rule) {
    const int tbl[H5XSS_NUM_ENTRIES] = {
#define H5XSS_ENTRY_OF(name) html5_xss_en_##name,
        H5XSS_RULE_LIST(H5XSS_ENTRY_OF)
#undef H5XSS_ENTRY_OF
    };
    if (rule < 0 || rule >= H5XSS_NUM_ENTRIES) return 0;
    return tbl[rule];
}

void h5xss_ctx_init(H5XssCtx* c, int rule) {
    c->entry = entry_state(rule);
    h5xss_ctx_reset(c);
}

void h5xss_ctx_clean(H5XssCtx* c) {
    c->entry = 0;
    c->cs = 0;               /* 0 = 不可再喂 */
    c->match_len = 0;
    c->consumed = 0;
}

/* 开始一次新尝试：拨回入口态，清空命中与已消费计数。每次换起点（或新
 * 请求复用同一 ctx）前调一次。 */
void h5xss_ctx_reset(H5XssCtx* c) {
    c->cs = c->entry;
    c->match_len = 0;
    c->consumed = 0;
}

/* ------------------------------------------------------------
 * 2) 匹配
 * ------------------------------------------------------------ */
int h5xss_ctx_feed(H5XssCtx* c, const int* types, const H5Tok* tk, int n,
                   int* hit_len) {
    if (!h5xss_ctx_alive(c)) return 0;
    return ctx_run(c, types, tk, n, 0, hit_len);   /* 收尾交给 finish */
}

int h5xss_ctx_finish(H5XssCtx* c, int* hit_len) {
    static const int empty_types = 0;   /* n = 0，不会被读 */
    static H5Tok empty_tk;              /* 同上（零初始化） */
    return ctx_run(c, &empty_types, &empty_tk, 0, 1, hit_len);
}

int h5xss_ctx_alive(const H5XssCtx* c) {
    return c->cs != 0;
}

/* ------------------------------------------------------------
 * 规则表：与 H5XSS_RULE_LIST 同序（名字，供上报）
 * ------------------------------------------------------------ */
const H5XssRuleDef H5XSS_RULES[H5XSS_NUM_ENTRIES] = {
#define H5XSS_TAB(name) { #name },
    H5XSS_RULE_LIST(H5XSS_TAB)
#undef H5XSS_TAB
};
