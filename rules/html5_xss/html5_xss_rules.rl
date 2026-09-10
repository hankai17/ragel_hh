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
 * is_black_url 在归一化后的属性值上匹配：
 *   1) 实体解码：数字实体（&#14; / &#x09; / &#106;）+ 命名实体
 *      （&colon; / &Tab; / &NewLine;，分号必需、大小写敏感）；
 *   2) 空白/控制字符折叠（jav\tascript:、前导空白、null 跳过）。
 * 对齐浏览器 HTML 属性值解析阶段的行为。
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

/* ------------------------------------------------------------
 * HTML 归一化：数字字符实体解码 + 空白/控制字符折叠
 *   &#14;  -> U+000E（折叠掉）   &#x09; -> TAB（折叠掉）
 *   &#106; -> 'j'（实体解码）    jav\ta\nscript -> javascript（折叠）
 * 对齐浏览器在 HTML 属性值解析阶段的行为：实体先解码，scheme 中的
 * tab/换行/控制字符会被剥掉，故黑 URL 前缀在归一化后的流上匹配。
 * ------------------------------------------------------------ */
typedef struct {
    const char* p;
    int n;
    char q[4];     /* 单个实体解码出的 UTF-8 字节缓冲 */
    int qi, qn;
} UrlNorm;

/* 码点 -> UTF-8，写入 out（需 4 字节空间），返回写入字节数 */
static int utf8_put(char* out, int cp) {
    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}

/* s[0..len) 以 &# 开头时解析数字实体（十进制 / 十六进制，分号可选）；
 * 成功返回码点并令 *adv = 消耗字节数，否则返回 -1 */
static int decode_num_entity(const char* s, int len, int* adv) {
    if (len < 3 || s[0] != '&' || s[1] != '#') return -1;
    int i = 2, hex = 0, cp = 0, any = 0;
    if (i < len && (s[i] == 'x' || s[i] == 'X')) { hex = 1; ++i; }
    while (i < len) {
        int d;
        char c = s[i];
        if (c >= '0' && c <= '9') d = c - '0';
        else if (hex && c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (hex && c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else break;
        cp = cp * (hex ? 16 : 10) + d;
        if (cp > 0x10FFFF) cp = 0xFFFD;
        any = 1; ++i;
    }
    if (!any) return -1;
    if (i < len && s[i] == ';') ++i;
    *adv = i;
    return cp;
}

/* ------------------------------------------------------------
 * 命名实体（HTML5 named character reference 的实用子集）
 * ------------------------------------------------------------
 * 全表 2000+ 条，这里只收 URL scheme 混淆真正用得上的字符：
 *   - 空白类 &Tab; / &NewLine;（浏览器解出后按 URL 规则折叠）
 *   - 冒号 &colon;（拼出 javascript: / vbscript: / data: 的分隔符）
 *   - 常见标点（配合数字实体拼装更复杂的混淆）
 * 规范要点：命名实体**大小写敏感**、**必须带分号**（属性值上下文里
 * 无分号且后跟字母数字/= 时不解），故这里按规范严格匹配，避免
 * 把 "&sect=1" 这类普通文本误当实体。
 * 注意 &nbsp; 解出的是 U+00A0，不是 ASCII 空格，浏览器 URL 解析
 * 不折叠它 —— 因此它不会被当作 scheme 前缀前的空白，行为与浏览器一致。
 * ------------------------------------------------------------ */
typedef struct { const char* name; int cp; } NamedEnt;

static const NamedEnt NAMED_ENTS[] = {
    /* 空白类（解出后被折叠） */
    { "Tab", 0x09 }, { "NewLine", 0x0A },
    /* 冒号：javascript&colon;alert(1) 的关键 */
    { "colon", 0x3A },
    /* 常见标点 */
    { "sol", 0x2F },  { "excl", 0x21 },  { "quot", 0x22 },
    { "apos", 0x27 }, { "lt", 0x3C },    { "gt", 0x3E },
    { "amp", 0x26 },  { "lpar", 0x28 },  { "rpar", 0x29 },
    { "comma", 0x2C },{ "period", 0x2E },{ "equals", 0x3D },
    { "plus", 0x2B }, { "num", 0x23 },   { "quest", 0x3F },
    { "semi", 0x3B }, { "bsol", 0x5C },  { "grave", 0x60 },
    { "dollar", 0x24 }, { "lowbar", 0x5F },
    /* 非 ASCII 空白：解出不折叠，仅保留以对齐浏览器 */
    { "nbsp", 0xA0 },
    { NULL, 0 }
};

/* s[0..len) 以 &name; 形式出现时查表；成功返回码点并令 *adv = 消耗
 * 字节数，否则返回 -1（不消耗输入） */
static int decode_named_entity(const char* s, int len, int* adv) {
    if (len < 3 || s[0] != '&') return -1;
    for (int i = 1; i < len; ++i) {
        char c = s[i];
        if (c == ';') {
            int nlen = i - 1;                 /* & 与 ; 之间的名字长度 */
            if (nlen <= 0) return -1;
            for (int k = 0; NAMED_ENTS[k].name; ++k) {
                const char* nm = NAMED_ENTS[k].name;
                int j = 0;
                while (j < nlen && nm[j] != '\0' && nm[j] == s[1 + j]) ++j;
                if (j == nlen && nm[j] == '\0') {
                    *adv = nlen + 2;          /* & + 名字 + ; */
                    return NAMED_ENTS[k].cp;
                }
            }
            return -1;
        }
        /* 名字只允许字母数字（大小写敏感，与规范一致） */
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9')))
            return -1;
    }
    return -1;                                /* 没有闭合的分号 */
}

/* 取下一个归一化字节（已小写）：解码数字实体，折叠全部空白/控制字符；
 * 返回 0 表示输入结束 */
static int norm_next(UrlNorm* st) {
    for (;;) {
        if (st->qi < st->qn)
            return tolower((unsigned char)st->q[st->qi++]);
        if (st->n <= 0) return 0;
        unsigned char c = (unsigned char)*st->p;
        if (c == '&') {
            int adv, cp = decode_num_entity(st->p, st->n, &adv);
            if (cp < 0) cp = decode_named_entity(st->p, st->n, &adv);
            if (cp >= 0) {
                st->p += adv; st->n -= adv;
                /* 折叠控制字符与空白：上界取 0x20（含空格），与下方原始
                 * 字节分支 `c <= 0x20` 保持一致 —— 否则 &#32; / &#x20;
                 * 解出的空格不折叠，与字面空格行为自相矛盾。 */
                if (cp <= 0x20 || cp == 0x7F) continue;  /* 控制字符/空白折叠 */
                st->qi = 0;
                st->qn = utf8_put(st->q, cp);
                continue;
            }
        }
        ++st->p; --st->n;
        if (c <= 0x20 || c == 0x7F) continue;  /* 原始空白/控制字符折叠 */
        return tolower(c);
    }
}

/* 归一化流剩余部分是否与 prefix[1..] 逐字符相等（首字符已在调用前判定） */
static int norm_rest_is(UrlNorm* st, const char* prefix) {
    for (int i = 1; prefix[i]; ++i) {
        if (norm_next(st) != tolower((unsigned char)prefix[i])) return 0;
    }
    return 1;
}

/* ------------------------------------------------------------
 * 属性值实体解码（供 JS 语义分析）
 * ------------------------------------------------------------
 * 与上面的"归一化流"不同，这里**只解实体**，保留空白与大小写：
 * 浏览器把属性值交给 JS 引擎时看到的就是这段解码后的文本，而空白/
 * 大小写交给 JS 词法器处理更准确 —— 折叠空白反而会把 `foo bar` 这类
 * 两个标识符粘成一个，制造误报。
 *
 * 适用范围：仅 ATTR_VALUE。<script>/<style> 是 raw text 元素，浏览器
 * 不解码其中的实体，故 SCRIPT_TEXT 必须保持原样。
 * ------------------------------------------------------------ */
static int decode_entities(const char* s, int len, char* out, int cap) {
    int o = 0;
    while (len > 0) {
        if (*s == '&') {
            int adv, cp = decode_num_entity(s, len, &adv);
            if (cp < 0) cp = decode_named_entity(s, len, &adv);
            if (cp >= 0) {
                s += adv; len -= adv;
                if (o + 4 >= cap) break;
                o += utf8_put(out + o, cp);
                continue;
            }
        }
        if (o + 1 >= cap) break;
        out[o++] = *s++;
        --len;
    }
    out[o] = '\0';
    return o;
}

/* 黑 URL：归一化（实体解码 + 空白/控制字符折叠）后前缀匹配
 * javascript: / vbscript: / data: */
static int is_black_url(const char* s, int len) {
    UrlNorm st;
    st.p = s; st.n = len; st.qi = st.qn = 0;
    int c = norm_next(&st);
    if (c == 'j') return norm_rest_is(&st, "javascript:");
    if (c == 'v') return norm_rest_is(&st, "vbscript:");
    if (c == 'd') return norm_rest_is(&st, "data:");
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
    # 语义层：属性值先解码 HTML 实体再交给 JS 分析（SCRIPT_TEXT 是 raw
    # text，浏览器不解其中的实体，保持原样）
    action is_djs {
        int di = (int)(p - types);
        int dok;
        if (tk[di].type == H5_ATTR_VALUE) {
            char dbuf[1024];
            int dn = decode_entities(tk[di].s, tk[di].len, dbuf, (int)sizeof(dbuf));
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
