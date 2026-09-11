/* ============================================================
 * html5_entities.c — HTML 字符实体解码 / 属性值归一化
 * ------------------------------------------------------------
 * 实现见 html5_entities.h。两部分：
 *   - h5_decode_entities：只解实体，保留空白与大小写（给 JS 语义分析）
 *   - H5UrlNorm / h5_norm_next：解码 + 折叠空白 + 转小写（给 URL 前缀匹配）
 * ============================================================ */

#include <ctype.h>
#include <stddef.h>

#include "esc.h"
#include "html5_entities.h"
#include "utf8.h"

/* s[0..len) 以 &# 开头时解析数字实体（十进制 / 十六进制，分号可选）；
 * 成功返回码点并令 *adv = 消耗字节数，否则返回 -1 */
static int decode_num_entity(const char* s, int len, int* adv) {
    if (len < 3 || s[0] != '&' || s[1] != '#') return -1;
    int i = 2, hex = 0, cp = 0, any = 0;
    if (i < len && (s[i] == 'x' || s[i] == 'X')) { hex = 1; ++i; }
    while (i < len) {
        int d = hex ? hex_val(s[i])
                    : (s[i] >= '0' && s[i] <= '9' ? s[i] - '0' : -1);
        if (d < 0) break;
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

/* ------------------------------------------------------------
 * 只解实体（保留空白与大小写）
 * ------------------------------------------------------------
 * 浏览器把属性值交给 JS 引擎时看到的就是这段解码后的文本；空白与
 * 大小写留给 JS 词法器处理更准确 —— 在这层折叠空白反而会把
 * `foo bar` 两个标识符粘成一个，制造误报。
 * ------------------------------------------------------------ */
int h5_decode_entities(const char* s, int len, char* out, int cap) {
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

/* ------------------------------------------------------------
 * 归一化流
 * ------------------------------------------------------------ */

void h5_norm_init(H5UrlNorm* st, const char* s, int len) {
    st->p = s;
    st->n = len;
    st->qi = st->qn = 0;
}

/* 取下一个归一化字节（已小写）：解码实体，折叠全部空白/控制字符；
 * 返回 0 表示输入结束 */
int h5_norm_next(H5UrlNorm* st) {
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
