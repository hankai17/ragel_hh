/* ============================================================
 * log4j_lookup.rl — log4j 查找表达式识别与攻击防护状态机（Ragel）
 * ------------------------------------------------------------
 * 对应 rules/antlr4/log4j 那套 g4 的判定面，生成 C 后导出
 * log4j_scan() 供调用方链接；驱动（examples/log4j_scan.c）只消费
 * 本库接口，不接触实现。
 *
 * 分工：
 *   Ragel 状态机（语法层）：识别 `${...}` 表达式，嵌套用 fcall/fret
 *     递归匹配（无界深度），并给出每个完整表达式的字符区间；
 *   C 动作回调（语义层）：对捕获的表达式做前缀解析，归约出
 *     "有效前缀"（嵌套 ${...} 取其值文本拼接），与 Log4jLookup.g4
 *     谓词同一套判定：
 *       JNDI      前缀解析结果含 "jndi" 或任意深度嵌套出现 jndi
 *       SENSITIVE 首个前缀关键字 ∈ {env,sys,docker,k8s,aws,spring,main}
 *       CHAIN     无 jndi 但存在嵌套查找链
 *       EXPR      ${...} 结构识别（信息层）
 *
 * 生成：ragel -C -o log4j_lookup.c log4j_lookup.rl
 * ============================================================ */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log4j_lookup.h"

/* ------------------------------------------------------------
 * 语义层：span 工具 + 前缀解析 + 分类
 * ------------------------------------------------------------ */

typedef struct {
    const char* s;
    int len;
} span;

static span make_span(const char* s, int len) {
    span sp = {s, len};
    return sp;
}

/* 顶层冒号索引（{} 深度 0；嵌套 ${ 深度 +1），无则 -1 */
static int top_colon(span b) {
    int depth = 0;
    for (int i = 0; i < b.len; ++i) {
        char c = b.s[i];
        if (c == '$' && i + 1 < b.len && b.s[i + 1] == '{') {
            depth++;
            i++;
        } else if (c == '}') {
            if (depth > 0) depth--;
        } else if (c == ':' && depth == 0) {
            return i;
        }
    }
    return -1;
}

/* 从指向 '$' 的位置找嵌套表达式结束 '}' 的索引，无则 -1 */
static int nested_expr_end(span s, int i) {
    int depth = 0;
    for (int k = i; k < s.len; ++k) {
        if (s.s[k] == '$' && k + 1 < s.len && s.s[k + 1] == '{') {
            depth++;
            k++;
        } else if (s.s[k] == '}') {
            depth--;
            if (depth == 0) return k;
        }
    }
    return -1;
}

static void append_ch(char* out, size_t* olen, size_t cap, char c) {
    if (*olen + 1 < cap) {
        out[(*olen)++] = c;
        out[*olen] = '\0';
    }
}

static void resolve_value(span v, char* out, size_t* olen, size_t cap);

/* 前缀解析：chunk 原文 + 嵌套 ${...} 取"值文本"拼接
 *   ${${lower:j}ndi}      -> "j" + "ndi" = "jndi"
 *   ${${::-j}ndi}         -> "-j" + "ndi" = "-jndi"
 *   ${${lower:j}${lower:n}${lower:d}${lower:i}} -> "jndi" */
static void resolve_prefix(span p, char* out, size_t* olen, size_t cap) {
    for (int i = 0; i < p.len; ++i) {
        if (p.s[i] == '$' && i + 1 < p.len && p.s[i + 1] == '{') {
            int end = nested_expr_end(p, i);
            if (end < 0) {
                append_ch(out, olen, cap, p.s[i]);
                continue;
            }
            span nbody = make_span(p.s + i + 2, end - (i + 2));
            int tc = top_colon(nbody);
            if (tc >= 0) {
                span nval = make_span(nbody.s + tc + 1, nbody.len - tc - 1);
                resolve_value(nval, out, olen, cap);
            }
            i = end;
        } else {
            append_ch(out, olen, cap, p.s[i]);
        }
    }
}

static void resolve_value(span v, char* out, size_t* olen, size_t cap) {
    for (int i = 0; i < v.len; ++i) {
        if (v.s[i] == '$' && i + 1 < v.len && v.s[i + 1] == '{') {
            int end = nested_expr_end(v, i);
            if (end < 0) {
                append_ch(out, olen, cap, v.s[i]);
                continue;
            }
            span nbody = make_span(v.s + i + 2, end - (i + 2));
            int tc = top_colon(nbody);
            if (tc >= 0) {
                span nval = make_span(nbody.s + tc + 1, nbody.len - tc - 1);
                resolve_value(nval, out, olen, cap);
            }
            i = end;
        } else {
            append_ch(out, olen, cap, v.s[i]);
        }
    }
}

static bool contains_ci(const char* hay, const char* needle) {
    size_t nlen = strlen(needle);
    for (const char* h = hay; *h; ++h) {
        size_t k = 0;
        while (k < nlen && h[k] &&
               tolower((unsigned char)h[k]) == tolower((unsigned char)needle[k])) {
            k++;
        }
        if (k == nlen) return true;
    }
    return false;
}

static int count_nested(span b) {
    int n = 0;
    for (int i = 0; i < b.len; ++i) {
        if (b.s[i] == '$' && i + 1 < b.len && b.s[i + 1] == '{') {
            n++;
            i++;
        }
    }
    return n;
}

/* 子树内任意深度是否存在前缀解析后含 jndi 的嵌套表达式 */
static bool any_nested_jndi(span b) {
    for (int i = 0; i < b.len; ++i) {
        if (b.s[i] == '$' && i + 1 < b.len && b.s[i + 1] == '{') {
            int end = nested_expr_end(b, i);
            if (end < 0) continue;
            span nbody = make_span(b.s + i + 2, end - (i + 2));
            int tc = top_colon(nbody);
            span nprefix = tc >= 0 ? make_span(nbody.s, tc) : nbody;
            char pfx[512];
            size_t ol = 0;
            pfx[0] = '\0';
            resolve_prefix(nprefix, pfx, &ol, sizeof(pfx));
            if (contains_ci(pfx, "jndi")) return true;
            if (any_nested_jndi(nbody)) return true;
            i = end;
        }
    }
    return false;
}

/* 原始前缀的第一个 chunk（小写；遇嵌套即停） */
static void first_prefix_chunk(span b, char* out, size_t cap) {
    int tc = top_colon(b);
    span pre = tc >= 0 ? make_span(b.s, tc) : b;
    size_t o = 0;
    for (int i = 0; i < pre.len && o + 1 < cap; ++i) {
        char c = pre.s[i];
        if (c == '$' && i + 1 < pre.len && pre.s[i + 1] == '{') break;
        if (isalnum((unsigned char)c) || c == '_' || c == '-') {
            out[o++] = (char)tolower((unsigned char)c);
        } else if (o > 0) {
            break;
        }
    }
    out[o] = '\0';
}

static bool is_sensitive(const char* p) {
    static const char* set[] = {"env", "sys", "docker", "k8s",
                                "aws", "spring", "main"};
    for (size_t i = 0; i < sizeof(set) / sizeof(set[0]); ++i) {
        if (strcmp(p, set[i]) == 0) return true;
    }
    return false;
}

/* 分类：JNDI > SENSITIVE > CHAIN > EXPR
 * 返回静态分类名；SENSITIVE 时把前缀关键字写入 detail。 */
static const char* classify(span b, char* detail, size_t dcap) {
    int tc = top_colon(b);
    if (tc < 0) return "EXPR";
    span pre = make_span(b.s, tc);
    char pfx[512];
    size_t ol = 0;
    pfx[0] = '\0';
    resolve_prefix(pre, pfx, &ol, sizeof(pfx));
    if (contains_ci(pfx, "jndi") || any_nested_jndi(b)) return "JNDI";
    char first[64];
    first_prefix_chunk(b, first, sizeof(first));
    if (is_sensitive(first)) {
        snprintf(detail, dcap, "%s", first);
        return "SENSITIVE";
    }
    if (count_nested(b) > 0) return "CHAIN";
    return "EXPR";
}

/* ------------------------------------------------------------
 * Ragel 匹配器：逐位置识别 ${...}，命中写入调用方数组
 * ------------------------------------------------------------ */

static const char* ts;         /* 匹配起始（collect_expr 用） */
static const char* te;         /* 匹配结束（collect_expr 用） */
static Log4jHit* g_hits;       /* 命中收集目标（本次扫描） */
static int g_cap;              /* 收集上限 */
static int g_count;            /* 已收集数 */

static void collect_expr(void) {
    if (g_count >= g_cap) return;
    size_t len = (size_t)(te - ts);
    char buf[4096];
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, ts, len);
    buf[len] = '\0';

    Log4jHit* h = &g_hits[g_count];
    h->s = ts;
    h->len = (int)(te - ts);
    h->detail[0] = '\0';
    /* 剥掉 ${ 和 }，取 body 做前缀解析 */
    span body = make_span(buf + 2, (int)len - 2);
    h->cls = classify(body, h->detail, sizeof(h->detail));
    g_count++;
}

%%{
    machine log4j;

    dollar = '$';
    lbrace = '{';
    rbrace = '}';
    colon  = ':';

    # 非结构连续段（等价 Log4jTokens 的 CHUNK；$ 仅在紧跟 { 时进入
    # 嵌套表达式，孤立 $ 属于内容）
    chunk = ( any - ( lbrace | rbrace | colon ) );

    # 嵌套 ${...} 用 fcall/fret 递归（替代 expr0..expr4 的有限展开）：
    #   消费 ${ 后 fcall lookup_call，被调方匹配 body + 右括号后 fret。
    action call_lookup { fcall lookup_call; }
    action ret_lookup  { fret; }
    action note_hit    { len = (int)(p - ts) + 1; }

    nested = dollar lbrace @call_lookup;
    prefix = ( chunk | nested )*;
    value  = ( chunk | colon | nested )*;
    body   = prefix colon value;

    lookup = dollar lbrace body rbrace;

    main := lookup @note_hit;

    # 递归入口：嵌套 ${...} 的 body + 闭合右括号
    lookup_call := body rbrace @ret_lookup;

    write data noerror nofinal noentry;
}%%

/* ------------------------------------------------------------
 * 逐位置匹配一个完整 ${...}（普通模式，替代 scanner 自动扫描）
 * ------------------------------------------------------------ */
static int match_one(const char* data, const char* pe, int* hit_len) {
    const char* p = data;
    int cs = log4j_start;
    int stack[256];   /* fcall/fret 嵌套栈 */
    int top = 0;
    int len = 0;
    ts = data;

    %%{
        machine log4j;
        write exec;
    }%%

    *hit_len = len;
    return len > 0;
}

/* ============================================================
 * log4j_scan()：库入口（log4j_lookup.h 声明的契约实现）
 * ============================================================ */
int log4j_scan(const char* data, size_t len, Log4jHit* hits, int cap) {
    const char* p = data;
    const char* pe = data + len;
    g_hits = hits;
    g_cap = cap;
    g_count = 0;

    /* 只有 ${ 开头才尝试匹配，其余位置跳过 */
    while (p < pe) {
        if (p + 1 >= pe || p[0] != '$' || p[1] != '{') {
            p++;
            continue;
        }
        int hit_len = 0;
        if (match_one(p, pe, &hit_len)) {
            te = p + hit_len;
            collect_expr();
            p += hit_len;
        } else {
            p++;
        }
    }
    return g_count;
}
