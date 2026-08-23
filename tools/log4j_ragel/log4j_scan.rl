/* ============================================================
 * log4j_scan.rl — log4j 查找表达式识别与攻击防护状态机（Ragel）
 * ------------------------------------------------------------
 * 分工：
 *   Ragel 状态机（语法层）：识别 `${...}` 表达式，含有界深度嵌套
 *     （expr0..expr4，最深 4 层；Ragel 是 DFA，无法表达无界递归，
 *     故按深度展开），并给出每个完整表达式的字符区间；
 *   C 动作回调（语义层）：对捕获的表达式做前缀解析，归约出
 *     "有效前缀"（嵌套 ${...} 取其值文本拼接），与 Log4jLookup.g4
 *     谓词同一套判定：
 *       JNDI      前缀解析结果含 "jndi" 或任意深度嵌套出现 jndi
 *       SENSITIVE 首个前缀关键字 ∈ {env,sys,docker,k8s,aws,spring,main}
 *       CHAIN     无 jndi 但存在嵌套查找链
 *       EXPR      ${...} 结构识别（信息层）
 *
 * 生成：ragel -C -o log4j_scan.c log4j_scan.rl（见 Makefile）
 * 用法：./log4j_scan '<payload>' [<payload>...]
 * ============================================================ */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

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

/* 分类：JNDI > SENSITIVE > CHAIN > EXPR */
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
 * Ragel 扫描器
 * ------------------------------------------------------------ */

const char* ts;         /* Ragel scanner 维护的 token 起始 */
const char* te;         /* Ragel scanner 维护的 token 结束 */
int act;                /* Ragel scanner 维护的 action 编号 */
static int match_count; /* 本次扫描命中表达式数 */

static void on_expr(const char* b, const char* e) {
    static char buf[4096];
    size_t len = (size_t)(e - b);
    if (len >= sizeof(buf)) len = sizeof(buf) - 1;
    memcpy(buf, b, len);
    buf[len] = '\0';

    span body = make_span(buf + 2, (int)len - 2); /* 剥掉 ${ 和 } */
    char detail[64] = "";
    const char* cls = classify(body, detail, sizeof(detail));
    char label[96];
    if (strcmp(cls, "SENSITIVE") == 0 && detail[0]) {
        snprintf(label, sizeof(label), "%s(%s)", cls, detail);
    } else {
        snprintf(label, sizeof(label), "%s", cls);
    }
    printf("  [%s] \"%.*s\"\n", label, (int)len, b);
    match_count++;
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

    # 嵌套表达式按深度展开（Ragel DFA 不支持无界递归）：
    # 最深 4 层嵌套（expr4 内嵌 expr3 ... expr0）。
    expr0 = lbrace ( chunk )* colon ( chunk | colon )* rbrace;
    expr1 = lbrace ( chunk | ( dollar expr0 ) )* colon
                 ( chunk | colon | ( dollar expr0 ) )* rbrace;
    expr2 = lbrace ( chunk | ( dollar expr1 ) )* colon
                 ( chunk | colon | ( dollar expr1 ) )* rbrace;
    expr3 = lbrace ( chunk | ( dollar expr2 ) )* colon
                 ( chunk | colon | ( dollar expr2 ) )* rbrace;
    expr4 = lbrace ( chunk | ( dollar expr3 ) )* colon
                 ( chunk | colon | ( dollar expr3 ) )* rbrace;

    lookup = dollar expr4;

    main := |*
        # action 触发时 p 指向匹配的最后一个字符，te 指向末尾之后
        lookup => { on_expr(ts, te); };
        any    => {};
    *|;

    write data;
}%%

static int scan_text(const char* data, size_t len) {
    const char* p = data;
    const char* pe = data + len;
    const char* eof = pe;
    int cs;
    match_count = 0;
    ts = data;

    %% write init;
    %% write exec;

    return match_count;
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [<payload>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; ++a) {
        const char* data = argv[a];
        printf("input: %s\n", data);
        int n = scan_text(data, strlen(data));
        if (n == 0) printf("  (none)\n");
        printf("\n");
    }
    return 0;
}
