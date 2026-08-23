/* ============================================================
 * log4j_scan_fcall.rl — log4j 查找表达式状态机（Ragel fcall/fret 版）
 * ------------------------------------------------------------
 * 与 tools/log4j_ragel/log4j_scan.rl（纯 DFA 展开版）的区别：
 *   纯 DFA 版：无栈，嵌套按深度展开 expr0..expr4，最深 4 层；
 *   本版：     用 fcall/fret + 宿主栈（stack[64]），嵌套深度
 *               只受栈大小限制（任意深度，栈满即止）。
 *
 * 触发方式统一：在 '$' 上做 finishing action（try_lookup），
 * 若下一个字符是 '{' 则 fcall lookup（lookup 从 '{' 开始匹配）；
 * 否则不调用，'$' 按普通字符处理——因此 $${jndi:...} 会在第二个
 * '$' 处再次尝试并命中。
 *
 * 语义层（C 动作回调）与纯 DFA 版一致：前缀解析归约出有效前缀，
 * 分类 JNDI > SENSITIVE > CHAIN > EXPR。
 *
 * 生成：ragel -C -o log4j_scan_fcall.c log4j_scan_fcall.rl
 * 用法：./log4j_scan_fcall '<payload>' [<payload>...]
 * ============================================================ */

#include <ctype.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------
 * 语义层：span 工具 + 前缀解析 + 分类（与纯 DFA 版同一套判定）
 * ------------------------------------------------------------ */

typedef struct {
    const char* s;
    int len;
} span;

static span make_span(const char* s, int len) {
    span sp = {s, len};
    return sp;
}

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
 * Ragel fcall/fret 机器
 * ------------------------------------------------------------ */

int stack[64];   /* Ragel fcall/fret 宿主栈 */
int top;         /* 栈顶 */
int starts[64];  /* 每个嵌套层表达式起始偏移（与 stack 同步） */
static int match_count;

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
    machine log4j_fcall;

    dollar = '$';
    lbrace = '{';
    rbrace = '}';
    colon  = ':';

    # 非结构连续段（$ 孤立时属于内容；仅 $ 后紧跟 { 才进嵌套）
    chunk = ( any - ( lbrace | rbrace | colon ) );

    # 进入 lookup：Ragel 运行时 action 触发时 p 指向当前字符
    # （_again 处才 ++p 消费），因此判断下一个字符是否为 '{'。
    # starts[top] 记录本层起始（即 '$' 的位置）。
    action try_lookup {
        if (p + 1 < pe && *(p + 1) == '{') {
            starts[top] = (int)(p - data);
            fcall lookup;
        }
    }

    # 退出 lookup：action 触发时 p 指向 '}'，报告区间为 [start, p+1)，
    # 再 fret（_again 消费 '}' 后回到调用点）。
    action note_expr {
        on_expr(data + starts[top - 1], p + 1);
    }
    action exit_lookup { fret; }

    # 一个完整表达式体：前缀? ':' 值?，前缀与值内部都可再嵌 lookup。
    # 嵌套深度只受 stack[64] 限制（这里最多 63 层）。
    lookup := lbrace
              ( chunk | ( dollar @try_lookup ) )* colon
              ( chunk | colon | ( dollar @try_lookup ) )*
              rbrace @note_expr @exit_lookup;

    # 顶层：'$' 后跟 '{' 时进入 lookup；否则 '$' 按普通字符继续
    # （因此 $${...} 会在第二个 '$' 再次尝试）。
    main := ( any - dollar | dollar @try_lookup )* ;

    write data;
}%%

static int scan_text(const char* data, size_t len) {
    const char* p = data;
    const char* pe = data + len;
    const char* eof = pe;
    int cs;
    match_count = 0;
    top = 0;

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
