/* ============================================================
 * html5_xss_scan.c — html5_xss_rules.rl（6 条 XSS 规则）的调用示例
 * ------------------------------------------------------------
 * 演示"调用方视角"的分层：状态机层（html5_xss_rules）是无位置的流式
 * 消费者，只吃 token、报匹配长度；token 流的顺序与起点循环都在本文件
 * （用户层）。
 *
 *   每个请求、每条规则一个 CTX（H5XssCtx ctx[6]）；起点循环在这里（for s），
 *   对每个起点 reset -> feed -> finish，命中则上报 [s, s+match_len)。
 *
 * 调用方只需 include html5_tokens.h / html5_xss_rules.h 并链接
 * libragel_sql（html5_tokens + html5_xss_rules 打包），无需 ragel。
 *
 * 用法：
 *   ./html5_xss_scan '<payload>' [<payload>...]
 * ============================================================ */

#include <stdio.h>
#include <string.h>

#include "html5_tokens.h"
#include "html5_xss_rules.h"

#define MAX_TOK 1024

/* 区间 [s,e) 的 token 原文（空格连接） */
static void range_text(const H5Tok* tk, int s, int e, char* out, size_t cap) {
    size_t o = 0;
    out[0] = '\0';
    for (int i = s; i < e && o + 1 < cap; ++i) {
        size_t need = (size_t)tk[i].len + (i > s ? 1 : 0);
        if (o + need + 1 > cap) break;
        if (i > s) out[o++] = ' ';
        memcpy(out + o, tk[i].s, (size_t)tk[i].len);
        o += (size_t)tk[i].len;
    }
    out[o] = '\0';
}

/* 词法 + 头部打印 */
static int lex_and_print(const char* data, H5Tok* tk, int* types) {
    int n = lex_html5(data, strlen(data), tk, MAX_TOK);
    for (int i = 0; i < n; ++i) types[i] = (int)tk[i].type;

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; ++i) {
        printf(" %s(%.*s)", h5_tok_name(tk[i].type),
                tk[i].len, tk[i].s);
    }
    printf("\n");
    return n;
}

/* ------------------------------------------------------------
 * 一条规则从起点 s 起试一次：reset -> 一次喂到末尾 -> finish。
 * 命中长度读 c->match_len。
 * ------------------------------------------------------------ */
static void try_from(H5XssCtx* c, const int* types, const H5Tok* tk,
                     int n, int s) {
    h5xss_ctx_reset(c);
    h5xss_ctx_feed(c, types + s, tk + s, n - s, NULL);
    if (h5xss_ctx_alive(c))
        h5xss_ctx_finish(c, NULL);
}

/* ------------------------------------------------------------
 * 每个请求：每条规则一个 CTX。起点循环在这里（用户层），状态机只吃 token。
 * ------------------------------------------------------------ */
static void scan(const char* data) {
    H5Tok tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_and_print(data, tk, types);

    H5XssCtx ctx[H5XSS_NUM_ENTRIES];
    for (int r = 0; r < H5XSS_NUM_ENTRIES; ++r)
        h5xss_ctx_init(&ctx[r], r);                       /* 1) 初始化 */

    for (int s = 0; s < n; ++s) {                        /* 起点循环（用户层） */
        for (int r = 0; r < H5XSS_NUM_ENTRIES; ++r) {
            try_from(&ctx[r], types, tk, n, s);          /* 2) 匹配 */
            if (ctx[r].match_len > 0) {
                char buf[256];
                range_text(tk, s, s + ctx[r].match_len, buf, sizeof(buf));
                printf("  !! %s [%d,%d) \"%s\"\n",
                       H5XSS_RULES[r].name, s, s + ctx[r].match_len, buf);
            }
        }
    }

    for (int r = 0; r < H5XSS_NUM_ENTRIES; ++r)
        h5xss_ctx_clean(&ctx[r]);                         /* 3) 清除 */

    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [<payload>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; ++a)
        scan(argv[a]);
    return 0;
}
