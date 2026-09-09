/* ============================================================
 * html5_xss_scan.c — html5_xss_rules.rl（5 条 XSS 黑名单规则）的调用示例
 * ------------------------------------------------------------
 * 位于 examples/，演示"调用方视角"：
 *   1) 词法层（html5_tokens.rl）扫描 -> token 流
 *   2) html5_xss_rules.rl 的 5 个规则入口在 token 类型数组上
 *      逐位置独立匹配（对齐 libinjection is_xss 主循环语义）
 *
 * 调用方只需 include html5_tokens.h / html5_xss_rules.h 并链接
 * libragel_sql（html5_tokens + html5_xss_rules 打包），无需 ragel。
 *
 * 用法：./html5_xss_scan '<payload>' [<payload>...]
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

typedef struct {
    const char* name;
    int (*match)(const int*, int, int, const H5Tok*, int*);
} RuleDef;

#define R(name) { #name, html5_xss_match_##name }
static const RuleDef RULES[] = {
    //R(black_tag),
    //R(black_attr),
    //R(black_url),
    //R(style_expr),
    //R(dangerous_comment),
    R(dangerous_js),
};
#undef R

static void scan_one(const char* data) {
    H5Tok tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_html5(data, strlen(data), tk, MAX_TOK);
    for (int i = 0; i < n; ++i) {
        types[i] = (int)tk[i].type;
    }

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; ++i) {
        printf(" %s", h5_tok_name(tk[i].type));
    }
    printf("\n");

    size_t n_rules = sizeof(RULES) / sizeof(RULES[0]);
    for (int s = 0; s < n; ++s) {
        for (size_t r = 0; r < n_rules; ++r) {
            int e = 0;
            if (RULES[r].match(types, n, s, tk, &e) && e > 0) {
                char buf[256];
                range_text(tk, s, s + e, buf, sizeof(buf));
                printf("  !! %s [%d,%d) \"%s\"\n", RULES[r].name, s, s + e, buf);
            }
        }
    }
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [<payload>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; ++a) {
        scan_one(argv[a]);
    }
    return 0;
}
