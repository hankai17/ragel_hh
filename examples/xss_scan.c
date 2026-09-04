/* ============================================================
 * xss_scan.c — xss_rules.rl（5 条 XSS 攻击规则）的调用示例
 * ------------------------------------------------------------
 * 位于 examples/，演示"调用方视角"：
 *   1) 词法层（xss_tokens.rl）扫描 -> token 流
 *   2) xss_rules.rl 的 5 个规则入口在 token 类型数组上逐位置匹配
 *
 * 调用方只需 include xss_tokens.h / xss_rules.h 并链接
 * libragel_sql（含 xss_rules），无需 ragel。
 *
 * 用法：./xss_scan '<payload>' [<payload>...]
 * ============================================================ */

#include <stdio.h>
#include <string.h>

#include "xss_tokens.h"
#include "xss_rules.h"

#define MAX_TOK 1024

typedef struct {
    const char* name;
    int (*match)(const int*, int, int, const XssTok*, int*);
} XssRuleDef;

#define R(name) { #name, xss_match_##name }
static const XssRuleDef XSS_RULES[] = {
    R(script_tag),
    R(dangerous_tag),
    R(event_handler),
    R(js_uri),
    R(entity_lt),
};
#undef R

static void scan_one(const char* data) {
    XssTok tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_xss(data, strlen(data), tk, MAX_TOK);
    for (int i = 0; i < n; ++i) types[i] = (int)tk[i].type;

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; ++i) printf(" %s", xss_tok_name(tk[i].type));
    printf("\n");

    size_t nr = sizeof(XSS_RULES) / sizeof(XSS_RULES[0]);
    for (int s = 0; s < n; ++s) {
        for (size_t r = 0; r < nr; ++r) {
            int e = 0;
            if (XSS_RULES[r].match(types, n, s, tk, &e) && e > 0)
                printf("  !! %s [%d,%d)\n", XSS_RULES[r].name, s, s + e);
        }
    }
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [<payload>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; ++a) scan_one(argv[a]);
    return 0;
}
