/*
 * js_scan.c — JavaScript 表达式语法骨架（js_syntax.rl）的调用示例
 *
 * 用法：./js_scan '<js>' [<js>...]
 *
 * 对每条输入：
 *   1. js_tokens 词法扫出 token 流
 *   2. js_syntax 的 expr 入口在 token 流上逐位置尝试，打印最长命中
 *
 * expr 命中区间恰好覆盖全部 token 时标 (whole)，
 * 表示输入被识别为一条完整的 JS 表达式。
 */

#include <stdio.h>
#include <string.h>

#include "js_tokens.h"
#include "js_syntax.h"

#define MAX_TOK 1024

static void dump_expr(const int* types, int n) {
    int bs = -1, be = 0, len;

    for (int s = 0; s < n; s++) {
        if (js_match_expr(types, n, s, &len) && (bs < 0 || len > be - bs)) {
            bs = s;
            be = s + len;
        }
    }
    if (bs < 0)
        return;
    if (bs == 0 && be == n)
        printf("  expr [%d,%d) (whole)\n", bs, be);
    else
        printf("  expr [%d,%d)\n", bs, be);
}

static void scan_one(const char* data) {
    JsTok tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_js(data, strlen(data), tk, MAX_TOK);

    for (int i = 0; i < n; i++)
        types[i] = (int)tk[i].type;

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; i++)
        printf(" %s", js_tok_name(tk[i].type));
    printf("\n");

    dump_expr(types, n);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s '<js>' [<js>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; a++)
        scan_one(argv[a]);
    return 0;
}
