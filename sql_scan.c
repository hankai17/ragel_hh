/*
 * sql_scan.c
 *
 * 用法：./sql_scan '<sql>' [<sql>...]
 *
 * 对每条输入：
 *   1. sql_tokens 词法扫出 token 流
 *   2. rule_sql 的三个骨架入口（expr / select_stmt / constant_value）
 *      在 token 流上逐位置尝试，打印各自的最长命中
 *
 * select_stmt 命中区间恰好覆盖全部 token 时标 (whole)，
 * 表示输入被识别为一条完整的 SELECT 语句。
 */

#include <stdio.h>
#include <string.h>

#include "sql_tokens.h"
#include "rule_sql.h"

#define MAX_TOK 1024

/* 用 match 从每个 token 位置试匹配，打印该类骨架的最长命中 */
static void dump_one(const char* kind, const int* types, int n,
                     int (*match)(const int*, int, int, int*), int check_whole) {
    int bs = -1, be = 0, len;

    for (int s = 0; s < n; s++) {
        if (match(types, n, s, &len) && len > be - bs) {
            bs = s;
            be = s + len;
        }
    }
    if (bs < 0)
        return;
    if (check_whole && bs == 0 && be == n)
        printf("  %s [%d,%d) (whole)\n", kind, bs, be);
    else
        printf("  %s [%d,%d)\n", kind, bs, be);
}

static void scan_one(const char* data) {
    Token tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_sql(data, strlen(data), tk, MAX_TOK);

    for (int i = 0; i < n; i++)
        types[i] = (int)tk[i].type;

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; i++)
        printf(" %s", tok_name(tk[i].type));
    printf("\n");

    dump_one("expr", types, n, sql_match_expr, 0);
    dump_one("select_stmt", types, n, sql_match_select, 1);
    dump_one("constant_value", types, n, sql_match_const, 0);
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s '<sql>' [<sql>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; a++)
        scan_one(argv[a]);
    return 0;
}
