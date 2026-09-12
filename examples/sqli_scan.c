/* ============================================================
 * sqli_scan.c — sqli_rules.rl（24 条 SQLi 攻击规则）的调用示例
 * ------------------------------------------------------------
 * 演示"调用方视角"：每个请求、每条规则一个 CTX（SqliCtx ctx[24]），
 * 驱动只做三步 —— 初始化 -> 扫描 -> 清除，起点循环由 CTX 自己推进，
 * 调用方不传起点、也不记位置。
 *
 *   chunk = 0（默认）  一次喂到输入末尾（批处理）
 *   chunk > 0（-c N）  每次喂 N 个 token、续跑（演示"后续 token 接着跑"）
 *
 * 谓词分工：
 *   - isIdent（sleep/load_file/benchmark/pg_sleep/db_enumeration）在 rl 内判定；
 *   - constNumbersEqual / constStringsEqual（always_true / string_tautology）
 *     在本文件复核：rl 只保证结构，本层求两侧 constant_value 区间并判等。
 *
 * 调用方只需 include sql_tokens.h / sql_syntax.h / sqli_rules.h 并链接
 * libragel_sql，无需 ragel。
 *
 * 用法：
 *   ./sqli_scan '<payload>' [<payload>...]
 *   ./sqli_scan -c 3 '<payload>' [<payload>...]
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sql_tokens.h"
#include "sql_syntax.h"
#include "sqli_rules.h"

#define MAX_TOK 1024

/* 区间 [s,e) 的 token 原文（空格连接） */
static void range_text(const Token* tk, int s, int e, char* out, size_t cap) {
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

/* ------------------------------------------------------------
 * 谓词复核（always_true / string_tautology）：
 * rl 命中区间 [s,e) 已保证 constant_value EQ constant_value 结构，
 * 这里求两侧区间并做数值/字符串规范化相等判定。
 * ------------------------------------------------------------ */
static int check_num_pred(const Token* tk, const int* types, int n,
                          int s, int e) {
    int l0;
    if (!sql_match_const(types, n, s, &l0)) return 0;
    int e0 = s + l0;
    if (e0 >= n || types[e0] != T_EQ) return 0;
    int l1;
    if (!sql_match_const(types, n, e0 + 1, &l1)) return 0;
    int e1 = e0 + 1 + l1;
    if (e1 - s != e) return 0;
    return sql_const_numbers_equal(tk, s, e0, e0 + 1, e1);
}

static int check_str_pred(const Token* tk, const int* types, int n,
                          int s, int e) {
    int l0;
    if (!sql_match_const(types, n, s, &l0)) return 0;
    int e0 = s + l0;
    if (e0 >= n || types[e0] != T_EQ) return 0;
    int l1;
    if (!sql_match_const(types, n, e0 + 1, &l1)) return 0;
    int e1 = e0 + 1 + l1;
    if (e1 - s != e) return 0;
    return sql_const_strings_equal(tk, s, e0, e0 + 1, e1);
}

/* 命中上报（含谓词复核）；s/e 是全局 token 下标 [s, e) */
static void report(const Token* tk, const int* types, int n,
                   int rule, int s, int e) {
    /* 谓词复核要的是长度，不是结束下标 */
    int len = e - s;
    if (SQLI_RULES[rule].pred == 1 && !check_num_pred(tk, types, n, s, len)) return;
    if (SQLI_RULES[rule].pred == 2 && !check_str_pred(tk, types, n, s, len)) return;
    char buf[256];
    range_text(tk, s, e, buf, sizeof(buf));
    printf("  !! %s [%d,%d) \"%s\"\n", SQLI_RULES[rule].name, s, e, buf);
}

/* 词法 + 头部打印：两种模式共用 */
static int lex_and_print(const char* data, Token* tk, int* types) {
    int n = lex_sql(data, strlen(data), tk, MAX_TOK);
    for (int i = 0; i < n; ++i) types[i] = (int)tk[i].type;

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; ++i) printf(" %s", tok_name(tk[i].type));
    printf("\n");
    return n;
}

/* ------------------------------------------------------------
 * 每个请求：每条规则一个 CTX。驱动只做 init -> scan -> clean，
 * 起点循环由 CTX 自己推进（sqli_ctx_scan），调用方不传起点。
 *   chunk <= 0：一次喂到输入末尾；chunk > 0：每次喂 chunk 个 token、续跑。
 * ------------------------------------------------------------ */
static void scan(const char* data, int chunk) {
    Token tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_and_print(data, tk, types);

    SqliCtx ctx[SQLI_NUM_ENTRIES];
    for (int r = 0; r < SQLI_NUM_ENTRIES; ++r)
        sqli_ctx_init(&ctx[r], r);                       /* 1) 初始化 */

    for (int r = 0; r < SQLI_NUM_ENTRIES; ++r) {
        while (sqli_ctx_scan(&ctx[r], types, tk, n, chunk))   /* 2) 扫描 */
            report(tk, types, n, r, ctx[r].start, ctx[r].start + ctx[r].match_len);
    }

    for (int r = 0; r < SQLI_NUM_ENTRIES; ++r)
        sqli_ctx_clean(&ctx[r]);                         /* 3) 清除 */

    printf("\n");
}

int main(int argc, char** argv) {
    int chunk = 0;          /* 0 = 一次喂到末尾 */
    int a = 1;

    if (argc >= 2 && strcmp(argv[1], "-c") == 0) {
        if (argc < 4) {
            fprintf(stderr, "usage: %s [-c <chunk>] <payload> [<payload>...]\n",
                    argv[0]);
            return 2;
        }
        chunk = atoi(argv[2]);
        if (chunk < 1) chunk = 1;
        a = 3;
    }
    if (a >= argc) {
        fprintf(stderr, "usage: %s [-c <chunk>] <payload> [<payload>...]\n",
                argv[0]);
        return 2;
    }

    for (; a < argc; ++a)
        scan(argv[a], chunk);
    return 0;
}
