/* ============================================================
 * bench.c — 各检测模块的性能测试（纯匹配，不含 printf I/O）
 * ------------------------------------------------------------
 * 复刻各驱动（*_scan.c）的"起点循环 × 规则循环"匹配逻辑，去掉所有
 * 打印，测 lex + 规则匹配的纯计算耗时。
 *
 * 用法：
 *   ./bench [N]        # N = 每项 payload 重复次数，默认 300000
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "sql_tokens.h"
#include "sqli_rules.h"
#include "html5_tokens.h"
#include "html5_xss_rules.h"

#define MAX_TOK 1024

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* sqli：复刻 sqli_scan.c 的匹配（24 规则 × 起点，无打印），返回命中数 */
static int sqli_once(const char* s) {
    Token tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_sql(s, strlen(s), tk, MAX_TOK);
    for (int i = 0; i < n; i++) types[i] = (int)tk[i].type;

    SqliCtx ctx[SQLI_NUM_ENTRIES];
    for (int r = 0; r < SQLI_NUM_ENTRIES; r++) sqli_ctx_init(&ctx[r], r);

    int hits = 0;
    for (int st = 0; st < n; st++)
        for (int r = 0; r < SQLI_NUM_ENTRIES; r++) {
            sqli_ctx_reset(&ctx[r]);
            sqli_ctx_feed(&ctx[r], types + st, tk + st, n - st, NULL);
            if (sqli_ctx_alive(&ctx[r])) sqli_ctx_finish(&ctx[r], NULL);
            if (ctx[r].match_len > 0) hits++;
        }

    for (int r = 0; r < SQLI_NUM_ENTRIES; r++) sqli_ctx_clean(&ctx[r]);
    return hits;
}

/* xss：复刻 html5_xss_scan.c 的匹配（6 规则 × 起点，无打印） */
static int xss_once(const char* s) {
    H5Tok tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_html5(s, strlen(s), tk, MAX_TOK);
    for (int i = 0; i < n; i++) types[i] = (int)tk[i].type;

    H5XssCtx ctx[H5XSS_NUM_ENTRIES];
    for (int r = 0; r < H5XSS_NUM_ENTRIES; r++) h5xss_ctx_init(&ctx[r], r);

    int hits = 0;
    for (int st = 0; st < n; st++)
        for (int r = 0; r < H5XSS_NUM_ENTRIES; r++) {
            h5xss_ctx_reset(&ctx[r]);
            h5xss_ctx_feed(&ctx[r], types + st, tk + st, n - st, NULL);
            if (h5xss_ctx_alive(&ctx[r])) h5xss_ctx_finish(&ctx[r], NULL);
            if (ctx[r].match_len > 0) hits++;
        }

    for (int r = 0; r < H5XSS_NUM_ENTRIES; r++) h5xss_ctx_clean(&ctx[r]);
    return hits;
}

typedef struct {
    const char* name;
    int (*fn)(const char*);
    const char* payload;
} Case;

static const Case CASES[] = {
    { "sqli 恒真",      sqli_once, "1=1 OR 1=2" },
    { "sqli 时间盲注",   sqli_once, "SLEEP(5)" },
    { "sqli 嵌套子查询", sqli_once, "(SELECT * FROM (SELECT 1))" },
    { "sqli 正常SQL",    sqli_once, "SELECT * FROM users WHERE id=1" },
    { "xss 事件属性",    xss_once, "<img onerror=alert(1)>" },
    { "xss 危险JS",      xss_once, "<script>window[\"eval\"](\"alert(1)\")</script>" },
    { "xss 正常HTML",    xss_once, "<div class=\"x\">hello</div>" },
};

int main(int argc, char** argv) {
    int N = argc > 1 ? atoi(argv[1]) : 300000;
    size_t n_cases = sizeof(CASES) / sizeof(CASES[0]);

    printf("每项 payload 重复 %d 次（纯匹配，不含打印）\n\n", N);
    printf("%-14s %-42s %10s %12s\n", "场景", "payload", "单次", "吞吐");
    printf("%-14s %-42s %10s %12s\n", "----", "-------", "----", "----");

    long total_hits = 0;
    for (size_t i = 0; i < n_cases; i++) {
        double t0 = now_us();
        int hits = 0;
        for (int k = 0; k < N; k++) hits += CASES[i].fn(CASES[i].payload);
        double t1 = now_us();
        double us = (t1 - t0) / N;
        total_hits += hits;
        printf("%-14s %-42s %7.3f us %10.0f/s\n",
               CASES[i].name, CASES[i].payload, us, 1e6 / us);
    }
    printf("\n总命中（校验匹配确实在跑）: %ld\n", total_hits);
    return 0;
}
