/* ============================================================
 * log4j_scan.c — log4j 查找表达式驱动（调用 rules/ragel/log4j_lookup 库）
 * ------------------------------------------------------------
 * 对每个输入串调用 log4j_scan() 收集命中并打印分类：
 *   JNDI / SENSITIVE[（前缀）] / CHAIN / EXPR，无命中打印 (none)。
 * 输出格式与 antlr4 版 validate_log4j.sh 断言对齐。
 *
 * 用法：./log4j_scan '<payload>' [<payload>...]
 * 构建：与 log4j_lookup.c（由 log4j_lookup.rl 生成）链接。
 * ============================================================ */

#include <stdio.h>
#include <string.h>

#include "log4j_lookup.h"

#define MAX_HITS 64

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [<payload>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; ++a) {
        const char* data = argv[a];
        printf("input: %s\n", data);
        Log4jHit hits[MAX_HITS];
        int n = log4j_scan(data, strlen(data), hits, MAX_HITS);
        for (int i = 0; i < n; ++i) {
            char label[96];
            const Log4jHit* h = &hits[i];
            if (strcmp(h->cls, "SENSITIVE") == 0 && h->detail[0]) {
                snprintf(label, sizeof(label), "%s(%s)", h->cls, h->detail);
            } else {
                snprintf(label, sizeof(label), "%s", h->cls);
            }
            printf("  [%s] \"%.*s\"\n", label, h->len, h->s);
        }
        if (n == 0) printf("  (none)\n");
        printf("\n");
    }
    return 0;
}
