/* ============================================================
 * cistr.c — 大小写不敏感的字符串比较与查找
 * ------------------------------------------------------------
 * 见 cistr.h。比较一律走 unsigned char + tolower，避免高位字节
 * 被当成负下标（中文等多字节内容也安全）。
 * ============================================================ */

#include <ctype.h>
#include <string.h>

#include "cistr.h"

static int lower(int c) {
    return tolower((unsigned char)c);
}

int ci_eq(const char* s, int len, const char* pat) {
    for (int i = 0; i < len; ++i) {
        if (pat[i] == '\0') return 0;          /* pat 更短 */
        if (lower(s[i]) != lower(pat[i])) return 0;
    }
    return pat[len] == '\0';                    /* pat 不能更长 */
}

int ci_eq_n(const char* s, int len, const char* pat) {
    for (int i = 0; i < len; ++i) {
        if (lower(s[i]) != lower(pat[i])) return 0;
    }
    return 1;
}

int ci_prefix(const char* s, int len, const char* pat) {
    for (int i = 0; pat[i]; ++i) {
        if (i >= len) return 0;                 /* s 比 pat 短 */
        if (lower(s[i]) != lower(pat[i])) return 0;
    }
    return 1;
}

int ci_find(const char* hay, int haylen, const char* needle) {
    int nlen = (int)strlen(needle);
    if (nlen == 0) return 0;                    /* 空 needle：视作在开头命中 */
    for (int i = 0; i + nlen <= haylen; ++i) {
        int j;
        for (j = 0; j < nlen; ++j) {
            if (lower(hay[i + j]) != lower(needle[j])) break;
        }
        if (j == nlen) return i;
    }
    return -1;
}
