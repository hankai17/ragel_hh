/* ============================================================
 * esc.c — 十六进制位与 \u 转义解析
 * ------------------------------------------------------------
 * 见 esc.h。u_esc_parse 两种形式：
 *   \u0061        固定 4 位十六进制
 *   \u{61}        花括号内 1~6 位（ES6），码点上限 U+10FFFF
 * ============================================================ */

#include "esc.h"

int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int u_esc_parse(const char* p, int len, int* adv) {
    int cp = -1, a = 0;

    if (len < 2 || p[0] != '\\' || p[1] != 'u') return -1;

    if (len > 2 && p[2] == '{') {          /* \u{XXXXXX}：花括号内任意位 */
        int j = 3, v = 0, any = 0;
        while (j < len && p[j] != '}') {
            int h = hex_val(p[j]);
            if (h < 0) break;
            v = (v << 4) | h;
            any = 1;
            ++j;
        }
        if (any && j < len && p[j] == '}') { cp = v; a = j + 1; }
    } else if (len >= 6) {                 /* \uXXXX：固定 4 位 */
        int k, v = 0, ok = 1;
        for (k = 0; k < 4; ++k) {
            int h = hex_val(p[2 + k]);
            if (h < 0) { ok = 0; break; }
            v = (v << 4) | h;
        }
        if (ok) { cp = v; a = 6; }
    }

    if (cp < 0 || cp > 0x10FFFF) return -1;
    *adv = a;
    return cp;
}
