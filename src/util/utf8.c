/* ============================================================
 * utf8.c — Unicode 码点 -> UTF-8 字节
 * ------------------------------------------------------------
 * 见 utf8.h。按 UTF-8 的 1~4 字节编码规则展开：
 *   < 0x80      1 字节  0xxxxxxx
 *   < 0x800     2 字节  110xxxxx 10xxxxxx
 *   < 0x10000   3 字节  1110xxxx 10xxxxxx 10xxxxxx
 *   其他        4 字节  11110xxx 10xxxxxx 10xxxxxx 10xxxxxx
 * ============================================================ */

#include "utf8.h"

int utf8_put(char* out, int cp) {
    if (cp < 0 || cp > 0x10FFFF) cp = 0xFFFD;   /* 非法码点按替换字符处理 */

    if (cp < 0x80) {
        out[0] = (char)cp;
        return 1;
    } else if (cp < 0x800) {
        out[0] = (char)(0xC0 | (cp >> 6));
        out[1] = (char)(0x80 | (cp & 0x3F));
        return 2;
    } else if (cp < 0x10000) {
        out[0] = (char)(0xE0 | (cp >> 12));
        out[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        out[2] = (char)(0x80 | (cp & 0x3F));
        return 3;
    }
    out[0] = (char)(0xF0 | (cp >> 18));
    out[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
    out[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
    out[3] = (char)(0x80 | (cp & 0x3F));
    return 4;
}
