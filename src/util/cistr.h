/* ============================================================
 * cistr.h — 大小写不敏感的字符串比较与查找
 * ------------------------------------------------------------
 * 各模块（HTML 分词、JS 危险名、SQL 关键字、log4j 前缀）都要做
 * "忽略大小写比对一段文本"，这里提供唯一实现，避免各抄一份。
 *
 * 统一约定：
 *   - 被查文本用 (指针, 长度) 描述，不一定以 '\0' 结尾 —— 常见于
 *     从输入缓冲区里切出来的一段（token 原文）；
 *   - 用于比对的 pattern 以 '\0' 结尾，函数自己算长度；
 *   - 参数顺序一律 (文本, 文本长度, pattern)，两个 e 系列函数也一样，
 *     避免"参数顺序不一样"这类易错点。
 * ============================================================ */
#ifndef RAGEL_CISTR_H
#define RAGEL_CISTR_H

/* s[0..len) 与 pat 是否完全相等（忽略大小写；pat 以 '\0' 结尾） */
int ci_eq(const char* s, int len, const char* pat);

/* 定长比较 s[0..len) 与 pat[0..len)（忽略大小写）。
 * pat 不要求以 '\0' 结尾 —— 两边都来自输入缓冲区时用这个。 */
int ci_eq_n(const char* s, int len, const char* pat);

/* s[0..len) 是否以 pat 开头（忽略大小写；pat 以 '\0' 结尾） */
int ci_prefix(const char* s, int len, const char* pat);

/* 在 hay[0..haylen) 中查找 needle（忽略大小写；needle 以 '\0' 结尾）。
 * 返回首次出现的下标，找不到返回 -1。 */
int ci_find(const char* hay, int haylen, const char* needle);

#endif /* RAGEL_CISTR_H */
