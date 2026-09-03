/* ============================================================
 * sql_scan.c — SQLTokens + RuleSQL 的 Ragel 模拟演示
 * ------------------------------------------------------------
 * 对每个输入串：
 *   1) 词法层（sql_tokens.rl）扫描 -> token 流
 *   2) 语法层（rule_sql.rl）在 token 类型数组上逐位置匹配：
 *      expr / select_stmt / constant_value 骨架
 *   3) 若干代表性规则（对齐 sqli_rules.rl 语义）命中报告：
 *      always_true / string_tautology / boolean_injection /
 *      union_select / sleep / load_file / benchmark / pg_sleep
 *
 * 用法：./sql_scan '<payload>' [<payload>...]
 * ============================================================ */

#include <stdio.h>
#include <string.h>

#include "sql_tokens.h"
#include "rule_sql.h"

#define MAX_TOK 1024

/* 结构骨架验证：从每个位置尝试，打印最长命中区间 */
static void dump_skeleton(const Token* tk, const int* types, int n) {
    (void)tk;
    int best_s = -1, best_e = -1;
    const char* best_kind = NULL;
    for (int s = 0; s < n; ++s) {
        int len = 0;
        if (sql_match_expr(types, n, s, &len) && len > best_e - best_s) {
            best_s = s; best_e = s + len; best_kind = "expr";
        }
        if (sql_match_select(types, n, s, &len) && len > best_e - best_s) {
            best_s = s; best_e = s + len; best_kind = "select_stmt";
        }
        if (sql_match_const(types, n, s, &len) && len > best_e - best_s) {
            best_s = s; best_e = s + len; best_kind = "constant_value";
        }
    }
    if (best_s >= 0) {
        printf("  skeleton: %s [%d,%d)\n", best_kind, best_s, best_e);
    }
}

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
 * 规则匹配（对齐 sqli_rules.g4 的语义，使用 RuleSQL 骨架）
 * 注意：sql_match_* 返回的是"匹配长度"（len），不是绝对位置；
 * 绝对区间为 [start, start+len)。
 * ------------------------------------------------------------ */

/* [start, end) 是否恰好构成一个完整 expr？
 * 拷贝子区间到临时数组后做全量匹配（expr 机器是贪心的，直接对全数组
 * 匹配会越过 end；截断后机器看不到后续 token，从而精确判定）。 */
static int match_expr_span(const int* types, int n, int start, int end) {
    if (start >= end || end > n) return 0;
    int len = end - start;
    if (len > MAX_TOK) return 0;
    int tmp[MAX_TOK];
    for (int i = start; i < end; ++i) tmp[i - start] = types[i];
    int l;
    return sql_match_expr(tmp, len, 0, &l) && l == len;
}

/* always_true：constant_value EQ constant_value 且数值规范化相等 */
static int match_always_true(const Token* tk, const int* types, int n,
                             int start, int* e) {
    int l0;
    if (!sql_match_const(types, n, start, &l0)) return 0;
    int e0 = start + l0;
    if (e0 >= n || tk[e0].type != T_EQ) return 0;
    int l1;
    if (!sql_match_const(types, n, e0 + 1, &l1)) return 0;
    int e1 = e0 + 1 + l1;
    if (!sql_const_numbers_equal(tk, start, e0, e0 + 1, e1)) return 0;
    *e = e1;
    return 1;
}

/* string_tautology：constant_value EQ constant_value 且字符串相等 */
static int match_string_tautology(const Token* tk, const int* types, int n,
                                  int start, int* e) {
    int l0;
    if (!sql_match_const(types, n, start, &l0)) return 0;
    int e0 = start + l0;
    if (e0 >= n || tk[e0].type != T_EQ) return 0;
    int l1;
    if (!sql_match_const(types, n, e0 + 1, &l1)) return 0;
    int e1 = e0 + 1 + l1;
    if (!sql_const_strings_equal(tk, start, e0, e0 + 1, e1)) return 0;
    *e = e1;
    return 1;
}

/* boolean_injection：const_cmp (OR|AND) comparison 或反向 */
static int match_boolean_injection(const Token* tk, const int* types, int n,
                                   int start, int* e) {
    /* 方向 1：const_cmp (OR|AND) comparison（右侧贪心即可） */
    int l0;
    if (sql_match_const(types, n, start, &l0)) {
        int e0 = start + l0;
        if (e0 < n && tk[e0].type == T_EQ) {
            int l1;
            if (sql_match_const(types, n, e0 + 1, &l1)) {
                int e1 = e0 + 1 + l1;
                if (e1 < n && (tk[e1].type == T_OR || tk[e1].type == T_AND)) {
                    int l2;
                    if (sql_match_expr(types, n, e1 + 1, &l2)) {
                        *e = e1 + 1 + l2;
                        return 1;
                    }
                }
            }
        }
    }
    /* 方向 2：comparison (OR|AND) const_cmp。
     * comparison 在遇到 OR/AND 时必须精确结束（贪心 expr 会越过），
     * 故在 [start+1, n) 找 OR/AND，用截断匹配验证左侧是完整 expr，
     * 右侧要求 constant_value EQ constant_value。 */
    for (int k = start + 1; k + 1 < n; ++k) {
        if (tk[k].type != T_OR && tk[k].type != T_AND) continue;
        if (match_expr_span(types, n, start, k)) {
            int lc0;
            if (sql_match_const(types, n, k + 1, &lc0)) {
                int c0 = k + 1 + lc0;
                if (c0 < n && tk[c0].type == T_EQ) {
                    int lc1;
                    if (sql_match_const(types, n, c0 + 1, &lc1)) {
                        *e = c0 + 1 + lc1;
                        return 1;
                    }
                }
            }
        }
    }
    return 0;
}

/* union_select：UNION ALL? SELECT（union_select_pat 的骨架部分） */
static int match_union_select(const Token* tk, int n, int start, int* e) {
    int i = start;
    if (i >= n || tk[i].type != T_UNION) return 0;
    i++;
    if (i < n && tk[i].type == T_ALL) i++;
    if (i < n && tk[i].type == T_SELECT) { *e = i + 1; return 1; }
    return 0;
}

/* sleep / load_file / benchmark / pg_sleep：IDENT( ...（isIdent 谓词） */
static int match_func_call(const Token* tk, int n, int start, int* e,
                           const char* name) {
    if (start >= n || !sql_is_ident(&tk[start], name)) return 0;
    if (start + 1 >= n || tk[start + 1].type != T_LPAREN) return 0;
    *e = start + 2;
    return 1;
}

static void scan_one(const char* data) {
    Token tk[MAX_TOK];
    int types[MAX_TOK];
    int n = lex_sql(data, strlen(data), tk, MAX_TOK);
    for (int i = 0; i < n; ++i) {
        types[i] = (int)tk[i].type;
    }

    printf("input: %s\n", data);
    printf("tokens(%d):", n);
    for (int i = 0; i < n; ++i) {
        printf(" %s", tok_name(tk[i].type));
    }
    printf("\n");
    for (int i = 0; i < n; ++i) {
        printf("  [%d] %-8s \"%.*s\"\n", i, tok_name(tk[i].type),
               tk[i].len, tk[i].s);
    }

    dump_skeleton(tk, types, n);

    /* 逐位置尝试各规则（对齐 validate_sqli.sh 的命中语义） */
    for (int s = 0; s < n; ++s) {
        int e = 0;
        if (match_always_true(tk, types, n, s, &e)) {
            char buf[256];
            range_text(tk, s, e, buf, sizeof(buf));
            printf("  !! always_true [%d,%d) \"%s\"\n", s, e, buf);
        }
        if (match_string_tautology(tk, types, n, s, &e)) {
            char buf[256];
            range_text(tk, s, e, buf, sizeof(buf));
            printf("  !! string_tautology [%d,%d) \"%s\"\n", s, e, buf);
        }
        if (match_boolean_injection(tk, types, n, s, &e)) {
            char buf[256];
            range_text(tk, s, e, buf, sizeof(buf));
            printf("  !! boolean_injection [%d,%d) \"%s\"\n", s, e, buf);
        }
        if (match_union_select(tk, n, s, &e)) {
            printf("  !! union_select [%d,%d)\n", s, e);
        }
        if (match_func_call(tk, n, s, &e, "sleep")) {
            printf("  !! sleep [%d,%d)\n", s, e);
        }
        if (match_func_call(tk, n, s, &e, "load_file")) {
            printf("  !! load_file [%d,%d)\n", s, e);
        }
        if (match_func_call(tk, n, s, &e, "benchmark")) {
            printf("  !! benchmark [%d,%d)\n", s, e);
        }
        if (match_func_call(tk, n, s, &e, "pg_sleep")) {
            printf("  !! pg_sleep [%d,%d)\n", s, e);
        }
    }
    printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <payload> [<payload>...]\n", argv[0]);
        return 2;
    }
    for (int a = 1; a < argc; ++a) {
        scan_one(argv[a]);
    }
    return 0;
}
