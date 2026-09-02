/* ============================================================
 * sqli_scan.c — sqli_rules.g4（24 条攻击规则）的 Ragel 模拟驱动
 * ------------------------------------------------------------
 * 对每个输入串：
 *   1) 词法层（sql_tokens.rl）扫描 -> token 流
 *   2) sqli_rules.rl 的 24 个规则入口在 token 类型数组上
 *      逐位置独立匹配（对齐 rulec/wrapper 逐条匹配语义）
 *   3) 语义谓词分工：
 *      - isIdent（sleep/load_file/benchmark/pg_sleep/
 *        db_enumeration）在 rl 动作内判定
 *      - constNumbersEqual / constStringsEqual（always_true /
 *        string_tautology）在此复核：rl 只保证结构，本层用
 *        sql_match_const 求两侧 constant_value 区间并判等
 *
 * 用法：./sqli_scan '<payload>' [<payload>...]
 * ============================================================ */

#include <stdio.h>
#include <string.h>

#include "sql_tokens.h"

/* sqli_rules.rl：24 个规则入口（结构匹配 + isIdent 谓词） */
#define SQLI_ENTRY(name) \
    extern int sql_match_sqli_##name(const int* types, int n, int start, \
                                     const Token* tk, int* len);
SQLI_ENTRY(always_true)
SQLI_ENTRY(string_tautology)
SQLI_ENTRY(boolean_injection)
SQLI_ENTRY(union_select)
SQLI_ENTRY(stacked_query)
SQLI_ENTRY(sleep)
SQLI_ENTRY(load_file)
SQLI_ENTRY(benchmark)
SQLI_ENTRY(pg_sleep)
SQLI_ENTRY(subquery)
SQLI_ENTRY(exists_subquery)
SQLI_ENTRY(in_subquery)
SQLI_ENTRY(like_expr)
SQLI_ENTRY(between_expr)
SQLI_ENTRY(numeric_expr)
SQLI_ENTRY(order_by_expr)
SQLI_ENTRY(limit_expr)
SQLI_ENTRY(string_concat)
SQLI_ENTRY(insert_fragment)
SQLI_ENTRY(update_fragment)
SQLI_ENTRY(delete_fragment)
SQLI_ENTRY(select_fragment)
SQLI_ENTRY(select_from_fragment)
SQLI_ENTRY(db_enumeration)
#undef SQLI_ENTRY

/* rule_sql.rl：constant_value 骨架 + 常量相等谓词（谓词复核用） */
extern int sql_match_const(const int* types, int n, int start, int* len);
extern int sql_const_numbers_equal(const Token* tk, int s0, int e0,
                                   int s1, int e1);
extern int sql_const_strings_equal(const Token* tk, int s0, int e0,
                                   int s1, int e1);

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

/* 规则表：name + rl 入口 + 谓词复核类型（0 无 / 1 数值 / 2 字符串） */
typedef struct {
    const char* name;
    int (*match)(const int*, int, int, const Token*, int*);
    int pred;
} RuleDef;

#define R(name) { #name, sql_match_sqli_##name, 0 }
#define R_NUM(name) { #name, sql_match_sqli_##name, 1 }
#define R_STR(name) { #name, sql_match_sqli_##name, 2 }
static const RuleDef RULES[] = {
    R_NUM(always_true),
    R_STR(string_tautology),
    R(boolean_injection),
    R(union_select),
    R(stacked_query),
    R(sleep),
    R(load_file),
    R(benchmark),
    R(pg_sleep),
    R(subquery),
    R(exists_subquery),
    R(in_subquery),
    R(like_expr),
    R(between_expr),
    R(numeric_expr),
    R(order_by_expr),
    R(limit_expr),
    R(string_concat),
    R(insert_fragment),
    R(update_fragment),
    R(delete_fragment),
    R(select_fragment),
    R(select_from_fragment),
    R(db_enumeration),
};
#undef R
#undef R_NUM
#undef R_STR

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

    size_t n_rules = sizeof(RULES) / sizeof(RULES[0]);
    for (int s = 0; s < n; ++s) {
        for (size_t r = 0; r < n_rules; ++r) {
            int e = 0;
            if (RULES[r].match(types, n, s, tk, &e) && e > 0) {
                /* 谓词复核：结构命中 + 常量相等才上报 */
                if (RULES[r].pred == 1 && !check_num_pred(tk, types, n, s, e))
                    continue;
                if (RULES[r].pred == 2 && !check_str_pred(tk, types, n, s, e))
                    continue;
                char buf[256];
                range_text(tk, s, e, buf, sizeof(buf));
                printf("  !! %s [%d,%d) \"%s\"\n", RULES[r].name, s, e, buf);
            }
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
