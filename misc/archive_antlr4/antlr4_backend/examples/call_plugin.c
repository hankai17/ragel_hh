/*
 * 最小动态库调用示例（纯 C，dlopen 方式）
 * ------------------------------------------------------------
 * 构建：cmake --build build --target example_call_plugin
 * 运行：./build/example_call_plugin [可选测试串]
 *       （默认测试串见 TEST_INPUT；插件路径见 PLUGIN_PATH）
 *
 * 展示如何调用规则插件 .so 的 C 接口：
 *   int         rule_abi()               版本号
 *   int         rule_attack_count()      插件包含的攻击数量
 *   AttackInfo* rule_attack(int i)       第 i 个攻击元信息
 *   int         rule_check_text(text, matched, startOff, endOff, max)
 *                                        返回命中攻击索引数与字符区间
 *
 * 注意：本例直接调插件接口，不做引擎的画像门控
 * （fragment/raw 攻击在引擎里仅在输入不是完整 SQL 时生效）。
 */
#include <dlfcn.h>
#include <stdio.h>
#include <string.h>

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
#define PLUGIN_PATH "./build/plugins/libsqli_rules.so"
#define TEST_INPUT  "SELECT * FROM users WHERE 1=1"
#define MAX_MATCHES 16
#define RULE_ABI    6

int main(int argc, char* argv[]) {
    const char* input = argc > 1 ? argv[1] : TEST_INPUT;

    void* h = dlopen(PLUGIN_PATH, RTLD_NOW);
    if (!h) {
        fprintf(stderr, "dlopen failed: %s\n", dlerror());
        return 1;
    }

    abi_fn abi = (abi_fn)dlsym(h, "rule_abi");
    count_fn count = (count_fn)dlsym(h, "rule_attack_count");
    info_fn info = (info_fn)dlsym(h, "rule_attack");
    check_fn check = (check_fn)dlsym(h, "rule_check_text");
    if (!abi || !count || !info || !check) {
        fprintf(stderr, "dlsym failed: %s\n", dlerror());
        return 1;
    }

    if (abi() != RULE_ABI) {
        fprintf(stderr, "ABI mismatch: plugin=%d, expected=%d\n", abi(), RULE_ABI);
        return 1;
    }

    printf("ABI: %d, attacks: %d\n", abi(), count());
    printf("input: %s\n\n", input);

    int matched[MAX_MATCHES], startOff[MAX_MATCHES], endOff[MAX_MATCHES];
    int n = check(input, matched, startOff, endOff, MAX_MATCHES);
    for (int i = 0; i < n; ++i) {
        const AttackInfo* a = info(matched[i]);
        if (!a) continue;
        printf("attack: %s [%s] %s\n", a->name, a->severity, a->description);
        if (startOff[i] >= 0 && endOff[i] >= startOff[i] &&
            endOff[i] < (int)strlen(input)) {
            printf("        matched: %.*s\n",
                   endOff[i] - startOff[i] + 1, input + startOff[i]);
        }
    }
    printf("\ntotal matched: %d\n", n);

    dlclose(h);
    return 0;
}
