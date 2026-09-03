// ============================================================
// bench_log4j_plugin — log4j 规则插件微基准
// ------------------------------------------------------------
// 对同一 payload 连续调用 liblog4j_rules.so 的 rule_check_text
// N 次（同一进程，避开 dlopen/进程启动开销），打印每次调用平均
// 耗时（ns）。
//
// 与正则侧（grep -P 单进程 N 行）对等：都测"单请求深检"的
// 进程内匹配成本。注意这是插件深检成本（词法 + 滑窗 + 解析），
// 不含引擎 fast-path 预筛层。
//
// usage: bench_log4j_plugin <plugin.so> <payload> <iterations>
// ============================================================

#include <dlfcn.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>

using CheckFn = int (*)(const char*, int*, int*, int*, int);

int main(int argc, char** argv) {
    if (argc < 4) {
        std::fprintf(stderr,
                     "usage: %s <plugin.so> <payload> <iterations>\n", argv[0]);
        return 2;
    }
    const char* plugin = argv[1];
    const char* payload = argv[2];
    const int n = std::atoi(argv[3]);
    if (n <= 0) return 2;

    void* h = dlopen(plugin, RTLD_NOW);
    if (!h) {
        std::fprintf(stderr, "dlopen: %s\n", dlerror());
        return 1;
    }
    auto check = reinterpret_cast<CheckFn>(dlsym(h, "rule_check_text"));
    if (!check) {
        std::fprintf(stderr, "dlsym: %s\n", dlerror());
        return 1;
    }

    int matched[64], startOff[64], endOff[64];
    for (int i = 0; i < 10; ++i) check(payload, matched, startOff, endOff, 64);  // warmup

    const auto t0 = std::chrono::steady_clock::now();
    for (int i = 0; i < n; ++i) check(payload, matched, startOff, endOff, 64);
    const auto t1 = std::chrono::steady_clock::now();
    const long long total_ns =
        std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    std::printf("%.1f\n", static_cast<double>(total_ns) / n);

    dlclose(h);
    return 0;
}
