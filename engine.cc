// ============================================================
// engine — 编译型规则引擎主程序
// ------------------------------------------------------------
// 请求处理流水线：
//   HTTP payload
//     -> Normalization（注释剥离、空白折叠）
//     -> Fast Path（廉价子串扫描，无命中直接 ALLOW，性能关键路径）
//     -> MiniSQL Parser（完整 SQL，ANTLR 解析）
//     -> Fragment Wrap（不完整 SQL：包装进合法上下文再解析，如 WHERE <payload>）
//     -> AST（语义中间层，规则不接触 SQL 文本）
//     -> Rule Engine（dlopen 加载的规则插件逐个 check）
//     -> ALLOW / BLOCK / UNKNOWN
// ============================================================

#include <dlfcn.h>
#include <glob.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "antlr4-runtime.h"
#include "MiniSQLLexer.h"
#include "MiniSQLParser.h"

#include "rule_plugin.h"

using namespace antlr4;

namespace {

// ------------------------------------------------------------
// Normalization
// ------------------------------------------------------------

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

// 原型级归一化：剥离 SQL 注释、折叠空白。
// 注意：这是朴素实现，不感知字符串字面量；生产版需按词法感知处理
// （URL 解码、charset、关键字混淆、等价空白等）。
std::string normalize(const std::string& raw) {
    std::string s = raw;

    // 块注释 /* ... */
    while (true) {
        size_t p = s.find("/*");
        if (p == std::string::npos) break;
        size_t q = s.find("*/", p + 2);
        if (q == std::string::npos) {
            s.erase(p);
            break;
        }
        s.erase(p, q + 2 - p);
    }

    // 行注释 -- ...（含 MySQL 变体 -- 后跟空白才生效，原型从宽）
    std::string out;
    for (size_t i = 0; i < s.size();) {
        if (s[i] == '-' && i + 1 < s.size() && s[i + 1] == '-') {
            while (i < s.size() && s[i] != '\n') ++i;
        } else {
            out += s[i++];
        }
    }

    // 空白折叠
    std::string collapsed;
    bool lastSpace = false;
    for (char ch : out) {
        if (std::isspace(static_cast<unsigned char>(ch))) {
            if (!lastSpace) collapsed += ' ';
            lastSpace = true;
        } else {
            collapsed += ch;
            lastSpace = false;
        }
    }
    return trim(collapsed);
}

std::string lower(std::string s) {
    for (auto& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// ------------------------------------------------------------
// 规则插件加载
// ------------------------------------------------------------

struct LoadedPlugin {
    void* handle = nullptr;
    std::vector<rule::AttackInfo> attacks;   // 插件包含的攻击类型
    int (*countFn)() = nullptr;
    const rule::AttackInfo* (*infoFn)(int) = nullptr;
    int (*checkText)(const char*, int*, int*, int*, int) = nullptr;  // 命中索引 + 字符区间
};

std::vector<std::string> listPlugins(const std::string& dir) {
    std::vector<std::string> files;
    glob_t g;
    std::string pattern = dir + "/*.so";
    if (glob(pattern.c_str(), 0, nullptr, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; ++i) files.emplace_back(g.gl_pathv[i]);
    }
    globfree(&g);
    std::sort(files.begin(), files.end());
    return files;
}

std::vector<LoadedPlugin> loadRules(const std::string& dir) {
    std::vector<LoadedPlugin> rules;
    for (const auto& path : listPlugins(dir)) {
        void* handle = dlopen(path.c_str(), RTLD_NOW | RTLD_LOCAL);
        if (!handle) {
            std::cerr << "[engine] load failed: " << path << " : " << dlerror() << "\n";
            continue;
        }

        auto abi = reinterpret_cast<int (*)()>(dlsym(handle, "rule_abi"));
        auto countFn = reinterpret_cast<int (*)()>(dlsym(handle, "rule_attack_count"));
        auto infoFn = reinterpret_cast<const rule::AttackInfo* (*)(int)>(
            dlsym(handle, "rule_attack"));
        auto checkText = reinterpret_cast<int (*)(const char*, int*, int*, int*, int)>(
            dlsym(handle, "rule_check_text"));
        if (!abi || !countFn || !infoFn || !checkText) {
            std::cerr << "[engine] bad plugin symbols: " << path << "\n";
            dlclose(handle);
            continue;
        }
        if (abi() != rule::RULE_ABI) {
            std::cerr << "[engine] ABI mismatch (plugin=" << abi()
                      << ", engine=" << rule::RULE_ABI << "): " << path << "\n";
            dlclose(handle);
            continue;
        }

        LoadedPlugin r;
        r.handle = handle;
        r.countFn = countFn;
        r.infoFn = infoFn;
        r.checkText = checkText;
        int n = countFn();
        for (int i = 0; i < n; ++i) {
            if (const rule::AttackInfo* a = infoFn(i)) r.attacks.push_back(*a);
        }
        if (r.attacks.empty()) {
            std::cerr << "[engine] plugin has no attacks: " << path << "\n";
            dlclose(handle);
            continue;
        }
        rules.push_back(std::move(r));
    }
    return rules;
}

// ------------------------------------------------------------
// Fast Path：廉价预筛层（原型用子串特征表，生产可升级为 DFA 状态机）
// ------------------------------------------------------------

const std::vector<std::string> kFastPathTokens = {
    // SQL 关键结构与注入惯用特征（命中才进入深检；无命中直接 ALLOW）
    "select", "union", "sleep(", "load_file", "benchmark",
    "information_schema", "0x",
    // 其他语句类型与堆叠查询
    "insert ", "update ", "delete ", "drop ", "alter ", "create ", ";",
    "||", "order by", "limit ",
    // 恒真 / 布尔盲注惯用词
    "=", "or ", "and ", "'", "--", "/*",
    // XSS
    "<script",
    // log4j 查找表达式（Log4Shell 类；命中才进入 log4j 规则深检）
    "${", "jndi:", "ldap://", "ldaps://", "rmi://", "dns://",
    "iiop://", "corba://", "env:", "sys:", "docker:", "k8s:", "aws:",
};

std::vector<std::string> fastPathHit(const std::string& normalized) {
    std::string hay = lower(normalized);
    std::vector<std::string> hits;
    for (const auto& tok : kFastPathTokens) {
        if (hay.find(tok) != std::string::npos) hits.push_back(tok);
    }
    return hits;
}

// ------------------------------------------------------------
// SQL 解析 -> AST
// ------------------------------------------------------------

// 完整 SQL 解析：只判定"是不是完整可解析的 SQL"（fullSqlOk 门控与 UNKNOWN 判定）
bool parseSql(const std::string& sql) {
    ANTLRInputStream input(sql);
    MiniSQLLexer lexer(&input);
    CommonTokenStream tokens(&lexer);
    MiniSQLParser parser(&tokens);

    lexer.removeErrorListeners();
    parser.removeErrorListeners();

    MiniSQLParser::SqlContext* tree = parser.sql();
    return lexer.getNumberOfSyntaxErrors() == 0 && parser.getNumberOfSyntaxErrors() == 0;
}

std::string verdictName(bool blocked) {
    return blocked ? "BLOCK" : "ALLOW";
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string rulesDir = "build/plugins";
    std::string payload;
    bool failClosed = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--rules" && i + 1 < argc) {
            rulesDir = argv[++i];
        } else if (a == "--fail-closed") {
            failClosed = true;
        } else if (a == "--") {
            if (i + 1 < argc) payload = argv[++i];
        } else {
            payload = a;
        }
    }

    if (payload.empty()) {
        std::cerr << "usage: engine [--rules DIR] [--fail-closed] \"payload\"\n";
        return 2;
    }

    std::cout << "== Compiled Rule Engine ==\n";
    std::cout << "INPUT:  " << payload << "\n";

    // 1. Normalization
    std::string normalized = normalize(payload);
    std::cout << "NORMAL: " << normalized << "\n";

    // 2. Fast Path
    std::vector<std::string> hits = fastPathHit(normalized);
    if (hits.empty()) {
        std::cout << "FAST PATH: no suspicious token -> ALLOW\n";
        return 0;
    }
    std::cout << "FAST PATH: suspicious token(s):";
    for (const auto& t : hits) std::cout << " [" << t << "]";
    std::cout << "\n";

    // 3. 加载规则插件
    std::vector<LoadedPlugin> rules = loadRules(rulesDir);
    if (rules.empty()) {
        std::cerr << "[engine] no rule plugins loaded from " << rulesDir << "\n";
        return 1;
    }
    size_t totalAttacks = 0;
    for (const auto& r : rules) totalAttacks += r.attacks.size();
    std::cout << "RULES (" << totalAttacks << " attacks in " << rules.size()
              << " plugins from " << rulesDir << "):\n";
    for (const auto& r : rules) {
        for (const auto& a : r.attacks) {
            std::cout << "  - " << a.name << " [" << a.severity << "/" << a.action
                      << "/" << a.profile << "] " << a.description << "\n";
        }
    }

    bool needSql = false;
    for (const auto& r : rules) {
        for (const auto& a : r.attacks) {
            if (std::string(a.profile) == "sql") needSql = true;
        }
    }

    // 4. 完整 SQL 判定（fullSqlOk：fragment/raw 画像门控 + UNKNOWN 判定）
    bool fullSqlOk = false;
    if (needSql) {
        fullSqlOk = parseSql(normalized);
        std::cout << "SQL PARSE: " << (fullSqlOk ? "OK" : "ERROR") << "\n";
    }

    // 5. Rule Engine
    struct Matched {
        const rule::AttackInfo* attack;
        int start = -1;
        int end = -1;
    };
    std::vector<Matched> matched;
    for (const auto& r : rules) {
        int buf[64];
        int startOff[64];
        int endOff[64];
        int n = r.checkText(normalized.c_str(), buf, startOff, endOff, 64);
        for (int i = 0; i < n; ++i) {
            if (buf[i] < 0 || buf[i] >= static_cast<int>(r.attacks.size())) continue;
            const rule::AttackInfo* a = &r.attacks[buf[i]];
            // fragment/raw 画像只在输入不是完整 SQL 时参与判定
            if ((std::string(a->profile) == "fragment" || std::string(a->profile) == "raw") &&
                fullSqlOk) {
                continue;
            }
            matched.push_back({a, startOff[i], endOff[i]});
        }
    }

    std::cout << "MATCHED ATTACKS: " << matched.size() << "\n";
    for (const auto& m : matched) {
        std::cout << "  !! " << m.attack->name << " [" << m.attack->severity
                  << "] " << m.attack->description << "\n";
        if (m.start >= 0 && m.start <= m.end &&
            m.end < static_cast<int>(normalized.size())) {
            std::cout << "      matched: \"" << normalized.substr(m.start, m.end - m.start + 1)
                      << "\"\n";
        }
    }

    // 6. Verdict：完整 SQL 或命中任意规则 => 已识别（ALLOW），否则 UNKNOWN
    bool blocked = false;
    for (const auto& m : matched) {
        if (std::string(m.attack->action) == "BLOCK") blocked = true;
    }

    bool sqlOk = fullSqlOk || !matched.empty();
    if (!sqlOk && !blocked) {
        if (failClosed) {
            blocked = true;
            std::cout << "SQL PARSE ERROR with --fail-closed -> treated as BLOCK\n";
        } else {
            std::cout << "SQL PARSE ERROR -> verdict UNKNOWN (use --fail-closed to block)\n";
            return 3;
        }
    }

    std::cout << "VERDICT: " << verdictName(blocked) << "\n";
    return blocked ? 1 : 0;
}
