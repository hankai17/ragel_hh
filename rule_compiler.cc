// ============================================================
// rulec — 规则编译器（ANTLR 语法规则）
// ------------------------------------------------------------
// 输入：rules/**/*.g4（标准 ANTLR parser grammar + 元数据注释）
// 输出：lib<name>.so（独立插件，导出 rule_check_text）
//
// 流水线：
//   rules/sqli/sleep.g4（ANTLR 语法，import RuleSQL）
//     --java--> sleep.{h,cpp}（规则解析器）
//     + wrapper + 共享词法 SQLTokens
//     --g++ -shared--> libsleep.so
//
// 插件只依赖 rule_plugin.h 与 ANTLR 运行时，可独立分发、热加载。
// ============================================================

#include <cstdlib>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

// ------------------------------------------------------------
// 规则元数据（文件头注释：// rule: / // severity: / ...）
// ------------------------------------------------------------

struct AttackMeta {
    std::string name;
    std::string severity = "MEDIUM";
    std::string action = "BLOCK";
    std::string description;
    std::string profile = "sql";
    std::string matcher;   // 匹配子规则名（元数据块后的第一条语法规则）
    std::vector<std::string> startTokens;  // 可能的起始 token（首 token 索引）
};

bool isAntlrGrammar(const std::string& path) {
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("grammar ") != std::string::npos) return true;
    }
    return false;
}

std::string baseName(const std::string& path) {
    size_t slash = path.find_last_of('/');
    std::string b = slash == std::string::npos ? path : path.substr(slash + 1);
    size_t dot = b.rfind(".g4");
    if (dot != std::string::npos) b = b.substr(0, dot);
    return b;
}

// 解析文件中所有攻击块：// attack:/rule: 元数据注释 + 紧随其后的匹配子规则
std::vector<AttackMeta> parseAttacks(const std::string& path) {
    std::vector<AttackMeta> out;
    AttackMeta cur;
    bool have = false;
    std::ifstream in(path);
    std::string line;
    auto keyval = [](const std::string& line, const std::string& key, std::string* dst) {
        std::string prefix = "// " + key + ": ";
        size_t p = line.find(prefix);
        if (p != std::string::npos) {
            *dst = line.substr(p + prefix.size());
            if (!dst->empty() && dst->back() == '\r') dst->pop_back();
            return true;
        }
        return false;
    };
    while (std::getline(in, line)) {
        std::string newName;
        if (keyval(line, "attack", &newName) || keyval(line, "rule", &newName)) {
            if (have) out.push_back(cur);
            cur = AttackMeta();
            cur.name = newName;
            have = true;
        }
        keyval(line, "severity", &cur.severity);
        keyval(line, "action", &cur.action);
        keyval(line, "description", &cur.description);
        keyval(line, "profile", &cur.profile);
        // // start: NUMBER IDENT ...
        {
            std::string prefix = "// start:";
            size_t p = line.find(prefix);
            if (p != std::string::npos) {
                std::istringstream ss(line.substr(p + prefix.size()));
                std::string tok;
                while (ss >> tok) cur.startTokens.push_back(tok);
            }
        }
        // 元数据块后的第一条语法规则行 = 该攻击的匹配子规则名
        // （规则名顶格书写：单行 "name : ..." 或多行 "name" 均可）
        if (have && cur.matcher.empty()) {
            size_t p = line.find_first_not_of(" \t");
            if (p == 0 && line[p] != '/' && std::isalpha(static_cast<unsigned char>(line[p]))) {
                size_t q = line.find_first_of(" :");
                std::string name = q == std::string::npos ? line : line.substr(0, q);
                bool ok = !name.empty();
                for (char c : name) {
                    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_')) ok = false;
                }
                // 跳过语法头部行（parser grammar / options / import ...）
                if (ok && name != "parser" && name != "grammar" && name != "options" &&
                    name != "import") {
                    cur.matcher = name;
                }
            }
        }
    }
    if (have) out.push_back(cur);
    return out;
}

// ------------------------------------------------------------
// 工具
// ------------------------------------------------------------

bool fileExists(const std::string& p) {
    std::error_code ec;
    return std::filesystem::exists(p, ec);
}

bool writeFile(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    if (!out) return false;
    out << content;
    return out.good();
}

std::string cppEscape(const std::string& s) {
    std::string out;
    for (char ch : s) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\t': out += "\\t"; break;
            case '\r': out += "\\r"; break;
            default: out += ch; break;
        }
    }
    return out;
}

// ------------------------------------------------------------
// ANTLR 编译流水线
// ------------------------------------------------------------

// 生成共享词法（幂等）：ANTLR 会把输出镜像到源文件相对路径，需 cd 到目标目录
// tokensClass 由规则文件的 tokenVocab 决定（默认 SQLTokens），
// 共享语法骨架（RuleSQL.g4 / Log4jLookup.g4 等）全部复制过去供 import。
bool ensureShared(const std::string& sharedOut, const std::string& sharedSrc,
                  const std::string& jar, const std::string& tokensClass) {
    std::error_code ec;
    std::filesystem::create_directories(sharedOut, ec);
    // import 解析需要共享语法骨架与 tokenVocab 的 .tokens 在同一目录
    for (const auto& entry : std::filesystem::directory_iterator(sharedSrc, ec)) {
        if (!entry.is_regular_file(ec)) continue;
        if (entry.path().extension() == ".g4") {
            std::filesystem::copy_file(
                entry.path(), sharedOut + "/" + entry.path().filename().string(),
                std::filesystem::copy_options::overwrite_existing, ec);
        }
    }
    std::filesystem::remove(sharedOut + "/SQLExpr.g4", ec);  // 清理旧名残留
    if (fileExists(sharedOut + "/" + tokensClass + ".cpp")) return true;
    auto cwd = std::filesystem::current_path();
    std::filesystem::current_path(sharedOut);
    std::string cmd = "java -jar " + jar + " -Dlanguage=Cpp -no-listener -o . " +
                      sharedSrc + "/" + tokensClass + ".g4";
    int rc = std::system(cmd.c_str());
    std::filesystem::current_path(cwd);
    return rc == 0;
}

// 从规则文件中读取 tokenVocab = X 选择共享词法；找不到默认 SQLTokens
std::string detectTokenVocab(const std::string& path) {
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line)) {
        size_t p = line.find("tokenVocab");
        if (p == std::string::npos) continue;
        size_t eq = line.find('=', p);
        if (eq == std::string::npos) continue;
        size_t b = line.find_first_not_of(" \t", eq + 1);
        if (b == std::string::npos) continue;
        size_t e = b;
        while (e < line.size() &&
               (std::isalnum(static_cast<unsigned char>(line[e])) || line[e] == '_')) {
            ++e;
        }
        if (e > b) return line.substr(b, e - b);
    }
    return "SQLTokens";
}

std::string generateWrapper(const std::vector<AttackMeta>& attacks, const std::string& cls,
                            const std::string& tokensClass) {
    const size_t n = attacks.size();
    std::ostringstream out;
    out << "// Generated by rulec from ANTLR rule grammar. DO NOT EDIT.\n"
        << "#include \"rule_plugin.h\"\n"
        << "#include \"antlr4-runtime.h\"\n"
        << "#include \"" << tokensClass << ".h\"\n"
        << "#include \"" << cls << ".h\"\n"
        << "#include <chrono>\n"
        << "#include <memory>\n"
        << "#include <string>\n"
        << "#include <vector>\n\n"
        << "using namespace antlr4;\n\n"
        << "extern \"C\" int rule_abi() { return rule::RULE_ABI; }\n\n"
        << "extern \"C\" int rule_attack_count() { return " << n << "; }\n\n"
        << "extern \"C\" const rule::AttackInfo* rule_attack(int i) {\n"
        << "    static const rule::AttackInfo infos[" << n << "] = {\n";
    for (size_t i = 0; i < n; ++i) {
        const AttackMeta& a = attacks[i];
        out << "        {\"" << cppEscape(a.name) << "\", \"" << a.severity
            << "\", \"" << a.action << "\", \"" << cppEscape(a.description)
            << "\", \"" << a.profile << "\"}"
            << (i + 1 < n ? "," : "") << "\n";
    }
    out << "    };\n"
        << "    if (i < 0 || i >= " << n << ") return nullptr;\n"
        << "    return &infos[i];\n"
        << "}\n\n"
        << "// 首 token 索引：攻击只在起始 token 匹配的位置尝试（性能优化）\n"
        << "static bool startsOk(int k, int t) {\n"
        << "    switch (k) {\n";
    for (size_t i = 0; i < n; ++i) {
        out << "        case " << i << ": return ";
        const auto& st = attacks[i].startTokens;
        if (st.empty()) {
            out << "true;\n";
            continue;
        }
        for (size_t j = 0; j < st.size(); ++j) {
            if (j) out << " || ";
            const std::string& name = st[j] == "NULL" ? "NULL_" : st[j];
            out << "t == " << cls << "::" << name;
        }
        out << ";\n";
    }
    out << "        default: return true;\n"
        << "    }\n"
        << "}\n\n"
        << "extern \"C\" int rule_check_text(const char* text, int* matched,\n"
        << "                                int* startOff, int* endOff, int max_matches) {\n"
        << "    ANTLRInputStream input(text ? text : \"\");\n"
        << "    " << tokensClass << " lexer(&input);\n"
        << "    lexer.removeErrorListeners();\n"
        << "    CommonTokenStream tokens(&lexer);\n"
        << "    tokens.fill();\n"
        << "    std::vector<Token*> visible;\n"
        << "    for (size_t i = 0; i < tokens.size(); ++i) {\n"
        << "        Token* t = tokens.get(i);\n"
        << "        if (t->getType() == Token::EOF) break;\n"
        << "        if (t->getChannel() == Token::DEFAULT_CHANNEL) visible.push_back(t);\n"
        << "    }\n"
        << "    int count = 0;\n"
        << "    // 对抗输入保护：滑窗重解析的最坏路径是 O(位置数 x 规则数)。\n"
        << "    // 预算限制单次调用最多尝试数与耗时，超限即返回已命中（调用方\n"
        << "    // 可视为扫描被截断，按 fail-closed 策略处理）。\n"
        << "    constexpr int kMaxAttempts = 1024;\n"
        << "    constexpr int kMaxMillis = 5;\n"
        << "    int attempts = 0;\n"
        << "    const auto t0 = std::chrono::steady_clock::now();\n"
        << "    // 命中终止：裁决只取决于是否命中 BLOCK 规则（engine.cc Verdict）。\n"
        << "    // 一旦命中 BLOCK，后续匹配不可能再改变裁决，直接结束整个过程，\n"
        << "    // 不再继续收集多余的 ALLOW 检测结果。仅 ALLOW 命中时仍需扫描到\n"
        << "    // 底，避免把后面才出现的 BLOCK 规则漏掉（如 1+1=2 UNION SELECT）。\n"
        << "    static const bool kBlocking[" << n << "] = {";
    for (size_t i = 0; i < n; ++i) {
        out << (attacks[i].action == "BLOCK" ? "true" : "false")
            << (i + 1 < n ? "," : "");
    }
    out << "};\n"
        << "    std::vector<bool> done(" << n << ", false);\n"
        << "    for (size_t i = 0; i < visible.size() && count < max_matches; ++i) {\n"
        << "        const int t = visible[i]->getType();\n"
        << "        for (int k = 0; k < " << n << "; ++k) {\n"
        << "            if (done[k] || !startsOk(k, t)) continue;\n"
        << "            if (++attempts > kMaxAttempts ||\n"
        << "                std::chrono::duration_cast<std::chrono::milliseconds>(\n"
        << "                    std::chrono::steady_clock::now() - t0).count() > kMaxMillis) {\n"
        << "                return count;  // 预算耗尽\n"
        << "            }\n"
        << "            tokens.seek(visible[i]->getTokenIndex());\n"
        << "            " << cls << " parser(&tokens);\n"
        << "            parser.removeErrorListeners();\n"
        << "            // 快速失败：首个语法错误立即抛出，避免默认错误恢复\n"
        << "            // 把失败尝试一路吞到 EOF（滑窗最坏路径的二次方来源）。\n"
        << "            parser.setErrorHandler(std::make_shared<BailErrorStrategy>());\n"
        << "            try {\n"
        << "                switch (k) {\n";
    for (size_t i = 0; i < n; ++i) {
        out << "                    case " << i << ": parser." << attacks[i].matcher << "(); break;\n";
    }
    out << "                }\n"
        << "            } catch (...) {\n"
        << "                continue;  // 未命中：快速失败，不吞 token\n"
        << "            }\n"
        << "            if (parser.getNumberOfSyntaxErrors() != 0) continue;\n"
        << "            done[k] = true;\n"
        << "            {\n"
        << "                const int cur = parser.getCurrentToken()->getTokenIndex();\n"
        << "                matched[count] = k;\n"
        << "                startOff[count] = visible[i]->getStartIndex();\n"
        << "                endOff[count] = cur > 0 ? tokens.get(cur - 1)->getStopIndex()"
        << " : startOff[count];\n"
        << "                ++count;\n"
        << "                if (kBlocking[k]) return count;  // 已命中拦截规则，结束匹配\n"
        << "            }\n"
        << "        }\n"
        << "    }\n"
        << "    return count;\n"
        << "}\n";
    return out.str();
}

int compileAntlrRule(const std::vector<AttackMeta>& attacks, const std::string& ruleFile,
                     const std::string& outDir, const std::string& includeDir,
                     const std::string& sharedSrc, const std::string& jar,
                     const std::string& antlrInc, const std::string& antlrLib,
                     const std::string& pluginOpt) {
    const std::string cls = baseName(ruleFile);
    const std::string absOut = std::filesystem::absolute(outDir).string();
    const std::string genDir = absOut + "/gen";
    const std::string sharedOut = genDir + "/_shared";
    std::error_code ec;
    std::filesystem::create_directories(genDir, ec);

    const std::string tokensClass = detectTokenVocab(ruleFile);
    if (!ensureShared(sharedOut, sharedSrc, jar, tokensClass)) {
        std::cerr << "[rulec] shared lexer generation failed (" << tokensClass << ")\n";
        return 1;
    }

    // 1) 生成规则解析器（cd 到规则目录避免 ANTLR 镜像输出路径）
    std::string ruleDir = std::filesystem::path(ruleFile).parent_path().string();
    auto cwd = std::filesystem::current_path();
    std::filesystem::current_path(ruleDir);
    std::string cmd = "java -jar " + jar + " -Dlanguage=Cpp -no-listener -lib " +
                      sharedOut + " -o " + genDir + " " + cls + ".g4";
    int rc = std::system(cmd.c_str());
    std::filesystem::current_path(cwd);
    if (rc != 0 || !fileExists(genDir + "/" + cls + ".cpp")) {
        std::cerr << "[rulec] ANTLR generation failed for " << ruleFile << "\n";
        return 1;
    }

    // 2) 生成插件 wrapper
    std::string wrapperPath = genDir + "/" + cls + "_rule.cc";
    if (!writeFile(wrapperPath, generateWrapper(attacks, cls, tokensClass))) return 1;

    // 3) 编译 .so（共享词法 + 规则解析器 + wrapper）
    // 插件名与规则库文件名一致（如 sqli_rules.g4 -> libsqli_rules.so）
    std::string soPath = absOut + "/lib" + cls + ".so";
    cmd = "g++ -std=c++17 " + pluginOpt + " -fPIC -shared -I" + includeDir + " -I" + antlrInc +
          " -I" + sharedOut + " -I" + genDir + " " + wrapperPath + " " +
          genDir + "/" + cls + ".cpp " + sharedOut + "/" + tokensClass + ".cpp -L" +
          antlrLib + " -lantlr4-runtime -Wl,-rpath," + antlrLib + " -o " + soPath;
    if (std::system(cmd.c_str()) != 0) {
        std::cerr << "[rulec] g++ failed, see " << wrapperPath << "\n";
        return 1;
    }

    std::cout << "[rulec] " << ruleFile << " -> " << soPath << "\n"
              << "        attacks=" << attacks.size();
    for (const auto& a : attacks) {
        std::cout << " [" << a.name << "/" << a.severity << "/" << a.profile << "]";
    }
    std::cout << "\n        opt=\"" << pluginOpt << "\"\n";
    return 0;
}

}  // namespace

int main(int argc, char* argv[]) {
    std::string includeDir = ".";
    std::string outDir = "build/plugins";
    std::string ruleFile;
    std::string antlrJar = "antlr-4.13.2-complete.jar";
    std::string antlrInc;
    std::string antlrLib;
    std::string sharedDir = "rules/_shared";
    std::string pluginOpt = "-O2";

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--include" && i + 1 < argc) includeDir = argv[++i];
        else if (a == "-o" && i + 1 < argc) outDir = argv[++i];
        else if (a == "--antlr-jar" && i + 1 < argc) antlrJar = argv[++i];
        else if (a == "--antlr-inc" && i + 1 < argc) antlrInc = argv[++i];
        else if (a == "--antlr-lib" && i + 1 < argc) antlrLib = argv[++i];
        else if (a == "--shared-dir" && i + 1 < argc) sharedDir = argv[++i];
        else if (a == "--plugin-opt" && i + 1 < argc) pluginOpt = argv[++i];
        else ruleFile = a;
    }

    if (ruleFile.empty()) {
        std::cerr << "usage: rulec [--include DIR] [-o OUTDIR] [--antlr-jar JAR]"
                     " [--antlr-inc DIR] [--antlr-lib DIR] [--shared-dir DIR] rule.g4\n";
        return 2;
    }
    if (!isAntlrGrammar(ruleFile)) {
        std::cerr << "[rulec] not an ANTLR grammar file: " << ruleFile << "\n";
        return 2;
    }
    if (antlrInc.empty() || antlrLib.empty()) {
        std::cerr << "[rulec] need --antlr-inc and --antlr-lib\n";
        return 2;
    }

    std::vector<AttackMeta> attacks = parseAttacks(ruleFile);
    if (attacks.empty()) {
        std::cerr << "[rulec] no attack metadata found in " << ruleFile << "\n";
        return 2;
    }
    return compileAntlrRule(attacks, ruleFile, outDir, includeDir, sharedDir,
                            antlrJar, antlrInc, antlrLib, pluginOpt);
}
