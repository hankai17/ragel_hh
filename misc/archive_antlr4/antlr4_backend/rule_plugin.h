#pragma once

// ============================================================
// 规则插件 ABI（rule_abi / rule_attack_count / rule_attack / rule_check_text）
// ------------------------------------------------------------
// 每条攻击规则（标准 ANTLR 语法）经 rulec 编译后生成一个 .so，
// 一个插件可包含多条攻击（如 sqli_rules.g4 合并 24 条），导出：
//
//   int         rule_abi()          版本号，不匹配则拒绝加载
//   int         rule_attack_count() 插件包含的攻击数量
//   AttackInfo* rule_attack(int i)  第 i 个攻击的元信息
//   int         rule_check_text(const char*, int* matched,
//                               int* startOff, int* endOff, int max)
//                                    对归一化文本匹配，返回命中攻击索引数量，
//                                    并给出每个命中在输入中的字符区间（含端点）
//
// 主引擎通过 dlopen/dlsym 加载插件，热插拔；插件只需头文件，无需链接引擎。
// ============================================================

namespace rule {

constexpr int RULE_ABI = 6;

struct AttackInfo {
    const char* name;        // 攻击名，如 "sleep"
    const char* severity;    // LOW / MEDIUM / HIGH / CRITICAL
    const char* action;      // ALLOW / BLOCK（命中 BLOCK 规则 => 拦截）
    const char* description; // 人类可读描述
    const char* profile;     // "sql"（始终）/ "fragment"（仅非完整 SQL）/ "raw"（仅非完整 SQL）
};

}  // namespace rule
