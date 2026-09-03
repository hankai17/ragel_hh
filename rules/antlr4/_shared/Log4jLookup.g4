// ============================================================
// Log4jLookup.g4 — log4j 查找表达式共享匹配骨架
// ------------------------------------------------------------
// 供 rules/**/*.g4 import 复用。语法本体极小，核心在语义谓词：
//
//   log4j_expr : ${ lookup_body }
//   lookup_body: 前缀? : 值?     （前缀允许为空——log4j 的 :- 默认值写法
//                                ${::-j} 即空前缀；前缀与值内部都可以再嵌
//                                ${...}，形成递归子语法——这是 log4j 嵌套
//                                混淆的根源，如 ${${lower:j}ndi:...}）
//
// 语义谓词（近似解析，不做完整 lookup 求值）：
//   jndiDangerous(expr)  前缀解析后含 "jndi"，或任意深度嵌套里出现
//                        jndi 查找（直接 ${jndi:...} 与
//                        ${env:${jndi:...}} / ${${lower:j}ndi:...}
//                        / ${jndi:${lower:l}dap://...} 均命中）
//   sensitivePrefix(expr) 首个前缀关键字属于敏感查找
//                        （env / sys / docker / k8s / aws / spring / main）
//   nestedChain(expr)    无 jndi 但存在嵌套查找链（递归滥用/DoS 防护）
// ============================================================

parser grammar Log4jLookup;

options { tokenVocab = Log4jTokens; }

@parser::includes {
#include <algorithm>
#include <cctype>
#include <string>
#include <vector>
}

@parser::members {
// ----------------------------------------------------------
// 工具
// ----------------------------------------------------------
static std::string lowerText(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return r;
}

// 节点是否是一个 log4j_expr（首个子节点是 DOLLAR）
static bool isLookupExpr(antlr4::ParserRuleContext* c) {
    if (!c || c->children.empty()) return false;
    auto* t = dynamic_cast<antlr4::tree::TerminalNode*>(c->children[0]);
    return t && t->getSymbol()->getType() == DOLLAR;
}

// log4j_expr : DOLLAR LBRACE lookup_body RBRACE -> body 在 children[2]
static antlr4::ParserRuleContext* lookupBodyOf(antlr4::ParserRuleContext* expr) {
    if (!expr || expr->children.size() < 3) return nullptr;
    return dynamic_cast<antlr4::ParserRuleContext*>(expr->children[2]);
}

// 值子树文本：CHUNK 原文 + 嵌套查找取其值（近似解析，不真求值）
static std::string resolveValueSubtree(antlr4::ParserRuleContext* c) {
    if (!c) return "";
    std::string out;
    for (auto* child : c->children) {
        if (auto* t = dynamic_cast<antlr4::tree::TerminalNode*>(child)) {
            if (t->getSymbol()->getType() == CHUNK) out += t->getText();
        } else if (auto* pc = dynamic_cast<antlr4::ParserRuleContext*>(child)) {
            if (isLookupExpr(pc)) {
                out += resolveValueSubtree(lookupBodyOf(pc));
            } else {
                out += resolveValueSubtree(pc);
            }
        }
    }
    return out;
}

// lookup_body : lookup_prefix COLON lookup_value? -> 值在 children[2]
static std::string resolveValue(antlr4::ParserRuleContext* body) {
    if (!body || body->children.size() < 3) return "";
    return resolveValueSubtree(
        dynamic_cast<antlr4::ParserRuleContext*>(body->children[2]));
}

// 前缀解析：CHUNK 原文 + 嵌套查找取其值。${${lower:j}ndi} -> "j"+"ndi"，
// ${${::-j}ndi} -> "-j"+"ndi"，${${env:JNDI}ndi} -> "JNDI"+"ndi"
static std::string resolvePrefix(antlr4::ParserRuleContext* prefix) {
    if (!prefix) return "";
    std::string out;
    for (auto* child : prefix->children) {          // lookup_prefix : (log4j_expr | CHUNK)* ;
        if (auto* t = dynamic_cast<antlr4::tree::TerminalNode*>(child)) {
            if (t->getSymbol()->getType() == CHUNK) out += t->getText();
        } else if (auto* pc = dynamic_cast<antlr4::ParserRuleContext*>(child)) {
            if (isLookupExpr(pc)) {
                out += resolveValue(lookupBodyOf(pc));
            } else {
                out += resolvePrefix(pc);
            }
        }
    }
    return out;
}

// 前缀解析结果（小写）含 "jndi"
static bool hasJndiPrefix(antlr4::ParserRuleContext* body) {
    if (!body || body->children.empty()) return false;
    auto* prefix = dynamic_cast<antlr4::ParserRuleContext*>(body->children[0]);
    std::string eff = lowerText(resolvePrefix(prefix));
    return eff.find("jndi") != std::string::npos;
}

// 子树内任意深度是否存在前缀为 jndi 的查找表达式
static bool hasJndiLookupInSubtree(antlr4::ParserRuleContext* c) {
    if (!c) return false;
    if (isLookupExpr(c) && hasJndiPrefix(lookupBodyOf(c))) return true;
    for (auto* child : c->children) {
        if (auto* pc = dynamic_cast<antlr4::ParserRuleContext*>(child)) {
            if (hasJndiLookupInSubtree(pc)) return true;
        }
    }
    return false;
}

// 顶层判定：直接 jndi / 前缀混淆 jndi / 值内嵌套 jndi
static bool jndiDangerous(antlr4::ParserRuleContext* expr) {
    auto* body = lookupBodyOf(expr);
    if (!body) return false;
    return hasJndiPrefix(body) || hasJndiLookupInSubtree(body);
}

// 前缀子树里的第一个 CHUNK（嵌套时取最内层查找的前缀）
static std::string firstChunk(antlr4::ParserRuleContext* c) {
    if (!c) return "";
    for (auto* child : c->children) {
        if (auto* t = dynamic_cast<antlr4::tree::TerminalNode*>(child)) {
            if (t->getSymbol()->getType() == CHUNK) return t->getText();
        } else if (auto* pc = dynamic_cast<antlr4::ParserRuleContext*>(child)) {
            std::string s = firstChunk(pc);
            if (!s.empty()) return s;
        }
    }
    return "";
}

// 敏感前缀：env / sys / docker / k8s / aws / spring / main
static bool sensitivePrefix(antlr4::ParserRuleContext* body) {
    if (!body || body->children.empty()) return false;
    auto* prefix = dynamic_cast<antlr4::ParserRuleContext*>(body->children[0]);
    std::string first = lowerText(firstChunk(prefix));
    static const std::vector<std::string> kSensitive = {
        "env", "sys", "docker", "k8s", "aws", "spring", "main",
    };
    return std::find(kSensitive.begin(), kSensitive.end(), first) != kSensitive.end();
}

// 嵌套查找计数（用于"无 jndi 但存在嵌套链"的递归滥用/DoS 检测）
static int countLookups(antlr4::ParserRuleContext* c) {
    if (!c) return 0;
    int n = isLookupExpr(c) ? 1 : 0;
    for (auto* child : c->children) {
        if (auto* pc = dynamic_cast<antlr4::ParserRuleContext*>(child)) {
            n += countLookups(pc);
        }
    }
    return n;
}

static bool nestedChain(antlr4::ParserRuleContext* expr) {
    auto* body = lookupBodyOf(expr);
    return body && countLookups(body) > 0;
}
}

// ----------------------------------------------------------
// 递归查找表达式：前缀与值内部都允许嵌套 ${...}
// ----------------------------------------------------------

log4j_expr  : DOLLAR LBRACE lookup_body RBRACE ;

lookup_body : lookup_prefix COLON lookup_value? ;

lookup_prefix : (log4j_expr | CHUNK)* ;

lookup_value  : (log4j_expr | CHUNK | COLON)+ ;
