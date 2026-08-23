// ============================================================
// log4j_rules.g4 — log4j 查找表达式攻击规则集
// ------------------------------------------------------------
// 覆盖面（全方位）：
//   1. log4j_jndi          ${jndi:...} 直接载荷 + 任意深度嵌套混淆
//                          （${${lower:j}ndi:...} / ${env:${jndi:...}} /
//                           ${jndi:${lower:l}dap://...} / $$ 转义前缀保守命中）
//   2. log4j_sensitive     敏感 lookup 前缀（env/sys/docker/k8s/aws/spring/main）
//   3. log4j_nested_chain  无 jndi 的多层嵌套链（递归滥用/DoS 防护）
//   4. log4j_expr          ${...} 结构识别（检测层，ALLOW 不拦截）
//
// 词法/语法骨架：Log4jTokens + Log4jLookup（嵌套子语法 + 语义谓词）。
// rulec 依据本文件 tokenVocab 自动选择共享词法，不依赖 SQLTokens。
// ============================================================

parser grammar log4j_rules;

options { tokenVocab = Log4jTokens; }

import Log4jLookup;

// attack: log4j_jndi
// severity: CRITICAL
// action: BLOCK
// description: log4j JNDI 注入（Log4Shell 类）：直接 ${jndi:...} 或任意深度嵌套混淆（${${lower:j}ndi:...} / ${env:${jndi:...}}）
// profile: raw
// start: DOLLAR
log4j_jndi_pat
    : log4j_expr {jndiDangerous(_localctx->log4j_expr())}?
    ;

// attack: log4j_sensitive
// severity: HIGH
// action: BLOCK
// description: log4j 敏感查找：env/sys/docker/k8s/aws/spring/main 前缀（环境/系统信息泄露面）
// profile: raw
// start: DOLLAR
log4j_sensitive_pat
    : log4j_expr {sensitivePrefix(lookupBodyOf(_localctx->log4j_expr()))}?
    ;

// attack: log4j_nested_chain
// severity: MEDIUM
// action: BLOCK
// description: log4j 嵌套查找链（无 jndi）：多层 ${...} 递归，防查找递归滥用/解析 DoS
// profile: raw
// start: DOLLAR
log4j_nested_chain_pat
    : log4j_expr {nestedChain(_localctx->log4j_expr())}?
    ;

// attack: log4j_expr
// severity: LOW
// action: ALLOW
// description: log4j 查找表达式结构识别（检测/审计层，不拦截）
// profile: raw
// start: DOLLAR
log4j_expr_pat
    : log4j_expr
    ;
