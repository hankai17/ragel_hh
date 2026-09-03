// ============================================================
// SQLTokens.g4 — 规则共享词法
// ------------------------------------------------------------
// 所有攻击规则 .g4 通过 tokenVocab 复用这套 token：
//   * 关键字大小写不敏感（IDENT 运行时映射）
//   * 引号容错：字面量风格 -> STRING，否则进隐藏通道（QUOTE）
//   * 未知字符跳过，词法永不失败
// ============================================================

lexer grammar SQLTokens;

@lexer::includes {
#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
}

@lexer::members {
// 当前引号处向前扫描：直到第一个闭合引号，内容若不含空白/操作符 => 字面量字符串
bool literalLikeAhead() {
    size_t start = static_cast<size_t>(_input->index() + 1);
    size_t n = _input->size();
    for (size_t i = start; i < n; ++i) {
        int c = _input->LA(static_cast<ssize_t>(i) - static_cast<ssize_t>(_input->index()) + 1);
        if (c == '\'') return true;
        // 空白/操作符视为"结构字符"：引号内容含它们则按分隔引号处理
        // （% 和 / 常见于 LIKE 模式与路径字符串，不视为结构字符）
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r' ||
            c == '=' || c == '<' || c == '>' || c == '!' ||
            c == '(' || c == ')' || c == '+' || c == '-' ||
            c == '*' || c == ',' || c == ';' || c == '|' ||
            c == '&' || c == '~') return false;
    }
    return false;
}

// 关键字映射（大小写不敏感），非关键字返回 IDENT
int keywordType(const std::string& text) {
    std::string low = text;
    std::transform(low.begin(), low.end(), low.begin(),
                   [](unsigned char ch) { return std::tolower(ch); });
    static const std::unordered_map<std::string, int> map = {
        {"select", SELECT}, {"union", UNION}, {"all", ALL},
        {"from", FROM}, {"where", WHERE}, {"order", ORDER}, {"by", BY},
        {"limit", LIMIT}, {"offset", OFFSET}, {"insert", INSERT},
        {"into", INTO}, {"values", VALUES}, {"update", UPDATE}, {"set", SET},
        {"delete", DELETE}, {"drop", DROP}, {"alter", ALTER}, {"create", CREATE},
        {"exists", EXISTS}, {"in", IN}, {"like", LIKE},
        {"between", BETWEEN}, {"is", IS}, {"not", NOT}, {"and", AND}, {"or", OR},
        {"null", NULL_}, {"true", TRUE}, {"false", FALSE}, {"asc", ASC}, {"desc", DESC},
    };
    auto it = map.find(low);
    return it == map.end() ? IDENT : it->second;
}
}

tokens {
    SELECT, UNION, ALL, FROM, WHERE, ORDER, BY, LIMIT, OFFSET,
    INSERT, INTO, VALUES, UPDATE, SET, DELETE, DROP, ALTER, CREATE,
    EXISTS, IN, LIKE, BETWEEN, IS, NOT, AND, OR,
    NULL, TRUE, FALSE, ASC, DESC
}

fragment DIGIT : [0-9];

NUMBER : DIGIT+ ('.' DIGIT+)? ;

// 只有"字面量风格"的引号内容才收成 STRING；懒匹配停在第一个闭合引号
STRING : {literalLikeAhead()}? '\'' (~('\'' | '\r' | '\n'))*? '\'' ;

// 悬空/分隔引号进隐藏通道，解析器不可见
QUOTE : '\'' -> channel(HIDDEN);

IDENT : [a-zA-Z_] [a-zA-Z0-9_]* { setType(keywordType(getText())); } ;

EQ    : '=';
NE    : '!=' | '<>';
LE    : '<=';
GE    : '>=';
LT    : '<';
GT    : '>';
PLUS  : '+';
MINUS : '-';
STAR  : '*';
DIV   : '/';
MOD   : '%';
PIPE2 : '||';
LPAREN: '(';
RPAREN: ')';
COMMA : ',';
SEMI  : ';';

LINE_COMMENT  : ('--' ~[\r\n]* | '#' ~[\r\n]*) -> skip;
BLOCK_COMMENT : '/*' .*? '*/' -> skip;
WS            : [ \t\r\n]+ -> skip;

// 未知字符容错跳过，词法永不失败
UNKNOWN : . -> skip;
