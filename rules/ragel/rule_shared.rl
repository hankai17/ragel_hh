/* ============================================================
 * rule_shared.rl — rule_*.rl 公共片段
 * ------------------------------------------------------------
 * 两个命名段，供各规则文件按名 include：
 *   include rule_shared_tok  "rule_shared.rl";   token 编号 + 运算符
 *   include rule_shared_expr "rule_shared.rl";   expr 递归骨架
 * Ragel include 语义：仅段名与 include 名匹配时才并入宿主机器，
 * 本文件不单独编译（只被 rule_*.rl 引用）。
 * ============================================================ */

%%{
    machine rule_shared_tok;
    NUMBER = 1;  STRING = 2;  TRUE = 3;   FALSE = 4;  NULL = 5;  IDENT = 6;
    SELECT = 7;  UNION = 8;   ALL = 9;    FROM = 10;  WHERE = 11; ORDER = 12;
    BY = 13;     LIMIT = 14;  OFFSET = 15; INSERT = 16; INTO = 17; VALUES = 18;
    UPDATE = 19; SET = 20;    DELETE = 21; DROP = 22;  ALTER = 23; CREATE = 24;
    EXISTS = 25; IN = 26;     LIKE = 27;  BETWEEN = 28; IS = 29;  NOT = 30;
    AND = 31;    OR = 32;     ASC = 33;   DESC = 34;
    EQ = 35;     NE = 36;     LE = 37;    GE = 38;    LT = 39;    GT = 40;
    PLUS = 41;   MINUS = 42;  STAR = 43;  DIV = 44;   MOD = 45;   PIPE2 = 46;
    LPAREN = 47; RPAREN = 48; COMMA = 49; SEMI = 50;

    cmp_op = EQ | NE | LE | GE | LT | GT;
    add_op = PLUS | MINUS | PIPE2;
    mul_op = STAR | DIV | MOD;
}%%

%%{
    machine rule_shared_expr;
    # expr 递归骨架（token 级，常量来自 rule_shared_tok）：
    #   括号 / f(...) 递归走 fcall 到 expr_call / elist_call。
    # 递归入口（:=）与动作随 include 并入宿主机器，各宿主各自持有一份。
    action call_expr  { fcall expr_call; }
    action call_elist { fcall elist_call; }
    action ret_expr   { if (top > 0) cs = stack[--top];
                        if (top == 0) match_len = (int)(p - types) + 1 - start;
                        goto _again; }

    primary = NUMBER | STRING | TRUE | FALSE | NULL
            | IDENT ( LPAREN @call_elist )?
            | LPAREN @call_expr;
    unary_expr = ( PLUS | MINUS )* primary;
    mul_expr = unary_expr ( mul_op unary_expr )*;
    add_expr = mul_expr ( add_op mul_expr )*;
    comparison = add_expr ( cmp_op add_expr )?;
    not_expr = NOT* comparison;
    and_expr = not_expr ( AND not_expr )*;
    or_expr = and_expr ( OR and_expr )*;
    expr = or_expr;
    expr_list = expr ( COMMA expr )*;

    expr_call := expr RPAREN @ret_expr;
    elist_call := expr_list? RPAREN @ret_expr;
}%%
