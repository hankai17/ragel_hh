/* ============================================================
 * js_shared.rl — JS 规则公共片段
 * ------------------------------------------------------------
 * 两个命名段，供 js_syntax.rl 按名 include：
 *   include js_shared_tok  "js_shared.rl";   token 编号 + 运算符
 *   include js_shared_expr "js_shared.rl";   expr 规则链
 *
 * js_shared_expr 不含递归入口（:=）与返回动作：由使用方定义
 * （见 js_syntax.rl）。
 *
 * 参照 ECMAScript EBNF 的表达式优先级链（最小裁剪）：
 *   primary -> member(成员) -> call(调用) -> new -> unary -> exp(幂)
 *           -> mul -> add -> shift(移位) -> rel -> eq -> bit_and
 *           -> bit_xor -> bit_or -> and -> or -> nullish -> ternary -> assign
 * 括号/调用/方括号递归走 fcall（expr_call / elist_call / bracket_call）。
 *
 * Ragel include 语义：仅段名与 include 名匹配时才并入宿主机器，
 * 本文件不单独编译（只被 js_syntax.rl 引用）。
 * ============================================================ */

%%{
    machine js_shared_tok;
    NUMBER = 1;  STRING = 2;
    TRUE = 3;  FALSE = 4;  NULL = 5;  UNDEFINED = 6;  IDENT = 7;
    VAR = 8;  LET = 9;  CONST = 10;  FUNCTION = 11;  RETURN = 12;
    IF = 13;  ELSE = 14;  WHILE = 15;  FOR = 16;
    NEW = 17;  TYPEOF = 18;  VOID = 19;  DELETE = 20;  THIS = 21;
    EQ = 22;
    PLUS = 23;  MINUS = 24;  STAR = 25;  DIV = 26;  MOD = 27;  EXP = 28;
    EQEQ = 29;  EQEQEQ = 30;  NE = 31;  NEEQ = 32;
    LT = 33;  LE = 34;  GT = 35;  GE = 36;
    AND = 37;  OR = 38;  NOT = 39;  NULLISH = 40;
    AND_BIT = 41;  OR_BIT = 42;  XOR = 43;  NOT_BIT = 44;
    SHL = 45;  SHR = 46;  SHRU = 47;
    LPAREN = 48;  RPAREN = 49;  LBRACK = 50;  RBRACK = 51;
    LBRACE = 52;  RBRACE = 53;  COMMA = 54;  SEMI = 55;
    COLON = 56;  DOT = 57;  QUESTION = 58;

    eq_op   = EQEQ | EQEQEQ | NE | NEEQ;
    rel_op  = LT | LE | GT | GE;
    mul_op  = STAR | DIV | MOD;
    add_op  = PLUS | MINUS;
    unary_op = PLUS | MINUS | NOT | NOT_BIT | TYPEOF | VOID | DELETE;
}%%

%%{
    machine js_shared_expr;
    # expr 递归骨架（token 级，常量来自 js_shared_tok）：
    #   primary 的 (expr)         -> fcall expr_call
    #   member 的 [expr]          -> fcall bracket_call
    #   call 的 f(expr_list)      -> fcall elist_call
    # 入口与返回动作由使用方定义（见 js_syntax.rl）。
    action call_expr    { fcall expr_call; }
    action call_elist   { fcall elist_call; }
    action call_bracket { fcall bracket_call; }

    primary = NUMBER | STRING | TRUE | FALSE | NULL | UNDEFINED | THIS
            | IDENT
            | LPAREN @call_expr;
    member = primary ( DOT IDENT | LBRACK @call_bracket )*;
    call = member ( LPAREN @call_elist )*;
    new_expr = ( NEW )* call;
    unary = ( unary_op )* new_expr;
    mul = unary ( ( STAR | DIV | MOD | EXP ) unary )*;
    add = mul ( add_op mul )*;
    shift = add ( ( SHL | SHR | SHRU ) add )*;
    rel = shift ( rel_op shift )?;
    eq = rel ( eq_op rel )?;
    bit = eq ( ( AND_BIT | XOR | OR_BIT ) eq )*;
    and = bit ( AND bit )*;
    or = and ( ( OR | NULLISH ) and )*;
    ternary = or ( QUESTION or COLON or )?;
    assign = ternary ( EQ ternary )?;
    expr = assign;
    expr_list = expr ( COMMA expr )*;
}%%
