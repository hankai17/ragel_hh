/* ============================================================
 * js_oom_full.rl — 【OOM 案例存档，勿用】
 * ------------------------------------------------------------
 * 这是按 ECMAScript EBNF 完整铺开优先级链的 19 层版本。
 * 编译它会触发 ragel NFA 状态数爆炸，最终 OOM 被系统 kill：
 *
 *   $ ragel -C -o /dev/null js_oom_full.rl
 *   71.6 秒后 SIGKILL（rc=137），内存耗尽
 *
 * 根因：每层 `X = Y (op Y)*` 引入一套新状态，与 3 个 fcall/fret
 * 递归入口（expr_call/bracket_call/elist_call）的调用栈状态做
 * 笛卡尔积，NFA 状态数指数级增长。
 *
 * 对比：合并版（rules/js/js_syntax.rl，15 层）编译 2 秒 / 87MB。
 * 差异仅 4 层：exp(幂) 独立、bit_and/bit_xor/bit_or 拆 3 层、
 * nullish 独立。合并后状态数回到可控范围。
 *
 * 保留本文件用于：
 *   1) 记录"token 级递归 CFG 层数过多会 OOM"这一陷阱；
 *   2) 作为 test_js.sh 里 OOM 回归检查的对照样本。
 * ============================================================ */

%%{
    machine js_oom_tok;
    NUMBER=1; STRING=2; TRUE=3; FALSE=4; NULL=5; UNDEFINED=6; IDENT=7;
    VAR=8; LET=9; CONST=10; FUNCTION=11; RETURN=12;
    IF=13; ELSE=14; WHILE=15; FOR=16;
    NEW=17; TYPEOF=18; VOID=19; DELETE=20; THIS=21;
    EQ=22; PLUS=23; MINUS=24; STAR=25; DIV=26; MOD=27; EXP=28;
    EQEQ=29; EQEQEQ=30; NE=31; NEEQ=32; LT=33; LE=34; GT=35; GE=36;
    AND=37; OR=38; NOT=39; NULLISH=40;
    AND_BIT=41; OR_BIT=42; XOR=43; NOT_BIT=44; SHL=45; SHR=46; SHRU=47;
    LPAREN=48; RPAREN=49; LBRACK=50; RBRACK=51;
    LBRACE=52; RBRACE=53; COMMA=54; SEMI=55; COLON=56; DOT=57; QUESTION=58;
}%%

%%{
    machine js_oom_expr;
    include js_oom_tok "js_oom_full.rl";

    action call_expr    { fcall expr_call; }
    action call_elist   { fcall elist_call; }
    action call_bracket { fcall bracket_call; }

    # 19 层完整分离优先级链（OOM 之源）
    primary = NUMBER | STRING | TRUE | FALSE | NULL | UNDEFINED | THIS
            | IDENT
            | LPAREN @call_expr;
    member = primary ( DOT IDENT | LBRACK @call_bracket )*;
    call = member ( LPAREN @call_elist )*;
    new_expr = ( NEW )* call;
    unary = ( PLUS | MINUS | NOT | NOT_BIT | TYPEOF | VOID | DELETE )* new_expr;
    exp = unary ( EXP unary )?;
    mul = exp ( ( STAR | DIV | MOD ) exp )*;
    add = mul ( ( PLUS | MINUS ) mul )*;
    shift = add ( ( SHL | SHR | SHRU ) add )*;
    rel = shift ( ( LT | LE | GT | GE ) shift )?;
    eq = rel ( ( EQEQ | EQEQEQ | NE | NEEQ ) rel )?;
    bit_and = eq ( AND_BIT eq )*;
    bit_xor = bit_and ( XOR bit_and )*;
    bit_or = bit_xor ( OR_BIT bit_xor )*;
    and = bit_or ( AND bit_or )*;
    or = and ( OR and )*;
    nullish = or ( NULLISH or )?;
    ternary = nullish ( QUESTION nullish COLON nullish )?;
    assign = ternary ( EQ ternary )?;
    expr = assign;
    expr_list = expr ( COMMA expr )*;

    action ret { if (top > 0) cs = stack[--top]; goto _again; }
    expr_call    := expr RPAREN @ret;
    bracket_call := expr RBRACK @ret;
    elist_call   := expr_list? RPAREN @ret;

    main := expr;
    write data noerror nofinal noentry;
}%%
