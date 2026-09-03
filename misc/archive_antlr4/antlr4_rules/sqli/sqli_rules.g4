// ============================================================
// sqli_rules.g4 — SQLi 攻击规则合并集（24 条）
// ------------------------------------------------------------
// 每条攻击 = 元数据注释块 + 一个 <name>_pat 匹配子规则。
// rulec 按顺序解析攻击元数据，wrapper 逐条独立匹配并上报攻击类型。
// ============================================================

parser grammar sqli_rules;

options { tokenVocab = SQLTokens; }

import RuleSQL;

// attack: always_true
// severity: HIGH
// action: BLOCK
// description: 恒真条件：两侧等值常量（1=1 / 2=2 / 1=1.0）
// profile: sql
// 括号由 constant_value 语法处理，等值由 constNumbersEqual 谓词求值：
// 1=1 / 2=2 / 1=(1) / (1)=(1) 均命中
// start: NUMBER STRING TRUE FALSE NULL LPAREN
always_true_pat
    : constant_value EQ constant_value
      {constNumbersEqual(_localctx->constant_value(0), _localctx->constant_value(1))}?
    ;

// attack: string_tautology
// severity: HIGH
// action: BLOCK
// description: 恒真条件：两侧等值字符串常量（'a'='a'）
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL LPAREN
string_tautology_pat
    : constant_value EQ constant_value
      {constStringsEqual(_localctx->constant_value(0), _localctx->constant_value(1))}?
    ;

// attack: boolean_injection
// severity: MEDIUM
// action: BLOCK
// description: 布尔型注入：OR/AND 一侧为常量比较
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL IDENT LPAREN PLUS MINUS NOT EXISTS
boolean_injection_pat
    : const_cmp (OR | AND) comparison
    | comparison (OR | AND) const_cmp
    ;

const_cmp
    : constant_value EQ constant_value
    ;

// attack: union_select
// severity: CRITICAL
// action: BLOCK
// description: UNION SELECT 联合查询
// profile: sql
// start: UNION
union_select_pat : UNION ALL? SELECT expr_list? ;

// attack: stacked_query
// severity: CRITICAL
// action: BLOCK
// description: 堆叠查询：; 后跟 SQL 关键字
// profile: sql
// start: SEMI
stacked_query_pat : SEMI (SELECT | INSERT | UPDATE | DELETE | DROP | ALTER | CREATE) ;

// attack: sleep
// severity: CRITICAL
// action: BLOCK
// description: 时间盲注：SLEEP()
// profile: sql
// start: IDENT
sleep_pat : i=IDENT {isIdent($i, "sleep")}? LPAREN expr_list? RPAREN ;

// attack: load_file
// severity: CRITICAL
// action: BLOCK
// description: 文件读取：LOAD_FILE()
// profile: sql
// start: IDENT
load_file_pat : i=IDENT {isIdent($i, "load_file")}? LPAREN expr_list? RPAREN ;

// attack: benchmark
// severity: CRITICAL
// action: BLOCK
// description: 性能消耗函数 BENCHMARK()
// profile: sql
// start: IDENT
benchmark_pat : i=IDENT {isIdent($i, "benchmark")}? LPAREN expr_list? RPAREN ;

// attack: pg_sleep
// severity: CRITICAL
// action: BLOCK
// description: PostgreSQL 时间盲注：pg_sleep()
// profile: sql
// start: IDENT
pg_sleep_pat : i=IDENT {isIdent($i, "pg_sleep")}? LPAREN expr_list? RPAREN ;

// attack: subquery
// severity: MEDIUM
// action: ALLOW
// description: 子查询结构检测
// profile: sql
// start: LPAREN
subquery_pat : LPAREN select_stmt RPAREN ;

// attack: exists_subquery
// severity: MEDIUM
// action: ALLOW
// description: EXISTS 子查询结构检测
// profile: sql
// start: EXISTS NOT
exists_subquery_pat
    : EXISTS LPAREN select_stmt RPAREN
    | NOT EXISTS LPAREN select_stmt RPAREN
    ;

// attack: in_subquery
// severity: MEDIUM
// action: ALLOW
// description: IN 子查询结构检测
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL IDENT LPAREN PLUS MINUS NOT EXISTS
in_subquery_pat : add_expr NOT? IN LPAREN select_stmt RPAREN ;

// attack: like_expr
// severity: LOW
// action: ALLOW
// description: LIKE 表达式结构检测
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL IDENT LPAREN PLUS MINUS NOT EXISTS
like_expr_pat : add_expr NOT? LIKE add_expr ;

// attack: between_expr
// severity: LOW
// action: ALLOW
// description: BETWEEN 表达式结构检测
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL IDENT LPAREN PLUS MINUS NOT EXISTS
between_expr_pat : add_expr NOT? BETWEEN add_expr AND add_expr ;

// attack: numeric_expr
// severity: LOW
// action: ALLOW
// description: 数值表达式比较（如 1+1=2）
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL IDENT LPAREN PLUS MINUS NOT EXISTS
numeric_expr_pat : arith EQ add_expr ;

arith : mul_expr (add_op mul_expr)+ ;

// attack: order_by_expr
// severity: LOW
// action: ALLOW
// description: ORDER BY 表达式结构检测
// profile: sql
// start: ORDER
order_by_expr_pat : ORDER BY expr (ASC | DESC)? ;

// attack: limit_expr
// severity: LOW
// action: ALLOW
// description: LIMIT 表达式结构检测
// profile: sql
// start: LIMIT
limit_expr_pat : LIMIT expr (OFFSET expr)? ;

// attack: string_concat
// severity: LOW
// action: ALLOW
// description: 字符串拼接特征 ||
// profile: sql
// start: NUMBER STRING TRUE FALSE NULL IDENT LPAREN PLUS MINUS NOT EXISTS
string_concat_pat : add_expr PIPE2 add_expr ;

// attack: insert_fragment
// severity: MEDIUM
// action: ALLOW
// description: INSERT INTO 语句片段
// profile: fragment
// start: INSERT
insert_fragment_pat : INSERT INTO? IDENT? (LPAREN expr_list RPAREN)? (VALUES LPAREN expr_list RPAREN)? ;

// attack: update_fragment
// severity: MEDIUM
// action: ALLOW
// description: UPDATE ... SET 语句片段
// profile: fragment
// start: UPDATE
update_fragment_pat : UPDATE IDENT (SET expr_list?)? ;

// attack: delete_fragment
// severity: MEDIUM
// action: ALLOW
// description: DELETE FROM 语句片段
// profile: fragment
// start: DELETE
delete_fragment_pat : DELETE FROM? IDENT ;

// attack: select_fragment
// severity: LOW
// action: ALLOW
// description: SELECT 片段
// profile: fragment
// start: SELECT
select_fragment_pat : SELECT (STAR | expr_list) (FROM table_ref)? (WHERE expr)? (ORDER BY expr)? (LIMIT expr)? ;

// attack: select_from_fragment
// severity: LOW
// action: ALLOW
// description: SELECT ... FROM 片段
// profile: fragment
// start: SELECT
select_from_fragment_pat : SELECT (STAR | expr_list) FROM table_ref ;

// attack: db_enumeration
// severity: MEDIUM
// action: ALLOW
// description: 数据库结构枚举：information_schema 元数据访问
// profile: sql
// start: IDENT
db_enumeration_pat : i=IDENT {isIdent($i, "information_schema")}? ;
