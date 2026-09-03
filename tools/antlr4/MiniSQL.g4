grammar MiniSQL;

// ============================================================
// Entry
// ============================================================

sql
    : statement EOF
    ;

statement
    : queryStatement
    ;

queryStatement
    : withClause? queryExpression
    ;


// ============================================================
// WITH / CTE
// ============================================================

withClause
    : WITH RECURSIVE? cte (COMMA cte)*
    ;

cte
    : identifier columnAliasList? AS LPAREN queryExpression RPAREN
    ;

columnAliasList
    : LPAREN identifier (COMMA identifier)* RPAREN
    ;


// ============================================================
// Query / UNION
// ============================================================

queryExpression
    : queryTerm
      (UNION ALL? queryTerm)*
    ;

queryTerm
    : querySpecification
    | LPAREN queryExpression RPAREN
    ;


// ============================================================
// SELECT
// ============================================================

querySpecification
    : SELECT setQuantifier?
      selectList
      fromClause?
      whereClause?
      groupByClause?
      havingClause?
      orderByClause?
      limitClause?
    ;

setQuantifier
    : DISTINCT
    | ALL
    ;

selectList
    : STAR
    | selectItem (COMMA selectItem)*
    ;

selectItem
    : expression (AS? identifier)?
    ;


// ============================================================
// FROM
// ============================================================

fromClause
    : FROM tableReference (COMMA tableReference)*
    ;

tableReference
    : tablePrimary
      (joinClause)*
    ;

tablePrimary
    : identifier (AS? identifier)?
    | LPAREN queryExpression RPAREN (AS? identifier)?
    ;

joinClause
    : joinType? JOIN tablePrimary joinCondition?
    ;

joinType
    : INNER
    | LEFT OUTER?
    | RIGHT OUTER?
    | FULL OUTER?
    | CROSS
    ;

joinCondition
    : ON expression
    | USING LPAREN identifier (COMMA identifier)* RPAREN
    ;


// ============================================================
// WHERE
// ============================================================

whereClause
    : WHERE expression
    ;


// ============================================================
// GROUP BY
// ============================================================

groupByClause
    : GROUP BY expressionList
    ;


// ============================================================
// HAVING
// ============================================================

havingClause
    : HAVING expression
    ;


// ============================================================
// ORDER BY
// ============================================================

orderByClause
    : ORDER BY orderItem (COMMA orderItem)*
    ;

orderItem
    : expression (ASC | DESC)?
    ;


// ============================================================
// LIMIT
// ============================================================

limitClause
    : LIMIT expression
      (OFFSET expression)?
    ;


// ============================================================
// Expressions
// ============================================================

expression
    : orExpression
    ;

orExpression
    : andExpression
      (OR andExpression)*
    ;

andExpression
    : notExpression
      (AND notExpression)*
    ;

notExpression
    : NOT notExpression
    | comparisonExpression
    ;

comparisonExpression
    : EXISTS LPAREN queryExpression RPAREN
    | NOT EXISTS LPAREN queryExpression RPAREN
    | additiveExpression
      (
          comparisonOperator additiveExpression
        | IS NOT? NULL
        | IS NOT? TRUE
        | IS NOT? FALSE
        | IN LPAREN inExpression RPAREN
        | NOT IN LPAREN inExpression RPAREN
        | LIKE additiveExpression
        | NOT LIKE additiveExpression
        | BETWEEN additiveExpression AND additiveExpression
        | NOT BETWEEN additiveExpression AND additiveExpression
        | EXISTS LPAREN queryExpression RPAREN
        | NOT EXISTS LPAREN queryExpression RPAREN
      )?
    ;

comparisonOperator
    : EQ
    | NE
    | LT
    | LE
    | GT
    | GE
    ;


// ============================================================
// Arithmetic
// ============================================================

additiveExpression
    : multiplicativeExpression
      ((PLUS | MINUS) multiplicativeExpression)*
    ;

multiplicativeExpression
    : unaryExpression
      ((STAR | DIV | MOD) unaryExpression)*
    ;

unaryExpression
    : PLUS unaryExpression
    | MINUS unaryExpression
    | primaryExpression
    ;


// ============================================================
// Primary expressions
// ============================================================

primaryExpression
    : literal
    | columnReference
    | functionCall
    | caseExpression
    | LPAREN queryExpression RPAREN
    | LPAREN expression RPAREN
    ;


// ============================================================
// Column references
// ============================================================

columnReference
    : identifier
    | identifier DOT identifier
    | identifier DOT identifier DOT identifier
    ;


// ============================================================
// Function calls
// ============================================================

functionCall
    : identifier LPAREN functionArguments? RPAREN
    ;

functionArguments
    : STAR
    | expressionList
    ;


// ============================================================
// CASE
// ============================================================

caseExpression
    : CASE
      (expression)?
      whenClause+
      (ELSE expression)?
      END
    ;

whenClause
    : WHEN expression THEN expression
    ;


// ============================================================
// IN
// ============================================================

inExpression
    : expressionList
    | queryExpression
    ;


// ============================================================
// Lists
// ============================================================

expressionList
    : expression (COMMA expression)*
    ;


// ============================================================
// Literals
// ============================================================

literal
    : NUMBER
    | STRING
    | NULL
    | TRUE
    | FALSE
    ;


// ============================================================
// Identifier
// ============================================================

identifier
    : IDENTIFIER
    | QUOTED_IDENTIFIER
    ;


// ============================================================
// Lexer
// ============================================================

WITH       : W I T H;
RECURSIVE  : R E C U R S I V E;

SELECT     : S E L E C T;
FROM       : F R O M;
WHERE      : W H E R E;

GROUP      : G R O U P;
BY         : B Y;
HAVING     : H A V I N G;

ORDER      : O R D E R;
LIMIT      : L I M I T;
OFFSET     : O F F S E T;

UNION      : U N I O N;
ALL        : A L L;
DISTINCT   : D I S T I N C T;

JOIN       : J O I N;
INNER      : I N N E R;
LEFT       : L E F T;
RIGHT      : R I G H T;
FULL       : F U L L;
OUTER      : O U T E R;
CROSS      : C R O S S;

ON         : O N;
USING      : U S I N G;

AS         : A S;

AND        : A N D;
OR         : O R;
NOT        : N O T;

IN         : I N;
LIKE       : L I K E;
BETWEEN    : B E T W E E N;
EXISTS     : E X I S T S;

IS         : I S;
NULL       : N U L L;
TRUE       : T R U E;
FALSE      : F A L S E;

ASC        : A S C;
DESC       : D E S C;

CASE       : C A S E;
WHEN       : W H E N;
THEN       : T H E N;
ELSE       : E L S E;
END        : E N D;

EQ         : '=';
NE         : '!=' | '<>';
LE         : '<=';
GE         : '>=';
LT         : '<';
GT         : '>';

PLUS       : '+';
MINUS      : '-';
STAR       : '*';
DIV        : '/';
MOD        : '%';

LPAREN     : '(';
RPAREN     : ')';

COMMA      : ',';
DOT        : '.';

NUMBER
    : [0-9]+ ('.' [0-9]+)?
    ;

STRING
    : '\'' ('\'\'' | ~['\r\n])* '\''
    ;

QUOTED_IDENTIFIER
    : '"' ('""' | ~["\r\n])* '"'
    ;

IDENTIFIER
    : [a-zA-Z_] [a-zA-Z0-9_]*
    ;

WS
    : [ \t\r\n]+ -> skip
    ;

COMMENT
    : '--' ~[\r\n]* -> skip
    ;

BLOCK_COMMENT
    : '/*' .*? '*/' -> skip
    ;


// ============================================================
// Case-insensitive fragments
// ============================================================

fragment A : [aA];
fragment B : [bB];
fragment C : [cC];
fragment D : [dD];
fragment E : [eE];
fragment F : [fF];
fragment G : [gG];
fragment H : [hH];
fragment I : [iI];
fragment J : [jJ];
fragment K : [kK];
fragment L : [lL];
fragment M : [mM];
fragment N : [nN];
fragment O : [oO];
fragment P : [pP];
fragment Q : [qQ];
fragment R : [rR];
fragment S : [sS];
fragment T : [tT];
fragment U : [uU];
fragment V : [vV];
fragment W : [wW];
fragment X : [xX];
fragment Y : [yY];
fragment Z : [zZ];
