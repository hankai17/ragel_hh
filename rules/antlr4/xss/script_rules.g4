// rule: script_tag
// severity: HIGH
// action: BLOCK
// description: XSS：<script> 标签
// profile: raw

parser grammar script_rules;

options { tokenVocab = SQLTokens; }

import RuleSQL;

// start: LT
pattern : LT i=IDENT {isIdent($i, "script")}? ;
