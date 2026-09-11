/* ============================================================
 * html5_shared.rl — HTML5 token 编号共享
 * ------------------------------------------------------------
 * 供规则层（rules/html5_xss 黑名单）按名 include：
 *   include html5_shared "html5_shared.rl";
 *
 * token 编号与 html5_tokens.h 的 H5TokType 枚举严格一致。
 * 本文件不单独编译（只被规则层引用）。
 * ============================================================ */

%%{
    machine html5_shared;
    DATA_TEXT = 0;
    TAG_NAME_OPEN = 1;
    TAG_NAME_CLOSE = 2;
    TAG_NAME_SELFCLOSE = 3;
    TAG_DATA = 4;
    TAG_CLOSE = 5;
    ATTR_NAME = 6;
    ATTR_VALUE = 7;
    TAG_COMMENT = 8;
    DOCTYPE = 9;
    SCRIPT_TEXT = 10;
    RAWTEXT_TEXT = 11;
    RCDATA_TEXT = 12;
    PLAINTEXT_TEXT = 13;
}%%
