/* ============================================================
 * xss_shared.rl — XSS 规则公共片段
 * ------------------------------------------------------------
 * 命名段，供 xss_rules.rl 按名 include：
 *   include xss_shared "xss_shared.rl";   token 编号 + 标签/属性结构
 *
 * Ragel include 语义：仅段名与 include 名匹配时才并入宿主机器，
 * 本文件不单独编译（只被 xss_rules.rl 引用）。
 * ============================================================ */

%%{
    machine xss_shared;
    LT = 1; GT = 2; SLASH = 3; EQ = 4; IDENT = 5; STRING = 6; ENTITY = 7;

    # 标签名 / 属性名（词法层统一输出 IDENT，语义谓词在 C 层判定）
    tag_name = IDENT;
    attr_name = IDENT;
    attr_value = STRING | IDENT;
    attr = attr_name ( EQ attr_value )?;
    open_tag = LT tag_name attr* ( SLASH )? GT;
}%%
