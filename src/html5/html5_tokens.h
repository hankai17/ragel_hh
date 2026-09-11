/* ============================================================
 * html5_tokens.h — HTML5 词法 token 类型（对齐 libinjection html5.h）
 * ------------------------------------------------------------
 * 固定枚举值（显式赋值）：html5_tokens.rl 的状态机用这些值输出 token，
 * html5_shared.rl 的 Ragel 机器用数字字面量引用，三者保持一致。
 *
 * token 语义（对齐 libinjection html5_type）：
 *   DATA_TEXT          普通文本
 *   TAG_NAME_OPEN      开标签名（<div 的 div）
 *   TAG_NAME_CLOSE     闭标签名（</div> 的 div）
 *   TAG_NAME_SELFCLOSE 自闭合标签名（<img/> 的 img）
 *   TAG_DATA           标签内数据
 *   TAG_CLOSE          标签闭合 >（</tag> 的 >）
 *   ATTR_NAME          属性名
 *   ATTR_VALUE         属性值（含引号，token 只含值内容）
 *   TAG_COMMENT        注释（<!-- --> 内容）
 *   DOCTYPE            <!DOCTYPE ... >
 * ============================================================ */
#ifndef HTML5_TOKENS_H
#define HTML5_TOKENS_H

#include <stddef.h>

typedef enum {
    H5_DATA_TEXT = 0,
    H5_TAG_NAME_OPEN = 1,
    H5_TAG_NAME_CLOSE = 2,
    H5_TAG_NAME_SELFCLOSE = 3,
    H5_TAG_DATA = 4,
    H5_TAG_CLOSE = 5,
    H5_ATTR_NAME = 6,
    H5_ATTR_VALUE = 7,
    H5_TAG_COMMENT = 8,
    H5_DOCTYPE = 9,
    /* 文本内容类别（对齐 WHATWG HTML raw-text / RCDATA 状态） */
    H5_SCRIPT_TEXT = 10,    /* <script> 内容（JS 代码） */
    H5_RAWTEXT_TEXT = 11,   /* <style>/<xmp>/<iframe>/<noembed>/<noframes> 内容 */
    H5_RCDATA_TEXT = 12,    /* <textarea>/<title> 内容 */
    H5_PLAINTEXT_TEXT = 13, /* <plaintext> 内容（无闭合） */
} H5TokType;

typedef struct {
    H5TokType type;   /* 指向输入缓冲区的文本区间 */
    const char* s;
    int len;
} H5Tok;

/* 词法扫描：对 data[0..len) 做 HTML5 tokenizer（对齐 libinjection
 * html5.c 状态机），结果写入 out（最多 cap 个），返回 token 数。 */
int lex_html5(const char* data, size_t len, H5Tok* out, int cap);

/* token 类型名（调试用） */
const char* h5_tok_name(H5TokType t);

#endif /* HTML5_TOKENS_H */
