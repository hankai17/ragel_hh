/* ============================================================
 * html5_tokens.rl — HTML5 tokenizer（对齐 libinjection html5.c 状态机）
 * ------------------------------------------------------------
 * 用 Ragel 显式状态机（fgoto 切换）复刻 libinjection 的逐状态逻辑，
 * 对应 WHATWG HTML 规范 tokenizer 章节（12.2.4.x）。
 *
 * 状态：data / tag_open / end_tag_open / tag_name / before_attribute_name /
 *       attribute_name / after_attribute_name / before_attribute_value /
 *       attribute_value(双/单/反/无引号) / after_attribute_value /
 *       self_closing / markup_declaration / doctype / comment /
 *       bogus_comment / bogus_comment2 / cdata
 *
 * token 语义对齐 libinjection html5_type：
 *   TAG_NAME_OPEN  开标签名（<div 的 div）
 *   TAG_NAME_CLOSE 开标签闭合 >（<div> 的 >，长度 1）
 *   TAG_CLOSE      闭标签名（</div> 的 div）
 *   TAG_NAME_SELFCLOSE 自闭合 />（长度 2）
 *   ATTR_NAME / ATTR_VALUE / TAG_COMMENT / DOCTYPE / DATA_TEXT
 *
 * 生成：ragel -C -o html5_tokens.c html5_tokens.rl
 * ============================================================ */

#include <string.h>

#include "html5_tokens.h"

static H5Tok* h5_out;
static int h5_cap;
static int h5_n;
static const char* tok_s;   /* 当前 token 起始指针 */
static int is_close;        /* </ 闭合标签标志 */

static void h5_emit(H5TokType t, const char* s, int len) {
    if (h5_n < h5_cap) {
        h5_out[h5_n].type = t;
        h5_out[h5_n].s = s;
        h5_out[h5_n].len = len;
        h5_n++;
    }
}

const char* h5_tok_name(H5TokType t) {
    switch (t) {
        case H5_DATA_TEXT:          return "DATA_TEXT";
        case H5_TAG_NAME_OPEN:      return "TAG_NAME_OPEN";
        case H5_TAG_NAME_CLOSE:     return "TAG_NAME_CLOSE";
        case H5_TAG_NAME_SELFCLOSE: return "TAG_NAME_SELFCLOSE";
        case H5_TAG_DATA:           return "TAG_DATA";
        case H5_TAG_CLOSE:          return "TAG_CLOSE";
        case H5_ATTR_NAME:          return "ATTR_NAME";
        case H5_ATTR_VALUE:         return "ATTR_VALUE";
        case H5_TAG_COMMENT:        return "TAG_COMMENT";
        case H5_DOCTYPE:            return "DOCTYPE";
        default:                    return "?";
    }
}

%%{
    machine html5;

    # ---- 动作 ----
    action b_tok { tok_s = p; }
    action e_data    { if (p - tok_s > 0) h5_emit(H5_DATA_TEXT, tok_s, p - tok_s); }
    action e_topen   { h5_emit(H5_TAG_NAME_OPEN, tok_s, p - tok_s); }
    action e_tclose  { h5_emit(H5_TAG_NAME_CLOSE, p, 1); }
    action e_self    { h5_emit(H5_TAG_NAME_SELFCLOSE, p - 2, 2); }
    action e_attr    { h5_emit(H5_ATTR_NAME, tok_s, p - tok_s); }
    action e_aval    { h5_emit(H5_ATTR_VALUE, tok_s, p - tok_s); }
    action e_comment { h5_emit(H5_TAG_COMMENT, tok_s, p - tok_s); }
    action e_doctype { h5_emit(H5_DOCTYPE, tok_s, p - tok_s); }

    # <! 后 dispatch：DOCTYPE / CDATA / 注释 / bogus（对齐 libinjection 的 memchr 做法）
    action markup_dispatch {
        size_t rem = (size_t)(pe - p);
        if (rem >= 7 &&
            (p[0]=='D'||p[0]=='d') && (p[1]=='O'||p[1]=='o') &&
            (p[2]=='C'||p[2]=='c') && (p[3]=='T'||p[3]=='t') &&
            (p[4]=='Y'||p[4]=='y') && (p[5]=='P'||p[5]=='p') &&
            (p[6]=='E'||p[6]=='e')) {
            const char* gt = (const char*)memchr(p + 7, '>', rem - 7);
            h5_emit(H5_DOCTYPE, p, gt ? (int)(gt - p) : (int)rem);
            p = gt ? gt : pe - 1;
            fgoto h5_data;
        } else if (rem >= 7 && strncmp(p, "[CDATA[", 7) == 0) {
            const char* q, * end = NULL;
            for (q = p + 7; q + 2 < pe; ++q)
                if (q[0]==']' && q[1]==']' && q[2]=='>') { end = q; break; }
            h5_emit(H5_DATA_TEXT, p + 7, (int)((end ? end : pe) - (p + 7)));
            p = end ? end + 2 : pe - 1;
            fgoto h5_data;
        } else if (rem >= 2 && p[0]=='-' && p[1]=='-') {
            const char* q, * end = NULL;
            for (q = p + 2; q + 2 < pe; ++q)
                if (q[0]=='-' && (q[1]=='-' || q[1]=='!') && q[2]=='>') { end = q; break; }
            h5_emit(H5_TAG_COMMENT, p + 2, (int)((end ? end : pe) - (p + 2)));
            p = end ? end + 2 : pe - 1;
            fgoto h5_data;
        } else {
            const char* gt = (const char*)memchr(p, '>', rem);
            h5_emit(H5_TAG_COMMENT, p, gt ? (int)(gt - p) : (int)rem);
            p = gt ? gt : pe - 1;
            fgoto h5_data;
        }
    }

    # ---- 字符类 ----
    h_ws    = [ \t\n\v\f\r];
    h_alpha = [a-zA-Z];
    h_alnum = [a-zA-Z0-9];

    # DATA：文本直到 <
    h5_data := ( any - '<' )* >b_tok %e_data '<' @{ fgoto tag_open; };

    # TAG_OPEN：< 后一个字符
    tag_open := '!' @{ fgoto markup_decl; }
              | '/' @{ is_close = 1; fgoto end_tag_open; }
              | '?' @{ const char* gt = (const char*)memchr(p, '>', (size_t)(pe - p));
                       h5_emit(H5_TAG_COMMENT, p + 1, gt ? (int)(gt - p - 1) : (int)(pe - p - 1));
                       p = gt ? gt : pe - 1; fgoto h5_data; }
              | '%' @{ const char* q, *end = NULL;
                       for (q = p + 1; q + 1 < pe; ++q)
                           if (q[0]=='%' && q[1]=='>') { end = q; break; }
                       h5_emit(H5_TAG_COMMENT, p + 1, (int)((end ? end : pe) - (p + 1)));
                       p = end ? end + 1 : pe - 1; fgoto h5_data; }
              | ( h_alpha | 0 ) >b_tok @{ fgoto tag_name; }
              | any @{ fgoto h5_data; };

    # END_TAG_OPEN：</ 后
    end_tag_open := '>' @{ is_close = 0; fgoto h5_data; }
                  | ( h_alpha | 0 ) >b_tok @{ fgoto tag_name; }
                  | any @{ is_close = 0;
                           const char* gt = (const char*)memchr(p, '>', (size_t)(pe - p));
                           h5_emit(H5_TAG_COMMENT, p, gt ? (int)(gt - p) : (int)(pe - p));
                           p = gt ? gt : pe - 1; fgoto h5_data; };

    # TAG_NAME：读标签名（含 null，IE 忽略）
    tag_name := ( h_alnum | 0 )*
                ( h_ws  @e_topen @{ fgoto before_attr; }
                | '/' @e_topen @{ fgoto self_closing; }
                | '>' >{ if (is_close) {
                              h5_emit(H5_TAG_CLOSE, tok_s, p - tok_s);
                              is_close = 0;
                          } else {
                              h5_emit(H5_TAG_NAME_OPEN, tok_s, p - tok_s);
                              h5_emit(H5_TAG_NAME_CLOSE, p, 1);
                          } }
                  @{ fgoto h5_data; } );

    # BEFORE_ATTRIBUTE_NAME：标签名后跳过空白
    before_attr := h_ws*
                   ( '/' @{ fgoto self_closing; }
                   | '>' >e_tclose @{ fgoto h5_data; }
                   | any >b_tok @{ fgoto attr_name; } );

    # ATTRIBUTE_NAME：读属性名
    attr_name := ( any - ( h_ws | '/' | '=' | '>' ) )*
                 ( h_ws  @e_attr @{ fgoto after_attr; }
                 | '/' @e_attr @{ fgoto self_closing; }
                 | '=' @e_attr @{ fgoto before_avalue; }
                 | '>' >{ h5_emit(H5_ATTR_NAME, tok_s, p - tok_s);
                           h5_emit(H5_TAG_NAME_CLOSE, p, 1); }
                   @{ fgoto h5_data; } );

    # AFTER_ATTRIBUTE_NAME：属性名后跳过空白
    after_attr := h_ws*
                  ( '/' @{ fgoto self_closing; }
                  | '=' @{ fgoto before_avalue; }
                  | '>' >e_tclose @{ fgoto h5_data; }
                  | any >b_tok @{ fgoto attr_name; } );

    # BEFORE_ATTRIBUTE_VALUE：= 后
    before_avalue := h_ws*
                     ( '"'  @{ fgoto avalue_dq; }
                     | '\'' @{ fgoto avalue_sq; }
                     | '`'  @{ fgoto avalue_bq; }
                     | any >b_tok @{ fgoto avalue_nq; } );

    # 引号属性值（token = 引号内内容，不含引号）
    avalue_dq := ( any - '"' )* >b_tok %e_aval '"' @{ fgoto after_avalue; };
    avalue_sq := ( any - '\'' )* >b_tok %e_aval '\'' @{ fgoto after_avalue; };
    avalue_bq := ( any - '`' )* >b_tok %e_aval '`' @{ fgoto after_avalue; };

    # 无引号属性值
    avalue_nq := ( any - ( h_ws | '>' ) )* %e_aval
                 ( h_ws @{ fgoto before_attr; }
                 | '>' >{ h5_emit(H5_TAG_NAME_CLOSE, p, 1); } @{ fgoto h5_data; } );

    # AFTER_ATTRIBUTE_VALUE：引号值后
    after_avalue := h_ws*
                    ( '/' @{ fgoto self_closing; }
                    | '>' >e_tclose @{ fgoto h5_data; }
                    | any @{ fgoto before_attr; } );

    # SELF_CLOSING：/>
    self_closing := '>' >{ h5_emit(H5_TAG_NAME_SELFCLOSE, p - 1, 2); }
                    @{ fgoto h5_data; }
                  | any @{ fgoto before_attr; };

    # MARKUP_DECLARATION：<! 后（DOCTYPE/CDATA/注释/bogus 在 markup_dispatch 内用 memchr 处理）
    markup_decl := any >markup_dispatch;

    write data noerror nofinal;
}%%

int lex_html5(const char* data, size_t len, H5Tok* out, int cap) {
    const char* p = data;
    const char* pe = data + len;
    const char* eof = pe;
    int cs;
    (void)eof;

    h5_out = out;
    h5_cap = cap;
    h5_n = 0;
    tok_s = data;
    is_close = 0;

    %% write init;
    cs = html5_en_h5_data;
    %% write exec;

    return h5_n;
}
