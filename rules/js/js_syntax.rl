/* ============================================================
 * js_syntax.rl — JavaScript 表达式语法层（token 级状态机）
 * ------------------------------------------------------------
 * 参照 ECMAScript EBNF 的表达式优先级链（最小裁剪），在词法层
 * 输出的 token 数组上跑状态机。实现方式同 sql_syntax.rl：
 * Ragel 是字符级 DFA，这里把"token 类型"当作字母表（8 位）。
 *
 * CFG 递归（括号 / 方括号 / 函数调用）用 fcall/fret：
 *   primary 的 (expr)    -> fcall expr_call
 *   member  的 [expr]    -> fcall bracket_call
 *   call    的 f(...)    -> fcall elist_call
 *
 * 递归关键设计（同 sql_syntax.rl，避免 ragel"提前结束"陷阱）：
 *   被调 entry 以强制 token 结尾（expr_call := expr RPAREN 等），
 *   闭合 token 由被调方消费，entry 结束点无歧义；fret 手动实现，
 *   出栈后仅在栈空（top==0，最外层调用完成）时写 match_len。
 *
 * 生成：ragel -C -o js_syntax.c js_syntax.rl
 * ============================================================ */

#include <string.h>

#include "js_tokens.h"

/* fcall/fret 运行期栈大小。最深输入为纯括号串：n 个 token 最多
 * n/2 层调用（每层至少消耗 LPAREN+RPAREN 两个 token），
 * MAX_TOK=1024 时取 1024 留足余量。 */
#define CFG_STACKSZ 1024

%%{
    machine js_expr;
    include js_shared_tok  "js_shared.rl";
    include js_shared_expr "js_shared.rl";

    # 手动 fret（不用 @ret 包装）：出栈后仅当栈空才记录长度
    action ret_expr   { if (top > 0) cs = stack[--top];
                        if (top == 0) match_len = (int)(p - types) + 1 - start;
                        goto _again; }
    expr_call    := expr RPAREN @ret_expr;
    bracket_call := expr RBRACK @ret_expr;
    elist_call   := expr_list? RPAREN @ret_expr;

    action note_expr { if (top == 0) match_len = (int)(p - types) + 1 - start; }
    main := expr @note_expr;
    write data noerror nofinal noentry;
}%%

static int run_expr(const int* types, int n, int start, int* len) {
    const int* p = types + start;
    const int* pe = types + n;
    int cs = js_expr_start;
    int match_len = 0;
    int stack[CFG_STACKSZ];
    int top = 0;

    %%{
        machine js_expr;
        write exec;
    }%%

    if (match_len > 0) {
        *len = match_len;
        return 1;
    }
    return 0;
}

int js_match_expr(const int* types, int n, int start, int* len) {
    return run_expr(types, n, start, len);
}
