/* ============================================================
 * js_eval.c — JS 常量折叠求值器（jsfuck 拦截，阶段 1）
 * ------------------------------------------------------------
 * jsfuck 是"纯常量"混淆：只用 []()!+ 几个字符，靠 JS 类型强制
 * 转换构造出任意字符串和函数调用。因为没有变量、没有输入依赖，
 * 可以被完全静态求值。
 *
 * 本文件在 lex_js 的 token 流上做递归下降解析，按 JS 真实语义
 * 求值，把 [![]+[]][+!![]] 折叠成 "a"，把 [][...][...](...) 折叠
 * 成 [].constructor.constructor("...") = Function("...")，从而
 * 让危险名重新变成明文，并检测"动态构造代码"。
 *
 * 只覆盖 jsfuck 子集：
 *   数组字面量 [] / [x]、一元 !/+/、二元 +（加法/拼接）、
 *   成员访问 [x]/.x、调用 f(...)、分组 (expr)、字面量、
 *   undefined（[][[]] 的结果）。
 * 变量/关键字等不可求值结构返回失败（保守，不判危险）。
 * ============================================================ */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "js_eval.h"

/* ---- 值模型 ---- */
typedef enum {
    V_UNDEF, V_NULL, V_BOOL, V_NUM, V_STR, V_ARR, V_FUNC
} VType;

/* func: 0 = Array, 1 = Function, 2 = 其他内建构造器(String/Boolean/Number) */
typedef struct {
    VType type;
    int   b;          /* V_BOOL */
    long  num;        /* V_NUM */
    int   slen;       /* V_STR 长度 */
    const char* s;    /* V_STR 内容 */
    int   func;       /* V_FUNC 种类 */
    int   arr_len;    /* V_ARR 的 ToString 长度 */
    const char* arr_s;/* V_ARR 的 ToString 内容 */
} Value;

typedef struct {
    const JsTok* toks;
    int n;
    int pos;
    int dangerous;    /* 置 1 = 检出 Function(...) 动态构造代码 */
    char sbuf[2048];  /* 字符串拼接工作区 */
    int  slen;
} Ev;

static int eval_expr(Ev* e, Value* v);

static Value v_undef(void)      { Value v; v.type = V_UNDEF; return v; }
static Value v_null(void)       { Value v; v.type = V_NULL;  return v; }
static Value v_bool(int b)      { Value v; v.type = V_BOOL;  v.b = b; return v; }
static Value v_num(long n)      { Value v; v.type = V_NUM;   v.num = n; return v; }
static Value v_func(int f)      { Value v; v.type = V_FUNC;  v.func = f; return v; }
static Value v_arr(const char* s, int len) {
    Value v; v.type = V_ARR; v.arr_s = s; v.arr_len = len; return v;
}

/* 把字符串写入工作区（追加式）。溢出时返回空串兜底（保守）。 */
static Value v_str(Ev* e, const char* s, int len) {
    Value v;
    v.type = V_STR;
    if (len < 0) len = 0;
    if (e->slen + len + 1 > (int)sizeof(e->sbuf)) {
        v.s = ""; v.slen = 0;
        return v;
    }
    memcpy(e->sbuf + e->slen, s, (size_t)len);
    v.s = e->sbuf + e->slen;
    v.slen = len;
    e->slen += len;
    e->sbuf[e->slen] = '\0';
    return v;
}

static JsTokType peek(Ev* e) {
    return e->pos < e->n ? e->toks[e->pos].type : J_EOF;
}
static int accept(Ev* e, JsTokType t) {
    if (e->pos < e->n && e->toks[e->pos].type == t) { e->pos++; return 1; }
    return 0;
}

/* ---- JS 类型转换 ---- */
static int to_bool(const Value* v) {
    switch (v->type) {
        case V_BOOL: return v->b;
        case V_NUM:  return v->num != 0;
        case V_STR:  return v->slen > 0;
        case V_ARR:  return 1;   /* 数组（含空）都是真值 */
        case V_FUNC: return 1;
        default:     return 0;
    }
}

static int to_num(const Value* v, long* out) {
    switch (v->type) {
        case V_NUM:  *out = v->num; return 1;
        case V_BOOL: *out = v->b ? 1 : 0; return 1;
        case V_NULL: *out = 0; return 1;
        case V_ARR: {             /* 数组 ToNumber：空数组=0，单元素=元素 ToNumber */
            char* end;
            long x;
            if (v->arr_len == 0) { *out = 0; return 1; }
            x = strtol(v->arr_s, &end, 10);
            if (end == v->arr_s) return 0;
            *out = x;
            return 1;
        }
        case V_STR: {
            char* end;
            long x = strtol(v->s, &end, 10);
            if (end == v->s) return 0;            /* NaN：不可表示 */
            *out = x;
            return 1;
        }
        default: return 0;                        /* undefined -> NaN */
    }
}

static Value to_str(Ev* e, const Value* v) {
    char tmp[64];
    switch (v->type) {
        case V_STR:   return *v;
        case V_BOOL:  return v_str(e, v->b ? "true" : "false", v->b ? 4 : 5);
        case V_NUM: {
            int n = snprintf(tmp, sizeof(tmp), "%ld", v->num);
            return v_str(e, tmp, n);
        }
        case V_ARR:   return v_str(e, v->arr_s, v->arr_len);  /* 数组 -> 元素拼接 */
        case V_UNDEF: return v_str(e, "undefined", 9);
        case V_NULL:  return v_str(e, "null", 4);
        case V_FUNC: {                              /* 函数 -> 字符串化（jsfuck 从中取 c/o 等字符） */
            const char* fs;
            if (v->func == 0)      fs = "function Array() { [native code] }";
            else if (v->func == 1) fs = "function Function() { [native code] }";
            else if (v->func == 2) fs = "function at() { [native code] }";
            else if (v->func == 3) fs = "function filter() { [native code] }";
            else                   fs = "function () { [native code] }";
            return v_str(e, fs, (int)strlen(fs));
        }
        default:      return v_str(e, "", 0);
    }
}

static Value str_concat(Ev* e, const Value* a, const Value* b) {
    int len = a->slen + b->slen;
    Value v;
    v.type = V_STR;
    if (e->slen + len + 1 > (int)sizeof(e->sbuf)) { v.s = ""; v.slen = 0; return v; }
    memcpy(e->sbuf + e->slen, a->s, (size_t)a->slen);
    memcpy(e->sbuf + e->slen + a->slen, b->s, (size_t)b->slen);
    v.s = e->sbuf + e->slen;
    v.slen = len;
    e->slen += len;
    e->sbuf[e->slen] = '\0';
    return v;
}

/* ---- 成员访问 obj[key] ---- */
static int member_get(Ev* e, const Value* obj, const Value* key, Value* out) {
    /* 1) 字符串索引：obj 是字符串，key 是数字（或数字字符串） */
    if (obj->type == V_STR) {
        long idx;
        if (to_num(key, &idx)) {
            if (idx < 0 || idx >= obj->slen) return 0;
            *out = v_str(e, obj->s + idx, 1);      /* "false"[1] -> "a" */
            return 1;
        }
    }
    /* 2) 属性名（key 转字符串） */
    Value k = to_str(e, key);
    if (k.slen == 11 && strncmp(k.s, "constructor", 11) == 0) {
        switch (obj->type) {
            case V_ARR:  *out = v_func(0); return 1;  /* [].constructor = Array */
            case V_FUNC: *out = v_func(1); return 1;  /* x.constructor.constructor = Function */
            case V_STR:
            case V_BOOL:
            case V_NUM:  *out = v_func(2); return 1;  /* 包装类 String/Boolean/Number */
            default: return 0;
        }
    }
    /* Array.prototype 方法（jsfuck 用 []["at"] / []["filter"] 作为拿 Function
     * 的跳板，这些名字的字符都在 false/true/undefined 里，可纯 []()!+ 构造） */
    if (obj->type == V_ARR && k.slen == 2 && strncmp(k.s, "at", 2) == 0) {
        *out = v_func(2);                            /* at 函数 */
        return 1;
    }
    if (obj->type == V_ARR && k.slen == 6 && strncmp(k.s, "filter", 6) == 0) {
        *out = v_func(3);                            /* filter 函数 */
        return 1;
    }
    /* 3) 数组/对象上的其他属性 -> undefined（jsfuck 场景） */
    if (obj->type == V_ARR) { *out = v_undef(); return 1; }
    return 0;
}

/* ---- 调用 f(args) ---- */
static int call_val(Ev* e, const Value* fn, const Value* arg, Value* out) {
    (void)arg;
    if (fn->type == V_FUNC && fn->func == 1) {
        e->dangerous = 1;                          /* Function(...) = 动态构造代码 */
        *out = v_func(2);                          /* 返回"动态构造的函数" */
        return 1;
    }
    return 0;
}

/* ---- 递归下降解析 ---- */
static int eval_primary(Ev* e, Value* v) {
    if (e->pos >= e->n) return 0;
    JsTok t = e->toks[e->pos];
    switch (t.type) {
        case J_NUMBER: {
            char buf[32];
            int n = t.len < 31 ? t.len : 31;
            memcpy(buf, t.s, (size_t)n); buf[n] = '\0';
            e->pos++;
            *v = v_num(strtol(buf, NULL, 10));
            return 1;
        }
        case J_STRING: {
            char buf[256]; int dlen;
            const char* d = js_decode_string(t.s, t.len, buf, (int)sizeof(buf), &dlen);
            e->pos++;
            *v = v_str(e, d, dlen);
            return 1;
        }
        case J_TRUE:      e->pos++; *v = v_bool(1); return 1;
        case J_FALSE:     e->pos++; *v = v_bool(0); return 1;
        case J_NULL:      e->pos++; *v = v_null(); return 1;
        case J_UNDEFINED: e->pos++; *v = v_undef(); return 1;
        case J_LBRACK: {                            /* 数组字面量 [] / [x] */
            e->pos++;
            if (accept(e, J_RBRACK)) { *v = v_arr("", 0); return 1; }  /* [] */
            Value elem;
            if (!eval_expr(e, &elem)) return 0;
            if (!accept(e, J_RBRACK)) return 0;     /* 只支持单元素 [x] */
            Value ts = to_str(e, &elem);
            *v = v_arr(ts.s, ts.slen);              /* [x] 的 ToString = ToString(x) */
            return 1;
        }
        case J_LPAREN: {                            /* ( expr ) 分组 */
            e->pos++;
            if (!eval_expr(e, v)) return 0;
            if (!accept(e, J_RPAREN)) return 0;
            return 1;
        }
        default:
            return 0;                               /* IDENT / 关键字：不可求值 */
    }
}

static int eval_postfix(Ev* e, Value* v) {
    if (!eval_primary(e, v)) return 0;
    for (;;) {
        JsTokType c = peek(e);
        if (c == J_LBRACK) {                        /* obj[expr] */
            e->pos++;
            Value key;
            if (!eval_expr(e, &key)) return 0;
            if (!accept(e, J_RBRACK)) return 0;
            Value out;
            if (!member_get(e, v, &key, &out)) return 0;
            *v = out;
        } else if (c == J_DOT) {                    /* obj.ident */
            e->pos++;
            if (e->pos >= e->n || e->toks[e->pos].type != J_IDENT) return 0;
            JsTok id = e->toks[e->pos]; e->pos++;
            if (id.len == 11 && strncmp(id.s, "constructor", 11) == 0) {
                Value key = v_str(e, "constructor", 11);
                Value out;
                if (!member_get(e, v, &key, &out)) return 0;
                *v = out;
            } else {
                return 0;                           /* 其他属性：不可求值 */
            }
        } else if (c == J_LPAREN) {                 /* f(args) */
            e->pos++;
            Value arg = v_undef();
            if (peek(e) != J_RPAREN) {
                if (!eval_expr(e, &arg)) return 0;
                while (accept(e, J_COMMA)) {        /* 多参数：逐个消费 */
                    Value tmp;
                    if (!eval_expr(e, &tmp)) return 0;
                }
            }
            if (!accept(e, J_RPAREN)) return 0;
            Value out;
            if (!call_val(e, v, &arg, &out)) return 0;
            *v = out;
        } else {
            break;
        }
    }
    return 1;
}

static int eval_unary(Ev* e, Value* v) {
    JsTokType c = peek(e);
    if (c == J_NOT) {
        e->pos++;
        Value x;
        if (!eval_unary(e, &x)) return 0;
        *v = v_bool(!to_bool(&x));
        return 1;
    }
    if (c == J_PLUS) {
        e->pos++;
        Value x;
        if (!eval_unary(e, &x)) return 0;
        long n;
        if (!to_num(&x, &n)) return 0;
        *v = v_num(n);
        return 1;
    }
    if (c == J_MINUS) {
        e->pos++;
        Value x;
        if (!eval_unary(e, &x)) return 0;
        long n;
        if (!to_num(&x, &n)) return 0;
        *v = v_num(-n);
        return 1;
    }
    return eval_postfix(e, v);
}

static int eval_add(Ev* e, Value* v) {
    if (!eval_unary(e, v)) return 0;
    for (;;) {
        if (peek(e) != J_PLUS) break;
        e->pos++;
        Value rhs;
        if (!eval_unary(e, &rhs)) return 0;
        /* JS 二元 +：有字符串/数组/函数参与 -> 拼接；否则转数字相加 */
        if (v->type == V_STR || v->type == V_ARR || v->type == V_FUNC ||
            rhs.type == V_STR || rhs.type == V_ARR || rhs.type == V_FUNC) {
            Value s1 = to_str(e, v);
            Value s2 = to_str(e, &rhs);
            *v = str_concat(e, &s1, &s2);
        } else {
            long a, b;
            if (!to_num(v, &a) || !to_num(&rhs, &b)) return 0;
            *v = v_num(a + b);
        }
    }
    return 1;
}

static int eval_expr(Ev* e, Value* v) {
    return eval_add(e, v);
}

int js_eval_dangerous(const JsTok* toks, int n) {
    for (int start = 0; start < n; start++) {
        Ev e;
        e.toks = toks;
        e.n = n;
        e.pos = start;
        e.dangerous = 0;
        e.slen = 0;
        Value v;
        eval_expr(&e, &v);          /* 求值结果本身不重要，只看是否触发危险 */
        if (e.dangerous) return 1;
    }
    return 0;
}
