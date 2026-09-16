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

/* func: 0=Array 1=Function 2=at 3=filter 4=Number 5=String 6=RegExp 7=Boolean
 *       8=数字 toString（num 存 receiver）
 *       9=fontcolor 10=italics 11=entries 12=fromCharCode */
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
    char sbuf[16384]; /* 字符串拼接工作区（jsfuck 折叠中间结果累积较多） */
    int  slen;
} Ev;

static int eval_expr(Ev* e, Value* v);
static const char* func_name(int f);

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
            char fs[64];
            int n;
            if (v->func == 8) return v_str(e, "", 0);  /* toString 方法不直接字符串化 */
            n = snprintf(fs, sizeof(fs), "function %s() { [native code] }",
                         func_name(v->func));
            return v_str(e, fs, n);
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

/* V_FUNC 的内建函数名（func -> 名字），用于字符串化和 name 属性 */
static const char* func_name(int f) {
    switch (f) {
        case 0: return "Array";
        case 1: return "Function";
        case 2: return "at";
        case 3: return "filter";
        case 4: return "Number";
        case 5: return "String";
        case 6: return "RegExp";
        case 7: return "Boolean";
        default: return "";
    }
}

/* num.toString(radix)：整数转 2~36 进制字符串。返回长度，失败返回 -1。 */
static int num_to_string(char* buf, size_t cap, long num, long radix) {
    static const char digits[] = "0123456789abcdefghijklmnopqrstuvwxyz";
    char tmp[65];
    int i = 0, o = 0;
    if (radix < 2 || radix > 36 || cap < 2) return -1;
    if (num == 0) { buf[0] = '0'; buf[1] = '\0'; return 1; }
    if (num < 0) { buf[o++] = '-'; num = -num; }
    while (num > 0) { tmp[i++] = digits[num % radix]; num /= radix; }
    if (o + i + 1 > (int)cap) return -1;
    while (i > 0) buf[o++] = tmp[--i];
    buf[o] = '\0';
    return o;
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
            case V_STR:  *out = v_func(5); return 1;  /* "".constructor = String */
            case V_BOOL: *out = v_func(7); return 1;  /* false.constructor = Boolean */
            case V_NUM:  *out = v_func(4); return 1;  /* (0).constructor = Number */
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
    /* 函数的 name 属性：String["name"] = "String"（拼 "toString" 方法名） */
    if (obj->type == V_FUNC && k.slen == 4 && strncmp(k.s, "name", 4) == 0) {
        const char* nm = func_name(obj->func);
        *out = v_str(e, nm, (int)strlen(nm));
        return 1;
    }
    /* 数字的 toString 方法：(211)["toString"](31) = 进制转换 */
    if (obj->type == V_NUM && k.slen == 8 && strncmp(k.s, "toString", 8) == 0) {
        *out = v_func(8);
        out->num = obj->num;                         /* 记住 receiver 数字 */
        return 1;
    }
    /* 字符串的 fontcolor / italics 方法（jsfuck 用来生成引号等字符），
     * 用 s/slen 记住 receiver 字符串（fontcolor/italics 结果含 receiver） */
    if (obj->type == V_STR && k.slen == 9 && strncmp(k.s, "fontcolor", 9) == 0) {
        *out = v_func(9);
        out->s = obj->s; out->slen = obj->slen;
        return 1;
    }
    if (obj->type == V_STR && k.slen == 7 && strncmp(k.s, "italics", 7) == 0) {
        *out = v_func(10);
        out->s = obj->s; out->slen = obj->slen;
        return 1;
    }
    /* 数组的 entries 方法（[]["entries"]()+"..." 字符串化取字符） */
    if (obj->type == V_ARR && k.slen == 7 && strncmp(k.s, "entries", 7) == 0) {
        *out = v_func(11);
        return 1;
    }
    /* 3) 数组/对象上的其他属性 -> undefined（jsfuck 场景） */
    if (obj->type == V_ARR) { *out = v_undef(); return 1; }
    return 0;
}

/* ---- 调用 f(args) ---- */
static int call_val(Ev* e, const Value* fn, const Value* arg, Value* out) {
    if (fn->type != V_FUNC) return 0;
    if (fn->func == 1) {
        e->dangerous = 1;                          /* Function(...) = 动态构造代码 */
        *out = v_func(2);                          /* 返回"动态构造的函数" */
        return 1;
    }
    if (fn->func == 8) {                           /* 数字 toString(radix) = 进制转换 */
        long radix;
        char buf[65];
        int n;
        if (!to_num(arg, &radix)) return 0;
        n = num_to_string(buf, sizeof(buf), fn->num, radix);
        if (n < 0) return 0;
        *out = v_str(e, buf, n);
        return 1;
    }
    if (fn->func == 9) {                           /* fontcolor(arg) */
        Value as = to_str(e, arg);
        char buf[256];
        int n = snprintf(buf, sizeof(buf), "<font color=\"%.*s\">%.*s</font>",
                         as.slen, as.s, fn->slen, fn->s);
        if (n < 0 || n >= (int)sizeof(buf)) return 0;
        *out = v_str(e, buf, n);
        return 1;
    }
    if (fn->func == 10) {                          /* italics() */
        char buf[256];
        int n = snprintf(buf, sizeof(buf), "<i>%.*s</i>", fn->slen, fn->s);
        if (n < 0 || n >= (int)sizeof(buf)) return 0;
        *out = v_str(e, buf, n);
        return 1;
    }
    if (fn->func == 11) {                          /* entries() -> 迭代器字符串化 */
        const char* its = "[object Array Iterator]";
        *out = v_str(e, its, (int)strlen(its));
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
        case J_IDENT: {
            /* 内建全局标识符（jsfuck 用它们的字符串化取字符） */
            if (t.len == 6 && strncmp(t.s, "Number", 6) == 0)   { e->pos++; *v = v_func(4); return 1; }
            if (t.len == 6 && strncmp(t.s, "String", 6) == 0)   { e->pos++; *v = v_func(5); return 1; }
            if (t.len == 6 && strncmp(t.s, "RegExp", 6) == 0)   { e->pos++; *v = v_func(6); return 1; }
            if (t.len == 7 && strncmp(t.s, "Boolean", 7) == 0)  { e->pos++; *v = v_func(7); return 1; }
            if (t.len == 8 && strncmp(t.s, "Function", 8) == 0) { e->pos++; *v = v_func(1); return 1; }
            if (t.len == 3 && strncmp(t.s, "NaN", 3) == 0)      { e->pos++; *v = v_str(e, "NaN", 3); return 1; }
            if (t.len == 8 && strncmp(t.s, "Infinity", 8) == 0) { e->pos++; *v = v_str(e, "Infinity", 8); return 1; }
            return 0;                               /* 其他标识符：不可求值 */
        }
        default:
            return 0;
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
