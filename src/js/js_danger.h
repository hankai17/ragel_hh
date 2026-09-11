/* ============================================================
 * js_danger.h — JS 危险调用检测接口
 * ------------------------------------------------------------
 * 输入一段 JS 代码，判断是否含「危险调用」（alert/eval/
 * document.cookie/fromCharCode 等）。
 *
 * 用法：include 本头并链接（js_tokens + js_danger 打包）。
 * ============================================================ */
#ifndef JS_DANGER_H
#define JS_DANGER_H

int js_is_dangerous(const char* code, int len);

#endif /* JS_DANGER_H */
