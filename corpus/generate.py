#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
generate.py — 从 OWASP CheatSheetSeries 的 Markdown 源解析 XSS payload，
生成范式化 YAML 语料（corpus/owasp_xss.yaml）。

流程：拉取 Markdown -> 解析章节/代码块/列表 -> 自动分类 -> 自动解码 -> 生成 YAML

用法：
    python3 generate.py --md /tmp/xss_cheat.md --out owasp_xss.yaml
    python3 generate.py --fetch            # 从 GitHub 拉最新 Markdown 再生成
    python3 generate.py                    # 等价 --fetch（若本地无缓存则下载）
"""

import argparse
import html
import re
import sys
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import yaml

RAW_MD_URL = (
    "https://raw.githubusercontent.com/OWASP/CheatSheetSeries/"
    "master/cheatsheets/XSS_Filter_Evasion_Cheat_Sheet.md"
)

CATEGORIES = {
    'tag': '危险标签（本身危险，不需属性）',
    'event': '事件处理器属性 on*',
    'uri': '危险 URI（javascript:/vbscript:/data:）',
    'attr': '危险 URI 属性（background/dynsrc/lowsrc/...）',
    'css': 'CSS 注入（expression/@import/url()/-moz-binding）',
    'enc': '编码混淆（实体/URL/空白/字符转义，解码后归入上述类）',
    'server': '服务器端注入（SSI/PHP，引擎范围外，参考）',
}

# 规则登记：status=impl 引擎已实现 / todo 待补
RULES = {
    'script_tag': {'status': 'impl', 'desc': '<script>'},
    'dangerous_tag': {'status': 'impl',
                      'desc': '<iframe>/<object>/<embed>/<frame>/<svg>/<math>/<meta>'},
    'event_handler': {'status': 'impl', 'desc': 'on* 事件属性'},
    'js_uri': {'status': 'impl', 'desc': 'javascript:/vbscript:'},
    'entity_lt': {'status': 'impl', 'desc': '&#60;/&#x3c;/&lt;'},
    'TODO_dangerous_tag': {'status': 'todo', 'desc': '扩充 dangerous_tag：link/base/style'},
    'TODO_js_uri': {'status': 'todo', 'desc': '扩充 js_uri：data:'},
    'TODO_css': {'status': 'todo', 'desc': '新增 CSS 规则'},
    'TODO_attr_uri': {'status': 'todo', 'desc': '危险属性 URI 检测'},
    'TODO_protocol': {'status': 'todo', 'desc': '协议解析绕过 //host'},
    'TODO_js': {'status': 'todo', 'desc': 'JS 上下文注入/混淆（alert 函数名绕过等）'},
    'TODO_tokenizer': {'status': 'todo', 'desc': '词法改进：前导闭合/注释/XML/反引号干扰'},
    'TODO_unknown': {'status': 'todo', 'desc': '未归类'},
}

DANGEROUS_TAGS = ['iframe', 'object', 'embed', 'frame', 'svg', 'math', 'meta']
EXTRA_TAGS = ['link', 'base', 'style', 'bgsound', 'table', 'td', 'div',
              'input', 'body', 'img', 'applet', 'isindex', 'marquee',
              'video', 'audio', 'xml', 'br', 'button', 'form']


# --------------------------------------------------------------------------
# 解码
# --------------------------------------------------------------------------

def decode_entities(s):
    """HTML 实体解码：数字实体（含无分号/填充 0）+ 命名实体。"""
    def num_repl(m):
        base = 16 if m.group(1).lower() == 'x' else 10
        try:
            return chr(int(m.group(2), base))
        except (ValueError, OverflowError):
            return m.group(0)
    # 带分号
    s = re.sub(r'&#([xX]?)([0-9a-fA-F]+);', num_repl, s)
    # 不带分号（后面不跟数字/字母/分号，避免误伤）
    s = re.sub(r'&#([xX]?)([0-9a-fA-F]+)(?![0-9a-zA-Z;])', num_repl, s)
    # 命名实体（&lt; &colon; &NewLine; &lpar; 等）
    s = html.unescape(s)
    return s


def decode_js_escapes(s):
    """解码 \\xXX 与 \\uXXXX。"""
    def repl(m):
        try:
            return chr(int(m.group(1), 16))
        except (ValueError, OverflowError):
            return m.group(0)
    s = re.sub(r'\\u([0-9a-fA-F]{4})', repl, s)
    s = re.sub(r'\\x([0-9a-fA-F]{2})', repl, s)
    return s


def fold_scheme_ws(s):
    """折叠 javascript:/vbscript: 字母间及前缀的空白/控制字符混淆。

   覆盖：jav\\tascript / j a v a s c r i p t / java script 等字母间插空白，
   以及 =\" javascript:\" / url(\\x01javascript: 等前缀控制字符。
    """
    ws0 = r'[\x00-\x20]*'
    ws1 = r'[\x00-\x20]+'

    def strip(m):
        return re.sub(r'[\x00-\x20]', '', m.group(0))

    # 字母间空白折叠（jav\\tascript -> javascript）
    s = re.sub(r'(?i)j' + ws0 + 'a' + ws0 + 'v' + ws0 + 'a' + ws0 + 's' + ws0 +
               'c' + ws0 + 'r' + ws0 + 'i' + ws0 + 'p' + ws0 + 't', strip, s)
    s = re.sub(r'(?i)v' + ws0 + 'b' + ws0 + 's' + ws0 + 'c' + ws0 + 'r' + ws0 +
               'i' + ws0 + 'p' + ws0 + 't', strip, s)
    # 引号/等号/url( 后到 scheme 前的控制字符折叠
    s = re.sub(r'(?i)(["\'=])' + ws1 + r'(?=(java|vb)\s*script)', r'\1', s)
    s = re.sub(r'(?i)(url\s*\()' + ws1 + r'(?=(java|vb)\s*script)', r'\1', s)
    return s


def decode(payload):
    """把编码混淆的 payload 还原成规范形式（引擎实际输入）。"""
    s = payload
    s = decode_entities(s)
    s = urllib.parse.unquote(s)
    s = decode_js_escapes(s)
    s = fold_scheme_ws(s)
    return s


# --------------------------------------------------------------------------
# 分类与规则推导
# --------------------------------------------------------------------------

def classify(raw):
    r = raw.lower()
    # 1. server：明确服务器端特征（SSI / PHP / .htaccess）
    if '<!--#exec' in r:
        return 'server'
    if r.lstrip().startswith('<? echo') or r.lstrip().startswith('<?php'):
        return 'server'
    if r.lstrip().startswith('redirect '):
        return 'server'
    # 2. css：CSS 注入
    if ('expression(' in r or '@import' in r or '-moz-binding' in r
            or 'list-style-image' in r or 'behavior:' in r
            or 'background-image' in r or 'background:' in r):
        return 'css'
    # 3. event：on* 事件
    if re.search(r'\bon\w+\s*=', r):
        return 'event'
    # 4. attr：危险 URI 属性（优先于 uri，避免被 javascript: 抢走）
    if re.search(r'\b(background|dynsrc|lowsrc|action|poster|formaction)\s*=', r):
        return 'attr'
    # 5. uri：危险 URI
    if re.search(r'(javascript|vbscript|data)\s*:', r):
        return 'uri'
    # 6. enc：编码混淆
    if ('&#' in r or '&colon;' in r or '&lpar;' in r or '&period;' in r
            or '&newline;' in r
            or re.search(r'(java|vb)\s+script', r)
            or re.search(r'%[0-9a-f]{2}', r)
            or re.search(r'\\u[0-9a-f]{4}|\\x[0-9a-f]{2}', r)):
        return 'enc'
    # 7. tag：危险标签
    if re.search(r'<(script|iframe|object|embed|frame|svg|math|meta|link|base|style)\b', r):
        return 'tag'
    # 8. 无 HTML 结构：纯 JS 混淆 -> enc，其余（URL/代码片段）-> server
    if '<' not in raw:
        if re.search(r'alert|eval|document\.|top\[|fromcharcode|constructor', r):
            return 'enc'
        return 'server'
    # 9. 其余含 < 的 HTML -> tag
    if '<' in r:
        return 'tag'
    return 'enc'


def detect_rules(raw, decoded):
    """推导解码后应命中的规则（启发式，可被 override 修正）。"""
    rules = []
    r, d = raw.lower(), decoded.lower()
    if re.search(r'&#0*60;?|&#x0*3c;?|&lt;', r):
        rules.append('entity_lt')
    if re.search(r'<script\b', d):
        rules.append('script_tag')
    for t in DANGEROUS_TAGS:
        if re.search(r'<' + t + r'\b', d):
            rules.append('dangerous_tag')
            break
    if re.search(r'\bon\w+\s*=', d):
        rules.append('event_handler')
    # javascript:/vbscript: 在 CSS url() 里 -> TODO_css；HTML 属性里按引号分 js_uri/TODO_js_uri
    if re.search(r'url\s*\(\s*["\']?(javascript|vbscript)', d):
        rules.append('TODO_css')
    elif re.search(r'=\s*["\'](javascript|vbscript)\s*:', d):
        rules.append('js_uri')          # 带引号 URI，引擎支持
    elif re.search(r'=\s*(javascript|vbscript)\s*:', d):
        rules.append('TODO_js_uri')     # 无引号 URI，引擎不支持
    elif re.search(r'(javascript|vbscript)\s*:', d):
        rules.append('js_uri')          # 无 = 上下文（polyglot 等）
    if re.search(r'data\s*:', d) and 'js_uri' not in rules:
        rules.append('TODO_js_uri')
    if 'expression(' in d or '@import' in d or '-moz-binding' in d or 'behavior:' in d:
        rules.append('TODO_css')
    for t in EXTRA_TAGS:
        if re.search(r'<' + t + r'\b', d):
            rules.append('TODO_dangerous_tag')
            break
    if re.search(r'(href|src)\s*=\s*["\']?//', d):
        rules.append('TODO_protocol')
    if not rules:
        if '<' not in raw and re.search(r'alert|eval|document|constructor|top\[', d):
            rules.append('TODO_js')
        else:
            rules.append('TODO_unknown')
    return rules


def slugify(s):
    s = re.sub(r'[^a-z0-9]+', '-', s.lower()).strip('-')
    return s or 'item'


# --------------------------------------------------------------------------
# 解析 Markdown
# --------------------------------------------------------------------------

def parse_md(text):
    tests = []
    event_handlers = []
    char_escapes = []

    # nbsp 归一化成普通空格（OWASP 源里大量用 \xa0 作空格）
    text = text.replace('\xa0', ' ')
    lines = text.replace('\r\n', '\n').replace('\r', '\n').split('\n')
    sec2 = sec3 = sec4 = None
    in_code = False
    code_lang = ''
    code_lines = []

    def emit(payload, lang):
        if not payload.strip():
            return
        tests.append({
            'source': sec4 or sec3 or sec2 or 'Unknown',
            'section': sec2,
            'lang': lang,
            'payload': payload.strip('\n'),
        })

    for line in lines:
        if line.startswith('### '):
            sec3 = line[4:].strip()
            sec4 = None
            continue
        if line.startswith('#### '):
            sec4 = line[5:].strip()
            continue
        if line.startswith('## '):
            sec2 = line[3:].strip()
            sec3 = sec4 = None
            continue

        if line.startswith('```'):
            if not in_code:
                in_code = True
                code_lang = line[3:].strip()
                code_lines = []
            else:
                in_code = False
                emit('\n'.join(code_lines), code_lang)
            continue
        if in_code:
            code_lines.append(line)
            continue

        # 词汇表：事件处理器
        if sec4 == 'Attacks Using Event Handlers':
            m = re.match(r'^- `(on\w+)\(\)', line)
            if m:
                event_handlers.append(m.group(1))
                continue
        # 词汇表：< 的字符转义
        if sec2 == 'Character Escape Sequences':
            m = re.match(r'^- `(.+?)`\s*$', line)
            if m:
                char_escapes.append(m.group(1))
                continue
        # WAF bypass 与 alert 混淆（bullet 列表，非代码块）
        if sec3 in ('WAF ByPass Strings for XSS', 'Filter Bypass Alert Obfuscation'):
            m = re.match(r'^- `(.+)`\s*$', line)
            if m:
                emit(m.group(1), None)
                continue

    return tests, event_handlers, char_escapes


# --------------------------------------------------------------------------
# 人工覆盖（按章节名精确匹配，修正自动分类/解码/规则的偏差）
# --------------------------------------------------------------------------

OVERRIDES = {
    # '章节名': {'category': ..., 'decoded': ..., 'rules': [...]}
    'US-ASCII Encoding': {
        'category': 'enc',
        'decoded': '<script>alert("XSS")</script>',
        'rules': ['script_tag'],
    },
    'XSS Locator (Polyglot)': {'category': 'enc'},
    'IMG STYLE with Expressions': {'category': 'css', 'rules': ['TODO_css']},
    # URL 混淆：解码后是正常 URL，非 XSS（rules 空 = 负向测试，防误报）
    'IP Versus Hostname': {'category': 'enc', 'rules': []},
    'URL Encoding': {'category': 'enc', 'rules': []},
    'DWORD Encoding': {'category': 'enc', 'rules': []},
    'Hex Encoding': {'category': 'enc', 'rules': []},
    'Octal Encoding': {'category': 'enc', 'rules': []},
    'Mixed Encoding': {'category': 'enc', 'rules': []},
    'Protocol Resolution Bypass': {'category': 'enc', 'rules': []},
    'Removing CNAMEs': {'category': 'enc', 'rules': []},
    'Content Replace as Attack Vector': {'category': 'enc', 'rules': []},
    # 服务器端 / 示例代码（引擎范围外，rules 空 = 负向测试防误报）
    'SSI (Server Side Includes)': {'rules': []},
    'PHP': {'rules': []},
    'IMG Embedded Commands part II': {'rules': []},
    'raw:header(': {'rules': []},
    'Content Page Source Code': {'category': 'server', 'rules': []},
    'Share Page Source Code': {'category': 'server', 'rules': ['script_tag']},
    'Content Page Output': {'category': 'server', 'rules': []},
    'Share Page Output': {'category': 'server', 'rules': ['script_tag']},
    # 引擎词法缺口（tokenize 被前导干扰/特殊结构破坏，待 TODO_tokenizer）
    'Malformed IMG Tags': {'rules': ['TODO_tokenizer']},
    'Half Open HTML/JavaScript XSS Vector': {'rules': ['TODO_tokenizer']},
    'Downlevel-Hidden Block': {'rules': ['TODO_tokenizer']},
    'HTML+TIME in XML': {'rules': ['TODO_tokenizer']},
    'raw:/?param=<javascript': {'rules': ['TODO_tokenizer']},
    'raw:"><img src="x:x"': {'rules': ['TODO_tokenizer']},
    'raw:"><iframe': {'rules': ['TODO_tokenizer']},
    'raw:</script><img/*': {'rules': ['TODO_tokenizer']},
}


# --------------------------------------------------------------------------
# 主流程
# --------------------------------------------------------------------------

def fetch_md(path):
    req = urllib.request.Request(RAW_MD_URL, headers={'User-Agent': 'corpus-generator'})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = resp.read().decode('utf-8', 'replace')
    Path(path).write_text(data, encoding='utf-8')
    return data


def main():
    ap = argparse.ArgumentParser(description='生成 OWASP XSS 语料 YAML')
    ap.add_argument('--md', help='本地 Markdown 文件路径')
    ap.add_argument('--fetch', action='store_true', help='从 GitHub 拉取最新 Markdown')
    ap.add_argument('--out', default='owasp_xss.yaml', help='输出 YAML 路径')
    args = ap.parse_args()

    if args.md:
        text = Path(args.md).read_text(encoding='utf-8')
    else:
        cache = Path('/tmp/xss_cheat.md')
        if args.fetch or not cache.exists():
            print(f'fetching: {RAW_MD_URL}', file=sys.stderr)
            text = fetch_md(cache)
        else:
            print(f'using cache: {cache}', file=sys.stderr)
            text = cache.read_text(encoding='utf-8')

    raw_tests, event_handlers, char_escapes = parse_md(text)

    tests = []
    used_ids = {}
    for t in raw_tests:
        src = t['source']
        base = slugify(src)
        n = used_ids.get(base, 0) + 1
        used_ids[base] = n
        tid = base if n == 1 else f'{base}-{n}'

        raw = t['payload']
        category = classify(raw)
        decoded = decode(raw)
        rules = detect_rules(raw, decoded)

        ov = OVERRIDES.get(src)
        if ov is None:
            # 支持按 raw 子串精确匹配（用于同章节多条 payload 的差异化覆盖）
            for k, v in OVERRIDES.items():
                if k.startswith('raw:') and k[4:] in raw:
                    ov = v
                    break
        if ov:
            category = ov.get('category', category)
            decoded = ov.get('decoded', decoded)
            rules = ov.get('rules', rules)

        entry = {
            'id': tid,
            'category': category,
            'raw': raw,
            'decoded': decoded,
            'rules': rules,
            'source': src,
        }
        if t['section']:
            entry['section'] = t['section']
        if t['lang']:
            entry['lang'] = t['lang']
        tests.append(entry)

    doc = {
        'meta': {
            'version': 1,
            'title': 'OWASP XSS Filter Evasion Cheat Sheet 语料库',
            'source': {
                'name': 'OWASP XSS Filter Evasion Cheat Sheet',
                'url': 'https://cheatsheetseries.owasp.org/cheatsheets/'
                       'XSS_Filter_Evasion_Cheat_Sheet.html',
                'raw_md': RAW_MD_URL,
            },
            'generated_by': 'generate.py',
            'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'count': len(tests),
        },
        'categories': CATEGORIES,
        'rules': RULES,
        'tests': tests,
        'event_handlers': event_handlers,
        'char_escapes_lt': char_escapes,
    }

    out_path = Path(args.out)
    with out_path.open('w', encoding='utf-8') as f:
        yaml.safe_dump(doc, f, allow_unicode=True, sort_keys=False,
                       default_flow_style=False, width=100)

    print(f'OK: {len(tests)} tests, {len(event_handlers)} event handlers, '
          f'{len(char_escapes)} char escapes -> {out_path}', file=sys.stderr)

    # 分类分布
    from collections import Counter
    dist = Counter(x['category'] for x in tests)
    print('distribution:', dict(dist), file=sys.stderr)


if __name__ == '__main__':
    main()
