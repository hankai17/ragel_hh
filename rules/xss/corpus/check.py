#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
check.py — 语料回归：逐条跑 xss_scan，断言命中 / 不命中预期规则。

用法：
    python3 check.py [--scan ../build/ragel/xss_scan] [--yaml owasp_xss.yaml]
    python3 check.py --show        # 打印每条详情
    python3 check.py --list-todo   # 只汇总待补规则（下一批实现清单）
"""

import argparse
import re
import subprocess
import sys
from collections import Counter, defaultdict
from pathlib import Path

import yaml


def run_scan(scan, payload):
    try:
        r = subprocess.run([scan, payload], capture_output=True, text=True,
                           timeout=10)
        return r.stdout + r.stderr
    except Exception as e:  # noqa: BLE001
        return f'ERROR: {e}'


def hits_of(out):
    return set(re.findall(r'!!\s+(\S+)', out))


def main():
    ap = argparse.ArgumentParser(description='OWASP XSS 语料回归')
    ap.add_argument('--scan', default=None, help='xss_scan 路径')
    ap.add_argument('--yaml', default='owasp_xss.yaml')
    ap.add_argument('--list-todo', action='store_true', help='只汇总待补规则')
    ap.add_argument('--show', action='store_true', help='打印每条详情')
    args = ap.parse_args()

    base = Path(__file__).resolve().parent
    scan = args.scan or str(base / '../build/ragel/xss_scan')
    doc = yaml.safe_load((base / args.yaml).open(encoding='utf-8'))

    tests = doc['tests']
    todo_counter = Counter()
    passed = failed = todo = neg_ok = neg_bad = 0
    by_cls = defaultdict(lambda: [0, 0])

    for t in tests:
        cat = t['category']
        rules = t.get('rules') or []
        decoded = t['decoded']
        out = run_scan(scan, decoded)
        hit = hits_of(out)

        impl = [r for r in rules if not r.startswith('TODO_')]
        todos = [r for r in rules if r.startswith('TODO_')]
        for r in todos:
            todo_counter[r] += 1

        if not rules:
            # 负向测试：解码后是正常内容，预期不命中（防误报）
            by_cls[cat][1] += 1
            if hit:
                neg_bad += 1
                print(f'[NEG-FAIL] {t["id"]:44s} 预期不命中，实际命中 {sorted(hit)}')
            else:
                neg_ok += 1
                if args.show:
                    print(f'[NEG-OK]   {t["id"]:44s}')
            continue

        by_cls[cat][1] += 1
        if todos and not impl:
            todo += 1
            if args.show:
                print(f'[TODO]     {t["id"]:44s} {cat:6s} {rules}')
            continue

        if hit & set(impl):
            passed += 1
            by_cls[cat][0] += 1
            if args.show:
                extra = f' todo={todos}' if todos else ''
                print(f'[PASS]     {t["id"]:44s} hit={sorted(hit & set(impl))}{extra}')
        else:
            failed += 1
            print(f'[FAIL]     {t["id"]:44s} {cat:6s} expect={impl} got={sorted(hit)}')
            print(f'           decoded={decoded!r}')

    if args.list_todo:
        print('待补规则汇总（下一批实现清单）:')
        for r, n in todo_counter.most_common():
            desc = doc['rules'].get(r, {}).get('desc', '')
            print(f'  {r:22s} x{n:3d}  {desc}')
        return

    print()
    print('覆盖矩阵（命中/总数）:')
    for c in doc['categories']:
        p, n = by_cls[c]
        print(f'  {c:8s} {p:3d}/{n:3d}  {"#" * p}')
    print()
    print(f'summary: {passed} passed, {failed} failed, {todo} todo(待补), '
          f'{neg_ok} neg-ok, {neg_bad} neg-fail')
    if todo_counter:
        print()
        print('待补规则汇总:')
        for r, n in todo_counter.most_common():
            desc = doc['rules'].get(r, {}).get('desc', '')
            print(f'  {r:22s} x{n:3d}  {desc}')
    sys.exit(1 if (failed or neg_bad) else 0)


if __name__ == '__main__':
    main()
