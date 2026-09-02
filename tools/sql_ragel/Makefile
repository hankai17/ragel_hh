# SQLTokens + RuleSQL + sqli_rules 的 Ragel 模拟：生成 + 编译 + 测试
#   make (all)        生成 sql_tokens.c / rule_sql.c / sqli_rules.c
#                     并编译 sql_scan / sqli_scan
#   make test         编译并跑 test.sh（RuleSQL 骨架断言）
#   make test-sqli    编译并跑 test_sqli.sh（sqli_rules.g4 24 条规则断言）
#   make clean

RAGEL ?= ragel
CC    ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: sql_scan sqli_scan

sql_tokens.c: sql_tokens.rl sql_tokens.h
	$(RAGEL) -C -o $@ $<

rule_sql.c: rule_sql.rl sql_tokens.h
	$(RAGEL) -C -o $@ $<

sqli_rules.c: sqli_rules.rl sql_tokens.h
	$(RAGEL) -C -o $@ $<

sql_scan: sql_scan.c sql_tokens.c rule_sql.c
	$(CC) $(CFLAGS) -o $@ sql_scan.c sql_tokens.c rule_sql.c

sqli_scan: sqli_scan.c sql_tokens.c rule_sql.c sqli_rules.c
	$(CC) $(CFLAGS) -o $@ sqli_scan.c sql_tokens.c rule_sql.c sqli_rules.c

test: sql_scan
	./test.sh ./sql_scan

test-sqli: sqli_scan
	./test_sqli.sh ./sqli_scan

clean:
	rm -f sql_tokens.c rule_sql.c sqli_rules.c sql_scan sqli_scan

.PHONY: all test test-sqli clean
