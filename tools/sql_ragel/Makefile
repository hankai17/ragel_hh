# SQLTokens + RuleSQL 的 Ragel 模拟：生成 + 编译 + 测试
#   make (all)    生成 sql_tokens.c / rule_sql.c 并编译 sql_scan
#   make test     编译并跑 test.sh（正/负样本断言，对齐 validate_sqli.sh 语料）
#   make clean

RAGEL ?= ragel
CC    ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: sql_scan

sql_tokens.c: sql_tokens.rl sql_tokens.h
	$(RAGEL) -C -o $@ $<

rule_sql.c: rule_sql.rl sql_tokens.h
	$(RAGEL) -C -o $@ $<

sql_scan: sql_scan.c sql_tokens.c rule_sql.c
	$(CC) $(CFLAGS) -o $@ sql_scan.c sql_tokens.c rule_sql.c

test: sql_scan
	./test.sh ./sql_scan

clean:
	rm -f sql_tokens.c rule_sql.c sql_scan

.PHONY: all test clean
