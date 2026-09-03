# ============================================================
# 统一 Ragel 构建（sql + log4j）：生成 + 编译 + 测试
# ------------------------------------------------------------
#   规则源（rl + 共享头）      rules/ragel/
#   驱动 / 测试脚本            本目录（tools/ragel/）
#   生成物 / 二进制            build/ragel/（不入库）
#
#   make all         生成 gen/*.c 并编译 sql_scan / sqli_scan / log4j_scan
#   make test        跑 test.sh（RuleSQL 骨架断言）
#   make test-sqli   跑 test_sqli.sh（sqli_rules 24 条规则断言）
#   make test-log4j  跑 test_log4j.sh（log4j 查找表达式断言）
#   make clean
#
# 也可由顶层 CMake（tools/ragel/CMakeLists.txt）构建，二者产物一致。
# ============================================================

ROOT := $(abspath ../..)
RULES_DIR := $(ROOT)/rules/ragel
GEN := $(ROOT)/build/ragel/gen
BIN := $(ROOT)/build/ragel

RAGEL ?= ragel
CC    ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

all: $(BIN)/sql_scan $(BIN)/sqli_scan $(BIN)/log4j_scan

$(GEN):
	mkdir -p $(GEN) $(BIN)

$(GEN)/sql_tokens.c: $(RULES_DIR)/sql_tokens.rl $(RULES_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/rule_sql.c: $(RULES_DIR)/rule_sql.rl $(RULES_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/sqli_rules.c: $(RULES_DIR)/sqli_rules.rl $(RULES_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/log4j_lookup.c: $(RULES_DIR)/log4j_lookup.rl $(RULES_DIR)/log4j_lookup.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(BIN)/sql_scan: sql_scan.c $(GEN)/sql_tokens.c $(GEN)/rule_sql.c | $(GEN)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ sql_scan.c $(GEN)/sql_tokens.c $(GEN)/rule_sql.c

$(BIN)/sqli_scan: sqli_scan.c $(GEN)/sql_tokens.c $(GEN)/rule_sql.c $(GEN)/sqli_rules.c | $(GEN)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ sqli_scan.c $(GEN)/sql_tokens.c $(GEN)/rule_sql.c $(GEN)/sqli_rules.c

$(BIN)/log4j_scan: log4j_scan.c $(GEN)/log4j_lookup.c | $(GEN)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ log4j_scan.c $(GEN)/log4j_lookup.c

test: $(BIN)/sql_scan
	./test.sh $(BIN)/sql_scan

test-sqli: $(BIN)/sqli_scan
	./test_sqli.sh $(BIN)/sqli_scan

test-log4j: $(BIN)/log4j_scan
	./test_log4j.sh $(BIN)/log4j_scan

clean:
	rm -rf $(GEN) $(BIN)/sql_scan $(BIN)/sqli_scan $(BIN)/log4j_scan

.PHONY: all test test-sqli test-log4j clean
