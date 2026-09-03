# ============================================================
# Ragel 规则引擎构建（不依赖 cmake 的直连版本）
# ------------------------------------------------------------
#   规则源（rl + 契约头）  rules/ragel/
#   驱动                  sql_scan.c / log4j_scan.c（根目录）
#                         rules/ragel/sqli_scan.c（规则库自带最小驱动）
#   生成物 / 二进制       build/ragel/（不入库）
#
#   make                生成 gen/*.c -> 规则库 + sql_scan/sqli_scan/log4j_scan
#   make test           跑 test.sh（RuleSQL 骨架断言）
#   make test-sqli      跑 test_sqli.sh（sqli_rules 24 条规则断言）
#   make test-log4j     跑 test_log4j.sh（log4j 查找表达式断言）
#   make clean
#
# 与顶层 CMake（CMakeLists.txt）产物一致；cmake 亦可生成库 + install。
# ============================================================

ROOT := $(abspath .)
RULES_DIR := $(ROOT)/rules/ragel
GEN := $(ROOT)/build/ragel/gen
BIN := $(ROOT)/build/ragel

RAGEL ?= ragel
CC    ?= gcc
AR    ?= ar
CFLAGS ?= -O2 -Wall -Wextra

SQL_OBJS := $(GEN)/sql_tokens.o $(GEN)/rule_sql.o $(GEN)/sqli_rules.o
LOG4J_OBJS := $(GEN)/log4j_lookup.o

# 规则库（对外交付：头文件契约 + 库；antlr4 时代曾用 .so 插件）
SQL_LIB  := $(BIN)/libragel_sql.a
LOG4J_LIB := $(BIN)/libragel_log4j.a

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

$(GEN)/%.o: $(GEN)/%.c
	$(CC) $(CFLAGS) -I$(RULES_DIR) -c -o $@ $<

$(SQL_LIB): $(SQL_OBJS)
	$(AR) rcs $@ $(SQL_OBJS)

$(LOG4J_LIB): $(LOG4J_OBJS)
	$(AR) rcs $@ $(LOG4J_OBJS)

# 驱动链接规则库（不直接链生成物，模拟外部调用方）
$(BIN)/sql_scan: sql_scan.c $(SQL_LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ sql_scan.c $(SQL_LIB)

$(BIN)/sqli_scan: $(RULES_DIR)/sqli_scan.c $(SQL_LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ $(RULES_DIR)/sqli_scan.c $(SQL_LIB)

$(BIN)/log4j_scan: log4j_scan.c $(LOG4J_LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ log4j_scan.c $(LOG4J_LIB)

test: $(BIN)/sql_scan
	./test.sh $(BIN)/sql_scan

test-sqli: $(BIN)/sqli_scan
	./test_sqli.sh $(BIN)/sqli_scan

test-log4j: $(BIN)/log4j_scan
	./test_log4j.sh $(BIN)/log4j_scan

clean:
	rm -rf $(GEN) $(BIN)/sql_scan $(BIN)/sqli_scan $(BIN)/log4j_scan $(SQL_LIB) $(LOG4J_LIB)

.PHONY: all test test-sqli test-log4j clean
