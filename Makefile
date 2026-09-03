# 不依赖 cmake 的等价格建：
#   rules/ragel/*.rl --ragel--> gen/*.c --cc--> libragel_sql.a --link--> 驱动
#   驱动：sql_scan（主目录）+ examples/sqli_scan + examples/log4j_scan
#   make test 跑三套断言（sql 骨架 / sqli / log4j）
# 产物统一放 build/ragel/，与 CMake 路径一致。

ROOT := $(abspath .)
RULES_DIR := $(ROOT)/rules/ragel
GEN := $(ROOT)/build/ragel/gen
BIN := $(ROOT)/build/ragel

RAGEL ?= ragel
CC    ?= gcc
AR    ?= ar
CFLAGS ?= -O2 -Wall -Wextra

OBJS := $(GEN)/sql_tokens.o $(GEN)/rule_sql.o $(GEN)/sqli_rules.o $(GEN)/log4j_lookup.o
LIB  := $(BIN)/libragel_sql.a

all: $(BIN)/sql_scan $(BIN)/sqli_scan $(BIN)/log4j_scan

$(GEN):
	mkdir -p $(GEN) $(BIN)

$(GEN)/sql_tokens.c: $(RULES_DIR)/sql_tokens.rl $(RULES_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/rule_sql.c: $(RULES_DIR)/rule_sql.rl $(RULES_DIR)/sql_tokens.h $(RULES_DIR)/rule_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/sqli_rules.c: $(RULES_DIR)/sqli_rules.rl $(RULES_DIR)/sqli_rules.h $(RULES_DIR)/rule_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/log4j_lookup.c: $(RULES_DIR)/log4j_lookup.rl $(RULES_DIR)/log4j_lookup.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/%.o: $(GEN)/%.c
	$(CC) $(CFLAGS) -I$(RULES_DIR) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BIN)/sql_scan: sql_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ sql_scan.c $(LIB)

$(BIN)/sqli_scan: examples/sqli_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ examples/sqli_scan.c $(LIB)

$(BIN)/log4j_scan: examples/log4j_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ examples/log4j_scan.c $(LIB)

test: all
	./test.sh $(BIN)/sql_scan
	./examples/test_sqli.sh $(BIN)/sqli_scan
	./examples/test_log4j.sh $(BIN)/log4j_scan

clean:
	rm -rf $(GEN) $(BIN)

.PHONY: all test clean
