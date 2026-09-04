# 不依赖 cmake 的等价格建：
#   rules/{sql,log4j,xss}/*.rl --ragel--> gen/*.c --cc--> libragel_sql.a --link--> 驱动
#   驱动：sql_scan（主目录）+ examples/{sqli,log4j,xss}_scan
#   make test 跑四套断言（sql 骨架 / sqli / log4j / xss）
# 产物统一放 build/ragel/，与 CMake 路径一致。

ROOT := $(abspath .)
SQL_DIR   := $(ROOT)/rules/sql
LOG4J_DIR := $(ROOT)/rules/log4j
XSS_DIR   := $(ROOT)/rules/xss
GEN := $(ROOT)/build/ragel/gen
BIN := $(ROOT)/build/ragel

RAGEL ?= ragel
CC    ?= gcc
AR    ?= ar
CFLAGS ?= -O2 -Wall -Wextra

INC := -I$(SQL_DIR) -I$(LOG4J_DIR) -I$(XSS_DIR)

OBJS := $(GEN)/sql_tokens.o $(GEN)/sql_syntax.o $(GEN)/sqli_rules.o \
        $(GEN)/log4j_lookup.o $(GEN)/xss_tokens.o $(GEN)/xss_rules.o
LIB  := $(BIN)/libragel_sql.a

all: $(BIN)/sql_scan $(BIN)/sqli_scan $(BIN)/log4j_scan $(BIN)/xss_scan

$(GEN):
	mkdir -p $(GEN) $(BIN)

$(GEN)/sql_tokens.c: $(SQL_DIR)/sql_tokens.rl $(SQL_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/sql_syntax.c: $(SQL_DIR)/sql_syntax.rl $(SQL_DIR)/sql_tokens.h $(SQL_DIR)/sql_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/sqli_rules.c: $(SQL_DIR)/sqli_rules.rl $(SQL_DIR)/sqli_rules.h $(SQL_DIR)/sql_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/log4j_lookup.c: $(LOG4J_DIR)/log4j_lookup.rl $(LOG4J_DIR)/log4j_lookup.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/xss_tokens.c: $(XSS_DIR)/xss_tokens.rl $(XSS_DIR)/xss_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/xss_rules.c: $(XSS_DIR)/xss_rules.rl $(XSS_DIR)/xss_rules.h $(XSS_DIR)/xss_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/%.o: $(GEN)/%.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BIN)/sql_scan: sql_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SQL_DIR) -o $@ sql_scan.c $(LIB)

$(BIN)/sqli_scan: examples/sqli_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SQL_DIR) -o $@ examples/sqli_scan.c $(LIB)

$(BIN)/log4j_scan: examples/log4j_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(LOG4J_DIR) -o $@ examples/log4j_scan.c $(LIB)

$(BIN)/xss_scan: examples/xss_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(XSS_DIR) -o $@ examples/xss_scan.c $(LIB)

test: all
	./test.sh $(BIN)/sql_scan
	./examples/test_sqli.sh $(BIN)/sqli_scan
	./examples/test_log4j.sh $(BIN)/log4j_scan
	./examples/test_xss.sh $(BIN)/xss_scan

clean:
	rm -rf $(GEN) $(BIN)

.PHONY: all test clean
