# 不依赖 cmake 的等价格建：
#   rules/ragel/*.rl --ragel--> gen/*.c --cc--> libragel_sql.a --link--> sql_scan
#   make test 跑 test.sh
# 产物统一放 build/ragel/，与 CMake 路径一致。

ROOT := $(abspath .)
RULES_DIR := $(ROOT)/rules/ragel
GEN := $(ROOT)/build/ragel/gen
BIN := $(ROOT)/build/ragel

RAGEL ?= ragel
CC    ?= gcc
AR    ?= ar
CFLAGS ?= -O2 -Wall -Wextra

OBJS := $(GEN)/sql_tokens.o $(GEN)/rule_sql.o
LIB  := $(BIN)/libragel_sql.a

all: $(BIN)/sql_scan

$(GEN):
	mkdir -p $(GEN) $(BIN)

$(GEN)/sql_tokens.c: $(RULES_DIR)/sql_tokens.rl $(RULES_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/rule_sql.c: $(RULES_DIR)/rule_sql.rl $(RULES_DIR)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/%.o: $(GEN)/%.c
	$(CC) $(CFLAGS) -I$(RULES_DIR) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

$(BIN)/sql_scan: sql_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(RULES_DIR) -o $@ sql_scan.c $(LIB)

test: $(BIN)/sql_scan
	./test.sh $(BIN)/sql_scan

clean:
	rm -rf $(GEN) $(BIN)

.PHONY: all test clean
