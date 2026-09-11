# 不依赖 cmake 的等价构建：
#   .rl --ragel--> build/ragel/gen/*.c --cc--> libragel_sql.a --link--> 驱动
#
# 目录约定：
#   src/{sql,log4j,html5,js}/   词法层 + 共享片段 + 语法骨架（基础设施）
#   rules/{html5_xss,sqli}/     检测规则库（规则 .rl + 头文件 + 语料）
#
#   驱动与断言统一放 examples/：{sql,sqli,log4j,html5_xss,js}_scan + test_*.sh
#   make test 跑五套断言（sql 骨架 / sqli / log4j / html5_xss / js）
# 产物统一放 build/ragel/，与 CMake 路径一致。

ROOT  := $(abspath .)
SRC   := $(ROOT)/src
RULES := $(ROOT)/rules

SRC_SQL   := $(SRC)/sql
SRC_LOG4J := $(SRC)/log4j
SRC_HTML5 := $(SRC)/html5
SRC_JS    := $(SRC)/js

RULES_HTML5_XSS := $(RULES)/html5_xss
RULES_SQLI      := $(RULES)/sqli

GEN := $(ROOT)/build/ragel/gen
BIN := $(ROOT)/build/ragel

RAGEL ?= ragel
CC    ?= gcc
AR    ?= ar
CFLAGS ?= -O2 -Wall -Wextra

INC := -I$(SRC_SQL) -I$(SRC_LOG4J) -I$(SRC_HTML5) -I$(SRC_JS) \
       -I$(RULES_HTML5_XSS) -I$(RULES_SQLI)

OBJS := $(GEN)/sql_tokens.o $(GEN)/sql_syntax.o $(GEN)/sqli_rules.o \
        $(GEN)/log4j_lookup.o \
        $(GEN)/html5_tokens.o $(GEN)/html5_xss_rules.o \
        $(GEN)/js_tokens.o $(GEN)/js_syntax.o $(GEN)/js_danger.o
LIB  := $(BIN)/libragel_sql.a

all: $(BIN)/sql_scan $(BIN)/sqli_scan $(BIN)/log4j_scan $(BIN)/html5_xss_scan $(BIN)/js_scan

$(GEN):
	mkdir -p $(GEN) $(BIN)

# ---- ragel 生成：.rl -> .c ----
$(GEN)/sql_tokens.c: $(SRC_SQL)/sql_tokens.rl $(SRC_SQL)/sql_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/sql_syntax.c: $(SRC_SQL)/sql_syntax.rl $(SRC_SQL)/sql_tokens.h $(SRC_SQL)/sql_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

# sqli_rules.rl 与 sql_shared.rl 不同目录，需显式 -I
$(GEN)/sqli_rules.c: $(RULES_SQLI)/sqli_rules.rl $(RULES_SQLI)/sqli_rules.h $(SRC_SQL)/sql_shared.rl | $(GEN)
	$(RAGEL) -C -I$(SRC_SQL) -o $@ $<

$(GEN)/log4j_lookup.c: $(SRC_LOG4J)/log4j_lookup.rl $(SRC_LOG4J)/log4j_lookup.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/html5_tokens.c: $(SRC_HTML5)/html5_tokens.rl $(SRC_HTML5)/html5_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

# html5_xss_rules.rl 与 html5_shared.rl 不同目录，需显式 -I
$(GEN)/html5_xss_rules.c: $(RULES_HTML5_XSS)/html5_xss_rules.rl $(RULES_HTML5_XSS)/html5_xss_rules.h $(SRC_HTML5)/html5_shared.rl | $(GEN)
	$(RAGEL) -C -I$(SRC_HTML5) -o $@ $<

$(GEN)/js_tokens.c: $(SRC_JS)/js_tokens.rl $(SRC_JS)/js_tokens.h | $(GEN)
	$(RAGEL) -C -o $@ $<

$(GEN)/js_syntax.c: $(SRC_JS)/js_syntax.rl $(SRC_JS)/js_tokens.h $(SRC_JS)/js_shared.rl | $(GEN)
	$(RAGEL) -C -o $@ $<

# js_danger.c 是手写 C（非 ragel 生成），单独编译
$(GEN)/js_danger.o: $(SRC_JS)/js_danger.c $(SRC_JS)/js_danger.h $(SRC_JS)/js_tokens.h | $(GEN)
	$(CC) $(CFLAGS) $(INC) -c -o $@ $(SRC_JS)/js_danger.c

$(GEN)/%.o: $(GEN)/%.c
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(LIB): $(OBJS)
	$(AR) rcs $@ $(OBJS)

# ---- 驱动 ----
$(BIN)/sql_scan: examples/sql_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SRC_SQL) -o $@ examples/sql_scan.c $(LIB)

$(BIN)/sqli_scan: examples/sqli_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SRC_SQL) -I$(RULES_SQLI) -o $@ examples/sqli_scan.c $(LIB)

$(BIN)/log4j_scan: examples/log4j_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SRC_LOG4J) -o $@ examples/log4j_scan.c $(LIB)

$(BIN)/html5_xss_scan: examples/html5_xss_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SRC_HTML5) -I$(RULES_HTML5_XSS) -o $@ examples/html5_xss_scan.c $(LIB)

$(BIN)/js_scan: examples/js_scan.c $(LIB)
	$(CC) $(CFLAGS) -I$(SRC_JS) -o $@ examples/js_scan.c $(LIB)

test: all
	./examples/test_sql.sh $(BIN)/sql_scan
	./examples/test_sqli.sh $(BIN)/sqli_scan
	./examples/test_log4j.sh $(BIN)/log4j_scan
	./examples/test_html5_xss.sh $(BIN)/html5_xss_scan
	./examples/test_js.sh $(BIN)/js_scan

clean:
	rm -rf $(GEN) $(BIN)

.PHONY: all test clean
