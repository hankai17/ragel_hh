# log4j Ragel 状态机：生成 + 编译 + 测试
#   make           生成 log4j_scan.c 并编译 log4j_scan
#   make test      编译并跑 test.sh（正/负样本断言）
#   make clean

RAGEL ?= ragel
CC    ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

log4j_scan.c: log4j_scan.rl
	$(RAGEL) -C -o $@ $<

log4j_scan: log4j_scan.c
	$(CC) $(CFLAGS) -o $@ $<

test: log4j_scan
	./test.sh ./log4j_scan

clean:
	rm -f log4j_scan.c log4j_scan

.PHONY: test clean
