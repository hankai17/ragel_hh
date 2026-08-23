# log4j Ragel fcall/fret 状态机：生成 + 编译 + 测试
#   make           生成 log4j_scan_fcall.c 并编译 log4j_scan_fcall
#   make test      编译并跑 test.sh（正/负样本断言，含超 4 层嵌套）
#   make clean

RAGEL ?= ragel
CC    ?= gcc
CFLAGS ?= -O2 -Wall -Wextra

log4j_scan_fcall.c: log4j_scan_fcall.rl
	$(RAGEL) -C -o $@ $<

log4j_scan_fcall: log4j_scan_fcall.c
	$(CC) $(CFLAGS) -o $@ $<

test: log4j_scan_fcall
	./test.sh ./log4j_scan_fcall

clean:
	rm -f log4j_scan_fcall.c log4j_scan_fcall

.PHONY: test clean
