#include <stdio.h>

%%{
    machine test;

    action call_stmt {
        printf("CALL: p=%c\n", *p);
        fcall stmt;
    }

    action ret_stmt {
        printf("RET: p=%c\n", *p);
        fret;
    }

    mid = '(' @call_stmt ')';

    #stmt := 'a' 'b'? 'c'? @ret_stmt;    # ret_stmt作用于 ’c‘? 如果c匹配上了则就调用ret返回到fcall处了
    #stmt := 'a' 'b'? 'c'? mid? @ret_stmt; # 同理
                                           # 返回的唯一条件是 能够匹配stmt 但是stmt是个自引用结构 即时你abc(abc(abc(...)))写的无限长也只是能匹配上stmt 
                                            # 现实是 不存在无限长的字串 所以整个mid永远匹配不上 永远无法调用fret返回到fcall处
    stmt := ('a' 'b'? 'c'? mid? )@ret_stmt; # ret_stmt作用于 整个表达式所有终态 a也是终态 匹配上a则返回到fcall处

    main := mid @{ printf("main done\n"); };
}%%

int main()
{
    char *data = "(abc)";
    //char *data = "(abc(abc))";
    char *p = data;

    char *pe = data + 5;
    //char *pe = data + 10;

    int cs;

    /* fcall/fret 使用的调用栈 */
    int stack[32];
    int top = 0;

    %% write data;
    %% write init;
    %% write exec;

    printf("DONE\n");

    return 0;
}
