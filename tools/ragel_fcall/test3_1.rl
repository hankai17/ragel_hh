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

    mid = '(' @call_stmt;

    stmt := 'a' 'b'? 'c'? mid? ')' @ret_stmt;

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
