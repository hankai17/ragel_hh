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

    #stmt := 'a' 'b'? 'c'? @ret_stmt;
    stmt := ('a' 'b'? 'c'?) @ret_stmt;

    main := '(' @call_stmt ')';
}%%

int main()
{
    char *data = "(abc)";
    char *p = data;
    char *pe = data + 5;

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
