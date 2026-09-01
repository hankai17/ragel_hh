#include <stdio.h>

%%{
    machine test;

    action final {
        printf("FINAL\n");
    }

    main := 'a' 'b'? 'c'? @final;
}%%

int main()
{
    //char *data = "abc";
    char *data = "ab";
    char *p = data;
    //char *pe = data + 3;
    char *pe = data + 2;

    int cs;

    %% write data;
    %% write init;
    %% write exec;

    printf("cs = %d\n", cs);

    return 0;
}
