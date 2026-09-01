
rm -rf test1 test2 test3 test3_1
rm -rf test1.c test2.c test3.c test3_1.c

#ragel -C test1.rl -o test1.c
#gcc test1.c -o test1
#./test1

ragel -C test2.rl -o test2.c
gcc test2.c -o test2
./test2

ragel -C test3.rl -o test3.c
gcc test3.c -o test3
./test3

ragel -C test3_1.rl -o test3_1.c
gcc test3_1.c -o test3_1
./test3_1

