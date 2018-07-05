// -mllvm -fla fla_loop.c -o fla_loop.elf
// -fla_loop.c -o fla_loop_org.elf
#include <stdio.h>

int main(int argc, char **argv) {
    for (int i = 0; i < argc; ++i) {
        printf("arg%d : %s\n", i + 1, argv[i]);
    }
    return 0;
}