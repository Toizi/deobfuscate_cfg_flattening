// -mllvm -fla hash.c -o hash.elf
// hash.c -o hash_org.elf
#include <stdio.h>

__attribute__((noinline)) unsigned long
hash(unsigned char *str)
{
    unsigned long hash = 5381;
    int c;

    while (c = *str++)
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */

    return hash;
}

int main(int argc, char **argv) {
    printf("%lu\n", hash(argv[1]));
    return 0;
}
