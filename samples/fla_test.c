// -mllvm -fla fla_test.c -o fla_test.elf
// fla_test.c -o fla_test_org.elf
#include <stdio.h>
int main(int argc, const char **argv) {
  if (argc < 2)
    printf("no args\n");
  else
    printf("%d arg(s)\n", argc - 1);
  return 0;
}