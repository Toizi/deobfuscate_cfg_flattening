// -mllvm -fla fla_test.c -o fla_test_2_cmovs.elf
// -mllvm -fla fla_test.c -o fla_test_2_cmovs_opt.elf -O2
// fla_test.c -o fla_test_2_cmovs_org.elf
#include <stdio.h>
int main(int argc, char** argv) {
  if (argc == 0)
    printf("additional basic block\n");
  if (argc < 2)
    printf("no args\n");
  else
    printf("%d arg(s)\n", argc - 1);
  return 0;
}