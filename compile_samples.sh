ollvm=~/obfuscator/build_Release/bin/clang

cd samples

$ollvm -mllvm -fla fla_loop.c -o fla_loop.elf
$ollvm fla_loop.c -o fla_loop_org.elf

$ollvm -mllvm -fla fla_test.c -o fla_test.elf
$ollvm fla_test.c -o fla_test_org.elf

$ollvm -mllvm -fla quarkslab.c -o quarkslab.elf
$ollvm quarkslab.c -o quarkslab_org.elf

$ollvm -mllvm -fla hash.c -o hash.elf
$ollvm hash.c -o hash_org.elf

$ollvm -mllvm -fla fla_test_2_cmovs.c -o fla_test_2_cmovs.elf
$ollvm -mllvm -fla fla_test_2_cmovs.c -o fla_test_2_cmovs_opt.elf -O2
$ollvm fla_test_2_cmovs.c -o fla_test_2_cmovs_org.elf
