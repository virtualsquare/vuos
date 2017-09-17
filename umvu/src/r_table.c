#include <unistd.h>
#include <r_table.h>

long (*native_syscall)() = syscall;


