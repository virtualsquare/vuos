#ifndef _ARCH_TABLE_H
#define _ARCH_TABLE_H
#include<sys/syscall.h>
#include<stdint.h>

#define SYSCALL_NR_OVERESTIMATION 512

extern uint16_t vu_arch_table[];
extern uint8_t vu_arch_args[];
extern uint8_t vvu_arch_args[];

#define ARCH_TYPE_SYMLINK_NOFOLLOW 1
#define ARCH_TYPE_IS_AT 2
#define ARCH_TYPE_IS_EXCEPTION  (ARCH_TYPE_SYMLINK_NOFOLLOW | ARCH_TYPE_IS_AT)


/**The syscall number allows to obtain infos about the syscall itself:
	the number of arguments, the type (l-sycall,syscall-at ...) and the position of the path argument.*/

static inline int vu_arch_table_nargs(int syscall_number) {
	int argstag = vu_arch_args[syscall_number]; 
	return (argstag & 0x7);
}

static inline int vu_arch_table_type(int syscall_number) {
	int argstag = vu_arch_args[syscall_number]; 
	return argstag >> 6;
}

static inline int vu_arch_table_patharg(int syscall_number) {
	int argstag = vu_arch_args[syscall_number]; 
	return ((argstag >> 3) & 0x7) - 1;
}

static inline int vvu_arch_table_nargs(int syscall_number) {
	int argstag = vvu_arch_args[syscall_number]; 
	return (argstag & 0x7);
}

static inline int vvu_arch_table_type(int syscall_number) {
	int argstag = vvu_arch_args[syscall_number]; 
	return argstag >> 6;
}

static inline int vvu_arch_table_patharg(int syscall_number) {
	int argstag = vvu_arch_args[syscall_number]; 
	return ((argstag >> 3) & 0x7) - 1;
}
#endif
