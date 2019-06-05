#ifndef _ARCH_TABLE_H
#define _ARCH_TABLE_H
#include<sys/syscall.h>
#include<stdint.h>

/* header file for the file arch_table.c which is automatically generated
	 during the building/compilation process. The source file to generate
	 arch_table.c is vu_syscall.conf */

#define SYSCALL_NR_OVERESTIMATION 512

/* This is the mapping between the system calls numbers as defined
	 by the kernel for the current architecure and the correspondant
	 vuos system call number.
	 Several *real* system calls can be unified, processed and handled by
	 modules as one vuos systems call.
	 e.g. stat, lstat, fstat, fstatat, newfstatat: all are handled as __VU_lstat */
extern uint16_t vu_arch_table[];

/* vu_arch_args defines for each system call provided by the architecure:
 * i) the number of arguments
 * ii) if the syscall has a pathname arg, and which is the index of the path arg
 * iii) it if is a l- symbolic link opaque call (like lchown lstat)
 * iv) if it is a -at system call (including a dirfd arg, e.g. openat, fstatat)
 *
 * all this information is stored in a single byte:
 * +-+-+-+-+-+-+-+-+
 * |typ|path |nargs|
 * +-+-+-+-+-+-+-+-+
 *
 *	 typ = 01 l-call
 *	       02 -at call
 *				 03 *special* cases e.g. -at calls supporting AT_SYMLINK_NOFOLLOW
 * path = index of the path arg (of dirfd if this is a -at call)
 * nargs = numebr of args.
 *
 * Writing this value in octal the first digit is typ, the second is path and the third is nargs.
 * vu_arch_table[__NR_write] = 03; // 3 args, no path
 * vu_arch_table[__NR_stat] = 012; // 2 args, the first is the path
 * vu_arch_table[__NR_lstat] = 0112; // 2 args, the first is the path, do not follow links
 * vu_arch_table[__NR_mkdirat] = 0212; // 2 args, at-type, the first is the dirfd, so the second is the path
 * vu_arch_table[__NR_faccessat] = 314; // 2 args, at-type, the first is dirfd,
 *                                      AT_SYMLINK_NOFOLLOW is a supported flag
 */

extern uint8_t vu_arch_args[];

/* virtual system calls are those provided by vuos for its services.
	 e.g. insmod, rmmod, vuctl, msocket. umvu uses negative syscall numbers for virtual system calls */
/* vvu_arch_args provides for each *virtual* system call the same information
	 as vu_arch_table. The elements of vvu_arch_args has the same structure of vu_arch_table. */
extern uint8_t vvu_arch_args[];

#define ARCH_TYPE_SYMLINK_NOFOLLOW 1
#define ARCH_TYPE_IS_AT 2
#define ARCH_TYPE_IS_EXCEPTION 3

/* utility functions to read the (bit)fields of vu_arch_args and vvu_arch_args elements */

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
