#ifndef LINUX_32_64_H
#define LINUX_32_64_H
#include <sys/stat.h>

/* 32/64 compatibility issues.
	 vuos always uses the 64bits system calls.
	 vu_* and r_vu_* refer to the 64 bit implementation */

/* blame glibc for this */
#if __WORDSIZE == 32
#define vu_stat	stat64
#define vu_lstat lstat64
#define vu_fstat fstat64
#define vu_lstat lstat64
#define vu_fstat fstat64
#define vu_statfs statfs64
#define vu_fstatfs fstatfs64
#define vu_fstatat fstatat64
#define r_vu_stat	r_stat64
#define r_vu_lstat r_lstat64
#define r_vu_fstat r_fstat64
#define r_vu_lstat r_lstat64
#define r_vu_fstat r_fstat64
#define r_vu_statfs r_statfs64
#define r_vu_fstatfs r_fstatfs64
#define r_vu_fstatat r_fstatat64
#else
/* 64 bit architectures */
#define vu_stat stat
#define vu_lstat lstat
#define vu_fstat fstat
#define vu_lstat lstat
#define vu_fstat fstat
#define vu_statfs statfs
#define vu_fstatfs fstatfs
#define vu_fstatat fstatat
#define r_vu_stat r_stat
#define r_vu_lstat r_lstat
#define r_vu_fstat r_fstat
#define r_vu_lstat r_lstat
#define r_vu_fstat r_fstat
#define r_vu_statfs r_statfs
#define r_vu_fstatfs r_fstatfs
#define r_vu_fstatat r_fstatat
#endif

/* for 32 bit hosts missing in standard include files */
struct linux_dirent {
	unsigned long  d_ino;     /* Inode number */
	unsigned long  d_off;     /* Offset to next linux_dirent */
	unsigned short d_reclen;  /* Length of this linux_dirent */
	char           d_name[];  /* Filename (null-terminated) */
	/* length is actually (d_reclen - 2 -
		 offsetof(struct linux_dirent, d_name)) */
	/*
		 char           pad;       // Zero padding byte
		 char           d_type;    // File type (only since Linux
	// 2.6.4); offset is (d_reclen - 1)
	 */
};

void dirent64_to_dirent(void* buf, int count);
#endif
