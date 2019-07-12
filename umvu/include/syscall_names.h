#ifndef  SYSCALL_NAMES_H
#define  SYSCALL_NAMES_H

/* header file for the file syscall_names.c which is automatically generated
	 during the building/compilation process. The header file <sys/syscall.h>
	 is pre-processed to get the names of the the system calls provided by the
	 kernel for the current architecture. */

const char *syscallname(int sysno);
#endif
