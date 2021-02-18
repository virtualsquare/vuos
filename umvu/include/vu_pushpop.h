#ifndef VU_PUSHPOP_H
#define VU_PUSHPOP_H
#include <umvu_peekpoke.h>

/* push and pop data on the user process stack. */

/* The area above the stack pointer of the process is used to store data
	 (pathnames, memory structures) nededed by the kernel
	 to run the system call.  This method does not generate conflicts because the
	 kernel uses a different stack area to process the system call and when the
	 syscall returns, the values stored above the SP aren't used anymore. */


syscall_arg_t vu_push(struct syscall_descriptor_t *sd, void *buf, size_t datalen);

void vu_pop(struct syscall_descriptor_t *sd, void *buf, size_t datalen);

#endif
