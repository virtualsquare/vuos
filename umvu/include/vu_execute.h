#ifndef _VU_EXECUTE_H
#define _VU_EXECUTE_H
#include <umvu_peekpoke.h>
#include <linux_32_64.h>
#include <epoch.h>

/* second layer of virtualization, just above the tracer.
	 this module gets the system call requests,
	 calls the chice functions to decide if the request must be virtualized or not,
	 and dispatches them to the right wrappers */

#define VU_NESTED 1
#define VU_NOT_NESTED 0

/* extension of syscall state_t, field added for execute */
struct syscall_extra_t {
	/* the pathname of the syscall.
		 always canonicalized.
		 syscall using file descriptors: the canonicalized path used to open the file*/
	char *path;
	/* module path: path relative to the mountpoint of the module */
	const char *mpath;
	/* stat of the file: st_mode == 0 means that the file does not exist */
	struct vu_stat statbuf;
	/* errno returned during the path resolution */
	int path_errno;
	/* nested == 1 means self virtualization */
	uint8_t nested;
	/* if path_rewrite == 1, the pathname will be rewritten */
	uint8_t path_rewrite;
	/* hash table element of the module managing this system call.
		 NULL means not virtualized syscall */
	struct vuht_entry_t *ht;
	/* the epoch of the module match */
	epoch_t epoch;
};

void vu_syscall_execute(syscall_state_t state, struct syscall_descriptor_t *sd);
#endif

