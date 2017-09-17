#ifndef _VU_EXECUTE_H
#define _VU_EXECUTE_H
#include <umvu_peekpoke.h>
#include <linux_32_64.h>
#include <epoch.h>

#define VU_NESTED 1
#define VU_NOT_NESTED 0

struct syscall_extra_t {
	char *path;
	struct vu_stat statbuf;
	int path_errno;
	char nested;
	epoch_t epoch;
};

void vu_syscall_execute(syscall_state_t state, struct syscall_descriptor_t *sd);
#endif

