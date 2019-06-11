#ifndef _VU_THREAD_SD_H
#define _VU_THREAD_SD_H

/* get/set the syscall_descriptor of the current thread,
	 mainly for modules */

struct syscall_descriptor_t *set_thread_sd(struct syscall_descriptor_t *sd);
struct syscall_descriptor_t *get_thread_sd(void);

#endif

